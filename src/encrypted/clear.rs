//! Opens, unlinks and renames for a share that stores names as clients
//! spell them. The inner backend resolves the names. This module reserves
//! the marker in the root and keeps the nodes of the open files in step with
//! what the inner backend does.

use std::sync::Arc;

use super::backend::EncryptedBackend;
use super::format::MARKER_NAME;
use super::handle::{EncryptedHandle, OpenResult};
use super::inner::close_after_reading;
use super::locks::acquire_some;
use super::node::{Found, HeaderState, NameMatch, Node, Origin, path_key};
use crate::backend::{FileInfo, Handle, OpenAction, OpenIntent, OpenOptions, ShareBackend};
use crate::error::{SmbError, SmbResult};
use crate::path::SmbPath;

/// True if `name` is the name of the marker, compared the way the inner
/// backend compares names.
pub(super) fn is_marker_name(name: &str, names: NameMatch) -> bool {
    match names {
        NameMatch::Exact => name == MARKER_NAME,
        NameMatch::Folded => name.to_lowercase() == MARKER_NAME,
    }
}

/// True if `path` is the marker.
fn is_marker(path: &SmbPath, names: NameMatch) -> bool {
    matches!(path.components(), [name] if is_marker_name(name, names))
}

/// The intent creates an entry that may not exist yet.
pub(super) fn creates(intent: OpenIntent) -> bool {
    matches!(
        intent,
        OpenIntent::Create | OpenIntent::OpenOrCreate | OpenIntent::OverwriteOrCreate
    )
}

/// The intent empties an existing file.
fn truncates(intent: OpenIntent) -> bool {
    matches!(intent, OpenIntent::Truncate | OpenIntent::OverwriteOrCreate)
}

/// The options of the open in the inner backend. Files are opened for
/// reading whatever the client asked, since a write that covers part of a
/// block reads the block first, and an open that empties a file also asks to
/// write.
fn inner_options(opts: OpenOptions) -> OpenOptions {
    OpenOptions {
        read: true,
        write: opts.write || truncates(opts.intent),
        ..opts
    }
}

impl<B: ShareBackend> EncryptedBackend<B> {
    /// Opens or creates `path`. The call holds the tree lock shared from here
    /// to the end, and nothing below it takes the lock again.
    pub(super) async fn open_handle(&self, path: &SmbPath, opts: OpenOptions) -> OpenResult<B> {
        let encrypt_names = self.shared.settings.encrypt_names;
        if encrypt_names && let (Some(parent), Some(name)) = (path.parent(), path.file_name()) {
            let _tree = self.shared.locks.tree.read().await;
            return self.open_entry(&parent, name, opts).await;
        }
        let names = self.shared.name_match();
        if !encrypt_names && is_marker(path, names) {
            return Err(match opts.intent {
                OpenIntent::Open | OpenIntent::Truncate => SmbError::NotFound,
                _ => SmbError::AccessDenied,
            });
        }
        let _tree = self.shared.locks.tree.read().await;
        let dir = path
            .parent()
            .map(|parent| self.shared.locks.directory(path_key(&parent, names)));
        let _held = acquire_some(dir.as_deref(), |dir| dir.acquire(creates(opts.intent))).await;
        self.open_at(path, opts, names).await
    }

    /// Opens the entry at the stored path `path`, whose directory lock the
    /// caller holds.
    pub(super) async fn open_at(
        &self,
        path: &SmbPath,
        opts: OpenOptions,
        names: NameMatch,
    ) -> OpenResult<B> {
        if !path.is_root() && truncates(opts.intent) {
            return self.overwrite(path, opts, names).await;
        }
        self.open_new(path, opts, names).await
    }

    /// Opens the entry at the stored path `path` in the inner backend as
    /// `opts` say, which may create it, and wraps the handle.
    pub(super) async fn open_new(
        &self,
        path: &SmbPath,
        opts: OpenOptions,
        names: NameMatch,
    ) -> OpenResult<B> {
        let (inner, action) = self.shared.inner.open(path, inner_options(opts)).await?;
        let handle = self.wrap(inner, path, action, names).await?;
        Ok((handle, action))
    }

    /// Opens an entry that is not the root with an intent that empties an
    /// existing file. The node of the file takes its lock before the inner
    /// backend empties the file, so no read or write of another handle is
    /// under way.
    async fn overwrite(
        &self,
        path: &SmbPath,
        opts: OpenOptions,
        names: NameMatch,
    ) -> OpenResult<B> {
        let inner = &self.shared.inner;
        let existing = OpenOptions {
            directory: opts.directory,
            non_directory: opts.non_directory,
            ..OpenOptions::default()
        };
        let check = match inner.open(path, existing).await {
            Ok((check, _)) => check,
            Err(SmbError::NotFound) if opts.intent == OpenIntent::OverwriteOrCreate => {
                return self.open_new(path, opts, names).await;
            }
            Err(error) => return Err(error),
        };
        let info = match check.stat().await {
            Ok(info) => info,
            Err(error) => {
                close_after_reading(check).await;
                return Err(error);
            }
        };
        if info.is_directory {
            close_after_reading(check).await;
            let (handle, action) = inner.open(path, inner_options(opts)).await?;
            return Ok((self.wrap(handle, path, action, names).await?, action));
        }
        let node = self.node_of(path, &info, Origin::Opened, names);
        let mut file = acquire_some(node.file(), |file| file.write()).await;
        let opened = inner.open(path, inner_options(opts)).await;
        if opened.is_ok()
            && let Some(file) = &mut file
        {
            file.header = HeaderState::Absent;
        }
        close_after_reading(check).await;
        let (handle, action) = opened?;
        drop(file);
        Ok((
            EncryptedHandle::new(handle, node, Arc::clone(&self.shared)),
            action,
        ))
    }

    /// Wraps `inner`, opened at `path` with `action`, in a handle that holds
    /// the node of its file.
    async fn wrap(
        &self,
        inner: Box<dyn Handle>,
        path: &SmbPath,
        action: OpenAction,
        names: NameMatch,
    ) -> SmbResult<EncryptedHandle<B>> {
        let info = match inner.stat().await {
            Ok(info) => info,
            Err(error) => {
                let _ = inner.close().await;
                return Err(error);
            }
        };
        let origin = if action == OpenAction::Created {
            Origin::Created
        } else {
            Origin::Opened
        };
        let node = self.node_of(path, &info, origin, names);
        if action == OpenAction::Overwritten {
            node.forget_header().await;
        }
        Ok(EncryptedHandle::new(inner, node, Arc::clone(&self.shared)))
    }

    fn node_of(
        &self,
        path: &SmbPath,
        info: &FileInfo,
        origin: Origin,
        names: NameMatch,
    ) -> Arc<Node> {
        self.shared.nodes.attach(&Found {
            path,
            file_index: info.file_index,
            directory: info.is_directory,
            origin,
            names,
        })
    }

    /// Deletes the file or empty directory at `path`. The call holds the tree
    /// lock shared from here to the end, and nothing below it takes the lock
    /// again.
    pub(super) async fn unlink_path(&self, path: &SmbPath) -> SmbResult<()> {
        let (Some(parent), Some(name)) = (path.parent(), path.file_name()) else {
            return Err(SmbError::AccessDenied);
        };
        if self.shared.settings.encrypt_names {
            let _tree = self.shared.locks.tree.read().await;
            return self.unlink_entry(&parent, name).await;
        }
        let names = self.shared.name_match();
        if is_marker(path, names) {
            return Err(SmbError::NotFound);
        }
        let _tree = self.shared.locks.tree.read().await;
        let dir = self.shared.locks.directory(path_key(&parent, names));
        let _held = dir.acquire(true).await;
        self.shared.inner.unlink(path).await?;
        self.shared.nodes.unlinked(path, names);
        Ok(())
    }

    /// Renames `from` to `to`. The call holds the tree lock exclusively from
    /// here to the end, and nothing below it takes the lock again.
    pub(super) async fn rename_path(
        &self,
        from: &SmbPath,
        to: &SmbPath,
        replace_if_exists: bool,
    ) -> SmbResult<()> {
        let (Some(from_parent), Some(from_name), Some(to_parent), Some(to_name)) =
            (from.parent(), from.file_name(), to.parent(), to.file_name())
        else {
            return Err(SmbError::AccessDenied);
        };
        if self.shared.settings.encrypt_names {
            let _tree = self.shared.locks.tree.write().await;
            return self
                .rename_entry(
                    &from_parent,
                    from_name,
                    &to_parent,
                    to_name,
                    replace_if_exists,
                )
                .await;
        }
        let names = self.shared.name_match();
        if is_marker(from, names) {
            return Err(SmbError::NotFound);
        }
        if is_marker(to, names) {
            return Err(SmbError::AccessDenied);
        }
        let _tree = self.shared.locks.tree.write().await;
        self.shared
            .inner
            .rename(from, to, replace_if_exists)
            .await?;
        self.shared.nodes.renamed(from, to, names);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::super::node::HeaderKind;
    use super::super::testing::{
        clear_over, clear_settings, exact_names, key_schedule, marker_bytes, open, open_dir,
        open_file, settle, shares_node, spawn_open,
    };
    use super::*;
    use crate::tests::file_ids::FileIds;
    use crate::tests::folding::Folding;
    use crate::tests::gated::{Gated, Op};
    use crate::tests::memfs::MemFsBackend;
    use crate::tests::recorder::Recorder;
    use crate::tests::util::{dir_opts, opts, path};

    /// Waits until a request for the exclusive lock of the file of `node`
    /// is queued behind the holders of the lock.
    async fn wait_for_a_writer(node: &Node) {
        let file = node.file().expect("a file node");
        for _ in 0..1000 {
            if file.try_read().is_err() {
                return;
            }
            tokio::task::yield_now().await;
        }
        panic!("no request waits for the lock of the file");
    }

    async fn two_handles_of_one_file_share_a_node<B: ShareBackend>(
        files: &MemFsBackend,
        layer: &EncryptedBackend<B>,
    ) {
        files.clone().with_file("f", b"").with_file("g", b"");
        let (a, _) = open(layer, "f", OpenIntent::Open).await;
        let (b, _) = open(layer, "f", OpenIntent::Open).await;
        let (c, _) = open(layer, "g", OpenIntent::Open).await;
        assert!(shares_node(&a, &b));
        assert!(!shares_node(&a, &c));
        assert_eq!(layer.node_count(), 2);

        Box::new(a).close().await.unwrap();
        assert_eq!(layer.node_count(), 2, "the second handle still holds it");
        Box::new(b).close().await.unwrap();
        assert_eq!(layer.node_count(), 1);
        Box::new(c).close().await.unwrap();
        assert_eq!(layer.node_count(), 0);
    }

    async fn a_truncating_open_takes_the_exclusive_lock_and_resets_the_header<B: ShareBackend>(
        files: &MemFsBackend,
        layer: &EncryptedBackend<B>,
    ) {
        files.clone().with_file("f", b"abc");
        let (reader, _) = open(layer, "f", OpenIntent::Open).await;
        let node = Arc::clone(reader.node());
        assert_eq!(node.header().await, Some(HeaderKind::Unknown));

        let in_flight = node.file().expect("a file node").read().await;
        let truncating = spawn_open(layer, "f", OpenIntent::Truncate);
        wait_for_a_writer(&node).await;
        assert!(!truncating.is_finished());
        assert_eq!(files.contents("f"), Some(b"abc".to_vec()));

        drop(in_flight);
        let (truncated, action) = truncating.await.unwrap().unwrap();
        assert_eq!(action, OpenAction::Overwritten);
        assert_eq!(files.contents("f"), Some(Vec::new()));
        assert!(shares_node(&reader, &truncated));
        assert_eq!(node.header().await, Some(HeaderKind::Absent));
        assert!(!node.is_detached());
    }

    async fn an_unlink_and_a_create_at_one_path_give_a_new_node<B: ShareBackend>(
        files: &MemFsBackend,
        layer: &EncryptedBackend<B>,
    ) {
        files.clone().with_file("f", b"abc");
        let (old, _) = open(layer, "f", OpenIntent::Open).await;
        layer.unlink(&path("f")).await.unwrap();
        assert!(old.node().is_detached());
        assert_eq!(layer.node_count(), 0);

        let (new, action) = open(layer, "f", OpenIntent::Create).await;
        assert_eq!(action, OpenAction::Created);
        assert!(!shares_node(&old, &new));
        assert!(!new.node().is_detached());
        assert_eq!(old.node().header().await, Some(HeaderKind::Unknown));
        assert_eq!(new.node().header().await, Some(HeaderKind::Absent));
        assert_eq!(layer.node_count(), 1);
    }

    async fn a_rename_keeps_the_node_of_an_open_file<B: ShareBackend>(
        files: &MemFsBackend,
        layer: &EncryptedBackend<B>,
    ) {
        files
            .clone()
            .with_dir("d")
            .with_dir("d\\sub")
            .with_file("d\\sub\\f", b"")
            .with_file("a", b"")
            .with_file("b", b"");
        let (deep, _) = open(layer, "d\\sub\\f", OpenIntent::Open).await;
        let (a, _) = open(layer, "a", OpenIntent::Open).await;
        let (b, _) = open(layer, "b", OpenIntent::Open).await;

        layer.rename(&path("d"), &path("e"), false).await.unwrap();
        assert_eq!(deep.node().path(), path("e\\sub\\f"));
        let (again, _) = open(layer, "e\\sub\\f", OpenIntent::Open).await;
        assert!(shares_node(&deep, &again));
        assert!(matches!(
            layer
                .open_handle(&path("d\\sub\\f"), opts(OpenIntent::Open))
                .await,
            Err(SmbError::PathNotFound)
        ));

        layer.rename(&path("a"), &path("b"), true).await.unwrap();
        assert!(b.node().is_detached());
        assert!(!a.node().is_detached());
        assert_eq!(a.node().path(), path("b"));
        let (at_target, _) = open(layer, "b", OpenIntent::Open).await;
        assert!(shares_node(&a, &at_target));
        assert!(matches!(
            layer.open_handle(&path("a"), opts(OpenIntent::Open)).await,
            Err(SmbError::NotFound)
        ));
        assert_eq!(layer.node_count(), 2);
    }

    async fn a_handle_dropped_without_close_leaves_no_table_entry<B: ShareBackend>(
        files: &MemFsBackend,
        layer: &EncryptedBackend<B>,
    ) {
        files.clone().with_file("f", b"").with_dir("d");
        let (file, _) = open(layer, "f", OpenIntent::Open).await;
        let dir = open_dir(layer, "d").await;
        let root = open_dir(layer, "").await;
        assert_eq!(layer.node_count(), 3);
        drop((file, dir, root));
        assert_eq!(layer.node_count(), 0);
    }

    async fn a_create_of_a_name_in_use_fails_and_leaves_the_node<B: ShareBackend>(
        files: &MemFsBackend,
        layer: &EncryptedBackend<B>,
    ) {
        files.clone().with_file("f", b"");
        let (held, _) = open(layer, "f", OpenIntent::Open).await;
        assert!(matches!(
            layer
                .open_handle(&path("f"), opts(OpenIntent::Create))
                .await,
            Err(SmbError::Exists)
        ));
        let (again, _) = open(layer, "f", OpenIntent::Open).await;
        assert!(shares_node(&held, &again));
        assert!(!held.node().is_detached());
    }

    async fn a_refused_unlink_or_rename_leaves_the_nodes<B: ShareBackend>(
        files: &MemFsBackend,
        layer: &EncryptedBackend<B>,
    ) {
        files.clone().with_file("a", b"").with_file("b", b"");
        let (a, _) = open(layer, "a", OpenIntent::Open).await;
        let (b, _) = open(layer, "b", OpenIntent::Open).await;
        assert!(matches!(
            layer.rename(&path("a"), &path("b"), false).await,
            Err(SmbError::Exists)
        ));
        assert!(matches!(
            layer.rename(&path("zz"), &path("y"), false).await,
            Err(SmbError::NotFound)
        ));
        assert!(matches!(
            layer.unlink(&path("zz")).await,
            Err(SmbError::NotFound)
        ));
        assert_eq!(a.node().path(), path("a"));
        assert_eq!(b.node().path(), path("b"));
        assert!(!a.node().is_detached() && !b.node().is_detached());
        assert_eq!(layer.node_count(), 2);
    }

    async fn open_or_create_sets_the_header_by_what_it_did<B: ShareBackend>(
        files: &MemFsBackend,
        layer: &EncryptedBackend<B>,
    ) {
        files.clone().with_file("old", b"abc");
        let (made, action) = open(layer, "new", OpenIntent::OpenOrCreate).await;
        assert_eq!(action, OpenAction::Created);
        assert_eq!(made.node().header().await, Some(HeaderKind::Absent));
        let (found, action) = open(layer, "old", OpenIntent::OpenOrCreate).await;
        assert_eq!(action, OpenAction::Opened);
        assert_eq!(found.node().header().await, Some(HeaderKind::Unknown));
        let (again, action) = open(layer, "new", OpenIntent::OpenOrCreate).await;
        assert_eq!(action, OpenAction::Opened);
        assert!(shares_node(&made, &again));
    }

    async fn an_overwriting_open_of_a_file_empties_it_and_resets_the_header<B: ShareBackend>(
        files: &MemFsBackend,
        layer: &EncryptedBackend<B>,
    ) {
        files.clone().with_file("f", b"abc").with_file("g", b"abc");
        for (name, intent) in [
            ("f", OpenIntent::OverwriteOrCreate),
            ("g", OpenIntent::Truncate),
        ] {
            let (handle, action) = open(layer, name, intent).await;
            assert_eq!(action, OpenAction::Overwritten, "{intent:?}");
            assert_eq!(files.contents(name), Some(Vec::new()));
            assert_eq!(handle.node().header().await, Some(HeaderKind::Absent));
        }
        assert_eq!(
            files.open_handles(),
            2,
            "the open that stats the file first is closed"
        );
    }

    async fn an_overwriting_open_of_a_missing_file_creates_it_or_fails<B: ShareBackend>(
        files: &MemFsBackend,
        layer: &EncryptedBackend<B>,
    ) {
        let (made, action) = open(layer, "n", OpenIntent::OverwriteOrCreate).await;
        assert_eq!(action, OpenAction::Created);
        assert_eq!(files.contents("n"), Some(Vec::new()));
        assert_eq!(made.node().header().await, Some(HeaderKind::Absent));

        assert!(matches!(
            layer
                .open_handle(&path("m"), opts(OpenIntent::Truncate))
                .await,
            Err(SmbError::NotFound)
        ));
        for intent in [OpenIntent::Truncate, OpenIntent::OverwriteOrCreate] {
            assert!(
                matches!(
                    layer.open_handle(&path("x\\m"), opts(intent)).await,
                    Err(SmbError::PathNotFound)
                ),
                "{intent:?}"
            );
        }
        assert_eq!(files.contents("m"), None);
        assert_eq!(files.open_handles(), 1);
        assert_eq!(layer.node_count(), 1);
    }

    async fn an_overwriting_open_of_a_directory_is_the_inner_backends_to_answer<B: ShareBackend>(
        files: &MemFsBackend,
        layer: &EncryptedBackend<B>,
    ) {
        files.clone().with_dir("d");
        for intent in [OpenIntent::Truncate, OpenIntent::OverwriteOrCreate] {
            assert!(
                matches!(
                    layer.open_handle(&path("d"), opts(intent)).await,
                    Err(SmbError::IsDirectory)
                ),
                "{intent:?}"
            );
        }
        assert_eq!(
            files.open_handles(),
            0,
            "the open that stats the file first is closed"
        );
        assert_eq!(layer.node_count(), 0);
    }

    async fn a_failed_overwriting_open_keeps_the_header_state<B: ShareBackend>(
        files: &MemFsBackend,
        layer: &EncryptedBackend<B>,
    ) {
        files.clone().with_file("f", b"abc");
        let (opened, _) = open(layer, "f", OpenIntent::Open).await;
        let (made, _) = open(layer, "n", OpenIntent::Create).await;
        files.clone().failing_overwrites();

        for name in ["f", "n"] {
            for intent in [OpenIntent::Truncate, OpenIntent::OverwriteOrCreate] {
                assert!(
                    matches!(
                        layer.open_handle(&path(name), opts(intent)).await,
                        Err(SmbError::AccessDenied)
                    ),
                    "{name} {intent:?}"
                );
            }
        }
        assert_eq!(opened.node().header().await, Some(HeaderKind::Unknown));
        assert_eq!(made.node().header().await, Some(HeaderKind::Absent));
        assert_eq!(files.contents("f"), Some(b"abc".to_vec()));
        assert_eq!(
            files.open_handles(),
            2,
            "the open that stats the file first is closed"
        );
        assert!(opened.node().file().unwrap().try_write().is_ok());
    }

    macro_rules! over_both_inner_backends {
        ($($scenario:ident),+ $(,)?) => {
            mod over_memfs {
                use super::*;
                $(
                    #[tokio::test]
                    async fn $scenario() {
                        let files = MemFsBackend::new();
                        let layer = clear_over(files.clone()).await;
                        super::$scenario(&files, &layer).await;
                    }
                )+
            }

            mod over_file_ids {
                use super::*;
                $(
                    #[tokio::test]
                    async fn $scenario() {
                        let files = MemFsBackend::new();
                        let layer = clear_over(FileIds::new(files.clone())).await;
                        super::$scenario(&files, &layer).await;
                    }
                )+
            }
        };
    }

    over_both_inner_backends!(
        two_handles_of_one_file_share_a_node,
        a_truncating_open_takes_the_exclusive_lock_and_resets_the_header,
        an_unlink_and_a_create_at_one_path_give_a_new_node,
        a_rename_keeps_the_node_of_an_open_file,
        a_handle_dropped_without_close_leaves_no_table_entry,
        a_create_of_a_name_in_use_fails_and_leaves_the_node,
        a_refused_unlink_or_rename_leaves_the_nodes,
        open_or_create_sets_the_header_by_what_it_did,
        an_overwriting_open_of_a_file_empties_it_and_resets_the_header,
        an_overwriting_open_of_a_missing_file_creates_it_or_fails,
        an_overwriting_open_of_a_directory_is_the_inner_backends_to_answer,
        a_failed_overwriting_open_keeps_the_header_state,
    );

    #[tokio::test]
    async fn a_create_over_a_file_deleted_outside_the_backend_takes_the_node_over() {
        let files = MemFsBackend::new();
        let layer = clear_over(files.clone()).await;
        files.clone().with_file("f", b"abc");
        let (old, _) = open(&layer, "f", OpenIntent::Open).await;
        files.remove("f");

        let (new, action) = open(&layer, "f", OpenIntent::Create).await;
        assert_eq!(action, OpenAction::Created);
        assert!(!shares_node(&old, &new));
        assert!(old.node().is_detached());
        assert_eq!(new.node().header().await, Some(HeaderKind::Absent));
        assert_eq!(layer.node_count(), 1);
        drop(old);
        assert_eq!(layer.node_count(), 1);
    }

    #[tokio::test]
    async fn an_overwriting_open_that_finds_the_file_created_meanwhile_resets_the_header() {
        let files = MemFsBackend::new();
        let gated = Gated::new(files.clone());
        let layer = clear_over(gated.clone()).await;
        let gate = gated.arm_after_at(Op::Open, "f");
        let opening = spawn_open(&layer, "f", OpenIntent::OverwriteOrCreate);
        gate.reached().await;
        files.clone().with_file("f", b"abc");
        gate.release();

        let (handle, action) = opening.await.unwrap().unwrap();
        assert_eq!(action, OpenAction::Overwritten);
        assert_eq!(files.contents("f"), Some(Vec::new()));
        assert_eq!(handle.node().header().await, Some(HeaderKind::Absent));
    }

    #[tokio::test]
    async fn the_root_opens_and_forwards_what_the_inner_backend_answers() {
        let files = MemFsBackend::new();
        let layer = clear_over(files.clone()).await;
        let root = SmbPath::root();
        let (first, action) = layer
            .open_handle(&root, dir_opts(OpenIntent::Open))
            .await
            .unwrap();
        assert_eq!(action, OpenAction::Opened);
        let second = open_dir(&layer, "").await;
        assert!(shares_node(&first, &second));
        assert!(first.node().is_directory());
        assert_eq!(layer.node_count(), 1);
        assert!(matches!(
            layer.open_handle(&root, opts(OpenIntent::Truncate)).await,
            Err(SmbError::IsDirectory)
        ));
        assert!(matches!(
            layer.open_handle(&root, opts(OpenIntent::Create)).await,
            Err(SmbError::Exists)
        ));
    }

    #[tokio::test]
    async fn the_marker_is_reserved_in_the_root() {
        let files = MemFsBackend::new();
        let layer = clear_over(files.clone()).await;
        files.clone().with_dir("d");
        let marker = marker_bytes(&files);
        let at_marker = path(MARKER_NAME);

        for intent in [OpenIntent::Open, OpenIntent::Truncate] {
            assert!(
                matches!(
                    layer.open_handle(&at_marker, opts(intent)).await,
                    Err(SmbError::NotFound)
                ),
                "{intent:?}"
            );
        }
        for intent in [
            OpenIntent::Create,
            OpenIntent::OpenOrCreate,
            OpenIntent::OverwriteOrCreate,
        ] {
            assert!(
                matches!(
                    layer.open_handle(&at_marker, opts(intent)).await,
                    Err(SmbError::AccessDenied)
                ),
                "{intent:?}"
            );
        }
        assert!(matches!(
            layer
                .open_handle(&at_marker, dir_opts(OpenIntent::Open))
                .await,
            Err(SmbError::NotFound)
        ));
        assert!(matches!(
            layer.unlink(&at_marker).await,
            Err(SmbError::NotFound)
        ));
        assert!(matches!(
            layer.rename(&at_marker, &path("x"), true).await,
            Err(SmbError::NotFound)
        ));
        assert!(matches!(
            layer.rename(&path("d"), &at_marker, true).await,
            Err(SmbError::AccessDenied)
        ));
        assert!(matches!(
            layer.rename(&at_marker, &at_marker, true).await,
            Err(SmbError::NotFound)
        ));
        assert_eq!(marker_bytes(&files), marker);
        assert_eq!(layer.node_count(), 0);

        let (below, action) = open(&layer, "d\\.smb-encryption", OpenIntent::Create).await;
        assert_eq!(
            action,
            OpenAction::Created,
            "only the root holds the marker"
        );
        drop(below);
    }

    #[tokio::test]
    async fn the_marker_follows_the_case_rule_of_the_inner_backend() {
        let files = MemFsBackend::new();
        let folded = clear_over(files.clone()).await;
        let spelled = path(".SMB-Encryption");
        assert!(matches!(
            folded.open_handle(&spelled, opts(OpenIntent::Open)).await,
            Err(SmbError::NotFound)
        ));
        assert!(matches!(
            folded.open_handle(&spelled, opts(OpenIntent::Create)).await,
            Err(SmbError::AccessDenied)
        ));
        assert!(matches!(
            folded.unlink(&spelled).await,
            Err(SmbError::NotFound)
        ));
        assert!(matches!(
            folded.rename(&spelled, &path("x"), false).await,
            Err(SmbError::NotFound)
        ));

        let files = MemFsBackend::new();
        let exact = clear_over(exact_names(&files)).await;
        let (made, action) = open(&exact, ".SMB-Encryption", OpenIntent::Create).await;
        assert_eq!(action, OpenAction::Created);
        assert_eq!(files.contents(".SMB-Encryption"), Some(Vec::new()));
        drop(made);
        exact.unlink(&spelled).await.unwrap();
        assert_eq!(files.contents(".SMB-Encryption"), None);
    }

    #[tokio::test]
    async fn the_root_cannot_be_unlinked_or_renamed() {
        let files = MemFsBackend::new();
        let layer = clear_over(files.clone()).await;
        files.clone().with_file("f", b"");
        let root = SmbPath::root();
        assert!(matches!(
            layer.unlink(&root).await,
            Err(SmbError::AccessDenied)
        ));
        assert!(matches!(
            layer.rename(&root, &path("x"), true).await,
            Err(SmbError::AccessDenied)
        ));
        assert!(matches!(
            layer.rename(&path("f"), &root, true).await,
            Err(SmbError::AccessDenied)
        ));
        assert_eq!(files.contents("f"), Some(Vec::new()));
    }

    #[tokio::test]
    async fn exact_names_that_differ_in_case_are_two_files() {
        let files = MemFsBackend::new();
        let layer = clear_over(exact_names(&files)).await;
        let (lower, _) = open(&layer, "report", OpenIntent::Create).await;
        let (upper, _) = open(&layer, "Report", OpenIntent::Create).await;
        assert!(!shares_node(&lower, &upper));
        layer.unlink(&path("REPORT")).await.unwrap_err();
        assert!(!lower.node().is_detached());
        layer.unlink(&path("Report")).await.unwrap();
        assert!(upper.node().is_detached());
        assert!(!lower.node().is_detached());
    }

    #[tokio::test]
    async fn case_variants_of_an_open_file_share_one_file_lock() {
        let files = MemFsBackend::new();
        let layer = clear_over(Folding::new(files.clone())).await;
        let (upper, _) = open(&layer, "Report.docx", OpenIntent::Create).await;
        let lower = Arc::new(open_file(&layer, "report.docx").await);
        assert!(shares_node(&upper, &lower));
        assert_eq!(layer.node_count(), 1);

        let writer = upper.node().file().expect("a file node").write().await;
        let reading = tokio::spawn({
            let lower = Arc::clone(&lower);
            async move { lower.stat().await }
        });
        settle().await;
        assert!(!reading.is_finished(), "the other spelling waits");

        drop(writer);
        reading.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn an_overwriting_open_through_another_spelling_resets_the_header_for_every_handle() {
        let files = MemFsBackend::new();
        let layer = clear_over(Folding::new(files.clone())).await;
        files
            .clone()
            .with_file("report.docx", b"abc")
            .with_file("memo.txt", b"abc");
        for (first, second, intent) in [
            ("Report.docx", "REPORT.DOCX", OpenIntent::Truncate),
            ("Memo.txt", "memo.TXT", OpenIntent::OverwriteOrCreate),
        ] {
            let (held, _) = open(&layer, first, OpenIntent::Open).await;
            assert_eq!(held.node().header().await, Some(HeaderKind::Unknown));

            let (overwriting, action) = open(&layer, second, intent).await;
            assert_eq!(action, OpenAction::Overwritten, "{second} {intent:?}");
            assert!(shares_node(&held, &overwriting), "{second} {intent:?}");
            assert_eq!(held.node().header().await, Some(HeaderKind::Absent));
            assert_eq!(files.contents(&first.to_lowercase()), Some(Vec::new()));
            assert_eq!(layer.node_count(), 1);
        }
    }

    #[tokio::test]
    async fn an_unlink_through_another_spelling_detaches_the_node_and_a_create_starts_a_new_one() {
        let files = MemFsBackend::new();
        let layer = clear_over(Folding::new(files.clone())).await;
        let (first, _) = open(&layer, "Report.docx", OpenIntent::Create).await;

        layer.unlink(&path("report.docx")).await.unwrap();
        assert!(first.node().is_detached());
        assert_eq!(layer.node_count(), 0);

        let (second, action) = open(&layer, "Report.docx", OpenIntent::Create).await;
        assert_eq!(action, OpenAction::Created);
        assert!(!shares_node(&first, &second));
        assert!(!second.node().is_detached());

        layer.unlink(&path("REPORT.DOCX")).await.unwrap();
        assert!(second.node().is_detached());
        let (third, action) = open(&layer, "report.docx", OpenIntent::Create).await;
        assert_eq!(action, OpenAction::Created);
        assert!(!shares_node(&second, &third));
        assert!(!shares_node(&first, &third));
        assert!(!third.node().is_detached());
        assert_eq!(third.node().header().await, Some(HeaderKind::Absent));
        assert_eq!(layer.node_count(), 1);

        let (found, _) = open(&layer, "REPORT.docx", OpenIntent::Open).await;
        assert!(shares_node(&third, &found));
    }

    #[tokio::test]
    async fn a_rename_through_another_spelling_moves_the_node_of_an_open_file() {
        let files = MemFsBackend::new();
        let layer = clear_over(Folding::new(files.clone())).await;
        let (held, _) = open(&layer, "Report.docx", OpenIntent::Create).await;

        layer
            .rename(&path("REPORT.DOCX"), &path("Final.docx"), false)
            .await
            .unwrap();
        assert_eq!(held.node().path(), path("Final.docx"));
        assert_eq!(files.contents("report.docx"), None);
        assert!(files.contents("final.docx").is_some());
        let (moved, _) = open(&layer, "final.docx", OpenIntent::Open).await;
        assert!(shares_node(&held, &moved));
        assert!(matches!(
            layer
                .open_handle(&path("Report.docx"), opts(OpenIntent::Open))
                .await,
            Err(SmbError::NotFound)
        ));

        layer
            .rename(&path("fINAL.DOCX"), &path("Done.docx"), false)
            .await
            .unwrap();
        let (again, _) = open(&layer, "DONE.docx", OpenIntent::Open).await;
        assert!(shares_node(&held, &again));
        assert!(!held.node().is_detached());
        assert_eq!(layer.node_count(), 1);
    }

    #[tokio::test]
    async fn a_rename_over_a_case_variant_of_an_open_file_detaches_its_node() {
        let files = MemFsBackend::new();
        let layer = clear_over(Folding::new(files.clone())).await;
        files
            .clone()
            .with_file("a.txt", b"")
            .with_file("b.txt", b"");
        let (source, _) = open(&layer, "A.txt", OpenIntent::Open).await;
        let (target, _) = open(&layer, "B.txt", OpenIntent::Open).await;
        assert!(!shares_node(&source, &target));

        layer
            .rename(&path("a.TXT"), &path("b.txt"), true)
            .await
            .unwrap();
        assert!(target.node().is_detached());
        assert!(!source.node().is_detached());
        assert_eq!(source.node().path(), path("b.txt"));
        let (at_target, _) = open(&layer, "B.TXT", OpenIntent::Open).await;
        assert!(shares_node(&source, &at_target));
        assert_eq!(layer.node_count(), 1);
    }

    #[tokio::test]
    async fn a_directory_rename_through_another_spelling_moves_the_nodes_below_it() {
        let files = MemFsBackend::new();
        let layer = clear_over(Folding::new(files.clone())).await;
        files
            .clone()
            .with_dir("dir")
            .with_dir("dir\\sub")
            .with_file("dir\\f", b"")
            .with_file("dir\\sub\\g", b"");
        let (file, _) = open(&layer, "dir\\f", OpenIntent::Open).await;
        let (deep, _) = open(&layer, "Dir\\Sub\\g", OpenIntent::Open).await;
        let dir = open_dir(&layer, "Dir").await;

        layer
            .rename(&path("DIR"), &path("Moved"), false)
            .await
            .unwrap();
        assert_eq!(file.node().path(), path("Moved\\f"));
        assert_eq!(deep.node().path(), path("Moved\\Sub\\g"));
        assert_eq!(dir.node().path(), path("Moved"));
        let (file_again, _) = open(&layer, "MOVED\\F", OpenIntent::Open).await;
        let (deep_again, _) = open(&layer, "moved\\SUB\\G", OpenIntent::Open).await;
        assert!(shares_node(&file, &file_again));
        assert!(shares_node(&deep, &deep_again));
        let dir_again = open_dir(&layer, "moved").await;
        assert!(shares_node(&dir, &dir_again));
        assert!(matches!(
            layer
                .open_handle(&path("dir\\f"), opts(OpenIntent::Open))
                .await,
            Err(SmbError::PathNotFound)
        ));
        assert_eq!(layer.node_count(), 3);
    }

    #[tokio::test]
    async fn an_open_waits_for_a_create_in_its_directory_spelled_another_way() {
        let files = MemFsBackend::new();
        let gated = Gated::new(Folding::new(files.clone()));
        let layer = clear_over(gated.clone()).await;
        files.clone().with_dir("dir");
        let gate = gated.arm_after_at(Op::Open, "Dir\\x");
        let creating = spawn_open(&layer, "Dir\\x", OpenIntent::Create);
        gate.reached().await;
        assert_eq!(files.contents("dir\\x"), Some(Vec::new()));
        assert_eq!(layer.node_count(), 0, "the create has no node yet");

        let opening = spawn_open(&layer, "dir\\x", OpenIntent::Open);
        settle().await;
        assert!(!opening.is_finished());
        assert_eq!(layer.node_count(), 0);

        gate.release();
        let (created, action) = creating.await.unwrap().unwrap();
        assert_eq!(action, OpenAction::Created);
        let (opened, action) = opening.await.unwrap().unwrap();
        assert_eq!(action, OpenAction::Opened);
        assert!(shares_node(&created, &opened));
        assert_eq!(created.node().header().await, Some(HeaderKind::Absent));
        assert_eq!(layer.node_count(), 1);
    }

    #[tokio::test]
    async fn creates_in_one_directory_spelled_two_ways_run_one_at_a_time() {
        let files = MemFsBackend::new();
        let gated = Gated::new(Folding::new(files.clone()));
        let layer = clear_over(gated.clone()).await;
        files.clone().with_dir("dir");
        let gate = gated.arm_at(Op::Open, "Dir\\x");
        let first = spawn_open(&layer, "Dir\\x", OpenIntent::Create);
        gate.reached().await;

        let second = spawn_open(&layer, "dir\\y", OpenIntent::Create);
        settle().await;
        assert!(!second.is_finished());
        assert_eq!(files.contents("dir\\y"), None);
        assert_eq!(layer.shared.locks.directory_count(), 1);

        gate.release();
        let (x, action) = first.await.unwrap().unwrap();
        assert_eq!(action, OpenAction::Created);
        let (y, action) = second.await.unwrap().unwrap();
        assert_eq!(action, OpenAction::Created);
        assert!(!shares_node(&x, &y));
        assert_eq!(files.contents("dir\\x"), Some(Vec::new()));
        assert_eq!(files.contents("dir\\y"), Some(Vec::new()));
        assert_eq!(layer.node_count(), 2);
    }

    #[tokio::test]
    async fn an_unlink_waits_for_a_create_in_its_directory_spelled_another_way() {
        let files = MemFsBackend::new();
        let gated = Gated::new(Folding::new(files.clone()));
        let layer = clear_over(gated.clone()).await;
        files.clone().with_dir("dir").with_file("dir\\y", b"");
        let gate = gated.arm_at(Op::Open, "Dir\\x");
        let creating = spawn_open(&layer, "Dir\\x", OpenIntent::Create);
        gate.reached().await;

        let unlinking = tokio::spawn({
            let layer = layer.clone();
            async move { layer.unlink(&path("DIR\\y")).await }
        });
        settle().await;
        assert!(!unlinking.is_finished());
        assert!(files.contents("dir\\y").is_some());

        gate.release();
        let (_, action) = creating.await.unwrap().unwrap();
        assert_eq!(action, OpenAction::Created);
        unlinking.await.unwrap().unwrap();
        assert_eq!(files.contents("dir\\y"), None);
        assert!(files.contents("dir\\x").is_some());
    }

    #[tokio::test]
    async fn files_are_opened_in_the_inner_backend_for_reading() {
        let recorder = Recorder::default();
        let layer = EncryptedBackend::new(recorder.clone(), key_schedule(), clear_settings());
        let asked = OpenOptions {
            read: false,
            write_attributes: true,
            intent: OpenIntent::OpenOrCreate,
            non_directory: true,
            delete_on_close: true,
            ..OpenOptions::default()
        };
        layer.open_handle(&path("f"), asked).await.unwrap();
        let sent = OpenOptions {
            read: true,
            ..asked
        };
        assert_eq!(
            recorder.calls(),
            [
                "capabilities".to_string(),
                format!("open f {sent:?}"),
                "stat".to_string(),
            ]
        );
    }

    #[tokio::test]
    async fn an_overwriting_open_checks_the_file_before_the_inner_backend_empties_it() {
        let recorder = Recorder::default();
        let layer = EncryptedBackend::new(recorder.clone(), key_schedule(), clear_settings());
        let asked = OpenOptions {
            write_attributes: true,
            intent: OpenIntent::Truncate,
            non_directory: true,
            ..OpenOptions::default()
        };
        layer.open_handle(&path("f"), asked).await.unwrap();
        let check = OpenOptions {
            non_directory: true,
            ..OpenOptions::default()
        };
        let emptying = OpenOptions {
            write: true,
            ..asked
        };
        assert_eq!(
            recorder.calls(),
            [
                "capabilities".to_string(),
                format!("open f {check:?}"),
                "stat".to_string(),
                format!("open f {emptying:?}"),
                "close".to_string(),
            ]
        );
    }

    #[tokio::test]
    async fn every_open_that_creates_holds_its_directory_exclusively() {
        for intent in [
            OpenIntent::Create,
            OpenIntent::OpenOrCreate,
            OpenIntent::OverwriteOrCreate,
        ] {
            let files = MemFsBackend::new();
            let gated = Gated::new(files.clone());
            let layer = clear_over(gated.clone()).await;
            let gate = gated.arm_at(Op::Open, "f");
            let after_create =
                (intent == OpenIntent::Create).then(|| gated.arm_after_at(Op::Open, "f"));
            let creating = spawn_open(&layer, "f", intent);
            gate.reached().await;
            assert!(
                layer.shared.locks.directory(String::new()).is_exclusive(),
                "{intent:?}"
            );
            assert!(layer.shared.locks.tree.try_write().is_err(), "{intent:?}");

            let opening = spawn_open(&layer, "f", OpenIntent::Open);
            settle().await;
            assert!(!opening.is_finished(), "{intent:?}");

            gate.release();
            if let Some(after_create) = after_create {
                after_create.reached().await;
                assert_eq!(files.contents("f"), Some(Vec::new()), "{intent:?}");
                assert!(
                    layer.shared.locks.directory(String::new()).is_exclusive(),
                    "{intent:?} after the inner create"
                );
                assert!(
                    layer.shared.locks.tree.try_write().is_err(),
                    "{intent:?} after the inner create"
                );
                settle().await;
                assert!(!opening.is_finished(), "{intent:?} after the inner create");
                after_create.release();
            }
            let (created, action) = creating.await.unwrap().unwrap();
            assert_eq!(action, OpenAction::Created, "{intent:?}");
            let (opened, action) = opening.await.unwrap().unwrap();
            assert_eq!(action, OpenAction::Opened, "{intent:?}");
            assert!(shares_node(&created, &opened), "{intent:?}");
        }
    }

    #[tokio::test]
    async fn a_truncating_open_holds_its_directory_shared() {
        let files = MemFsBackend::new();
        let gated = Gated::new(files.clone());
        let layer = clear_over(gated.clone()).await;
        files.clone().with_file("f", b"abc").with_file("g", b"");
        let gate = gated.arm_at(Op::Open, "f");
        let truncating = spawn_open(&layer, "f", OpenIntent::Truncate);
        gate.reached().await;
        let directory = layer.shared.locks.directory(String::new());
        assert!(!directory.is_free() && !directory.is_exclusive());

        let opening = spawn_open(&layer, "g", OpenIntent::Open);
        settle().await;
        assert!(opening.is_finished());
        opening.await.unwrap().unwrap();

        gate.release();
        let (_, action) = truncating.await.unwrap().unwrap();
        assert_eq!(action, OpenAction::Overwritten);
    }

    #[tokio::test]
    async fn a_rename_waits_for_an_unlink_in_progress() {
        let files = MemFsBackend::new();
        let gated = Gated::new(files.clone());
        let layer = clear_over(gated.clone()).await;
        files.clone().with_file("f", b"").with_file("a", b"");
        let gate = gated.arm_at(Op::Unlink, "f");
        let unlinking = tokio::spawn({
            let layer = layer.clone();
            async move { layer.unlink(&path("f")).await }
        });
        gate.reached().await;

        let renaming = tokio::spawn({
            let layer = layer.clone();
            async move { layer.rename(&path("a"), &path("b"), false).await }
        });
        settle().await;
        assert!(!renaming.is_finished());
        assert!(files.contents("a").is_some());

        gate.release();
        unlinking.await.unwrap().unwrap();
        renaming.await.unwrap().unwrap();
        assert_eq!(files.contents("f"), None);
        assert_eq!(files.contents("a"), None);
        assert!(files.contents("b").is_some());
    }

    #[tokio::test]
    async fn an_open_waits_for_a_rename_in_progress() {
        let files = MemFsBackend::new();
        let gated = Gated::new(files.clone());
        let layer = clear_over(gated.clone()).await;
        files.clone().with_file("a", b"").with_file("g", b"");
        let gate = gated.arm_at(Op::Rename, "a");
        let renaming = tokio::spawn({
            let layer = layer.clone();
            async move { layer.rename(&path("a"), &path("b"), false).await }
        });
        gate.reached().await;

        let opening = spawn_open(&layer, "g", OpenIntent::Open);
        settle().await;
        assert!(!opening.is_finished());
        assert!(files.contents("a").is_some());

        gate.release();
        renaming.await.unwrap().unwrap();
        opening.await.unwrap().unwrap();
        assert_eq!(files.contents("a"), None);
        assert!(files.contents("b").is_some());
    }

    #[tokio::test]
    async fn opens_of_different_directories_do_not_wait_for_each_other() {
        let files = MemFsBackend::new();
        let gated = Gated::new(files.clone());
        let layer = clear_over(gated.clone()).await;
        files
            .clone()
            .with_dir("a")
            .with_dir("b")
            .with_file("a\\f", b"")
            .with_file("b\\g", b"");
        let gate = gated.arm_at(Op::Stat, "a\\f");
        let parked = spawn_open(&layer, "a\\f", OpenIntent::Open);
        gate.reached().await;

        let (other, _) = open(&layer, "b\\g", OpenIntent::OpenOrCreate).await;
        assert_eq!(other.node().path(), path("b\\g"));

        gate.release();
        parked.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn a_failed_stat_after_the_inner_open_closes_the_inner_handle() {
        let files = MemFsBackend::new();
        let gated = Gated::new(files.clone());
        let layer = clear_over(gated.clone()).await;
        files.clone().with_file("f", b"");
        let gate = gated.arm_at(Op::Stat, "f");
        let opening = spawn_open(&layer, "f", OpenIntent::Open);
        gate.reached().await;
        files.remove("f");
        gate.release();

        assert!(matches!(opening.await.unwrap(), Err(SmbError::NotFound)));
        assert_eq!(files.open_handles(), 0);
        assert_eq!(layer.node_count(), 0);
    }
}
