//! The handles the backend gives out.

use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;

use super::backend::Shared;
use super::clear::is_marker_name;
use super::locks::acquire_some;
use super::node::{NameMatch, Node};
use super::size::logical_size;
use crate::backend::{
    DirChange, DirChangeKind, DirEntry, DirWatch, FileInfo, FileTimes, Handle, ShareBackend,
};
use crate::error::{SmbError, SmbResult};

/// A handle of the backend: an inner handle and the node of its file.
pub(super) struct EncryptedHandle<B> {
    pub(super) inner: Box<dyn Handle>,
    pub(super) node: Arc<Node>,
    pub(super) shared: Arc<Shared<B>>,
}

impl<B: ShareBackend> EncryptedHandle<B> {
    pub(super) fn new(inner: Box<dyn Handle>, node: Arc<Node>, shared: Arc<Shared<B>>) -> Self {
        Self {
            inner,
            node,
            shared,
        }
    }

    #[cfg(test)]
    pub(super) fn node(&self) -> &Arc<Node> {
        &self.node
    }

    /// The handle is on the share root.
    fn on_root(&self) -> bool {
        self.node.path().is_root()
    }

    /// The inner handle of a directory; writes and truncates of a file are
    /// not supported.
    fn directory(&self) -> SmbResult<&dyn Handle> {
        if self.node.is_directory() {
            Ok(&*self.inner)
        } else {
            Err(SmbError::NotSupported)
        }
    }

    /// Turns what the inner backend reports into what the share reports: the
    /// size of a file is its size before encryption, and there are no
    /// extended attributes.
    fn report(&self, info: &mut FileInfo) {
        info.ea_size = 0;
        if !info.is_directory {
            let size = logical_size(self.shared.settings.block_shift, info.end_of_file).size;
            info.end_of_file = size;
            info.allocation_size = size;
        }
    }

    /// `entries` of a listing as the share reports them.
    fn list_entries(&self, mut entries: Vec<DirEntry>) -> Vec<DirEntry> {
        if self.on_root() {
            let names = self.shared.name_match();
            entries.retain(|entry| !is_marker_name(&entry.info.name, names));
        }
        for entry in &mut entries {
            self.report(&mut entry.info);
        }
        entries
    }
}

#[async_trait]
impl<B: ShareBackend> Handle for EncryptedHandle<B> {
    async fn read(&self, offset: u64, len: u32) -> SmbResult<Bytes> {
        match self.node.file() {
            Some(file) => self.read_file(file, offset, len).await,
            None => self.inner.read(offset, len).await,
        }
    }

    async fn write(&self, offset: u64, data: &[u8]) -> SmbResult<u32> {
        self.directory()?.write(offset, data).await
    }

    async fn flush(&self) -> SmbResult<()> {
        self.inner.flush().await
    }

    async fn stat(&self) -> SmbResult<FileInfo> {
        let _file = acquire_some(self.node.file(), |file| file.read()).await;
        let mut info = self.inner.stat().await?;
        self.report(&mut info);
        Ok(info)
    }

    async fn set_times(&self, times: FileTimes) -> SmbResult<()> {
        self.inner.set_times(times).await
    }

    async fn set_attributes(&self, attributes: u32) -> SmbResult<()> {
        self.inner.set_attributes(attributes).await
    }

    async fn truncate(&self, len: u64) -> SmbResult<()> {
        self.directory()?.truncate(len).await
    }

    async fn list_dir(&self, pattern: Option<&str>) -> SmbResult<Vec<DirEntry>> {
        if self.shared.settings.encrypt_names {
            return Err(SmbError::NotSupported);
        }
        Ok(self.list_entries(self.inner.list_dir_sized(pattern, false).await?))
    }

    async fn close(self: Box<Self>) -> SmbResult<()> {
        self.inner.close().await
    }

    async fn link_count(&self) -> SmbResult<u32> {
        self.inner.link_count().await
    }

    async fn dir_is_empty(&self) -> SmbResult<bool> {
        if self.shared.settings.encrypt_names {
            return Err(SmbError::NotSupported);
        }
        if self.inner.dir_is_empty().await? {
            return Ok(true);
        }
        if !self.on_root() {
            return Ok(false);
        }
        let entries = self.inner.list_dir_sized(None, false).await?;
        let names = self.shared.name_match();
        Ok(!entries.is_empty()
            && entries
                .iter()
                .all(|entry| is_marker_name(&entry.info.name, names)))
    }

    async fn watch(&self) -> SmbResult<Option<Box<dyn DirWatch>>> {
        if self.shared.settings.encrypt_names {
            return Err(SmbError::NotSupported);
        }
        let Some(inner) = self.inner.watch().await? else {
            return Ok(None);
        };
        if !self.on_root() {
            return Ok(Some(inner));
        }
        Ok(Some(Box::new(RootWatch {
            inner,
            names: self.shared.name_match(),
        })))
    }
}

/// The watch of the share root: its changes without those of the marker.
struct RootWatch {
    inner: Box<dyn DirWatch>,
    names: NameMatch,
}

impl RootWatch {
    /// `change` as the share sees it: `None` when it only concerns the
    /// marker, and a rename from or to the marker as the other name
    /// appearing or going away.
    fn visible(&self, change: DirChange) -> Option<DirChange> {
        let is_marker = |name: &str| is_marker_name(name, self.names);
        let DirChangeKind::Renamed { from } = &change.kind else {
            return (!is_marker(&change.name)).then_some(change);
        };
        match (is_marker(from), is_marker(&change.name)) {
            (false, false) => Some(change),
            (true, true) => None,
            (true, false) => Some(DirChange::new(
                change.name,
                DirChangeKind::Added,
                change.is_directory,
            )),
            (false, true) => Some(DirChange::new(
                from.clone(),
                DirChangeKind::Removed,
                change.is_directory,
            )),
        }
    }
}

#[async_trait]
impl DirWatch for RootWatch {
    async fn next(&mut self) -> Option<Vec<DirChange>> {
        loop {
            let batch = self.inner.next().await?;
            let visible: Vec<_> = batch
                .into_iter()
                .filter_map(|change| self.visible(change))
                .collect();
            if !visible.is_empty() {
                return Some(visible);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::io;

    use tokio::sync::Notify;

    use super::super::backend::EncryptedBackend;
    use super::super::format::{BlockShift, MARKER_NAME};
    use super::super::node::{Found, Origin};
    use super::super::testing::{
        clear_over, clear_settings, exact_names, key_schedule, open_dir, open_file, settle,
        stored_file, stored_hole,
    };
    use super::*;
    use crate::backend::{OpenAction, OpenOptions};
    use crate::ea::Ea;
    use crate::path::SmbPath;
    use crate::tests::faulty::Faulty;
    use crate::tests::file_ids::FileIds;
    use crate::tests::memfs::MemFsBackend;
    use crate::tests::recorder::Recorder;
    use crate::tests::util::path;

    const SHIFT: BlockShift = BlockShift::DEFAULT;

    /// The stored bytes of a file that holds `plain`.
    fn stored(plain: &[u8]) -> Vec<u8> {
        stored_file(&key_schedule(), SHIFT, plain)
    }

    fn names(entries: Vec<DirEntry>) -> Vec<String> {
        let mut names: Vec<_> = entries.into_iter().map(|entry| entry.info.name).collect();
        names.sort();
        names
    }

    #[tokio::test]
    async fn stat_reports_the_size_of_a_file_before_encryption() {
        let files = MemFsBackend::new();
        let layer = clear_over(files.clone()).await;
        files
            .clone()
            .with_file("f", &stored(b"hello"))
            .with_file("hole", &stored_hole(SHIFT, 70))
            .with_file("torn", &[1; 10])
            .with_file("empty", b"")
            .with_times("f", 111, 222)
            .with_ea("f", Ea::new("note", b"value".to_vec()));

        let inner = files
            .open(&path("f"), OpenOptions::default())
            .await
            .unwrap()
            .0
            .stat()
            .await
            .unwrap();
        assert_eq!(inner.end_of_file, 57);
        assert_ne!(inner.ea_size, 0);

        let info = open_file(&layer, "f").await.stat().await.unwrap();
        assert_eq!(info.name, "f");
        assert_eq!((info.end_of_file, info.allocation_size), (5, 5));
        assert_eq!(info.ea_size, 0);
        assert_eq!((info.creation_time, info.last_write_time), (111, 222));
        assert_eq!(info.unix_mode, inner.unix_mode);
        for (name, size) in [("hole", 70), ("torn", 0), ("empty", 0)] {
            let info = open_file(&layer, name).await.stat().await.unwrap();
            assert_eq!(
                (info.end_of_file, info.allocation_size),
                (size, size),
                "{name}"
            );
        }
    }

    #[tokio::test]
    async fn a_directory_reports_the_size_the_inner_backend_gives_it() {
        let files = MemFsBackend::new();
        let layer = clear_over(files.clone()).await;
        files.clone().with_dir("d").with_dir_size(4096);
        let info = open_dir(&layer, "d").await.stat().await.unwrap();
        assert!(info.is_directory);
        assert_eq!((info.end_of_file, info.allocation_size), (4096, 4096));
    }

    #[tokio::test]
    async fn the_file_id_of_the_inner_backend_passes_through() {
        let files = MemFsBackend::new();
        let layer = clear_over(FileIds::new(files.clone())).await;
        files.clone().with_file("f", &stored(b"x"));
        let from_stat = open_file(&layer, "f")
            .await
            .stat()
            .await
            .unwrap()
            .file_index;
        let listed = open_dir(&layer, "").await.list_dir(None).await.unwrap();
        let from_list = listed
            .iter()
            .find(|entry| entry.info.name == "f")
            .unwrap()
            .info
            .file_index;
        assert_ne!(from_stat, 0);
        assert_eq!(from_stat, from_list);
    }

    #[tokio::test]
    async fn stat_waits_for_a_writer_of_the_file() {
        let files = MemFsBackend::new();
        let layer = clear_over(files.clone()).await;
        files.clone().with_file("f", &stored(b"abc"));
        let handle = Arc::new(open_file(&layer, "f").await);
        let writing = handle.node().file().unwrap().write().await;

        let stat = tokio::spawn({
            let handle = Arc::clone(&handle);
            async move { handle.stat().await }
        });
        settle().await;
        assert!(!stat.is_finished());
        drop(writing);
        assert_eq!(stat.await.unwrap().unwrap().end_of_file, 3);
    }

    #[tokio::test]
    async fn writes_and_truncates_of_a_file_are_not_supported() {
        let files = MemFsBackend::new();
        let layer = clear_over(files.clone()).await;
        files.clone().with_file("f", b"abc");
        let handle = open_file(&layer, "f").await;
        assert!(matches!(
            handle.write(0, b"x").await,
            Err(SmbError::NotSupported)
        ));
        assert!(matches!(
            handle.write_owned(0, b"x".to_vec()).await,
            Err(SmbError::NotSupported)
        ));
        assert!(matches!(
            handle.truncate(0).await,
            Err(SmbError::NotSupported)
        ));
        assert_eq!(files.contents("f"), Some(b"abc".to_vec()));
    }

    #[tokio::test]
    async fn a_directory_handle_forwards_data_calls() {
        let files = MemFsBackend::new();
        let layer = clear_over(files.clone()).await;
        files.clone().with_dir("d");
        let handle = open_dir(&layer, "d").await;
        assert!(matches!(
            handle.read(0, 3).await,
            Err(SmbError::IsDirectory)
        ));
        assert!(matches!(
            handle.write(0, b"x").await,
            Err(SmbError::IsDirectory)
        ));
        assert!(matches!(
            handle.write_owned(0, b"x".to_vec()).await,
            Err(SmbError::IsDirectory)
        ));
        assert!(matches!(
            handle.truncate(0).await,
            Err(SmbError::IsDirectory)
        ));
    }

    /// Name, end of file, allocation size and EA size of each entry, by name.
    fn summary(entries: &[DirEntry]) -> Vec<(String, u64, u64, u32)> {
        let mut summary: Vec<_> = entries
            .iter()
            .map(|entry| {
                let info = &entry.info;
                (
                    info.name.clone(),
                    info.end_of_file,
                    info.allocation_size,
                    info.ea_size,
                )
            })
            .collect();
        summary.sort();
        summary
    }

    #[tokio::test]
    async fn a_listing_maps_sizes_and_leaves_out_the_marker_in_the_root_only() {
        let files = MemFsBackend::new();
        let layer = clear_over(files.clone()).await;
        files
            .clone()
            .with_file("f", &stored(b"hello"))
            .with_file("h", &stored_hole(SHIFT, 70))
            .with_dir("d")
            .with_file("d\\.smb-encryption", &stored(b"abc"))
            .with_file("d\\x", &stored(b"xy"))
            .with_ea("f", Ea::new("note", b"value".to_vec()));

        let root = open_dir(&layer, "").await;
        for entries in [
            root.list_dir(None).await.unwrap(),
            root.list_dir_sized(None, true).await.unwrap(),
        ] {
            assert_eq!(
                summary(&entries),
                [
                    ("d".to_string(), 0, 0, 0),
                    ("f".to_string(), 5, 5, 0),
                    ("h".to_string(), 70, 70, 0),
                ]
            );
        }

        let below = open_dir(&layer, "d").await;
        assert_eq!(
            summary(&below.list_dir(None).await.unwrap()),
            [
                (".smb-encryption".to_string(), 3, 3, 0),
                ("x".to_string(), 2, 2, 0),
            ]
        );
    }

    #[tokio::test]
    async fn the_marker_is_left_out_by_the_case_rule_of_the_inner_backend() {
        let files = MemFsBackend::new();
        let folded = clear_over(files.clone()).await;
        files.clone().with_file(".SMB-ENCRYPTION", b"");
        let listed = open_dir(&folded, "").await.list_dir(None).await.unwrap();
        assert!(names(listed).is_empty());

        let exact = clear_over(exact_names(&files)).await;
        let listed = open_dir(&exact, "").await.list_dir(None).await.unwrap();
        assert_eq!(names(listed), [".SMB-ENCRYPTION"]);
    }

    #[tokio::test]
    async fn the_inner_backend_gets_every_call_the_handle_does_not_change() {
        let recorder = Recorder::default();
        let layer = EncryptedBackend::new(recorder.clone(), key_schedule(), clear_settings());
        let (handle, action) = layer
            .open_handle(&path("Dir\\File.TXT"), OpenOptions::default())
            .await
            .unwrap();
        assert_eq!(action, OpenAction::Opened);
        assert!(handle.as_any().is_none());

        handle.flush().await.unwrap();
        let times = FileTimes {
            last_write_time: Some(5),
            ..FileTimes::default()
        };
        handle.set_times(times).await.unwrap();
        handle.set_attributes(0x20).await.unwrap();
        assert_eq!(handle.link_count().await.unwrap(), 3);
        assert!(handle.dir_is_empty().await.unwrap());
        let listed = handle.list_dir(Some("*.TXT")).await.unwrap();
        assert_eq!(names(listed), ["x"]);
        handle.list_dir_sized(Some("a*"), true).await.unwrap();
        let mut watch = handle.watch().await.unwrap().expect("the inner watch");
        assert_eq!(
            watch.next().await,
            Some(vec![DirChange::new("seen", DirChangeKind::Added, false)])
        );
        Box::new(handle).close().await.unwrap();

        assert_eq!(
            recorder.calls(),
            [
                "capabilities".to_string(),
                format!("open Dir\\File.TXT {:?}", OpenOptions::default()),
                "stat".to_string(),
                "flush".to_string(),
                format!("set_times {times:?}"),
                "set_attributes 32".to_string(),
                "link_count".to_string(),
                "dir_is_empty".to_string(),
                "list_dir_sized Some(\"*.TXT\") false".to_string(),
                "list_dir_sized Some(\"a*\") false".to_string(),
                "watch".to_string(),
                "close".to_string(),
            ]
        );
    }

    #[tokio::test]
    async fn a_directory_is_empty_when_the_inner_backend_says_so() {
        let files = MemFsBackend::new();
        let layer = clear_over(files.clone()).await;
        files
            .clone()
            .with_dir("empty")
            .with_dir("full")
            .with_file("full\\f", b"")
            .with_dir("named")
            .with_file("named\\.smb-encryption", b"");
        for (name, empty) in [("empty", true), ("full", false), ("named", false)] {
            let dir = open_dir(&layer, name).await;
            assert_eq!(dir.dir_is_empty().await.unwrap(), empty, "{name}");
        }
    }

    #[tokio::test]
    async fn a_root_that_holds_only_the_marker_is_empty() {
        let files = MemFsBackend::new();
        let layer = clear_over(files.clone()).await;
        let root = open_dir(&layer, "").await;
        assert_eq!(
            files.contents(MARKER_NAME).map(|marker| marker.len()),
            Some(60)
        );
        assert!(root.dir_is_empty().await.unwrap());

        files.clone().with_file("f", b"");
        assert!(!root.dir_is_empty().await.unwrap());
        files.remove("f");
        files.clone().with_dir("d");
        assert!(!root.dir_is_empty().await.unwrap());
    }

    /// A directory handle that reports entries and lists none, as an inner
    /// backend does when it hides some.
    struct Hiding;

    #[async_trait]
    impl Handle for Hiding {
        async fn read(&self, _offset: u64, _len: u32) -> SmbResult<Bytes> {
            Err(SmbError::NotSupported)
        }

        async fn write(&self, _offset: u64, _data: &[u8]) -> SmbResult<u32> {
            Err(SmbError::NotSupported)
        }

        async fn flush(&self) -> SmbResult<()> {
            Ok(())
        }

        async fn stat(&self) -> SmbResult<FileInfo> {
            Ok(FileInfo::new(""))
        }

        async fn set_times(&self, _times: FileTimes) -> SmbResult<()> {
            Ok(())
        }

        async fn set_attributes(&self, _attributes: u32) -> SmbResult<()> {
            Ok(())
        }

        async fn truncate(&self, _len: u64) -> SmbResult<()> {
            Err(SmbError::NotSupported)
        }

        async fn list_dir(&self, _pattern: Option<&str>) -> SmbResult<Vec<DirEntry>> {
            Ok(Vec::new())
        }

        async fn close(self: Box<Self>) -> SmbResult<()> {
            Ok(())
        }

        async fn dir_is_empty(&self) -> SmbResult<bool> {
            Ok(false)
        }
    }

    #[tokio::test]
    async fn a_root_with_entries_that_the_inner_listing_hides_is_not_empty() {
        let layer = clear_over(MemFsBackend::new()).await;
        let node = layer.shared.nodes.attach(&Found {
            path: &SmbPath::root(),
            file_index: 0,
            directory: true,
            origin: Origin::Opened,
            names: NameMatch::Folded,
        });
        let root = EncryptedHandle::new(Box::new(Hiding), node, Arc::clone(&layer.shared));
        assert!(!root.dir_is_empty().await.unwrap());
    }

    #[tokio::test]
    async fn closing_closes_the_inner_handle_drops_the_node_and_returns_the_inner_result() {
        let files = MemFsBackend::new();
        let faulty = Faulty::new(files.clone());
        let layer = clear_over(faulty.clone()).await;
        files.clone().with_file("f", b"");
        let handle = open_file(&layer, "f").await;
        assert_eq!((layer.node_count(), files.open_handles()), (1, 1));

        faulty.fail_close(1, SmbError::Io(io::Error::other("injected")));
        assert!(matches!(
            Box::new(handle).close().await,
            Err(SmbError::Io(_))
        ));
        assert_eq!((layer.node_count(), files.open_handles()), (0, 0));

        let handle = open_file(&layer, "f").await;
        Box::new(handle).close().await.unwrap();
        assert_eq!((layer.node_count(), files.open_handles()), (0, 0));
    }

    /// A watch that returns what it was given and then stops.
    struct Script {
        batches: VecDeque<Vec<DirChange>>,
    }

    #[async_trait]
    impl DirWatch for Script {
        async fn next(&mut self) -> Option<Vec<DirChange>> {
            self.batches.pop_front()
        }
    }

    fn root_watch(batches: Vec<Vec<DirChange>>, names: NameMatch) -> RootWatch {
        RootWatch {
            inner: Box::new(Script {
                batches: batches.into(),
            }),
            names,
        }
    }

    fn change(name: &str, kind: DirChangeKind) -> DirChange {
        DirChange::new(name, kind, false)
    }

    fn renamed(from: &str, to: &str) -> DirChange {
        change(
            to,
            DirChangeKind::Renamed {
                from: from.to_string(),
            },
        )
    }

    #[tokio::test]
    async fn the_root_watch_drops_changes_of_the_marker() {
        let mut watch = root_watch(
            vec![
                vec![
                    change("a", DirChangeKind::Added),
                    change(MARKER_NAME, DirChangeKind::Modified),
                    change("b", DirChangeKind::Removed),
                ],
                vec![change(MARKER_NAME, DirChangeKind::AttributesChanged)],
                vec![],
                vec![change("c", DirChangeKind::Modified)],
            ],
            NameMatch::Exact,
        );
        assert_eq!(
            watch.next().await,
            Some(vec![
                change("a", DirChangeKind::Added),
                change("b", DirChangeKind::Removed),
            ])
        );
        assert_eq!(
            watch.next().await,
            Some(vec![change("c", DirChangeKind::Modified)]),
            "batches left with nothing are skipped"
        );
        assert_eq!(watch.next().await, None);
    }

    #[tokio::test]
    async fn the_root_watch_follows_the_case_rule_of_the_inner_backend() {
        let spelled = change(".SMB-ENCRYPTION", DirChangeKind::Added);
        let mut folded = root_watch(vec![vec![spelled.clone()]], NameMatch::Folded);
        assert_eq!(folded.next().await, None);
        let mut exact = root_watch(vec![vec![spelled.clone()]], NameMatch::Exact);
        assert_eq!(exact.next().await, Some(vec![spelled]));
    }

    #[tokio::test]
    async fn a_rename_of_the_marker_shows_as_the_other_name_coming_or_going() {
        let mut watch = root_watch(
            vec![vec![
                renamed(MARKER_NAME, "gone"),
                renamed("here", MARKER_NAME),
                renamed(MARKER_NAME, MARKER_NAME),
                renamed("a", "b"),
            ]],
            NameMatch::Exact,
        );
        assert_eq!(
            watch.next().await,
            Some(vec![
                change("gone", DirChangeKind::Added),
                change("here", DirChangeKind::Removed),
                renamed("a", "b"),
            ])
        );
    }

    #[tokio::test]
    async fn the_root_watch_passes_changes_with_no_name_through() {
        let batch = vec![
            change("", DirChangeKind::Lost),
            change("", DirChangeKind::Moved),
            DirChange::new("d", DirChangeKind::Added, true),
            change("", DirChangeKind::Deleted),
        ];
        let mut watch = root_watch(vec![batch.clone()], NameMatch::Folded);
        assert_eq!(watch.next().await, Some(batch));
    }

    /// A watch that has its batch only once the test opens its gate.
    struct Parked {
        gate: Arc<Notify>,
        batch: Option<Vec<DirChange>>,
    }

    #[async_trait]
    impl DirWatch for Parked {
        async fn next(&mut self) -> Option<Vec<DirChange>> {
            self.gate.notified().await;
            self.batch.take()
        }
    }

    #[tokio::test]
    async fn a_dropped_wait_for_the_next_changes_loses_none() {
        let gate = Arc::new(Notify::new());
        let batch = vec![change("a", DirChangeKind::Added)];
        let mut watch = RootWatch {
            inner: Box::new(Parked {
                gate: Arc::clone(&gate),
                batch: Some(batch.clone()),
            }),
            names: NameMatch::Folded,
        };
        tokio::select! {
            biased;
            _ = watch.next() => panic!("nothing has happened yet"),
            () = std::future::ready(()) => {}
        }
        gate.notify_one();
        assert_eq!(watch.next().await, Some(batch));
    }

    #[tokio::test]
    async fn the_changes_of_the_inner_watch_reach_the_client() {
        let recorder = Recorder::default();
        let layer = EncryptedBackend::new(recorder.clone(), key_schedule(), clear_settings());
        for name in ["", "Dir\\File.TXT"] {
            let handle = layer
                .open_handle(&path(name), OpenOptions::default())
                .await
                .unwrap()
                .0;
            let mut watch = handle.watch().await.unwrap().expect("a watch");
            assert_eq!(
                watch.next().await,
                Some(vec![DirChange::new("seen", DirChangeKind::Added, false)])
            );
            assert_eq!(watch.next().await, None);
        }
    }

    #[tokio::test]
    async fn a_directory_without_a_watch_has_none() {
        let files = MemFsBackend::new();
        let layer = clear_over(files.clone()).await;
        files.clone().with_dir("d");
        assert!(open_dir(&layer, "d").await.watch().await.unwrap().is_none());
        assert!(open_dir(&layer, "").await.watch().await.unwrap().is_none());
    }
}
