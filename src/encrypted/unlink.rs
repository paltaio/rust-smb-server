//! Unlinks in a share with encrypted names.
//!
//! An unlink holds the lock of the stored directory exclusively, finds the
//! entry in the names of the directory, and unlinks it in the inner backend.
//! The cached names and the nodes follow, and the side object of a long name
//! goes last.

use tracing::warn;

use super::backend::EncryptedBackend;
use super::inner::is_missing;
use super::names::{StoredKind, classify, side_object_name};
use super::node::{NameMatch, path_key};
use super::resolve::Dir;
use super::scan::DropChange;
use crate::backend::{DirEntry, ShareBackend};
use crate::error::{SmbError, SmbResult};
use crate::path::SmbPath;

/// The entries are all side objects, and there is at least one.
fn only_side_objects(entries: &[DirEntry]) -> bool {
    !entries.is_empty()
        && entries
            .iter()
            .all(|entry| classify(&entry.info.name, false) == StoredKind::SideObject)
}

impl<B: ShareBackend> EncryptedBackend<B> {
    /// Deletes the file or empty directory `name` of the directory `parent`,
    /// whose names are as the client spells them. The caller holds the tree
    /// lock shared.
    pub(super) async fn unlink_entry(&self, parent: &SmbPath, name: &str) -> SmbResult<()> {
        self.in_parent(parent, &|dir| {
            Box::pin(async move { self.unlink_in(&dir, name).await })
        })
        .await
    }

    /// Deletes `name` from the directory `dir`, holding the lock of `dir`.
    ///
    /// With `case_insensitive` on, the entry is the one the names of the
    /// directory give, and an entry that was added from outside is found by
    /// building the names again. A name that the names hold and the inner
    /// backend lacks drops them, which are built again and asked once more. A
    /// second such answer fails with `Sharing`. With it off, the stored name
    /// `name` encrypts to is unlinked as it is.
    ///
    /// Once the inner backend has unlinked the entry, the cached names and the
    /// nodes follow. A directory also drops the cached names below it. The
    /// side object of a long entry is removed last, and a failure there is
    /// logged.
    async fn unlink_in(&self, dir: &Dir, name: &str) -> SmbResult<()> {
        let lock = self
            .shared
            .locks
            .directory(path_key(&dir.stored, NameMatch::Exact));
        let _held = lock.acquire(true).await;
        let canonical = self.stored_name(name)?;
        let listed = self.shared.settings.case_insensitive;
        let mut contradicted = false;
        loop {
            let entry = if listed {
                Some(self.find_entry(&dir.stored, name, &canonical).await?)
            } else {
                None
            };
            let stored = entry
                .as_ref()
                .map_or_else(|| canonical.clone(), |entry| entry.stored.clone());
            let at = dir.stored.join(&stored)?;
            let below = entry.as_ref().filter(|entry| entry.directory).map(|_| &at);
            let mut changing = DropChange::arm(self, &[&dir.stored], below);
            let unlinked = self.unlink_stored(&at).await;
            changing.disarm();
            match unlinked {
                Ok(()) => {
                    self.shared.nodes.unlinked(&at, self.shared.name_match());
                    if let Some(entry) = &entry {
                        self.shared.names.patch(&lock, Some(entry), None);
                        if entry.directory {
                            self.forget_below(&at);
                        }
                    }
                    if let Some(side) = side_object_name(&stored) {
                        self.remove_side_object(&dir.stored, &side).await;
                    }
                    return Ok(());
                }
                Err(SmbError::NotFound) if listed => {
                    self.invalidate(lock.key());
                    if contradicted {
                        return Err(SmbError::Sharing);
                    }
                    contradicted = true;
                }
                Err(error) => {
                    if listed && is_missing(&error) {
                        self.invalidate(lock.key());
                    }
                    return Err(error);
                }
            }
        }
    }

    /// Unlinks the entry at the stored path `at` in the inner backend. The
    /// caller holds the lock of the directory that holds it. A directory that
    /// answers `NotEmpty` is listed under its own lock, taken after that one.
    /// When it holds nothing but side objects, whose entries are gone, those
    /// are removed and the unlink is tried once more.
    async fn unlink_stored(&self, at: &SmbPath) -> SmbResult<()> {
        match self.shared.inner.unlink(at).await {
            Err(SmbError::NotEmpty) => {}
            done => return done,
        }
        let lock = self.shared.locks.directory(path_key(at, NameMatch::Exact));
        let _held = lock.acquire(true).await;
        match self.list_stored(at).await? {
            Some(listed) if only_side_objects(&listed) => {
                for orphan in &listed {
                    self.remove_side_object(at, &orphan.info.name).await;
                }
            }
            Some(_) => return Err(SmbError::NotEmpty),
            None => {}
        }
        self.shared.inner.unlink(at).await
    }

    /// Removes the side object `name` of the stored directory `dir`. A failure
    /// is logged and leaves the object, which listings leave out.
    pub(super) async fn remove_side_object(&self, dir: &SmbPath, name: &str) {
        let removed = match dir.join(name) {
            Ok(at) => self.shared.inner.unlink(&at).await,
            Err(error) => Err(error),
        };
        if let Err(error) = removed {
            warn!(dir = %dir, side_object = ?name, error = ?error, "side object was not removed");
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use super::super::testing::{
        Hidden, Strict, assert_err, drop_at, injected, layer, long_name, names_over, names_with,
        open, open_dir, open_dir_as, open_file, refused, refused_dir, seed_dir, seed_file,
        seed_orphan, settle, spawn_open, stored_at, stored_bytes, stored_form, stored_name,
    };
    use super::*;
    use crate::backend::{Handle, OpenAction, OpenIntent};
    use crate::tests::faulty::Faulty;
    use crate::tests::file_ids::FileIds;
    use crate::tests::gated::{Gated, Op};
    use crate::tests::logs::Logs;
    use crate::tests::memfs::MemFsBackend;
    use crate::tests::util::path;

    #[tokio::test]
    async fn a_file_is_unlinked_under_any_spelling_and_is_gone_from_the_names_and_the_nodes() {
        let (files, layer) = layer().await;
        let (_other, _) = open(&layer, "Other.txt", OpenIntent::Create).await;
        let (made, _) = open(&layer, "Foo.txt", OpenIntent::Create).await;
        let counter = layer.shared.locks.directory(String::new());
        let before = counter.changes();

        layer.unlink(&path("foo.TXT")).await.unwrap();
        assert_eq!(files.contents(&stored_at("Foo.txt")), None);
        assert!(made.node().is_detached());
        assert_eq!(layer.node_count(), 1);
        assert_eq!(counter.changes(), before + 1);
        let names = layer.shared.names.fresh("").expect("the root stays cached");
        assert_eq!(names.len(), 1);
        assert!(names.entry("foo.txt", &stored_name("foo.txt")).is_none());
        assert!(
            names
                .entry("other.txt", &stored_name("other.txt"))
                .is_some()
        );
        drop(names);

        let error = refused(&layer, "Foo.txt", OpenIntent::Open).await;
        assert!(matches!(error, SmbError::NotFound), "{error:?}");
        let (_, action) = open(&layer, "FOO.TXT", OpenIntent::Create).await;
        assert_eq!(action, OpenAction::Created);
        assert_eq!(files.open_handles(), 3);
    }

    #[tokio::test]
    async fn an_unlink_detaches_only_its_own_node_when_files_have_ids() {
        let files = MemFsBackend::new();
        let layer = names_over(FileIds::new(files.clone())).await;
        let (first, _) = open(&layer, "a", OpenIntent::Create).await;
        let (second, _) = open(&layer, "b", OpenIntent::Create).await;

        layer.unlink(&path("A")).await.unwrap();
        assert!(first.node().is_detached());
        assert!(!second.node().is_detached());
        assert_eq!(layer.node_count(), 1);
    }

    #[tokio::test]
    async fn a_directory_is_unlinked_and_the_names_below_it_are_dropped() {
        let (files, layer) = layer().await;
        open_dir_as(&layer, "Docs", OpenIntent::Create).await;
        open_dir_as(&layer, "Docs\\Sub", OpenIntent::Create).await;
        open(&layer, "Docs\\Sub\\x", OpenIntent::Create).await;
        open(&layer, "Docs\\a", OpenIntent::Create).await;
        layer.unlink(&path("Docs\\Sub\\x")).await.unwrap();

        let docs = stored_name("Docs");
        let sub = format!("{docs}\\{}", stored_name("Sub"));
        let mut cached = layer.shared.names.keys();
        cached.sort();
        let mut expected = vec![String::new(), docs.clone(), sub.clone()];
        expected.sort();
        assert_eq!(cached, expected);
        let below = layer.shared.locks.directory(sub.clone());
        let counted = below.changes();
        let docs_counter = layer.shared.locks.directory(docs.clone());
        let docs_counted = docs_counter.changes();

        layer.unlink(&path("DOCS\\sub")).await.unwrap();
        let mut cached = layer.shared.names.keys();
        cached.sort();
        let mut expected = vec![String::new(), docs.clone()];
        expected.sort();
        assert_eq!(cached, expected, "the names of `Sub` are gone");
        assert_eq!(below.changes(), counted + 1);
        assert_eq!(docs_counter.changes(), docs_counted + 1);
        let names = layer.shared.names.fresh(&docs).expect("`Docs` stays");
        assert_eq!(names.len(), 1);
        assert!(names.directory("sub", &stored_name("sub")).is_none());
        drop(names);
        let error = refused_dir(&layer, "Docs\\Sub", OpenIntent::Open).await;
        assert!(matches!(error, SmbError::NotFound), "{error:?}");
        assert!(files.contents(&stored_at("Docs\\a")).is_some());
    }

    #[tokio::test]
    async fn a_missing_name_is_not_found_and_a_missing_directory_is_path_not_found() {
        let (files, layer) = layer().await;
        seed_file(&files, "Docs\\a.txt", &stored_bytes(b"x"));

        for (name, expected) in [
            ("Docs\\missing", SmbError::NotFound),
            ("docs\\MISSING", SmbError::NotFound),
            ("missing", SmbError::NotFound),
            ("nodocs\\a.txt", SmbError::PathNotFound),
            ("Docs\\nope\\a.txt", SmbError::PathNotFound),
            ("docs\\nope\\a.txt", SmbError::PathNotFound),
            ("docs\\a.txt\\x", SmbError::PathNotFound),
        ] {
            assert_err(layer.unlink(&path(name)).await, expected);
        }
        assert!(files.contents(&stored_at("Docs\\a.txt")).is_some());
        assert_eq!(files.open_handles(), 0);
    }

    #[tokio::test]
    async fn a_name_added_from_outside_to_cached_names_is_found_by_building_them_again() {
        let files = MemFsBackend::new();
        let faulty = Faulty::new(files.clone());
        let layer = names_over(faulty.clone()).await;
        open(&layer, "Seed", OpenIntent::Create).await;
        seed_file(&files, "Late.txt", &stored_bytes(b"outside"));
        let listings = || faulty.list_calls().len();
        let before = listings();

        layer.unlink(&path("late.TXT")).await.unwrap();
        assert_eq!(files.contents(&stored_at("Late.txt")), None);
        assert_eq!(listings() - before, 1, "the names are built again once");

        let before = listings();
        let error = layer.unlink(&path("Nowhere")).await.unwrap_err();
        assert!(matches!(error, SmbError::NotFound), "{error:?}");
        assert_eq!(listings() - before, 1, "a name that is not there, once");
        let names = layer.shared.names.fresh("").expect("the new names stay");
        assert!(names.entry("seed", &stored_name("seed")).is_some());
    }

    #[tokio::test(start_paused = true)]
    async fn names_that_this_call_built_are_not_built_again() {
        let files = MemFsBackend::new();
        let faulty = Faulty::new(files.clone());
        let layer = names_over(faulty.clone()).await;
        open(&layer, "Seed", OpenIntent::Create).await;
        tokio::time::advance(Duration::from_secs(31)).await;
        let before = faulty.list_calls().len();

        let error = layer.unlink(&path("Nowhere")).await.unwrap_err();
        assert!(matches!(error, SmbError::NotFound), "{error:?}");
        assert_eq!(faulty.list_calls().len() - before, 1, "one listing");
    }

    #[tokio::test]
    async fn a_name_that_the_store_lacks_is_not_found_once_the_names_are_built_again() {
        let files = MemFsBackend::new();
        let faulty = Faulty::new(files.clone());
        let layer = names_over(faulty.clone()).await;
        open(&layer, "Foo", OpenIntent::Create).await;
        files.remove(&stored_at("Foo"));
        assert!(layer.shared.names.fresh("").is_some());
        let before = faulty.list_calls().len();

        let error = layer.unlink(&path("foo")).await.unwrap_err();
        assert!(matches!(error, SmbError::NotFound), "{error:?}");
        assert_eq!(faulty.list_calls().len() - before, 1, "built again once");
        let names = layer.shared.names.fresh("").expect("the new names stay");
        assert_eq!(names.len(), 0);
    }

    #[tokio::test]
    async fn a_name_that_an_outside_writer_respelled_is_unlinked_under_its_new_spelling() {
        let (files, layer) = layer().await;
        open(&layer, "Foo", OpenIntent::Create).await;
        files.remove(&stored_at("Foo"));
        seed_file(&files, "foo", &stored_bytes(b"outside"));

        layer.unlink(&path("foo")).await.unwrap();
        assert_eq!(files.contents(&stored_at("foo")), None);
        let names = layer.shared.names.fresh("").expect("the new names stay");
        assert_eq!(names.len(), 0);
    }

    #[tokio::test]
    async fn a_name_the_inner_backend_cannot_find_twice_is_a_sharing_violation() {
        let files = MemFsBackend::new();
        let hidden = Hidden::new(files.clone());
        let layer = names_over(hidden.clone()).await;
        seed_file(&files, "Foo", &stored_bytes(b"data"));
        hidden.hide(&stored_at("Foo"));

        let error = layer.unlink(&path("foo")).await.unwrap_err();
        assert!(matches!(error, SmbError::Sharing), "{error:?}");
        assert!(
            layer.shared.names.fresh("").is_none(),
            "the cached names are dropped"
        );
        assert!(files.contents(&stored_at("Foo")).is_some());

        hidden.show(&stored_at("Foo"));
        layer.unlink(&path("foo")).await.unwrap();
        assert_eq!(files.contents(&stored_at("Foo")), None);
    }

    #[tokio::test]
    async fn a_long_entry_goes_before_its_side_object() {
        let files = MemFsBackend::new();
        let gated = Gated::new(files.clone());
        let layer = names_over(gated.clone()).await;
        let long = long_name("x");
        let form = stored_form(&long);
        let side = form.side_object.clone().expect("a long name");
        open(&layer, &long, OpenIntent::Create).await;
        assert!(files.contents(&side.name).is_some());
        let gate = gated.arm_after_at(Op::Unlink, &form.entry);

        let unlinking = tokio::spawn({
            let layer = layer.clone();
            let name = path(&long.to_uppercase());
            async move { layer.unlink(&name).await }
        });
        gate.reached().await;
        assert_eq!(files.contents(&form.entry), None);
        assert_eq!(files.contents(&side.name), Some(side.content.clone()));
        assert_eq!(layer.node_count(), 0, "the nodes follow the entry");
        gate.release();

        unlinking.await.unwrap().unwrap();
        assert_eq!(files.contents(&side.name), None);
        let names = layer.shared.names.fresh("").expect("the root is cached");
        assert_eq!(names.len(), 0);
    }

    #[tokio::test]
    async fn a_side_object_that_cannot_be_removed_is_logged_and_the_unlink_succeeds() {
        let logs = Logs::new();
        let files = MemFsBackend::new();
        let faulty = Faulty::new(files.clone());
        let layer = names_over(faulty.clone()).await;
        let long = long_name("x");
        let form = stored_form(&long);
        let side = form.side_object.clone().expect("a long name");
        open(&layer, &long, OpenIntent::Create).await;
        faulty.fail_unlink(2, injected());

        layer.unlink(&path(&long)).await.unwrap();
        assert_eq!(faulty.unlinks(), 2);
        assert_eq!(files.contents(&form.entry), None);
        assert_eq!(files.contents(&side.name), Some(side.content.clone()));
        let warnings = logs.warnings();
        assert_eq!(warnings.len(), 1, "{warnings:?}");
        assert!(warnings[0].contains(&side.name), "{warnings:?}");

        let (_, action) = open(&layer, &long, OpenIntent::Create).await;
        assert_eq!(action, OpenAction::Created, "the object is reused");
        assert_eq!(files.contents(&side.name), Some(side.content));
    }

    #[tokio::test]
    async fn a_directory_that_holds_only_side_objects_is_unlinked_after_they_are_removed() {
        let files = MemFsBackend::new();
        let faulty = Faulty::new(Strict::new(files.clone()));
        let layer = names_over(faulty.clone()).await;
        seed_dir(&files, "Docs");
        let docs = stored_at("Docs");
        let orphans = [
            seed_orphan(&files, &docs, &long_name("a")),
            seed_orphan(&files, &docs, &long_name("b")),
        ];

        layer.unlink(&path("docs")).await.unwrap();
        assert_eq!(
            faulty.unlinks(),
            4,
            "the directory, two objects, the directory"
        );
        for orphan in &orphans {
            assert_eq!(files.contents(orphan), None);
        }
        let error = refused_dir(&layer, "Docs", OpenIntent::Open).await;
        assert!(matches!(error, SmbError::NotFound), "{error:?}");
        assert_eq!(files.open_handles(), 0);
    }

    #[tokio::test]
    async fn a_directory_with_a_real_entry_is_not_empty_and_keeps_its_side_objects() {
        let files = MemFsBackend::new();
        let faulty = Faulty::new(Strict::new(files.clone()));
        let layer = names_over(faulty.clone()).await;
        seed_file(&files, "Full\\Real.txt", &stored_bytes(b"x"));
        let orphan = seed_orphan(&files, &stored_at("Full"), &long_name("a"));

        let error = layer.unlink(&path("Full")).await.unwrap_err();
        assert!(matches!(error, SmbError::NotEmpty), "{error:?}");
        assert_eq!(faulty.unlinks(), 1, "nothing is removed");
        assert!(files.contents(&orphan).is_some());
        assert!(files.contents(&stored_at("Full\\Real.txt")).is_some());
        assert!(layer.shared.names.fresh("").is_some());
    }

    #[tokio::test]
    async fn a_name_that_is_not_the_shares_counts_as_an_entry_of_the_directory() {
        let files = MemFsBackend::new();
        let layer = names_over(Strict::new(files.clone())).await;
        seed_dir(&files, "Docs");
        let docs = stored_at("Docs");
        let orphan = seed_orphan(&files, &docs, &long_name("a"));
        files.clone().with_file(&format!("{docs}\\junk"), b"");

        let error = layer.unlink(&path("Docs")).await.unwrap_err();
        assert!(matches!(error, SmbError::NotEmpty), "{error:?}");
        assert!(files.contents(&orphan).is_some());
    }

    #[tokio::test]
    async fn the_unlink_is_tried_again_once_after_the_side_objects_are_removed() {
        let files = MemFsBackend::new();
        let faulty = Faulty::new(Strict::new(files.clone()));
        let layer = names_over(faulty.clone()).await;
        seed_dir(&files, "Docs");
        let orphan = seed_orphan(&files, &stored_at("Docs"), &long_name("a"));
        faulty.fail_unlink(3, SmbError::NotEmpty);

        let error = layer.unlink(&path("Docs")).await.unwrap_err();
        assert!(matches!(error, SmbError::NotEmpty), "{error:?}");
        assert_eq!(
            faulty.unlinks(),
            3,
            "the directory, the object, the directory"
        );
        assert_eq!(files.contents(&orphan), None);
        assert!(layer.shared.names.fresh("").is_some());
    }

    #[tokio::test]
    async fn a_directory_that_answers_not_empty_and_lists_nothing_stays_not_empty() {
        let files = MemFsBackend::new();
        let faulty = Faulty::new(files.clone());
        let layer = names_over(faulty.clone()).await;
        seed_dir(&files, "Docs");
        faulty.fail_unlink(1, SmbError::NotEmpty);

        let error = layer.unlink(&path("Docs")).await.unwrap_err();
        assert!(matches!(error, SmbError::NotEmpty), "{error:?}");
        assert_eq!(faulty.unlinks(), 1);
    }

    #[tokio::test]
    async fn removing_the_side_objects_waits_for_a_create_in_the_directory() {
        let files = MemFsBackend::new();
        let gated = Gated::new(Strict::new(files.clone()));
        let layer = names_over(gated.clone()).await;
        seed_dir(&files, "Docs");
        let long = long_name("a");
        let form = stored_form(&long);
        let side = form.side_object.expect("a long name");
        let side_at = format!("{}\\{}", stored_at("Docs"), side.name);
        let entry_at = format!("{}\\{}", stored_at("Docs"), form.entry);
        let gate = gated.arm_at(Op::Open, &entry_at);

        let creating = spawn_open(&layer, &format!("Docs\\{long}"), OpenIntent::Create);
        gate.reached().await;
        assert!(files.contents(&side_at).is_some());
        let unlinking = tokio::spawn({
            let layer = layer.clone();
            async move { layer.unlink(&path("Docs")).await }
        });
        settle().await;
        assert!(!unlinking.is_finished(), "the removal waits for the create");
        assert!(files.contents(&side_at).is_some());

        gate.release();
        let (_, action) = creating.await.unwrap().unwrap();
        assert_eq!(action, OpenAction::Created);
        let error = unlinking.await.unwrap().unwrap_err();
        assert!(matches!(error, SmbError::NotEmpty), "{error:?}");
        assert!(files.contents(&entry_at).is_some());
        assert!(files.contents(&side_at).is_some());
    }

    #[tokio::test]
    async fn an_unlink_holds_the_tree_shared_and_its_directory_exclusively() {
        let files = MemFsBackend::new();
        let gated = Gated::new(files.clone());
        let layer = names_over(gated.clone()).await;
        seed_dir(&files, "Docs");
        seed_file(&files, "Docs\\f", &stored_bytes(b"x"));
        let gate = gated.arm_at(Op::Unlink, &stored_at("Docs\\f"));

        let unlinking = tokio::spawn({
            let layer = layer.clone();
            async move { layer.unlink(&path("docs\\F")).await }
        });
        gate.reached().await;
        let locks = &layer.shared.locks;
        assert!(locks.directory(stored_name("Docs")).is_exclusive());
        assert!(locks.directory(String::new()).is_free());
        assert!(locks.tree.try_write().is_err());
        assert!(locks.tree.try_read().is_ok());

        let creating = spawn_open(&layer, "Docs\\g", OpenIntent::Create);
        settle().await;
        assert!(!creating.is_finished(), "the directory is held");
        gate.release();
        unlinking.await.unwrap().unwrap();
        creating.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn a_rename_queued_behind_an_unlink_does_not_deadlock_it() {
        let files = MemFsBackend::new();
        let gated = Gated::new(files.clone());
        let layer = names_over(gated.clone()).await;
        seed_dir(&files, "Docs");
        seed_file(&files, "Docs\\f", &stored_bytes(b"x"));
        let gate = gated.arm(Op::Unlink);

        let unlinking = tokio::spawn({
            let layer = layer.clone();
            async move { layer.unlink(&path("Docs\\f")).await }
        });
        gate.reached().await;
        let renaming = tokio::spawn({
            let layer = layer.clone();
            async move { drop(layer.shared.locks.tree.write().await) }
        });
        settle().await;
        assert!(!renaming.is_finished(), "the rename queues");

        gate.release();
        settle().await;
        assert!(unlinking.is_finished(), "the unlink ends");
        unlinking.await.unwrap().unwrap();
        renaming.await.unwrap();
    }

    #[tokio::test]
    async fn an_unlink_waits_for_the_open_that_is_getting_its_node() {
        let files = MemFsBackend::new();
        let gated = Gated::new(files.clone());
        let layer = names_over(gated.clone()).await;
        seed_file(&files, "f", &stored_bytes(b"x"));
        let gate = gated.arm_at(Op::Stat, &stored_at("f"));
        let opening = spawn_open(&layer, "f", OpenIntent::Open);
        gate.reached().await;

        let unlinking = tokio::spawn({
            let layer = layer.clone();
            async move { layer.unlink(&path("f")).await }
        });
        settle().await;
        assert!(!unlinking.is_finished());
        assert!(files.contents(&stored_at("f")).is_some());
        gate.release();

        let (opened, _) = opening.await.unwrap().unwrap();
        unlinking.await.unwrap().unwrap();
        assert!(opened.node().is_detached());
        assert_eq!(layer.node_count(), 0);
    }

    #[tokio::test]
    async fn a_listing_that_began_before_the_unlink_of_its_directory_is_not_kept() {
        let files = MemFsBackend::new();
        let gated = Gated::new(files.clone());
        let layer = names_over(gated.clone()).await;
        seed_dir(&files, "Docs");
        let docs = Arc::new(open_dir(&layer, "Docs").await);
        let gate = gated.arm_after_at(Op::ListDir, &stored_at("Docs"));
        let listing = tokio::spawn({
            let docs = Arc::clone(&docs);
            async move { docs.list_dir(None).await }
        });
        gate.reached().await;

        layer.unlink(&path("Docs")).await.unwrap();
        gate.release();
        listing.await.unwrap().unwrap();
        assert!(layer.shared.names.fresh(&stored_name("Docs")).is_none());
        assert!(docs.node().is_detached());
    }

    #[tokio::test]
    async fn without_case_insensitive_the_stored_name_of_the_exact_spelling_is_unlinked() {
        let files = MemFsBackend::new();
        let faulty = Faulty::new(files.clone());
        let layer = names_with(faulty.clone(), |builder| builder.case_insensitive(false)).await;
        let listings = faulty.list_calls().len();
        let (lower, _) = open(&layer, "foo", OpenIntent::Create).await;
        let (upper, _) = open(&layer, "Foo", OpenIntent::Create).await;
        let long = long_name("x");
        let side = stored_form(&long).side_object.expect("a long name");
        open(&layer, &long, OpenIntent::Create).await;

        layer.unlink(&path("Foo")).await.unwrap();
        assert!(upper.node().is_detached() && !lower.node().is_detached());
        assert_eq!(files.contents(&stored_at("Foo")), None);
        assert!(files.contents(&stored_at("foo")).is_some());
        let error = layer.unlink(&path("FOO")).await.unwrap_err();
        assert!(matches!(error, SmbError::NotFound), "{error:?}");

        let before = faulty.unlinks();
        layer.unlink(&path(&long)).await.unwrap();
        assert_eq!(
            faulty.unlinks() - before,
            2,
            "the entry and the side object"
        );
        assert_eq!(files.contents(&side.name), None);
        assert_eq!(faulty.list_calls().len(), listings, "no listings");
        assert!(layer.shared.names.keys().is_empty());
    }

    #[tokio::test]
    async fn an_unlink_that_the_inner_backend_refuses_changes_nothing() {
        let files = MemFsBackend::new();
        let faulty = Faulty::new(files.clone());
        let layer = names_over(faulty.clone()).await;
        let (handle, _) = open(&layer, "Foo", OpenIntent::Create).await;
        let counter = layer.shared.locks.directory(String::new());
        let before = counter.changes();
        faulty.fail_unlink(1, SmbError::AccessDenied);

        let error = layer.unlink(&path("foo")).await.unwrap_err();
        assert!(matches!(error, SmbError::AccessDenied), "{error:?}");
        assert!(!handle.node().is_detached());
        assert_eq!(counter.changes(), before);
        assert!(files.contents(&stored_at("Foo")).is_some());
        let names = layer.shared.names.fresh("").expect("the names stay");
        assert!(names.entry("foo", &stored_name("foo")).is_some());
        let _ = open_file(&layer, "FOO").await;
    }

    #[tokio::test]
    async fn an_unlink_dropped_after_the_inner_unlink_drops_the_names_it_may_have_changed() {
        let files = MemFsBackend::new();
        let gated = Gated::new(files.clone());
        let layer = names_over(gated.clone()).await;
        open_dir_as(&layer, "Docs", OpenIntent::Create).await;
        open(&layer, "Docs\\a", OpenIntent::Create).await;
        layer.unlink(&path("Docs\\a")).await.unwrap();
        assert_eq!(layer.shared.names.keys().len(), 2, "the root and `Docs`");
        let gate = gated.arm_after_at(Op::Unlink, &stored_at("Docs"));

        drop_at(&gate, layer.unlink(&path("docs"))).await;
        assert!(layer.shared.names.keys().is_empty());
        assert!(layer.shared.locks.directory(String::new()).is_free());

        let error = refused_dir(&layer, "DOCS", OpenIntent::Open).await;
        assert!(matches!(error, SmbError::NotFound), "{error:?}");
        let names = layer.shared.names.fresh("").expect("built again");
        assert_eq!(names.len(), 0);
    }
}
