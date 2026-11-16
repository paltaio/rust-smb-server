//! Renames in a share with encrypted names.
//!
//! A rename holds the tree lock exclusively and takes no directory lock. With
//! names that match without regard to case, the entries to move and to
//! replace come from the names of their directories. The new name gets its
//! side object and its entry in the long-name cache before any entry moves,
//! and the side objects of the names that go away are removed after.

use tracing::warn;

use super::backend::EncryptedBackend;
use super::cache::Entry;
use super::inner::is_missing;
use super::names::side_object_name;
use super::node::{NameMatch, path_key};
use super::scan::{DropChange, Hold};
use crate::backend::ShareBackend;
use crate::error::{SmbError, SmbResult};
use crate::path::SmbPath;

/// How a try at a rename ended.
enum Attempt {
    Done,
    /// The inner backend lacks the source that the cached names hold.
    Contradicted,
}

impl<B: ShareBackend> EncryptedBackend<B> {
    /// Renames the entry `from_name` of the directory `from_parent` to
    /// `to_name` in `to_parent`, whose names are as the client spells them.
    /// The caller holds the tree lock exclusively.
    pub(super) async fn rename_entry(
        &self,
        from_parent: &SmbPath,
        from_name: &str,
        to_parent: &SmbPath,
        to_name: &str,
        replace: bool,
    ) -> SmbResult<()> {
        if !self.shared.settings.case_insensitive {
            return self
                .rename_exact(from_parent, from_name, to_parent, to_name, replace)
                .await;
        }
        let mut contradicted = false;
        loop {
            let attempt = self
                .rename_listed(from_parent, from_name, to_parent, to_name, replace)
                .await?;
            match attempt {
                Attempt::Done => return Ok(()),
                Attempt::Contradicted if contradicted => return Err(SmbError::Sharing),
                Attempt::Contradicted => contradicted = true,
            }
        }
    }

    /// Renames with names that match without regard to case.
    ///
    /// The entry `from_name` of `from_parent` is the one the names of its
    /// directory give, and cached names that lack it are built again once. The
    /// entry `to_name` of `to_parent`, if the names of that directory have one,
    /// is the entry the rename meets. It may be the entry that moves, spelled
    /// another way. A source that the names hold and the inner backend lacks
    /// is `Contradicted`: the names are dropped and the caller tries again.
    ///
    /// - The same entry with the same spelling: nothing to do. With another
    ///   spelling the entry is renamed to the stored name of `to_name`.
    /// - Another entry without `replace`: `Exists`. A directory with
    ///   `replace`: `AccessDenied`.
    /// - Another file with `replace`, stored as `to_name` encrypts to: it is
    ///   replaced. Stored under another spelling: the entry replaces it under
    ///   that spelling, then moves to the stored name of `to_name`. If that
    ///   second rename fails, it is logged and the entry stays under the
    ///   spelling of the file it replaced.
    /// - No entry: the inner backend decides about `replace`.
    async fn rename_listed(
        &self,
        from_parent: &SmbPath,
        from_name: &str,
        to_parent: &SmbPath,
        to_name: &str,
        replace: bool,
    ) -> SmbResult<Attempt> {
        let to_form = self.stored_form(to_name)?;
        let from_canonical = self.stored_name(from_name)?;
        let (from_canonical, to_canonical) = (from_canonical.as_str(), to_form.entry.as_str());
        let (from_dir, source) = self
            .in_parent(from_parent, &|dir| {
                Box::pin(async move {
                    let entry = self
                        .find_entry(&dir.stored, from_name, from_canonical)
                        .await?;
                    Ok((dir.stored, entry))
                })
            })
            .await?;
        let (to_dir, existing) = self
            .in_parent(to_parent, &|dir| {
                Box::pin(async move {
                    let names = self
                        .lookup_names(&dir.stored, Hold::Lock)
                        .await?
                        .ok_or(SmbError::PathNotFound)?;
                    let held = names.snapshot.entry(to_name, to_canonical);
                    Ok((dir.stored, held))
                })
            })
            .await?;

        let same_entry = from_dir == to_dir
            && existing
                .as_ref()
                .is_some_and(|held| held.stored == source.stored);
        let replaced = existing.filter(|_| !same_entry);
        if same_entry && source.plain == to_name {
            return Ok(Attempt::Done);
        }
        if let Some(held) = &replaced {
            if !replace {
                return Err(SmbError::Exists);
            }
            if held.directory {
                return Err(SmbError::AccessDenied);
            }
        }

        self.write_long_name(&to_dir, to_name, &to_form).await?;
        let target = Entry {
            plain: to_name.to_string(),
            stored: to_form.entry.clone(),
            directory: source.directory,
        };
        let over = replaced
            .as_ref()
            .filter(|held| held.stored != target.stored)
            .map(|held| Entry {
                directory: source.directory,
                ..held.clone()
            });
        let first = over.as_ref().unwrap_or(&target).clone();
        let moved = self
            .rename_stored(&from_dir, &source, &to_dir, first, replace && !same_entry)
            .await;
        match moved {
            Err(SmbError::NotFound) => return Ok(Attempt::Contradicted),
            moved => moved?,
        }
        let stays = match over {
            Some(over) => match self
                .rename_stored(&to_dir, &over, &to_dir, target.clone(), false)
                .await
            {
                Ok(()) => target,
                Err(error) => {
                    warn!(
                        dir = %to_dir,
                        stored = ?over.stored,
                        wanted = ?target.stored,
                        error = ?error,
                        "renamed file keeps the name of the file it replaced"
                    );
                    over
                }
            },
            None => target,
        };

        let kept = (&to_dir, stays.stored.as_str());
        self.drop_side_object(&from_dir, &source.stored, kept).await;
        if let Some(held) = &replaced {
            self.drop_side_object(&to_dir, &held.stored, kept).await;
        }
        Ok(Attempt::Done)
    }

    /// Renames with exact names: the inner backend decides about `replace`,
    /// and nothing is cached.
    async fn rename_exact(
        &self,
        from_parent: &SmbPath,
        from_name: &str,
        to_parent: &SmbPath,
        to_name: &str,
        replace: bool,
    ) -> SmbResult<()> {
        let from_form = self.stored_form(from_name)?;
        let to_form = self.stored_form(to_name)?;
        let from_dir = self.stored_path(from_parent)?;
        let to_dir = self.stored_path(to_parent)?;
        let from_at = from_dir.join(&from_form.entry)?;
        let to_at = to_dir.join(&to_form.entry)?;
        self.write_long_name(&to_dir, to_name, &to_form).await?;
        self.shared.inner.rename(&from_at, &to_at, replace).await?;
        self.shared
            .nodes
            .renamed(&from_at, &to_at, self.shared.name_match());
        let kept = (&to_dir, to_form.entry.as_str());
        self.drop_side_object(&from_dir, &from_form.entry, kept)
            .await;
        Ok(())
    }

    /// Renames the entry `from` of the stored directory `from_dir` to `to` in
    /// `to_dir` in the inner backend, which replaces a file there if `replace`.
    /// Then the nodes follow, and the cached names of the two directories:
    /// `from` is gone from the first, `to` is in the second. A directory also
    /// drops the cached names at and below its old path.
    async fn rename_stored(
        &self,
        from_dir: &SmbPath,
        from: &Entry,
        to_dir: &SmbPath,
        to: Entry,
        replace: bool,
    ) -> SmbResult<()> {
        let from_at = from_dir.join(&from.stored)?;
        let to_at = to_dir.join(&to.stored)?;
        let below = from.directory.then_some(&from_at);
        let mut changing = DropChange::arm(self, &[from_dir, to_dir], below);
        let renamed = self.shared.inner.rename(&from_at, &to_at, replace).await;
        changing.disarm();
        if let Err(error) = renamed {
            if is_missing(&error) {
                self.invalidate(&path_key(from_dir, NameMatch::Exact));
                self.invalidate(&path_key(to_dir, NameMatch::Exact));
            }
            return Err(error);
        }
        self.shared
            .nodes
            .renamed(&from_at, &to_at, self.shared.name_match());
        let locks = &self.shared.locks;
        let names = &self.shared.names;
        let source = locks.directory(path_key(from_dir, NameMatch::Exact));
        if from_dir == to_dir {
            names.patch(&source, Some(from), Some(to));
        } else {
            names.patch(&source, Some(from), None);
            let target = locks.directory(path_key(to_dir, NameMatch::Exact));
            names.patch(&target, None, Some(to));
        }
        if from.directory {
            self.forget_below(&from_at);
        }
        Ok(())
    }

    /// Removes the side object of the long entry `stored` of the stored
    /// directory `dir`, unless `kept`, the directory and stored name of an
    /// entry that stays, is the entry.
    async fn drop_side_object(&self, dir: &SmbPath, stored: &str, kept: (&SmbPath, &str)) {
        if (dir, stored) == kept {
            return;
        }
        if let Some(side) = side_object_name(stored) {
            self.remove_side_object(dir, &side).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::super::handle::EncryptedHandle;
    use super::super::testing::{
        Hidden, assert_err, drop_at, fail_open_of, has, injected, layer, long_name,
        names as listed_names, names_over, names_with, open, open_dir, open_dir_as, open_file,
        read_all, seed_dir, seed_file, settle, shares_node, spawn_open, stored_at, stored_bytes,
        stored_form, stored_name,
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
    async fn a_case_only_rename_moves_a_file_to_its_new_spelling() {
        let files = MemFsBackend::new();
        let faulty = Faulty::new(files.clone());
        let layer = names_over(faulty.clone()).await;
        let (handle, _) = open(&layer, "report.txt", OpenIntent::Create).await;
        handle.write(0, b"hello").await.unwrap();
        let counter = layer.shared.locks.directory(String::new());
        let (renames, changes) = (faulty.renames(), counter.changes());

        layer
            .rename(&path("REPORT.txt"), &path("Report.TXT"), false)
            .await
            .unwrap();
        assert_eq!(faulty.renames() - renames, 1);
        assert_eq!(counter.changes() - changes, 1);
        assert_eq!(files.contents(&stored_at("report.txt")), None);
        assert!(files.contents(&stored_at("Report.TXT")).is_some());
        assert_eq!(handle.node().path(), path(&stored_at("Report.TXT")));
        let names = layer.shared.names.fresh("").expect("the root stays cached");
        assert_eq!(names.len(), 1);
        assert_eq!(names.entry("report.txt", "x").unwrap().plain, "Report.TXT");
        drop(names);

        let again = open_file(&layer, "report.txt").await;
        assert!(shares_node(&handle, &again));
        assert_eq!(again.stat().await.unwrap().name, "Report.TXT");
        assert_eq!(read_all(&again).await, b"hello");
    }

    #[tokio::test]
    async fn a_case_only_rename_moves_a_directory_and_what_is_below_it() {
        let (files, layer) = layer().await;
        open_dir_as(&layer, "docs", OpenIntent::Create).await;
        let (below, _) = open(&layer, "docs\\a.txt", OpenIntent::Create).await;
        let docs = open_dir(&layer, "docs").await;
        assert!(layer.shared.names.keys().contains(&stored_name("docs")));

        layer
            .rename(&path("DOCS"), &path("Docs"), false)
            .await
            .unwrap();
        assert!(files.contents(&stored_at("Docs\\a.txt")).is_some());
        assert_eq!(files.contents(&stored_at("docs\\a.txt")), None);
        assert_eq!(below.node().path(), path(&stored_at("Docs\\a.txt")));
        assert_eq!(docs.node().path(), path(&stored_at("Docs")));
        assert!(!layer.shared.names.keys().contains(&stored_name("docs")));

        let found = open_file(&layer, "DOCS\\A.TXT").await;
        assert!(shares_node(&below, &found));
        assert_eq!(found.stat().await.unwrap().name, "a.txt");
        let again = open_dir(&layer, "docs").await;
        assert!(shares_node(&docs, &again));
        assert_eq!(again.stat().await.unwrap().name, "Docs");
    }

    #[tokio::test]
    async fn a_rename_to_the_spelling_the_entry_has_does_nothing() {
        let files = MemFsBackend::new();
        let faulty = Faulty::new(files.clone());
        let layer = names_over(faulty.clone()).await;
        let (handle, _) = open(&layer, "Foo", OpenIntent::Create).await;
        let counter = layer.shared.locks.directory(String::new());
        let changes = counter.changes();

        for (from, replace) in [("Foo", false), ("FOO", false), ("foo", true), ("Foo", true)] {
            layer
                .rename(&path(from), &path("Foo"), replace)
                .await
                .unwrap();
        }
        assert_eq!(faulty.renames(), 0);
        assert_eq!(counter.changes(), changes);
        assert_eq!(handle.node().path(), path(&stored_at("Foo")));
        assert!(files.contents(&stored_at("Foo")).is_some());
    }

    /// A store with `report.TXT` holding "old" and `new.tmp` holding "new!",
    /// and a handle on each.
    async fn replace_scene() -> (
        MemFsBackend,
        Faulty<MemFsBackend>,
        EncryptedBackend<Faulty<MemFsBackend>>,
        [EncryptedHandle<Faulty<MemFsBackend>>; 2],
    ) {
        let files = MemFsBackend::new();
        let faulty = Faulty::new(files.clone());
        let layer = names_over(faulty.clone()).await;
        let (old, _) = open(&layer, "report.TXT", OpenIntent::Create).await;
        old.write(0, b"old").await.unwrap();
        let (new, _) = open(&layer, "new.tmp", OpenIntent::Create).await;
        new.write(0, b"new!").await.unwrap();
        (files, faulty, layer, [old, new])
    }

    #[tokio::test]
    async fn a_replace_onto_a_case_variant_renames_twice_and_ends_under_the_new_spelling() {
        let (files, faulty, layer, [old, new]) = replace_scene().await;
        let moved = files.contents(&stored_at("new.tmp")).unwrap();
        let renames = faulty.renames();

        layer
            .rename(&path("NEW.tmp"), &path("Report.txt"), true)
            .await
            .unwrap();
        assert_eq!(faulty.renames() - renames, 2);
        assert_eq!(files.contents(&stored_at("report.TXT")), None);
        assert_eq!(files.contents(&stored_at("new.tmp")), None);
        assert_eq!(files.contents(&stored_at("Report.txt")), Some(moved));
        assert!(old.node().is_detached());
        assert_eq!(new.node().path(), path(&stored_at("Report.txt")));
        let names = layer.shared.names.fresh("").expect("the root stays cached");
        assert_eq!(names.len(), 1);
        assert_eq!(names.entry("report.txt", "x").unwrap().plain, "Report.txt");
        drop(names);

        let found = open_file(&layer, "REPORT.TXT").await;
        assert!(shares_node(&new, &found));
        assert_eq!(read_all(&found).await, b"new!");
    }

    #[tokio::test]
    async fn a_second_rename_that_fails_is_logged_and_the_file_keeps_the_spelling_it_replaced() {
        let logs = Logs::new();
        let (files, faulty, layer, [old, new]) = replace_scene().await;
        let moved = files.contents(&stored_at("new.tmp")).unwrap();
        let renames = faulty.renames();
        faulty.fail_rename(2, injected());

        layer
            .rename(&path("new.tmp"), &path("Report.txt"), true)
            .await
            .unwrap();
        assert_eq!(faulty.renames() - renames, 2);
        assert_eq!(files.contents(&stored_at("report.TXT")), Some(moved));
        assert_eq!(files.contents(&stored_at("Report.txt")), None);
        assert_eq!(files.contents(&stored_at("new.tmp")), None);
        assert!(old.node().is_detached());
        assert_eq!(new.node().path(), path(&stored_at("report.TXT")));
        let names = layer.shared.names.fresh("").expect("the root stays cached");
        assert_eq!(names.len(), 1);
        assert_eq!(names.entry("REPORT.txt", "x").unwrap().plain, "report.TXT");
        drop(names);
        let warnings = logs.warnings();
        assert_eq!(warnings.len(), 1, "{warnings:?}");
        assert!(
            warnings[0].contains(&stored_name("report.TXT")),
            "{warnings:?}"
        );

        let found = open_file(&layer, "Report.txt").await;
        assert!(shares_node(&new, &found));
        assert_eq!(found.stat().await.unwrap().name, "report.TXT");
    }

    #[tokio::test]
    async fn a_replace_onto_the_same_spelling_renames_once() {
        let (files, faulty, layer, [old, new]) = replace_scene().await;
        let moved = files.contents(&stored_at("new.tmp")).unwrap();
        let renames = faulty.renames();

        layer
            .rename(&path("new.tmp"), &path("report.TXT"), true)
            .await
            .unwrap();
        assert_eq!(faulty.renames() - renames, 1);
        assert_eq!(files.contents(&stored_at("report.TXT")), Some(moved));
        assert_eq!(files.contents(&stored_at("new.tmp")), None);
        assert!(old.node().is_detached());
        assert_eq!(new.node().path(), path(&stored_at("report.TXT")));
        assert_eq!(layer.shared.names.fresh("").unwrap().len(), 1);
    }

    #[tokio::test]
    async fn a_rename_onto_a_directory_exists_without_replace_and_is_denied_with_it() {
        let files = MemFsBackend::new();
        let faulty = Faulty::new(files.clone());
        let layer = names_over(faulty.clone()).await;
        let (dir, _) = open_dir_as(&layer, "Dir", OpenIntent::Create).await;
        let (file, _) = open(&layer, "File", OpenIntent::Create).await;
        let (src, _) = open(&layer, "src", OpenIntent::Create).await;
        let renames = faulty.renames();

        for to in ["Dir", "dir"] {
            let error = layer
                .rename(&path("src"), &path(to), false)
                .await
                .unwrap_err();
            assert!(matches!(error, SmbError::Exists), "{to}: {error:?}");
        }
        for to in ["Dir", "DIR"] {
            let error = layer
                .rename(&path("src"), &path(to), true)
                .await
                .unwrap_err();
            assert!(matches!(error, SmbError::AccessDenied), "{to}: {error:?}");
        }
        for to in ["File", "file"] {
            let error = layer
                .rename(&path("src"), &path(to), false)
                .await
                .unwrap_err();
            assert!(matches!(error, SmbError::Exists), "{to}: {error:?}");
        }
        assert_eq!(
            faulty.renames(),
            renames,
            "nothing reached the inner backend"
        );
        assert!(files.contents(&stored_at("src")).is_some());
        assert!(files.contents(&stored_at("File")).is_some());
        assert_eq!(src.node().path(), path(&stored_at("src")));
        assert!(!dir.node().is_detached() && !file.node().is_detached());
        assert_eq!(layer.shared.names.fresh("").unwrap().len(), 3);
    }

    #[tokio::test]
    async fn the_cache_of_long_names_and_the_new_side_object_come_before_the_inner_rename() {
        let files = MemFsBackend::new();
        let gated = Gated::new(files.clone());
        let layer = names_over(gated.clone()).await;
        let (handle, _) = open(&layer, "a.txt", OpenIntent::Create).await;
        let long = long_name("x");
        let form = stored_form(&long);
        let side = form.side_object.clone().expect("a long name");
        let gate = gated.arm_at(Op::Rename, &stored_at("a.txt"));

        let renaming = tokio::spawn({
            let layer = layer.clone();
            let to = path(&long);
            async move { layer.rename(&path("a.txt"), &to, false).await }
        });
        gate.reached().await;
        assert_eq!(layer.shared.long_names.get(&form.entry), Some(long.clone()));
        assert_eq!(files.contents(&side.name), Some(side.content.clone()));
        assert_eq!(files.contents(&form.entry), None);
        assert!(files.contents(&stored_at("a.txt")).is_some());
        assert_eq!(handle.node().path(), path(&stored_at("a.txt")));
        gate.release();

        renaming.await.unwrap().unwrap();
        assert!(files.contents(&form.entry).is_some());
        assert_eq!(handle.node().path(), path(&form.entry));
        let found = open_file(&layer, &long.to_uppercase()).await;
        assert_eq!(found.stat().await.unwrap().name, long);
        assert!(shares_node(&handle, &found));
    }

    #[tokio::test]
    async fn the_side_object_of_the_old_name_goes_after_the_inner_rename() {
        let files = MemFsBackend::new();
        let gated = Gated::new(files.clone());
        let layer = names_over(gated.clone()).await;
        let (old, new) = (long_name("x"), long_name("y"));
        let (old_form, new_form) = (stored_form(&old), stored_form(&new));
        let old_side = old_form.side_object.clone().expect("a long name");
        let new_side = new_form.side_object.clone().expect("a long name");
        open(&layer, &old, OpenIntent::Create).await;

        for (to, to_form) in [
            (&new, &new_form),
            (&"short.txt".to_string(), &stored_form("short.txt")),
        ] {
            let gate = gated.arm_after_at(Op::Rename, &stored_name(&old));
            let renaming = tokio::spawn({
                let layer = layer.clone();
                let (from, to) = (path(&old), path(to));
                async move { layer.rename(&from, &to, false).await }
            });
            gate.reached().await;
            assert!(files.contents(&to_form.entry).is_some());
            assert_eq!(files.contents(&old_form.entry), None);
            assert_eq!(
                files.contents(&old_side.name),
                Some(old_side.content.clone()),
                "the old side object waits for the entry"
            );
            gate.release();
            renaming.await.unwrap().unwrap();
            assert_eq!(files.contents(&old_side.name), None);
            assert_eq!(
                files.contents(&new_side.name).is_some(),
                to_form.side_object.is_some()
            );

            layer.rename(&path(to), &path(&old), false).await.unwrap();
            assert!(files.contents(&old_side.name).is_some());
            assert_eq!(files.contents(&new_side.name), None);
        }
    }

    #[tokio::test]
    async fn a_side_object_that_cannot_be_removed_is_logged_and_the_rename_succeeds() {
        let logs = Logs::new();
        let files = MemFsBackend::new();
        let faulty = Faulty::new(files.clone());
        let layer = names_over(faulty.clone()).await;
        let long = long_name("x");
        let side = stored_form(&long).side_object.expect("a long name");
        open(&layer, &long, OpenIntent::Create).await;
        faulty.fail_unlink(1, injected());

        layer
            .rename(&path(&long), &path("short.txt"), false)
            .await
            .unwrap();
        assert!(files.contents(&stored_at("short.txt")).is_some());
        assert_eq!(files.contents(&side.name), Some(side.content));
        let warnings = logs.warnings();
        assert_eq!(warnings.len(), 1, "{warnings:?}");
        assert!(warnings[0].contains(&stored_form(&long).side_object.unwrap().name));
        let names = layer.shared.names.fresh("").unwrap();
        assert!(has(&names, "short.txt") && !has(&names, &long));
    }

    #[tokio::test]
    async fn a_side_object_that_cannot_be_made_fails_the_rename_before_any_entry_moves() {
        let files = MemFsBackend::new();
        let faulty = Faulty::new(files.clone());
        let layer = names_over(faulty.clone()).await;
        let (handle, _) = open(&layer, "a.txt", OpenIntent::Create).await;
        let long = long_name("x");
        let form = stored_form(&long);
        let side = form.side_object.clone().expect("a long name");
        let counter = layer.shared.locks.directory(String::new());
        let (renames, changes) = (faulty.renames(), counter.changes());
        fail_open_of(&faulty, &side.name);

        let error = layer
            .rename(&path("a.txt"), &path(&long), false)
            .await
            .unwrap_err();
        assert!(matches!(error, SmbError::Io(_)), "{error:?}");
        assert_eq!(faulty.renames(), renames);
        assert_eq!(counter.changes(), changes);
        assert!(files.contents(&stored_at("a.txt")).is_some());
        assert_eq!(files.contents(&form.entry), None);
        assert_eq!(files.contents(&side.name), None);
        assert_eq!(handle.node().path(), path(&stored_at("a.txt")));
        assert!(has(&layer.shared.names.fresh("").unwrap(), "a.txt"));
    }

    #[tokio::test]
    async fn a_replace_onto_a_long_case_variant_leaves_the_side_object_of_the_new_name_only() {
        let (lower, upper) = (long_name("x"), long_name("X"));
        let (lower_form, upper_form) = (stored_form(&lower), stored_form(&upper));
        let lower_side = lower_form.side_object.clone().expect("a long name");
        let upper_side = upper_form.side_object.clone().expect("a long name");

        for second_fails in [false, true] {
            let files = MemFsBackend::new();
            let faulty = Faulty::new(files.clone());
            let layer = names_over(faulty.clone()).await;
            open(&layer, &lower, OpenIntent::Create).await;
            let (src, _) = open(&layer, "src.tmp", OpenIntent::Create).await;
            if second_fails {
                faulty.fail_rename(2, injected());
            }

            layer
                .rename(&path("src.tmp"), &path(&upper), true)
                .await
                .unwrap();
            let case = format!("second fails: {second_fails}");
            let kept = if second_fails {
                &lower_form
            } else {
                &upper_form
            };
            assert!(files.contents(&kept.entry).is_some(), "{case}");
            assert_eq!(src.node().path(), path(&kept.entry), "{case}");
            assert_eq!(
                files.contents(&lower_form.entry).is_some(),
                second_fails,
                "{case}"
            );
            assert_eq!(
                files.contents(&lower_side.name).is_some(),
                second_fails,
                "{case}"
            );
            assert!(files.contents(&upper_side.name).is_some(), "{case}");
            assert_eq!(files.contents(&stored_at("src.tmp")), None, "{case}");
            let names = layer.shared.names.fresh("").unwrap();
            assert_eq!(names.len(), 1, "{case}");
            let plain = if second_fails { &lower } else { &upper };
            assert_eq!(&names.entry(&lower, "x").unwrap().plain, plain, "{case}");
        }
    }

    #[tokio::test]
    async fn a_long_name_moved_to_another_directory_takes_its_side_object_with_it() {
        let (files, layer) = layer().await;
        open_dir_as(&layer, "A", OpenIntent::Create).await;
        open_dir_as(&layer, "B", OpenIntent::Create).await;
        let long = long_name("x");
        let side = stored_form(&long).side_object.expect("a long name");
        open(&layer, &format!("A\\{long}"), OpenIntent::Create).await;
        let side_at = |dir: &str| format!("{}\\{}", stored_name(dir), side.name);
        assert!(files.contents(&side_at("A")).is_some());

        layer
            .rename(
                &path(&format!("A\\{long}")),
                &path(&format!("b\\{long}")),
                false,
            )
            .await
            .unwrap();
        assert_eq!(files.contents(&side_at("A")), None);
        assert_eq!(files.contents(&side_at("B")), Some(side.content));
        assert!(files.contents(&stored_at(&format!("B\\{long}"))).is_some());
        assert_eq!(files.contents(&stored_at(&format!("A\\{long}"))), None);
    }

    #[tokio::test]
    async fn a_directory_rename_moves_every_node_below_and_drops_the_names_below() {
        let files = MemFsBackend::new();
        let gated = Gated::new(files.clone());
        let layer = names_over(gated.clone()).await;
        open_dir_as(&layer, "Docs", OpenIntent::Create).await;
        open_dir_as(&layer, "Docs\\Sub", OpenIntent::Create).await;
        let (deep, _) = open(&layer, "Docs\\Sub\\f", OpenIntent::Create).await;
        let (shallow, _) = open(&layer, "Docs\\a", OpenIntent::Create).await;
        let docs = open_dir(&layer, "Docs").await;
        let sub = Arc::new(open_dir(&layer, "Docs\\Sub").await);
        let other = open(&layer, "Other", OpenIntent::Create).await.0;
        let (docs_key, sub_key) = (stored_name("Docs"), stored_at("Docs\\Sub"));
        let cached = layer.shared.names.keys();
        assert!(cached.contains(&docs_key) && cached.contains(&sub_key));

        let gate = gated.arm_after_at(Op::ListDir, &sub_key);
        let listing = tokio::spawn({
            let sub = Arc::clone(&sub);
            async move { sub.list_dir(None).await }
        });
        gate.reached().await;
        layer
            .rename(&path("docs"), &path("Moved"), false)
            .await
            .unwrap();

        assert_eq!(deep.node().path(), path(&stored_at("Moved\\Sub\\f")));
        assert_eq!(shallow.node().path(), path(&stored_at("Moved\\a")));
        assert_eq!(docs.node().path(), path(&stored_at("Moved")));
        assert_eq!(sub.node().path(), path(&stored_at("Moved\\Sub")));
        assert_eq!(other.node().path(), path(&stored_at("Other")));
        let cached = layer.shared.names.keys();
        assert_eq!(
            cached,
            [String::new()],
            "only the root is cached: {cached:?}"
        );
        let root = layer.shared.names.fresh("").unwrap();
        assert!(has(&root, "Moved") && !has(&root, "Docs"));
        drop(root);

        gate.release();
        listing.await.unwrap().unwrap();
        assert!(
            layer.shared.names.fresh(&sub_key).is_none(),
            "the listing began before the rename"
        );
        assert!(layer.shared.names.fresh(&docs_key).is_none());

        let found = open_file(&layer, "MOVED\\sub\\F").await;
        assert!(shares_node(&deep, &found));
        assert_eq!(layer.node_count(), 5);
    }

    #[tokio::test]
    async fn a_name_added_from_outside_to_cached_names_is_found_by_a_rename() {
        let files = MemFsBackend::new();
        let faulty = Faulty::new(files.clone());
        let layer = names_over(faulty.clone()).await;
        open(&layer, "Seed", OpenIntent::Create).await;
        seed_file(&files, "Late.txt", &stored_bytes(b"outside"));
        let before = faulty.list_calls().len();

        layer
            .rename(&path("late.TXT"), &path("Moved.txt"), false)
            .await
            .unwrap();
        assert_eq!(faulty.list_calls().len() - before, 1, "built again once");
        assert_eq!(files.contents(&stored_at("Late.txt")), None);
        assert_eq!(
            files.contents(&stored_at("Moved.txt")),
            Some(stored_bytes(b"outside"))
        );

        let before = faulty.list_calls().len();
        let error = layer
            .rename(&path("Nowhere"), &path("Else"), false)
            .await
            .unwrap_err();
        assert!(matches!(error, SmbError::NotFound), "{error:?}");
        assert_eq!(faulty.list_calls().len() - before, 1);
        assert_eq!(faulty.renames(), 1);
    }

    #[tokio::test]
    async fn a_missing_source_is_not_found_and_a_missing_directory_is_path_not_found() {
        let (files, layer) = layer().await;
        seed_file(&files, "Docs\\a.txt", &stored_bytes(b"x"));

        for (from, to, expected) in [
            ("Docs\\missing", "Docs\\b", SmbError::NotFound),
            ("missing", "b", SmbError::NotFound),
            ("nodocs\\a.txt", "b", SmbError::PathNotFound),
            ("docs\\nope\\a.txt", "b", SmbError::PathNotFound),
            ("Docs\\a.txt", "nodocs\\b", SmbError::PathNotFound),
            ("docs\\A.TXT", "Docs\\nope\\b", SmbError::PathNotFound),
            ("docs\\a.txt", "docs\\a.txt\\b", SmbError::PathNotFound),
        ] {
            assert_err(layer.rename(&path(from), &path(to), false).await, expected);
        }
        assert!(files.contents(&stored_at("Docs\\a.txt")).is_some());
        assert_eq!(files.open_handles(), 0);
    }

    #[tokio::test]
    async fn a_rename_across_directories_updates_the_names_of_both() {
        let (files, layer) = layer().await;
        open_dir_as(&layer, "A", OpenIntent::Create).await;
        open_dir_as(&layer, "B", OpenIntent::Create).await;
        let (moving, _) = open(&layer, "A\\x", OpenIntent::Create).await;
        open(&layer, "A\\stay", OpenIntent::Create).await;
        open(&layer, "B\\other", OpenIntent::Create).await;
        let (a, b) = (stored_name("A"), stored_name("B"));
        let (a_lock, b_lock) = (
            layer.shared.locks.directory(a.clone()),
            layer.shared.locks.directory(b.clone()),
        );
        let (a_changes, b_changes) = (a_lock.changes(), b_lock.changes());

        layer
            .rename(&path("a\\X"), &path("b\\Y"), false)
            .await
            .unwrap();
        assert_eq!(a_lock.changes() - a_changes, 1);
        assert_eq!(b_lock.changes() - b_changes, 1);
        assert_eq!(files.contents(&stored_at("A\\x")), None);
        assert!(files.contents(&stored_at("B\\Y")).is_some());
        assert_eq!(moving.node().path(), path(&stored_at("B\\Y")));
        let (names_a, names_b) = (
            layer.shared.names.fresh(&a).unwrap(),
            layer.shared.names.fresh(&b).unwrap(),
        );
        assert_eq!(names_a.len(), 1);
        assert!(has(&names_a, "stay") && !has(&names_a, "x"));
        assert_eq!(names_b.len(), 2);
        assert!(has(&names_b, "other") && has(&names_b, "Y"));
    }

    /// A store with `A\src` holding "new!" and the name `old` in `B` holding
    /// "old", and a handle on each.
    async fn across_scene(
        old: &str,
    ) -> (
        MemFsBackend,
        Faulty<MemFsBackend>,
        EncryptedBackend<Faulty<MemFsBackend>>,
        [EncryptedHandle<Faulty<MemFsBackend>>; 2],
    ) {
        let files = MemFsBackend::new();
        let faulty = Faulty::new(files.clone());
        let layer = names_over(faulty.clone()).await;
        open_dir_as(&layer, "A", OpenIntent::Create).await;
        open_dir_as(&layer, "B", OpenIntent::Create).await;
        let (src, _) = open(&layer, "A\\src", OpenIntent::Create).await;
        src.write(0, b"new!").await.unwrap();
        let (held, _) = open(&layer, &format!("B\\{old}"), OpenIntent::Create).await;
        held.write(0, b"old").await.unwrap();
        (files, faulty, layer, [src, held])
    }

    #[tokio::test]
    async fn a_replace_across_directories_onto_a_case_variant_patches_both_names() {
        let (lower, upper) = (long_name("x"), long_name("X"));
        let (lower_form, upper_form) = (stored_form(&lower), stored_form(&upper));
        let lower_side = lower_form.side_object.clone().expect("a long name");
        let upper_side = upper_form.side_object.clone().expect("a long name");
        let (files, faulty, layer, [src, old]) = across_scene(&lower).await;
        let (a, b) = (stored_name("A"), stored_name("B"));
        let in_b = |name: &str| format!("{b}\\{name}");
        let (a_lock, b_lock) = (
            layer.shared.locks.directory(a.clone()),
            layer.shared.locks.directory(b.clone()),
        );
        let (a_changes, b_changes) = (a_lock.changes(), b_lock.changes());
        let moved = files.contents(&stored_at("A\\src")).unwrap();
        let renames = faulty.renames();

        layer
            .rename(&path("A\\src"), &path(&format!("B\\{upper}")), true)
            .await
            .unwrap();
        assert_eq!(faulty.renames() - renames, 2);
        assert_eq!(files.contents(&stored_at("A\\src")), None);
        assert_eq!(files.contents(&in_b(&lower_form.entry)), None);
        assert_eq!(files.contents(&in_b(&upper_form.entry)), Some(moved));
        assert_eq!(files.contents(&in_b(&lower_side.name)), None);
        assert_eq!(
            files.contents(&in_b(&upper_side.name)),
            Some(upper_side.content)
        );
        assert!(old.node().is_detached());
        assert_eq!(src.node().path(), path(&in_b(&upper_form.entry)));
        assert_eq!(a_lock.changes() - a_changes, 1);
        assert_eq!(b_lock.changes() - b_changes, 2);
        let (names_a, names_b) = (
            layer.shared.names.fresh(&a).unwrap(),
            layer.shared.names.fresh(&b).unwrap(),
        );
        assert_eq!(names_a.len(), 0);
        assert_eq!(names_b.len(), 1);
        assert_eq!(names_b.entry(&lower, "x").unwrap().plain, upper);
    }

    #[tokio::test]
    async fn a_failure_of_the_first_of_two_renames_leaves_both_entries_and_both_names() {
        let (lower, upper) = (long_name("x"), long_name("X"));
        let (files, faulty, layer, [src, old]) = across_scene(&lower).await;
        let (a, b) = (stored_name("A"), stored_name("B"));
        let (a_lock, b_lock) = (
            layer.shared.locks.directory(a.clone()),
            layer.shared.locks.directory(b.clone()),
        );
        let (a_changes, b_changes) = (a_lock.changes(), b_lock.changes());
        let src_at = stored_at("A\\src");
        let old_at = stored_at(&format!("B\\{lower}"));
        let (src_bytes, old_bytes) = (files.contents(&src_at), files.contents(&old_at));
        faulty.fail_rename(1, injected());

        let error = layer
            .rename(&path("A\\src"), &path(&format!("B\\{upper}")), true)
            .await
            .unwrap_err();
        assert!(matches!(error, SmbError::Io(_)), "{error:?}");
        assert_eq!(files.contents(&src_at), src_bytes);
        assert_eq!(files.contents(&old_at), old_bytes);
        assert_eq!(files.contents(&stored_at(&format!("B\\{upper}"))), None);
        assert_eq!(src.node().path(), path(&src_at));
        assert!(!old.node().is_detached());
        assert_eq!(a_lock.changes(), a_changes);
        assert_eq!(b_lock.changes(), b_changes);
        let (names_a, names_b) = (
            layer.shared.names.fresh(&a).unwrap(),
            layer.shared.names.fresh(&b).unwrap(),
        );
        assert!(names_a.len() == 1 && has(&names_a, "src"));
        assert!(names_b.len() == 1 && has(&names_b, &lower));
    }

    #[tokio::test]
    async fn a_rename_across_directories_of_a_source_the_store_lacks_drops_the_target_names() {
        let (files, layer) = layer().await;
        open_dir_as(&layer, "A", OpenIntent::Create).await;
        open_dir_as(&layer, "B", OpenIntent::Create).await;
        open(&layer, "A\\x", OpenIntent::Create).await;
        open(&layer, "B\\y", OpenIntent::Create).await;
        let (a, b) = (stored_name("A"), stored_name("B"));
        files.remove(&stored_at("A\\x"));
        assert!(layer.shared.names.fresh(&a).is_some());
        assert!(layer.shared.names.fresh(&b).is_some());

        let error = layer
            .rename(&path("A\\x"), &path("B\\z"), false)
            .await
            .unwrap_err();
        assert!(matches!(error, SmbError::NotFound), "{error:?}");
        assert!(layer.shared.names.fresh(&b).is_none());
        let names_a = layer.shared.names.fresh(&a).expect("built again");
        assert_eq!(names_a.len(), 0);
    }

    #[tokio::test]
    async fn a_rename_dropped_after_the_inner_rename_drops_the_names_it_may_have_changed() {
        let files = MemFsBackend::new();
        let gated = Gated::new(files.clone());
        let layer = names_over(gated.clone()).await;
        open_dir_as(&layer, "A", OpenIntent::Create).await;
        open_dir_as(&layer, "B", OpenIntent::Create).await;
        open_dir_as(&layer, "A\\Sub", OpenIntent::Create).await;
        open(&layer, "A\\Sub\\f", OpenIntent::Create).await;
        open(&layer, "B\\g", OpenIntent::Create).await;
        assert_eq!(layer.shared.names.keys().len(), 4, "the root, A, B, A\\Sub");
        let gate = gated.arm_after_at(Op::Rename, &stored_at("A\\Sub"));

        drop_at(
            &gate,
            layer.rename(&path("A\\Sub"), &path("B\\Moved"), false),
        )
        .await;
        assert_eq!(layer.shared.names.keys(), [String::new()]);
        assert!(layer.shared.locks.tree.try_write().is_ok());

        let moved = open_dir(&layer, "b\\moved").await;
        assert_eq!(moved.stat().await.unwrap().name, "Moved");
        let names_b = layer.shared.names.fresh(&stored_name("B")).unwrap();
        assert_eq!(names_b.len(), 2);
    }

    #[tokio::test]
    async fn a_listing_in_flight_across_a_directory_rename_lists_every_entry_at_the_new_path() {
        let files = MemFsBackend::new();
        let gated = Gated::new(files.clone());
        let layer = names_over(gated.clone()).await;
        let long = long_name("x");
        seed_dir(&files, "Docs");
        seed_file(&files, "Docs\\a.txt", &stored_bytes(b""));
        seed_file(&files, &format!("Docs\\{long}"), &stored_bytes(b""));
        let docs = Arc::new(open_dir(&layer, "Docs").await);
        let gate = gated.arm_after_at(Op::ListDir, &stored_at("Docs"));
        let listing = tokio::spawn({
            let docs = Arc::clone(&docs);
            async move { docs.list_dir(None).await }
        });
        gate.reached().await;

        layer
            .rename(&path("Docs"), &path("Moved"), false)
            .await
            .unwrap();
        gate.release();
        let listed = listing.await.unwrap().unwrap();
        let mut expected = ["a.txt".to_string(), long.clone()];
        expected.sort();
        assert_eq!(listed_names(&listed), expected);
        assert!(layer.shared.names.fresh(&stored_name("Docs")).is_none());
        let kept = layer.shared.names.fresh(&stored_name("Moved")).unwrap();
        assert!(kept.len() == 2 && has(&kept, &long));
    }

    #[tokio::test]
    async fn a_lookup_in_flight_across_a_directory_rename_finds_the_entry_at_the_new_path() {
        let files = MemFsBackend::new();
        let gated = Gated::new(files.clone());
        let layer = names_over(gated.clone()).await;
        seed_file(&files, "Docs\\Report.TXT", &stored_bytes(b"abc"));
        let docs = Arc::new(open_dir(&layer, "Docs").await);
        let gate = gated.arm_after_at(Op::ListDir, &stored_at("Docs"));
        let looking = tokio::spawn({
            let docs = Arc::clone(&docs);
            async move { docs.list_dir(Some("report.txt")).await }
        });
        gate.reached().await;

        layer
            .rename(&path("Docs"), &path("Moved"), false)
            .await
            .unwrap();
        gate.release();
        let found = looking.await.unwrap().unwrap();
        assert_eq!(listed_names(&found), ["Report.TXT"]);
        assert_eq!(found[0].info.end_of_file, 3);
        assert!(layer.shared.names.fresh(&stored_name("Docs")).is_none());
    }

    #[tokio::test]
    async fn a_directory_moved_to_another_directory_takes_its_nodes_and_drops_its_names() {
        let (files, layer) = layer().await;
        open_dir_as(&layer, "A", OpenIntent::Create).await;
        open_dir_as(&layer, "B", OpenIntent::Create).await;
        open_dir_as(&layer, "A\\Sub", OpenIntent::Create).await;
        let (deep, _) = open(&layer, "A\\Sub\\f", OpenIntent::Create).await;
        let moved = format!("{}\\{}", stored_name("B"), stored_name("Moved"));

        layer
            .rename(&path("A\\sub"), &path("B\\Moved"), false)
            .await
            .unwrap();
        assert_eq!(
            deep.node().path(),
            path(&format!("{moved}\\{}", stored_name("f")))
        );
        assert!(files.contents(&stored_at("B\\Moved\\f")).is_some());
        let sub = format!("{}\\{}", stored_name("A"), stored_name("Sub"));
        assert!(!layer.shared.names.keys().contains(&sub));
        let found = open_file(&layer, "b\\MOVED\\F").await;
        assert!(shares_node(&deep, &found));
    }

    #[tokio::test]
    async fn a_rename_holds_the_tree_exclusively_and_takes_no_directory_lock() {
        let files = MemFsBackend::new();
        let gated = Gated::new(files.clone());
        let layer = names_over(gated.clone()).await;
        open(&layer, "a", OpenIntent::Create).await;
        let gate = gated.arm_at(Op::Rename, &stored_at("a"));

        let renaming = tokio::spawn({
            let layer = layer.clone();
            async move { layer.rename(&path("a"), &path("b"), false).await }
        });
        gate.reached().await;
        let locks = &layer.shared.locks;
        assert!(locks.tree.try_read().is_err());
        assert!(locks.directory(String::new()).is_free());

        let creating = spawn_open(&layer, "c", OpenIntent::Create);
        settle().await;
        assert!(!creating.is_finished(), "an open waits for the rename");
        gate.release();
        renaming.await.unwrap().unwrap();
        creating.await.unwrap().unwrap();
        assert!(files.contents(&stored_at("b")).is_some());
    }

    #[tokio::test]
    async fn a_rename_that_the_inner_backend_refuses_changes_nothing() {
        let files = MemFsBackend::new();
        let faulty = Faulty::new(files.clone());
        let layer = names_over(faulty.clone()).await;
        let (handle, _) = open(&layer, "Foo", OpenIntent::Create).await;
        let counter = layer.shared.locks.directory(String::new());
        let changes = counter.changes();
        faulty.fail_rename(1, SmbError::AccessDenied);

        let error = layer
            .rename(&path("foo"), &path("Bar"), false)
            .await
            .unwrap_err();
        assert!(matches!(error, SmbError::AccessDenied), "{error:?}");
        assert_eq!(counter.changes(), changes);
        assert_eq!(handle.node().path(), path(&stored_at("Foo")));
        assert!(files.contents(&stored_at("Foo")).is_some());
        assert!(has(&layer.shared.names.fresh("").unwrap(), "Foo"));
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

        let error = layer
            .rename(&path("foo"), &path("Bar"), false)
            .await
            .unwrap_err();
        assert!(matches!(error, SmbError::NotFound), "{error:?}");
        assert_eq!(faulty.list_calls().len() - before, 1, "built again once");
        let names = layer.shared.names.fresh("").expect("the new names stay");
        assert_eq!(names.len(), 0);
        let (_, action) = open(&layer, "FOO", OpenIntent::Create).await;
        assert_eq!(action, OpenAction::Created);
    }

    #[tokio::test]
    async fn a_name_that_an_outside_writer_respelled_is_renamed_under_its_new_spelling() {
        let (files, layer) = layer().await;
        open(&layer, "Foo", OpenIntent::Create).await;
        files.remove(&stored_at("Foo"));
        seed_file(&files, "foo", &stored_bytes(b"outside"));

        layer
            .rename(&path("foo"), &path("Bar"), false)
            .await
            .unwrap();
        assert_eq!(files.contents(&stored_at("foo")), None);
        assert_eq!(
            files.contents(&stored_at("Bar")),
            Some(stored_bytes(b"outside"))
        );
        let names = layer.shared.names.fresh("").expect("the new names stay");
        assert_eq!(names.len(), 1);
        assert!(has(&names, "Bar"));
    }

    #[tokio::test]
    async fn a_source_the_inner_backend_cannot_find_twice_is_a_sharing_violation() {
        let files = MemFsBackend::new();
        let hidden = Hidden::new(files.clone());
        let layer = names_over(hidden.clone()).await;
        seed_file(&files, "Foo", &stored_bytes(b"data"));
        hidden.hide(&stored_at("Foo"));

        let error = layer
            .rename(&path("foo"), &path("Bar"), false)
            .await
            .unwrap_err();
        assert!(matches!(error, SmbError::Sharing), "{error:?}");
        assert!(
            layer.shared.names.fresh("").is_none(),
            "the cached names are dropped"
        );
        assert!(files.contents(&stored_at("Foo")).is_some());

        hidden.show(&stored_at("Foo"));
        layer
            .rename(&path("foo"), &path("Bar"), false)
            .await
            .unwrap();
        assert!(files.contents(&stored_at("Bar")).is_some());
    }

    /// Opens `a`, `B` and `c`, renames `a` over `b`, and checks that the node
    /// of `B` is detached and the other two are not, `a` at `b`.
    async fn rename_over_an_open_file<I: ShareBackend>(layer: &EncryptedBackend<I>) {
        let (a, _) = open(layer, "a", OpenIntent::Create).await;
        let (b, _) = open(layer, "B", OpenIntent::Create).await;
        let (c, _) = open(layer, "c", OpenIntent::Create).await;
        layer.rename(&path("A"), &path("b"), true).await.unwrap();
        assert!(b.node().is_detached());
        assert!(!a.node().is_detached() && !c.node().is_detached());
        assert_eq!(a.node().path(), path(&stored_at("b")));
        assert_eq!(c.node().path(), path(&stored_at("c")));
    }

    #[tokio::test]
    async fn a_rename_keeps_the_nodes_of_open_files_and_detaches_the_replaced_one() {
        rename_over_an_open_file(&names_over(MemFsBackend::new()).await).await;
        rename_over_an_open_file(&names_over(FileIds::new(MemFsBackend::new())).await).await;
    }

    #[tokio::test]
    async fn without_case_insensitive_the_inner_backend_decides_on_exact_names() {
        let files = MemFsBackend::new();
        let faulty = Faulty::new(files.clone());
        let layer = names_with(faulty.clone(), |builder| builder.case_insensitive(false)).await;
        let listings = faulty.list_calls().len();
        let (foo, _) = open(&layer, "Foo", OpenIntent::Create).await;
        let (lower, _) = open(&layer, "foo", OpenIntent::Create).await;
        let (dir, _) = open_dir_as(&layer, "Dir", OpenIntent::Create).await;
        open(&layer, "Dir\\inside", OpenIntent::Create).await;

        let error = layer
            .rename(&path("FOO"), &path("x"), false)
            .await
            .unwrap_err();
        assert!(matches!(error, SmbError::NotFound), "{error:?}");
        let error = layer
            .rename(&path("Foo"), &path("foo"), false)
            .await
            .unwrap_err();
        assert!(matches!(error, SmbError::Exists), "{error:?}");
        let error = layer
            .rename(&path("Foo"), &path("Dir"), true)
            .await
            .unwrap_err();
        assert!(matches!(error, SmbError::AccessDenied), "{error:?}");
        assert!(files.contents(&stored_at("Foo")).is_some());

        layer
            .rename(&path("Foo"), &path("Bar"), false)
            .await
            .unwrap();
        assert_eq!(foo.node().path(), path(&stored_at("Bar")));
        layer
            .rename(&path("Bar"), &path("foo"), true)
            .await
            .unwrap();
        assert!(lower.node().is_detached());
        assert_eq!(foo.node().path(), path(&stored_at("foo")));
        layer
            .rename(&path("Dir"), &path("Moved"), false)
            .await
            .unwrap();
        assert_eq!(dir.node().path(), path(&stored_at("Moved")));
        assert!(files.contents(&stored_at("Moved\\inside")).is_some());
        layer
            .rename(&path("foo"), &path("foo"), true)
            .await
            .unwrap();
        assert!(!foo.node().is_detached());

        assert_eq!(faulty.list_calls().len(), listings, "no listings");
        assert!(layer.shared.names.keys().is_empty());
    }

    #[tokio::test]
    async fn without_case_insensitive_the_side_objects_follow_the_names() {
        let files = MemFsBackend::new();
        let gated = Gated::new(files.clone());
        let layer = names_with(gated.clone(), |builder| builder.case_insensitive(false)).await;
        let (old, new) = (long_name("x"), long_name("y"));
        let (old_form, new_form) = (stored_form(&old), stored_form(&new));
        let old_side = old_form.side_object.clone().expect("a long name");
        let new_side = new_form.side_object.clone().expect("a long name");
        open(&layer, &old, OpenIntent::Create).await;
        let gate = gated.arm_at(Op::Rename, &old_form.entry);

        let renaming = tokio::spawn({
            let layer = layer.clone();
            let (from, to) = (path(&old), path(&new));
            async move { layer.rename(&from, &to, false).await }
        });
        gate.reached().await;
        assert_eq!(
            layer.shared.long_names.get(&new_form.entry),
            Some(new.clone())
        );
        assert_eq!(
            files.contents(&new_side.name),
            Some(new_side.content.clone())
        );
        assert!(files.contents(&old_side.name).is_some());
        gate.release();
        renaming.await.unwrap().unwrap();
        assert_eq!(files.contents(&old_side.name), None);
        assert!(files.contents(&new_form.entry).is_some());

        layer.rename(&path(&new), &path(&new), true).await.unwrap();
        assert_eq!(files.contents(&new_side.name), Some(new_side.content));
        assert!(files.contents(&new_form.entry).is_some());
    }
}
