//! Finds and opens the entries of a share with encrypted names, and creates
//! them.
//!
//! A client's name is encrypted and opened as it stands. When the inner
//! backend has no entry of that name, the names of the directory are searched
//! for one that differs only in case, and when a directory on the way is
//! missing, the path is walked from the root the same way. Unlinks and renames
//! find their entries and directories the same way.

use std::pin::Pin;

use super::backend::EncryptedBackend;
use super::cache::Entry;
use super::clear::creates;
use super::handle::OpenResult;
use super::locks::DirLock;
use super::names::{StoredName, encode_name};
use super::node::{NameMatch, path_key};
use super::scan::Hold;
use crate::backend::{OpenIntent, OpenOptions, ShareBackend};
use crate::error::{SmbError, SmbResult};
use crate::path::SmbPath;

/// A directory: the path it is stored under and the path as its names are
/// spelled in plaintext.
#[derive(Clone)]
pub(super) struct Dir {
    pub(super) stored: SmbPath,
    pub(super) plain: SmbPath,
}

/// The boxed future of an operation on a directory.
pub(super) type DirFuture<'a, T> = Pin<Box<dyn Future<Output = SmbResult<T>> + Send + 'a>>;

impl<B: ShareBackend> EncryptedBackend<B> {
    /// Opens the entry `name` of the directory `parent`, whose names are as
    /// the client spells them, and creates it when the intent allows. The
    /// caller holds the tree lock shared. The open holds the lock of the
    /// stored directory it finds the entry in until the handle has its node:
    /// shared to open an existing entry, exclusive to create one.
    ///
    /// The entry is looked up under the stored name `name` encrypts to. When
    /// the inner backend has none, the names of the directory give an entry
    /// that differs in case. A name that matches exactly comes before names
    /// that differ in case, and of those the first by stored name wins. With
    /// `case_insensitive` off only the exact stored name is tried.
    pub(super) async fn open_entry(
        &self,
        parent: &SmbPath,
        name: &str,
        opts: OpenOptions,
    ) -> OpenResult<B> {
        self.in_parent(parent, &|dir| {
            Box::pin(async move { self.open_in(&dir, name, opts).await })
        })
        .await
    }

    /// Runs `op` on the stored directory that `parent` stands for. `op`
    /// answers `PathNotFound` when the directory is missing.
    ///
    /// The directory is first the one the names of `parent` encrypt to. When
    /// `op` finds it missing and names match without regard to case, the path
    /// is walked from the root, and `op` runs on the directory the walk finds.
    /// A directory that the walk found and the inner backend lacks drops the
    /// caches of the directories above it, and the path is walked once more.
    /// A second miss fails with `Sharing`, unless the walk ends in the
    /// directory `op` first found missing: that one is missing.
    pub(super) async fn in_parent<'a, T>(
        &self,
        parent: &SmbPath,
        op: &(dyn Fn(Dir) -> DirFuture<'a, T> + Sync + 'a),
    ) -> SmbResult<T> {
        let dir = Dir {
            stored: self.stored_path(parent)?,
            plain: parent.clone(),
        };
        match op(dir.clone()).await {
            Err(SmbError::PathNotFound) if self.shared.settings.case_insensitive => {}
            done => return done,
        }
        let mut contradicted = false;
        loop {
            let Some(found) = self.walk(parent).await? else {
                return Err(SmbError::PathNotFound);
            };
            let tried = found.stored == dir.stored;
            let answer = if tried {
                Err(SmbError::PathNotFound)
            } else {
                op(found.clone()).await
            };
            if !matches!(answer, Err(SmbError::PathNotFound)) {
                return answer;
            }
            if contradicted {
                return Err(if tried {
                    SmbError::PathNotFound
                } else {
                    SmbError::Sharing
                });
            }
            contradicted = true;
            self.forget_above(&found.stored);
        }
    }

    /// The entry of the stored directory `dir` that `name` stands for, which
    /// encrypts to the stored name `canonical`. The caller holds the lock of
    /// `dir`, or the tree lock exclusively, so the names built here are kept.
    ///
    /// Cached names that lack the entry may be out of date, since another
    /// writer can add entries. They are built again once, and what that
    /// listing lacks is absent. `PathNotFound` when the directory is missing
    /// and `NotFound` when it has no such entry.
    pub(super) async fn find_entry(
        &self,
        dir: &SmbPath,
        name: &str,
        canonical: &str,
    ) -> SmbResult<Entry> {
        let mut rebuilt = false;
        loop {
            let Some(names) = self.lookup_names(dir, Hold::Lock).await? else {
                return Err(SmbError::PathNotFound);
            };
            if let Some(entry) = names.snapshot.entry(name, canonical) {
                return Ok(entry);
            }
            if names.built || rebuilt {
                return Err(SmbError::NotFound);
            }
            self.invalidate(&path_key(dir, NameMatch::Exact));
            rebuilt = true;
        }
    }

    /// Opens `name` in the directory `dir`. An intent that creates goes to
    /// `create_in`; the others hold the lock of `dir` shared.
    async fn open_in(&self, dir: &Dir, name: &str, opts: OpenOptions) -> OpenResult<B> {
        if creates(opts.intent) {
            return self.create_in(dir, name, opts).await;
        }
        let lock = self
            .shared
            .locks
            .directory(path_key(&dir.stored, NameMatch::Exact));
        let _held = lock.acquire(false).await;
        let exact = self.stored_name(name)?;
        let at = dir.stored.join(&exact)?;
        match self.open_stored(&at, &dir.plain.join(name)?, opts).await {
            Err(SmbError::NotFound) if self.shared.settings.case_insensitive => {}
            opened => return opened,
        }
        self.open_listed(dir, &lock, name, &exact, opts)
            .await
            .unwrap_or(Err(SmbError::NotFound))
    }

    /// Opens the entry of the directory `dir` that the cached names give for
    /// `name`, which encrypts to the stored name `canonical`. The caller holds
    /// `lock`, the lock of `dir`. The names are built when the cache has none
    /// that is fresh. `None` when they have no such entry.
    ///
    /// `OpenOrCreate` opens the entry as `Open` does and `OverwriteOrCreate`
    /// as `Truncate` does. `Create` fails with `Exists`.
    ///
    /// A name that the cache holds and the inner backend does not have drops
    /// the cache, which is built again and asked once more. A second such
    /// answer fails with `Sharing`. No snapshot is held while the entry opens,
    /// so a create that follows changes the cached one in place.
    pub(super) async fn open_listed(
        &self,
        dir: &Dir,
        lock: &DirLock,
        name: &str,
        canonical: &str,
        opts: OpenOptions,
    ) -> Option<OpenResult<B>> {
        let mut contradicted = false;
        loop {
            let found = match self.names_of(&dir.stored, Hold::Lock).await {
                Ok(Some(names)) => names.entry(name, canonical)?,
                Ok(None) => return Some(Err(SmbError::PathNotFound)),
                Err(error) => return Some(Err(error)),
            };
            let intent = match opts.intent {
                OpenIntent::Create => return Some(Err(SmbError::Exists)),
                OpenIntent::OpenOrCreate => OpenIntent::Open,
                OpenIntent::OverwriteOrCreate => OpenIntent::Truncate,
                intent => intent,
            };
            let opened = async {
                let at = dir.stored.join(&found.stored)?;
                let plain = dir.plain.join(&found.plain)?;
                self.open_stored(&at, &plain, OpenOptions { intent, ..opts })
                    .await
            }
            .await;
            if !matches!(opened, Err(SmbError::NotFound)) {
                return Some(opened);
            }
            self.invalidate(lock.key());
            if contradicted {
                return Some(Err(SmbError::Sharing));
            }
            contradicted = true;
        }
    }

    /// The directory that `dir` names, found from the root through the names
    /// of each directory on the way. A component is the directory stored
    /// under its exact stored name, else the first directory that differs
    /// only in case. `None` when one is missing.
    ///
    /// The caller holds the tree lock, so no rename moves a directory during
    /// the walk.
    async fn walk(&self, dir: &SmbPath) -> SmbResult<Option<Dir>> {
        let mut at = Dir {
            stored: SmbPath::root(),
            plain: SmbPath::root(),
        };
        for name in dir.components() {
            let Some(names) = self.names_of(&at.stored, Hold::Nothing).await? else {
                return Ok(None);
            };
            let Some(found) = names.directory(name, &self.stored_name(name)?) else {
                return Ok(None);
            };
            at = Dir {
                stored: at.stored.join(&found.stored)?,
                plain: at.plain.join(&found.plain)?,
            };
        }
        Ok(Some(at))
    }

    /// Drops the cached names of the directories above the stored directory
    /// `dir`, which a walk to it reads.
    fn forget_above(&self, dir: &SmbPath) {
        let mut above = dir.parent();
        while let Some(path) = above {
            self.invalidate(&path_key(&path, NameMatch::Exact));
            above = path.parent();
        }
    }

    /// Opens the entry at the stored path `stored`, which clients know by the
    /// path `plain`.
    pub(super) async fn open_stored(
        &self,
        stored: &SmbPath,
        plain: &SmbPath,
        opts: OpenOptions,
    ) -> OpenResult<B> {
        let names = self.shared.name_match();
        let (handle, action) = self.open_at(stored, opts, names).await?;
        Ok((handle.with_plaintext(plain.clone()), action))
    }

    /// The name the inner backend stores `name` under, and the side object of
    /// a long name.
    pub(super) fn stored_form(&self, name: &str) -> SmbResult<StoredName> {
        let threshold = self.shared.settings.long_name_threshold;
        encode_name(&self.shared.keys, name, threshold).ok_or(SmbError::NameInvalid)
    }

    /// The name the inner backend stores `name` under.
    pub(super) fn stored_name(&self, name: &str) -> SmbResult<String> {
        self.stored_form(name).map(|stored| stored.entry)
    }

    /// The path the inner backend stores `path` under.
    pub(super) fn stored_path(&self, path: &SmbPath) -> SmbResult<SmbPath> {
        path.components()
            .iter()
            .try_fold(SmbPath::root(), |stored, name| {
                stored.join(&self.stored_name(name)?)
            })
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::super::format::{HEADER_LEN, NONCE_LEN};
    use super::super::node::{HeaderKind, NameMatch};
    use super::super::testing::{
        Hidden, assert_err, layer, names_over, names_with, open, open_dir, open_file, read_all,
        refused, seed_dir, seed_file, settle, shares_node, spawn_open, stored_at, stored_bytes,
        stored_form, stored_name, with_name_limit,
    };
    use super::*;
    use crate::backend::{Handle, OpenAction, OpenIntent, ShareBackend};
    use crate::tests::faulty::Faulty;
    use crate::tests::file_ids::FileIds;
    use crate::tests::folding::Folding;
    use crate::tests::gated::{Gated, Op};
    use crate::tests::logs::Logs;
    use crate::tests::memfs::MemFsBackend;
    use crate::tests::util::{dir_opts, opts, path};

    #[tokio::test]
    async fn an_exact_name_opens_with_one_inner_open_and_no_listing() {
        let files = MemFsBackend::new();
        let faulty = Faulty::new(files.clone());
        let layer = names_over(faulty.clone()).await;
        seed_file(&files, "Docs\\Notes.md", &stored_bytes(b"hello"));
        let before = faulty.opens();

        let handle = open_file(&layer, "Docs\\Notes.md").await;
        assert_eq!(faulty.opens() - before, 1);
        let info = handle.stat().await.unwrap();
        assert_eq!(info.name, "Notes.md", "the plaintext name");
        assert_eq!(info.end_of_file, 5);
        assert_eq!(read_all(&handle).await, b"hello");
        assert_eq!(handle.node().path(), path(&stored_at("Docs\\Notes.md")));
        assert_eq!(handle.plain, Some(path("Docs\\Notes.md")));
        assert_eq!(layer.shared.names.keys().len(), 0, "nothing was listed");
    }

    #[tokio::test]
    async fn a_case_variant_opens_the_entry_under_its_stored_spelling() {
        let files = MemFsBackend::new();
        let faulty = Faulty::new(files.clone());
        let layer = names_over(faulty.clone()).await;
        seed_file(&files, "Report.TXT", &stored_bytes(b"quarterly"));
        seed_file(&files, "other", &stored_bytes(b"x"));

        for asked in ["report.txt", "REPORT.TXT", "rEpOrT.tXt"] {
            let handle = open_file(&layer, asked).await;
            let info = handle.stat().await.unwrap();
            assert_eq!(info.name, "Report.TXT", "{asked}");
            assert_eq!(read_all(&handle).await, b"quarterly", "{asked}");
            assert_eq!(handle.node().path(), path(&stored_at("Report.TXT")));
            assert_eq!(handle.plain, Some(path("Report.TXT")));
        }

        let before = faulty.opens();
        open_file(&layer, "REPORT.txt").await;
        assert_eq!(
            faulty.opens() - before,
            2,
            "the exact name misses, the names are cached"
        );
    }

    #[tokio::test]
    async fn the_first_variant_costs_one_listing() {
        let files = MemFsBackend::new();
        let faulty = Faulty::new(files.clone());
        let layer = names_over(faulty.clone()).await;
        seed_file(&files, "Report.TXT", &stored_bytes(b"x"));
        let before = faulty.opens();
        open_file(&layer, "report.txt").await;
        assert_eq!(faulty.opens() - before, 3, "exact, directory, entry");
        assert_eq!(layer.shared.names.keys(), [""]);
    }

    #[tokio::test]
    async fn a_case_variant_of_a_directory_on_the_way_opens() {
        let (files, layer) = layer().await;
        seed_file(&files, "Docs\\Sub\\Report.txt", &stored_bytes(b"deep"));
        seed_file(&files, "Docs\\other.txt", &stored_bytes(b"x"));

        let wanted = path(&stored_at("Docs\\Sub\\Report.txt"));
        for asked in [
            "docs\\Sub\\Report.txt",
            "Docs\\SUB\\Report.txt",
            "DOCS\\sub\\REPORT.TXT",
            "docs\\sub\\report.txt",
        ] {
            let handle = open_file(&layer, asked).await;
            assert_eq!(handle.node().path(), wanted, "{asked}");
            assert_eq!(handle.plain, Some(path("Docs\\Sub\\Report.txt")), "{asked}");
            assert_eq!(handle.stat().await.unwrap().name, "Report.txt");
            assert_eq!(read_all(&handle).await, b"deep");
        }
        let dir = open_dir(&layer, "DOCS\\sub").await;
        assert_eq!(dir.stat().await.unwrap().name, "Sub");
        assert!(dir.node().is_directory());
        assert_eq!(
            layer.shared.names.keys().len(),
            3,
            "the root, `Docs` and `Docs\\Sub` were listed"
        );
    }

    #[tokio::test]
    async fn a_missing_directory_is_path_not_found_and_a_missing_name_is_not_found() {
        let (files, layer) = layer().await;
        seed_file(&files, "Docs\\a.txt", &stored_bytes(b"x"));
        seed_dir(&files, "Docs\\Sub");

        for intent in [OpenIntent::Open, OpenIntent::Truncate] {
            for (asked, expected) in [
                ("Docs\\missing", SmbError::NotFound),
                ("docs\\MISSING", SmbError::NotFound),
                ("missing", SmbError::NotFound),
                ("nodocs\\a.txt", SmbError::PathNotFound),
                ("Docs\\nope\\a.txt", SmbError::PathNotFound),
                ("docs\\nope\\a.txt", SmbError::PathNotFound),
                ("docs\\a.txt\\x", SmbError::PathNotFound),
                ("docs\\sub\\missing", SmbError::NotFound),
                ("docs\\sub\\deeper\\missing", SmbError::PathNotFound),
            ] {
                let opened = layer.open_handle(&path(asked), opts(intent)).await;
                assert_err(opened.map(drop), expected);
            }
        }
        assert_eq!(layer.node_count(), 0);
    }

    #[tokio::test]
    async fn names_that_differ_in_case_are_found_by_the_exact_spelling_first() {
        let (files, layer) = layer().await;
        seed_file(&files, "Foo", &stored_bytes(b"upper"));
        seed_file(&files, "foo", &stored_bytes(b"lower"));
        seed_file(&files, "FOO", &stored_bytes(b"shout"));

        for (asked, content) in [("Foo", "upper"), ("foo", "lower"), ("FOO", "shout")] {
            let handle = open_file(&layer, asked).await;
            assert_eq!(read_all(&handle).await, content.as_bytes(), "{asked}");
            assert_eq!(handle.stat().await.unwrap().name, asked);
        }

        let mut by_stored = ["Foo", "foo", "FOO"].map(|name| (stored_name(name), name));
        by_stored.sort();
        let smallest = by_stored[0].1;
        let handle = open_file(&layer, "fOO").await;
        assert_eq!(
            handle.stat().await.unwrap().name,
            smallest,
            "the smallest stored name"
        );
    }

    #[tokio::test]
    async fn a_long_name_opens_in_any_case_and_a_long_directory_is_walked() {
        let (files, layer) = layer().await;
        let long = "x".repeat(150);
        let dir = "Y".repeat(200);
        assert!(stored_form(&long).side_object.is_some());
        seed_file(&files, &long, &stored_bytes(b"long file"));
        seed_file(
            &files,
            &format!("{dir}\\inside.txt"),
            &stored_bytes(b"inside"),
        );

        let exact = open_file(&layer, &long).await;
        assert_eq!(read_all(&exact).await, b"long file");
        let variant = open_file(&layer, &long.to_uppercase()).await;
        assert_eq!(variant.stat().await.unwrap().name, long);
        assert!(shares_node(&exact, &variant));

        let inside = open_file(&layer, &format!("{}\\INSIDE.txt", dir.to_lowercase())).await;
        assert_eq!(inside.stat().await.unwrap().name, "inside.txt");
        assert_eq!(read_all(&inside).await, b"inside");
        assert_eq!(
            inside.node().path(),
            path(&stored_at(&format!("{dir}\\inside.txt")))
        );
        assert_eq!(layer.shared.long_names.len(), 2);
    }

    #[tokio::test]
    async fn a_long_entry_whose_side_object_is_missing_or_invalid_opens_only_by_its_exact_name() {
        let logs = Logs::new();
        let (files, layer) = layer().await;
        let missing = "m".repeat(150);
        let invalid = "i".repeat(150);
        let swapped = "s".repeat(150);
        for name in [&missing, &invalid, &swapped] {
            seed_file(&files, name, &stored_bytes(b"data"));
        }
        let side = |name: &String| stored_form(name).side_object.unwrap();
        files.remove(&side(&missing).name);
        files
            .clone()
            .with_file(&side(&invalid).name, b"not a sealed name");
        files
            .clone()
            .with_file(&side(&swapped).name, &side(&missing).content);

        for name in [&missing, &invalid, &swapped] {
            let handle = open_file(&layer, name).await;
            assert_eq!(read_all(&handle).await, b"data");
        }
        for name in [&missing, &invalid, &swapped] {
            let error = refused(&layer, &name.to_uppercase(), OpenIntent::Open).await;
            assert!(matches!(error, SmbError::NotFound), "{error:?}");
        }
        let warnings = logs.warnings();
        assert_eq!(warnings.len(), 3, "{warnings:?}");
        for name in [&missing, &invalid, &swapped] {
            let entry = stored_form(name).entry;
            assert!(
                warnings.iter().any(|line| line.contains(&entry)),
                "{entry}: {warnings:?}"
            );
        }
        assert_eq!(layer.shared.long_names.len(), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn the_side_object_of_a_long_name_is_read_once() {
        let files = MemFsBackend::new();
        let faulty = Faulty::new(files.clone());
        let layer = names_over(faulty.clone()).await;
        let long = "x".repeat(150);
        seed_file(&files, &long, &stored_bytes(b"data"));

        let before = faulty.opens();
        open_file(&layer, &long.to_uppercase()).await;
        assert_eq!(
            faulty.opens() - before,
            4,
            "exact, directory, side object, entry"
        );

        tokio::time::advance(Duration::from_secs(31)).await;
        let before = faulty.opens();
        open_file(&layer, &long.to_uppercase()).await;
        assert_eq!(faulty.opens() - before, 3, "exact, directory, entry");
    }

    #[tokio::test]
    async fn without_case_insensitive_only_exact_stored_names_open() {
        let files = MemFsBackend::new();
        let faulty = Faulty::new(files.clone());
        let layer = names_with(faulty.clone(), |builder| builder.case_insensitive(false)).await;
        seed_file(&files, "Docs\\Report.txt", &stored_bytes(b"x"));

        let before = faulty.opens();
        let exact = open_file(&layer, "Docs\\Report.txt").await;
        assert_eq!(exact.stat().await.unwrap().name, "Report.txt");
        for (asked, expected) in [
            ("Docs\\report.txt", SmbError::NotFound),
            ("docs\\Report.txt", SmbError::PathNotFound),
            ("DOCS\\REPORT.TXT", SmbError::PathNotFound),
            ("Docs\\Report", SmbError::NotFound),
        ] {
            let opened = layer
                .open_handle(&path(asked), opts(OpenIntent::Open))
                .await;
            assert_err(opened.map(drop), expected);
        }
        assert_eq!(
            faulty.opens() - before,
            5,
            "one inner open each, no listing"
        );
        assert!(layer.shared.names.keys().is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn a_name_added_from_outside_is_found_once_the_cache_is_stale() {
        let (files, layer) = layer().await;
        seed_file(&files, "Foo", &stored_bytes(b"foo"));
        open_file(&layer, "foo").await;
        seed_file(&files, "Bar", &stored_bytes(b"bar"));

        let exact = open_file(&layer, "Bar").await;
        assert_eq!(
            read_all(&exact).await,
            b"bar",
            "an exact name needs no cache"
        );
        let error = refused(&layer, "bar", OpenIntent::Open).await;
        assert!(matches!(error, SmbError::NotFound), "{error:?}");

        tokio::time::advance(Duration::from_secs(30) - Duration::from_nanos(1)).await;
        let error = refused(&layer, "bar", OpenIntent::Open).await;
        assert!(
            matches!(error, SmbError::NotFound),
            "still fresh: {error:?}"
        );

        tokio::time::advance(Duration::from_nanos(1)).await;
        let found = open_file(&layer, "BAR").await;
        assert_eq!(found.stat().await.unwrap().name, "Bar");
        assert_eq!(read_all(&found).await, b"bar");
    }

    #[tokio::test(start_paused = true)]
    async fn a_directory_added_from_outside_is_found_once_the_cache_is_stale() {
        let (files, layer) = layer().await;
        seed_file(&files, "Foo", &stored_bytes(b"foo"));
        open_file(&layer, "foo").await;
        seed_file(&files, "New\\inside", &stored_bytes(b"in"));

        let error = refused(&layer, "new\\inside", OpenIntent::Open).await;
        assert!(matches!(error, SmbError::PathNotFound), "{error:?}");
        tokio::time::advance(Duration::from_secs(30)).await;
        let found = open_file(&layer, "NEW\\inside").await;
        assert_eq!(read_all(&found).await, b"in");
    }

    #[tokio::test]
    async fn no_time_to_live_lists_the_directory_on_every_variant() {
        let files = MemFsBackend::new();
        let faulty = Faulty::new(files.clone());
        let layer = names_with(faulty.clone(), |builder| {
            builder.name_cache_ttl(Duration::ZERO)
        })
        .await;
        seed_file(&files, "Foo", &stored_bytes(b"foo"));

        for _ in 0..2 {
            let before = faulty.opens();
            open_file(&layer, "foo").await;
            assert_eq!(faulty.opens() - before, 3, "exact, directory, entry");
        }
        seed_file(&files, "Bar", &stored_bytes(b"bar"));
        open_file(&layer, "bar").await;
        assert!(layer.shared.names.keys().is_empty());
    }

    #[tokio::test]
    async fn a_cached_name_the_inner_backend_lacks_is_dropped_and_listed_again() {
        let files = MemFsBackend::new();
        let faulty = Faulty::new(files.clone());
        let layer = names_over(faulty.clone()).await;
        seed_file(&files, "Foo", &stored_bytes(b"old"));
        open_file(&layer, "foo").await;
        files.remove(&stored_at("Foo"));
        seed_file(&files, "FOO", &stored_bytes(b"new"));

        let before = faulty.opens();
        let handle = open_file(&layer, "foo").await;
        assert_eq!(
            faulty.opens() - before,
            4,
            "exact, the cached name, directory, the listed name"
        );
        assert_eq!(handle.stat().await.unwrap().name, "FOO");
        assert_eq!(read_all(&handle).await, b"new");
    }

    #[tokio::test]
    async fn a_cached_name_that_is_gone_for_good_is_not_found_after_one_new_listing() {
        let files = MemFsBackend::new();
        let faulty = Faulty::new(files.clone());
        let layer = names_over(faulty.clone()).await;
        seed_file(&files, "Foo", &stored_bytes(b"old"));
        open_file(&layer, "foo").await;
        files.remove(&stored_at("Foo"));

        let before = faulty.opens();
        let error = refused(&layer, "foo", OpenIntent::Open).await;
        assert!(matches!(error, SmbError::NotFound), "{error:?}");
        assert_eq!(
            faulty.opens() - before,
            3,
            "exact, the cached name, directory"
        );
        let again = refused(&layer, "FOO", OpenIntent::Open).await;
        assert!(matches!(again, SmbError::NotFound), "{again:?}");
        assert_eq!(
            layer.shared.names.fresh("").unwrap().len(),
            0,
            "the new listing is cached"
        );
    }

    #[tokio::test]
    async fn a_listed_name_that_fails_to_open_twice_is_a_sharing_violation() {
        let files = MemFsBackend::new();
        let hidden = Hidden::new(files.clone());
        let faulty = Faulty::new(hidden.clone());
        let layer = names_over(faulty.clone()).await;
        seed_file(&files, "Foo", &stored_bytes(b"data"));
        hidden.hide(&stored_at("Foo"));

        let before = faulty.opens();
        let error = refused(&layer, "foo", OpenIntent::Open).await;
        assert!(matches!(error, SmbError::Sharing), "{error:?}");
        assert_eq!(
            faulty.opens() - before,
            5,
            "exact, directory, name, directory, name"
        );
        assert!(
            layer.shared.names.fresh("").is_none(),
            "the names of the root are dropped"
        );

        hidden.show(&stored_at("Foo"));
        let handle = open_file(&layer, "foo").await;
        assert_eq!(read_all(&handle).await, b"data");
    }

    #[tokio::test]
    async fn a_directory_renamed_from_outside_is_found_by_walking_again() {
        for asked in ["docs\\a.txt", "Docs\\a.txt"] {
            let (files, layer) = layer().await;
            seed_file(&files, "Docs\\a.txt", &stored_bytes(b"inside"));
            open_file(&layer, "docs\\a.txt").await;
            assert_eq!(layer.shared.names.keys(), [""], "the root lists `Docs`");
            files
                .rename(&path(&stored_at("Docs")), &path(&stored_at("DOCS")), false)
                .await
                .unwrap();

            let handle = open_file(&layer, asked).await;
            assert_eq!(handle.plain, Some(path("DOCS\\a.txt")), "{asked}");
            assert_eq!(read_all(&handle).await, b"inside", "{asked}");
            let listed = layer
                .shared
                .names
                .fresh("")
                .expect("the root was listed again");
            assert!(listed.directory("docs", &stored_name("DOCS")).is_some());
        }
    }

    #[tokio::test]
    async fn a_directory_gone_from_outside_is_missing_once_the_names_above_are_listed_again() {
        let (files, layer) = layer().await;
        seed_file(&files, "Docs\\a.txt", &stored_bytes(b"x"));
        open_file(&layer, "docs\\a.txt").await;
        files
            .rename(&path(&stored_at("Docs")), &path(&stored_at("Other")), false)
            .await
            .unwrap();

        let error = refused(&layer, "docs\\a.txt", OpenIntent::Open).await;
        assert!(matches!(error, SmbError::PathNotFound), "{error:?}");
        let listed = layer
            .shared
            .names
            .fresh("")
            .expect("the root was listed again");
        assert!(listed.directory("other", &stored_name("other")).is_some());
        assert!(listed.directory("docs", &stored_name("docs")).is_none());
    }

    #[tokio::test]
    async fn a_walked_directory_that_fails_to_open_twice_is_a_sharing_violation() {
        let files = MemFsBackend::new();
        let hidden = Hidden::new(files.clone());
        let faulty = Faulty::new(hidden.clone());
        let layer = names_over(faulty.clone()).await;
        seed_file(&files, "Docs\\a.txt", &stored_bytes(b"data"));
        hidden.cut_off(&stored_at("Docs\\a.txt"));

        let before = faulty.opens();
        let error = refused(&layer, "docs\\a.txt", OpenIntent::Open).await;
        assert!(matches!(error, SmbError::Sharing), "{error:?}");
        assert_eq!(
            faulty.opens() - before,
            5,
            "exact, root, entry, root, entry"
        );

        hidden.show(&stored_at("Docs\\a.txt"));
        let handle = open_file(&layer, "docs\\a.txt").await;
        assert_eq!(read_all(&handle).await, b"data");
    }

    #[tokio::test]
    async fn a_directory_that_cannot_be_listed_is_a_missing_directory() {
        let files = MemFsBackend::new();
        let hidden = Hidden::new(files.clone());
        let faulty = Faulty::new(hidden.clone());
        let layer = names_over(faulty.clone()).await;
        seed_file(&files, "Docs\\a.txt", &stored_bytes(b"x"));
        hidden.hide(&stored_at("Docs"));

        let before = faulty.opens();
        let error = refused(&layer, "Docs\\missing", OpenIntent::Open).await;
        assert!(matches!(error, SmbError::PathNotFound), "{error:?}");
        assert_eq!(
            faulty.opens() - before,
            4,
            "exact, directory, root, root: the walk ends where the exact name was tried"
        );
    }

    #[tokio::test]
    async fn the_directories_listed_are_cached_under_their_stored_paths() {
        let (files, layer) = layer().await;
        seed_file(&files, "Docs\\Sub\\Report.txt", &stored_bytes(b"x"));
        open_file(&layer, "docs\\sub\\report.txt").await;
        assert_eq!(
            layer.shared.names.keys(),
            ["".to_string(), stored_name("Docs"), stored_at("Docs\\Sub")]
        );
    }

    async fn one_node_per_file<B: ShareBackend>(files: &MemFsBackend, layer: &EncryptedBackend<B>) {
        seed_file(files, "Docs\\Report.txt", &stored_bytes(b"x"));
        seed_file(files, "Docs\\Other.txt", &stored_bytes(b"x"));
        let exact = open_file(layer, "Docs\\Report.txt").await;
        let variant = open_file(layer, "docs\\REPORT.TXT").await;
        let other = open_file(layer, "Docs\\Other.txt").await;
        assert!(shares_node(&exact, &variant));
        assert!(!shares_node(&exact, &other));
        assert_eq!(layer.node_count(), 2);
        drop((exact, variant, other));
        assert_eq!(layer.node_count(), 0);
    }

    #[tokio::test]
    async fn handles_of_one_file_share_one_node_whatever_the_spelling() {
        let (files, layer) = layer().await;
        one_node_per_file(&files, &layer).await;
    }

    #[tokio::test]
    async fn handles_of_one_file_share_one_node_when_the_inner_backend_reports_file_ids() {
        let files = MemFsBackend::new();
        let layer = names_over(FileIds::new(files.clone())).await;
        one_node_per_file(&files, &layer).await;
    }

    #[tokio::test]
    async fn stored_paths_are_compared_as_they_are_whatever_the_inner_backend_folds() {
        let files = MemFsBackend::new();
        let layer = names_over(Folding::new(files.clone())).await;
        assert!(matches!(layer.shared.name_match(), NameMatch::Exact));

        seed_file(&files, "Report", &stored_bytes(b"x"));
        let exact = open_file(&layer, "Report").await;
        let variant = open_file(&layer, "report").await;
        assert_eq!(variant.stat().await.unwrap().name, "Report");
        assert!(shares_node(&exact, &variant));
        assert_eq!(layer.node_count(), 1);
    }

    #[tokio::test]
    async fn the_directory_lock_is_the_one_of_the_stored_parent_found() {
        for intent in [OpenIntent::Open, OpenIntent::Truncate] {
            let files = MemFsBackend::new();
            let gated = Gated::new(files.clone());
            let layer = names_over(gated.clone()).await;
            seed_file(&files, "Docs\\file.txt", &stored_bytes(b"x"));
            let stored_file = stored_at("Docs\\file.txt");
            let gate = gated.arm_at(Op::Stat, &stored_file);
            let opening = spawn_open(&layer, "docs\\file.txt", intent);
            gate.reached().await;

            let locks = &layer.shared.locks;
            assert_eq!(
                locks.directory_count(),
                1,
                "{intent:?}: only the directory found is held"
            );
            let key = stored_name("Docs");
            let held = locks.directory(key);
            assert!(
                !held.is_free() && !held.is_exclusive(),
                "{intent:?}: held shared"
            );
            let by_client_path = locks.directory("docs".to_string());
            assert!(by_client_path.is_free());
            assert!(
                locks.tree.try_write().is_err(),
                "{intent:?}: the tree lock is held shared"
            );
            assert_eq!(layer.node_count(), 0, "the node is not attached yet");

            gate.release();
            let (handle, _) = opening.await.unwrap().unwrap();
            assert_eq!(layer.node_count(), 1);
            assert!(held.is_free());
            assert!(locks.tree.try_write().is_ok());
            drop(handle);
        }
    }

    #[tokio::test]
    async fn an_open_of_a_directory_waits_for_a_create_in_it() {
        let (files, layer) = layer().await;
        seed_file(&files, "Docs\\file.txt", &stored_bytes(b"x"));
        let docs = layer.shared.locks.directory(stored_name("Docs"));
        let writer = docs.acquire(true).await;
        let opening = spawn_open(&layer, "Docs\\file.txt", OpenIntent::Open);
        settle().await;
        assert!(
            !opening.is_finished(),
            "an exclusive holder keeps readers out"
        );
        drop(writer);
        opening.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn a_truncating_open_through_a_variant_empties_the_file_and_forgets_its_header() {
        let (files, layer) = layer().await;
        seed_file(&files, "Docs\\Data.BIN", &stored_bytes(b"contents"));
        let reader = open_file(&layer, "Docs\\Data.BIN").await;
        assert_eq!(read_all(&reader).await, b"contents");
        assert_eq!(reader.node().header().await, Some(HeaderKind::Present));

        let (handle, action) = open(&layer, "DOCS\\data.bin", OpenIntent::Truncate).await;
        assert_eq!(action, OpenAction::Overwritten);
        assert_eq!(
            files.contents(&stored_at("Docs\\Data.BIN")),
            Some(Vec::new())
        );
        assert!(shares_node(&reader, &handle));
        assert_eq!(handle.node().header().await, Some(HeaderKind::Absent));
        assert_eq!(handle.stat().await.unwrap().name, "Data.BIN");
        assert_eq!(handle.stat().await.unwrap().end_of_file, 0);
        assert_eq!(
            files.open_handles(),
            2,
            "the open that stats the file first is closed"
        );
    }

    #[tokio::test]
    async fn a_truncating_open_of_a_directory_is_the_inner_backends_to_answer() {
        let (files, layer) = layer().await;
        seed_dir(&files, "Docs");
        for asked in ["Docs", "docs"] {
            let error = refused(&layer, asked, OpenIntent::Truncate).await;
            assert!(matches!(error, SmbError::IsDirectory), "{asked}: {error:?}");
        }
        assert_eq!(files.open_handles(), 0);
    }

    #[tokio::test]
    async fn a_corrupt_block_warns_with_the_plaintext_path_and_the_stored_path() {
        let logs = Logs::new();
        let (files, layer) = layer().await;
        let mut bytes = stored_bytes(b"some data");
        bytes[HEADER_LEN + NONCE_LEN + 2] ^= 1;
        seed_file(&files, "Dir\\File.TXT", &bytes);

        let handle = open_file(&layer, "dir\\file.txt").await;
        let error = handle.read(0, 9).await.unwrap_err();
        assert!(matches!(error, SmbError::Io(_)), "{error:?}");
        let warnings = logs.warnings();
        assert_eq!(warnings.len(), 1, "{warnings:?}");
        let line = &warnings[0];
        let stored = stored_at("Dir\\File.TXT");
        assert!(line.contains("path=Dir\\File.TXT"), "{line}");
        assert!(line.contains(&format!("stored={stored}")), "{line}");
        assert!(!line.contains("dir\\file.txt"), "{line}");
        assert!(line.contains("block=0"), "{line}");
    }

    #[tokio::test]
    async fn a_directory_handle_reports_the_plaintext_name_and_the_root_keeps_the_inner_one() {
        let (files, layer) = layer().await;
        seed_dir(&files, "Docs");
        let dir = open_dir(&layer, "docs").await;
        assert_eq!(dir.stat().await.unwrap().name, "Docs");
        let root = layer
            .open_handle(&SmbPath::root(), dir_opts(OpenIntent::Open))
            .await
            .unwrap()
            .0;
        assert_eq!(root.plain, None);
        assert_eq!(root.stat().await.unwrap().name, "");
    }

    #[tokio::test]
    async fn of_directories_that_differ_in_case_the_exact_one_wins_and_then_the_smallest_stored_name()
     {
        let (files, layer) = layer().await;
        let spellings = ["Docs", "docs", "DOCS"];
        for name in spellings {
            seed_file(
                &files,
                &format!("{name}\\f"),
                &stored_bytes(name.as_bytes()),
            );
        }
        seed_file(&files, "docs\\g", &stored_bytes(b"g"));

        for name in spellings {
            let handle = open_file(&layer, &format!("{name}\\f")).await;
            assert_eq!(read_all(&handle).await, name.as_bytes(), "{name}");
        }
        let mut by_stored = spellings.map(|name| (stored_name(name), name));
        by_stored.sort();
        let handle = open_file(&layer, "dOcS\\f").await;
        assert_eq!(read_all(&handle).await, by_stored[0].1.as_bytes());

        let error = refused(&layer, "Docs\\g", OpenIntent::Open).await;
        assert!(
            matches!(error, SmbError::NotFound),
            "the exact directory is the one asked: {error:?}"
        );
    }

    #[tokio::test]
    async fn the_directory_caches_hold_a_bounded_number_of_names_least_recently_used_first() {
        let files = MemFsBackend::new();
        let faulty = Faulty::new(files.clone());
        let layer = with_name_limit(names_over(faulty.clone()).await, 50);
        for (dir, count) in [("A", 20), ("B", 20), ("C", 30), ("D", 60)] {
            seed_dir(&files, dir);
            for n in 0..count {
                seed_file(&files, &format!("{dir}\\f{n}"), b"");
            }
        }
        let cached = || layer.shared.names.keys();
        let miss = async |dir: &str| {
            let before = faulty.opens();
            let error = refused(&layer, &format!("{dir}\\missing"), OpenIntent::Open).await;
            assert!(matches!(error, SmbError::NotFound), "{error:?}");
            faulty.opens() - before
        };
        let [a, b, c, d] = ["A", "B", "C", "D"].map(stored_name);

        assert_eq!(miss("A").await, 2, "exact, listing");
        assert_eq!(miss("B").await, 2);
        assert_eq!(cached(), [a.clone(), b.clone()]);
        assert_eq!(miss("A").await, 1, "cached");
        assert_eq!(cached(), [b.clone(), a.clone()], "A was used last");

        assert_eq!(miss("C").await, 2);
        assert_eq!(
            cached(),
            [a.clone(), c.clone()],
            "B went, the least recently used"
        );
        assert_eq!(layer.shared.names.weight(), 50);

        assert_eq!(miss("B").await, 2);
        assert_eq!(cached(), [c.clone(), b.clone()], "then A");

        assert_eq!(miss("D").await, 2);
        assert_eq!(cached(), [d], "a directory over the limit is kept alone");
        assert_eq!(miss("D").await, 1, "and used");
        assert_eq!(miss("A").await, 2);
        assert_eq!(cached(), [a], "the next one pushes it out");
    }
}
