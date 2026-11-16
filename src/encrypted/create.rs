//! Creates in a share with encrypted names.
//!
//! A create holds the lock of the stored directory exclusively and answers
//! from the names of the directory: an entry with the exact stored name, then
//! one that differs in case, then none. It makes the entry in the inner
//! backend, and when that succeeds it adds the entry to the cached names.

use super::backend::EncryptedBackend;
use super::cache::Entry;
use super::handle::OpenResult;
use super::inner::write_side_object;
use super::locks::DirLock;
use super::names::StoredName;
use super::node::{NameMatch, path_key};
use super::resolve::Dir;
use crate::backend::{OpenAction, OpenOptions, ShareBackend};
use crate::error::SmbResult;
use crate::path::SmbPath;

/// Drops the cached names of the directory `key` when it goes out of scope
/// armed. A create holds one from before the inner create until the cached
/// names have the entry, so a create that fails or is dropped meanwhile never
/// leaves the names saying the entry is absent.
struct DropNames<'a, B: ShareBackend> {
    layer: &'a EncryptedBackend<B>,
    key: &'a str,
    armed: bool,
}

impl<B: ShareBackend> DropNames<'_, B> {
    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl<B: ShareBackend> Drop for DropNames<'_, B> {
    fn drop(&mut self) {
        if self.armed {
            self.layer.invalidate(self.key);
        }
    }
}

impl<B: ShareBackend> EncryptedBackend<B> {
    /// Opens or creates the entry `name` in the stored directory `dir`.
    /// `opts.intent` is one that creates. The caller holds the tree lock
    /// shared.
    ///
    /// An entry with the stored name `name` encrypts to, or with a name that
    /// differs in case, is there already: `Create` fails with `Exists`,
    /// `OpenOrCreate` opens it, and `OverwriteOrCreate` empties it as an open
    /// that truncates does. With no such entry the inner backend creates it
    /// under that stored name, after the side object of a long name. A
    /// directory the inner backend lacks fails with `PathNotFound`.
    ///
    /// With `case_insensitive` off no names are listed and the inner backend
    /// answers for the exact stored name.
    pub(super) async fn create_in(
        &self,
        dir: &Dir,
        name: &str,
        opts: OpenOptions,
    ) -> OpenResult<B> {
        let lock = self
            .shared
            .locks
            .directory(path_key(&dir.stored, NameMatch::Exact));
        let _held = lock.acquire(true).await;
        let stored = self.stored_form(name)?;
        if self.shared.settings.case_insensitive
            && let Some(opened) = self
                .open_listed(dir, &lock, name, &stored.entry, opts)
                .await
        {
            return opened;
        }
        self.create_entry(dir, &lock, name, &stored, opts).await
    }

    /// Makes the entry `name`, stored as `stored`, in `dir`. The caller holds
    /// `lock`, the lock of `dir`.
    ///
    /// The side object of a long name is written first, and a failure there
    /// fails the create before the entry exists. The long-name cache gets the
    /// entry after that and before the inner create. Once the inner backend
    /// has made the entry, the cached names of the directory gain it. An entry
    /// that was there already, which the cached names did not show, a
    /// directory that is gone, and a create that fails or is dropped after the
    /// inner create began all mean the cached names are out of date, and they
    /// are dropped.
    async fn create_entry(
        &self,
        dir: &Dir,
        lock: &DirLock,
        name: &str,
        stored: &StoredName,
        opts: OpenOptions,
    ) -> OpenResult<B> {
        let at = dir.stored.join(&stored.entry)?;
        let plain = dir.plain.join(name)?;
        self.write_long_name(&dir.stored, name, stored).await?;
        let names = self.shared.name_match();
        let listed = self.shared.settings.case_insensitive;
        let mut stale = DropNames {
            layer: self,
            key: lock.key(),
            armed: listed,
        };
        let (handle, action) = if listed {
            self.open_new(&at, opts, names).await?
        } else {
            self.open_at(&at, opts, names).await?
        };
        if action == OpenAction::Created {
            let entry = Entry {
                plain: name.to_string(),
                stored: stored.entry.clone(),
                directory: handle.node.is_directory(),
            };
            self.shared.names.patch(lock, None, Some(entry));
        } else if listed {
            self.invalidate(lock.key());
        }
        stale.disarm();
        Ok((handle.with_plaintext(plain), action))
    }

    /// Makes the side object of the long name `name`, stored as `stored`, in
    /// the stored directory `dir`, and gives the long-name cache the entry. A
    /// name that is not long has neither.
    pub(super) async fn write_long_name(
        &self,
        dir: &SmbPath,
        name: &str,
        stored: &StoredName,
    ) -> SmbResult<()> {
        if let Some(side) = &stored.side_object {
            let side_at = dir.join(&side.name)?;
            write_side_object(&self.shared.inner, &side_at, &side.content).await?;
            self.shared.long_names.insert(stored.entry.clone(), name);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::super::node::HeaderKind;
    use super::super::scan::Hold;
    use super::super::testing::{
        Hidden, drop_at, fail_open_of, injected, layer, long_name, names_over, names_with, open,
        open_dir, open_dir_as, open_file, read_all, refused, refused_dir, seed_dir, seed_file,
        settle, shares_node, spawn_open, stored_at, stored_bytes, stored_form, stored_len,
        stored_name, writes_since,
    };
    use super::*;
    use crate::backend::{Handle, OpenIntent};
    use crate::error::SmbError;
    use crate::path::SmbPath;
    use crate::tests::faulty::Faulty;
    use crate::tests::file_ids::FileIds;
    use crate::tests::gated::{Gated, Op};
    use crate::tests::memfs::MemFsBackend;
    use crate::tests::util::{opts, path};

    const CREATING: [OpenIntent; 3] = [
        OpenIntent::Create,
        OpenIntent::OpenOrCreate,
        OpenIntent::OverwriteOrCreate,
    ];

    #[tokio::test]
    async fn create_fails_for_an_entry_of_any_case_file_or_directory() {
        let (files, layer) = layer().await;
        seed_file(&files, "Foo", &stored_bytes(b"x"));
        seed_dir(&files, "Dir");

        for name in ["Foo", "foo", "FOO", "fOo", "Dir", "dir", "DIR"] {
            let error = refused(&layer, name, OpenIntent::Create).await;
            assert!(matches!(error, SmbError::Exists), "{name}: {error:?}");
            let error = refused_dir(&layer, name, OpenIntent::Create).await;
            assert!(matches!(error, SmbError::Exists), "{name}: {error:?}");
        }
        assert_eq!(layer.node_count(), 0);
        assert_eq!(files.open_handles(), 0);
        assert_eq!(files.contents(&stored_at("foo")), None);
        assert_eq!(files.contents(&stored_at("dir")), None);
    }

    #[tokio::test]
    async fn open_or_create_opens_an_entry_of_any_case() {
        let (files, layer) = layer().await;
        seed_file(&files, "Foo", &stored_bytes(b"x"));
        seed_dir(&files, "Dir");
        let exact = open_file(&layer, "Foo").await;

        for name in ["Foo", "foo", "FOO"] {
            let (handle, action) = open(&layer, name, OpenIntent::OpenOrCreate).await;
            assert_eq!(action, OpenAction::Opened, "{name}");
            assert_eq!(handle.stat().await.unwrap().name, "Foo");
            assert_eq!(read_all(&handle).await, b"x");
            assert!(shares_node(&exact, &handle), "{name}");
        }
        for name in ["Dir", "dir", "DIR"] {
            let (handle, action) = open_dir_as(&layer, name, OpenIntent::OpenOrCreate).await;
            assert_eq!(action, OpenAction::Opened, "{name}");
            assert_eq!(handle.stat().await.unwrap().name, "Dir");
            assert!(handle.node().is_directory());
        }
        assert_eq!(files.contents(&stored_at("foo")), None);
    }

    #[tokio::test]
    async fn overwrite_or_create_empties_a_file_of_any_case_and_refuses_a_directory() {
        let (files, layer) = layer().await;
        seed_file(&files, "Foo", &stored_bytes(b"old"));
        seed_dir(&files, "Dir");
        let reader = open_file(&layer, "Foo").await;
        assert_eq!(read_all(&reader).await, b"old");
        assert_eq!(reader.node().header().await, Some(HeaderKind::Present));

        for name in ["Foo", "fOO"] {
            let (handle, action) = open(&layer, name, OpenIntent::OverwriteOrCreate).await;
            assert_eq!(action, OpenAction::Overwritten, "{name}");
            assert!(shares_node(&reader, &handle));
            assert_eq!(handle.node().header().await, Some(HeaderKind::Absent));
            assert_eq!(files.contents(&stored_at("Foo")), Some(Vec::new()));
            assert_eq!(handle.stat().await.unwrap().name, "Foo");
        }
        for name in ["Dir", "dir"] {
            let error = refused(&layer, name, OpenIntent::OverwriteOrCreate).await;
            assert!(matches!(error, SmbError::IsDirectory), "{name}: {error:?}");
        }
        assert_eq!(files.contents(&stored_at("foo")), None);
    }

    #[tokio::test]
    async fn without_case_insensitive_the_inner_backend_answers_for_the_exact_stored_name() {
        let files = MemFsBackend::new();
        let faulty = Faulty::new(files.clone());
        let layer = names_with(faulty.clone(), |builder| builder.case_insensitive(false)).await;
        seed_file(&files, "Foo", &stored_bytes(b"x"));
        seed_dir(&files, "Dir");

        let before = faulty.opens();
        let error = refused(&layer, "Foo", OpenIntent::Create).await;
        assert!(matches!(error, SmbError::Exists), "{error:?}");
        let error = refused_dir(&layer, "Dir", OpenIntent::Create).await;
        assert!(matches!(error, SmbError::Exists), "{error:?}");
        assert_eq!(faulty.opens() - before, 2, "one inner open each");

        let (_, action) = open(&layer, "foo", OpenIntent::Create).await;
        assert_eq!(action, OpenAction::Created);
        let (_, action) = open_dir_as(&layer, "dir", OpenIntent::Create).await;
        assert_eq!(action, OpenAction::Created);
        let (_, action) = open(&layer, "Foo", OpenIntent::OpenOrCreate).await;
        assert_eq!(action, OpenAction::Opened);
        let (_, action) = open(&layer, "FOO", OpenIntent::OpenOrCreate).await;
        assert_eq!(action, OpenAction::Created);
        let (_, action) = open(&layer, "Foo", OpenIntent::OverwriteOrCreate).await;
        assert_eq!(action, OpenAction::Overwritten);
        let (_, action) = open(&layer, "fOO", OpenIntent::OverwriteOrCreate).await;
        assert_eq!(action, OpenAction::Created);

        for name in ["Foo", "foo", "FOO", "fOO"] {
            assert!(files.contents(&stored_at(name)).is_some(), "{name}");
        }
        assert!(layer.shared.names.keys().is_empty(), "no listing, no cache");
    }

    #[tokio::test]
    async fn two_creates_of_names_that_differ_in_case_make_one_entry() {
        for (first_name, second_name) in [("Foo", "foo"), ("foo", "Foo")] {
            let files = MemFsBackend::new();
            let gated = Gated::new(files.clone());
            let layer = names_over(gated.clone()).await;
            let gate = gated.arm_at(Op::Open, &stored_at(first_name));
            let first = spawn_open(&layer, first_name, OpenIntent::Create);
            gate.reached().await;
            let second = spawn_open(&layer, second_name, OpenIntent::Create);
            settle().await;
            assert!(!second.is_finished(), "the second create waits");

            gate.release();
            let (handle, action) = first.await.unwrap().unwrap();
            assert_eq!(action, OpenAction::Created);
            let error = second
                .await
                .unwrap()
                .err()
                .expect("the second create fails");
            assert!(matches!(error, SmbError::Exists), "{error:?}");
            assert_eq!(handle.stat().await.unwrap().name, first_name);
            assert_eq!(files.contents(&stored_at(first_name)), Some(Vec::new()));
            assert_eq!(files.contents(&stored_at(second_name)), None);
        }
    }

    #[tokio::test]
    async fn overwrite_or_create_meets_a_file_that_appeared_from_outside() {
        let (files, layer) = layer().await;
        open(&layer, "Seed", OpenIntent::Create).await;
        seed_file(&files, "Late", &stored_bytes(b"outside"));
        let reader = open_file(&layer, "Late").await;
        assert_eq!(read_all(&reader).await, b"outside");
        assert_eq!(reader.node().header().await, Some(HeaderKind::Present));
        let names = layer.shared.names.fresh("").expect("the root is cached");
        assert!(names.entry("Late", &stored_name("Late")).is_none());
        drop(names);

        let (handle, action) = open(&layer, "Late", OpenIntent::OverwriteOrCreate).await;
        assert_eq!(action, OpenAction::Overwritten);
        assert!(shares_node(&reader, &handle));
        assert_eq!(handle.node().header().await, Some(HeaderKind::Absent));
        assert_eq!(files.contents(&stored_at("Late")), Some(Vec::new()));
        assert_eq!(read_all(&handle).await, b"");
        assert!(
            layer.shared.names.fresh("").is_none(),
            "the cached names were out of date"
        );
        let error = refused(&layer, "LATE", OpenIntent::Create).await;
        assert!(matches!(error, SmbError::Exists), "{error:?}");
        let names = layer.shared.names.fresh("").expect("the root is listed");
        assert!(names.entry("late", &stored_name("late")).is_some());
    }

    #[tokio::test]
    async fn create_over_an_entry_that_appeared_from_outside_is_exists_and_drops_the_cache() {
        let (files, layer) = layer().await;
        open(&layer, "Seed", OpenIntent::Create).await;
        seed_file(&files, "Late", &stored_bytes(b"outside"));

        let error = refused(&layer, "Late", OpenIntent::Create).await;
        assert!(matches!(error, SmbError::Exists), "{error:?}");
        assert!(
            layer.shared.names.fresh("").is_none(),
            "the cached names were out of date"
        );
    }

    #[tokio::test]
    async fn a_created_file_has_no_header_and_is_found_in_any_case_without_a_listing() {
        let files = MemFsBackend::new();
        let faulty = Faulty::new(files.clone());
        let layer = names_over(faulty.clone()).await;

        let (handle, action) = open(&layer, "Docs.txt", OpenIntent::Create).await;
        assert_eq!(action, OpenAction::Created);
        assert_eq!(handle.node().header().await, Some(HeaderKind::Absent));
        assert_eq!(handle.plain, Some(path("Docs.txt")));
        assert_eq!(handle.node().path(), path(&stored_at("Docs.txt")));
        assert_eq!(handle.stat().await.unwrap().name, "Docs.txt");
        handle.write(0, b"hello").await.unwrap();
        assert_eq!(read_all(&handle).await, b"hello");
        assert_eq!(
            files.contents(&stored_at("Docs.txt")).unwrap().len(),
            stored_len(5)
        );

        let before = faulty.opens();
        let variant = open_file(&layer, "DOCS.TXT").await;
        assert_eq!(
            faulty.opens() - before,
            2,
            "the exact name misses and the entry opens, with no listing"
        );
        assert!(shares_node(&handle, &variant));
        assert_eq!(variant.stat().await.unwrap().name, "Docs.txt");
    }

    #[tokio::test]
    async fn a_create_in_a_directory_that_is_not_there_is_path_not_found() {
        for case_insensitive in [true, false] {
            let files = MemFsBackend::new();
            let layer = names_with(files.clone(), |builder| {
                builder.case_insensitive(case_insensitive)
            })
            .await;
            seed_file(&files, "Docs\\a.txt", &stored_bytes(b"x"));

            for name in [
                "nodocs\\a",
                "Docs\\nope\\a",
                "Docs\\a.txt\\x",
                "Docs\\nope\\deeper\\a",
            ] {
                let error = refused(&layer, name, OpenIntent::Create).await;
                let case = format!("{name} {case_insensitive}");
                assert!(matches!(error, SmbError::PathNotFound), "{case}: {error:?}");
            }
            let error = refused_dir(&layer, "nodocs\\sub", OpenIntent::Create).await;
            assert!(matches!(error, SmbError::PathNotFound), "{error:?}");
            assert_eq!(layer.node_count(), 0);
            assert_eq!(files.open_handles(), 0);
        }
    }

    #[tokio::test]
    async fn a_create_in_a_directory_of_another_case_goes_to_that_directory() {
        let (files, layer) = layer().await;
        seed_dir(&files, "Docs");

        let (handle, action) = open(&layer, "docs\\New.txt", OpenIntent::Create).await;
        assert_eq!(action, OpenAction::Created);
        assert_eq!(handle.plain, Some(path("Docs\\New.txt")));
        assert_eq!(handle.node().path(), path(&stored_at("Docs\\New.txt")));
        assert_eq!(
            files.contents(&stored_at("Docs\\New.txt")),
            Some(Vec::new())
        );
        assert_eq!(files.contents(&stored_at("docs\\New.txt")), None);

        let error = refused(&layer, "DOCS\\new.TXT", OpenIntent::Create).await;
        assert!(matches!(error, SmbError::Exists), "{error:?}");
        let (again, action) = open(&layer, "dOCS\\NEW.txt", OpenIntent::OpenOrCreate).await;
        assert_eq!(action, OpenAction::Opened);
        assert!(shares_node(&handle, &again));
    }

    #[tokio::test]
    async fn a_long_name_has_its_side_object_before_its_entry() {
        let files = MemFsBackend::new();
        let gated = Gated::new(files.clone());
        let layer = names_over(gated.clone()).await;
        let long = long_name("x");
        let form = stored_form(&long);
        let side = form.side_object.clone().expect("a long name");
        let gate = gated.arm_at(Op::Open, &form.entry);

        let creating = spawn_open(&layer, &long, OpenIntent::Create);
        gate.reached().await;
        assert_eq!(files.contents(&side.name), Some(side.content.clone()));
        assert_eq!(files.contents(&form.entry), None);
        gate.release();

        let (handle, action) = creating.await.unwrap().unwrap();
        assert_eq!(action, OpenAction::Created);
        assert_eq!(files.contents(&form.entry), Some(Vec::new()));
        assert_eq!(handle.stat().await.unwrap().name, long);
        let error = refused(&layer, &long.to_uppercase(), OpenIntent::Create).await;
        assert!(matches!(error, SmbError::Exists), "{error:?}");
    }

    #[tokio::test]
    async fn the_long_name_cache_has_a_long_entry_before_the_inner_create() {
        let files = MemFsBackend::new();
        let gated = Gated::new(files.clone());
        let layer = names_over(gated.clone()).await;
        let long = long_name("x");
        let entry = stored_form(&long).entry;
        let gate = gated.arm_at(Op::Open, &entry);
        assert_eq!(layer.shared.long_names.len(), 0);

        let creating = spawn_open(&layer, &long, OpenIntent::Create);
        gate.reached().await;
        assert_eq!(files.contents(&entry), None);
        assert_eq!(layer.shared.long_names.get(&entry), Some(long.clone()));
        gate.release();
        creating.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn a_side_object_that_cannot_be_made_fails_the_create_before_the_entry() {
        let files = MemFsBackend::new();
        let faulty = Faulty::new(files.clone());
        let layer = names_over(faulty.clone()).await;
        let long = long_name("x");
        let form = stored_form(&long);
        let side = form.side_object.clone().expect("a long name");

        fail_open_of(&faulty, &side.name);
        let error = refused(&layer, &long, OpenIntent::Create).await;
        assert!(matches!(error, SmbError::Io(_)), "{error:?}");
        assert_eq!(files.contents(&form.entry), None);
        assert_eq!(files.contents(&side.name), None);
        assert_eq!(layer.shared.long_names.get(&form.entry), None);

        faulty.fail_write(1, SmbError::DiskFull);
        let error = refused(&layer, &long, OpenIntent::OpenOrCreate).await;
        assert!(matches!(error, SmbError::DiskFull), "{error:?}");
        assert_eq!(files.contents(&form.entry), None);
        assert_eq!(files.open_handles(), 0, "the side object is closed");
        assert_eq!(layer.node_count(), 0);
        assert_eq!(layer.shared.long_names.get(&form.entry), None);
        let names = layer.shared.names.fresh("").expect("the root is cached");
        assert!(names.entry(&long, &form.entry).is_none());
        drop(names);

        let (handle, action) = open(&layer, &long, OpenIntent::Create).await;
        assert_eq!(action, OpenAction::Created);
        assert_eq!(files.contents(&side.name), Some(side.content));
        assert_eq!(files.contents(&form.entry), Some(Vec::new()));
        assert_eq!(handle.stat().await.unwrap().name, long);
        assert_eq!(layer.shared.long_names.get(&form.entry), Some(long));
    }

    #[tokio::test]
    async fn a_directory_in_the_place_of_a_side_object_fails_the_create_before_the_entry() {
        let (files, layer) = layer().await;
        let long = long_name("x");
        let form = stored_form(&long);
        let side = form.side_object.expect("a long name");
        files.clone().with_dir(&side.name);

        let error = refused(&layer, &long, OpenIntent::Create).await;
        assert!(matches!(error, SmbError::IsDirectory), "{error:?}");
        assert_eq!(files.contents(&form.entry), None);
        assert_eq!(files.open_handles(), 0);
    }

    #[tokio::test]
    async fn a_side_object_with_the_same_content_is_left_alone_and_another_is_rewritten() {
        let long = long_name("x");
        let side = stored_form(&long).side_object.expect("a long name");
        let mut flipped = side.content.clone();
        flipped[0] ^= 1;
        let cases = [
            (None, false),
            (Some(side.content.clone()), true),
            (Some(flipped), false),
            (Some(vec![7; 2000]), false),
        ];

        for (held, untouched) in cases {
            let files = MemFsBackend::new();
            let faulty = Faulty::new(files.clone());
            let layer = names_over(faulty.clone()).await;
            if let Some(held) = &held {
                files.clone().with_file(&side.name, held);
            }
            let before = faulty.write_calls().len();

            let (_, action) = open(&layer, &long, OpenIntent::Create).await;
            assert_eq!(action, OpenAction::Created);
            let case = format!("{:?}", held.as_ref().map(Vec::len));
            assert_eq!(
                files.contents(&side.name),
                Some(side.content.clone()),
                "{case}"
            );
            let writes = writes_since(&faulty, before);
            if untouched {
                assert!(writes.is_empty(), "{case}: {writes:?}");
                assert!(faulty.truncate_calls().is_empty(), "{case}");
            } else {
                assert_eq!(writes, [(0, side.content.len())], "{case}");
                let truncates: &[u64] = if held.is_some() { &[0] } else { &[] };
                assert_eq!(faulty.truncate_calls(), truncates, "{case}");
            }
            assert_eq!(files.open_handles(), 1, "only the new entry is open");
        }
    }

    #[tokio::test]
    async fn a_long_directory_is_made_with_its_side_object_and_opens_in_any_case() {
        let (files, layer) = layer().await;
        let long = long_name("x");
        let form = stored_form(&long);
        let side = form.side_object.expect("a long name");

        let (handle, action) = open_dir_as(&layer, &long, OpenIntent::Create).await;
        assert_eq!(action, OpenAction::Created);
        assert!(handle.node().is_directory());
        assert_eq!(files.contents(&side.name), Some(side.content));
        let (_, action) = open(&layer, &format!("{long}\\f"), OpenIntent::Create).await;
        assert_eq!(action, OpenAction::Created);
        let dir = open_dir(&layer, &long.to_uppercase()).await;
        assert_eq!(dir.stat().await.unwrap().name, long);
        assert!(shares_node(&handle, &dir));
    }

    #[tokio::test(start_paused = true)]
    async fn a_create_rebuilds_a_stale_cache_and_sees_a_name_added_from_outside() {
        let files = MemFsBackend::new();
        let faulty = Faulty::new(files.clone());
        let layer = names_over(faulty.clone()).await;
        open(&layer, "Foo", OpenIntent::Create).await;
        seed_file(&files, "Bar", &stored_bytes(b"outside"));

        let before = faulty.opens();
        open(&layer, "Baz", OpenIntent::Create).await;
        assert_eq!(faulty.opens() - before, 1, "the cache is fresh: no listing");

        tokio::time::advance(Duration::from_secs(30)).await;
        let before = faulty.opens();
        let error = refused(&layer, "bar", OpenIntent::Create).await;
        assert!(matches!(error, SmbError::Exists), "{error:?}");
        assert_eq!(faulty.opens() - before, 1, "one listing, no create");
        assert_eq!(files.contents(&stored_at("bar")), None);

        let before = faulty.opens();
        let (handle, action) = open(&layer, "BAR", OpenIntent::OpenOrCreate).await;
        assert_eq!(action, OpenAction::Opened);
        assert_eq!(faulty.opens() - before, 1, "the rebuilt cache has `Bar`");
        assert_eq!(handle.stat().await.unwrap().name, "Bar");
    }

    #[tokio::test]
    async fn the_cached_names_gain_a_create_and_count_a_change_after_the_inner_create() {
        let files = MemFsBackend::new();
        let gated = Gated::new(files.clone());
        let layer = names_over(gated.clone()).await;
        for name in ["a", "b", "c"] {
            seed_file(&files, name, b"");
        }
        let counter = layer.shared.locks.directory(String::new());
        let gate = gated.arm_at(Op::Open, &stored_at("d"));

        let creating = spawn_open(&layer, "d", OpenIntent::Create);
        gate.reached().await;
        assert_eq!(
            counter.changes(),
            0,
            "nothing counts before the inner create"
        );
        let held = layer.shared.names.fresh("").expect("the root was listed");
        assert_eq!(held.len(), 3);
        assert_eq!(layer.shared.names.weight(), 3);
        gate.release();

        let (_first, _) = creating.await.unwrap().unwrap();
        assert_eq!(counter.changes(), 1);
        assert_eq!(layer.shared.names.weight(), 4);
        let names = layer.shared.names.fresh("").unwrap();
        assert_eq!(names.len(), 4);
        assert_eq!(names.entry("D", &stored_name("D")).unwrap().plain, "d");
        assert_eq!(held.len(), 3, "a reader keeps the names it held");
        drop((held, names));

        let (_second, _) = open(&layer, "e", OpenIntent::Create).await;
        assert_eq!(counter.changes(), 2);
        assert_eq!(layer.shared.names.weight(), 5);
    }

    #[tokio::test(start_paused = true)]
    async fn a_listing_that_began_before_a_create_is_not_kept_over_it() {
        let files = MemFsBackend::new();
        let gated = Gated::new(files.clone());
        let layer = names_over(gated.clone()).await;
        seed_file(&files, "a.txt", b"");
        let gate = gated.arm_after_at(Op::ListDir, "");
        let building = tokio::spawn({
            let layer = layer.clone();
            async move { layer.names_of(&SmbPath::root(), Hold::Nothing).await }
        });
        gate.reached().await;

        let (_handle, _) = open(&layer, "new.txt", OpenIntent::Create).await;
        gate.release();
        let listed = building.await.unwrap().unwrap().unwrap();
        let new = stored_name("new.txt");
        assert!(listed.entry("new.txt", &new).is_none(), "it listed before");
        let kept = layer.shared.names.fresh("").expect("a listing is cached");
        assert!(kept.entry("new.txt", &new).is_some());
    }

    #[tokio::test]
    async fn a_create_in_a_directory_made_through_the_layer_works_without_a_listing_of_it() {
        let files = MemFsBackend::new();
        let faulty = Faulty::new(files.clone());
        let layer = names_over(faulty.clone()).await;
        let (docs, action) = open_dir_as(&layer, "Docs", OpenIntent::Create).await;
        assert_eq!(action, OpenAction::Created);
        assert!(layer.shared.names.fresh(&stored_name("Docs")).is_none());

        let before = faulty.opens();
        let (file, action) = open(&layer, "Docs\\a.txt", OpenIntent::Create).await;
        assert_eq!(action, OpenAction::Created);
        assert_eq!(
            faulty.opens() - before,
            2,
            "the names of `Docs`, the create"
        );
        let names = layer.shared.names.fresh(&stored_name("Docs")).unwrap();
        assert!(names.entry("A.TXT", &stored_name("A.TXT")).is_some());
        drop(names);

        let before = faulty.opens();
        let error = refused(&layer, "docs\\A.TXT", OpenIntent::Create).await;
        assert!(matches!(error, SmbError::Exists), "{error:?}");
        assert_eq!(
            faulty.opens() - before,
            1,
            "the walk and the names are cached"
        );

        let before = faulty.opens();
        let variant = open_file(&layer, "DOCS\\A.TXT").await;
        assert_eq!(
            faulty.opens() - before,
            3,
            "`DOCS` misses, `A.TXT` misses in `Docs`, the entry opens"
        );
        assert!(shares_node(&file, &variant));
        assert!(docs.node().is_directory());
        let mut keys = layer.shared.names.keys();
        keys.sort();
        let mut expected = ["".to_string(), stored_name("Docs")];
        expected.sort();
        assert_eq!(keys, expected);
    }

    #[tokio::test]
    async fn without_a_time_to_live_nothing_is_kept_and_a_variant_is_still_found() {
        let files = MemFsBackend::new();
        let layer = names_with(files.clone(), |builder| {
            builder.name_cache_ttl(Duration::ZERO)
        })
        .await;
        let (_, action) = open(&layer, "Foo", OpenIntent::Create).await;
        assert_eq!(action, OpenAction::Created);
        let (_, action) = open_dir_as(&layer, "Dir", OpenIntent::Create).await;
        assert_eq!(action, OpenAction::Created);

        let error = refused(&layer, "foo", OpenIntent::Create).await;
        assert!(matches!(error, SmbError::Exists), "{error:?}");
        let (handle, action) = open(&layer, "fOO", OpenIntent::OpenOrCreate).await;
        assert_eq!(action, OpenAction::Opened);
        assert_eq!(handle.stat().await.unwrap().name, "Foo");
        let (_, action) = open(&layer, "Dir\\x", OpenIntent::Create).await;
        assert_eq!(action, OpenAction::Created);
        assert!(layer.shared.names.keys().is_empty());
    }

    #[tokio::test]
    async fn a_cached_name_the_inner_backend_lacks_is_listed_again_and_created() {
        let (files, layer) = layer().await;
        seed_file(&files, "Foo", &stored_bytes(b"old"));
        open_file(&layer, "foo").await;
        files.remove(&stored_at("Foo"));

        let (handle, action) = open(&layer, "foo", OpenIntent::OpenOrCreate).await;
        assert_eq!(action, OpenAction::Created);
        assert_eq!(files.contents(&stored_at("foo")), Some(Vec::new()));
        assert_eq!(handle.stat().await.unwrap().name, "foo");

        open(&layer, "Bar", OpenIntent::Create).await;
        files.remove(&stored_at("Bar"));
        let (_, action) = open(&layer, "BAR", OpenIntent::OverwriteOrCreate).await;
        assert_eq!(action, OpenAction::Created);
        assert_eq!(files.contents(&stored_at("BAR")), Some(Vec::new()));
    }

    #[tokio::test]
    async fn a_create_holds_the_tree_shared_and_its_directory_exclusively_until_the_node_is_attached()
     {
        let files = MemFsBackend::new();
        let gated = Gated::new(files.clone());
        let layer = names_over(gated.clone()).await;
        seed_dir(&files, "Docs");
        let gate = gated.arm_at(Op::Open, &stored_at("Docs\\file"));
        let creating = spawn_open(&layer, "Docs\\file", OpenIntent::Create);
        gate.reached().await;

        let locks = &layer.shared.locks;
        assert_eq!(locks.directory_count(), 1);
        let held = locks.directory(stored_name("Docs"));
        assert!(held.is_exclusive());
        assert!(locks.tree.try_write().is_err());
        assert!(locks.tree.try_read().is_ok());
        assert_eq!(layer.node_count(), 0);

        gate.release();
        let (_handle, _) = creating.await.unwrap().unwrap();
        assert_eq!(layer.node_count(), 1);
        assert!(held.is_free() && locks.tree.try_write().is_ok());
    }

    #[tokio::test]
    async fn a_create_keeps_its_directory_until_the_cached_names_have_the_entry() {
        let files = MemFsBackend::new();
        let gated = Gated::new(files.clone());
        let layer = names_over(gated.clone()).await;
        seed_dir(&files, "Docs");
        let docs = stored_name("Docs");
        let gate = gated.arm_after_at(Op::Open, &stored_at("Docs\\file"));
        let creating = spawn_open(&layer, "Docs\\file", OpenIntent::Create);
        gate.reached().await;

        assert_eq!(
            files.contents(&stored_at("Docs\\file")),
            Some(Vec::new()),
            "the inner create is done"
        );
        let held = layer.shared.locks.directory(docs.clone());
        assert!(held.is_exclusive());
        assert_eq!(layer.node_count(), 0);
        assert_eq!(held.changes(), 0, "the cached names are not patched");
        let names = layer.shared.names.fresh(&docs).expect("`Docs` was listed");
        assert!(names.entry("file", &stored_name("file")).is_none());
        drop(names);

        let second = spawn_open(&layer, "docs\\FILE", OpenIntent::Create);
        settle().await;
        assert!(!second.is_finished(), "the second create waits");
        gate.release();

        let (first, action) = creating.await.unwrap().unwrap();
        assert_eq!(action, OpenAction::Created);
        let error = second
            .await
            .unwrap()
            .err()
            .expect("the second create fails");
        assert!(matches!(error, SmbError::Exists), "{error:?}");
        assert_eq!(held.changes(), 1);
        assert_eq!(files.contents(&stored_at("Docs\\FILE")), None);
        assert_eq!(first.stat().await.unwrap().name, "file");
    }

    #[tokio::test]
    async fn two_creates_through_different_spellings_of_the_parent_make_one_entry() {
        let cases = [
            ("Docs\\x", "x", "docs\\X"),
            ("docs\\X", "X", "Docs\\x"),
            ("DOCS\\x", "x", "dOcS\\X"),
        ];
        for (first_name, first_leaf, second_name) in cases {
            let files = MemFsBackend::new();
            let gated = Gated::new(files.clone());
            let layer = names_over(gated.clone()).await;
            seed_dir(&files, "Docs");
            let stored = stored_at(&format!("Docs\\{first_leaf}"));
            let gate = gated.arm_at(Op::Open, &stored);
            let first = spawn_open(&layer, first_name, OpenIntent::Create);
            gate.reached().await;
            let second = spawn_open(&layer, second_name, OpenIntent::Create);
            settle().await;
            assert!(!second.is_finished(), "{first_name}: the second waits");

            gate.release();
            let (handle, action) = first.await.unwrap().unwrap();
            assert_eq!(action, OpenAction::Created, "{first_name}");
            let error = second
                .await
                .unwrap()
                .err()
                .expect("the second create fails");
            assert!(matches!(error, SmbError::Exists), "{first_name}: {error:?}");
            assert_eq!(files.contents(&stored), Some(Vec::new()), "{first_name}");
            let other = if first_leaf == "x" { "X" } else { "x" };
            assert_eq!(files.contents(&stored_at(&format!("Docs\\{other}"))), None);
            assert_eq!(handle.stat().await.unwrap().name, first_leaf);
        }
    }

    #[tokio::test]
    async fn a_create_over_a_file_deleted_from_outside_gets_its_own_node_when_files_have_ids() {
        let files = MemFsBackend::new();
        let layer = names_over(FileIds::new(files.clone())).await;
        seed_file(&files, "f", &stored_bytes(b"old"));
        let old = open_file(&layer, "f").await;
        files.remove(&stored_at("f"));

        let (new, action) = open(&layer, "f", OpenIntent::OpenOrCreate).await;
        assert_eq!(action, OpenAction::Created);
        assert!(!shares_node(&old, &new));
        assert_eq!(new.node().header().await, Some(HeaderKind::Absent));
        assert_eq!(old.node().header().await, Some(HeaderKind::Unknown));
        let again = open_file(&layer, "F").await;
        assert!(shares_node(&new, &again));
        assert_eq!(layer.node_count(), 2);
    }

    #[tokio::test]
    async fn a_create_that_fails_after_the_inner_create_drops_the_cached_names() {
        let files = MemFsBackend::new();
        let faulty = Faulty::new(files.clone());
        let layer = names_over(faulty.clone()).await;
        faulty.fail_stat(1, injected());

        let error = refused(&layer, "Foo", OpenIntent::Create).await;
        assert!(matches!(error, SmbError::Io(_)), "{error:?}");
        assert_eq!(files.contents(&stored_at("Foo")), Some(Vec::new()));
        assert_eq!(files.open_handles(), 0);
        assert_eq!(layer.node_count(), 0);

        let error = refused(&layer, "foo", OpenIntent::Create).await;
        assert!(matches!(error, SmbError::Exists), "{error:?}");
        assert_eq!(files.contents(&stored_at("foo")), None);
    }

    #[tokio::test]
    async fn a_create_dropped_after_the_inner_create_drops_the_cached_names() {
        let files = MemFsBackend::new();
        let gated = Gated::new(files.clone());
        let layer = names_over(gated.clone()).await;
        let gate = gated.arm_after_at(Op::Open, &stored_at("Foo"));

        drop_at(
            &gate,
            layer.open_handle(&path("Foo"), opts(OpenIntent::Create)),
        )
        .await;
        assert_eq!(files.contents(&stored_at("Foo")), Some(Vec::new()));
        assert!(layer.shared.locks.directory(String::new()).is_free());

        let error = refused(&layer, "foo", OpenIntent::Create).await;
        assert!(matches!(error, SmbError::Exists), "{error:?}");
        assert_eq!(files.contents(&stored_at("foo")), None);
    }

    #[tokio::test]
    async fn an_open_takes_the_tree_lock_once_so_a_rename_queued_behind_it_does_not_deadlock_it() {
        let cases = [
            ("Docs\\new", OpenIntent::Create),
            ("docs\\new", OpenIntent::Create),
            ("docs\\new", OpenIntent::OpenOrCreate),
            ("docs\\f", OpenIntent::Open),
            ("DOCS\\F", OpenIntent::Truncate),
            ("Docs\\f", OpenIntent::OverwriteOrCreate),
        ];
        for (name, intent) in cases {
            let files = MemFsBackend::new();
            let gated = Gated::new(files.clone());
            let layer = names_over(gated.clone()).await;
            seed_dir(&files, "Docs");
            seed_file(&files, "Docs\\f", &stored_bytes(b"x"));
            let gate = gated.arm(Op::Open);

            let opening = spawn_open(&layer, name, intent);
            gate.reached().await;
            let renaming = tokio::spawn({
                let layer = layer.clone();
                async move { drop(layer.shared.locks.tree.write().await) }
            });
            settle().await;
            assert!(!renaming.is_finished(), "{name}: the rename queues");

            gate.release();
            settle().await;
            assert!(opening.is_finished(), "{name} {intent:?}: the open ends");
            opening.await.unwrap().unwrap();
            renaming.await.unwrap();
        }
    }

    #[tokio::test]
    async fn a_new_name_is_created_for_every_intent_as_a_file_and_as_a_directory() {
        let (files, layer) = layer().await;
        for (n, intent) in CREATING.into_iter().enumerate() {
            let file = format!("File{n}");
            let (handle, action) = open(&layer, &file, intent).await;
            assert_eq!(action, OpenAction::Created, "{intent:?}");
            assert_eq!(handle.plain, Some(path(&file)));
            assert_eq!(handle.node().path(), path(&stored_at(&file)));
            assert!(!handle.node().is_directory());
            assert_eq!(handle.node().header().await, Some(HeaderKind::Absent));
            assert_eq!(files.contents(&stored_at(&file)), Some(Vec::new()));
        }
        for (n, intent) in [OpenIntent::Create, OpenIntent::OpenOrCreate]
            .into_iter()
            .enumerate()
        {
            let dir = format!("Dir{n}");
            let (handle, action) = open_dir_as(&layer, &dir, intent).await;
            assert_eq!(action, OpenAction::Created, "{intent:?}");
            assert_eq!(handle.plain, Some(path(&dir)));
            assert!(handle.node().is_directory());
            assert!(handle.stat().await.unwrap().is_directory);
            let (below, _) = open(&layer, &format!("{dir}\\x"), OpenIntent::Create).await;
            assert_eq!(below.node().path(), path(&stored_at(&format!("{dir}\\x"))));
        }

        let names = layer.shared.names.fresh("").expect("the root is cached");
        assert_eq!(names.len(), 5);
        for (name, directory) in [("file0", false), ("FILE2", false), ("dir0", true)] {
            let found = names.entry(name, &stored_name(name)).expect(name);
            assert_eq!(found.directory, directory, "{name}");
        }
        assert!(names.directory("DIR1", &stored_name("DIR1")).is_some());
        assert!(names.directory("file0", &stored_name("file0")).is_none());
    }

    #[tokio::test]
    async fn an_inner_create_goes_to_the_stored_name_with_the_side_object_first() {
        for (insensitive, intent) in CREATING
            .into_iter()
            .flat_map(|intent| [(true, intent), (false, intent)])
        {
            let files = MemFsBackend::new();
            let faulty = Faulty::new(files.clone());
            let layer = names_with(faulty.clone(), |builder| {
                builder.case_insensitive(insensitive)
            })
            .await;
            let long = long_name("x");
            let form = stored_form(&long);
            let side = form.side_object.expect("a long name").name;
            let before = faulty.open_calls().len();

            open(&layer, &long, intent).await;
            let mut expected = Vec::new();
            if insensitive {
                expected.push((String::new(), OpenIntent::Open));
            }
            expected.push((side, OpenIntent::OpenOrCreate));
            if !insensitive && intent == OpenIntent::OverwriteOrCreate {
                expected.push((form.entry.clone(), OpenIntent::Open));
            }
            expected.push((form.entry, intent));
            assert_eq!(
                faulty.open_calls()[before..],
                expected,
                "{intent:?} case_insensitive={insensitive}"
            );
        }
    }

    #[tokio::test]
    async fn a_name_that_is_not_long_has_no_side_object() {
        let files = MemFsBackend::new();
        let faulty = Faulty::new(files.clone());
        let layer = names_over(faulty.clone()).await;
        let before = faulty.open_calls().len();
        open(&layer, "short.txt", OpenIntent::Create).await;
        assert_eq!(
            faulty.open_calls()[before..],
            [
                (String::new(), OpenIntent::Open),
                (stored_name("short.txt"), OpenIntent::Create)
            ]
        );
    }

    #[tokio::test]
    async fn a_failed_inner_create_drops_the_cached_names_and_leaves_the_nodes_as_they_were() {
        let files = MemFsBackend::new();
        let faulty = Faulty::new(files.clone());
        let layer = names_over(faulty.clone()).await;
        let counter = layer.shared.locks.directory(String::new());
        let (_seed, _) = open(&layer, "Seed", OpenIntent::Create).await;
        assert_eq!(counter.changes(), 1);

        let entry = stored_name("New");
        faulty.fail_open(
            1,
            move |at, opts| {
                opts.intent == OpenIntent::Create && at.file_name() == Some(entry.as_str())
            },
            SmbError::DiskFull,
        );
        let error = refused(&layer, "New", OpenIntent::Create).await;
        assert!(matches!(error, SmbError::DiskFull), "{error:?}");
        assert_eq!(counter.changes(), 2);
        assert!(layer.shared.names.fresh("").is_none());
        assert_eq!(layer.node_count(), 1);
        assert_eq!(files.contents(&stored_at("New")), None);

        let (_, action) = open(&layer, "New", OpenIntent::Create).await;
        assert_eq!(action, OpenAction::Created);
        assert_eq!(counter.changes(), 3);
        assert_eq!(layer.shared.names.fresh("").unwrap().len(), 2);
    }

    #[tokio::test]
    async fn a_cached_name_the_inner_backend_cannot_find_twice_is_a_sharing_violation() {
        let files = MemFsBackend::new();
        let hidden = Hidden::new(files.clone());
        let layer = names_over(hidden.clone()).await;
        seed_file(&files, "Foo", &stored_bytes(b"data"));
        hidden.hide(&stored_at("Foo"));

        for intent in [OpenIntent::OpenOrCreate, OpenIntent::OverwriteOrCreate] {
            let error = refused(&layer, "foo", intent).await;
            assert!(matches!(error, SmbError::Sharing), "{intent:?}: {error:?}");
            assert!(
                layer.shared.names.fresh("").is_none(),
                "the cached names are dropped"
            );
        }
        let error = refused(&layer, "FOO", OpenIntent::Create).await;
        assert!(matches!(error, SmbError::Exists), "{error:?}");

        hidden.show(&stored_at("Foo"));
        let (handle, action) = open(&layer, "foo", OpenIntent::OpenOrCreate).await;
        assert_eq!(action, OpenAction::Opened);
        assert_eq!(read_all(&handle).await, b"data");
        assert_eq!(files.contents(&stored_at("foo")), None);
    }

    #[tokio::test(start_paused = true)]
    async fn a_listing_that_starts_during_the_inner_create_is_not_kept_over_the_change() {
        let files = MemFsBackend::new();
        let gated = Gated::new(files.clone());
        let layer = names_over(gated.clone()).await;
        seed_file(&files, "a.txt", b"");
        let create_gate = gated.arm_at(Op::Open, &stored_name("new.txt"));
        let creating = spawn_open(&layer, "new.txt", OpenIntent::Create);
        create_gate.reached().await;
        layer.shared.names.forget("");
        let listing_gate = gated.arm_after_at(Op::ListDir, "");
        let building = tokio::spawn({
            let layer = layer.clone();
            async move { layer.names_of(&SmbPath::root(), Hold::Nothing).await }
        });
        listing_gate.reached().await;

        create_gate.release();
        let (_handle, _) = creating.await.unwrap().unwrap();
        listing_gate.release();
        building.await.unwrap().unwrap().unwrap();
        assert!(
            layer.shared.names.fresh("").is_none(),
            "the listing began before the change and does not replace the cache"
        );
    }
}
