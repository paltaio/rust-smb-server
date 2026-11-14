//! Lists a stored directory and decodes the names in it, for the name cache.

use std::io;
use std::sync::Arc;

use tokio::task::JoinSet;
use tokio::time::Instant;
use tracing::{debug, warn};

use super::backend::EncryptedBackend;
use super::cache::{Entry, Snapshot};
use super::inner::{close_after_reading, is_missing, read_side_object};
use super::names::{StoredKind, classify, decode_long, decode_short, side_object_name};
use super::node::{NameMatch, path_key};
use crate::backend::{DirEntry, OpenOptions, ShareBackend};
use crate::error::{SmbError, SmbResult};
use crate::path::SmbPath;

/// Side objects read at once.
const SIDE_READS_IN_FLIGHT: usize = 8;

/// What the caller of a build holds.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Hold {
    /// The lock of the directory, or the tree lock exclusively. Nothing
    /// changes the names of the directory meanwhile, so the listing is kept
    /// as it is.
    Lock,
    /// Neither. The listing is kept only if the names of the directory did
    /// not change while it was read.
    Nothing,
}

impl<B: ShareBackend> EncryptedBackend<B> {
    /// The names of the stored directory `dir`: the cached ones while they
    /// are fresh, else a new listing, which the cache keeps as `hold` says.
    /// `None` when the inner backend has no such directory.
    pub(super) async fn names_of(
        &self,
        dir: &SmbPath,
        hold: Hold,
    ) -> SmbResult<Option<Arc<Snapshot>>> {
        let key = path_key(dir, NameMatch::Exact);
        if let Some(names) = self.shared.names.fresh(&key) {
            return Ok(Some(names));
        }
        // The entry stays in the lock table while this call holds it, so its
        // count of changes does not start over during the listing.
        let lock = self.shared.locks.directory(key.clone());
        let changes = lock.changes();
        let built = Instant::now();
        let Some(listed) = self.list_stored(dir).await? else {
            return Ok(None);
        };
        let entries = self.decode(dir, listed).await?;
        let names = Arc::new(Snapshot::new(entries, built));
        self.shared.names.install_if(key, Arc::clone(&names), || {
            hold == Hold::Lock || lock.changes() == changes
        });
        Ok(Some(names))
    }

    /// Drops the cached names of the directory with `key`. A listing that
    /// began earlier and holds no lock is not kept.
    pub(super) fn invalidate(&self, key: &str) {
        self.shared.locks.directory(key.to_string()).count_change();
        self.shared.names.forget(key);
    }

    /// The entries of the stored directory `dir`, or `None` when the inner
    /// backend has no such directory.
    async fn list_stored(&self, dir: &SmbPath) -> SmbResult<Option<Vec<DirEntry>>> {
        let opts = OpenOptions {
            read: true,
            directory: true,
            ..OpenOptions::default()
        };
        let handle = match self.shared.inner.open(dir, opts).await {
            Ok((handle, _)) => handle,
            Err(error) if is_missing(&error) => return Ok(None),
            Err(error) => return Err(error),
        };
        let listed = handle.list_dir_sized(None, false).await;
        close_after_reading(handle).await;
        match listed {
            Ok(entries) => Ok(Some(entries)),
            Err(error) if is_missing(&error) => Ok(None),
            Err(error) => Err(error),
        }
    }

    /// The names in a listing of the stored directory `dir`. The marker, side
    /// objects and names that do not decode are left out.
    async fn decode(&self, dir: &SmbPath, listed: Vec<DirEntry>) -> SmbResult<Vec<Entry>> {
        let in_root = dir.is_root();
        let mut entries = Vec::with_capacity(listed.len());
        let mut long = Vec::new();
        for DirEntry { info } in listed {
            let directory = info.is_directory;
            let stored = info.name;
            let plain = match classify(&stored, in_root) {
                StoredKind::Marker | StoredKind::SideObject => continue,
                StoredKind::ShortCandidate => decode_short(&self.shared.keys, &stored).ok(),
                StoredKind::Foreign => None,
                StoredKind::LongEntry => {
                    let Some(plain) = self.shared.long_names.get(&stored) else {
                        long.push((stored, directory));
                        continue;
                    };
                    Some(plain)
                }
            };
            match plain {
                Some(plain) => entries.push(Entry {
                    plain,
                    stored,
                    directory,
                }),
                None => debug!(stored = ?stored, "not an encrypted name"),
            }
        }
        self.decode_long_entries(dir, long, &mut entries).await?;
        Ok(entries)
    }

    /// Reads the side objects of the long entries `pending` of the stored
    /// directory `dir`, a few at a time, and adds the entries that decode to
    /// `entries`. An entry whose side object is missing, invalid or cannot be
    /// read is left out.
    async fn decode_long_entries(
        &self,
        dir: &SmbPath,
        mut pending: Vec<(String, bool)>,
        entries: &mut Vec<Entry>,
    ) -> SmbResult<()> {
        let mut reads = JoinSet::new();
        loop {
            while reads.len() < SIDE_READS_IN_FLIGHT
                && let Some((stored, directory)) = pending.pop()
            {
                let name = side_object_name(&stored).expect("a long entry has a side object name");
                let Ok(side) = dir.join(&name) else {
                    warn!(dir = %dir, stored = ?stored, "long entry has no valid side object");
                    continue;
                };
                let shared = Arc::clone(&self.shared);
                reads.spawn(async move {
                    let content = read_side_object(&shared.inner, &side).await;
                    (stored, directory, content)
                });
            }
            let Some(joined) = reads.join_next().await else {
                return Ok(());
            };
            let (stored, directory, content) =
                joined.map_err(|error| SmbError::Io(io::Error::other(error)))?;
            let plain = match content {
                Ok(content) => content
                    .and_then(|content| decode_long(&self.shared.keys, &stored, &content).ok()),
                Err(error) => {
                    warn!(dir = %dir, stored = ?stored, error = ?error, "side object of a long entry cannot be read");
                    continue;
                }
            };
            let Some(plain) = plain else {
                warn!(dir = %dir, stored = ?stored, "long entry has no valid side object");
                continue;
            };
            self.shared.long_names.insert(stored.clone(), &plain);
            entries.push(Entry {
                plain,
                stored,
                directory,
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    use async_trait::async_trait;

    use super::super::format::MARKER_NAME;
    use super::super::names::encode_name;
    use super::super::testing::{
        names_over, names_with, open_file, other_key_schedule, seed_dir, seed_file, spawn_open,
        stored_at, stored_form, stored_name,
    };
    use super::*;
    use crate::backend::{BackendCapabilities, Handle, OpenAction, OpenIntent};
    use crate::tests::faulty::Faulty;
    use crate::tests::gated::{Gate, Gated, Op};
    use crate::tests::logs::Logs;
    use crate::tests::memfs::MemFsBackend;

    type Layer = EncryptedBackend<Gated<MemFsBackend>>;

    fn root() -> SmbPath {
        SmbPath::root()
    }

    /// A store with `a.txt` in the root, and a backend over it that parks the
    /// listing of the root once the inner backend has answered.
    async fn parked() -> (MemFsBackend, Layer, Gate) {
        let files = MemFsBackend::new();
        let gated = Gated::new(files.clone());
        let layer = names_over(gated.clone()).await;
        seed_file(&files, "a.txt", b"");
        let gate = gated.arm_after_at(Op::ListDir, "");
        (files, layer, gate)
    }

    /// The names of the root, built in a task. The task parks after the
    /// listing, until the gate is released.
    fn build(
        layer: &Layer,
        hold: Hold,
    ) -> tokio::task::JoinHandle<SmbResult<Option<Arc<Snapshot>>>> {
        let layer = layer.clone();
        tokio::spawn(async move { layer.names_of(&root(), hold).await })
    }

    fn lists(names: &Snapshot, name: &str) -> bool {
        names.entry(name, &stored_name(name)).is_some()
    }

    #[tokio::test]
    async fn a_listing_made_under_the_lock_is_kept_whatever_changed_meanwhile() {
        let (files, layer, gate) = parked().await;
        let building = build(&layer, Hold::Lock);
        gate.reached().await;
        layer.shared.locks.directory(String::new()).count_change();
        seed_file(&files, "late.txt", b"");
        gate.release();

        let names = building.await.unwrap().unwrap().unwrap();
        assert!(lists(&names, "a.txt") && !lists(&names, "late.txt"));
        let kept = layer.shared.names.fresh("").expect("the listing is kept");
        assert!(Arc::ptr_eq(&kept, &names));
    }

    #[tokio::test]
    async fn a_listing_made_without_a_lock_is_kept_when_nothing_changed() {
        let (_, layer, gate) = parked().await;
        let building = build(&layer, Hold::Nothing);
        gate.reached().await;
        gate.release();

        let names = building.await.unwrap().unwrap().unwrap();
        let kept = layer.shared.names.fresh("").expect("the listing is kept");
        assert!(Arc::ptr_eq(&kept, &names));
    }

    #[tokio::test]
    async fn a_listing_made_without_a_lock_is_not_kept_when_the_names_changed_meanwhile() {
        let (files, layer, gate) = parked().await;
        let building = build(&layer, Hold::Nothing);
        gate.reached().await;
        layer.shared.locks.directory(String::new()).count_change();
        seed_file(&files, "late.txt", b"");
        gate.release();

        let names = building.await.unwrap().unwrap().unwrap();
        assert!(lists(&names, "a.txt"), "the caller still gets its listing");
        assert!(layer.shared.names.fresh("").is_none());
    }

    #[tokio::test]
    async fn a_listing_that_is_not_kept_leaves_the_cache_that_is_there() {
        let (_, layer, gate) = parked().await;
        let building = build(&layer, Hold::Nothing);
        gate.reached().await;
        let installed = layer.names_of(&root(), Hold::Lock).await.unwrap().unwrap();
        layer.shared.locks.directory(String::new()).count_change();
        gate.release();

        let late = building.await.unwrap().unwrap().unwrap();
        assert!(!Arc::ptr_eq(&late, &installed));
        let kept = layer.shared.names.fresh("").expect("the cache stays");
        assert!(Arc::ptr_eq(&kept, &installed));
    }

    #[tokio::test(start_paused = true)]
    async fn a_listing_that_began_earlier_does_not_replace_a_later_one() {
        let (files, layer, gate) = parked().await;
        let slow = build(&layer, Hold::Lock);
        gate.reached().await;
        tokio::time::advance(Duration::from_secs(1)).await;
        seed_file(&files, "late.txt", b"");
        let fast = layer.names_of(&root(), Hold::Lock).await.unwrap().unwrap();
        assert!(lists(&fast, "late.txt"));
        gate.release();

        let old = slow.await.unwrap().unwrap().unwrap();
        assert!(!lists(&old, "late.txt"), "the caller gets what it listed");
        let kept = layer
            .shared
            .names
            .fresh("")
            .expect("the later listing stays");
        assert!(Arc::ptr_eq(&kept, &fast));
    }

    #[tokio::test(start_paused = true)]
    async fn a_listing_goes_stale_a_time_to_live_after_it_began() {
        let ttl = Duration::from_secs(10);
        let files = MemFsBackend::new();
        let gated = Gated::new(files.clone());
        let layer = names_with(gated.clone(), |builder| builder.name_cache_ttl(ttl)).await;
        seed_file(&files, "a.txt", b"");
        let gate = gated.arm_after_at(Op::ListDir, "");
        let building = build(&layer, Hold::Lock);
        gate.reached().await;
        tokio::time::advance(ttl - Duration::from_secs(1)).await;
        gate.release();
        building.await.unwrap().unwrap().unwrap();

        assert!(layer.shared.names.fresh("").is_some());
        tokio::time::advance(Duration::from_secs(1)).await;
        assert!(
            layer.shared.names.fresh("").is_none(),
            "the time to live counts from before the listing"
        );
    }

    #[tokio::test]
    async fn the_count_of_changes_survives_a_listing_in_flight() {
        let (_, layer, gate) = parked().await;
        let locks = &layer.shared.locks;
        assert_eq!(locks.directory_count(), 0);
        let building = build(&layer, Hold::Nothing);
        gate.reached().await;
        assert_eq!(locks.directory_count(), 1, "the listing holds its entry");

        locks.directory(String::new()).count_change();
        locks.directory(String::new()).count_change();
        assert_eq!(locks.directory(String::new()).changes(), 2);
        gate.release();
        building.await.unwrap().unwrap();
        assert_eq!(locks.directory_count(), 0);
        assert_eq!(locks.directory(String::new()).changes(), 0);
    }

    #[tokio::test]
    async fn a_walk_does_not_keep_a_listing_that_a_change_overtook() {
        let (files, layer, gate) = parked().await;
        seed_file(&files, "Docs\\f.txt", b"");
        let opening = spawn_open(&layer, "docs\\f.txt", OpenIntent::Open);
        gate.reached().await;
        layer.shared.locks.directory(String::new()).count_change();
        gate.release();
        let (first, action) = opening.await.unwrap().unwrap();
        assert_eq!(action, OpenAction::Opened);
        assert_eq!(first.stat().await.unwrap().name, "f.txt");
        assert!(layer.shared.names.fresh("").is_none());

        open_file(&layer, "docs\\f.txt").await;
        assert!(layer.shared.names.fresh("").is_some());
    }

    #[tokio::test]
    async fn a_listing_leaves_out_the_marker_side_objects_and_names_that_do_not_decode() {
        let logs = Logs::new();
        let files = MemFsBackend::new();
        let layer = names_over(files.clone()).await;
        let long = "l".repeat(150);
        let orphan = "o".repeat(150);
        seed_dir(&files, "Docs");
        seed_file(&files, "a.txt", b"");
        seed_file(&files, &long, b"");
        seed_file(&files, &orphan, b"");
        files.remove(&stored_form(&orphan).entry);
        let other_key = encode_name(&other_key_schedule(), "other", 255)
            .unwrap()
            .entry;
        for foreign in [
            "junk",
            "UPPER-case.txt",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.n.n",
            &other_key,
        ] {
            files.clone().with_file(foreign, b"");
        }
        assert!(files.contents(MARKER_NAME).is_some());

        let names = layer.names_of(&root(), Hold::Lock).await.unwrap().unwrap();
        assert_eq!(names.len(), 3);
        assert!(names.directory("docs", &stored_name("docs")).is_some());
        assert!(lists(&names, "a.txt") && lists(&names, &long));
        assert!(!lists(&names, &orphan));
        assert!(logs.warnings().is_empty(), "{:?}", logs.warnings());
    }

    #[tokio::test]
    async fn a_missing_directory_has_no_names() {
        let files = MemFsBackend::new();
        let layer = names_over(files.clone()).await;
        seed_file(&files, "f", b"");
        for missing in [
            "nowhere",
            &stored_at("f"),
            &format!("{}\\x", stored_at("f")),
        ] {
            let at: SmbPath = missing.parse().unwrap();
            assert!(
                layer.names_of(&at, Hold::Lock).await.unwrap().is_none(),
                "{missing}"
            );
        }
        assert!(layer.shared.names.keys().is_empty());
    }

    /// An inner backend that counts the opens of side objects in flight.
    #[derive(Clone)]
    struct Watching {
        inner: MemFsBackend,
        now: Arc<AtomicUsize>,
        most: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl ShareBackend for Watching {
        async fn open(
            &self,
            at: &SmbPath,
            opts: OpenOptions,
        ) -> SmbResult<(Box<dyn Handle>, OpenAction)> {
            if !at.file_name().is_some_and(|name| name.ends_with(".n")) {
                return self.inner.open(at, opts).await;
            }
            let now = self.now.fetch_add(1, Ordering::SeqCst) + 1;
            self.most.fetch_max(now, Ordering::SeqCst);
            for _ in 0..4 {
                tokio::task::yield_now().await;
            }
            let opened = self.inner.open(at, opts).await;
            self.now.fetch_sub(1, Ordering::SeqCst);
            opened
        }

        async fn unlink(&self, at: &SmbPath) -> SmbResult<()> {
            self.inner.unlink(at).await
        }

        async fn rename(&self, from: &SmbPath, to: &SmbPath, replace: bool) -> SmbResult<()> {
            self.inner.rename(from, to, replace).await
        }

        fn capabilities(&self) -> BackendCapabilities {
            self.inner.capabilities()
        }
    }

    #[tokio::test]
    async fn at_most_eight_side_objects_are_read_at_once() {
        let files = MemFsBackend::new();
        let watching = Watching {
            inner: files.clone(),
            now: Arc::default(),
            most: Arc::default(),
        };
        let layer = names_over(watching.clone()).await;
        let names: Vec<String> = (0..20).map(|n| format!("{n:0>150}")).collect();
        for name in &names {
            seed_file(&files, name, b"");
        }

        let listed = layer.names_of(&root(), Hold::Lock).await.unwrap().unwrap();
        assert_eq!(listed.len(), 20);
        assert!(names.iter().all(|name| lists(&listed, name)));
        assert_eq!(watching.most.load(Ordering::SeqCst), 8);
        assert_eq!(layer.shared.long_names.len(), 20);
        assert_eq!(files.open_handles(), 0, "every side object is closed");
    }

    #[tokio::test]
    async fn a_listing_that_fails_fails_the_build_and_keeps_nothing() {
        let files = MemFsBackend::new();
        let faulty = Faulty::new(files.clone());
        let layer = names_over(faulty.clone()).await;
        seed_file(&files, "a.txt", b"");
        let injected = || SmbError::Io(io::Error::other("injected"));

        faulty.fail_open(1, |_, opts| opts.directory, injected());
        assert!(matches!(
            layer.names_of(&root(), Hold::Lock).await,
            Err(SmbError::Io(_))
        ));
        faulty.fail_listing(1, injected());
        assert!(matches!(
            layer.names_of(&root(), Hold::Lock).await,
            Err(SmbError::Io(_))
        ));
        assert!(layer.shared.names.keys().is_empty());
        assert_eq!(files.open_handles(), 0, "the directory is closed");

        let names = layer.names_of(&root(), Hold::Lock).await.unwrap().unwrap();
        assert!(lists(&names, "a.txt"));
    }

    #[tokio::test]
    async fn a_side_object_that_cannot_be_read_leaves_out_its_entry_only() {
        let logs = Logs::new();
        let files = MemFsBackend::new();
        let faulty = Faulty::new(files.clone());
        let layer = names_over(faulty.clone()).await;
        let (broken, sound) = ("b".repeat(150), "s".repeat(150));
        seed_file(&files, "a.txt", b"");
        seed_file(&files, &broken, b"");
        seed_file(&files, &sound, b"");
        let side = stored_form(&broken).side_object.unwrap().name;
        faulty.fail_open(
            1,
            move |at, _| at.file_name() == Some(side.as_str()),
            SmbError::Io(io::Error::other("injected")),
        );

        let names = layer.names_of(&root(), Hold::Lock).await.unwrap().unwrap();
        assert_eq!(names.len(), 2);
        assert!(lists(&names, "a.txt") && lists(&names, &sound));
        assert!(!lists(&names, &broken));
        let warnings = logs.warnings();
        assert_eq!(warnings.len(), 1, "{warnings:?}");
        assert!(warnings[0].contains(&stored_form(&broken).entry));
        assert!(
            layer.shared.names.fresh("").is_some(),
            "the listing is kept"
        );
        assert_eq!(files.open_handles(), 0);
    }

    #[tokio::test]
    async fn a_side_object_that_is_too_long_or_a_directory_is_not_a_name() {
        let logs = Logs::new();
        let files = MemFsBackend::new();
        let faulty = Faulty::new(files.clone());
        let layer = names_over(faulty.clone()).await;
        let (huge, folder) = ("h".repeat(150), "f".repeat(150));
        seed_file(&files, &huge, b"");
        seed_file(&files, &folder, b"");
        files
            .clone()
            .with_file(&stored_form(&huge).side_object.unwrap().name, &[7; 5000]);
        files.remove(&stored_form(&folder).side_object.unwrap().name);
        files
            .clone()
            .with_dir(&stored_form(&folder).side_object.unwrap().name);

        let names = layer.names_of(&root(), Hold::Lock).await.unwrap().unwrap();
        assert_eq!(names.len(), 0);
        assert_eq!(logs.warnings().len(), 2, "{:?}", logs.warnings());
        assert!(
            faulty.reads().is_empty(),
            "nothing of an object over 1024 bytes is read"
        );
    }
}
