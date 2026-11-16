//! Lists a stored directory and decodes the names in it.

use std::io;
use std::sync::Arc;

use tokio::task::JoinSet;
use tokio::time::Instant;
use tracing::{debug, warn};

use super::backend::{EncryptedBackend, Shared};
use super::cache::{Entry, Snapshot};
use super::inner::{close_after_reading, is_missing, read_side_object};
use super::locks::DirLock;
use super::names::{StoredKind, classify, decode_long, decode_short, side_object_name};
use super::node::{NameMatch, path_key};
use crate::backend::{DirEntry, FileInfo, OpenOptions, ShareBackend};
use crate::error::{SmbError, SmbResult};
use crate::path::SmbPath;

/// Side objects read at once.
const SIDE_READS_IN_FLIGHT: usize = 8;

/// A name of a listing, decoded, with what the inner backend listed for its
/// entry.
pub(super) struct Decoded {
    pub(super) entry: Entry,
    /// The info the inner listing gave; its `name` is the stored name.
    pub(super) info: FileInfo,
}

impl Decoded {
    fn new(plain: String, info: FileInfo) -> Self {
        Self {
            entry: Entry {
                plain,
                stored: info.name.clone(),
                directory: info.is_directory,
            },
            info,
        }
    }
}

/// The names of a listing, decoded.
pub(super) struct Listing {
    pub(super) names: Vec<Decoded>,
    /// False when an entry is left out because its side object could not be
    /// read.
    pub(super) complete: bool,
}

/// What a stored name is, judged without reading anything.
pub(super) enum Name {
    /// An entry of the share, under this name.
    Plain(String),
    /// A long entry that the long-name cache does not hold. Its side object
    /// says what it is called.
    Long,
    /// The marker, a side object, or a name that is not one of the share's.
    Hidden,
}

impl<B> Shared<B> {
    /// What the stored name `stored` is. `in_root` is true in the root of the
    /// inner backend, the only place of the marker. A name that is not one of
    /// the share's is logged, by its stored name only.
    pub(super) fn read_name(&self, stored: &str, in_root: bool) -> Name {
        let plain = match classify(stored, in_root) {
            StoredKind::Marker | StoredKind::SideObject => return Name::Hidden,
            StoredKind::LongEntry => {
                return self.long_names.get(stored).map_or(Name::Long, Name::Plain);
            }
            StoredKind::ShortCandidate => decode_short(&self.keys, stored).ok(),
            StoredKind::Foreign => None,
        };
        match plain {
            Some(plain) => Name::Plain(plain),
            None => {
                debug!(stored = ?stored, "not an encrypted name");
                Name::Hidden
            }
        }
    }
}

/// What the caller of a listing holds.
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

/// The time and the count of changes of a directory when a listing of it
/// began.
#[derive(Clone, Copy)]
pub(super) struct Began {
    built: Instant,
    changes: u64,
}

impl Began {
    /// Read before the listing, from the lock entry the listing holds.
    pub(super) fn of(lock: &DirLock) -> Self {
        Self {
            built: Instant::now(),
            changes: lock.changes(),
        }
    }
}

impl<B> Shared<B> {
    /// The snapshot of `entries`, the names of the directory of `lock` as a
    /// listing that `began` read them. The name cache keeps it, unless an
    /// entry was left out for want of its side object (`complete` is false),
    /// or `hold` is `Nothing` and a change was counted since the listing
    /// began.
    pub(super) fn keep_names(
        &self,
        lock: &DirLock,
        began: Began,
        hold: Hold,
        complete: bool,
        entries: impl Iterator<Item = Entry>,
    ) -> Arc<Snapshot> {
        let names = Arc::new(Snapshot::new(entries.collect(), began.built));
        if complete {
            let key = lock.key().to_string();
            self.names.install_if(key, Arc::clone(&names), || {
                hold == Hold::Lock || lock.changes() == began.changes
            });
        }
        names
    }
}

/// The names of a stored directory, and where they came from.
pub(super) struct Names {
    pub(super) snapshot: Arc<Snapshot>,
    /// The call built the names by listing the directory. Otherwise they were
    /// cached, and may lack entries that were added from outside.
    pub(super) built: bool,
}

/// Drops the cached names of the directories it was made for when it goes out
/// of scope armed. An unlink or a rename holds one while the inner call runs,
/// so a call that is dropped meanwhile never leaves cached names that disagree
/// with the inner backend. Nodes keep their paths: a dropped call does not say
/// whether the inner call landed.
pub(super) struct DropChange<'a, B: ShareBackend> {
    layer: &'a EncryptedBackend<B>,
    keys: Vec<String>,
    below: Option<SmbPath>,
    armed: bool,
}

impl<'a, B: ShareBackend> DropChange<'a, B> {
    /// A guard for the stored directories `dirs`, and for the directories at
    /// and below `below`, the old path of a directory that is renamed or
    /// removed.
    pub(super) fn arm(
        layer: &'a EncryptedBackend<B>,
        dirs: &[&SmbPath],
        below: Option<&SmbPath>,
    ) -> Self {
        Self {
            layer,
            keys: dirs
                .iter()
                .map(|dir| path_key(dir, NameMatch::Exact))
                .collect(),
            below: below.cloned(),
            armed: true,
        }
    }

    /// The inner call has returned.
    pub(super) fn disarm(&mut self) {
        self.armed = false;
    }
}

impl<B: ShareBackend> Drop for DropChange<'_, B> {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        for key in &self.keys {
            self.layer.invalidate(key);
        }
        if let Some(dir) = &self.below {
            self.layer.forget_below(dir);
        }
    }
}

impl<B: ShareBackend> EncryptedBackend<B> {
    /// The names of the stored directory `dir`: the cached ones while they
    /// are fresh, else a new listing, which the cache keeps as `hold` says
    /// when every side object was read. `None` when the inner backend has no
    /// such directory.
    pub(super) async fn names_of(
        &self,
        dir: &SmbPath,
        hold: Hold,
    ) -> SmbResult<Option<Arc<Snapshot>>> {
        Ok(self
            .lookup_names(dir, hold)
            .await?
            .map(|names| names.snapshot))
    }

    /// `names_of`, with whether this call built the names.
    pub(super) async fn lookup_names(&self, dir: &SmbPath, hold: Hold) -> SmbResult<Option<Names>> {
        let key = path_key(dir, NameMatch::Exact);
        if let Some(snapshot) = self.shared.names.fresh(&key) {
            return Ok(Some(Names {
                snapshot,
                built: false,
            }));
        }
        // The entry stays in the lock table while this call holds it, so its
        // count of changes does not start over during the listing.
        let lock = self.shared.locks.directory(key);
        let began = Began::of(&lock);
        let Some(listed) = self.list_stored(dir).await? else {
            return Ok(None);
        };
        let listing = self.decode(dir, listed).await?;
        let entries = listing.names.into_iter().map(|decoded| decoded.entry);
        let snapshot = self
            .shared
            .keep_names(&lock, began, hold, listing.complete, entries);
        Ok(Some(Names {
            snapshot,
            built: true,
        }))
    }

    /// Drops the cached names of the directory with `key`. A listing that
    /// began earlier and holds no lock is not kept.
    pub(super) fn invalidate(&self, key: &str) {
        self.shared.locks.directory(key.to_string()).count_change();
        self.shared.names.forget(key);
    }

    /// Drops the cached names of the stored directory `dir` and of the
    /// directories below it. Called once the inner backend has renamed or
    /// removed the directory. Every directory of those that a listing holds
    /// the lock entry of counts a change, so a listing that began earlier is
    /// not kept.
    pub(super) fn forget_below(&self, dir: &SmbPath) {
        let key = path_key(dir, NameMatch::Exact);
        let held = self.shared.locks.directories_below(&key);
        self.shared.names.forget_below(&key, &held);
    }

    /// The entries of the stored directory `dir`, or `None` when the inner
    /// backend has no such directory.
    pub(super) async fn list_stored(&self, dir: &SmbPath) -> SmbResult<Option<Vec<DirEntry>>> {
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

    /// The names in a listing of the stored directory `dir`, each with the
    /// info its entry came with. The marker, side objects and names that do
    /// not decode are left out. Long entries come after the others.
    pub(super) async fn decode(&self, dir: &SmbPath, listed: Vec<DirEntry>) -> SmbResult<Listing> {
        let in_root = dir.is_root();
        let mut names = Vec::with_capacity(listed.len());
        let mut long = Vec::new();
        for DirEntry { info } in listed {
            match self.shared.read_name(&info.name, in_root) {
                Name::Plain(plain) => names.push(Decoded::new(plain, info)),
                Name::Long => long.push(info),
                Name::Hidden => {}
            }
        }
        let complete = self.decode_long_entries(dir, long, &mut names).await?;
        Ok(Listing { names, complete })
    }

    /// Reads the side objects of the long entries `pending` of the stored
    /// directory `dir`, a few at a time, and adds the entries that decode to
    /// `decoded`. An entry whose side object is missing or invalid is left
    /// out. So is one whose side object cannot be read, and then the result
    /// is false.
    async fn decode_long_entries(
        &self,
        dir: &SmbPath,
        mut pending: Vec<FileInfo>,
        decoded: &mut Vec<Decoded>,
    ) -> SmbResult<bool> {
        let mut complete = true;
        let mut reads = JoinSet::new();
        loop {
            while reads.len() < SIDE_READS_IN_FLIGHT
                && let Some(info) = pending.pop()
            {
                let name =
                    side_object_name(&info.name).expect("a long entry has a side object name");
                let Ok(side) = dir.join(&name) else {
                    warn!(dir = %dir, stored = ?info.name, "long entry has no valid side object");
                    continue;
                };
                let shared = Arc::clone(&self.shared);
                reads.spawn(async move {
                    let content = read_side_object(&shared.inner, &side).await;
                    (info, content)
                });
            }
            let Some(joined) = reads.join_next().await else {
                return Ok(complete);
            };
            let (info, content) = joined.map_err(|error| SmbError::Io(io::Error::other(error)))?;
            let plain = match content {
                Ok(content) => content
                    .and_then(|content| decode_long(&self.shared.keys, &info.name, &content).ok()),
                Err(error) => {
                    warn!(dir = %dir, stored = ?info.name, error = ?error, "side object of a long entry cannot be read");
                    complete = false;
                    continue;
                }
            };
            let Some(plain) = plain else {
                warn!(dir = %dir, stored = ?info.name, "long entry has no valid side object");
                continue;
            };
            self.shared.long_names.insert(info.name.clone(), &plain);
            decoded.push(Decoded::new(plain, info));
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    use async_trait::async_trait;

    use super::super::format::MARKER_NAME;
    use super::super::testing::{
        GatedLayer, fail_open_of, has, injected, names_over, names_with, open_file, parked,
        seed_dir, seed_file, seed_hidden_names, spawn_open, stored_at, stored_form, stored_name,
    };
    use super::*;
    use crate::backend::{BackendCapabilities, Handle, OpenAction, OpenIntent};
    use crate::tests::faulty::Faulty;
    use crate::tests::gated::{Gated, Op};
    use crate::tests::logs::Logs;
    use crate::tests::memfs::MemFsBackend;

    fn root() -> SmbPath {
        SmbPath::root()
    }

    /// The names of the root, built in a task. The task parks after the
    /// listing, until the gate is released.
    fn build(
        layer: &GatedLayer,
        hold: Hold,
    ) -> tokio::task::JoinHandle<SmbResult<Option<Arc<Snapshot>>>> {
        let layer = layer.clone();
        tokio::spawn(async move { layer.names_of(&root(), hold).await })
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
        assert!(has(&names, "a.txt") && !has(&names, "late.txt"));
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
        assert!(has(&names, "a.txt"), "the caller still gets its listing");
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
        assert!(has(&fast, "late.txt"));
        gate.release();

        let old = slow.await.unwrap().unwrap().unwrap();
        assert!(!has(&old, "late.txt"), "the caller gets what it listed");
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
        seed_dir(&files, "Docs");
        seed_file(&files, "a.txt", b"");
        seed_file(&files, &long, b"");
        seed_hidden_names(&files);
        assert!(files.contents(MARKER_NAME).is_some());

        let names = layer.names_of(&root(), Hold::Lock).await.unwrap().unwrap();
        assert_eq!(names.len(), 3);
        assert!(names.directory("docs", &stored_name("docs")).is_some());
        assert!(has(&names, "a.txt") && has(&names, &long));
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
        assert!(names.iter().all(|name| has(&listed, name)));
        assert_eq!(watching.most.load(Ordering::SeqCst), 8);
        assert_eq!(layer.shared.long_names.len(), 20);
        assert_eq!(files.open_handles(), 0, "every side object is closed");
    }

    #[tokio::test]
    async fn a_listing_that_fails_fails_the_lookup_and_keeps_nothing() {
        let files = MemFsBackend::new();
        let faulty = Faulty::new(files.clone());
        let layer = names_over(faulty.clone()).await;
        seed_file(&files, "a.txt", b"");

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
        assert!(has(&names, "a.txt"));
    }

    #[tokio::test]
    async fn a_side_object_that_cannot_be_read_leaves_out_its_entry_and_the_names_are_not_kept() {
        let logs = Logs::new();
        let files = MemFsBackend::new();
        let faulty = Faulty::new(files.clone());
        let layer = names_over(faulty.clone()).await;
        let (broken, sound) = ("b".repeat(150), "s".repeat(150));
        seed_file(&files, "a.txt", b"");
        seed_file(&files, &broken, b"");
        seed_file(&files, &sound, b"");
        let side = stored_form(&broken).side_object.unwrap().name;
        fail_open_of(&faulty, &side);

        let names = layer.names_of(&root(), Hold::Lock).await.unwrap().unwrap();
        assert_eq!(names.len(), 2);
        assert!(has(&names, "a.txt") && has(&names, &sound));
        assert!(!has(&names, &broken));
        let warnings = logs.warnings();
        assert_eq!(warnings.len(), 1, "{warnings:?}");
        assert!(warnings[0].contains(&stored_form(&broken).entry));
        assert!(layer.shared.names.fresh("").is_none());
        assert_eq!(files.open_handles(), 0);

        let names = layer.names_of(&root(), Hold::Lock).await.unwrap().unwrap();
        assert_eq!(names.len(), 3);
        assert!(has(&names, &broken));
        let kept = layer.shared.names.fresh("").expect("the listing is kept");
        assert!(Arc::ptr_eq(&kept, &names));
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
