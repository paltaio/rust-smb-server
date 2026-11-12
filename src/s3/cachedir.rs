//! The cache directory: its lock, its identity, and the data files and
//! records in it.
//!
//! ```text
//! lock          held while a backend uses the directory
//! identity      the endpoint, bucket and prefix the directory belongs to
//! data/<id>     the local data of an entry
//! records/<id>  the record of an entry or tombstone
//! conflicts/    records and data files that could not be used
//! tmp/          files on their way to the other directories
//! ```
//!
//! An id is 128 random bits as 32 hexadecimal digits.

use std::collections::HashSet;
use std::ffi::{OsStr, OsString};
use std::fs::{self, DirBuilder, File, TryLockError};
use std::io::{self, Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::sync::Arc;
#[cfg(test)]
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use tracing::{debug, error};

use crate::backend::VolumeInfo;

use super::data::{self, private_options};
use super::error::S3Error;
use super::keys::{Slot, dir_prefix, join_key, slot};
use super::record::{EntryRecord, MAX_RECORD_LEN, Record, RecordId, TombstoneRecord, escape};

const SUBDIRS: [&str; 4] = ["data", "records", "conflicts", "tmp"];

/// A cache directory this process holds the lock of.
pub(crate) struct CacheDir {
    root: PathBuf,
    /// Holds the lock until the backend is gone, and names the volume of the
    /// directory.
    lock: File,
    #[cfg(test)]
    pub(crate) hooks: Hooks,
}

/// What a test makes the directory do: the number of the next calls that
/// fail, and a count of calls.
#[cfg(test)]
#[derive(Default)]
pub(crate) struct Hooks {
    pub(crate) record_writes: AtomicUsize,
    /// The record writes that succeed before `record_writes` starts to fail.
    pub(crate) record_write_skips: AtomicUsize,
    pub(crate) record_removals: AtomicUsize,
    /// A failed data write has put the first half of its bytes in the file.
    pub(crate) data_writes: AtomicUsize,
    /// Calls of `sync_data_dir`.
    pub(crate) data_dir_syncs: AtomicUsize,
    /// A failed move of a data file to `conflicts/` leaves the file where it
    /// was.
    pub(crate) data_moves: AtomicUsize,
    /// The failures injected are those of a full disk.
    pub(crate) disk_full: AtomicBool,
}

#[cfg(test)]
impl Hooks {
    fn take(&self, counter: &AtomicUsize) -> io::Result<()> {
        let left = counter.fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1));
        match left {
            Ok(_) if self.disk_full.load(Ordering::SeqCst) => {
                Err(io::ErrorKind::StorageFull.into())
            }
            Ok(_) => Err(io::Error::other("injected failure")),
            Err(_) => Ok(()),
        }
    }
}

/// What the records of a cache directory say.
#[derive(Default)]
pub(crate) struct Recovered {
    /// The entries, with the open data file of those that have local data.
    pub(crate) entries: Vec<(EntryRecord, Option<File>)>,
    pub(crate) tombstones: Vec<TombstoneRecord>,
}

/// The text of the `identity` file for a backend of `bucket` at `endpoint`,
/// serving the keys below `prefix`, whose names match without regard to case
/// when `case_insensitive`.
pub(crate) fn identity(
    endpoint: &str,
    bucket: &str,
    prefix: &str,
    case_insensitive: bool,
) -> String {
    format!(
        "smb-s3-cache 1\nendpoint {}\nbucket {}\nprefix {}\ncase_insensitive {case_insensitive}\n",
        escape(endpoint),
        escape(bucket),
        escape(prefix)
    )
}

/// A new id.
pub(crate) fn new_id() -> io::Result<RecordId> {
    let mut bytes = [0u8; 16];
    crate::utils::fill_random(&mut bytes).map_err(io::Error::other)?;
    Ok(RecordId::from_bytes(&bytes))
}

pub(super) fn cache_error(e: io::Error) -> S3Error {
    S3Error::Cache(Arc::new(e))
}

fn mismatch() -> S3Error {
    S3Error::InvalidArgument(
        "the cache directory belongs to another endpoint, bucket, prefix or case setting",
    )
}

impl CacheDir {
    /// Makes the directory `root` if it is missing, takes its lock, and
    /// checks that it belongs to `identity`. Empties `tmp/`.
    ///
    /// # Errors
    ///
    /// Fails when the directory cannot be made or used, when another backend
    /// holds its lock, and when it belongs to another identity.
    pub(crate) fn open(root: &Path, identity: &str) -> Result<CacheDir, S3Error> {
        let mut dirs = DirBuilder::new();
        dirs.recursive(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt as _;
            dirs.mode(0o700);
        }
        dirs.create(root).map_err(cache_error)?;
        for name in SUBDIRS {
            dirs.create(root.join(name)).map_err(cache_error)?;
        }

        let lock = private_options()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(root.join("lock"))
            .map_err(cache_error)?;
        match lock.try_lock() {
            Ok(()) => {}
            Err(TryLockError::WouldBlock) => {
                return Err(S3Error::InvalidArgument(
                    "the cache directory is in use by another backend",
                ));
            }
            Err(TryLockError::Error(e)) => return Err(cache_error(e)),
        }
        let dir = CacheDir {
            root: root.to_owned(),
            lock,
            #[cfg(test)]
            hooks: Hooks::default(),
        };

        match fs::read(root.join("identity")) {
            Ok(found) if found == identity.as_bytes() => {}
            Ok(_) => return Err(mismatch()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                for name in ["records", "data"] {
                    if !list_names(&root.join(name))
                        .map_err(cache_error)?
                        .is_empty()
                    {
                        return Err(S3Error::InvalidArgument(
                            "the cache directory has files and no identity",
                        ));
                    }
                }
                dir.write_file("identity", root.join("identity"), identity)
                    .map_err(cache_error)?;
            }
            Err(e) => return Err(cache_error(e)),
        }

        for name in list_names(&root.join("tmp")).map_err(cache_error)? {
            let path = root.join("tmp").join(name);
            if fs::remove_file(&path).is_err() {
                let _ = fs::remove_dir_all(&path);
            }
        }
        Ok(dir)
    }

    /// Writes `text` to `tmp/<name>`, syncs it, and moves it to `target`. On
    /// Unix hosts it then syncs the directory of `target`.
    fn write_file(&self, name: &str, target: PathBuf, text: &str) -> io::Result<()> {
        let tmp = self.root.join("tmp").join(name);
        let mut file = private_options()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&tmp)?;
        file.write_all(text.as_bytes())?;
        file.sync_all()?;
        drop(file);
        fs::rename(&tmp, &target)?;
        match target.parent() {
            Some(dir) => sync_dir(dir),
            None => Ok(()),
        }
    }

    fn data_path(&self, id: &RecordId) -> PathBuf {
        self.root.join("data").join(id.as_str())
    }

    fn record_path(&self, id: &RecordId) -> PathBuf {
        self.root.join("records").join(id.as_str())
    }

    /// Makes the data file of entry `id`, `len` bytes of holes.
    pub(crate) fn create_data(&self, id: &RecordId, len: u64) -> io::Result<File> {
        data::create(&self.data_path(id), len)
    }

    pub(crate) fn remove_data(&self, id: &RecordId) -> io::Result<()> {
        ignore_missing(fs::remove_file(self.data_path(id)))
    }

    /// Writes all of `bytes` at `offset` of a data file.
    pub(crate) fn write_data(&self, file: &File, bytes: &[u8], offset: u64) -> io::Result<()> {
        #[cfg(test)]
        if let Err(e) = self.hooks.take(&self.hooks.data_writes) {
            data::write_all_at(file, &bytes[..bytes.len() / 2], offset)?;
            return Err(e);
        }
        data::write_all_at(file, bytes, offset)
    }

    /// On Unix hosts, syncs the directory of the data files, so their names
    /// survive a crash.
    pub(crate) fn sync_data_dir(&self) -> io::Result<()> {
        #[cfg(test)]
        self.hooks.data_dir_syncs.fetch_add(1, Ordering::SeqCst);
        sync_dir(&self.root.join("data"))
    }

    /// Stores the record `id` with `text`. On success the record is whole on
    /// disk. On failure the file holds either the previous record or the new
    /// one, never a partial write.
    pub(crate) fn write_record(&self, id: &RecordId, text: &str) -> io::Result<()> {
        #[cfg(test)]
        {
            let skipped = self.hooks.record_write_skips.fetch_update(
                Ordering::SeqCst,
                Ordering::SeqCst,
                |n| n.checked_sub(1),
            );
            if skipped.is_err() {
                self.hooks.take(&self.hooks.record_writes)?;
            }
        }
        self.write_file(id.as_str(), self.record_path(id), text)
    }

    pub(crate) fn remove_record(&self, id: &RecordId) -> io::Result<()> {
        #[cfg(test)]
        self.hooks.take(&self.hooks.record_removals)?;
        ignore_missing(fs::remove_file(self.record_path(id)))?;
        sync_dir(&self.root.join("records"))
    }

    /// Moves the data file of entry `id` to `target`. A file that is not
    /// there is left out.
    fn move_data(&self, id: &RecordId, target: &Path) -> io::Result<()> {
        #[cfg(test)]
        self.hooks.take(&self.hooks.data_moves)?;
        ignore_missing(fs::rename(self.data_path(id), target))
    }

    /// Moves the data file and then the record of entry `id` to `conflicts/`,
    /// under a new id, syncing `conflicts/` in between. A file that is not
    /// there is left out. If the data file cannot be moved, both stay where
    /// they are.
    pub(crate) fn keep_conflict(&self, id: &RecordId) -> io::Result<RecordId> {
        let fresh = new_id()?;
        let conflicts = self.root.join("conflicts");
        self.move_data(id, &conflicts.join(format!("{fresh}.data")))?;
        sync_dir(&conflicts)?;
        ignore_missing(fs::rename(
            self.record_path(id),
            conflicts.join(format!("{fresh}.record")),
        ))?;
        sync_dir(&self.root.join("records"))?;
        sync_dir(&conflicts)?;
        Ok(fresh)
    }

    /// The size and free space of the volume of the directory.
    #[cfg(unix)]
    pub(crate) fn volume_info(&self) -> io::Result<VolumeInfo> {
        let st = rustix::fs::fstatvfs(&self.lock)?;
        Ok(crate::host::volume_info(&st, st.f_fsid))
    }

    /// The size and free space of the volume of the directory.
    #[cfg(windows)]
    pub(crate) fn volume_info(&self) -> io::Result<VolumeInfo> {
        crate::host::volume_info_of(&self.lock)
    }

    /// Reads the records back. A record that cannot be used moves to
    /// `conflicts/` with an error in the log, with its data file if it has
    /// one. Data files that no record uses are deleted. A key to delete that
    /// an entry holds is dropped from its tombstone record, which is removed
    /// when it has no key left. Keys match as spelled.
    ///
    /// # Errors
    ///
    /// Fails when a directory cannot be listed or synced, a tombstone record
    /// cannot be rewritten or removed, or an unused data file cannot be
    /// deleted.
    pub(crate) fn recover(&self, prefix: &str, fold: bool) -> io::Result<Recovered> {
        let mut names = list_names(&self.root.join("records"))?;
        names.sort();
        let inside = dir_prefix(prefix);
        let mut recovered = Recovered::default();
        let mut keys = HashSet::new();
        let mut exact = HashSet::new();
        let mut dead_keys = HashSet::new();
        let mut live = HashSet::new();
        let mut tombstones = Vec::new();
        for name in names {
            let Some(id) = name.to_str().and_then(RecordId::parse) else {
                self.quarantine(&name, None, "the file name is not a record id", &mut live);
                continue;
            };
            let decoded = match read_capped(&self.record_path(&id)) {
                Ok(bytes) => Record::decode(&bytes).map_err(|e| e.to_string()),
                Err(e) => Err(e.to_string()),
            };
            let record = match decoded {
                Ok(record) if *record.id() == id => record,
                Ok(_) => {
                    self.quarantine(&name, Some(&id), "the record has another id", &mut live);
                    continue;
                }
                Err(why) => {
                    self.quarantine(&name, Some(&id), &why, &mut live);
                    continue;
                }
            };
            match record {
                Record::Tombstone(tombstone) => {
                    if !tombstone.keys.iter().all(|key| key.starts_with(&inside)) {
                        self.quarantine(
                            &name,
                            Some(&id),
                            "the key is outside the prefix",
                            &mut live,
                        );
                    } else if tombstone.keys.iter().any(|key| dead_keys.contains(key)) {
                        self.quarantine(
                            &name,
                            Some(&id),
                            "another record has the same key",
                            &mut live,
                        );
                    } else {
                        dead_keys.extend(tombstone.keys.iter().cloned());
                        tombstones.push(tombstone);
                    }
                }
                Record::Entry(entry) => match self.revive(&entry, prefix, fold, &mut keys) {
                    Ok(data) => {
                        exact.insert(entry.key.clone());
                        if entry.is_dir {
                            exact.insert(dir_prefix(&entry.key));
                        }
                        if data.is_some() {
                            live.insert(id);
                        }
                        recovered.entries.push((*entry, data));
                    }
                    Err(why) => self.quarantine(&name, Some(&id), &why, &mut live),
                },
            }
        }

        for mut tombstone in tombstones {
            let held = tombstone.keys.len();
            tombstone.keys.retain(|key| !exact.contains(key));
            if tombstone.keys.len() == held {
                recovered.tombstones.push(tombstone);
            } else if tombstone.keys.is_empty() {
                self.remove_record(&tombstone.id)?;
            } else {
                self.write_record(&tombstone.id, &tombstone.encode())?;
                recovered.tombstones.push(tombstone);
            }
        }

        for name in list_names(&self.root.join("data"))? {
            if name
                .to_str()
                .and_then(RecordId::parse)
                .is_none_or(|id| !live.contains(&id))
            {
                debug!(file = ?name, "a data file without a record was deleted");
                ignore_missing(fs::remove_file(self.root.join("data").join(&name)))?;
            }
        }
        sync_dir(&self.root.join("records"))?;
        sync_dir(&self.root.join("conflicts"))?;
        Ok(recovered)
    }

    /// Checks `entry` and opens its data file. `keys` collects the names the
    /// entries hold: their keys, and the marker keys of directories.
    fn revive(
        &self,
        entry: &EntryRecord,
        prefix: &str,
        fold: bool,
        keys: &mut HashSet<Slot>,
    ) -> Result<Option<File>, String> {
        if entry.key != join_key(prefix, &entry.path) {
            return Err("the key is not the path below the prefix".to_owned());
        }
        let name = slot(&entry.key, fold);
        if keys.contains(&name) {
            return Err("another record has the same name".to_owned());
        }
        let data = match &entry.local {
            None => None,
            Some(local) => {
                let file = private_options()
                    .read(true)
                    .write(true)
                    .open(self.data_path(&entry.id))
                    .map_err(|e| format!("the data file cannot be opened: {e}"))?;
                let len = file
                    .metadata()
                    .map_err(|e| format!("the data file cannot be read: {e}"))?
                    .len();
                if len < local.present.end() {
                    return Err(
                        "the data file is shorter than the ranges the record claims".to_owned()
                    );
                }
                if len != local.len {
                    file.set_len(local.len)
                        .map_err(|e| format!("the data file cannot be resized: {e}"))?;
                }
                Some(file)
            }
        };
        keys.insert(name);
        if entry.is_dir {
            keys.insert(slot(&dir_prefix(&entry.key), fold));
        }
        Ok(data)
    }

    /// Moves the data file of `data_id` and then the record `name` to
    /// `conflicts/`. If the data file cannot be moved, the record stays in
    /// `records/` for this build, and `data_id` is added to `live` so the
    /// data file is kept.
    fn quarantine(
        &self,
        name: &OsStr,
        data_id: Option<&RecordId>,
        why: &str,
        live: &mut HashSet<RecordId>,
    ) {
        let Ok(fresh) = new_id() else {
            live.extend(data_id.cloned());
            error!(record = ?name, reason = why, "a record in the cache directory is unusable");
            return;
        };
        let conflicts = self.root.join("conflicts");
        if let Some(id) = data_id {
            let data = self
                .move_data(id, &conflicts.join(format!("{fresh}.data")))
                .and_then(|()| sync_dir(&conflicts));
            if let Err(e) = data {
                live.insert(id.clone());
                error!(
                    record = ?name,
                    reason = why,
                    error = %e,
                    "a record in the cache directory is unusable and its data file could not be moved; both stay where they are"
                );
                return;
            }
        }
        let moved = fs::rename(
            self.root.join("records").join(name),
            conflicts.join(format!("{fresh}.record")),
        );
        match moved {
            Ok(()) => error!(
                record = ?name,
                moved_to = %fresh,
                reason = why,
                "a record in the cache directory is unusable and was moved to its conflicts directory"
            ),
            Err(e) => error!(
                record = ?name,
                reason = why,
                error = %e,
                "a record in the cache directory is unusable and could not be moved"
            ),
        }
    }
}

fn list_names(dir: &Path) -> io::Result<Vec<OsString>> {
    fs::read_dir(dir)?
        .map(|entry| entry.map(|entry| entry.file_name()))
        .collect()
}

fn ignore_missing(result: io::Result<()>) -> io::Result<()> {
    match result {
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        other => other,
    }
}

/// The bytes of the file at `path`, which must not be longer than a record.
fn read_capped(path: &Path) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    File::open(path)?
        .take(MAX_RECORD_LEN + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_RECORD_LEN {
        return Err(io::Error::other("the record is too long"));
    }
    Ok(bytes)
}

/// Makes the entries of `dir` durable.
#[cfg(unix)]
fn sync_dir(dir: &Path) -> io::Result<()> {
    File::open(dir)?.sync_all()
}

/// Does nothing: only Unix hosts sync a directory.
#[cfg(not(unix))]
fn sync_dir(_dir: &Path) -> io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, UNIX_EPOCH};

    use super::*;
    use crate::s3::object::{Metadata, ObjectHead};
    use crate::s3::ranges::RangeSet;
    use crate::s3::record::{BaseRecord, LocalRecord};

    const WHO: &str = "http://127.0.0.1:9000";

    fn who() -> String {
        identity(WHO, "bucket", "pre/fix", true)
    }

    fn entry(path: &str, local: Option<u64>) -> EntryRecord {
        EntryRecord {
            id: new_id().unwrap(),
            is_dir: false,
            path: path.to_owned(),
            key: join_key("pre/fix", path),
            gone: Vec::new(),
            base: Some(BaseRecord {
                key: join_key("pre/fix", path),
                head: ObjectHead {
                    size: 3,
                    etag: "\"e\"".to_owned(),
                    last_modified: UNIX_EPOCH + Duration::from_secs(5),
                    metadata: Metadata::default(),
                },
            }),
            remote: true,
            local: local.map(|len| LocalRecord {
                len,
                present: std::iter::once(0..len).collect::<RangeSet>(),
            }),
            times: [1, 2, 3, 4],
            attributes: 0,
            generation: 1,
            upload_id: None,
            upload_key: None,
            failed: false,
            meta_pending: false,
            marker_pending: false,
        }
    }

    fn store(dir: &CacheDir, record: &EntryRecord, data: Option<&[u8]>) {
        if let Some(bytes) = data {
            let file = dir.create_data(&record.id, 0).unwrap();
            data::write_all_at(&file, bytes, 0).unwrap();
        }
        dir.write_record(&record.id, &record.encode()).unwrap();
    }

    fn names(dir: &Path) -> Vec<String> {
        let mut names: Vec<String> = list_names(dir)
            .unwrap()
            .into_iter()
            .map(|n| n.to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    }

    #[test]
    fn a_new_directory_has_the_layout() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("cache");
        let dir = CacheDir::open(&root, &who()).unwrap();
        assert_eq!(
            names(&root),
            ["conflicts", "data", "identity", "lock", "records", "tmp"]
        );
        assert_eq!(fs::read_to_string(root.join("identity")).unwrap(), who());
        drop(dir);
        CacheDir::open(&root, &who()).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn a_new_directory_and_its_files_are_private() {
        use std::os::unix::fs::PermissionsExt as _;
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("cache");
        let dir = CacheDir::open(&root, &who()).unwrap();
        let record = entry("f", Some(2));
        store(&dir, &record, Some(b"ab"));
        let mode = |path: PathBuf| fs::metadata(path).unwrap().permissions().mode() & 0o777;
        for sub in ["", "data", "records", "conflicts", "tmp"] {
            assert_eq!(mode(root.join(sub)), 0o700, "{sub:?}");
        }
        for file in ["lock", "identity"] {
            assert_eq!(mode(root.join(file)), 0o600, "{file}");
        }
        assert_eq!(mode(dir.data_path(&record.id)), 0o600);
        assert_eq!(mode(dir.record_path(&record.id)), 0o600);
    }

    #[test]
    fn the_volume_of_the_directory_reports_its_size_and_free_space() {
        let temp = tempfile::tempdir().unwrap();
        let dir = CacheDir::open(temp.path(), &who()).unwrap();
        let info = dir.volume_info().unwrap();
        assert!(info.total_allocation_units > 0);
        assert!(info.actual_available_allocation_units <= info.total_allocation_units);
        assert!(info.caller_available_allocation_units <= info.total_allocation_units);
        assert!(info.allocation_unit() >= 512);
    }

    #[test]
    fn a_second_backend_cannot_use_a_directory_that_is_in_use() {
        let temp = tempfile::tempdir().unwrap();
        let first = CacheDir::open(temp.path(), &who()).unwrap();
        assert!(matches!(
            CacheDir::open(temp.path(), &who()),
            Err(S3Error::InvalidArgument(why)) if why.contains("in use")
        ));
        drop(first);
        CacheDir::open(temp.path(), &who()).unwrap();
    }

    #[test]
    fn a_directory_of_another_endpoint_bucket_prefix_or_case_setting_is_refused() {
        let temp = tempfile::tempdir().unwrap();
        drop(CacheDir::open(temp.path(), &who()).unwrap());
        for other in [
            identity(WHO, "bucket", "pre", true),
            identity(WHO, "bucket", "", true),
            identity(WHO, "other", "pre/fix", true),
            identity("http://127.0.0.1:9001", "bucket", "pre/fix", true),
            identity(WHO, "bucket", "pre/fix", false),
        ] {
            assert!(
                matches!(
                    CacheDir::open(temp.path(), &other),
                    Err(S3Error::InvalidArgument(why)) if why.contains("belongs to another")
                ),
                "{other}"
            );
        }
        CacheDir::open(temp.path(), &who()).unwrap();
    }

    #[test]
    fn an_identity_does_not_run_its_parts_together() {
        assert_ne!(
            identity("a", "b c", "d", true),
            identity("a", "b", "c d", true)
        );
        assert_ne!(
            identity("a", "b", "c/d", true),
            identity("a", "b/c", "d", true)
        );
    }

    #[test]
    fn a_directory_with_files_and_no_identity_is_refused() {
        let temp = tempfile::tempdir().unwrap();
        drop(CacheDir::open(temp.path(), &who()).unwrap());
        fs::remove_file(temp.path().join("identity")).unwrap();
        fs::write(
            temp.path().join("records").join(new_id().unwrap().as_str()),
            "x",
        )
        .unwrap();
        assert!(matches!(
            CacheDir::open(temp.path(), &who()),
            Err(S3Error::InvalidArgument(why)) if why.contains("no identity")
        ));
    }

    #[test]
    fn open_empties_tmp() {
        let temp = tempfile::tempdir().unwrap();
        drop(CacheDir::open(temp.path(), &who()).unwrap());
        fs::write(temp.path().join("tmp/left"), "x").unwrap();
        fs::create_dir(temp.path().join("tmp/dir")).unwrap();
        fs::write(temp.path().join("tmp/dir/inner"), "x").unwrap();
        CacheDir::open(temp.path(), &who()).unwrap();
        assert!(names(&temp.path().join("tmp")).is_empty());
    }

    #[test]
    fn a_record_is_whole_or_absent_and_replaces_the_one_before() {
        let temp = tempfile::tempdir().unwrap();
        let dir = CacheDir::open(temp.path(), &who()).unwrap();
        let id = new_id().unwrap();
        dir.write_record(&id, "one").unwrap();
        dir.write_record(&id, "two").unwrap();
        assert_eq!(fs::read_to_string(dir.record_path(&id)).unwrap(), "two");
        assert!(names(&temp.path().join("tmp")).is_empty());
        dir.remove_record(&id).unwrap();
        dir.remove_record(&id).unwrap();
        assert!(names(&temp.path().join("records")).is_empty());
    }

    #[test]
    fn records_with_their_data_come_back() {
        let temp = tempfile::tempdir().unwrap();
        let dir = CacheDir::open(temp.path(), &who()).unwrap();
        let with_data = entry("dir/a.txt", Some(5));
        let without = entry("b.txt", None);
        let tombstone = TombstoneRecord {
            id: new_id().unwrap(),
            keys: vec!["pre/fix/gone".to_owned()],
        };
        store(&dir, &with_data, Some(b"hello"));
        store(&dir, &without, None);
        dir.write_record(&tombstone.id, &tombstone.encode())
            .unwrap();

        let recovered = dir.recover("pre/fix", false).unwrap();
        assert_eq!(recovered.tombstones, [tombstone]);
        assert_eq!(recovered.entries.len(), 2);
        for (record, file) in &recovered.entries {
            if *record == with_data {
                let mut buf = [0u8; 5];
                data::read_full_at(file.as_ref().unwrap(), &mut buf, 0).unwrap();
                assert_eq!(&buf, b"hello");
            } else {
                assert_eq!(*record, without);
                assert!(file.is_none());
            }
        }
        assert!(names(&temp.path().join("conflicts")).is_empty());
    }

    fn conflicts(root: &Path) -> Vec<String> {
        names(&root.join("conflicts"))
    }

    #[test]
    fn records_that_do_not_parse_move_to_conflicts() {
        let temp = tempfile::tempdir().unwrap();
        let dir = CacheDir::open(temp.path(), &who()).unwrap();
        let records = temp.path().join("records");
        let good = entry("good", None);
        store(&dir, &good, None);

        let garbage = new_id().unwrap();
        fs::write(records.join(garbage.as_str()), b"\xff\x00 not a record").unwrap();
        let empty = new_id().unwrap();
        fs::write(records.join(empty.as_str()), b"").unwrap();
        let cut = entry("cut", Some(3));
        let text = cut.encode();
        fs::write(
            records.join(cut.id.as_str()),
            &text.as_bytes()[..text.len() - 6],
        )
        .unwrap();
        fs::write(records.join("not-an-id"), b"x").unwrap();
        let other = entry("other", None);
        let renamed = new_id().unwrap();
        fs::write(records.join(renamed.as_str()), other.encode()).unwrap();

        let recovered = dir.recover("pre/fix", false).unwrap();
        assert_eq!(recovered.entries.len(), 1);
        assert_eq!(recovered.entries[0].0, good);
        assert_eq!(names(&records), [good.id.to_string()]);
        let moved = conflicts(temp.path());
        assert_eq!(moved.len(), 5, "{moved:?}");
        assert!(moved.iter().all(|n| n.ends_with(".record")), "{moved:?}");
    }

    #[test]
    fn a_record_whose_data_is_missing_or_short_moves_to_conflicts_with_its_data() {
        let temp = tempfile::tempdir().unwrap();
        let dir = CacheDir::open(temp.path(), &who()).unwrap();
        let missing = entry("missing", Some(10));
        store(&dir, &missing, None);
        let short = entry("short", Some(10));
        store(&dir, &short, Some(b"abc"));
        let long = entry("long", Some(2));
        store(&dir, &long, Some(b"abcdef"));

        let recovered = dir.recover("pre/fix", false).unwrap();
        assert_eq!(recovered.entries.len(), 1);
        assert_eq!(recovered.entries[0].0, long);
        let file = recovered.entries[0].1.as_ref().unwrap();
        assert_eq!(file.metadata().unwrap().len(), 2, "cut to the record");

        let mut moved = conflicts(temp.path());
        moved.sort();
        assert_eq!(moved.len(), 3, "{moved:?}");
        assert_eq!(moved.iter().filter(|n| n.ends_with(".data")).count(), 1);
        assert_eq!(moved.iter().filter(|n| n.ends_with(".record")).count(), 2);
        let data_file = moved.iter().find(|n| n.ends_with(".data")).unwrap();
        let kept = fs::read(temp.path().join("conflicts").join(data_file)).unwrap();
        assert_eq!(kept, b"abc");
        assert_eq!(names(&temp.path().join("data")), [long.id.to_string()]);
    }

    #[test]
    fn a_data_file_that_has_the_claimed_ranges_is_cut_or_grown_to_the_length() {
        let temp = tempfile::tempdir().unwrap();
        let dir = CacheDir::open(temp.path(), &who()).unwrap();
        let mut grown = entry("grown", Some(10));
        grown.local.as_mut().unwrap().present = std::iter::once(0..4).collect();
        store(&dir, &grown, Some(b"abcdef"));

        let recovered = dir.recover("pre/fix", false).unwrap();
        assert_eq!(recovered.entries.len(), 1);
        let file = recovered.entries[0].1.as_ref().unwrap();
        assert_eq!(file.metadata().unwrap().len(), 10);
        let mut buf = [1u8; 10];
        data::read_full_at(file, &mut buf, 0).unwrap();
        assert_eq!(&buf[..4], b"abcd");
        assert!(conflicts(temp.path()).is_empty());
    }

    #[test]
    fn data_files_without_a_record_are_removed() {
        let temp = tempfile::tempdir().unwrap();
        let dir = CacheDir::open(temp.path(), &who()).unwrap();
        let orphan = new_id().unwrap();
        dir.create_data(&orphan, 4).unwrap();
        let metadata_only = entry("meta", None);
        store(&dir, &metadata_only, None);
        dir.create_data(&metadata_only.id, 4).unwrap();
        let kept = entry("kept", Some(1));
        store(&dir, &kept, Some(b"x"));

        let recovered = dir.recover("pre/fix", false).unwrap();
        assert_eq!(recovered.entries.len(), 2);
        assert_eq!(names(&temp.path().join("data")), [kept.id.to_string()]);
        assert!(conflicts(temp.path()).is_empty());
    }

    #[test]
    fn records_for_names_that_differ_only_in_case_clash_when_case_is_ignored() {
        let temp = tempfile::tempdir().unwrap();
        let dir = CacheDir::open(temp.path(), &who()).unwrap();
        store(&dir, &entry("Name", None), None);
        store(&dir, &entry("name", None), None);
        assert_eq!(dir.recover("pre/fix", false).unwrap().entries.len(), 2);
        let recovered = dir.recover("pre/fix", true).unwrap();
        assert_eq!(recovered.entries.len(), 1);
        assert_eq!(conflicts(temp.path()).len(), 1);
    }

    fn tombstone(dir: &CacheDir, keys: &[&str]) -> TombstoneRecord {
        let record = TombstoneRecord {
            id: new_id().unwrap(),
            keys: keys.iter().map(|key| (*key).to_owned()).collect(),
        };
        dir.write_record(&record.id, &record.encode()).unwrap();
        record
    }

    fn tombstone_keys(recovered: &Recovered) -> Vec<Vec<String>> {
        let mut keys: Vec<Vec<String>> = recovered
            .tombstones
            .iter()
            .map(|tombstone| tombstone.keys.clone())
            .collect();
        keys.sort();
        keys
    }

    #[test]
    fn keys_an_entry_holds_are_dropped_from_tombstone_records() {
        for fold in [false, true] {
            let temp = tempfile::tempdir().unwrap();
            let dir = CacheDir::open(temp.path(), &who()).unwrap();
            store(&dir, &entry("a.txt", None), None);
            store(&dir, &entry("Sub/B.txt", None), None);
            let marked = EntryRecord {
                is_dir: true,
                ..entry("made", None)
            };
            store(&dir, &marked, None);
            let some = tombstone(&dir, &["pre/fix/a.txt", "pre/fix/other"]);
            let cased = tombstone(&dir, &["pre/fix/sub/b.txt"]);
            let all = tombstone(&dir, &["pre/fix/made/", "pre/fix/a.txt/"]);
            let none = tombstone(&dir, &["pre/fix/c.txt"]);

            let recovered = dir.recover("pre/fix", fold).unwrap();
            assert_eq!(recovered.entries.len(), 3);
            let mut expected = vec![
                vec!["pre/fix/a.txt/".to_owned()],
                vec!["pre/fix/c.txt".to_owned()],
                vec!["pre/fix/other".to_owned()],
                vec!["pre/fix/sub/b.txt".to_owned()],
            ];
            expected.sort();
            assert_eq!(tombstone_keys(&recovered), expected, "fold {fold}");

            let on_disk = |id: &RecordId| match fs::read(dir.record_path(id)) {
                Ok(bytes) => Some(Record::decode(&bytes).unwrap()),
                Err(_) => None,
            };
            let keys = |id: &RecordId, keys: &[&str]| {
                Some(Record::Tombstone(TombstoneRecord {
                    id: id.clone(),
                    keys: keys.iter().map(|key| (*key).to_owned()).collect(),
                }))
            };
            assert_eq!(on_disk(&some.id), keys(&some.id, &["pre/fix/other"]));
            assert_eq!(on_disk(&all.id), keys(&all.id, &["pre/fix/a.txt/"]));
            assert_eq!(on_disk(&none.id), keys(&none.id, &["pre/fix/c.txt"]));
            assert_eq!(
                on_disk(&cased.id),
                keys(&cased.id, &["pre/fix/sub/b.txt"]),
                "keys match as spelled, whatever the names do"
            );
            assert!(conflicts(temp.path()).is_empty());
        }
    }

    #[test]
    fn a_tombstone_record_that_loses_every_key_is_removed() {
        let temp = tempfile::tempdir().unwrap();
        let dir = CacheDir::open(temp.path(), &who()).unwrap();
        store(&dir, &entry("a.txt", None), None);
        let gone = tombstone(&dir, &["pre/fix/a.txt"]);
        let recovered = dir.recover("pre/fix", false).unwrap();
        assert!(recovered.tombstones.is_empty());
        assert!(!dir.record_path(&gone.id).exists());
        assert!(dir.recover("pre/fix", false).unwrap().tombstones.is_empty());
    }

    #[test]
    fn two_tombstone_records_with_a_key_in_common_clash() {
        let temp = tempfile::tempdir().unwrap();
        let dir = CacheDir::open(temp.path(), &who()).unwrap();
        tombstone(&dir, &["pre/fix/a", "pre/fix/b"]);
        tombstone(&dir, &["pre/fix/c", "pre/fix/b"]);
        let recovered = dir.recover("pre/fix", false).unwrap();
        assert_eq!(recovered.tombstones.len(), 1);
        assert_eq!(conflicts(temp.path()).len(), 1);
    }

    #[test]
    fn records_with_a_wrong_key_a_taken_name_or_a_key_outside_the_prefix_move_to_conflicts() {
        let temp = tempfile::tempdir().unwrap();
        let dir = CacheDir::open(temp.path(), &who()).unwrap();
        let mut wrong = entry("a", None);
        wrong.key = "elsewhere/a".to_owned();
        store(&dir, &wrong, None);
        let first = entry("same", None);
        store(&dir, &first, None);
        let mut twin = entry("same", None);
        twin.id = RecordId::parse("ffffffffffffffffffffffffffffffff").unwrap();
        store(&dir, &twin, None);
        let outside = TombstoneRecord {
            id: new_id().unwrap(),
            keys: vec!["pre/fix/in".to_owned(), "other/x".to_owned()],
        };
        dir.write_record(&outside.id, &outside.encode()).unwrap();

        let recovered = dir.recover("pre/fix", false).unwrap();
        assert_eq!(recovered.entries.len(), 1);
        assert!(recovered.tombstones.is_empty());
        assert_eq!(conflicts(temp.path()).len(), 3);
    }

    #[test]
    fn a_conflict_takes_the_data_file_and_the_record_under_one_new_id() {
        let temp = tempfile::tempdir().unwrap();
        let dir = CacheDir::open(temp.path(), &who()).unwrap();
        let held = entry("held", Some(4));
        store(&dir, &held, Some(b"data"));
        let bare = entry("bare", None);
        store(&dir, &bare, None);

        let fresh = dir.keep_conflict(&held.id).unwrap();
        assert_eq!(
            conflicts(temp.path()),
            [format!("{fresh}.data"), format!("{fresh}.record")]
        );
        let kept = temp.path().join("conflicts").join(format!("{fresh}.data"));
        assert_eq!(fs::read(kept).unwrap(), b"data");
        assert_eq!(names(&temp.path().join("records")), [bare.id.to_string()]);
        assert!(names(&temp.path().join("data")).is_empty());

        let other = dir.keep_conflict(&bare.id).unwrap();
        assert!(conflicts(temp.path()).contains(&format!("{other}.record")));
        assert!(!conflicts(temp.path()).contains(&format!("{other}.data")));
        assert!(names(&temp.path().join("records")).is_empty());
    }

    #[test]
    fn a_conflict_whose_data_file_cannot_be_moved_leaves_both_files_in_place() {
        let temp = tempfile::tempdir().unwrap();
        let dir = CacheDir::open(temp.path(), &who()).unwrap();
        let held = entry("held", Some(4));
        store(&dir, &held, Some(b"data"));

        dir.hooks.data_moves.store(1, Ordering::SeqCst);
        assert!(dir.keep_conflict(&held.id).is_err());
        assert_eq!(names(&temp.path().join("records")), [held.id.to_string()]);
        assert_eq!(names(&temp.path().join("data")), [held.id.to_string()]);
        assert!(conflicts(temp.path()).is_empty());

        dir.keep_conflict(&held.id).unwrap();
        assert_eq!(conflicts(temp.path()).len(), 2);
    }

    #[test]
    fn a_record_whose_data_file_cannot_be_moved_stays_with_it_until_the_next_build() {
        let temp = tempfile::tempdir().unwrap();
        let dir = CacheDir::open(temp.path(), &who()).unwrap();
        let short = entry("short", Some(10));
        store(&dir, &short, Some(b"abc"));

        dir.hooks.data_moves.store(1, Ordering::SeqCst);
        assert!(dir.recover("pre/fix", false).unwrap().entries.is_empty());
        assert_eq!(names(&temp.path().join("records")), [short.id.to_string()]);
        assert_eq!(names(&temp.path().join("data")), [short.id.to_string()]);
        assert!(conflicts(temp.path()).is_empty());

        assert!(dir.recover("pre/fix", false).unwrap().entries.is_empty());
        assert!(names(&temp.path().join("records")).is_empty());
        assert!(names(&temp.path().join("data")).is_empty());
        let moved = conflicts(temp.path());
        assert_eq!(moved.len(), 2, "{moved:?}");
        let data = moved.iter().find(|n| n.ends_with(".data")).unwrap();
        assert_eq!(
            fs::read(temp.path().join("conflicts").join(data)).unwrap(),
            b"abc"
        );
    }

    #[test]
    fn a_crash_between_the_two_moves_of_a_conflict_keeps_the_data_in_conflicts() {
        let temp = tempfile::tempdir().unwrap();
        let dir = CacheDir::open(temp.path(), &who()).unwrap();
        let held = entry("held", Some(4));
        store(&dir, &held, Some(b"data"));
        let moved = temp
            .path()
            .join("conflicts")
            .join(format!("{}.data", new_id().unwrap()));
        fs::rename(dir.data_path(&held.id), &moved).unwrap();

        assert!(dir.recover("pre/fix", false).unwrap().entries.is_empty());
        assert_eq!(fs::read(&moved).unwrap(), b"data");
        assert!(names(&temp.path().join("records")).is_empty());
        let found = conflicts(temp.path());
        assert_eq!(found.len(), 2, "{found:?}");
        assert_eq!(found.iter().filter(|n| n.ends_with(".record")).count(), 1);
    }
}
