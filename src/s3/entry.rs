//! A file or directory the backend has a handle open on or holds changes
//! for.

use std::fs::File;
use std::io;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant, SystemTime};

use crate::backend::FileInfo;
use crate::error::{SmbError, SmbResult};
use crate::utils::now_filetime;

use super::cachedir::new_id;
use super::dirmove::Batch;
use super::error::S3Error;
use super::keys::{dir_prefix, last_name, path_below};
use super::lookup::{DirRef, Found};
use super::meta;
use super::object::ObjectHead;
use super::ranges::RangeSet;
use super::readahead::{Pin, ReadAhead, Version};
use super::record::{BaseRecord, EntryRecord, LocalRecord, RecordId, copy_source};
use super::retry::Stop;

/// The local data of a file: a sparse file with the bytes written into it
/// and the ranges of those that count.
pub(super) struct Local {
    pub(super) file: Arc<File>,
    /// The length of the file as clients see it.
    pub(super) len: u64,
    /// The ranges whose bytes are in `file`. The other bytes below `len` are
    /// those of the base.
    pub(super) present: RangeSet,
}

/// Times and attributes that are not those of the base.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Own {
    /// Creation, access, write and change time as FILETIME ticks.
    pub(super) times: [u64; 4],
    pub(super) attributes: u32,
}

impl Own {
    /// Whether `self`, a change to `before`, differs from it. A change that
    /// leaves the change time as it was moves it to now.
    pub(super) fn changed_from(&mut self, before: &Own) -> bool {
        if self == before {
            return false;
        }
        if self.times[3] == before.times[3] {
            self.times[3] = now_filetime();
        }
        true
    }
}

/// The object in the bucket an entry starts from: the object of a file, or
/// the marker object of a directory.
pub(super) struct Base {
    pub(super) key: String,
    pub(super) head: Arc<ObjectHead>,
    /// The head came from a listing: it has the size, ETag and time of the
    /// object and none of its metadata.
    pub(super) bare: bool,
    /// Keeps the chunks read of the object while the entry exists.
    _pin: Option<Pin>,
}

impl Base {
    /// The base `head` describes. A file pins the chunks its reads fetch.
    pub(super) fn new(
        ahead: &Arc<ReadAhead>,
        key: String,
        head: Arc<ObjectHead>,
        is_file: bool,
    ) -> Self {
        let pin = is_file
            .then(|| Version::of(&key, &head))
            .flatten()
            .map(|version| ahead.pin(version));
        Base {
            key,
            head,
            bare: false,
            _pin: pin,
        }
    }

    /// The base a listing describes: [`new`](Self::new) for a head without
    /// the metadata of the object.
    pub(super) fn listed(
        ahead: &Arc<ReadAhead>,
        key: String,
        head: Arc<ObjectHead>,
        is_file: bool,
    ) -> Self {
        Base {
            bare: true,
            ..Base::new(ahead, key, head, is_file)
        }
    }
}

#[cfg(test)]
impl Base {
    /// The base of a file at `key`: an object of one byte.
    pub(super) fn at(key: &str) -> Base {
        let ahead = Arc::new(ReadAhead::new());
        let head = Arc::new(ObjectHead {
            size: 1,
            etag: "\"e\"".to_owned(),
            last_modified: SystemTime::UNIX_EPOCH,
            metadata: super::object::Metadata::default(),
        });
        Base::new(&ahead, key.to_owned(), head, true)
    }
}

/// What a record says about the local data as written to disk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Sealed {
    pub(super) generation: u64,
    pub(super) len: u64,
}

/// A multipart upload that is running, and the key it stores.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Upload {
    pub(super) key: String,
    pub(super) id: String,
}

/// What the overlay counts for an entry: the keys it owns to delete and the
/// key it copies from, as the index last saw them.
#[derive(Debug, Default)]
pub(super) struct Counted {
    pub(super) gone: Vec<String>,
    pub(super) source: Option<String>,
}

/// What an entry holds besides what files and directories share.
pub(super) enum Body {
    File {
        local: Option<Local>,
        /// The newest record of the local data on disk.
        sealed: Option<Sealed>,
        upload: Option<Upload>,
    },
    Dir {
        /// The marker object of the directory is not in the bucket.
        marker_pending: bool,
    },
}

/// What can change about an entry. Read and written under its lock.
pub(super) struct State {
    /// The id of the data file and the record, made when one is needed.
    pub(super) id: Option<RecordId>,
    pub(super) key: String,
    pub(super) base: Option<Base>,
    /// Whether `key` may exist in the bucket.
    pub(super) may_exist: bool,
    /// `None` while the times and attributes are those of the base.
    pub(super) own: Option<Own>,
    /// Bumped by every change, by [`State::bump`] only.
    pub(super) generation: u64,
    /// Handles open on the entry, and tasks that act for one.
    pub(super) handles: u32,
    /// The time of the last change.
    pub(super) changed: Instant,
    /// The entry gets no job before this time: its last job met a full disk.
    pub(super) rest_until: Option<Instant>,
    /// A record of the entry is on disk.
    pub(super) recorded: bool,
    /// Why the last job of the entry failed for good. The entry gets no job
    /// until the next backend is built.
    pub(super) failure: Option<S3Error>,
    /// Keys to delete from the bucket once the entry's content is stored.
    pub(super) gone: Vec<String>,
    /// Stops the job that is running for the entry.
    pub(super) job: Option<Stop>,
    /// The entry is in the queue for a job.
    pub(super) queued: bool,
    /// The entry came back from the cache directory, and its job is due at
    /// once.
    pub(super) eager: bool,
    /// The newest generation whose content a job has stored.
    pub(super) uploaded: u64,
    /// The directory is being made: the open that made it is putting its
    /// marker object.
    pub(super) creating: bool,
    /// The entry left the overlay while handles were open on it, and nothing
    /// may change through it.
    pub(super) detached: bool,
    /// What the overlay counts for the entry.
    pub(super) counted: Counted,
    /// The keys the entry's running job writes. The overlay holds them until
    /// the job ends.
    pub(super) writing: Vec<String>,
    /// The ETag of the object at `key` as the entry last knew it: a lookup
    /// found it, the entry stored it, or the entry that held the key had it
    /// when a rename replaced that entry. `None` if unknown.
    pub(super) prior: Option<String>,
    /// The base key the last record written for the entry names, when it is
    /// not the key and the record's local data does not hold every byte: a
    /// restart copies the content from there.
    pub(super) recorded_source: Option<String>,
    /// The batch record of a directory rename that holds the entry, until
    /// the entries have records of their own. The entry gets no job meanwhile.
    pub(super) batch: Option<Arc<Batch>>,
    pub(super) body: Body,
}

impl State {
    pub(super) fn new(key: String, is_dir: bool) -> Self {
        State {
            id: None,
            key,
            base: None,
            may_exist: false,
            own: None,
            generation: 0,
            handles: 0,
            changed: Instant::now(),
            rest_until: None,
            recorded: false,
            failure: None,
            gone: Vec::new(),
            job: None,
            queued: false,
            eager: false,
            uploaded: 0,
            creating: false,
            detached: false,
            counted: Counted::default(),
            writing: Vec::new(),
            prior: None,
            recorded_source: None,
            batch: None,
            body: if is_dir {
                Body::Dir {
                    marker_pending: false,
                }
            } else {
                Body::File {
                    local: None,
                    sealed: None,
                    upload: None,
                }
            },
        }
    }

    pub(super) fn is_dir(&self) -> bool {
        matches!(self.body, Body::Dir { .. })
    }

    /// The local data of a file that has some.
    pub(super) fn local(&self) -> Option<&Local> {
        match &self.body {
            Body::File { local, .. } => local.as_ref(),
            Body::Dir { .. } => None,
        }
    }

    pub(super) fn local_mut(&mut self) -> Option<&mut Local> {
        match &mut self.body {
            Body::File { local, .. } => local.as_mut(),
            Body::Dir { .. } => None,
        }
    }

    /// Makes `new` the local data of a file.
    pub(super) fn set_local(&mut self, new: Local) {
        if let Body::File { local, .. } = &mut self.body {
            *local = Some(new);
        }
    }

    /// The newest record of the local data on disk.
    pub(super) fn sealed(&self) -> Option<Sealed> {
        match &self.body {
            Body::File { sealed, .. } => *sealed,
            Body::Dir { .. } => None,
        }
    }

    pub(super) fn set_sealed(&mut self, new: Sealed) {
        if let Body::File { sealed, .. } = &mut self.body {
            *sealed = Some(new);
        }
    }

    /// Whether the entry waits for the batch `batch` to be recorded.
    pub(super) fn in_batch(&self, batch: &Arc<Batch>) -> bool {
        self.batch
            .as_ref()
            .is_some_and(|held| Arc::ptr_eq(held, batch))
    }

    /// Notes whether the marker object of a directory is not in the bucket.
    pub(super) fn set_marker_pending(&mut self, pending: bool) {
        if let Body::Dir { marker_pending } = &mut self.body {
            *marker_pending = pending;
        }
    }

    /// Fails for an entry that left the overlay: what it holds can no longer
    /// be found by name.
    pub(super) fn attached(&self) -> SmbResult<()> {
        if self.detached {
            return Err(SmbError::AccessDenied);
        }
        Ok(())
    }

    /// Notes a change: the generation moves, the time of the last change is
    /// now, and the job running for the entry is told to stop. The caller
    /// holds the `io` lock of the entry.
    pub(super) fn bump(&mut self) {
        self.generation += 1;
        self.changed = Instant::now();
        self.eager = false;
        if let Some(stop) = &self.job {
            stop.stop();
        }
    }

    /// Whether a job has something to do: store local data, put a marker
    /// object, store times or attributes, copy the base to a new key, or
    /// delete keys.
    pub(super) fn has_work(&self) -> bool {
        self.writes() || !self.gone.is_empty()
    }

    /// Whether a job has to write the key of the entry.
    pub(super) fn writes(&self) -> bool {
        let held = match &self.body {
            Body::File { local, .. } => local.is_some(),
            Body::Dir { marker_pending } => *marker_pending,
        };
        held || self.own.is_some() || self.moved()
    }

    /// Whether the key of the entry may hold an object: the entry or a job of
    /// it put one, or the base is at the key.
    pub(super) fn in_bucket(&self) -> bool {
        self.may_exist
            || self
                .base
                .as_ref()
                .is_some_and(|base| self.is_write_key(&base.key))
    }

    /// The key of the object the entry stores: its key, or for a directory
    /// the key of its marker object.
    pub(super) fn write_key(&self) -> String {
        if self.is_dir() {
            dir_prefix(&self.key)
        } else {
            self.key.clone()
        }
    }

    /// Whether `key` is the key of the object the entry stores.
    pub(super) fn is_write_key(&self, key: &str) -> bool {
        if self.is_dir() {
            key.strip_suffix('/') == Some(self.key.as_str())
        } else {
            key == self.key
        }
    }

    /// The key whose object the entry still needs: its base key while it
    /// copies from there and its local data does not hold every byte, or the
    /// key the last record it wrote names for the same reason.
    pub(super) fn source(&self) -> Option<&str> {
        copy_source(
            self.is_dir(),
            &self.key,
            self.base.as_ref().map(|base| base.key.as_str()),
            || self.covers(),
        )
        .or(self.recorded_source.as_deref())
    }

    /// Whether the entry still needs the object at another key.
    pub(super) fn needs_source(&self) -> bool {
        self.source().is_some()
    }

    /// Notes that `record` is the last record written for the entry.
    pub(super) fn set_recorded(&mut self, record: &EntryRecord) {
        self.recorded = true;
        self.recorded_source = record.source().map(str::to_owned);
    }

    /// Whether the local data holds every byte of the file.
    fn covers(&self) -> bool {
        self.local()
            .is_some_and(|local| local.present.covers(local.len))
    }

    /// The key the entry's content is copied from, if that is not its key.
    pub(super) fn moved_from(&self) -> Option<&str> {
        copy_source(
            self.is_dir(),
            &self.key,
            self.base.as_ref().map(|base| base.key.as_str()),
            || false,
        )
    }

    /// Whether the base of the entry is at another key than the entry's.
    pub(super) fn moved(&self) -> bool {
        self.moved_from().is_some()
    }

    /// When a job may start for the entry, or `None` if none may now: the
    /// entry has nothing to store, a job is running, it failed for good, it
    /// left the overlay, or its directory is still being made.
    pub(super) fn job_due(&self, delay: Duration) -> Option<Instant> {
        let blocked = self.job.is_some()
            || self.failure.is_some()
            || self.detached
            || self.creating
            || !self.has_work();
        if blocked {
            return None;
        }
        if self.eager {
            return Some(self.changed);
        }
        // A delay too long for the clock never comes.
        let due = self.changed.checked_add(delay)?;
        Some(self.rest_until.map_or(due, |rest| due.max(rest)))
    }

    /// The path of the entry below the share root `prefix`.
    pub(super) fn path(&self, prefix: &str) -> String {
        path_below(prefix, &self.key)
    }

    /// Whether the entry holds something that is not in the bucket.
    pub(super) fn pending(&self) -> bool {
        self.has_work() || self.recorded
    }

    /// The id of the entry, made by the first call.
    pub(super) fn id(&mut self) -> io::Result<RecordId> {
        if let Some(id) = &self.id {
            return Ok(id.clone());
        }
        let id = new_id()?;
        self.id = Some(id.clone());
        Ok(id)
    }

    /// The last name of the key.
    pub(super) fn name(&self) -> &str {
        last_name(&self.key)
    }

    /// The directory the entry is, with the spelling of its key.
    pub(super) fn dir_ref(&self) -> DirRef {
        DirRef {
            key: self.key.clone(),
            name: self.name().to_owned(),
            marker: None,
        }
    }

    /// The times and attributes the entry reports. A directory with nothing
    /// stored has `built` as all four times.
    pub(super) fn own_or_base(&self, built: SystemTime) -> Own {
        if let Some(own) = self.own {
            return own;
        }
        match &self.base {
            Some(base) => Own {
                times: meta::head_times(&base.head),
                attributes: meta::attributes(&base.head),
            },
            None => Own {
                times: meta::same_times(built),
                attributes: 0,
            },
        }
    }

    /// The length of the file: its local data, else its base.
    pub(super) fn size(&self) -> u64 {
        match (&self.body, &self.base) {
            (
                Body::File {
                    local: Some(local), ..
                },
                _,
            ) => local.len,
            (Body::File { local: None, .. }, Some(base)) => base.head.size,
            _ => 0,
        }
    }

    /// Notes a change at `now` (FILETIME ticks) that writes the file: the
    /// write and change times move, the others stay.
    pub(super) fn wrote(&mut self, built: SystemTime, now: u64) {
        let own = self.own_or_base(built);
        let [created, accessed, ..] = own.times;
        self.own = Some(Own {
            times: [created, accessed, now, now],
            attributes: own.attributes,
        });
        self.bump();
    }

    /// Takes in a job that stored the content the entry held at `generation`
    /// as the object `head` at `key`: the object is the base of the entry
    /// from now on. If nothing changed the entry since, everything it held is
    /// in the bucket, and [`stored`](Self::stored) drops it. An entry that
    /// moved to another key meanwhile takes nothing in. The caller holds the
    /// `io` lock of the entry.
    pub(super) fn landed(
        &mut self,
        ahead: &Arc<ReadAhead>,
        generation: u64,
        key: &str,
        head: Arc<ObjectHead>,
    ) -> Landing {
        if self.key != key {
            return Landing::Moved;
        }
        self.prior = Some(head.etag.clone()).filter(|etag| !etag.is_empty());
        self.base = Some(Base::new(ahead, key.to_owned(), head, true));
        self.may_exist = true;
        self.uploaded = generation;
        if let Body::File { upload, .. } = &mut self.body {
            *upload = None;
        }
        if self.generation == generation {
            Landing::Whole
        } else {
            Landing::Newer
        }
    }

    /// Drops what the bucket has now: the local data and the times.
    pub(super) fn stored(&mut self) {
        if let Body::File { local, sealed, .. } = &mut self.body {
            *local = None;
            *sealed = None;
        }
        self.own = None;
    }

    /// Drops what the entry held, which the bucket has: its local data,
    /// record and times. A later change makes them under a new id.
    pub(super) fn settled(&mut self) {
        self.stored();
        self.id = None;
        self.recorded = false;
        self.recorded_source = None;
    }

    /// Gives the bare base of the entry at `key` the full description `found`
    /// of the object.
    pub(super) fn complete_base(
        &mut self,
        ahead: &Arc<ReadAhead>,
        key: &str,
        found: Arc<ObjectHead>,
    ) {
        let bare = self
            .base
            .as_ref()
            .is_some_and(|base| base.bare && base.key == key);
        if bare {
            self.base = Some(Base::new(ahead, key.to_owned(), found, !self.is_dir()));
        }
    }

    /// Takes in what a lookup found while the entry has nothing to keep: the
    /// entry follows the bucket.
    pub(super) fn follow(&mut self, found: Found, ahead: &Arc<ReadAhead>) {
        match found {
            Found::File(file) => {
                self.may_exist = true;
                self.key = file.key.clone();
                self.prior = Some(file.head.etag.clone()).filter(|etag| !etag.is_empty());
                let same = self
                    .base
                    .as_ref()
                    .is_some_and(|base| *base.head == *file.head);
                if !same {
                    self.base = Some(Base::new(ahead, file.key, file.head, true));
                }
            }
            Found::Dir(dir) => {
                self.may_exist = dir.marker.is_some();
                self.key = dir.key;
                self.base = dir.marker.map(|head| {
                    let key = format!("{}/", self.key);
                    Base::new(ahead, key, head, false)
                });
            }
        }
    }
}

/// How an entry took in the object a job stored.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Landing {
    /// The entry is at another key now and took nothing in.
    Moved,
    /// The object is the base, and the entry changed since the job began.
    Newer,
    /// The object is the base, and it holds everything the entry held.
    Whole,
}

/// How an entry stands with a call that waits for its changes to reach the
/// bucket.
pub(super) enum Progress {
    Done,
    Waiting,
    Failed(S3Error),
}

/// A file or directory with a handle open on it, or with changes the bucket
/// does not have.
pub(super) struct Entry {
    /// Whether the entry is a directory. It never changes.
    is_dir: bool,
    /// Held across the disk operations that change the data file, so they
    /// happen one at a time, and across every bump of the generation. The
    /// locks are taken in the order `io`, `seal`, state. The state lock is
    /// held only for short reads and writes of the state, never while
    /// waiting for the other two.
    io: Mutex<()>,
    /// Held across the writes of the record, so a newer record is never
    /// replaced by an older one.
    seal: Mutex<()>,
    state: Mutex<State>,
}

impl Entry {
    pub(super) fn from_state(state: State) -> Arc<Entry> {
        Arc::new(Entry {
            is_dir: state.is_dir(),
            io: Mutex::new(()),
            seal: Mutex::new(()),
            state: Mutex::new(state),
        })
    }

    pub(super) fn is_dir(&self) -> bool {
        self.is_dir
    }

    /// Waits for the turn to change the data file.
    pub(super) fn lock_io(&self) -> MutexGuard<'_, ()> {
        self.io.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Waits for the turn to write the record.
    pub(super) fn lock_seal(&self) -> MutexGuard<'_, ()> {
        self.seal.lock().unwrap_or_else(PoisonError::into_inner)
    }

    pub(super) fn state(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Takes the `io` and `seal` locks of every entry in `entries`, in the
    /// order of their addresses, so callers that lock several entries may
    /// wait for each other but never deadlock.
    pub(super) fn lock_all<'a>(
        entries: &[&'a Arc<Entry>],
    ) -> Vec<(MutexGuard<'a, ()>, MutexGuard<'a, ()>)> {
        let mut order = entries.to_vec();
        order.sort_by_key(|entry| Arc::as_ptr(entry) as usize);
        order.dedup_by(|a, b| Arc::ptr_eq(a, b));
        order
            .iter()
            .map(|entry| (entry.lock_io(), entry.lock_seal()))
            .collect()
    }

    /// A new file at `key` with no bytes, created at `now`, whose data file
    /// has the id `id`.
    pub(super) fn created_file(key: String, id: RecordId, now: u64, file: File) -> Arc<Entry> {
        let mut state = State::new(key, false);
        state.id = Some(id);
        state.set_local(Local {
            file: Arc::new(file),
            len: 0,
            present: RangeSet::new(),
        });
        state.own = Some(Own {
            times: [now; 4],
            attributes: 0,
        });
        state.generation = 1;
        Entry::from_state(state)
    }

    /// A new directory at `key`, created at `now`, whose marker object is
    /// still to be put.
    pub(super) fn created_dir(key: String, now: u64) -> Arc<Entry> {
        let mut state = State::new(key, true);
        state.own = Some(Own {
            times: [now; 4],
            attributes: 0,
        });
        state.generation = 1;
        state.may_exist = true;
        state.creating = true;
        state.set_marker_pending(true);
        Entry::from_state(state)
    }

    /// The entry for what a lookup found.
    pub(super) fn found(found: Found, ahead: &Arc<ReadAhead>) -> Arc<Entry> {
        let (key, is_dir) = match &found {
            Found::File(file) => (file.key.clone(), false),
            Found::Dir(dir) => (dir.key.clone(), true),
        };
        let mut state = State::new(key, is_dir);
        state.follow(found, ahead);
        Entry::from_state(state)
    }

    /// The entry a record describes, with its open data file if it has local
    /// data.
    pub(super) fn recovered(
        record: EntryRecord,
        file: Option<File>,
        ahead: &Arc<ReadAhead>,
    ) -> Arc<Entry> {
        let source = record.source().map(str::to_owned);
        let mut state = State::new(record.key, record.is_dir);
        state.id = Some(record.id);
        state.may_exist = record.remote;
        state.base = record.base.map(|base| {
            let make = if base.bare { Base::listed } else { Base::new };
            make(ahead, base.key, Arc::new(base.head), !record.is_dir)
        });
        match &mut state.body {
            Body::File {
                local,
                sealed,
                upload,
            } => {
                if let (Some(held), Some(file)) = (record.local, file) {
                    *sealed = Some(Sealed {
                        generation: record.generation,
                        len: held.len,
                    });
                    *local = Some(Local {
                        file: Arc::new(file),
                        len: held.len,
                        present: held.present,
                    });
                }
                *upload = record
                    .upload_id
                    .zip(record.upload_key)
                    .map(|(id, key)| Upload { key, id });
            }
            Body::Dir { marker_pending } => *marker_pending = record.marker_pending,
        }
        if record.meta_pending {
            state.own = Some(Own {
                times: record.times,
                attributes: record.attributes,
            });
        }
        state.generation = record.generation;
        state.recorded = true;
        state.recorded_source = source;
        state.gone = record.gone;
        state.eager = true;
        Entry::from_state(state)
    }

    /// How the entry stands for a call that waits for the changes made up to
    /// `generation` to reach the bucket, and for the deletion of the keys
    /// `gone`, those the entry owned when the call began.
    pub(super) fn progress(&self, generation: u64, gone: &[String]) -> Progress {
        let state = self.state();
        if let Some(failure) = &state.failure {
            return Progress::Failed(failure.clone());
        }
        if state.detached || !state.pending() {
            return Progress::Done;
        }
        let deleted = !state.gone.iter().any(|key| gone.contains(key));
        if state.uploaded >= generation && deleted && state.job.is_none() {
            return Progress::Done;
        }
        Progress::Waiting
    }

    /// What a client sees of the entry.
    pub(super) fn info(&self, built: SystemTime) -> FileInfo {
        let state = self.state();
        let own = state.own_or_base(built);
        meta::entry_info(
            state.name(),
            self.is_dir,
            state.size(),
            own.times,
            own.attributes,
        )
    }

    /// The record of the entry as it is now. `prefix` is the key of the share
    /// root.
    pub(super) fn record(
        state: &mut State,
        prefix: &str,
        built: SystemTime,
    ) -> io::Result<EntryRecord> {
        let id = state.id()?;
        let own = state.own_or_base(built);
        let path = state.path(prefix);
        let (local, upload, marker_pending) = match &state.body {
            Body::File { local, upload, .. } => (
                local.as_ref().map(|local| LocalRecord {
                    len: local.len,
                    present: local.present.clone(),
                }),
                upload.clone(),
                false,
            ),
            Body::Dir { marker_pending } => (None, None, *marker_pending),
        };
        Ok(EntryRecord {
            id,
            is_dir: state.is_dir(),
            path,
            key: state.key.clone(),
            gone: state.gone.clone(),
            base: state.base.as_ref().map(|base| BaseRecord {
                key: base.key.clone(),
                head: (*base.head).clone(),
                bare: base.bare,
            }),
            remote: state.may_exist,
            local,
            times: own.times,
            attributes: own.attributes,
            generation: state.generation,
            upload_id: upload.as_ref().map(|upload| upload.id.clone()),
            upload_key: upload.map(|upload| upload.key),
            failed: state.failure.is_some(),
            meta_pending: state.own.is_some(),
            marker_pending,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::s3::object::Metadata;

    fn head(etag: &str, size: u64) -> Arc<ObjectHead> {
        Arc::new(ObjectHead {
            size,
            etag: etag.to_owned(),
            last_modified: SystemTime::UNIX_EPOCH,
            metadata: Metadata::default(),
        })
    }

    /// A file with 10 bytes of local data, a record, times of its own and an
    /// upload that is running.
    fn kept(generation: u64) -> State {
        let mut state = State::new("f".to_owned(), false);
        state.id = Some(RecordId::parse(&"a".repeat(32)).unwrap());
        state.set_local(Local {
            file: Arc::new(tempfile::tempfile().unwrap()),
            len: 10,
            present: std::iter::once(0..10).collect(),
        });
        state.set_sealed(Sealed {
            generation,
            len: 10,
        });
        if let Body::File { upload, .. } = &mut state.body {
            *upload = Some(Upload {
                key: "f".to_owned(),
                id: "upload".to_owned(),
            });
        }
        state.own = Some(Own {
            times: [1; 4],
            attributes: 0,
        });
        state.recorded = true;
        state.generation = generation;
        state.gone = vec!["a".to_owned(), "b".to_owned()];
        state
    }

    #[test]
    fn an_entry_has_work_for_local_data_times_a_marker_a_move_or_keys_to_delete() {
        let mut file = State::new("f".to_owned(), false);
        assert!(!file.has_work());
        file.base = Some(Base::at("f"));
        assert!(!file.has_work(), "a base at its own key is nothing to do");
        file.own = Some(Own {
            times: [1; 4],
            attributes: 0,
        });
        assert!(file.has_work(), "pending times");
        file.own = None;
        file.base = Some(Base::at("g"));
        assert!(file.has_work(), "a base at another key is copied");
        assert_eq!(file.moved_from(), Some("g"));
        file.base = Some(Base::at("f"));
        file.gone.push("h".to_owned());
        assert!(file.has_work(), "keys to delete");
        file.gone.clear();
        file.set_local(Local {
            file: Arc::new(tempfile::tempfile().unwrap()),
            len: 0,
            present: RangeSet::new(),
        });
        assert!(file.has_work(), "local data");

        let mut dir = State::new("d".to_owned(), true);
        assert!(!dir.has_work());
        dir.set_marker_pending(true);
        assert!(dir.has_work());
        dir.set_marker_pending(false);
        dir.own = Some(Own {
            times: [1; 4],
            attributes: 0,
        });
        assert!(dir.has_work(), "times of a directory go in its marker");
        dir.base = Some(Base::at("other"));
        dir.own = None;
        assert!(!dir.has_work(), "a directory has no base to copy");
    }

    #[test]
    fn an_entry_with_work_counts_as_pending_without_a_record() {
        let mut file = State::new("f".to_owned(), false);
        assert!(!file.pending());
        file.gone.push("old".to_owned());
        assert!(file.pending());
        file.gone.clear();
        file.recorded = true;
        assert!(file.pending());
    }

    #[test]
    fn a_job_that_stored_the_object_for_an_entry_that_moved_takes_nothing_in() {
        let ahead = Arc::new(ReadAhead::new());
        let mut state = kept(3);
        state.key = "g".to_owned();
        assert_eq!(
            state.landed(&ahead, 3, "f", head("\"new\"", 10)),
            Landing::Moved
        );
        assert!(state.base.is_none());
        assert_eq!(state.uploaded, 0);
        assert!(state.local().is_some());
    }

    #[test]
    fn a_change_moves_the_generation_and_stops_the_job_that_runs() {
        let mut state = kept(3);
        state.eager = true;
        let stop = Stop::new();
        state.job = Some(stop.clone());
        state.bump();
        assert_eq!(state.generation, 4);
        assert!(stop.is_stopped());
        assert!(!state.eager);

        let mut idle = kept(3);
        idle.bump();
        assert_eq!(idle.generation, 4);
    }

    #[test]
    fn a_job_of_a_generation_the_entry_still_has_takes_everything_the_entry_held() {
        let ahead = Arc::new(ReadAhead::new());
        let mut state = kept(3);
        assert_eq!(
            state.landed(&ahead, 3, "f", head("\"new\"", 10)),
            Landing::Whole
        );
        assert!(state.local().is_some(), "settled drops it");
        state.settled();
        assert!(state.local().is_none());
        assert!(state.sealed().is_none());
        assert!(state.own.is_none());
        assert!(!state.recorded);
        assert!(state.id.is_none());
        assert_eq!(state.gone, ["a", "b"]);
        assert_eq!(state.uploaded, 3);
        assert!(state.may_exist);
        let base = state.base.as_ref().unwrap();
        assert_eq!(
            (base.key.as_str(), base.head.etag.as_str()),
            ("f", "\"new\"")
        );
        assert!(matches!(state.body, Body::File { upload: None, .. }));
        assert!(state.has_work(), "the keys to delete are left");
        state.gone.clear();
        assert!(!state.has_work());
    }

    #[test]
    fn a_job_of_an_older_generation_keeps_what_the_entry_holds() {
        let ahead = Arc::new(ReadAhead::new());
        let mut state = kept(3);
        state.bump();
        assert_eq!(
            state.landed(&ahead, 3, "f", head("\"new\"", 10)),
            Landing::Newer
        );
        assert_eq!(state.local().unwrap().len, 10);
        assert!(state.own.is_some());
        assert!(state.recorded);
        assert!(state.id.is_some());
        assert_eq!(
            state.uploaded, 3,
            "the generation the job stored, not the entry's"
        );
        assert_eq!(state.base.as_ref().unwrap().head.etag, "\"new\"");
        assert!(matches!(state.body, Body::File { upload: None, .. }));
        assert!(state.has_work());
    }

    #[test]
    fn an_entry_waits_its_delay_after_the_last_change_unless_it_came_back_from_disk() {
        let delay = Duration::from_secs(5);
        let mut state = kept(1);
        let changed = state.changed;
        assert_eq!(state.job_due(delay), Some(changed + delay));
        state.eager = true;
        assert_eq!(state.job_due(delay), Some(changed));
        state.eager = false;
        state.bump();
        assert_eq!(state.job_due(delay), Some(state.changed + delay));
    }

    #[test]
    fn an_entry_that_met_a_full_disk_waits_for_its_rest_when_that_is_longer_than_the_delay() {
        let mut state = kept(1);
        let rest = state.changed + Duration::from_secs(1);
        state.rest_until = Some(rest);
        assert_eq!(state.job_due(Duration::ZERO), Some(rest));
        assert_eq!(
            state.job_due(Duration::from_secs(5)),
            Some(state.changed + Duration::from_secs(5))
        );
    }

    #[test]
    fn an_entry_gets_no_job_while_one_runs_after_it_failed_or_left_or_has_nothing_to_store() {
        let delay = Duration::from_secs(5);
        let mut running = kept(1);
        running.job = Some(Stop::new());
        assert_eq!(running.job_due(delay), None);
        let mut failed = kept(1);
        failed.failure = Some(S3Error::Stopped);
        assert_eq!(failed.job_due(delay), None);
        let mut detached = kept(1);
        detached.detached = true;
        assert_eq!(detached.job_due(delay), None);
        assert_eq!(State::new("g".to_owned(), false).job_due(delay), None);

        let mut dir = State::new("d".to_owned(), true);
        assert_eq!(dir.job_due(delay), None);
        dir.set_marker_pending(true);
        assert!(dir.job_due(delay).is_some());
        dir.creating = true;
        assert_eq!(dir.job_due(delay), None);
    }

    #[test]
    fn a_waiting_call_is_not_done_while_the_job_that_stored_the_entry_still_runs() {
        let entry = Entry::from_state(kept(4));
        entry.state().uploaded = 4;
        entry.state().job = Some(Stop::new());
        assert!(matches!(entry.progress(4, &[]), Progress::Waiting));
        entry.state().job = None;
        assert!(matches!(entry.progress(4, &[]), Progress::Done));
    }

    #[test]
    fn a_waiting_call_sees_done_waiting_and_failed() {
        let entry = Entry::from_state(kept(4));
        assert!(matches!(entry.progress(4, &[]), Progress::Waiting));
        entry.state().uploaded = 4;
        assert!(matches!(entry.progress(4, &[]), Progress::Done));
        assert!(matches!(entry.progress(5, &[]), Progress::Waiting));
        entry.state().failure = Some(S3Error::Stopped);
        assert!(matches!(entry.progress(5, &[]), Progress::Failed(_)));
        entry.state().detached = true;
        assert!(
            matches!(entry.progress(5, &[]), Progress::Failed(_)),
            "a file moved to conflicts fails the call"
        );
        entry.state().failure = None;
        assert!(matches!(entry.progress(5, &[]), Progress::Done));
    }

    #[test]
    fn the_etag_of_the_key_is_known_from_a_lookup_and_from_a_landing_and_not_from_a_base_the_entry_left()
     {
        let ahead = Arc::new(ReadAhead::new());
        let found = |etag: &str| {
            Found::File(crate::s3::lookup::FileRef {
                key: "f".to_owned(),
                name: "f".to_owned(),
                head: head(etag, 1),
            })
        };
        let mut state = State::new("f".to_owned(), false);
        assert_eq!(state.prior, None);
        state.follow(found("\"a\""), &ahead);
        assert_eq!(state.prior.as_deref(), Some("\"a\""));
        state.follow(found("\"b\""), &ahead);
        assert_eq!(state.prior.as_deref(), Some("\"b\""));
        state.follow(found(""), &ahead);
        assert_eq!(state.prior, None, "an object without an ETag");
        assert_eq!(
            state.landed(&ahead, 0, "f", head("\"c\"", 1)),
            Landing::Whole
        );
        assert_eq!(state.prior.as_deref(), Some("\"c\""));
        state.key = "g".to_owned();
        state.prior = None;
        assert_eq!(
            state.landed(&ahead, 0, "f", head("\"d\"", 1)),
            Landing::Moved
        );
        assert_eq!(state.prior, None, "an entry that moved took nothing in");
    }

    fn record_of(state: &mut State) -> EntryRecord {
        state.id = Some(RecordId::parse(&"b".repeat(32)).unwrap());
        Entry::record(state, "", SystemTime::UNIX_EPOCH).unwrap()
    }

    #[test]
    fn the_source_is_the_base_key_until_every_byte_is_local_and_the_record_says_so() {
        let mut state = State::new("new".to_owned(), false);
        state.base = Some(Base::at("old"));
        state.set_local(Local {
            file: Arc::new(tempfile::tempfile().unwrap()),
            len: 4,
            present: std::iter::once(0..2).collect(),
        });
        assert_eq!(state.source(), Some("old"));
        let record = record_of(&mut state);
        assert_eq!(record.source(), Some("old"));
        state.set_recorded(&record);
        state.local_mut().unwrap().present.insert(2..4);
        assert_eq!(state.source(), Some("old"), "the record still names it");
        let record = record_of(&mut state);
        assert_eq!(record.source(), None);
        state.set_recorded(&record);
        assert_eq!(state.source(), None);
    }

    #[test]
    fn a_landed_copy_keeps_the_source_until_a_record_without_it_is_written() {
        let ahead = Arc::new(ReadAhead::new());
        let mut copy = State::new("new".to_owned(), false);
        copy.base = Some(Base::at("old"));
        let record = record_of(&mut copy);
        copy.set_recorded(&record);
        assert_eq!(copy.source(), Some("old"));
        assert_eq!(
            copy.landed(&ahead, 0, "new", head("\"e\"", 1)),
            Landing::Whole
        );
        assert_eq!(copy.source(), Some("old"), "the record is not written yet");
        let record = record_of(&mut copy);
        copy.set_recorded(&record);
        assert_eq!(copy.source(), None);

        copy.recorded_source = Some("old".to_owned());
        copy.settled();
        assert_eq!(copy.source(), None, "no record, no source");
    }

    #[test]
    fn a_record_names_no_source_for_a_directory_or_a_base_at_the_key() {
        let mut state = State::new("k".to_owned(), false);
        state.base = Some(Base::at("k"));
        assert_eq!(record_of(&mut state).source(), None);
        let mut dir = State::new("d".to_owned(), true);
        dir.base = Some(Base::at("other"));
        assert_eq!(record_of(&mut dir).source(), None);
    }
}
