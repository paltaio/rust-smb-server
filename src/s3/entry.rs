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
use super::error::S3Error;
use super::keys::last_name;
use super::lookup::{DirRef, Found};
use super::meta;
use super::object::ObjectHead;
use super::ranges::RangeSet;
use super::readahead::{Pin, ReadAhead, Version};
use super::record::{BaseRecord, EntryRecord, LocalRecord, RecordId};
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
            _pin: pin,
        }
    }
}

/// What a record says about the local data as written to disk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Sealed {
    pub(super) generation: u64,
    pub(super) len: u64,
}

/// What an entry holds besides what files and directories share.
pub(super) enum Body {
    File {
        local: Option<Local>,
        /// The newest record of the local data on disk.
        sealed: Option<Sealed>,
        upload_id: Option<String>,
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
            body: if is_dir {
                Body::Dir {
                    marker_pending: false,
                }
            } else {
                Body::File {
                    local: None,
                    sealed: None,
                    upload_id: None,
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

    /// Whether a job has something to store: the local data of a file, or
    /// the marker object of a directory.
    pub(super) fn has_work(&self) -> bool {
        match &self.body {
            Body::File { local, .. } => local.is_some(),
            Body::Dir { marker_pending } => *marker_pending,
        }
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
        self.key
            .strip_prefix(prefix)
            .map_or(self.key.as_str(), |rest| rest.trim_start_matches('/'))
            .to_owned()
    }

    /// Whether the entry holds something that is not in the bucket.
    pub(super) fn pending(&self) -> bool {
        let held = match &self.body {
            Body::File { local, .. } => local.is_some(),
            Body::Dir { marker_pending } => *marker_pending,
        };
        held || self.own.is_some() || self.recorded
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
    /// as the object `head` at `key`, and the deletion of the keys `deleted`:
    /// the object is the base of the entry from now on. Returns whether
    /// nothing changed the entry since. If so, everything it held is in the
    /// bucket, and [`settled`](Self::settled) drops it. The caller holds the
    /// `io` lock of the entry.
    pub(super) fn landed(
        &mut self,
        ahead: &Arc<ReadAhead>,
        generation: u64,
        key: &str,
        head: Arc<ObjectHead>,
        deleted: &[String],
    ) -> bool {
        self.base = Some(Base::new(ahead, key.to_owned(), head, true));
        self.may_exist = true;
        self.gone.retain(|gone| !deleted.contains(gone));
        self.uploaded = generation;
        if let Body::File { upload_id, .. } = &mut self.body {
            *upload_id = None;
        }
        self.generation == generation
    }

    /// Drops what the entry held, which the bucket has: its local data,
    /// record and times. A later change makes them under a new id.
    pub(super) fn settled(&mut self) {
        if let Body::File { local, sealed, .. } = &mut self.body {
            *local = None;
            *sealed = None;
        }
        self.id = None;
        self.recorded = false;
        self.own = None;
    }

    /// Takes in what a lookup found while the entry has nothing to keep: the
    /// entry follows the bucket.
    pub(super) fn follow(&mut self, found: Found, ahead: &Arc<ReadAhead>) {
        match found {
            Found::File(file) => {
                self.may_exist = true;
                self.key = file.key.clone();
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
        let mut state = State::new(record.key, record.is_dir);
        state.id = Some(record.id);
        state.may_exist = record.remote;
        state.base = record
            .base
            .map(|base| Base::new(ahead, base.key, Arc::new(base.head), !record.is_dir));
        match &mut state.body {
            Body::File {
                local,
                sealed,
                upload_id,
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
                *upload_id = record.upload_id;
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
        state.gone = record.gone;
        state.eager = true;
        Entry::from_state(state)
    }

    /// How the entry stands for a call that waits for the changes made up to
    /// `generation` to reach the bucket.
    pub(super) fn progress(&self, generation: u64) -> Progress {
        let state = self.state();
        if let Some(failure) = &state.failure {
            return Progress::Failed(failure.clone());
        }
        if state.uploaded >= generation || state.detached || !state.has_work() {
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
        let (local, upload_id, marker_pending) = match &state.body {
            Body::File {
                local, upload_id, ..
            } => (
                local.as_ref().map(|local| LocalRecord {
                    len: local.len,
                    present: local.present.clone(),
                }),
                upload_id.clone(),
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
            }),
            remote: state.may_exist,
            local,
            times: own.times,
            attributes: own.attributes,
            generation: state.generation,
            upload_id,
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
        if let Body::File { upload_id, .. } = &mut state.body {
            *upload_id = Some("upload".to_owned());
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
        assert!(state.landed(&ahead, 3, "f", head("\"new\"", 10), &["a".to_owned()]));
        assert!(state.local().is_some(), "settled drops it");
        state.settled();
        assert!(state.local().is_none());
        assert!(state.sealed().is_none());
        assert!(state.own.is_none());
        assert!(!state.recorded);
        assert!(state.id.is_none());
        assert_eq!(state.gone, ["b"]);
        assert_eq!(state.uploaded, 3);
        assert!(state.may_exist);
        let base = state.base.as_ref().unwrap();
        assert_eq!(
            (base.key.as_str(), base.head.etag.as_str()),
            ("f", "\"new\"")
        );
        assert!(matches!(
            state.body,
            Body::File {
                upload_id: None,
                ..
            }
        ));
        assert!(!state.has_work());
    }

    #[test]
    fn a_job_of_an_older_generation_keeps_what_the_entry_holds() {
        let ahead = Arc::new(ReadAhead::new());
        let mut state = kept(3);
        state.bump();
        assert!(!state.landed(&ahead, 3, "f", head("\"new\"", 10), &[]));
        assert_eq!(state.local().unwrap().len, 10);
        assert!(state.own.is_some());
        assert!(state.recorded);
        assert!(state.id.is_some());
        assert_eq!(
            state.uploaded, 3,
            "the generation the job stored, not the entry's"
        );
        assert_eq!(state.base.as_ref().unwrap().head.etag, "\"new\"");
        assert!(matches!(
            state.body,
            Body::File {
                upload_id: None,
                ..
            }
        ));
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
    fn a_waiting_call_sees_done_waiting_and_failed() {
        let entry = Entry::from_state(kept(4));
        assert!(matches!(entry.progress(4), Progress::Waiting));
        entry.state().uploaded = 4;
        assert!(matches!(entry.progress(4), Progress::Done));
        assert!(matches!(entry.progress(5), Progress::Waiting));
        entry.state().failure = Some(S3Error::Stopped);
        assert!(matches!(entry.progress(5), Progress::Failed(_)));
        entry.state().detached = true;
        assert!(
            matches!(entry.progress(5), Progress::Failed(_)),
            "a file moved to conflicts fails the call"
        );
        entry.state().failure = None;
        assert!(matches!(entry.progress(5), Progress::Done));
    }
}
