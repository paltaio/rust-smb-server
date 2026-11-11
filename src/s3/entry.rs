//! A file or directory the backend has a handle open on or holds changes
//! for.

use std::fs::File;
use std::io;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Instant, SystemTime};

use crate::backend::FileInfo;
use crate::error::{SmbError, SmbResult};
use crate::utils::now_filetime;

use super::cachedir::new_id;
use super::keys::last_name;
use super::lookup::{DirRef, Found};
use super::meta;
use super::object::ObjectHead;
use super::ranges::RangeSet;
use super::readahead::{Pin, ReadAhead, Version};
use super::record::{BaseRecord, EntryRecord, LocalRecord, RecordId};

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
    /// Bumped by every change.
    pub(super) generation: u64,
    /// Handles open on the entry, and tasks that act for one.
    pub(super) handles: u32,
    /// The time of the last change or close.
    pub(super) changed: Instant,
    /// A record of the entry is on disk.
    pub(super) recorded: bool,
    pub(super) failed: bool,
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
            recorded: false,
            failed: false,
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
        self.generation += 1;
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
        state.failed = record.failed;
        Entry::from_state(state)
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
        let path = state
            .key
            .strip_prefix(prefix)
            .map_or(state.key.as_str(), |rest| rest.trim_start_matches('/'))
            .to_owned();
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
            gone: Vec::new(),
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
            failed: state.failed,
            meta_pending: state.own.is_some(),
            marker_pending,
        })
    }
}
