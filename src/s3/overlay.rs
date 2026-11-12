//! The entries and tombstones of a backend: its view of the paths whose
//! state differs from the bucket's, or may.
//!
//! Lock order: the `io` and `seal` locks of entries, the lock of the keys to
//! delete, the index of the [`Overlay`], then the state of one [`Entry`], then
//! the locks of the read-ahead chunks. The metadata cache lock is never taken
//! while any of them is held. The index and state locks are held across no
//! await and no disk or network I/O.

use std::collections::BTreeMap;
use std::collections::{HashMap, HashSet};
use std::io;
use std::ops::{Deref, DerefMut};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use tokio::sync::watch;
use tracing::error;

use super::cachedir::CacheDir;
use super::client::MAX_DELETE_KEYS;
use super::entry::{Counted, Entry, Progress, State};
use super::error::S3Error;
use super::keys::{Slot, dir_prefix, slot};
use super::lookup::Found;
use super::queue::Queue;
use super::readahead::ReadAhead;
use super::record::{RecordId, TombstoneRecord};
use super::retry::Stop;
use super::unlink::keys_to_delete;

/// A key to delete from the bucket that no entry owns.
struct Tomb {
    /// The record that names the key.
    id: RecordId,
    /// The key may be deleted from this time on.
    due: Instant,
    /// Numbers the keys in the order they became keys to delete.
    seq: u64,
    /// Why the key could not be deleted.
    failure: Option<S3Error>,
    /// A job waits for the key to go: it needs no pause in the deletes.
    urgent: bool,
}

/// A key that an entry copies from while it is not the entry's own.
struct Source {
    key: String,
    holder: Arc<Entry>,
}

/// The entries, keys to delete and requests in flight of a backend. Every map
/// that decides whether a request may start is keyed by [`Slot`], which is the
/// key itself unless names match without regard to case. The keys that tell
/// objects apart are kept as spelled.
#[derive(Default)]
struct Index {
    /// Whether names match without regard to case.
    fold: bool,
    entries: BTreeMap<Slot, Arc<Entry>>,
    /// The keys to delete from the bucket that no entry owns, by key.
    tombs: HashMap<String, Tomb>,
    next_seq: u64,
    /// The entries that own each key to delete, by key.
    gone: HashMap<String, Vec<Arc<Entry>>>,
    /// The keys to delete, owned or not, by slot.
    hidden: HashMap<Slot, Vec<String>>,
    /// The entries that copy from a key that is not their own, by the slot of
    /// the key: one for each key, several for a slot.
    sources: HashMap<Slot, Vec<Source>>,
    /// How many requests delete a key of each slot now.
    deleting: HashMap<Slot, usize>,
    /// The names a rename is about to take.
    reserved: HashSet<Slot>,
    /// How many running jobs write a key of each slot.
    writing: HashMap<Slot, usize>,
    /// The entries that wait for a slot to clear.
    parked: HashMap<Slot, Vec<Arc<Entry>>>,
    /// The slot each entry in `parked` waits for, by the address of the
    /// entry.
    parked_at: HashMap<usize, Slot>,
    /// The entries a change woke, for the queue.
    ready: Vec<Arc<Entry>>,
    /// A key cleared, and the worker is to look again.
    cleared: bool,
    /// The latest due time of any key to delete. Keys wait for it, so a burst
    /// of deletes goes out in few requests.
    quiet_from: Option<Instant>,
    /// How many times an entry was put to wait for a slot.
    #[cfg(test)]
    parks: usize,
}

fn add(counts: &mut HashMap<Slot, usize>, name: Slot) {
    *counts.entry(name).or_insert(0) += 1;
}

fn sub(counts: &mut HashMap<Slot, usize>, name: &Slot) {
    if let Some(count) = counts.get_mut(name) {
        *count -= 1;
        if *count == 0 {
            counts.remove(name);
        }
    }
}

/// What stands between a job and the key it writes.
struct Block {
    /// The key to wait for.
    key: String,
    /// The entry that copies from the slot of the key, when that is all that
    /// stands in the way and it is the only one.
    source: Option<Arc<Entry>>,
}

/// How a job that is due stands with the keys it needs.
enum Blocked {
    No,
    /// The job resolves a cycle of entries that each wait for the next.
    Cycle,
    Yes(String),
}

impl Index {
    /// `key` as this index compares names.
    fn slot(&self, key: &str) -> Slot {
        slot(key, self.fold)
    }

    /// Whether `key` is to be deleted from the bucket, or a key of its slot.
    fn hides(&self, key: &str) -> bool {
        self.hidden.contains_key(&self.slot(key))
    }

    /// How many keys are to be deleted, owned or not.
    #[cfg(test)]
    fn hidden_keys(&self) -> usize {
        self.hidden.values().map(Vec::len).sum()
    }

    /// Notes that `key` is to be deleted, by an entry or as a key no entry
    /// owns.
    fn hide(&mut self, key: &str) {
        let name = self.slot(key);
        let keys = self.hidden.entry(name).or_default();
        if !keys.iter().any(|held| held == key) {
            keys.push(key.to_owned());
        }
    }

    /// Notes that `key` is to be deleted no more, unless something still
    /// names it.
    fn unhide(&mut self, key: &str) {
        if self.tombs.contains_key(key) || self.gone.contains_key(key) {
            return;
        }
        let name = self.slot(key);
        if let Some(keys) = self.hidden.get_mut(&name) {
            keys.retain(|held| held != key);
            if keys.is_empty() {
                self.hidden.remove(&name);
            }
        }
    }

    /// Whether a file entry other than those in `except` holds `key`. Locks
    /// the state of the entry at the slot unless it is in `except`.
    fn held(&self, key: &str, except: &[&Arc<Entry>]) -> bool {
        self.entries.get(&self.slot(key)).is_some_and(|entry| {
            !entry.is_dir() && !except.iter().any(|other| Arc::ptr_eq(other, entry)) && {
                let state = entry.state();
                !state.detached && state.key == key
            }
        })
    }

    /// Whether the name `to` belongs to an entry other than `entry` and
    /// `replaced`.
    fn taken(&self, to: &str, entry: &Arc<Entry>, replaced: Option<&Arc<Entry>>) -> bool {
        self.entries.get(&self.slot(to)).is_some_and(|held| {
            !Arc::ptr_eq(held, entry) && !replaced.is_some_and(|other| Arc::ptr_eq(held, other))
        })
    }

    /// Takes the entry out of the slot of `key` if it is there, and wakes the
    /// entries that wait for the key.
    fn vacate(&mut self, key: &str, entry: &Arc<Entry>) {
        let name = self.slot(key);
        if self
            .entries
            .get(&name)
            .is_some_and(|held| Arc::ptr_eq(held, entry))
        {
            self.entries.remove(&name);
        }
        self.cleared(key);
    }

    /// Whether a job other than the one of `owner` writes a key of the slot
    /// `name`: the job of `owner` deletes the keys it owns after its own
    /// write, so waiting for that write would wait for the job itself. The
    /// caller holds the state of no entry.
    fn written_by_other(&self, name: &Slot, owner: Option<&Arc<Entry>>) -> bool {
        let own = owner.map_or(0, |owner| {
            owner
                .state()
                .writing
                .iter()
                .filter(|written| self.slot(written) == *name)
                .count()
        });
        self.writing.get(name).is_some_and(|count| *count > own)
    }

    /// The entries other than `except` that copy from a key of the slot
    /// `name` and still need it.
    fn holders(&self, name: &Slot, except: Option<&Arc<Entry>>) -> Vec<Arc<Entry>> {
        self.sources
            .get(name)
            .into_iter()
            .flatten()
            .map(|source| &source.holder)
            .filter(|holder| {
                !except.is_some_and(|except| Arc::ptr_eq(holder, except))
                    && holder.state().needs_source()
            })
            .cloned()
            .collect()
    }

    /// Whether a job writes a key of the slot of `key`, an entry copies from
    /// one, or a request deletes one: nothing is deleted or written there
    /// until that ends. The writes of `owner` do not count.
    fn in_use(&self, key: &str, owner: Option<&Arc<Entry>>) -> bool {
        let name = self.slot(key);
        self.written_by_other(&name, owner)
            || self.deleting.contains_key(&name)
            || !self.holders(&name, None).is_empty()
    }

    /// Whether the key `key` may be deleted now: nothing is in use in its
    /// slot, and no entry holds it.
    fn may_delete(&self, key: &str, owner: Option<&Arc<Entry>>) -> bool {
        !self.in_use(key, owner) && !self.held(key, &[])
    }

    /// Whether a job of `entry` may write `key`, or what it has to wait for.
    /// A request that deletes a key of its slot, a job that writes one, a key
    /// above it that is to be deleted, and an entry that copies from one
    /// stand in the way. A key above that is to be deleted becomes due at
    /// once.
    fn write_block(&mut self, key: &str, entry: &Arc<Entry>, now: Instant) -> Option<Block> {
        let name = self.slot(key);
        let plain = |key: &str| Block {
            key: key.to_owned(),
            source: None,
        };
        if self.deleting.contains_key(&name) || self.writing.contains_key(&name) {
            return Some(plain(key));
        }
        if let Some(above) = self.pending_above(key) {
            self.expedite(&above, now);
            return Some(plain(&above));
        }
        let mut holders = self.holders(&name, Some(entry));
        let first = holders.pop()?;
        Some(Block {
            key: key.to_owned(),
            source: holders.is_empty().then_some(first),
        })
    }

    /// The first key above `key` that is to be deleted.
    fn pending_above(&self, key: &str) -> Option<String> {
        key.match_indices('/')
            .map(|(at, _)| &key[..at])
            .find(|above| self.hides(above))
            .map(str::to_owned)
    }

    /// Makes the keys no entry owns in the slot of `key` due at once, unless
    /// a delete of them failed.
    fn expedite(&mut self, key: &str, now: Instant) {
        let name = self.slot(key);
        for held in self.hidden.get(&name).into_iter().flatten() {
            if let Some(tomb) = self.tombs.get_mut(held)
                && tomb.failure.is_none()
                && !tomb.urgent
            {
                tomb.urgent = true;
                tomb.due = tomb.due.min(now);
                self.cleared = true;
            }
        }
    }

    /// The file entry that holds the name of `key` under another spelling,
    /// when names ignore case, with its key.
    fn twin(&self, key: &str) -> Option<(String, Arc<Entry>)> {
        if !self.fold {
            return None;
        }
        let entry = self.entries.get(&self.slot(key))?;
        if entry.is_dir() {
            return None;
        }
        let state = entry.state();
        (!state.detached && state.key != key).then(|| (state.key.clone(), Arc::clone(entry)))
    }

    /// Notes that a request deletes `keys`. Returns the keys among them that
    /// name the other spelling of a key an entry holds, each with that key.
    fn claim(&mut self, keys: &[String]) -> Vec<(String, String)> {
        let twins: Vec<(String, String)> = keys
            .iter()
            .filter_map(|key| self.twin(key).map(|(twin, _)| (key.clone(), twin)))
            .collect();
        for key in keys {
            let name = self.slot(key);
            add(&mut self.deleting, name);
        }
        twins
    }

    /// Wakes the entries that wait for the slot of `key`.
    fn cleared(&mut self, key: &str) {
        self.cleared = true;
        let name = self.slot(key);
        if let Some(waiting) = self.parked.remove(&name) {
            for entry in waiting {
                self.parked_at.remove(&(Arc::as_ptr(&entry) as usize));
                self.ready.push(entry);
            }
        }
    }

    /// Puts `entry` to wait for the slot of `key`. The caller marks it as
    /// queued.
    fn park(&mut self, entry: &Arc<Entry>, key: &str) {
        #[cfg(test)]
        {
            self.parks += 1;
        }
        let name = self.slot(key);
        self.parked_at
            .insert(Arc::as_ptr(entry) as usize, name.clone());
        self.parked.entry(name).or_default().push(Arc::clone(entry));
    }

    /// Takes `entry` out of the entries that wait, and returns whether it was
    /// one.
    fn unpark(&mut self, entry: &Arc<Entry>) -> bool {
        let Some(name) = self.parked_at.remove(&(Arc::as_ptr(entry) as usize)) else {
            return false;
        };
        if let Some(waiting) = self.parked.get_mut(&name) {
            waiting.retain(|held| !Arc::ptr_eq(held, entry));
            if waiting.is_empty() {
                self.parked.remove(&name);
            }
        }
        true
    }

    /// Whether an entry other than `entry` copies from `key`.
    fn source_taken(&self, key: &str, entry: &Arc<Entry>) -> bool {
        self.sources
            .get(&self.slot(key))
            .into_iter()
            .flatten()
            .any(|source| source.key == key && !Arc::ptr_eq(&source.holder, entry))
    }

    /// Updates the index counts for `entry` to match `state`, or clears them
    /// when it is not `attached`. An entry that waits for a key is queued
    /// again.
    fn recount(&mut self, entry: &Arc<Entry>, state: &mut State, attached: bool) {
        let attached = attached && !state.detached;
        let gone = if attached {
            state.gone.clone()
        } else {
            Vec::new()
        };
        let mut source = if attached {
            state.source().map(str::to_owned)
        } else {
            None
        };
        let before = std::mem::take(&mut state.counted);
        for key in &gone {
            self.gone
                .entry(key.clone())
                .or_default()
                .push(Arc::clone(entry));
            self.hide(key);
        }
        for key in &before.gone {
            if let Some(owners) = self.gone.get_mut(key) {
                if let Some(at) = owners.iter().position(|owner| Arc::ptr_eq(owner, entry)) {
                    owners.swap_remove(at);
                }
                if owners.is_empty() {
                    self.gone.remove(key);
                }
            }
            self.unhide(key);
            if !self.hides(key) {
                self.cleared(key);
            }
        }
        if before.source != source {
            if let Some(key) = &before.source {
                let name = self.slot(key);
                if let Some(held) = self.sources.get_mut(&name) {
                    let count = held.len();
                    held.retain(|source| {
                        !(source.key == *key && Arc::ptr_eq(&source.holder, entry))
                    });
                    let removed = held.len() < count;
                    if held.is_empty() {
                        self.sources.remove(&name);
                    }
                    if removed {
                        self.cleared(key);
                    }
                }
            }
            if let Some(key) = source.take_if(|key| self.source_taken(key, entry)) {
                error!(
                    key,
                    "two files copy from one object; the second may lose it to a delete or an overwrite"
                );
            }
            if let Some(key) = &source {
                let name = self.slot(key);
                self.sources.entry(name).or_default().push(Source {
                    key: key.clone(),
                    holder: Arc::clone(entry),
                });
            }
        }
        state.counted = Counted { gone, source };
        if self.unpark(entry) {
            self.ready.push(Arc::clone(entry));
        }
    }

    /// Makes `key` a key to delete that no entry owns, named by the record
    /// `id`, unless it is one already.
    fn add_tomb(&mut self, key: &str, id: &RecordId, due: Instant) {
        if self.tombs.contains_key(key) {
            return;
        }
        self.hide(key);
        self.quiet_from = self.quiet_from.max(Some(due));
        let seq = self.next_seq;
        self.next_seq += 1;
        self.tombs.insert(
            key.to_owned(),
            Tomb {
                id: id.clone(),
                due,
                seq,
                failure: None,
                urgent: false,
            },
        );
    }

    /// When keys to delete may go: the upload delay after the last key became
    /// one, or, if keys keep coming, a minute after the first was due.
    fn sweep_gate(&self) -> Option<Instant> {
        let oldest = self
            .tombs
            .values()
            .filter(|tomb| tomb.failure.is_none())
            .map(|tomb| tomb.due)
            .min()?;
        Some(
            self.quiet_from
                .map_or(oldest, |quiet| quiet.min(oldest + MAX_QUIET)),
        )
    }

    fn remove_tomb(&mut self, key: &str) -> Option<Tomb> {
        let tomb = self.tombs.remove(key)?;
        self.unhide(key);
        if !self.hides(key) {
            self.cleared(key);
        }
        Some(tomb)
    }

    /// The entries that wait for each other, with the base of each: `start`,
    /// whose base is `base`, waits for the entry `first` that copies from its
    /// key, and so on. Every entry in the chain waits for nothing else, and
    /// the last waits for `start`. `None` if the chain does not close.
    fn cycle(
        &mut self,
        start: &Arc<Entry>,
        base: Option<String>,
        first: Arc<Entry>,
        now: Instant,
    ) -> Option<Vec<(Arc<Entry>, String)>> {
        let mut members = vec![(Arc::clone(start), base?)];
        let mut next = first;
        loop {
            if Arc::ptr_eq(&next, start) {
                return Some(members);
            }
            if members.iter().any(|(member, _)| Arc::ptr_eq(member, &next)) {
                return None;
            }
            let (key, base) = {
                let state = next.state();
                let waits = state.writes()
                    && !state.is_dir()
                    && !state.detached
                    && state.job.is_none()
                    && state.failure.is_none();
                if !waits {
                    return None;
                }
                (state.key.clone(), state.moved_from()?.to_owned())
            };
            members.push((Arc::clone(&next), base));
            next = self.write_block(&key, &next, now)?.source?;
        }
    }

    /// How a job of `entry` stands with the keys it needs. An entry that
    /// waits only for a copy that waits for it is part of a cycle; the one
    /// whose base has the least key resolves it.
    fn blocked(&mut self, entry: &Arc<Entry>, now: Instant) -> Blocked {
        let (key, writes, gone, base) = {
            let state = entry.state();
            (
                state.key.clone(),
                state.writes() && !state.is_dir(),
                state.gone.clone(),
                state.moved_from().map(str::to_owned),
            )
        };
        if !writes {
            let mut waits_for = None;
            for key in &gone {
                if !self.in_use(key, None) {
                    return Blocked::No;
                }
                waits_for.get_or_insert(key);
            }
            return waits_for.map_or(Blocked::No, |key| Blocked::Yes(key.clone()));
        }
        let Some(Block {
            key: waits_for,
            source,
        }) = self.write_block(&key, entry, now)
        else {
            return Blocked::No;
        };
        let least = source
            .and_then(|first| self.cycle(entry, base, first, now))
            .and_then(|members| members.into_iter().min_by(|a, b| a.1.cmp(&b.1)));
        match least {
            Some((member, _)) if Arc::ptr_eq(&member, entry) => Blocked::Cycle,
            Some((member, _)) => {
                if self.unpark(&member) {
                    self.ready.push(member);
                }
                Blocked::Yes(waits_for)
            }
            None => Blocked::Yes(waits_for),
        }
    }
}

/// The index of an overlay, locked. Entries a change woke go to the queue
/// when the lock is let go.
struct Locked<'a> {
    overlay: &'a Overlay,
    guard: MutexGuard<'a, Index>,
}

impl Deref for Locked<'_> {
    type Target = Index;

    fn deref(&self) -> &Index {
        &self.guard
    }
}

impl DerefMut for Locked<'_> {
    fn deref_mut(&mut self) -> &mut Index {
        &mut self.guard
    }
}

impl Drop for Locked<'_> {
    fn drop(&mut self) {
        for entry in std::mem::take(&mut self.guard.ready) {
            self.overlay.queue.push(entry, Instant::now());
        }
        if std::mem::take(&mut self.guard.cleared) {
            self.overlay.queue.wake();
        }
    }
}

/// The entries below a directory.
#[derive(Default)]
pub(super) struct Below {
    /// Entries named in the directory itself.
    pub(super) direct: Vec<Arc<Entry>>,
    /// Names of directories that only entries below them imply.
    pub(super) implied: Vec<String>,
}

pub(super) struct Overlay {
    fold: bool,
    /// How long an entry rests after its last change before a job may start.
    delay: Duration,
    /// The entries that wait for a job.
    queue: Queue<Arc<Entry>>,
    index: Mutex<Index>,
    /// Held while the records of keys to delete are decided and written.
    tomb_io: Mutex<()>,
    /// Counts the changes that can settle a call that waits for the bucket.
    progress: watch::Sender<u64>,
}

/// The longest keys to delete wait for a pause in the deletes.
const MAX_QUIET: Duration = Duration::from_secs(60);

/// What the worker finds when it takes an entry off the queue.
pub(super) enum Claim {
    /// The entry has a job to run, with the signal that stops it. The flag
    /// tells that the job resolves a cycle of entries that each wait for the
    /// next.
    Run(Held, Stop, bool),
    /// The entry waits for a later time.
    Later(Arc<Entry>, Instant),
    /// The entry has no job to run, or waits for a key to clear.
    Skip,
}

/// Keys a request deletes. They count as being deleted until this is dropped.
pub(super) struct Deleting {
    overlay: Arc<Overlay>,
    keys: Vec<String>,
    /// When names ignore case, the keys among `keys` that name another
    /// spelling of a key an entry holds, each with that key. No job writes a
    /// key of their slot while the claim lasts.
    twins: Vec<(String, String)>,
}

impl Deleting {
    pub(super) fn keys(&self) -> &[String] {
        &self.keys
    }

    pub(super) fn twins(&self) -> &[(String, String)] {
        &self.twins
    }
}

impl Drop for Deleting {
    fn drop(&mut self) {
        if self.keys.is_empty() {
            return;
        }
        let mut index = self.overlay.lock();
        for key in &self.keys {
            let name = index.slot(key);
            sub(&mut index.deleting, &name);
            index.cleared(key);
        }
        drop(index);
        self.overlay.touch();
    }
}

/// How [`Overlay::claim_gone`] sorted the keys an entry owns to delete.
pub(super) struct GoneClaim {
    /// The keys to delete now.
    pub(super) claimed: Deleting,
    /// The keys an entry holds: the owner lets go.
    pub(super) left: Vec<String>,
    /// The keys whose slot a job writes, an entry copies from or a request
    /// deletes: they stay.
    pub(super) busy: Vec<String>,
}

/// The entry a file rename moves, and where.
pub(super) struct Moving<'a> {
    pub(super) entry: &'a Arc<Entry>,
    pub(super) to: &'a str,
    /// The keys the entry owns to delete once it has moved.
    pub(super) gone: &'a [String],
}

/// A name a rename is about to take. No entry is made at it meanwhile.
pub(super) struct Reservation<'a> {
    overlay: &'a Overlay,
    name: Slot,
}

impl Drop for Reservation<'_> {
    fn drop(&mut self) {
        self.overlay.lock().reserved.remove(&self.name);
    }
}

/// Why a job may not write its key.
pub(super) enum Fence {
    /// The entry left the overlay.
    Gone,
    /// The entry changed, or the backend ends.
    Stopped,
    /// A key stands in the way.
    Blocked,
}

/// An entry a call waits for, as it stood when the call began.
pub(super) struct Wait {
    pub(super) entry: Arc<Entry>,
    pub(super) generation: u64,
    pub(super) gone: Vec<String>,
}

/// A hold on an entry. The entry stays in the overlay while a hold is on it,
/// and leaves with the last one if it has nothing to keep.
pub(super) struct Held {
    overlay: Arc<Overlay>,
    pub(super) entry: Arc<Entry>,
}

impl Held {
    /// Another hold on the entry, for a task that acts for this one.
    pub(super) fn another(&self) -> Held {
        self.entry.state().handles += 1;
        Held {
            overlay: Arc::clone(&self.overlay),
            entry: Arc::clone(&self.entry),
        }
    }
}

impl Drop for Held {
    fn drop(&mut self) {
        self.overlay.release(&self.entry);
    }
}

impl Overlay {
    /// An overlay whose names match without regard to case when
    /// `case_insensitive`, and whose entries wait `delay` after their last
    /// change for a job.
    pub(super) fn new(case_insensitive: bool, delay: Duration) -> Arc<Overlay> {
        Arc::new(Overlay {
            fold: case_insensitive,
            delay,
            queue: Queue::new(),
            index: Mutex::new(Index {
                fold: case_insensitive,
                ..Index::default()
            }),
            tomb_io: Mutex::new(()),
            progress: watch::Sender::new(0),
        })
    }

    /// Tells the calls that wait for the bucket to look again.
    pub(super) fn touch(&self) {
        self.progress.send_modify(|count| *count += 1);
    }

    /// Notices of [`touch`](Self::touch).
    pub(super) fn subscribe(&self) -> watch::Receiver<u64> {
        self.progress.subscribe()
    }

    /// The entries that wait for a job.
    pub(super) fn queue(&self) -> &Queue<Arc<Entry>> {
        &self.queue
    }

    /// Queues `entry`, whose state is `state`, for a job if it has one to run
    /// and is not queued.
    fn schedule(&self, entry: &Arc<Entry>, state: &mut State) {
        if state.queued {
            return;
        }
        if let Some(due) = state.job_due(self.delay) {
            state.queued = true;
            self.queue.push(Arc::clone(entry), due);
        }
    }

    /// Takes `entry` off the queue: a hold on it and the signal that stops
    /// its job if a job may run at `now`. Jobs of one entry never overlap. An
    /// entry whose job would wait for a key waits here instead, and is queued
    /// again when the key clears.
    pub(super) fn claim(self: &Arc<Self>, entry: Arc<Entry>, now: Instant) -> Claim {
        let mut index = self.lock();
        let due = {
            let mut state = entry.state();
            state.queued = false;
            state.job_due(self.delay)
        };
        let Some(due) = due else {
            return Claim::Skip;
        };
        if due > now {
            entry.state().queued = true;
            return Claim::Later(entry, due);
        }
        let blocked = index.blocked(&entry, now);
        let mut state = entry.state();
        match state.job_due(self.delay) {
            None => return Claim::Skip,
            Some(due) if due > now => {
                state.queued = true;
                drop(state);
                return Claim::Later(entry, due);
            }
            Some(_) => {}
        }
        let cycle = match blocked {
            Blocked::No => false,
            Blocked::Cycle => true,
            Blocked::Yes(key) => {
                state.queued = true;
                drop(state);
                index.park(&entry, &key);
                return Claim::Skip;
            }
        };
        let stop = Stop::new();
        state.job = Some(stop.clone());
        state.eager = false;
        state.handles += 1;
        drop(state);
        drop(index);
        Claim::Run(self.held(entry), stop, cycle)
    }

    /// Takes `entry` out of the overlay. It takes no more changes.
    pub(super) fn evict(&self, entry: &Arc<Entry>) {
        let mut index = self.lock();
        let mut state = entry.state();
        let key = state.key.clone();
        state.detached = true;
        index.recount(entry, &mut state, false);
        drop(state);
        index.vacate(&key, entry);
        drop(index);
        self.touch();
    }

    /// The entries that hold something for a job to store, each with its
    /// generation now. A directory whose open is still putting its marker is
    /// left out: the open has not answered.
    pub(super) fn work(&self) -> Vec<Wait> {
        let index = self.lock();
        index
            .entries
            .values()
            .filter_map(|entry| {
                let state = entry.state();
                (state.has_work() && !state.creating).then(|| Wait {
                    entry: Arc::clone(entry),
                    generation: state.generation,
                    gone: state.gone.clone(),
                })
            })
            .collect()
    }

    /// The paths whose jobs failed for good, with the errors, in the order of
    /// the names. `prefix` is the key of the share root.
    pub(super) fn failures(&self, prefix: &str) -> Vec<(String, S3Error)> {
        let index = self.lock();
        index
            .entries
            .values()
            .filter_map(|entry| {
                let state = entry.state();
                state
                    .failure
                    .clone()
                    .map(|failure| (state.path(prefix), failure))
            })
            .collect()
    }

    fn lock(&self) -> Locked<'_> {
        Locked {
            overlay: self,
            guard: self.index.lock().unwrap_or_else(PoisonError::into_inner),
        }
    }

    /// `key` as the index compares names.
    fn slot(&self, key: &str) -> Slot {
        slot(key, self.fold)
    }

    /// The index prefix of the keys below the directory `key`, and how many
    /// names `key` has.
    fn below_bounds(&self, key: &str) -> (Slot, usize) {
        let depth = if key.is_empty() {
            0
        } else {
            key.split('/').count()
        };
        (self.slot(&dir_prefix(key)), depth)
    }

    fn held(self: &Arc<Self>, entry: Arc<Entry>) -> Held {
        Held {
            overlay: Arc::clone(self),
            entry,
        }
    }

    /// A hold on the entry for `key` if it holds something that is not in
    /// the bucket.
    pub(super) fn take_pending(self: &Arc<Self>, key: &str) -> Option<Held> {
        let slot = self.slot(key);
        let index = self.lock();
        let entry = Arc::clone(index.entries.get(&slot)?);
        let mut state = entry.state();
        if !state.pending() {
            return None;
        }
        state.handles += 1;
        drop(state);
        Some(self.held(entry))
    }

    /// The entry for `key`, if there is one that holds something that is not
    /// in the bucket.
    pub(super) fn peek(&self, key: &str) -> Option<Arc<Entry>> {
        let entry = self.lock().entries.get(&self.slot(key)).cloned()?;
        let pending = entry.state().pending();
        pending.then_some(entry)
    }

    /// A hold on the entry for what a lookup found. An entry for the name
    /// that has nothing to keep follows the lookup; one that has is kept as
    /// it is. `None` if the lookup is out of date: a rename has reserved the
    /// name, or the object became a key to delete after the lookup.
    pub(super) fn take_found(
        self: &Arc<Self>,
        found: Found,
        ahead: &Arc<ReadAhead>,
    ) -> Option<Held> {
        let (key, is_dir) = match &found {
            Found::File(file) => (file.key.clone(), false),
            Found::Dir(dir) => (dir.key.clone(), true),
        };
        let slot = self.slot(&key);
        let mut index = self.lock();
        let held = index.entries.get(&slot).cloned();
        if let Some(entry) = &held {
            let mut state = entry.state();
            if state.pending() || entry.is_dir() == is_dir {
                if !state.pending() {
                    state.follow(found, ahead);
                }
                state.handles += 1;
                drop(state);
                return Some(self.held(Arc::clone(entry)));
            }
        }
        if index.reserved.contains(&slot) || (!is_dir && index.hides(&key)) {
            return None;
        }
        if let Some(entry) = held {
            // What was a file is a directory, or the other way round. Handles
            // that stay open on it can change nothing.
            let mut state = entry.state();
            state.detached = state.handles > 0;
            index.recount(&entry, &mut state, false);
            drop(state);
            index.entries.remove(&slot);
        }
        let entry = Entry::found(found, ahead);
        entry.state().handles = 1;
        index.entries.insert(slot, Arc::clone(&entry));
        Some(self.held(entry))
    }

    /// Puts `entry` in the overlay with a hold on it, unless an entry for
    /// the name is there or a rename has reserved it. Looking and putting are
    /// one step, so two creates of one name never both succeed. A key to delete
    /// from the bucket may be there still, so the entry's key may exist.
    pub(super) fn insert_new(self: &Arc<Self>, entry: Arc<Entry>) -> Option<Held> {
        let slot = self.slot(&entry.state().key);
        let mut index = self.lock();
        if index.entries.contains_key(&slot) || index.reserved.contains(&slot) {
            return None;
        }
        {
            let mut state = entry.state();
            state.handles = 1;
            state.may_exist |= index.hides(&state.key);
            self.schedule(&entry, &mut state);
        }
        index.entries.insert(slot, Arc::clone(&entry));
        Some(self.held(entry))
    }

    /// Ends one hold on `entry`, and queues the entry for a job if it has one
    /// to run. Every change to an entry holds it for its task, so the end of
    /// that hold is where a change reaches the queue.
    fn release(&self, entry: &Arc<Entry>) {
        let mut index = self.lock();
        let mut state = entry.state();
        state.handles = state.handles.saturating_sub(1);
        if state.handles == 0 && !state.pending() {
            let key = state.key.clone();
            index.recount(entry, &mut state, false);
            drop(state);
            index.vacate(&key, entry);
            return;
        }
        self.schedule(entry, &mut state);
    }

    /// The spelling of the directory `key` in the keys of the entries below
    /// it that hold something that is not in the bucket, if there are any.
    pub(super) fn spelling(&self, key: &str) -> Option<String> {
        let (prefix, depth) = self.below_bounds(key);
        let index = self.lock();
        index
            .entries
            .range(prefix.clone()..)
            .take_while(|(slot, _)| slot.starts_with(&prefix))
            .find_map(|(_, entry)| {
                let state = entry.state();
                state.pending().then(|| {
                    state
                        .key
                        .split('/')
                        .take(depth)
                        .collect::<Vec<_>>()
                        .join("/")
                })
            })
    }

    /// The entries below the directory `key` that hold something that is not
    /// in the bucket.
    pub(super) fn below(&self, key: &str) -> Below {
        let (prefix, depth) = self.below_bounds(key);
        let entries: Vec<Arc<Entry>> = {
            let index = self.lock();
            index
                .entries
                .range(prefix.clone()..)
                .take_while(|(slot, _)| slot.starts_with(&prefix))
                .map(|(_, entry)| Arc::clone(entry))
                .collect()
        };
        let mut below = Below::default();
        for entry in entries {
            let (key, pending) = {
                let state = entry.state();
                (state.key.clone(), state.pending())
            };
            if !pending {
                continue;
            }
            let mut names = key.split('/').skip(depth);
            let Some(name) = names.next() else {
                continue;
            };
            if names.next().is_none() {
                below.direct.push(entry);
            } else if !below.implied.iter().any(|seen| self.same(seen, name)) {
                below.implied.push(name.to_owned());
            }
        }
        below
    }

    /// Whether two names are one name.
    fn same(&self, a: &str, b: &str) -> bool {
        self.slot(a) == self.slot(b)
    }

    /// How many keys below the directory prefix `prefix` are to be deleted.
    pub(super) fn hidden_below(&self, prefix: &str) -> usize {
        let prefix = self.slot(prefix);
        self.lock()
            .hidden
            .iter()
            .filter(|(name, _)| name.starts_with(&prefix))
            .map(|(_, keys)| keys.len())
            .sum()
    }

    /// Whether `key`, or another spelling of it when names ignore case, is to
    /// be deleted from the bucket.
    pub(super) fn tombstoned(&self, key: &str) -> bool {
        self.lock().hides(key)
    }

    /// Puts what was read from the cache directory in the overlay. `entries`
    /// have distinct names. Returns how many entries it put.
    pub(super) fn install(
        &self,
        entries: Vec<Arc<Entry>>,
        tombstones: Vec<TombstoneRecord>,
    ) -> usize {
        let mut index = self.lock();
        let count = entries.len();
        for entry in entries {
            let slot = self.slot(&entry.state().key);
            {
                let mut state = entry.state();
                index.recount(&entry, &mut state, true);
                self.schedule(&entry, &mut state);
            }
            let taken = index.entries.insert(slot, entry);
            debug_assert!(taken.is_none(), "two recovered entries have one name");
        }
        let now = Instant::now();
        for tombstone in tombstones {
            for key in &tombstone.keys {
                index.add_tomb(key, &tombstone.id, now);
            }
        }
        count
    }

    /// Takes `entry` out of the overlay for good, as an unlink or a replace
    /// does: it takes no more changes, and `keys` become keys to delete that
    /// the record `id` names.
    fn drop_entry(&self, index: &mut Index, entry: &Arc<Entry>, keys: &[String], id: &RecordId) {
        let mut state = entry.state();
        let key = state.key.clone();
        state.detached = true;
        index.recount(entry, &mut state, false);
        drop(state);
        index.vacate(&key, entry);
        let due = Instant::now() + self.delay;
        for key in keys {
            index.add_tomb(key, id, due);
        }
    }

    /// Takes `entry` out of the overlay for an unlink: `keys` become keys to
    /// delete that the record `id` names.
    pub(super) fn unlinked(&self, entry: &Arc<Entry>, keys: &[String], id: &RecordId) {
        let mut index = self.lock();
        self.drop_entry(&mut index, entry, keys, id);
        drop(index);
        self.touch();
    }

    /// Reserves the name `to` for a rename of `entry`, which replaces
    /// `replaced` if that holds the name. Fails if another entry holds the
    /// name or another rename has reserved it. No entry is made at a reserved
    /// name until the reservation ends.
    pub(super) fn reserve(
        &self,
        to: &str,
        entry: &Arc<Entry>,
        replaced: Option<&Arc<Entry>>,
    ) -> Option<Reservation<'_>> {
        let mut index = self.lock();
        let name = index.slot(to);
        if index.taken(to, entry, replaced) || !index.reserved.insert(name.clone()) {
            return None;
        }
        Some(Reservation {
            overlay: self,
            name,
        })
    }

    /// Moves `entry` to the key `to`, which `change` has set up in its
    /// state. `replaced` is the entry that held `to`, with the keys of it to
    /// delete and the record that names them. The caller has reserved `to`.
    /// The index changes in one step.
    pub(super) fn renamed(
        &self,
        entry: &Arc<Entry>,
        to: &str,
        change: impl FnOnce(&mut State),
        replaced: Option<(&Arc<Entry>, &[String], &RecordId)>,
    ) {
        let mut index = self.lock();
        if let Some((replaced, keys, id)) = replaced {
            self.drop_entry(&mut index, replaced, keys, id);
        }
        let old = entry.state().key.clone();
        index.vacate(&old, entry);
        {
            let mut state = entry.state();
            state.key = to.to_owned();
            change(&mut state);
            index.recount(entry, &mut state, true);
            self.schedule(entry, &mut state);
        }
        let displaced = index.entries.insert(self.slot(to), Arc::clone(entry));
        debug_assert!(
            displaced.is_none(),
            "an entry holds a name that a rename reserved"
        );
        drop(index);
        self.touch();
    }

    /// Makes the counts of `entry` those of its state, after its keys to
    /// delete, its base or its local data changed.
    pub(super) fn track(&self, entry: &Arc<Entry>) {
        let mut index = self.lock();
        let mut state = entry.state();
        let attached = index
            .entries
            .get(&self.slot(&state.key))
            .is_some_and(|held| Arc::ptr_eq(held, entry));
        index.recount(entry, &mut state, attached);
    }

    /// Notes that the running job of `entry` is about to write `key`, if it
    /// may: the entry is attached, it still has the key, the job was not
    /// stopped, and nothing stands in the way. Checking and noting are one
    /// step. The key stays noted until the job ends.
    pub(super) fn begin_write(
        &self,
        entry: &Arc<Entry>,
        key: &str,
        stop: &Stop,
    ) -> Result<(), Fence> {
        let mut index = self.lock();
        {
            let state = entry.state();
            if state.detached {
                return Err(Fence::Gone);
            }
            if state.key != key || stop.is_stopped() {
                return Err(Fence::Stopped);
            }
        }
        if index.write_block(key, entry, Instant::now()).is_some() {
            return Err(Fence::Blocked);
        }
        let name = index.slot(key);
        add(&mut index.writing, name);
        entry.state().writing.push(key.to_owned());
        Ok(())
    }

    /// Ends the notes of the keys the job of `entry` wrote.
    pub(super) fn end_writes(&self, entry: &Arc<Entry>) {
        let keys = std::mem::take(&mut entry.state().writing);
        if keys.is_empty() {
            return;
        }
        let mut index = self.lock();
        for key in keys {
            let name = index.slot(&key);
            sub(&mut index.writing, &name);
            if !index.writing.contains_key(&name) {
                index.cleared(&key);
            }
        }
        drop(index);
        self.touch();
    }

    /// The keys to delete that differ from `key` in case only, when names
    /// ignore case: those no entry owns, and those an entry other than `entry`
    /// owns, with that entry.
    pub(super) fn variants(
        &self,
        key: &str,
        entry: &Arc<Entry>,
    ) -> Vec<(String, Option<Arc<Entry>>)> {
        let index = self.lock();
        if !index.fold {
            return Vec::new();
        }
        let mut found: Vec<(String, Option<Arc<Entry>>)> = Vec::new();
        for variant in index.hidden.get(&index.slot(key)).into_iter().flatten() {
            if variant == key {
                continue;
            }
            if index.tombs.contains_key(variant) {
                found.push((variant.clone(), None));
            }
            for owner in index.gone.get(variant).into_iter().flatten() {
                if !Arc::ptr_eq(owner, entry) {
                    found.push((variant.clone(), Some(Arc::clone(owner))));
                }
            }
        }
        found.sort_by(|a, b| a.0.cmp(&b.0));
        found
    }

    /// The entries other than `entry` that own `key` to delete.
    pub(super) fn owners(&self, key: &str, entry: &Arc<Entry>) -> Vec<Arc<Entry>> {
        self.lock()
            .gone
            .get(key)
            .into_iter()
            .flatten()
            .filter(|owner| !Arc::ptr_eq(owner, entry))
            .cloned()
            .collect()
    }

    /// The keys of `keys` that are keys to delete no entry owns and that a
    /// file entry with a record holds.
    pub(super) fn recorded_at(&self, keys: &[String]) -> Vec<String> {
        let index = self.lock();
        keys.iter()
            .filter(|key| index.tombs.contains_key(*key))
            .filter(|key| {
                index.entries.get(&index.slot(key)).is_some_and(|entry| {
                    let state = entry.state();
                    !entry.is_dir() && !state.detached && state.key == **key && state.recorded
                })
            })
            .cloned()
            .collect()
    }

    /// Whether `key` is a key to delete that no entry owns.
    pub(super) fn tomb_named(&self, key: &str) -> bool {
        self.lock().tombs.contains_key(key)
    }

    /// Holds off other changes to the keys to delete and their records, from
    /// the choice of the keys to the change of the overlay.
    pub(super) fn lock_tombs(&self) -> MutexGuard<'_, ()> {
        self.tomb_io.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The keys `leaving` may have in the bucket or owns to delete, less: keys
    /// already to delete, the key `moving` takes and the keys it owns to
    /// delete, and keys another entry holds. The caller holds the lock of
    /// [`lock_tombs`](Self::lock_tombs) and the `io` and `seal` locks of both
    /// entries.
    pub(super) fn tomb_keys(
        &self,
        leaving: &Arc<Entry>,
        moving: Option<Moving<'_>>,
    ) -> Vec<String> {
        let candidates = keys_to_delete(&leaving.state());
        let index = self.lock();
        let except: Vec<&Arc<Entry>> = std::iter::once(leaving)
            .chain(moving.as_ref().map(|moving| moving.entry))
            .collect();
        candidates
            .into_iter()
            .filter(|key| !index.tombs.contains_key(key))
            .filter(|key| {
                moving
                    .as_ref()
                    .is_none_or(|moving| key != moving.to && !moving.gone.contains(key))
            })
            .filter(|key| !index.held(key, &except))
            .collect()
    }

    /// Takes `keys` off the keys to delete that no entry owns: the records
    /// that name them are rewritten without them, or removed when no key is
    /// left, and then the keys leave the overlay. Keys that are not there are
    /// left out.
    ///
    /// # Errors
    ///
    /// Fails when a record cannot be written or removed. The keys stay.
    pub(super) fn drop_tombs(&self, cache: &CacheDir, keys: &[String]) -> io::Result<()> {
        let _io = self.tomb_io.lock().unwrap_or_else(PoisonError::into_inner);
        let rewrites: Vec<(RecordId, Vec<String>)> = {
            let index = self.lock();
            let mut ids: Vec<RecordId> = keys
                .iter()
                .filter_map(|key| index.tombs.get(key).map(|tomb| tomb.id.clone()))
                .collect();
            ids.sort_by(|a, b| a.as_str().cmp(b.as_str()));
            ids.dedup();
            ids.into_iter()
                .map(|id| {
                    let mut left: Vec<String> = index
                        .tombs
                        .iter()
                        .filter(|(key, tomb)| tomb.id == id && !keys.contains(*key))
                        .map(|(key, _)| key.clone())
                        .collect();
                    left.sort();
                    (id, left)
                })
                .collect()
        };
        for (id, left) in rewrites {
            if left.is_empty() {
                cache.remove_record(&id)?;
            } else {
                let record = TombstoneRecord {
                    id: id.clone(),
                    keys: left,
                };
                cache.write_record(&id, &record.encode())?;
            }
        }
        let mut index = self.lock();
        let removed = keys
            .iter()
            .filter(|key| index.remove_tomb(key).is_some())
            .count();
        drop(index);
        if removed > 0 {
            self.touch();
        }
        Ok(())
    }

    /// Takes the keys to delete that are due at `now`, at most one request's
    /// worth, unless an entry holds the key or a job uses it. They count as
    /// being deleted until the claim is dropped.
    pub(super) fn claim_tombs(self: &Arc<Self>, now: Instant) -> Option<Deleting> {
        let mut index = self.lock();
        let open = index.sweep_gate().is_some_and(|gate| gate <= now);
        if !open && !index.tombs.values().any(|tomb| tomb.urgent) {
            return None;
        }
        let mut due: Vec<String> = index
            .tombs
            .iter()
            .filter(|(key, tomb)| {
                tomb.failure.is_none()
                    && tomb.due <= now
                    && (open || tomb.urgent)
                    && index.may_delete(key, None)
            })
            .map(|(key, _)| key.clone())
            .collect();
        due.sort();
        due.truncate(MAX_DELETE_KEYS);
        if due.is_empty() {
            return None;
        }
        let twins = index.claim(&due);
        Some(Deleting {
            overlay: Arc::clone(self),
            keys: due,
            twins,
        })
    }

    /// Notes the keys a request could not delete for good, with why.
    pub(super) fn finish_tombs(&self, failed: &[(String, S3Error)]) {
        let mut index = self.lock();
        for (key, error) in failed {
            if let Some(tomb) = index.tombs.get_mut(key) {
                tomb.failure = Some(error.clone());
            }
        }
        drop(index);
        self.touch();
    }

    /// The next time after `now` at which a key to delete that no entry owns
    /// may go: when keys to delete may go, or, once they may, when the
    /// earliest key that is not due yet is. `None` when no such time is
    /// ahead.
    pub(super) fn tomb_next_due(&self, now: Instant) -> Option<Instant> {
        let index = self.lock();
        let gate = index.sweep_gate()?;
        if gate > now {
            return Some(gate);
        }
        index
            .tombs
            .values()
            .filter(|tomb| tomb.failure.is_none() && tomb.due > now)
            .map(|tomb| tomb.due)
            .min()
    }

    /// The keys to delete that no entry owns, each with its sequence number,
    /// for a call that waits for their deletion.
    pub(super) fn tomb_waits(&self) -> Vec<(String, u64)> {
        let index = self.lock();
        index
            .tombs
            .iter()
            .map(|(key, tomb)| (key.clone(), tomb.seq))
            .collect()
    }

    /// How a key from [`tomb_waits`](Self::tomb_waits) stands.
    pub(super) fn tomb_progress(&self, key: &str, seq: u64) -> Progress {
        match self.lock().tombs.get(key) {
            Some(tomb) if tomb.seq <= seq => match &tomb.failure {
                Some(failure) => Progress::Failed(failure.clone()),
                None => Progress::Waiting,
            },
            _ => Progress::Done,
        }
    }

    /// Sorts the keys an entry owns to delete: those to delete now, which
    /// count as being deleted until the claim is dropped; those an entry
    /// holds, which the owner lets go; and those whose slot a job writes, an
    /// entry copies from or a request deletes, which stay with it. `owner` is
    /// the entry that owns the keys.
    pub(super) fn claim_gone(self: &Arc<Self>, keys: &[String], owner: &Arc<Entry>) -> GoneClaim {
        let mut index = self.lock();
        let (mut now, mut left, mut busy) = (Vec::new(), Vec::new(), Vec::new());
        for key in keys {
            if index.in_use(key, Some(owner)) {
                busy.push(key.clone());
            } else if index.held(key, &[]) {
                left.push(key.clone());
            } else {
                now.push(key.clone());
            }
        }
        let twins = index.claim(&now);
        GoneClaim {
            claimed: Deleting {
                overlay: Arc::clone(self),
                keys: now,
                twins,
            },
            left,
            busy,
        }
    }

    /// The failure of an entry that keeps `entry` from storing its changes:
    /// it copies from a key `entry` writes or is to delete, or waits for such
    /// an entry.
    pub(super) fn failure_behind(&self, entry: &Arc<Entry>) -> Option<S3Error> {
        let index = self.lock();
        let mut seen = vec![Arc::clone(entry)];
        let mut pending = vec![Arc::clone(entry)];
        while let Some(waiting) = pending.pop() {
            let keys: Vec<String> = {
                let state = waiting.state();
                state
                    .writes()
                    .then(|| state.key.clone())
                    .into_iter()
                    .chain(state.gone.iter().cloned())
                    .collect()
            };
            let blockers = keys
                .iter()
                .filter_map(|key| index.sources.get(&index.slot(key)))
                .flatten()
                .map(|source| &source.holder);
            for blocker in blockers {
                if seen.iter().any(|known| Arc::ptr_eq(known, blocker)) {
                    continue;
                }
                if let Some(failure) = blocker.state().failure.clone() {
                    return Some(failure);
                }
                seen.push(Arc::clone(blocker));
                pending.push(Arc::clone(blocker));
            }
        }
        None
    }

    /// The entries held.
    #[cfg(test)]
    pub(super) fn len(&self) -> usize {
        self.lock().entries.len()
    }

    /// How many times an entry was put to wait for a slot.
    #[cfg(test)]
    pub(super) fn parks(&self) -> usize {
        self.lock().parks
    }

    /// Whether a job writes a key of the slot of `key`, an entry copies from
    /// one, or a request deletes one.
    #[cfg(test)]
    pub(super) fn in_use(&self, key: &str) -> bool {
        self.lock().in_use(key, None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::s3::cachedir::CacheDir;
    use crate::s3::entry::State;
    use crate::s3::lookup::DirRef;
    use crate::s3::record::RecordId;

    fn test_overlay(fold: bool) -> Arc<Overlay> {
        Overlay::new(fold, Duration::from_secs(5))
    }

    fn plain(key: &str) -> Arc<Entry> {
        Entry::from_state(State::new(key.to_owned(), false))
    }

    fn dir(key: &str) -> Arc<Entry> {
        Entry::created_dir(key.to_owned(), 1)
    }

    fn kept(key: &str) -> Arc<Entry> {
        let entry = plain(key);
        entry.state().recorded = true;
        entry
    }

    /// A file with local data, which a job has to store.
    fn stored_later(overlay: &Arc<Overlay>, key: &str) -> Held {
        let id = RecordId::parse(&"b".repeat(32)).unwrap();
        let file = tempfile::tempfile().unwrap();
        overlay
            .insert_new(Entry::created_file(key.to_owned(), id, 1, file))
            .unwrap()
    }

    fn queued(overlay: &Overlay) -> usize {
        overlay.queue().len()
    }

    fn keys(entries: &[Arc<Entry>]) -> Vec<String> {
        let mut keys: Vec<String> = entries.iter().map(|e| e.state().key.clone()).collect();
        keys.sort();
        keys
    }

    #[test]
    fn two_inserts_of_one_name_never_both_succeed() {
        let overlay = test_overlay(false);
        let first = overlay.insert_new(plain("a"));
        assert!(first.is_some());
        assert!(overlay.insert_new(plain("a")).is_none());
        let upper = overlay.insert_new(plain("A"));
        assert!(upper.is_some());
        assert_eq!(overlay.len(), 2);
    }

    #[test]
    fn names_that_differ_in_case_are_one_name_when_case_is_ignored() {
        let overlay = test_overlay(true);
        let held = overlay.insert_new(kept("Dir/File.TXT")).unwrap();
        assert!(overlay.insert_new(plain("dir/file.txt")).is_none());
        let found = overlay.take_pending("DIR/FILE.txt").unwrap();
        assert!(Arc::ptr_eq(&found.entry, &held.entry));
        assert_eq!(found.entry.state().key, "Dir/File.TXT");
        assert!(overlay.take_pending("dir/other").is_none());
    }

    #[test]
    fn names_that_differ_in_case_are_two_names_when_case_counts() {
        let overlay = test_overlay(false);
        let _held = overlay.insert_new(kept("a")).unwrap();
        assert!(overlay.peek("A").is_none());
        assert!(overlay.peek("a").is_some());
    }

    #[test]
    fn the_last_release_drops_an_entry_with_nothing_to_keep() {
        let overlay = test_overlay(false);
        let first = overlay.insert_new(plain("f")).unwrap();
        let second = first.another();
        assert_eq!(first.entry.state().handles, 2);
        drop(first);
        assert_eq!(overlay.len(), 1);
        drop(second);
        assert_eq!(overlay.len(), 0);
        assert!(overlay.peek("f").is_none());
    }

    #[test]
    fn an_entry_with_something_to_keep_stays_after_its_last_release() {
        let overlay = test_overlay(false);
        drop(overlay.insert_new(kept("f")).unwrap());
        assert_eq!(overlay.len(), 1);
        let held = overlay.take_pending("f").unwrap();
        assert_eq!(held.entry.state().handles, 1);

        drop(overlay.insert_new(dir("g")).unwrap());
        assert_eq!(overlay.len(), 2);
    }

    #[test]
    fn entries_with_nothing_to_keep_do_not_count_as_below_a_directory() {
        let overlay = test_overlay(false);
        let _held = overlay.insert_new(plain("d/f")).unwrap();
        assert_eq!(overlay.spelling("d"), None);
        let _kept = overlay.insert_new(kept("d/g")).unwrap();
        assert_eq!(overlay.spelling("d").as_deref(), Some("d"));
    }

    #[test]
    fn an_entry_with_nothing_to_keep_is_not_taken_as_pending() {
        let overlay = test_overlay(false);
        let held = overlay.insert_new(plain("f")).unwrap();
        assert!(overlay.take_pending("f").is_none());
        drop(held);
    }

    #[test]
    fn a_release_leaves_the_time_of_the_last_change() {
        let overlay = test_overlay(false);
        let held = overlay.insert_new(kept("f")).unwrap();
        let entry = Arc::clone(&held.entry);
        let before = entry.state().changed;
        std::thread::sleep(std::time::Duration::from_millis(2));
        drop(held);
        assert_eq!(entry.state().changed, before);
    }

    #[test]
    fn a_release_of_an_entry_another_took_the_place_of_leaves_that_one() {
        let overlay = test_overlay(false);
        let old = overlay.insert_new(plain("f")).unwrap();
        overlay.lock().entries.clear();
        let new = overlay.insert_new(plain("f")).unwrap();
        drop(old);
        assert_eq!(overlay.len(), 1);
        let held = Arc::clone(overlay.lock().entries.get(&overlay.slot("f")).unwrap());
        assert!(Arc::ptr_eq(&held, &new.entry));
    }

    #[test]
    fn entries_below_a_directory_are_direct_or_imply_a_directory() {
        let overlay = test_overlay(false);
        let entries = vec![
            kept("p/a.txt"),
            kept("p/sub/b.txt"),
            kept("p/sub/deep/c.txt"),
            kept("p/other/d.txt"),
            dir("p/made"),
            kept("p2/x"),
            kept("q"),
            dir("p"),
            plain("p/clean"),
            plain("p/clean_dir/x"),
        ];
        assert_eq!(overlay.install(entries, Vec::new()), 10);
        let below = overlay.below("p");
        assert_eq!(keys(&below.direct), ["p/a.txt", "p/made"]);
        let mut implied = below.implied;
        implied.sort();
        assert_eq!(implied, ["other", "sub"]);

        let sub = overlay.below("p/sub");
        assert_eq!(keys(&sub.direct), ["p/sub/b.txt"]);
        assert_eq!(sub.implied, ["deep"]);

        let root = overlay.below("");
        assert_eq!(keys(&root.direct), ["p", "q"]);
        let mut implied = root.implied;
        implied.sort();
        assert_eq!(implied, ["p", "p2"]);
        assert!(overlay.below("nothing").direct.is_empty());
    }

    #[test]
    fn a_directory_is_spelled_as_the_entries_below_it_spell_it() {
        let overlay = test_overlay(true);
        overlay.install(vec![kept("Up/Down/c.txt"), dir("Up")], Vec::new());
        assert_eq!(overlay.spelling("up").as_deref(), Some("Up"));
        assert_eq!(overlay.spelling("UP/down").as_deref(), Some("Up/Down"));
        assert_eq!(overlay.spelling("up/down/c.txt"), None);
        assert_eq!(overlay.spelling("upp"), None);
        assert_eq!(overlay.spelling("").as_deref(), Some(""));
        let below = overlay.below("up");
        assert_eq!(below.implied, ["Down"]);
    }

    #[test]
    fn implied_names_that_differ_in_case_count_once() {
        let overlay = test_overlay(true);
        overlay.install(vec![kept("p/Sub/a"), kept("p/sub/b")], Vec::new());
        let below = overlay.below("p");
        assert_eq!(below.implied.len(), 1);
    }

    fn tombstone(keys: &[&str]) -> TombstoneRecord {
        TombstoneRecord {
            id: RecordId::parse(&"0".repeat(32)).unwrap(),
            keys: keys.iter().map(|key| (*key).to_owned()).collect(),
        }
    }

    #[test]
    fn tombstones_are_found_by_key_as_the_names_compare() {
        let overlay = test_overlay(true);
        overlay.install(Vec::new(), vec![tombstone(&["Gone/x", "other"])]);
        assert!(overlay.tombstoned("gone/X"));
        assert!(overlay.tombstoned("OTHER"));
        assert!(!overlay.tombstoned("gone"));
        let exact = test_overlay(false);
        exact.install(Vec::new(), vec![tombstone(&["Gone/x"])]);
        assert!(exact.tombstoned("Gone/x"));
        assert!(!exact.tombstoned("gone/x"));
    }

    #[test]
    fn a_new_entry_at_a_key_to_delete_may_exist_in_the_bucket() {
        let overlay = test_overlay(false);
        overlay.install(Vec::new(), vec![tombstone(&["gone"])]);
        let over = overlay.insert_new(plain("gone")).unwrap();
        assert!(over.entry.state().may_exist);
        let fresh = overlay.insert_new(plain("fresh")).unwrap();
        assert!(!fresh.entry.state().may_exist);
    }

    #[test]
    fn an_entry_that_a_lookup_of_another_kind_replaces_is_detached_while_held() {
        let overlay = test_overlay(false);
        let held = overlay.insert_new(plain("x")).unwrap();
        let ahead = Arc::new(ReadAhead::new());
        let dir = Found::Dir(DirRef {
            key: "x".to_owned(),
            name: "x".to_owned(),
            marker: None,
        });
        let new = overlay.take_found(dir, &ahead).unwrap();
        assert!(!Arc::ptr_eq(&held.entry, &new.entry));
        assert!(held.entry.state().detached);
        assert!(held.entry.state().attached().is_err());
        assert!(!new.entry.state().detached);
        drop(held);
        assert_eq!(overlay.len(), 1);
    }

    fn found_file(key: &str) -> Found {
        Found::File(crate::s3::lookup::FileRef {
            key: key.to_owned(),
            name: key.to_owned(),
            head: Arc::new(crate::s3::object::ObjectHead {
                size: 1,
                etag: "\"e\"".to_owned(),
                last_modified: std::time::SystemTime::UNIX_EPOCH,
                metadata: crate::s3::object::Metadata::default(),
            }),
        })
    }

    #[test]
    fn a_lookup_does_not_make_an_entry_at_a_name_a_rename_reserved_or_that_is_to_be_deleted() {
        let overlay = test_overlay(true);
        let ahead = Arc::new(ReadAhead::new());
        let renamed = plain("f");
        let _renamed = overlay.insert_new(Arc::clone(&renamed)).unwrap();
        let reservation = overlay.reserve("T", &renamed, None).unwrap();
        assert!(overlay.take_found(found_file("t"), &ahead).is_none());
        assert_eq!(overlay.len(), 1);
        drop(reservation);
        let held = overlay.take_found(found_file("t"), &ahead).unwrap();
        assert_eq!(overlay.len(), 2);
        drop(held);

        let id = RecordId::parse(&"c".repeat(32)).unwrap();
        overlay.unlinked(&kept("u"), &["u".to_owned()], &id);
        assert!(overlay.take_found(found_file("U"), &ahead).is_none());
    }

    #[test]
    fn an_entry_with_local_data_is_queued_when_it_is_made_and_a_directory_being_made_is_not() {
        let overlay = test_overlay(false);
        let _file = stored_later(&overlay, "f");
        assert_eq!(queued(&overlay), 1);
        let _dir = overlay.insert_new(dir("d")).unwrap();
        assert_eq!(queued(&overlay), 1, "its open puts the marker");
        let _plain = overlay.insert_new(plain("p")).unwrap();
        assert_eq!(queued(&overlay), 1);
    }

    #[test]
    fn a_job_starts_only_when_its_time_has_come_and_jobs_of_one_entry_never_overlap() {
        let overlay = test_overlay(false);
        let held = stored_later(&overlay, "f");
        let entry = Arc::clone(&held.entry);
        let first = overlay
            .queue()
            .pop_due(Instant::now() + Duration::from_secs(60));
        assert!(Arc::ptr_eq(first.as_ref().unwrap(), &entry));

        let now = Instant::now();
        let Claim::Later(back, due) = overlay.claim(Arc::clone(&entry), now) else {
            panic!("expected Later");
        };
        assert!(due > now);
        assert!(entry.state().queued);
        overlay.queue().push(back, due);

        let later = now + Duration::from_secs(60);
        let Some(next) = overlay.queue().pop_due(later) else {
            panic!("expected the entry in the queue");
        };
        let Claim::Run(job, stop, false) = overlay.claim(next, later) else {
            panic!("expected Run");
        };
        assert!(entry.state().job.is_some());
        assert_eq!(entry.state().handles, 2);
        assert!(!stop.is_stopped());
        assert!(matches!(
            overlay.claim(Arc::clone(&entry), later),
            Claim::Skip
        ));
        entry.state().bump();
        assert!(stop.is_stopped(), "a change stops the job");

        // The job ends: the entry waits its turn again.
        entry.state().job = None;
        drop(job);
        assert_eq!(queued(&overlay), 1);
        drop(held);
    }

    #[test]
    fn an_entry_that_failed_or_left_is_not_claimed() {
        let overlay = test_overlay(false);
        let failed = stored_later(&overlay, "a");
        failed.entry.state().failure = Some(S3Error::Stopped);
        let gone = stored_later(&overlay, "b");
        overlay.evict(&gone.entry);
        assert!(gone.entry.state().detached);
        let later = Instant::now() + Duration::from_secs(60);
        while let Some(entry) = overlay.queue().pop_due(later) {
            assert!(matches!(overlay.claim(entry, later), Claim::Skip));
        }
        assert_eq!(overlay.len(), 1);
        assert_eq!(overlay.failures("").len(), 1);
        assert_eq!(overlay.work().len(), 1, "an entry that left holds nothing");
    }

    #[test]
    fn entries_that_came_back_from_disk_are_due_at_once_oldest_first() {
        let overlay = test_overlay(false);
        let make = |key: &str| {
            let mut state = State::new(key.to_owned(), false);
            state.set_local(crate::s3::entry::Local {
                file: Arc::new(tempfile::tempfile().unwrap()),
                len: 0,
                present: crate::s3::ranges::RangeSet::new(),
            });
            state.eager = true;
            state.recorded = true;
            Entry::from_state(state)
        };
        overlay.install(vec![make("one"), make("two"), make("three")], Vec::new());
        let now = Instant::now() + Duration::from_millis(1);
        let order: Vec<String> = std::iter::from_fn(|| overlay.queue().pop_due(now))
            .map(|entry| entry.state().key.clone())
            .collect();
        assert_eq!(order, ["one", "two", "three"]);
    }

    #[test]
    fn work_gives_each_entry_with_something_to_store_and_its_generation() {
        let overlay = test_overlay(false);
        let held = stored_later(&overlay, "f");
        let work = overlay.work();
        assert_eq!(work.len(), 1);
        let generation = work[0].generation;
        held.entry.state().bump();
        assert_eq!(overlay.work()[0].generation, generation + 1);
    }

    fn moved(key: &str, from: &str, gone: &[&str]) -> Arc<Entry> {
        let mut state = State::new(key.to_owned(), false);
        state.base = Some(crate::s3::entry::Base::at(from));
        state.gone = gone.iter().map(|key| (*key).to_owned()).collect();
        state.recorded = true;
        Entry::from_state(state)
    }

    fn claimable(overlay: &Arc<Overlay>, entry: &Arc<Entry>) -> bool {
        matches!(
            overlay.claim(Arc::clone(entry), Instant::now() + Duration::from_secs(60)),
            Claim::Run(..)
        )
    }

    /// Local data of `len` bytes, of which the first `covered` are present.
    fn local_data(len: u64, covered: u64) -> crate::s3::entry::Local {
        let mut present = crate::s3::ranges::RangeSet::new();
        if covered > 0 {
            present.insert(0..covered);
        }
        crate::s3::entry::Local {
            file: Arc::new(tempfile::tempfile().unwrap()),
            len,
            present,
        }
    }

    #[test]
    fn a_job_waits_while_another_entry_copies_from_its_key() {
        let overlay = test_overlay(false);
        let old = moved("doc.bak", "doc", &["doc"]);
        let new = kept("doc");
        new.state().may_exist = true;
        new.state().set_local(local_data(0, 0));
        let _old = overlay.insert_new(Arc::clone(&old)).unwrap();
        overlay.track(&old);
        let held = overlay.insert_new(Arc::clone(&new)).unwrap();
        assert!(
            !claimable(&overlay, &new),
            "the old file still copies from it"
        );

        old.state().gone.clear();
        overlay.track(&old);
        assert!(!claimable(&overlay, &new), "it still copies from it");

        old.state().base = None;
        overlay.track(&old);
        drop(held);
        assert!(claimable(&overlay, &new));
    }

    #[test]
    fn a_file_that_holds_every_byte_is_not_a_source_once_its_record_says_so() {
        let overlay = test_overlay(false);
        let old = moved("doc.bak", "doc", &[]);
        let _old = overlay.insert_new(Arc::clone(&old)).unwrap();
        overlay.track(&old);
        let doc = overlay.slot("doc");
        assert!(overlay.lock().sources.contains_key(&doc));
        old.state().set_local(local_data(4, 2));
        overlay.track(&old);
        assert!(
            overlay.lock().sources.contains_key(&doc),
            "only half of the file is local"
        );
        old.state().set_local(local_data(4, 4));
        old.state().recorded_source = Some("doc".to_owned());
        overlay.track(&old);
        assert!(
            overlay.lock().sources.contains_key(&doc),
            "the record names it"
        );
        old.state().recorded_source = None;
        overlay.track(&old);
        assert!(overlay.lock().sources.is_empty());
    }

    #[test]
    fn a_job_waits_while_a_request_deletes_its_key_or_a_job_writes_it() {
        let overlay = test_overlay(false);
        let owner = moved("b", "x", &["a"]);
        let _owner = overlay.insert_new(Arc::clone(&owner)).unwrap();
        overlay.track(&owner);
        let claim = overlay.claim_gone(&["a".to_owned()], &owner);
        assert_eq!(claim.claimed.keys(), ["a"]);
        let file = kept("a");
        file.state().set_local(local_data(0, 0));
        let _file = overlay.insert_new(Arc::clone(&file)).unwrap();
        assert!(!claimable(&overlay, &file), "the delete is in flight");
        drop(claim);
        assert!(claimable(&overlay, &file));
    }

    #[test]
    fn a_job_that_writes_a_key_keeps_the_key_from_being_deleted() {
        let overlay = test_overlay(false);
        let writer = kept("a");
        writer.state().set_local(local_data(0, 0));
        let _held = overlay.insert_new(Arc::clone(&writer)).unwrap();
        assert!(overlay.begin_write(&writer, "a", &Stop::new()).is_ok());
        let owner = moved("c", "z", &["a"]);
        let _owner = overlay.insert_new(Arc::clone(&owner)).unwrap();
        let claim = overlay.claim_gone(&["a".to_owned()], &owner);
        assert_eq!(claim.busy, ["a"]);
        assert!(claim.claimed.keys().is_empty());
        let other = kept("b");
        other.state().set_local(local_data(0, 0));
        let _other = overlay.insert_new(Arc::clone(&other)).unwrap();
        assert!(overlay.begin_write(&other, "a", &Stop::new()).is_err());
        overlay.end_writes(&writer);
        assert_eq!(overlay.claim_gone(&["a".to_owned()], &owner).left, ["a"]);
    }

    #[test]
    fn keys_an_entry_owns_hide_the_names_until_they_are_deleted() {
        let overlay = test_overlay(false);
        let entry = moved("b", "a", &["a"]);
        let _held = overlay.insert_new(Arc::clone(&entry)).unwrap();
        overlay.track(&entry);
        assert!(overlay.tombstoned("a"));
        assert!(!overlay.tombstoned("b"));
        entry.state().gone.clear();
        overlay.track(&entry);
        assert!(!overlay.tombstoned("a"));
    }

    #[test]
    fn an_owned_key_a_live_entry_holds_is_left_and_one_nobody_holds_is_deleted() {
        let overlay = test_overlay(false);
        let owner = moved("c", "z", &["a", "b"]);
        let _owner = overlay.insert_new(Arc::clone(&owner)).unwrap();
        let _live = overlay.insert_new(kept("b")).unwrap();
        let claim = overlay.claim_gone(&["a".to_owned(), "b".to_owned()], &owner);
        assert_eq!(claim.claimed.keys(), ["a"]);
        assert_eq!(claim.left, ["b"]);
        let again = overlay.claim_gone(&["a".to_owned()], &owner);
        assert!(
            again.claimed.keys().is_empty(),
            "a key being deleted is not claimed twice"
        );
        assert_eq!(again.busy, ["a"]);
    }

    #[test]
    fn the_copy_source_of_the_owner_is_not_deleted() {
        let overlay = test_overlay(false);
        let owner = moved("b", "a", &["a"]);
        let _owner = overlay.insert_new(Arc::clone(&owner)).unwrap();
        overlay.track(&owner);
        let claim = overlay.claim_gone(&["a".to_owned()], &owner);
        assert_eq!(claim.busy, ["a"]);
        assert!(claim.claimed.keys().is_empty());
    }

    #[test]
    fn a_detached_entry_does_not_hold_its_key() {
        let overlay = test_overlay(false);
        let owner = moved("c", "z", &["b"]);
        let _owner = overlay.insert_new(Arc::clone(&owner)).unwrap();
        let other = kept("b");
        let _held = overlay.insert_new(Arc::clone(&other)).unwrap();
        other.state().detached = true;
        let claim = overlay.claim_gone(&["b".to_owned()], &owner);
        assert_eq!(claim.claimed.keys(), ["b"]);
    }

    fn claimed(overlay: &Arc<Overlay>, now: Instant) -> Vec<String> {
        let mut keys = overlay
            .claim_tombs(now)
            .map(|claim| claim.keys().to_vec())
            .unwrap_or_default();
        keys.sort();
        keys
    }

    #[test]
    fn a_burst_of_keys_to_delete_goes_out_together_once_the_burst_is_over() {
        let overlay = test_overlay(false);
        let id = RecordId::parse(&"c".repeat(32)).unwrap();
        let start = Instant::now();
        for key in ["x", "y", "z"] {
            let victim = kept(key);
            overlay.unlinked(&victim, &[key.to_owned()], &id);
        }
        assert!(
            claimed(&overlay, start).is_empty(),
            "the delay has not passed"
        );
        let later = start + Duration::from_secs(6);
        let claim = overlay.claim_tombs(later).unwrap();
        assert_eq!(claim.keys().len(), 3);
        assert!(
            claimed(&overlay, later).is_empty(),
            "claimed keys are in flight"
        );
        drop(claim);
        assert_eq!(claimed(&overlay, later).len(), 3);
    }

    #[test]
    fn a_key_to_delete_that_a_live_entry_holds_is_not_claimed() {
        let overlay = test_overlay(false);
        let id = RecordId::parse(&"c".repeat(32)).unwrap();
        overlay.unlinked(&kept("x"), &["x".to_owned()], &id);
        let _new = overlay.insert_new(kept("x")).unwrap();
        assert!(claimed(&overlay, Instant::now() + Duration::from_secs(6)).is_empty());
    }

    #[test]
    fn a_new_entry_at_a_key_to_delete_takes_it_off_the_records_that_name_it() {
        let dir = tempfile::tempdir().unwrap();
        let cache = CacheDir::open(&dir.path().join("c"), "identity").unwrap();
        let overlay = test_overlay(false);
        let id = RecordId::parse(&"d".repeat(32)).unwrap();
        overlay.unlinked(&kept("x"), &["x".to_owned(), "y".to_owned()], &id);
        let record = TombstoneRecord {
            id: id.clone(),
            keys: vec!["x".to_owned(), "y".to_owned()],
        };
        cache.write_record(&id, &record.encode()).unwrap();

        overlay.drop_tombs(&cache, &["x".to_owned()]).unwrap();
        assert!(!overlay.tombstoned("x"));
        assert!(overlay.tombstoned("y"));
        let text = std::fs::read_to_string(dir.path().join("c/records").join(id.as_str())).unwrap();
        assert!(text.contains("key y") && !text.contains("key x"), "{text}");

        overlay.drop_tombs(&cache, &["y".to_owned()]).unwrap();
        assert!(!dir.path().join("c/records").join(id.as_str()).exists());
    }

    #[test]
    fn at_any_time_a_key_to_delete_is_claimable_or_the_next_due_time_is_ahead() {
        let overlay = test_overlay(false);
        let id = RecordId::parse(&"e".repeat(32)).unwrap();
        let start = Instant::now();
        overlay.unlinked(&kept("x"), &["x".to_owned()], &id);
        let gate = overlay.tomb_next_due(start).expect("a time is ahead");
        let before = gate - Duration::from_millis(1);
        assert!(claimed(&overlay, before).is_empty());
        assert_eq!(overlay.tomb_next_due(before), Some(gate));
        assert_eq!(claimed(&overlay, gate), ["x"]);
        assert_eq!(overlay.tomb_next_due(gate), None);
    }

    #[test]
    fn a_key_not_due_yet_has_a_time_ahead_while_an_older_key_is_blocked() {
        let overlay = test_overlay(false);
        let id = RecordId::parse(&"e".repeat(32)).unwrap();
        let start = Instant::now();
        let writer = kept("a");
        writer.state().set_local(local_data(0, 0));
        let _held = overlay.insert_new(Arc::clone(&writer)).unwrap();
        assert!(overlay.begin_write(&writer, "a", &Stop::new()).is_ok());
        overlay.unlinked(&writer, &["a".to_owned()], &id);
        let due = start + Duration::from_secs(200);
        overlay.lock().add_tomb("b", &id, due);

        let now = start + Duration::from_secs(100);
        assert!(
            claimed(&overlay, now).is_empty(),
            "a is blocked, b is early"
        );
        assert_eq!(overlay.tomb_next_due(now), Some(due));
        assert_eq!(claimed(&overlay, due), ["b"]);
    }

    #[tokio::test]
    async fn a_key_to_delete_that_a_write_blocks_wakes_the_worker_when_the_write_ends() {
        let overlay = test_overlay(false);
        let id = RecordId::parse(&"e".repeat(32)).unwrap();
        let writer = kept("x");
        writer.state().set_local(local_data(0, 0));
        let _held = overlay.insert_new(Arc::clone(&writer)).unwrap();
        assert!(overlay.begin_write(&writer, "x", &Stop::new()).is_ok());
        overlay.unlinked(&writer, &["x".to_owned()], &id);
        let later = Instant::now() + Duration::from_secs(600);
        assert!(overlay.claim_tombs(later).is_none(), "a job writes x");

        while tokio::time::timeout(Duration::ZERO, overlay.queue().woken())
            .await
            .is_ok()
        {}
        overlay.end_writes(&writer);
        tokio::time::timeout(Duration::from_secs(5), overlay.queue().woken())
            .await
            .expect("the end of the write wakes the worker");
        assert!(overlay.claim_tombs(later).is_some());
    }

    #[test]
    fn a_key_above_one_a_job_writes_that_is_to_be_deleted_is_deleted_first_and_at_once() {
        let overlay = test_overlay(false);
        let id = RecordId::parse(&"f".repeat(32)).unwrap();
        let start = Instant::now();
        overlay.unlinked(&kept("d"), &["d".to_owned()], &id);
        overlay.unlinked(&kept("other"), &["other".to_owned()], &id);
        let file = kept("d/x");
        file.state().set_local(local_data(0, 0));
        let _held = overlay.insert_new(Arc::clone(&file)).unwrap();
        assert!(claimed(&overlay, start).is_empty());
        assert!(overlay.begin_write(&file, "d/x", &Stop::new()).is_err());
        assert_eq!(
            claimed(&overlay, Instant::now()),
            ["d"],
            "only the key in the way"
        );
    }

    #[test]
    fn a_job_waits_on_the_key_in_its_way_and_wakes_when_it_clears() {
        let overlay = test_overlay(false);
        let file = kept("a");
        file.state().set_local(local_data(0, 0));
        let _held = overlay.insert_new(Arc::clone(&file)).unwrap();
        let owner = moved("b", "a", &[]);
        let _owner = overlay.insert_new(Arc::clone(&owner)).unwrap();
        overlay.track(&owner);
        let later = Instant::now() + Duration::from_secs(60);
        while overlay.queue().pop_due(later).is_some() {}
        file.state().queued = false;
        assert!(matches!(
            overlay.claim(Arc::clone(&file), later),
            Claim::Skip
        ));
        assert!(file.state().queued, "it waits in the overlay");
        assert!(overlay.queue().pop_due(later).is_none());
        owner.state().base = None;
        overlay.track(&owner);
        let woke = overlay.queue().pop_due(later).expect("the key cleared");
        assert!(Arc::ptr_eq(&woke, &file));
        assert!(matches!(
            overlay.claim(woke, later),
            Claim::Run(_, _, false)
        ));
    }

    /// Entries in a ring: each is at one of `names` and copies from the next
    /// name, the last from the first.
    fn ring(overlay: &Arc<Overlay>, names: &[&str]) -> (Vec<Arc<Entry>>, Vec<Held>) {
        let entries: Vec<Arc<Entry>> = names
            .iter()
            .enumerate()
            .map(|(i, name)| moved(name, names[(i + 1) % names.len()], &[]))
            .collect();
        let holds = entries
            .iter()
            .map(|entry| {
                let held = overlay.insert_new(Arc::clone(entry)).unwrap();
                overlay.track(entry);
                held
            })
            .collect();
        (entries, holds)
    }

    #[test]
    fn entries_that_wait_for_each_other_are_resolved_by_the_one_with_the_least_base() {
        let overlay = test_overlay(false);
        let (entries, _holds) = ring(&overlay, &["t", "a", "b"]);
        let later = Instant::now() + Duration::from_secs(60);
        while overlay.queue().pop_due(later).is_some() {}
        // `a` copies from `b`, `b` from `t`, and `t` from `a`: the base with
        // the least key is `a`, the base of `t`.
        for entry in &entries {
            entry.state().queued = false;
        }
        assert!(matches!(
            overlay.claim(Arc::clone(&entries[1]), later),
            Claim::Skip
        ));
        assert!(
            entries[1].state().queued,
            "an entry that does not resolve it waits"
        );
        let Claim::Run(_job, _stop, cycle) = overlay.claim(Arc::clone(&entries[0]), later) else {
            panic!("the entry with the least base resolves the cycle");
        };
        assert!(cycle);
    }

    #[test]
    fn a_chain_that_does_not_close_is_no_cycle() {
        let overlay = test_overlay(false);
        let tail = moved("c", "x", &[]);
        let middle = moved("b", "c", &[]);
        let head = moved("a", "b", &[]);
        let _holds: Vec<Held> = [&tail, &middle, &head]
            .into_iter()
            .map(|entry| {
                let held = overlay.insert_new(Arc::clone(entry)).unwrap();
                overlay.track(entry);
                held
            })
            .collect();
        let later = Instant::now() + Duration::from_secs(60);
        while overlay.queue().pop_due(later).is_some() {}
        tail.state().queued = false;
        // `c` waits for the copy to `b`, which waits for the copy to `a`,
        // which waits for nothing.
        assert!(matches!(
            overlay.claim(Arc::clone(&tail), later),
            Claim::Skip
        ));
        assert!(tail.state().queued);
        head.state().queued = false;
        assert!(matches!(
            overlay.claim(Arc::clone(&head), later),
            Claim::Run(_, _, false)
        ));
    }

    #[test]
    fn keys_a_request_deletes_are_released_when_it_ends_by_a_panic() {
        let overlay = test_overlay(false);
        let claim = overlay.claim_gone(&["a".to_owned()], &plain("owner"));
        assert_eq!(claim.claimed.keys(), ["a"]);
        let ended = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
            let _claim = claim;
            panic!("the request failed");
        }));
        assert!(ended.is_err());
        assert_eq!(
            overlay
                .claim_gone(&["a".to_owned()], &plain("owner"))
                .claimed
                .keys(),
            ["a"]
        );
    }

    #[test]
    fn a_waiting_entry_reports_the_failure_of_the_entry_it_waits_for() {
        let overlay = test_overlay(false);
        let file = kept("a");
        file.state().set_local(local_data(0, 0));
        let _held = overlay.insert_new(Arc::clone(&file)).unwrap();
        let owner = moved("b", "a", &[]);
        let _owner = overlay.insert_new(Arc::clone(&owner)).unwrap();
        overlay.track(&owner);
        assert!(overlay.failure_behind(&file).is_none());
        owner.state().failure = Some(S3Error::Stopped);
        assert!(overlay.failure_behind(&file).is_some());
    }

    #[test]
    fn a_second_entry_that_copies_from_a_key_does_not_take_it_from_the_first() {
        let overlay = test_overlay(false);
        let first = moved("b", "a", &[]);
        let second = moved("c", "a", &[]);
        let _first = overlay.insert_new(Arc::clone(&first)).unwrap();
        let _second = overlay.insert_new(Arc::clone(&second)).unwrap();
        overlay.track(&first);
        overlay.track(&second);
        let at = overlay.slot("a");
        let holders = |overlay: &Arc<Overlay>| -> Vec<Arc<Entry>> {
            overlay.lock().sources[&at]
                .iter()
                .map(|source| Arc::clone(&source.holder))
                .collect()
        };
        assert!(holders(&overlay).len() == 1 && Arc::ptr_eq(&holders(&overlay)[0], &first));
        assert!(second.state().counted.source.is_none());
        overlay.track(&second);
        assert!(holders(&overlay).len() == 1 && Arc::ptr_eq(&holders(&overlay)[0], &first));
        first.state().base = None;
        overlay.track(&first);
        assert!(overlay.lock().sources.is_empty());
    }

    #[test]
    fn a_name_a_rename_reserves_takes_no_entry_and_no_second_rename() {
        let overlay = test_overlay(true);
        let renamed = plain("a");
        let replaced = plain("T");
        let _a = overlay.insert_new(Arc::clone(&renamed)).unwrap();
        let _t = overlay.insert_new(Arc::clone(&replaced)).unwrap();
        assert!(overlay.reserve("t", &renamed, None).is_none(), "t is held");
        let reservation = overlay.reserve("t", &renamed, Some(&replaced)).unwrap();
        assert!(overlay.reserve("T", &renamed, Some(&replaced)).is_none());
        assert!(overlay.insert_new(plain("free")).is_some());
        drop(overlay.lock().entries.remove(&overlay.slot("t")));
        assert!(overlay.insert_new(plain("t")).is_none(), "reserved");
        drop(reservation);
        assert!(overlay.insert_new(plain("t")).is_some());
        assert!(
            overlay.reserve("a", &renamed, None).is_some(),
            "its own name"
        );
    }

    #[test]
    fn a_key_in_another_case_than_an_entry_holds_is_checked_and_shields_the_entry_name() {
        let overlay = test_overlay(true);
        let file = kept("doc");
        file.state().set_local(local_data(0, 0));
        let _held = overlay.insert_new(Arc::clone(&file)).unwrap();
        overlay.install(Vec::new(), vec![tombstone(&["Doc", "other"])]);
        let later = Instant::now() + Duration::from_secs(600);
        let claim = overlay.claim_tombs(later).unwrap();
        assert_eq!(claim.keys(), ["Doc", "other"]);
        assert_eq!(claim.twins(), [("Doc".to_owned(), "doc".to_owned())]);
        assert!(
            overlay.begin_write(&file, "doc", &Stop::new()).is_err(),
            "the file waits while the keys are checked"
        );
        drop(claim);
        assert!(overlay.begin_write(&file, "doc", &Stop::new()).is_ok());
        let others = overlay.claim_tombs(later).unwrap();
        assert_eq!(others.keys(), ["other"], "a job writes the other spelling");
        drop(others);
        overlay.end_writes(&file);
        assert_eq!(overlay.claim_tombs(later).unwrap().keys(), ["Doc", "other"]);
    }

    #[test]
    fn keys_an_entry_owns_in_another_case_than_its_own_key_are_checked_against_it() {
        let overlay = test_overlay(true);
        let owner = moved("report.txt", "x", &["Report.txt"]);
        let _owner = overlay.insert_new(Arc::clone(&owner)).unwrap();
        overlay.track(&owner);
        let claim = overlay.claim_gone(&["Report.txt".to_owned()], &owner);
        assert_eq!(claim.claimed.keys(), ["Report.txt"]);
        assert_eq!(
            claim.claimed.twins(),
            [("Report.txt".to_owned(), "report.txt".to_owned())]
        );
        let exact = test_overlay(false);
        let _exact = exact.insert_new(Arc::clone(&owner)).unwrap();
        assert!(
            exact
                .claim_gone(&["Report.txt".to_owned()], &owner)
                .claimed
                .twins()
                .is_empty()
        );
    }

    #[test]
    fn the_keys_to_delete_in_another_case_than_a_stored_key_are_found_with_their_owners() {
        let overlay = test_overlay(true);
        let stored = plain("doc");
        let owner = moved("b", "x", &["DOC", "other"]);
        let _owner = overlay.insert_new(Arc::clone(&owner)).unwrap();
        overlay.track(&owner);
        overlay.install(Vec::new(), vec![tombstone(&["Doc", "doc", "docs"])]);
        let found = overlay.variants("doc", &stored);
        let keys: Vec<&str> = found.iter().map(|(key, _)| key.as_str()).collect();
        assert_eq!(keys, ["DOC", "Doc"]);
        assert!(
            found[0]
                .1
                .as_ref()
                .is_some_and(|held| Arc::ptr_eq(held, &owner))
        );
        assert!(found[1].1.is_none());
        assert!(
            overlay
                .variants("doc", &owner)
                .iter()
                .all(|(key, _)| key != "DOC")
        );
        assert!(test_overlay(false).variants("doc", &stored).is_empty());
    }

    #[test]
    fn a_job_may_not_write_a_key_while_a_request_deletes_another_case_of_it() {
        let overlay = test_overlay(true);
        overlay.install(Vec::new(), vec![tombstone(&["Doc"])]);
        let later = Instant::now() + Duration::from_secs(600);
        let claim = overlay.claim_tombs(later).unwrap();
        let file = kept("doc");
        file.state().set_local(local_data(0, 0));
        let _held = overlay.insert_new(Arc::clone(&file)).unwrap();
        assert!(!claimable(&overlay, &file), "it waits for the delete");
        assert!(overlay.begin_write(&file, "doc", &Stop::new()).is_err());
        drop(claim);
        assert!(claimable(&overlay, &file), "the delete ended");

        let exact = test_overlay(false);
        exact.install(Vec::new(), vec![tombstone(&["Doc"])]);
        let claim = exact.claim_tombs(later).unwrap();
        let other = kept("doc");
        other.state().set_local(local_data(0, 0));
        let _other = exact.insert_new(Arc::clone(&other)).unwrap();
        assert!(exact.begin_write(&other, "doc", &Stop::new()).is_ok());
        drop(claim);
    }

    #[test]
    fn a_key_is_not_deleted_while_a_job_writes_another_case_of_it_except_for_its_own_owner() {
        let overlay = test_overlay(true);
        let writer = kept("doc");
        writer.state().set_local(local_data(0, 0));
        let _held = overlay.insert_new(Arc::clone(&writer)).unwrap();
        assert!(overlay.begin_write(&writer, "doc", &Stop::new()).is_ok());
        overlay.install(Vec::new(), vec![tombstone(&["Doc"])]);
        let later = Instant::now() + Duration::from_secs(600);
        assert!(overlay.claim_tombs(later).is_none(), "a job writes doc");
        let other = plain("other");
        let claim = overlay.claim_gone(&["Doc".to_owned()], &other);
        assert_eq!(claim.busy, ["Doc"]);
        let claim = overlay.claim_gone(&["Doc".to_owned()], &writer);
        assert_eq!(claim.claimed.keys(), ["Doc"], "its own write is over");
        drop(claim);
        overlay.end_writes(&writer);
        assert!(overlay.claim_tombs(later).is_some());

        let exact = test_overlay(false);
        let writer = kept("doc");
        writer.state().set_local(local_data(0, 0));
        let _held = exact.insert_new(Arc::clone(&writer)).unwrap();
        assert!(exact.begin_write(&writer, "doc", &Stop::new()).is_ok());
        exact.install(Vec::new(), vec![tombstone(&["Doc"])]);
        assert!(exact.claim_tombs(later).is_some());
    }

    #[test]
    fn a_copy_source_keeps_its_name_in_every_case_from_being_written_or_deleted() {
        for fold in [true, false] {
            let overlay = test_overlay(fold);
            let copy = moved("Report.bak", "Report.docx", &[]);
            let _copy = overlay.insert_new(Arc::clone(&copy)).unwrap();
            overlay.track(&copy);
            let saved = kept("report.docx");
            saved.state().set_local(local_data(0, 0));
            let _saved = overlay.insert_new(Arc::clone(&saved)).unwrap();
            assert_eq!(
                claimable(&overlay, &saved),
                !fold,
                "the save waits only when names ignore case"
            );

            overlay.install(Vec::new(), vec![tombstone(&["report.DOCX"])]);
            let later = Instant::now() + Duration::from_secs(600);
            assert_eq!(
                overlay.claim_tombs(later).is_none(),
                fold,
                "the delete waits only when names ignore case"
            );
        }
    }

    #[test]
    fn jobs_that_write_names_in_two_cases_never_run_together_when_names_ignore_case() {
        for fold in [true, false] {
            let overlay = test_overlay(fold);
            let first = kept("Doc");
            first.state().set_local(local_data(0, 0));
            let _first = overlay.insert_new(Arc::clone(&first)).unwrap();
            assert!(overlay.begin_write(&first, "Doc", &Stop::new()).is_ok());
            overlay.renamed(&first, "Elsewhere", |_| {}, None);
            let second = kept("doc");
            second.state().set_local(local_data(0, 0));
            let _second = overlay.insert_new(Arc::clone(&second)).unwrap();
            let started = overlay.begin_write(&second, "doc", &Stop::new());
            assert_eq!(started.is_err(), fold);
            overlay.end_writes(&first);
            if fold {
                assert!(overlay.begin_write(&second, "doc", &Stop::new()).is_ok());
            }
        }
    }

    #[test]
    fn a_name_two_files_copy_from_is_no_candidate_for_a_cycle() {
        let overlay = test_overlay(true);
        let upper = moved("x", "A", &[]);
        let lower = moved("y", "a", &[]);
        let _upper = overlay.insert_new(Arc::clone(&upper)).unwrap();
        let _lower = overlay.insert_new(Arc::clone(&lower)).unwrap();
        overlay.track(&upper);
        overlay.track(&lower);
        let newcomer = kept("a");
        let now = Instant::now();
        let block = overlay.lock().write_block("a", &newcomer, now).unwrap();
        assert!(block.source.is_none(), "two files stand in the way");
        upper.state().base = None;
        overlay.track(&upper);
        let block = overlay.lock().write_block("a", &newcomer, now).unwrap();
        assert!(
            block
                .source
                .is_some_and(|holder| Arc::ptr_eq(&holder, &lower))
        );
    }

    #[test]
    fn keys_to_delete_are_found_by_name_in_every_spelling() {
        let overlay = test_overlay(true);
        let owner = moved("c", "z", &["A"]);
        let _owner = overlay.insert_new(Arc::clone(&owner)).unwrap();
        overlay.track(&owner);
        overlay.install(Vec::new(), vec![tombstone(&["a", "other"])]);
        let asking = plain("x");
        let found = overlay.variants("a", &asking);
        assert_eq!(found.len(), 1, "the exact key is not a variant");
        assert_eq!(found[0].0, "A");
        assert!(
            found[0]
                .1
                .as_ref()
                .is_some_and(|who| Arc::ptr_eq(who, &owner))
        );
        let found = overlay.variants("A", &asking);
        assert_eq!(found.len(), 1);
        assert_eq!((found[0].0.as_str(), found[0].1.is_none()), ("a", true));

        let now = Instant::now();
        overlay.lock().expedite("A", now);
        let index = overlay.lock();
        assert!(index.tombs["a"].urgent);
        assert!(!index.tombs["other"].urgent);
        assert_eq!(index.hidden_keys(), 3);
    }

    #[test]
    fn an_entry_waits_for_the_delete_of_another_case_of_its_key_and_is_woken_when_it_ends() {
        let overlay = test_overlay(true);
        overlay.install(Vec::new(), vec![tombstone(&["Doc"])]);
        let later = Instant::now() + Duration::from_secs(600);
        let claim = overlay.claim_tombs(later).unwrap();
        let file = kept("doc");
        file.state().set_local(local_data(0, 0));
        let _held = overlay.insert_new(Arc::clone(&file)).unwrap();
        let entry = overlay.queue().pop_due(later).unwrap();
        assert!(matches!(overlay.claim(entry, later), Claim::Skip));
        assert_eq!(queued(&overlay), 0, "it waits");
        drop(claim);
        assert_eq!(queued(&overlay), 1, "the end of the delete woke it");
    }
}
