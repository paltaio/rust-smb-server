//! The entries and tombstones of a backend: its view of the paths whose
//! state differs from the bucket's, or may.
//!
//! Lock order: the `io` and `seal` locks of entries, the lock of the keys to
//! delete, the index of the [`Overlay`], then the state of one [`Entry`], then
//! the locks of the read-ahead chunks. The metadata cache lock is never taken
//! while any of them is held. The index and state locks are held across no
//! await and no disk or network I/O.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::io;
use std::ops::{Deref, DerefMut};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use tokio::sync::watch;
use tracing::error;

use crate::error::{SmbError, SmbResult};

use super::cachedir::CacheDir;
use super::client::MAX_DELETE_KEYS;
use super::dirmove::{Batch, Left};
use super::entry::{Counted, Entry, Progress, Sealed, State};
use super::error::S3Error;
use super::keys::{Row, RowKind, Slot, dir_prefix, join_key, slot};
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

/// A note of whether the entries and keys to delete below a directory changed.
struct Watch {
    id: u64,
    /// The prefix of the keys below the directory.
    below: Slot,
    changed: bool,
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
    hidden: BTreeMap<Slot, Vec<String>>,
    /// The keys among `hidden` that the store holds as another object than
    /// the other spellings of their name. Such a key hides its own spelling
    /// only.
    apart: HashSet<String>,
    /// The entries that left a batch with a tombstone record standing for
    /// them, with the batch, until its record is rewritten without them.
    covered: HashMap<RecordId, Arc<Batch>>,
    /// The entries that copy from a key that is not their own, by the slot of
    /// the key: one for each key, several for a slot.
    sources: HashMap<Slot, Vec<Source>>,
    /// How many requests delete a key of each slot now.
    deleting: HashMap<Slot, usize>,
    /// The names a rename is about to take.
    reserved: HashSet<Slot>,
    /// The directories being renamed or deleted, by the slot of the prefix of
    /// the keys below them, and the directories they move to while the move is
    /// made. The rename holds the entries below the first. No entry is put,
    /// no name reserved and no key deleted below any of them meanwhile.
    moving: HashSet<Slot>,
    /// The directories among `moving` below which no entry is made for an
    /// object of the bucket either: the rename holds every entry below the
    /// one it moves, and is making its move.
    frozen: HashSet<Slot>,
    /// The directories whose listings are being made. Every change to
    /// `entries`, `hidden` or `apart` marks the watches of the directories
    /// above it.
    watches: Vec<Watch>,
    next_watch: u64,
    /// How many running jobs write a key of each slot.
    writing: HashMap<Slot, usize>,
    /// The entries that wait for a slot to clear.
    parked: HashMap<Slot, Vec<Arc<Entry>>>,
    /// The slots each entry in `parked` waits for, by the address of the
    /// entry: it wakes when any of them clears.
    parked_at: HashMap<usize, Vec<Slot>>,
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

/// The key of the other kind of object that has the name of `key`: the marker
/// of a directory for a file, and the file for a marker.
fn twin_key(key: &str) -> String {
    match key.strip_suffix('/') {
        Some(file) => file.to_owned(),
        None => dir_prefix(key),
    }
}

/// Whether the job of an entry with this state waits to start: it has
/// something to store, and nothing runs for it, holds it or has failed it.
fn waiting(state: &State) -> bool {
    state.has_work()
        && state.job.is_none()
        && state.failure.is_none()
        && !state.detached
        && !state.creating
        && state.batch.is_none()
}

/// How a job that is due stands with the keys it needs.
enum Blocked {
    No,
    /// The job resolves a cycle of entries that each wait for the next.
    Cycle,
    /// The job waits until any of these keys clears.
    Yes(Vec<String>),
}

impl Index {
    /// `key` as this index compares names.
    fn slot(&self, key: &str) -> Slot {
        slot(key, self.fold)
    }

    /// Whether `key` is to be deleted from the bucket, or a key of its slot
    /// that the store does not keep apart from `key`.
    fn hides(&self, key: &str) -> bool {
        self.hidden.get(&self.slot(key)).is_some_and(|keys| {
            keys.iter()
                .any(|held| held == key || !self.apart.contains(held))
        })
    }

    /// Whether a key other than `marker` itself is to be deleted below the
    /// directory marker `marker`, which ends in `/`.
    fn has_hidden_below(&self, marker: &str) -> bool {
        let name = self.slot(marker);
        self.hidden
            .range(name.clone()..)
            .take_while(|(held, _)| held.starts_with(&name))
            .any(|(held, _)| *held != name)
    }

    /// Whether the exact key `key` is to be deleted, whatever its case.
    fn hides_exact(&self, key: &str) -> bool {
        self.hidden
            .get(&self.slot(key))
            .is_some_and(|keys| keys.iter().any(|held| held == key))
    }

    /// The keys to delete that differ from `key` in case only and that the
    /// store is not known to hold as other objects than `key`. None while
    /// `key` is to be deleted itself.
    fn other_spellings(&self, key: &str) -> Vec<String> {
        if self.hides_exact(key) {
            return Vec::new();
        }
        self.hidden
            .get(&self.slot(key))
            .into_iter()
            .flatten()
            .filter(|held| !self.apart.contains(*held))
            .cloned()
            .collect()
    }

    /// Whether an entry is at the directory `key` or below it. A file at the
    /// name is not at the directory.
    fn has_entry_at_or_below(&self, key: &str) -> bool {
        if self
            .entries
            .get(&self.slot(key))
            .is_some_and(|entry| entry.is_dir())
        {
            return true;
        }
        let below = self.slot(&dir_prefix(key));
        self.entries
            .range(below.clone()..)
            .next()
            .is_some_and(|(held, _)| held.starts_with(&below))
    }

    /// Whether the directory `key` is gone: its marker key is to be deleted
    /// and no entry is at the directory or below it.
    fn dir_dead(&self, key: &str) -> bool {
        self.hides(&dir_prefix(key)) && !self.has_entry_at_or_below(key)
    }

    /// Whether a directory above the name `key` is gone.
    fn dead_above(&self, key: &str) -> bool {
        key.match_indices('/')
            .any(|(at, _)| self.dir_dead(&key[..at]))
    }

    /// Whether the name `key` is below one of the directories `dirs`, which
    /// are `moving` or `frozen`.
    fn below(&self, dirs: &HashSet<Slot>, key: &str) -> bool {
        let name = self.slot(key);
        dirs.iter().any(|prefix| name.starts_with(prefix))
    }

    /// Whether the key `key` is inside a directory that a rename or delete
    /// holds, and not the marker of the directory itself.
    fn fenced(&self, key: &str) -> bool {
        let name = self.slot(key);
        self.moving
            .iter()
            .any(|prefix| name.starts_with(prefix) && name != *prefix)
    }

    /// Whether `existing` are in the index under their keys, and no entry that
    /// does not move holds a name that an entry of `moves` moves to.
    fn moves_cleanly(&self, moves: &[Moved], existing: &[Arc<Entry>]) -> bool {
        let all_there = existing.iter().all(|entry| {
            let state = entry.state();
            !state.detached
                && self
                    .entries
                    .get(&self.slot(&state.key))
                    .is_some_and(|held| Arc::ptr_eq(held, entry))
        });
        if !all_there {
            return false;
        }
        let leaving: HashSet<*const Entry> = moves
            .iter()
            .filter(|moved| moved.from.is_some())
            .map(|moved| Arc::as_ptr(&moved.entry))
            .collect();
        moves.iter().all(|moved| {
            self.entries
                .get(&self.slot(&moved.to))
                .is_none_or(|held| leaving.contains(&Arc::as_ptr(held)))
        })
    }

    /// The entries below the directory whose key prefix has the slot `prefix`.
    fn entries_under(&self, prefix: &Slot) -> Vec<Arc<Entry>> {
        self.entries
            .range(prefix.clone()..)
            .take_while(|(slot, _)| slot.starts_with(prefix))
            .map(|(_, entry)| Arc::clone(entry))
            .collect()
    }

    /// How many entries are below the directory whose key prefix has the slot
    /// `prefix`, counted up to `limit + 1`.
    fn count_under(&self, prefix: &Slot, limit: usize) -> usize {
        self.entries
            .range(prefix.clone()..)
            .take_while(|(slot, _)| slot.starts_with(prefix))
            .take(limit.saturating_add(1))
            .count()
    }

    /// How many keys are to be deleted, owned or not.
    #[cfg(test)]
    fn hidden_keys(&self) -> usize {
        self.hidden.values().map(Vec::len).sum()
    }

    /// Marks the watches of the directories above the name `name`.
    fn touched(&mut self, name: &Slot) {
        for watch in &mut self.watches {
            if name != &watch.below && name.starts_with(&watch.below) {
                watch.changed = true;
            }
        }
    }

    /// Puts `entry` in the slot `name`, and returns the entry that was there.
    fn put_entry(&mut self, name: Slot, entry: Arc<Entry>) -> Option<Arc<Entry>> {
        self.touched(&name);
        self.entries.insert(name, entry)
    }

    /// Takes the entry out of the slot `name`.
    fn remove_entry(&mut self, name: &Slot) {
        if self.entries.remove(name).is_some() {
            self.touched(name);
        }
    }

    /// Notes that `key` is to be deleted, by an entry or as a key no entry
    /// owns.
    fn hide(&mut self, key: &str) {
        let name = self.slot(key);
        let keys = self.hidden.entry(name.clone()).or_default();
        if !keys.iter().any(|held| held == key) {
            keys.push(key.to_owned());
            self.touched(&name);
        }
    }

    /// Notes that `key` is to be deleted no more, unless something still
    /// names it.
    fn unhide(&mut self, key: &str) {
        if self.tombs.contains_key(key) || self.gone.contains_key(key) {
            return;
        }
        let name = self.slot(key);
        let mut changed = self.apart.remove(key);
        if let Some(keys) = self.hidden.get_mut(&name) {
            let before = keys.len();
            keys.retain(|held| held != key);
            changed |= keys.len() < before;
            if keys.is_empty() {
                self.hidden.remove(&name);
            }
        }
        if changed {
            self.touched(&name);
        }
    }

    /// Notes that the store holds the key to delete `key` as another object
    /// than the other spellings of its name, if it is still to be deleted.
    fn keep_apart(&mut self, key: &str) {
        if self.hides_exact(key) {
            self.apart.insert(key.to_owned());
            let name = self.slot(key);
            self.touched(&name);
        }
    }

    /// Whether an entry other than those in `except` holds `key`: a file at
    /// the key, or for a key that ends in `/` a directory with that marker.
    /// Locks the state of the entry at the slot unless it is in `except`.
    fn held(&self, key: &str, except: &[&Arc<Entry>]) -> bool {
        let name = key.strip_suffix('/').unwrap_or(key);
        self.entries.get(&self.slot(name)).is_some_and(|entry| {
            entry.is_dir() == (name.len() < key.len())
                && !except.iter().any(|other| Arc::ptr_eq(other, entry))
                && {
                    let state = entry.state();
                    !state.detached && state.is_write_key(key)
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
            self.remove_entry(&name);
        }
        self.cleared(key);
    }

    /// Takes `entry`, whose state is `state`, out of the overlay if nothing
    /// holds it, it has nothing to keep and no batch lists it. Returns whether
    /// it left.
    fn vacate_if_idle(&mut self, entry: &Arc<Entry>, state: &mut State) -> bool {
        if state.handles > 0 || state.pending() || state.detached || state.batch.is_some() {
            return false;
        }
        let key = state.key.clone();
        self.recount(entry, state, false);
        self.vacate(&key, entry);
        true
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
    /// until that ends. The writes of `owner` do not count. A directory
    /// marker is in use while a key below it is to be deleted: a store keeps
    /// the directory of an object, and refuses to delete one that is not
    /// empty. A key inside a directory that a rename or delete holds is in
    /// use until it lets go.
    fn in_use(&self, key: &str, owner: Option<&Arc<Entry>>) -> bool {
        let name = self.slot(key);
        self.written_by_other(&name, owner)
            || self.deleting.contains_key(&name)
            || !self.holders(&name, None).is_empty()
            || (key.ends_with('/') && self.has_hidden_below(key))
            || self.fenced(key)
    }

    /// Notes that no rename or delete holds the directory `dir` any more: the
    /// entries that wait for a key inside it wake, and the worker looks for
    /// keys to delete again.
    fn unfence(&mut self, dir: &Slot) {
        self.cleared = true;
        let waiting: Vec<Slot> = self
            .parked
            .keys()
            .filter(|name| name.starts_with(dir))
            .cloned()
            .collect();
        for name in waiting {
            self.wake_slot(&name);
        }
    }

    /// Whether the key `key` may be deleted now: nothing is in use in its
    /// slot, and no entry holds it.
    fn may_delete(&self, key: &str, owner: Option<&Arc<Entry>>) -> bool {
        !self.in_use(key, owner) && !self.held(key, &[])
    }

    /// Whether a job of `entry` may write `key`, or what it has to wait for.
    /// A request that deletes a key of its slot, a job that writes one, a key
    /// above it that is to be deleted, the object of the other kind that has
    /// its name, and an entry that copies from one stand in the way. A key
    /// above or the other object that is to be deleted becomes due at once,
    /// unless its delete comes only after the job of `entry` has ended: the
    /// write does not wait for it then, and the store takes it or refuses it.
    fn write_block(&mut self, key: &str, entry: &Arc<Entry>, now: Instant) -> Option<Block> {
        let (block, delete) = self.blocker(key, entry)?;
        if delete {
            self.expedite(&block.key, now);
        }
        Some(block)
    }

    /// What [`write_block`](Self::write_block) finds, with whether the key to
    /// wait for is one to be deleted, and no change to the index.
    fn blocker(&self, key: &str, entry: &Arc<Entry>) -> Option<(Block, bool)> {
        let name = self.slot(key);
        let plain = |key: &str| Block {
            key: key.to_owned(),
            source: None,
        };
        if self.deleting.contains_key(&name) || self.writing.contains_key(&name) {
            return Some((plain(key), false));
        }
        let waits = self.delete_waits(key);
        if let Some(wait) = waits.iter().find(|wait| !self.stuck_on(entry, wait)) {
            return Some((plain(wait), true));
        }
        let twin = twin_key(key);
        let twin_name = self.slot(&twin);
        if self.deleting.contains_key(&twin_name) || self.writing.contains_key(&twin_name) {
            return Some((plain(&twin), false));
        }
        let mut holders = self.holders(&name, Some(entry));
        let first = holders.pop()?;
        let block = Block {
            key: key.to_owned(),
            source: holders.is_empty().then_some(first),
        };
        Some((block, false))
    }

    /// The keys that are to be deleted and stand in the way of a write of
    /// `key`: those above it, then the object of the other kind that has its
    /// name, the marker of a directory for a file and the file for a marker. A
    /// store that keeps a directory as a folder refuses either while the other
    /// is there.
    fn delete_waits(&self, key: &str) -> Vec<String> {
        let mut waits: Vec<String> = key
            .match_indices('/')
            .map(|(at, _)| &key[..at])
            .filter(|above| self.delete_awaited(above))
            .map(str::to_owned)
            .collect();
        let twin = twin_key(key);
        if !waits.contains(&twin) && self.delete_awaited(&twin) {
            waits.push(twin);
        }
        waits
    }

    /// Whether `key` is to be deleted and something will still delete it. A
    /// write that waits for a key that [`stays`](Self::stays) goes ahead, and
    /// the store takes it or refuses it.
    fn delete_awaited(&self, key: &str) -> bool {
        self.hidden.get(&self.slot(key)).is_some_and(|keys| {
            keys.iter()
                .any(|held| (held == key || !self.apart.contains(held)) && !self.stays(held))
        })
    }

    /// Whether the key to delete `held` stays in the bucket: no delete is left
    /// to come for it, or for a key below it when it is a marker.
    fn stays(&self, held: &str) -> bool {
        let goes = |key: &str| {
            self.tombs
                .get(key)
                .is_some_and(|tomb| tomb.failure.is_none())
                || self.gone.get(key).is_some_and(|owners| {
                    owners.iter().any(|owner| owner.state().failure.is_none())
                })
        };
        if !goes(held) {
            return true;
        }
        if !held.ends_with('/') {
            return false;
        }
        let name = self.slot(held);
        self.hidden
            .range(name.clone()..)
            .take_while(|(below, _)| below.starts_with(&name))
            .any(|(_, keys)| keys.iter().any(|below| !goes(below)))
    }

    /// The entries whose jobs have to end before the key to delete `key`
    /// goes, as [`blockers_of`](Self::blockers_of) finds them for each key of
    /// its slot that is to be deleted.
    fn deleters(&self, key: &str) -> Vec<Arc<Entry>> {
        let mut found = Vec::new();
        for held in self.hidden.get(&self.slot(key)).into_iter().flatten() {
            if held == key || !self.apart.contains(held) {
                self.blockers_of(held, &mut found);
            }
        }
        found
    }

    /// Adds to `found` the entries that keep the key to delete `key` from
    /// going: the entries that own it, those that copy from it, and for a
    /// marker those that own a key to delete below it.
    fn blockers_of(&self, key: &str, found: &mut Vec<Arc<Entry>>) {
        let name = self.slot(key);
        found.extend(self.gone.get(key).into_iter().flatten().cloned());
        found.extend(self.holders(&name, None));
        if !key.ends_with('/') {
            return;
        }
        for (below, keys) in self
            .hidden
            .range(name.clone()..)
            .take_while(|(below, _)| below.starts_with(&name))
            .filter(|(below, _)| **below != name)
        {
            for held in keys {
                found.extend(self.gone.get(held).into_iter().flatten().cloned());
            }
            found.extend(self.holders(below, None));
        }
    }

    /// The entries that the job of `entry` waits for before it writes: those
    /// that copy from the key it writes and those that delete a key in its
    /// way. None for an entry whose job is not waiting to start, or that
    /// writes nothing.
    fn needs(&self, entry: &Arc<Entry>) -> Vec<Arc<Entry>> {
        let key = {
            let state = entry.state();
            if !waiting(&state) || !state.writes() {
                return Vec::new();
            }
            state.write_key()
        };
        let mut found = self.holders(&self.slot(&key), Some(entry));
        for wait in self.delete_waits(&key) {
            found.extend(self.deleters(&wait));
        }
        found.retain(|other| !Arc::ptr_eq(other, entry));
        found
    }

    /// The entries of `from`, those they wait for, and so on.
    fn reach(&self, from: Vec<Arc<Entry>>) -> Vec<Arc<Entry>> {
        let mut seen: HashSet<*const Entry> = HashSet::new();
        let mut reached = Vec::new();
        let mut pending = from;
        while let Some(next) = pending.pop() {
            if seen.insert(Arc::as_ptr(&next)) {
                pending.extend(self.needs(&next));
                reached.push(next);
            }
        }
        reached
    }

    /// Whether the delete of the key `wait` comes only after the job of
    /// `entry` has ended, so that waiting for it is waiting for itself.
    fn stuck_on(&self, entry: &Arc<Entry>, wait: &str) -> bool {
        self.reach(self.deleters(wait))
            .iter()
            .any(|reached| Arc::ptr_eq(reached, entry))
    }

    /// Wakes the entries that wait for a delete that comes only after their
    /// own jobs, when `entry`, which has to wait too, is among those it waits
    /// for: the waits close on themselves, and an entry that parked before the
    /// last of them began would not look again. Only an entry that has nothing
    /// else in its way is woken, so it starts and the waits do not close
    /// again. One that has another key in its way waits for that key.
    fn wake_stuck(&mut self, entry: &Arc<Entry>, now: Instant) {
        let reached = self.reach(self.needs(entry));
        if !reached.iter().any(|other| Arc::ptr_eq(other, entry)) {
            return;
        }
        for member in reached {
            if Arc::ptr_eq(&member, entry) {
                continue;
            }
            let (key, writes) = {
                let state = member.state();
                (state.write_key(), state.writes())
            };
            if !writes || !self.unpark(&member) {
                continue;
            }
            match self.write_block(&key, &member, now) {
                None => self.ready.push(member),
                Some(block) => self.park_on(&member, &[block.key]),
            }
        }
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

    /// The entry that holds the name of `key` under another spelling, when
    /// names ignore case, with the key of its object. A key that ends in `/`
    /// is the marker of a directory, and the entry is a directory.
    fn twin(&self, key: &str) -> Option<(String, Arc<Entry>)> {
        if !self.fold {
            return None;
        }
        let (name, marker) = match key.strip_suffix('/') {
            Some(name) => (name, true),
            None => (key, false),
        };
        let entry = self.entries.get(&self.slot(name))?;
        if entry.is_dir() != marker {
            return None;
        }
        let state = entry.state();
        (!state.detached && state.key != name).then(|| (state.write_key(), Arc::clone(entry)))
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

    /// Wakes the entries that wait for the slot of `key`, and those that wait
    /// to delete the marker of a directory above it.
    fn cleared(&mut self, key: &str) {
        self.cleared = true;
        self.wake(key);
        for (at, _) in key.match_indices('/') {
            if at + 1 < key.len() {
                self.wake(&key[..=at]);
            }
        }
    }

    /// Queues the entries that wait for the slot of `key`.
    fn wake(&mut self, key: &str) {
        let name = self.slot(key);
        self.wake_slot(&name);
    }

    /// Queues the entries that wait for the slot `name`.
    fn wake_slot(&mut self, name: &Slot) {
        for entry in self.parked.remove(name).unwrap_or_default() {
            self.unpark(&entry);
            self.ready.push(entry);
        }
    }

    /// Puts `entry` to wait until any of the slots of `keys` clears. The
    /// caller marks it as queued.
    fn park(&mut self, entry: &Arc<Entry>, keys: &[String]) {
        #[cfg(test)]
        {
            self.parks += 1;
        }
        self.park_on(entry, keys);
    }

    /// Puts `entry`, which is marked as queued, to wait until any of the slots
    /// of `keys` clears.
    fn park_on(&mut self, entry: &Arc<Entry>, keys: &[String]) {
        let mut names: Vec<Slot> = keys.iter().map(|key| self.slot(key)).collect();
        names.sort_unstable();
        names.dedup();
        for name in &names {
            self.parked
                .entry(name.clone())
                .or_default()
                .push(Arc::clone(entry));
        }
        self.parked_at.insert(Arc::as_ptr(entry) as usize, names);
    }

    /// Takes `entry` out of the entries that wait, and returns whether it was
    /// one.
    fn unpark(&mut self, entry: &Arc<Entry>) -> bool {
        let Some(names) = self.parked_at.remove(&(Arc::as_ptr(entry) as usize)) else {
            return false;
        };
        for name in names {
            if let Some(waiting) = self.parked.get_mut(&name) {
                waiting.retain(|held| !Arc::ptr_eq(held, entry));
                if waiting.is_empty() {
                    self.parked.remove(&name);
                }
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
    /// whose base has the least key resolves it. An entry that has to wait
    /// wakes the entries that wait for a delete that comes only after their
    /// own jobs, if its wait closes the chain.
    fn blocked(&mut self, entry: &Arc<Entry>, now: Instant) -> Blocked {
        let blocked = self.standing(entry, now);
        if matches!(blocked, Blocked::Yes(_)) {
            self.wake_stuck(entry, now);
        }
        blocked
    }

    /// [`blocked`](Self::blocked) without the wake of the entries that wait
    /// for their own jobs. An entry with nothing to write waits for all the
    /// keys it owns to delete, and may go once any of them is free.
    fn standing(&mut self, entry: &Arc<Entry>, now: Instant) -> Blocked {
        let (key, writes, gone, base, batch) = {
            let state = entry.state();
            (
                state.write_key(),
                state.writes(),
                state.gone.clone(),
                state.moved_from().map(str::to_owned),
                state.batch.clone(),
            )
        };
        if let Some(batch) = batch {
            return Blocked::Yes(vec![batch.key().to_owned()]);
        }
        if !writes {
            if gone.is_empty() || gone.iter().any(|key| !self.in_use(key, None)) {
                return Blocked::No;
            }
            return Blocked::Yes(gone);
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
                Blocked::Yes(vec![waits_for])
            }
            None => Blocked::Yes(vec![waits_for]),
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

/// How many rows [`Overlay::hidden`] checks with the index locked once.
const HIDDEN_CHUNK: usize = 1024;

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

/// The lock of the keys to delete, passed on by a caller that holds it, so
/// code it calls does not take it a second time.
pub(super) type TombsHeld<'a> = Option<&'a MutexGuard<'a, ()>>;

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

/// One entry a directory rename moves, and what its state becomes.
pub(super) struct Moved {
    pub(super) entry: Arc<Entry>,
    /// The key the entry has in the overlay now; `None` for an entry made for
    /// an object of the bucket.
    pub(super) from: Option<String>,
    pub(super) to: String,
    /// The keys the entry owns to delete once it has moved.
    pub(super) gone: Vec<String>,
    /// Whether `to` may exist in the bucket.
    pub(super) may_exist: bool,
    /// What the batch record seals of the local data.
    pub(super) sealed: Option<Sealed>,
    /// The key the batch record says the content is copied from.
    pub(super) source: Option<String>,
}

/// Holds on the entries below a directory that is being renamed or deleted, so
/// none leaves the overlay but by a change of its own. No entry is put, no name
/// reserved and no key deleted inside the directory while this lasts. After
/// [`freeze`](Self::freeze), no entry is made for an object of the bucket
/// below it, or below the directory it moves to, either.
pub(super) struct Subtree {
    overlay: Arc<Overlay>,
    prefix: Slot,
    /// The prefix of the directory it moves to, while that is fenced.
    target: Option<Slot>,
    held: Vec<Held>,
}

impl Subtree {
    pub(super) fn entries(&self) -> Vec<Arc<Entry>> {
        self.held
            .iter()
            .map(|held| Arc::clone(&held.entry))
            .collect()
    }

    /// Takes a hold on the entries below the directory that were made since
    /// the first hold, and fences the directory and `to`, the directory it
    /// moves to: no entry is made below either, so none can appear between the
    /// check of a move and the move itself.
    ///
    /// # Errors
    ///
    /// Fails with `Sharing` if `to` is, or is in, or has in it a directory
    /// that is being renamed, and with `AccessDenied` if more than `limit`
    /// entries of the overlay are below the directory.
    pub(super) fn freeze(&mut self, to: &str, limit: usize) -> SmbResult<()> {
        let mut index = self.overlay.lock();
        let target = index.slot(&dir_prefix(to));
        let own = target == self.prefix;
        let overlaps = index.moving.iter().any(|held| {
            *held != self.prefix && (held.starts_with(&target) || target.starts_with(held))
        });
        if overlaps {
            return Err(SmbError::Sharing);
        }
        if index.count_under(&self.prefix, limit) > limit {
            return Err(SmbError::AccessDenied);
        }
        if !own {
            index.moving.insert(target.clone());
            index.frozen.insert(target.clone());
            self.target = Some(target);
        }
        index.frozen.insert(self.prefix.clone());
        let mut known: HashSet<*const Entry> = self
            .held
            .iter()
            .map(|held| Arc::as_ptr(&held.entry))
            .collect();
        for entry in index.entries_under(&self.prefix) {
            if known.insert(Arc::as_ptr(&entry)) {
                entry.state().handles += 1;
                self.held.push(self.overlay.held(entry));
            }
        }
        Ok(())
    }

    /// Lifts the fences of [`freeze`](Self::freeze), so names below the
    /// directory can be looked up while it is listed again. The entries stay
    /// held.
    pub(super) fn thaw(&mut self) {
        let mut index = self.overlay.lock();
        index.frozen.remove(&self.prefix);
        if let Some(target) = self.target.take() {
            index.moving.remove(&target);
            index.frozen.remove(&target);
            index.unfence(&target);
        }
    }

    /// Whether a request deletes a key inside the directory. None starts
    /// while the directory is held.
    pub(super) fn deleting(&self) -> bool {
        self.overlay
            .lock()
            .deleting
            .keys()
            .any(|name| name.starts_with(&self.prefix) && *name != self.prefix)
    }
}

impl Drop for Subtree {
    fn drop(&mut self) {
        self.thaw();
        let mut index = self.overlay.lock();
        index.moving.remove(&self.prefix);
        index.unfence(&self.prefix);
    }
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

/// A note of the changes made to the entries and the keys to delete below a
/// directory since it was made.
pub(super) struct Watching<'a> {
    overlay: &'a Overlay,
    id: u64,
}

impl Watching<'_> {
    /// Whether an entry or a key to delete below the directory changed.
    pub(super) fn changed(&self) -> bool {
        self.overlay
            .lock()
            .watches
            .iter()
            .any(|watch| watch.id == self.id && watch.changed)
    }
}

impl Drop for Watching<'_> {
    fn drop(&mut self) {
        self.overlay
            .lock()
            .watches
            .retain(|watch| watch.id != self.id);
    }
}

/// The keys a request writes for an entry. They count as written until this
/// is dropped.
pub(super) struct Writes {
    overlay: Arc<Overlay>,
    entry: Arc<Entry>,
}

impl Drop for Writes {
    fn drop(&mut self) {
        self.overlay.end_writes(&self.entry);
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
            Blocked::Yes(keys) => {
                state.queued = true;
                drop(state);
                index.park(&entry, &keys);
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
    /// it is.
    ///
    /// # Errors
    ///
    /// Fails with `NotFound` if the lookup is out of date: a rename has
    /// reserved the name, or the object became a key to delete after the
    /// lookup, or it is a directory that is gone. Fails with `Sharing` if an
    /// entry would be made below a directory that is being renamed.
    pub(super) fn take_found(
        self: &Arc<Self>,
        found: Found,
        ahead: &Arc<ReadAhead>,
    ) -> SmbResult<Held> {
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
                return Ok(self.held(Arc::clone(entry)));
            }
        }
        if index.reserved.contains(&slot) || (!is_dir && index.hides(&key)) {
            return Err(SmbError::NotFound);
        }
        if (is_dir && index.dir_dead(&key)) || index.dead_above(&key) {
            return Err(SmbError::NotFound);
        }
        if index.below(&index.frozen, &key) {
            return Err(SmbError::Sharing);
        }
        if let Some(entry) = held {
            // What was a file is a directory, or the other way round. Handles
            // that stay open on it can change nothing.
            let mut state = entry.state();
            state.detached = state.handles > 0;
            index.recount(&entry, &mut state, false);
            drop(state);
            index.remove_entry(&slot);
        }
        let entry = Entry::found(found, ahead);
        entry.state().handles = 1;
        index.put_entry(slot, Arc::clone(&entry));
        Ok(self.held(entry))
    }

    /// Puts `entry` in the overlay with a hold on it. Looking and putting are
    /// one step, so two creates of one name never both succeed. A key to delete
    /// from the bucket may be there still, so the entry's key may exist.
    ///
    /// # Errors
    ///
    /// Fails with `Exists` if an entry for the name is there or a rename has
    /// reserved it, with `Sharing` below a directory that is being renamed,
    /// and with `PathNotFound` below a directory that is gone.
    pub(super) fn insert_new(self: &Arc<Self>, entry: Arc<Entry>) -> SmbResult<Held> {
        let key = entry.state().key.clone();
        let slot = self.slot(&key);
        let mut index = self.lock();
        if index.entries.contains_key(&slot) || index.reserved.contains(&slot) {
            return Err(SmbError::Exists);
        }
        if index.below(&index.moving, &key) {
            return Err(SmbError::Sharing);
        }
        if index.dead_above(&key) {
            return Err(SmbError::PathNotFound);
        }
        {
            let mut state = entry.state();
            state.handles = 1;
            state.may_exist |= index.hides(&state.key);
            self.schedule(&entry, &mut state);
        }
        index.put_entry(slot, Arc::clone(&entry));
        Ok(self.held(entry))
    }

    /// Ends one hold on `entry`, and queues the entry for a job if it has one
    /// to run. Every change to an entry holds it for its task, so the end of
    /// that hold is where a change reaches the queue. An entry of a batch
    /// stays until the batch is released.
    fn release(&self, entry: &Arc<Entry>) {
        let mut index = self.lock();
        let mut state = entry.state();
        state.handles = state.handles.saturating_sub(1);
        if !index.vacate_if_idle(entry, &mut state) {
            self.schedule(entry, &mut state);
        }
    }

    /// Takes `entry` out of the overlay if nothing holds it and it has nothing
    /// to keep. An entry loses its work without a job of its own when another
    /// entry takes a key to delete from it, and no release follows then.
    pub(super) fn leave_if_idle(&self, entry: &Arc<Entry>) {
        let mut index = self.lock();
        let mut state = entry.state();
        index.vacate_if_idle(entry, &mut state);
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

    /// Whether the overlay hides each of `rows`, the rows of the store in the
    /// directory `dir`: a file whose key is to be deleted, or a directory that
    /// is gone.
    pub(super) fn hidden(&self, dir: &str, rows: &[Row]) -> Vec<bool> {
        let marker = dir_prefix(dir);
        let mut hidden = Vec::with_capacity(rows.len());
        for chunk in rows.chunks(HIDDEN_CHUNK) {
            let index = self.lock();
            if index.has_hidden_below(&marker) {
                hidden.extend(chunk.iter().map(|row| {
                    let key = join_key(dir, &row.name);
                    match row.kind {
                        RowKind::File(_) => index.hides(&key),
                        RowKind::Dir => index.dir_dead(&key),
                    }
                }));
            } else {
                hidden.resize(hidden.len() + chunk.len(), false);
            }
        }
        hidden
    }

    /// Notes the changes made to the entries and the keys to delete below the
    /// directory `dir`, until the value returned is dropped.
    pub(super) fn watch(&self, dir: &str) -> Watching<'_> {
        let (below, _) = self.below_bounds(dir);
        let mut index = self.lock();
        let id = index.next_watch;
        index.next_watch += 1;
        index.watches.push(Watch {
            id,
            below,
            changed: false,
        });
        Watching { overlay: self, id }
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
            .range(prefix.clone()..)
            .take_while(|(name, _)| name.starts_with(&prefix))
            .map(|(_, keys)| keys.len())
            .sum()
    }

    /// Whether `key`, or another spelling of it when names ignore case, is to
    /// be deleted from the bucket. A key the store keeps apart from the other
    /// spellings of its name counts only for its own spelling.
    pub(super) fn tombstoned(&self, key: &str) -> bool {
        self.lock().hides(key)
    }

    /// Whether the exact key `key` is to be deleted from the bucket: other
    /// spellings of it do not count.
    pub(super) fn to_delete(&self, key: &str) -> bool {
        self.lock().hides_exact(key)
    }

    /// The keys to delete that differ from `key` in case only and that the
    /// store is not known to hold as other objects than `key`. None while
    /// `key` is to be deleted itself.
    pub(super) fn other_spellings(&self, key: &str) -> Vec<String> {
        self.lock().other_spellings(key)
    }

    /// Whether the directory `key` is gone: its marker key is to be deleted,
    /// and no entry is at the directory or below it.
    pub(super) fn dir_dead(&self, key: &str) -> bool {
        self.lock().dir_dead(key)
    }

    /// Whether a directory above the name `key` is gone.
    pub(super) fn dead_above(&self, key: &str) -> bool {
        self.lock().dead_above(key)
    }

    /// Takes a hold on every entry in the overlay below the directory `dir`,
    /// whether it holds something to keep or not, and makes the index refuse
    /// to put entries or reservations below the directory, and to start
    /// deleting keys inside it, until the value returned is dropped: a
    /// directory rename needs the entries it lists to stay, and the keys it
    /// lists to be there. Lookups still make entries for objects of the bucket
    /// there, until [`Subtree::freeze`].
    ///
    /// # Errors
    ///
    /// Fails with `Sharing` if the directory is, or is in, or has in it a
    /// directory that is being renamed.
    pub(super) fn hold_below(self: &Arc<Self>, dir: &str) -> SmbResult<Subtree> {
        let (prefix, _) = self.below_bounds(dir);
        let mut index = self.lock();
        if index
            .moving
            .iter()
            .any(|held| held.starts_with(&prefix) || prefix.starts_with(held))
        {
            return Err(SmbError::Sharing);
        }
        index.moving.insert(prefix.clone());
        let held = index
            .entries_under(&prefix)
            .into_iter()
            .map(|entry| {
                entry.state().handles += 1;
                self.held(entry)
            })
            .collect();
        Ok(Subtree {
            overlay: Arc::clone(self),
            prefix,
            target: None,
            held,
        })
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
            let taken = index.put_entry(slot, entry);
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
    /// `replaced` if that holds the name. No entry is made at a reserved
    /// name until the reservation ends.
    ///
    /// # Errors
    ///
    /// Fails with `Exists` if another entry holds the name or another rename
    /// has reserved it, with `Sharing` below a directory that is being
    /// renamed, and with `PathNotFound` below a directory that is gone.
    pub(super) fn reserve(
        &self,
        to: &str,
        entry: &Arc<Entry>,
        replaced: Option<&Arc<Entry>>,
    ) -> SmbResult<Reservation<'_>> {
        let mut index = self.lock();
        let name = index.slot(to);
        if index.below(&index.moving, to) {
            return Err(SmbError::Sharing);
        }
        if index.dead_above(to) {
            return Err(SmbError::PathNotFound);
        }
        if index.taken(to, entry, replaced) || !index.reserved.insert(name.clone()) {
            return Err(SmbError::Exists);
        }
        Ok(Reservation {
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
        let displaced = index.put_entry(self.slot(to), Arc::clone(entry));
        debug_assert!(
            displaced.is_none(),
            "an entry holds a name that a rename reserved"
        );
        drop(index);
        self.touch();
    }

    /// Whether the entries of a directory can be moved as `moves` says: those
    /// of `existing` are in the overlay under their keys, and no entry that
    /// stays holds a name that an entry moves to. The caller holds the `io` and
    /// `seal` locks of the entries, so the answer stands until the move is made
    /// if the names below the directories are fenced.
    pub(super) fn can_move_dir(&self, moves: &[Moved], existing: &[Arc<Entry>]) -> bool {
        self.lock().moves_cleanly(moves, existing)
    }

    /// Moves the entries of a directory to their new keys in one step, and
    /// notes that they wait for the batch `batch`. The caller has reserved the
    /// new name of the directory, and holds the `io` and `seal` locks of the
    /// entries that are in the overlay, which are `existing`. Returns `false`,
    /// having changed nothing, unless [`can_move_dir`](Self::can_move_dir)
    /// holds. The fence on the names below the directory keeps it from
    /// returning `false` once the batch record is written, and the check
    /// guards that case, since the record is already on disk.
    pub(super) fn moved_dir(
        &self,
        moves: &[Moved],
        batch: &Arc<Batch>,
        existing: &[Arc<Entry>],
    ) -> bool {
        let mut index = self.lock();
        if !index.moves_cleanly(moves, existing) {
            return false;
        }
        for moved in moves {
            if let Some(old) = &moved.from {
                index.vacate(old, &moved.entry);
            }
        }
        for moved in moves {
            {
                let mut state = moved.entry.state();
                state.key.clone_from(&moved.to);
                state.gone.clone_from(&moved.gone);
                state.may_exist = moved.may_exist;
                state.prior = None;
                state.bump();
                if let Some(sealed) = moved.sealed {
                    state.set_sealed(sealed);
                }
                state.recorded_source.clone_from(&moved.source);
                if state.is_dir() {
                    state.set_marker_pending(true);
                }
                state.batch = Some(Arc::clone(batch));
                index.recount(&moved.entry, &mut state, true);
                self.schedule(&moved.entry, &mut state);
            }
            index.put_entry(self.slot(&moved.to), Arc::clone(&moved.entry));
        }
        drop(index);
        self.touch();
        true
    }

    /// Ends the wait of `members` for the batch `batch`: the entries are on
    /// disk on their own, and wake. Those that have nothing to keep leave the
    /// overlay.
    pub(super) fn release_batch(&self, members: &[Arc<Entry>], batch: &Arc<Batch>) {
        let mut index = self.lock();
        for member in members {
            let mut state = member.state();
            if state.in_batch(batch) {
                state.batch = None;
                index.vacate_if_idle(member, &mut state);
            }
        }
        index.covered.retain(|_, held| !Arc::ptr_eq(held, batch));
        index.cleared(batch.key());
        drop(index);
        self.touch();
    }

    /// Notes that the records of the entries of `batch` could not be written:
    /// the entries that still wait for it, and have something to keep, fail,
    /// and the entries that wait for the batch wake. The others leave the
    /// batch, and the overlay once nothing holds them. Entries that another
    /// batch holds now are left as they are.
    pub(super) fn fail_batch(&self, members: &[Arc<Entry>], batch: &Arc<Batch>, failure: &S3Error) {
        let mut index = self.lock();
        for member in members {
            let mut state = member.state();
            if !state.in_batch(batch) || state.detached {
                continue;
            }
            if state.pending() {
                state.failure = Some(failure.clone());
                for key in &state.gone {
                    index.cleared(key);
                }
            } else {
                state.batch = None;
                index.vacate_if_idle(member, &mut state);
            }
        }
        index.cleared(batch.key());
        drop(index);
        self.touch();
    }

    /// Notes that the entry failed for good: it deletes none of the keys it
    /// owns, and the entries that wait for them look again. A call that waits
    /// for the entry is not told: the caller does that once the record of the
    /// failure is written.
    pub(super) fn failed(&self, entry: &Arc<Entry>, failure: S3Error) {
        let gone = {
            let mut state = entry.state();
            state.failure = Some(failure);
            state.gone.clone()
        };
        let mut index = self.lock();
        for key in &gone {
            index.cleared(key);
        }
    }

    /// Notes that the entry `id` left `batch` in memory only: a tombstone
    /// record stands for it, and the record of the batch is written without
    /// the entry before the tombstone record goes. Returns what puts the entry
    /// back.
    pub(super) fn left_batch(&self, batch: &Arc<Batch>, id: &RecordId) -> Option<Left> {
        let left = batch.cover(id)?;
        self.lock().covered.insert(id.clone(), Arc::clone(batch));
        Some(left)
    }

    /// Puts an entry back in the batch it left, as it was.
    ///
    /// # Errors
    ///
    /// Fails when the record of the batch cannot be written with the entry. It
    /// is a member in memory all the same.
    pub(super) fn rejoin_batch(&self, cache: &CacheDir, left: Left) -> io::Result<()> {
        self.lock().covered.remove(left.id());
        Batch::rejoin(left, cache)
    }

    /// Writes the batch records that have a tombstone record of `ids` to stand
    /// for entries that left them, without those entries.
    fn flush_batches(&self, cache: &CacheDir, ids: &[&RecordId]) -> io::Result<()> {
        let mut batches: Vec<Arc<Batch>> = Vec::new();
        {
            let index = self.lock();
            for id in ids {
                if let Some(batch) = index.covered.get(*id)
                    && !batches.iter().any(|held| Arc::ptr_eq(held, batch))
                {
                    batches.push(Arc::clone(batch));
                }
            }
        }
        for batch in &batches {
            batch.flush(cache)?;
        }
        if !batches.is_empty() {
            self.lock()
                .covered
                .retain(|_, held| !batches.iter().any(|batch| Arc::ptr_eq(batch, held)));
        }
        Ok(())
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
        self.begin(entry, key, stop, false)
    }

    /// [`begin_write`](Self::begin_write) for the open that makes a directory
    /// and puts its marker object: only a request in flight for a key of the
    /// slot stands in the way. A file of the name of the directory that is to
    /// be deleted does not: see [`marker_deferred`](Self::marker_deferred). The
    /// key stays noted until the value returned is dropped.
    pub(super) fn begin_marker_write(
        self: &Arc<Self>,
        entry: &Arc<Entry>,
        key: &str,
        stop: &Stop,
    ) -> Result<Writes, Fence> {
        self.begin(entry, key, stop, true)?;
        Ok(Writes {
            overlay: Arc::clone(self),
            entry: Arc::clone(entry),
        })
    }

    fn begin(
        &self,
        entry: &Arc<Entry>,
        key: &str,
        stop: &Stop,
        requests_only: bool,
    ) -> Result<(), Fence> {
        let mut index = self.lock();
        {
            let state = entry.state();
            if state.detached {
                return Err(Fence::Gone);
            }
            if !state.is_write_key(key) || stop.is_stopped() {
                return Err(Fence::Stopped);
            }
        }
        let name = index.slot(key);
        let blocked = if requests_only {
            index.deleting.contains_key(&name) || index.writing.contains_key(&name)
        } else {
            index.write_block(key, entry, Instant::now()).is_some()
        };
        if blocked {
            return Err(Fence::Blocked);
        }
        add(&mut index.writing, name);
        entry.state().writing.push(key.to_owned());
        Ok(())
    }

    /// Whether the open that makes the directory with the marker `key` leaves
    /// the marker to the job of the directory, because a key above it is to be
    /// deleted: a store that keeps a directory as a folder refuses the marker
    /// while an object of that name is there. The job puts the marker once
    /// the object is gone, as it does for a renamed directory.
    pub(super) fn marker_deferred(&self, key: &str) -> bool {
        let index = self.lock();
        key.match_indices('/')
            .any(|(at, _)| index.delete_awaited(&key[..at]))
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

    /// Notes that the store holds the key to delete `key` as another object
    /// than the other spellings of its name, so it hides its own spelling
    /// only.
    pub(super) fn keep_apart(&self, key: &str) {
        self.lock().keep_apart(key);
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
        let tombs = self.lock_tombs();
        self.drop_tombs_held(&tombs, cache, keys)
    }

    /// [`drop_tombs`](Self::drop_tombs) for a caller that holds the lock of
    /// [`lock_tombs`](Self::lock_tombs), which it passes as `tombs`.
    pub(super) fn drop_tombs_held(
        &self,
        _tombs: &MutexGuard<'_, ()>,
        cache: &CacheDir,
        keys: &[String],
    ) -> io::Result<()> {
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
        let removed: Vec<&RecordId> = rewrites
            .iter()
            .filter(|(_, left)| left.is_empty())
            .map(|(id, _)| id)
            .collect();
        self.flush_batches(cache, &removed)?;
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

    /// How many directories are being watched.
    #[cfg(test)]
    pub(super) fn watching(&self) -> usize {
        self.lock().watches.len()
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

    /// How many entries wait for the slot of `key` to clear.
    #[cfg(test)]
    pub(super) fn waiting_for(&self, key: &str) -> usize {
        let index = self.lock();
        index
            .parked
            .get(&index.slot(key))
            .map_or(0, std::vec::Vec::len)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::s3::cachedir::{CacheDir, RecordOp};
    use crate::s3::data::DataFile;
    use crate::s3::entry::State;
    use crate::s3::lookup::DirRef;
    use crate::s3::record::{BatchRecord, RecordId};
    use crate::tests::util::scratch_dir;

    /// A bound on the entries below a directory that no test reaches.
    const NO_LIMIT: usize = usize::MAX;

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
        overlay
            .insert_new(Entry::created_file(
                key.to_owned(),
                id,
                1,
                DataFile::absent(),
            ))
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
        assert!(first.is_ok());
        assert!(overlay.insert_new(plain("a")).is_err());
        let upper = overlay.insert_new(plain("A"));
        assert!(upper.is_ok());
        assert_eq!(overlay.len(), 2);
    }

    #[test]
    fn names_that_differ_in_case_are_one_name_when_case_is_ignored() {
        let overlay = test_overlay(true);
        let held = overlay.insert_new(kept("Dir/File.TXT")).unwrap();
        assert!(overlay.insert_new(plain("dir/file.txt")).is_err());
        let found = overlay.take_pending("DIR/FILE.txt").unwrap();
        assert!(Arc::ptr_eq(&found.entry, &held.entry));
        assert_eq!(found.entry.state().key, "Dir/File.TXT");
        assert!(overlay.take_pending("dir/other").is_none());
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
    fn implicit_directories_that_differ_in_case_count_once() {
        let overlay = test_overlay(true);
        overlay.install(vec![kept("p/Sub/a"), kept("p/sub/b")], Vec::new());
        let below = overlay.below("p");
        assert_eq!(below.implied.len(), 1);
    }

    fn row(name: &str, is_dir: bool) -> Row {
        let kind = if is_dir {
            RowKind::Dir
        } else {
            RowKind::File(crate::s3::keys::FileStamp {
                size: 1,
                etag: String::new(),
                last_modified: std::time::SystemTime::UNIX_EPOCH,
            })
        };
        Row {
            name: name.to_owned(),
            kind,
        }
    }

    #[test]
    fn a_row_is_hidden_when_its_key_is_to_be_deleted_or_its_directory_is_gone() {
        let overlay = test_overlay(true);
        overlay.install(
            vec![kept("p/a")],
            vec![tombstone(&["P/X.txt", "p/d/", "q/y.txt"])],
        );
        let rows = [
            row("x.txt", false),
            row("y.txt", false),
            row("d", true),
            row("e", true),
        ];
        assert_eq!(overlay.hidden("p", &rows), [true, false, true, false]);
        assert_eq!(overlay.hidden("r", &rows), [false; 4]);
    }

    #[test]
    fn rows_beyond_one_chunk_are_each_checked() {
        let overlay = test_overlay(false);
        let gone = [0, HIDDEN_CHUNK - 1, HIDDEN_CHUNK, 3 * HIDDEN_CHUNK - 1];
        let keys: Vec<String> = gone.iter().map(|n| format!("p/f{n:05}")).collect();
        let keys: Vec<&str> = keys.iter().map(String::as_str).collect();
        overlay.install(Vec::new(), vec![tombstone(&keys)]);
        let rows: Vec<Row> = (0..3 * HIDDEN_CHUNK)
            .map(|n| row(&format!("f{n:05}"), false))
            .collect();
        let hidden = overlay.hidden("p", &rows);
        let at: Vec<usize> = (0..hidden.len()).filter(|n| hidden[*n]).collect();
        assert_eq!(at, gone);
    }

    /// Whether a watch of `dir` noted `change`.
    fn marked(overlay: &Overlay, dir: &str, change: impl FnOnce()) -> bool {
        let watch = overlay.watch(dir);
        change();
        watch.changed()
    }

    #[test]
    fn a_watch_notes_an_entry_put_or_taken_out_below_its_directory() {
        let overlay = test_overlay(true);
        let mut held = Vec::new();
        assert!(marked(&overlay, "p", || held
            .push(overlay.insert_new(kept("p/a")).unwrap())));
        assert!(marked(&overlay, "P", || held
            .push(overlay.insert_new(kept("p/Sub/b")).unwrap())));
        assert!(marked(&overlay, "p/sub", || held
            .push(overlay.insert_new(kept("p/sub/c")).unwrap())));
        let entry = Arc::clone(&held[0].entry);
        assert!(marked(&overlay, "p", || overlay.evict(&entry)));
        assert_eq!(overlay.watching(), 0);
    }

    #[test]
    fn a_watch_notes_the_old_and_the_new_name_of_an_entry_that_moves() {
        let overlay = test_overlay(false);
        let held = overlay.insert_new(kept("p/a")).unwrap();
        let (from, to, other) = (overlay.watch("p"), overlay.watch("q"), overlay.watch("r"));
        overlay.renamed(&held.entry, "q/b", |_| {}, None);
        assert!(from.changed() && to.changed());
        assert!(!other.changed());
    }

    #[test]
    fn a_watch_does_not_note_changes_elsewhere() {
        let overlay = test_overlay(false);
        let watch = overlay.watch("p/sub");
        let held = [
            overlay.insert_new(kept("p/a")).unwrap(),
            overlay.insert_new(kept("q/sub/a")).unwrap(),
            overlay.insert_new(kept("p/subs/a")).unwrap(),
            overlay.insert_new(kept("p/sub")).unwrap(),
        ];
        overlay.install(Vec::new(), vec![tombstone(&["p/sub/", "p/other"])]);
        overlay.lock().remove_tomb("p/sub/");
        assert!(!watch.changed());
        drop(held);
        let held = overlay.insert_new(kept("p/sub/a")).unwrap();
        assert!(watch.changed());
        drop(held);
    }

    #[test]
    fn a_watch_notes_a_key_to_delete_that_is_added_or_taken_off() {
        let overlay = test_overlay(true);
        assert!(marked(&overlay, "p", || {
            overlay.install(Vec::new(), vec![tombstone(&["p/X"])]);
        }));
        assert!(marked(&overlay, "p", || overlay.keep_apart("p/X")));
        assert!(marked(&overlay, "p", || {
            overlay.lock().remove_tomb("p/X");
        }));
        assert!(!marked(&overlay, "p", || {
            overlay.lock().remove_tomb("p/X");
        }));
        assert!(!marked(&overlay, "p", || overlay.keep_apart("p/X")));
    }

    #[test]
    fn a_dropped_watch_is_not_kept() {
        let overlay = test_overlay(false);
        let first = overlay.watch("p");
        let second = overlay.watch("p");
        assert_eq!(overlay.watching(), 2);
        drop(first);
        overlay.install(vec![kept("p/a")], Vec::new());
        assert!(second.changed());
        assert_eq!(overlay.watching(), 1);
        drop(second);
        assert_eq!(overlay.watching(), 0);
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
    fn a_key_to_delete_the_store_keeps_apart_hides_its_own_spelling_only() {
        let overlay = test_overlay(true);
        overlay.install(Vec::new(), vec![tombstone(&["F/", "G/"])]);
        overlay.keep_apart("F/");
        assert!(overlay.tombstoned("F/"));
        assert!(!overlay.tombstoned("f/"));
        assert!(overlay.dir_dead("F"));
        assert!(!overlay.dir_dead("f"));
        assert!(overlay.tombstoned("g/"), "G/ is not kept apart");
    }

    #[test]
    fn the_other_spellings_of_a_key_are_the_keys_to_delete_the_store_may_hold_as_it() {
        let spellings = |overlay: &Overlay, key: &str| {
            let mut found = overlay.other_spellings(key);
            found.sort();
            found
        };
        let overlay = test_overlay(true);
        overlay.install(Vec::new(), vec![tombstone(&["Doc", "DOC", "x/F/", "y"])]);
        assert_eq!(spellings(&overlay, "doc"), ["DOC", "Doc"]);
        assert_eq!(spellings(&overlay, "x/f/"), ["x/F/"]);
        assert!(spellings(&overlay, "Doc").is_empty(), "it is to be deleted");
        assert!(spellings(&overlay, "y").is_empty());
        assert!(spellings(&overlay, "other").is_empty());

        overlay.keep_apart("DOC");
        assert_eq!(spellings(&overlay, "doc"), ["Doc"]);

        let exact = test_overlay(false);
        exact.install(Vec::new(), vec![tombstone(&["Doc"])]);
        assert!(spellings(&exact, "doc").is_empty());
    }

    #[test]
    fn a_key_is_kept_apart_only_while_it_is_to_be_deleted() {
        let dir = scratch_dir();
        let cache = CacheDir::open(&dir.path().join("c"), "identity").unwrap();
        let overlay = test_overlay(true);
        overlay.keep_apart("F");
        let id = RecordId::parse(&"d".repeat(32)).unwrap();
        overlay.unlinked(&kept("F"), &["F".to_owned()], &id);
        assert!(overlay.tombstoned("f"), "it was not kept apart before");

        overlay.keep_apart("F");
        assert!(!overlay.tombstoned("f"));
        let record = TombstoneRecord {
            id: id.clone(),
            keys: vec!["F".to_owned()],
        };
        cache.write_record(&id, &record.encode()).unwrap();
        overlay.drop_tombs(&cache, &["F".to_owned()]).unwrap();
        overlay.unlinked(&kept("F"), &["F".to_owned()], &id);
        assert!(overlay.tombstoned("f"), "it is not kept apart any more");
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
        assert!(overlay.take_found(found_file("t"), &ahead).is_err());
        assert_eq!(overlay.len(), 1);
        drop(reservation);
        let held = overlay.take_found(found_file("t"), &ahead).unwrap();
        assert_eq!(overlay.len(), 2);
        drop(held);

        let id = RecordId::parse(&"c".repeat(32)).unwrap();
        overlay.unlinked(&kept("u"), &["u".to_owned()], &id);
        assert!(overlay.take_found(found_file("U"), &ahead).is_err());
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
                file: Arc::new(DataFile::absent()),
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
            file: Arc::new(DataFile::absent()),
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
        let dir = scratch_dir();
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
    fn a_file_waits_for_the_marker_of_its_name_and_the_marker_is_deleted_at_once() {
        let overlay = test_overlay(false);
        let id = RecordId::parse(&"f".repeat(32)).unwrap();
        let start = Instant::now();
        overlay.unlinked(&dir("d"), &["d/".to_owned()], &id);
        overlay.unlinked(&kept("other"), &["other".to_owned()], &id);
        let file = kept("d");
        file.state().set_local(local_data(0, 0));
        let _held = overlay.insert_new(Arc::clone(&file)).unwrap();
        assert!(claimed(&overlay, start).is_empty());
        assert!(overlay.begin_write(&file, "d", &Stop::new()).is_err());
        assert!(!claimable(&overlay, &file));
        assert_eq!(overlay.waiting_for("d/"), 1);
        assert_eq!(
            claimed(&overlay, Instant::now()),
            ["d/"],
            "only the marker in the way"
        );
    }

    #[test]
    fn a_file_waits_while_the_marker_of_its_name_is_to_be_deleted_or_is_being_deleted() {
        let overlay = test_overlay(false);
        let owner = moved("b", "x", &["d/"]);
        let _owner = overlay.insert_new(Arc::clone(&owner)).unwrap();
        overlay.track(&owner);
        let file = kept("d");
        file.state().set_local(local_data(0, 0));
        let _file = overlay.insert_new(Arc::clone(&file)).unwrap();
        assert!(!claimable(&overlay, &file), "an entry is to delete it");
        let claim = overlay.claim_gone(&["d/".to_owned()], &owner);
        assert_eq!(claim.claimed.keys(), ["d/"]);
        assert!(!claimable(&overlay, &file), "a request deletes it");
        drop(claim);
        assert!(!claimable(&overlay, &file), "it is still to be deleted");
        owner.state().gone.clear();
        overlay.track(&owner);
        assert!(claimable(&overlay, &file));
    }

    #[test]
    fn a_file_does_not_wait_for_a_marker_the_store_refused_to_delete() {
        let overlay = test_overlay(false);
        let id = RecordId::parse(&"f".repeat(32)).unwrap();
        overlay.unlinked(&dir("d"), &["d/".to_owned()], &id);
        let file = kept("d");
        file.state().set_local(local_data(0, 0));
        let _held = overlay.insert_new(Arc::clone(&file)).unwrap();
        assert!(overlay.begin_write(&file, "d", &Stop::new()).is_err());
        overlay.finish_tombs(&[("d/".to_owned(), S3Error::InvalidResponse("refused"))]);
        assert!(overlay.begin_write(&file, "d", &Stop::new()).is_ok());
    }

    #[test]
    fn a_marker_waits_for_the_file_of_its_name_and_the_file_is_deleted_at_once() {
        let overlay = test_overlay(false);
        let id = RecordId::parse(&"f".repeat(32)).unwrap();
        overlay.unlinked(&kept("d"), &["d".to_owned()], &id);
        let directory = dir("d");
        let _held = overlay.insert_new(Arc::clone(&directory)).unwrap();
        assert!(overlay.begin_write(&directory, "d/", &Stop::new()).is_err());
        assert_eq!(claimed(&overlay, Instant::now()), ["d"]);
    }

    #[test]
    fn a_marker_is_left_to_the_job_of_its_directory_while_a_key_above_it_is_to_be_deleted() {
        let overlay = test_overlay(false);
        let id = RecordId::parse(&"f".repeat(32)).unwrap();
        overlay.unlinked(&kept("d"), &["d".to_owned()], &id);
        assert!(overlay.marker_deferred("d/"));
        assert!(overlay.marker_deferred("d/sub/"));
        assert!(!overlay.marker_deferred("other/"));
        assert!(!overlay.marker_deferred("dd/"));
        overlay.finish_tombs(&[("d".to_owned(), S3Error::InvalidResponse("refused"))]);
        assert!(
            !overlay.marker_deferred("d/"),
            "the store refused the delete"
        );
    }

    /// Whether the job of `entry` may start now. The entry is as it was
    /// before, unless the job had to wait.
    fn starts(overlay: &Arc<Overlay>, entry: &Arc<Entry>) -> bool {
        let later = Instant::now() + Duration::from_secs(60);
        let started = matches!(overlay.claim(Arc::clone(entry), later), Claim::Run(..));
        entry.state().job = None;
        started
    }

    /// A directory that is not being made any more, with the marker to put.
    fn marked_dir(key: &str, gone: &[&str]) -> Arc<Entry> {
        let directory = dir(key);
        {
            let mut state = directory.state();
            state.creating = false;
            state.gone = gone.iter().map(|key| (*key).to_owned()).collect();
        }
        directory
    }

    /// Takes the entries that are queued for a job off the queue, so what the
    /// queue holds later is what a change woke.
    fn drain(overlay: &Arc<Overlay>) {
        while woken(overlay).is_some() {}
    }

    /// The entry the worker takes off the queue.
    fn woken(overlay: &Arc<Overlay>) -> Option<Arc<Entry>> {
        overlay
            .queue()
            .pop_due(Instant::now() + Duration::from_secs(60))
    }

    #[test]
    fn a_file_taking_the_name_of_its_directory_does_not_wait_for_the_directory() {
        let overlay = test_overlay(false);
        let id = RecordId::parse(&"f".repeat(32)).unwrap();
        let start = Instant::now();
        // `d/x` was moved to `tmp` and `d` deleted, and `tmp` moved to `d`: the
        // file deletes `d/x` once it is stored, and `d/` goes after that.
        overlay.unlinked(&dir("d"), &["d/".to_owned()], &id);
        let file = moved("d", "d/x", &["d/x"]);
        let _held = overlay.insert_new(Arc::clone(&file)).unwrap();
        overlay.track(&file);
        assert!(starts(&overlay, &file), "the file does not wait for itself");
        assert_eq!(overlay.waiting_for("d/"), 0);

        file.state().gone.clear();
        overlay.track(&file);
        assert_eq!(
            claimed(&overlay, start + Duration::from_secs(6)),
            ["d/"],
            "the marker goes once the file it held up is stored"
        );
    }

    #[test]
    fn a_file_and_a_directory_that_swap_names_do_not_wait_for_each_other() {
        let overlay = test_overlay(false);
        // The file at `d` went to `x`, and the directory at `x` to `d`.
        let file = moved("x", "d", &["d"]);
        let directory = marked_dir("d", &["x/"]);
        let _file = overlay.insert_new(Arc::clone(&file)).unwrap();
        let _directory = overlay.insert_new(Arc::clone(&directory)).unwrap();
        overlay.track(&file);
        overlay.track(&directory);
        assert!(starts(&overlay, &file));
        assert!(starts(&overlay, &directory));
        assert_eq!(overlay.waiting_for("x/") + overlay.waiting_for("d"), 0);
    }

    #[test]
    fn a_file_wrapped_in_a_directory_of_its_name_does_not_wait_for_itself() {
        let overlay = test_overlay(false);
        // The file at `d` went to `d/d`, and a directory was made at `d`.
        let file = moved("d/d", "d", &["d"]);
        let directory = marked_dir("d", &[]);
        let _file = overlay.insert_new(Arc::clone(&file)).unwrap();
        let _directory = overlay.insert_new(Arc::clone(&directory)).unwrap();
        overlay.track(&file);
        overlay.track(&directory);
        drain(&overlay);
        assert!(!starts(&overlay, &directory), "it waits for the file's job");
        assert_eq!(overlay.waiting_for("d"), 1);
        assert!(starts(&overlay, &file), "the file waits for no other job");

        file.state().gone.clear();
        overlay.track(&file);
        let next = woken(&overlay).expect("the directory looks again");
        assert!(Arc::ptr_eq(&next, &directory));
        assert!(starts(&overlay, &next));
    }

    #[test]
    fn a_file_waits_for_a_directory_whose_marker_goes_after_a_job_that_waits_for_nothing() {
        let overlay = test_overlay(false);
        let file = kept("x");
        file.state().set_local(local_data(0, 0));
        let directory = marked_dir("d", &["x/"]);
        let _file = overlay.insert_new(Arc::clone(&file)).unwrap();
        let _directory = overlay.insert_new(Arc::clone(&directory)).unwrap();
        overlay.track(&directory);
        drain(&overlay);
        assert!(!starts(&overlay, &file));
        assert_eq!(overlay.waiting_for("x/"), 1);
        assert!(starts(&overlay, &directory));

        directory.state().gone.clear();
        overlay.track(&directory);
        let next = woken(&overlay).expect("the key cleared");
        assert!(Arc::ptr_eq(&next, &file));
        assert!(starts(&overlay, &next));
    }

    #[test]
    fn an_entry_that_parked_for_a_delete_looks_again_when_a_later_wait_closes_the_chain() {
        let overlay = test_overlay(false);
        // `g` has to be stored before `x`, which copies from it, and deletes
        // `x/`, which `x` waits for.
        let owner = kept("g");
        owner.state().set_local(local_data(0, 0));
        owner.state().gone = vec!["x/".to_owned()];
        let file = moved("x", "g", &[]);
        let _owner = overlay.insert_new(Arc::clone(&owner)).unwrap();
        let _file = overlay.insert_new(Arc::clone(&file)).unwrap();
        overlay.track(&owner);
        overlay.track(&file);
        drain(&overlay);
        owner.state().job = Some(Stop::new());
        assert!(!starts(&overlay, &file), "the job of the owner is running");
        assert_eq!(overlay.waiting_for("x/"), 1);
        owner.state().job = None;
        assert!(!starts(&overlay, &owner), "the file copies from its key");
        let next = woken(&overlay).expect("the file looks again");
        assert!(Arc::ptr_eq(&next, &file));
        assert!(starts(&overlay, &next), "the file does not wait for itself");
    }

    #[test]
    fn an_entry_parked_for_a_delete_waits_for_a_copy_in_its_way_when_the_chain_closes() {
        let overlay = test_overlay(false);
        // As in the test above, and `y` copies from `x` too.
        let owner = kept("g");
        owner.state().set_local(local_data(0, 0));
        owner.state().gone = vec!["x/".to_owned()];
        let file = moved("x", "g", &[]);
        let copier = moved("y", "x", &[]);
        let _owner = overlay.insert_new(Arc::clone(&owner)).unwrap();
        let _file = overlay.insert_new(Arc::clone(&file)).unwrap();
        let _copier = overlay.insert_new(Arc::clone(&copier)).unwrap();
        for entry in [&owner, &file, &copier] {
            overlay.track(entry);
        }
        drain(&overlay);
        owner.state().job = Some(Stop::new());
        assert!(!starts(&overlay, &file), "the job of the owner is running");
        assert_eq!(overlay.waiting_for("x/"), 1);
        owner.state().job = None;
        assert!(!starts(&overlay, &owner), "the file copies from its key");
        assert!(woken(&overlay).is_none(), "the copy of x is in its way");
        assert_eq!(overlay.waiting_for("x"), 1);

        copier.state().base = None;
        overlay.track(&copier);
        let next = woken(&overlay).expect("the copy of x ended");
        assert!(Arc::ptr_eq(&next, &file));
        assert!(starts(&overlay, &next), "the file does not wait for itself");
    }

    #[test]
    fn a_file_does_not_wait_for_a_delete_that_waits_for_a_job_that_copies_from_its_key() {
        let overlay = test_overlay(false);
        let id = RecordId::parse(&"f".repeat(32)).unwrap();
        // `d/x` waits for `d` to go, which waits for `e` to copy from it, which
        // waits for the marker `e/`, which `d/x` is to delete.
        overlay.unlinked(&plain("p"), &["d".to_owned()], &id);
        let copier = moved("e", "d", &[]);
        let file = kept("d/x");
        file.state().set_local(local_data(0, 0));
        file.state().gone = vec!["e/".to_owned()];
        let _copier = overlay.insert_new(Arc::clone(&copier)).unwrap();
        let _file = overlay.insert_new(Arc::clone(&file)).unwrap();
        overlay.track(&copier);
        overlay.track(&file);
        drain(&overlay);
        assert!(starts(&overlay, &file));
        assert_eq!(overlay.waiting_for("d"), 0);
    }

    #[test]
    fn a_file_does_not_wait_for_a_marker_that_waits_for_a_job_that_copies_from_a_key_below_it() {
        let overlay = test_overlay(false);
        let id = RecordId::parse(&"f".repeat(32)).unwrap();
        // `d` waits for `d/` to go, which waits for `e` to copy from `d/f`,
        // which waits for the marker `e/`, which `d` is to delete.
        overlay.unlinked(&plain("p"), &["d/".to_owned(), "d/f".to_owned()], &id);
        let copier = moved("e", "d/f", &[]);
        let file = kept("d");
        file.state().set_local(local_data(0, 0));
        file.state().gone = vec!["e/".to_owned()];
        let _copier = overlay.insert_new(Arc::clone(&copier)).unwrap();
        let _file = overlay.insert_new(Arc::clone(&file)).unwrap();
        overlay.track(&copier);
        overlay.track(&file);
        drain(&overlay);
        assert!(starts(&overlay, &file));
        assert_eq!(overlay.waiting_for("d/"), 0);
    }

    #[test]
    fn a_file_does_not_wait_for_a_marker_that_waits_for_a_job_that_owns_a_key_below_it() {
        let overlay = test_overlay(false);
        let id = RecordId::parse(&"f".repeat(32)).unwrap();
        // `d` waits for `d/` to go, which waits for the job of `e` to delete
        // `d/f`, which comes after it stores `e`, which `d` copies from.
        overlay.unlinked(&plain("p"), &["d/".to_owned()], &id);
        let owner = kept("e");
        owner.state().set_local(local_data(0, 0));
        owner.state().gone = vec!["d/f".to_owned()];
        let file = moved("d", "e", &[]);
        let _owner = overlay.insert_new(Arc::clone(&owner)).unwrap();
        let _file = overlay.insert_new(Arc::clone(&file)).unwrap();
        overlay.track(&owner);
        overlay.track(&file);
        drain(&overlay);
        assert!(starts(&overlay, &file));
        assert_eq!(overlay.waiting_for("d/"), 0);
    }

    /// A directory whose marker is in the bucket, which is to delete `gone`.
    fn deleting_dir(key: &str, gone: &[&str]) -> Arc<Entry> {
        let directory = marked_dir(key, gone);
        {
            let mut state = directory.state();
            state.own = None;
            state.set_marker_pending(false);
        }
        directory
    }

    /// An entry with nothing to write that is to delete the markers `c/` and
    /// `b/`, below each of which a key is to be deleted, and waits for them.
    fn waiting_to_delete_two_markers(overlay: &Arc<Overlay>, below_b: &str) -> (Arc<Entry>, Held) {
        let id = RecordId::parse(&"f".repeat(32)).unwrap();
        overlay.unlinked(&plain("p"), &[below_b.to_owned()], &id);
        overlay.unlinked(&plain("r"), &["c/x".to_owned()], &id);
        let owner = deleting_dir("a", &["c/", "b/"]);
        let held = overlay.insert_new(Arc::clone(&owner)).unwrap();
        overlay.track(&owner);
        drain(overlay);
        assert!(!starts(overlay, &owner));
        (owner, held)
    }

    #[test]
    fn an_entry_waiting_to_delete_two_keys_wakes_when_the_second_is_free() {
        let overlay = test_overlay(false);
        let (owner, _held) = waiting_to_delete_two_markers(&overlay, "b/q");
        assert_eq!(overlay.waiting_for("c/"), 1);
        assert_eq!(overlay.waiting_for("b/"), 1);

        overlay.lock().remove_tomb("b/q");
        let next = woken(&overlay).expect("b/ is free");
        assert!(Arc::ptr_eq(&next, &owner));
        assert!(starts(&overlay, &next));
        assert_eq!(overlay.waiting_for("c/"), 0);
    }

    #[test]
    fn an_entry_waiting_to_delete_two_keys_wakes_when_the_second_is_free_in_another_case() {
        let overlay = test_overlay(true);
        let (owner, _held) = waiting_to_delete_two_markers(&overlay, "B/Q");

        overlay.lock().remove_tomb("B/Q");
        let next = woken(&overlay).expect("b/ is free");
        assert!(Arc::ptr_eq(&next, &owner));
        assert!(starts(&overlay, &next));
    }

    #[test]
    fn an_entry_that_owns_two_spellings_of_a_key_waits_for_the_slot_once() {
        let overlay = test_overlay(true);
        let id = RecordId::parse(&"f".repeat(32)).unwrap();
        overlay.unlinked(&plain("p"), &["b/q".to_owned()], &id);
        let owner = deleting_dir("a", &["B/", "b/"]);
        let _owner = overlay.insert_new(Arc::clone(&owner)).unwrap();
        overlay.track(&owner);
        drain(&overlay);
        assert!(!starts(&overlay, &owner));
        assert_eq!(overlay.waiting_for("b/"), 1);

        overlay.lock().remove_tomb("b/q");
        assert!(woken(&overlay).is_some());
        assert!(woken(&overlay).is_none(), "it is queued once");
    }

    #[test]
    fn an_entry_waiting_to_delete_two_keys_wakes_when_a_held_directory_is_let_go() {
        let overlay = test_overlay(false);
        let id = RecordId::parse(&"f".repeat(32)).unwrap();
        overlay.unlinked(&plain("p"), &["c/x".to_owned()], &id);
        let owner = deleting_dir("a", &["c/", "d/y"]);
        let _owner = overlay.insert_new(Arc::clone(&owner)).unwrap();
        overlay.track(&owner);
        drain(&overlay);
        let held = overlay.hold_below("d").unwrap();
        assert!(!starts(&overlay, &owner), "both keys are in use");
        assert_eq!(overlay.waiting_for("d/y"), 1);

        drop(held);
        let next = woken(&overlay).expect("d/y is free");
        assert!(Arc::ptr_eq(&next, &owner));
        assert!(starts(&overlay, &next));
    }

    #[test]
    fn a_file_does_not_wait_for_a_key_that_only_an_entry_that_failed_owns() {
        let overlay = test_overlay(false);
        let owner = moved("b", "a", &["d/"]);
        let _owner = overlay.insert_new(Arc::clone(&owner)).unwrap();
        overlay.track(&owner);
        let file = kept("d");
        file.state().set_local(local_data(0, 0));
        let _file = overlay.insert_new(Arc::clone(&file)).unwrap();
        drain(&overlay);
        assert!(!starts(&overlay, &file));
        assert_eq!(overlay.waiting_for("d/"), 1);

        overlay.failed(&owner, S3Error::InvalidResponse("refused"));
        let next = woken(&overlay).expect("the owner failed");
        assert!(Arc::ptr_eq(&next, &file));
        assert!(starts(&overlay, &next));
    }

    #[test]
    fn a_marker_is_not_left_to_the_job_of_its_directory_for_a_file_that_only_a_failed_entry_owns() {
        let overlay = test_overlay(false);
        let owner = moved("b", "a", &["d"]);
        let _owner = overlay.insert_new(Arc::clone(&owner)).unwrap();
        overlay.track(&owner);
        assert!(overlay.marker_deferred("d/"));
        overlay.failed(&owner, S3Error::InvalidResponse("refused"));
        assert!(!overlay.marker_deferred("d/"));
    }

    #[test]
    fn a_directory_does_not_wait_for_a_file_the_store_refused_to_delete() {
        let overlay = test_overlay(false);
        let id = RecordId::parse(&"f".repeat(32)).unwrap();
        overlay.unlinked(&kept("d"), &["d".to_owned()], &id);
        let directory = marked_dir("d", &[]);
        let _directory = overlay.insert_new(Arc::clone(&directory)).unwrap();
        drain(&overlay);
        assert!(!starts(&overlay, &directory));
        assert_eq!(overlay.waiting_for("d"), 1);

        let request = overlay
            .claim_tombs(Instant::now() + Duration::from_secs(60))
            .expect("the file is due");
        assert_eq!(request.keys(), ["d"]);
        overlay.finish_tombs(&[("d".to_owned(), S3Error::InvalidResponse("refused"))]);
        drop(request);
        let next = woken(&overlay).expect("the request ended");
        assert!(Arc::ptr_eq(&next, &directory));
        assert!(starts(&overlay, &next));
    }

    #[test]
    fn a_file_below_a_file_to_delete_waits_for_the_delete_unless_the_store_refused_it() {
        let overlay = test_overlay(false);
        let id = RecordId::parse(&"f".repeat(32)).unwrap();
        overlay.unlinked(&kept("a"), &["a".to_owned()], &id);
        let file = kept("a/b");
        file.state().set_local(local_data(0, 0));
        let _file = overlay.insert_new(Arc::clone(&file)).unwrap();
        drain(&overlay);
        assert!(!starts(&overlay, &file));
        assert_eq!(overlay.waiting_for("a"), 1);

        let request = overlay
            .claim_tombs(Instant::now() + Duration::from_secs(60))
            .expect("the file is due");
        overlay.finish_tombs(&[("a".to_owned(), S3Error::InvalidResponse("refused"))]);
        drop(request);
        let next = woken(&overlay).expect("the request ended");
        assert!(Arc::ptr_eq(&next, &file));
        assert!(starts(&overlay, &next));
    }

    #[test]
    fn a_file_waits_for_a_marker_while_a_key_to_delete_below_it_stays() {
        let overlay = test_overlay(false);
        let id = RecordId::parse(&"f".repeat(32)).unwrap();
        overlay.unlinked(&dir("d"), &["d/".to_owned()], &id);
        overlay.unlinked(&kept("d/x"), &["d/x".to_owned()], &id);
        let file = kept("d");
        file.state().set_local(local_data(0, 0));
        let _file = overlay.insert_new(Arc::clone(&file)).unwrap();
        assert!(!starts(&overlay, &file));
        assert_eq!(overlay.waiting_for("d/"), 1);

        overlay.finish_tombs(&[("d/x".to_owned(), S3Error::InvalidResponse("refused"))]);
        assert!(starts(&overlay, &file), "the marker stays with it");
    }

    #[test]
    fn a_marker_waits_for_a_write_of_the_file_of_its_name_that_outlives_its_entry() {
        let overlay = test_overlay(false);
        let id = RecordId::parse(&"f".repeat(32)).unwrap();
        let file = kept("d");
        file.state().set_local(local_data(0, 0));
        let held = overlay.insert_new(Arc::clone(&file)).unwrap();
        assert!(overlay.begin_write(&file, "d", &Stop::new()).is_ok());
        overlay.unlinked(&file, &[], &id);
        drop(held);
        let directory = marked_dir("d", &[]);
        let _directory = overlay.insert_new(Arc::clone(&directory)).unwrap();
        assert!(overlay.begin_write(&directory, "d/", &Stop::new()).is_err());

        overlay.end_writes(&file);
        assert!(overlay.begin_write(&directory, "d/", &Stop::new()).is_ok());
    }

    #[test]
    fn a_file_waits_for_a_write_of_the_marker_of_its_name_that_outlives_its_entry() {
        let overlay = test_overlay(false);
        let id = RecordId::parse(&"f".repeat(32)).unwrap();
        let directory = marked_dir("d", &[]);
        let held = overlay.insert_new(Arc::clone(&directory)).unwrap();
        assert!(overlay.begin_write(&directory, "d/", &Stop::new()).is_ok());
        overlay.unlinked(&directory, &[], &id);
        drop(held);
        let file = kept("d");
        file.state().set_local(local_data(0, 0));
        let _file = overlay.insert_new(Arc::clone(&file)).unwrap();
        assert!(overlay.begin_write(&file, "d", &Stop::new()).is_err());

        overlay.end_writes(&directory);
        assert!(overlay.begin_write(&file, "d", &Stop::new()).is_ok());
    }

    #[test]
    fn a_file_waits_for_a_request_that_deletes_the_marker_of_its_name_whoever_asked() {
        let overlay = test_overlay(false);
        let request = overlay.claim_gone(&["d/".to_owned()], &plain("other"));
        assert_eq!(request.claimed.keys(), ["d/"]);
        let file = kept("d");
        file.state().set_local(local_data(0, 0));
        let _held = overlay.insert_new(Arc::clone(&file)).unwrap();
        assert!(overlay.begin_write(&file, "d", &Stop::new()).is_err());

        drop(request);
        assert!(overlay.begin_write(&file, "d", &Stop::new()).is_ok());
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
        assert!(overlay.reserve("t", &renamed, None).is_err(), "t is held");
        let reservation = overlay.reserve("t", &renamed, Some(&replaced)).unwrap();
        assert!(overlay.reserve("T", &renamed, Some(&replaced)).is_err());
        assert!(overlay.insert_new(plain("free")).is_ok());
        drop(overlay.lock().entries.remove(&overlay.slot("t")));
        assert!(overlay.insert_new(plain("t")).is_err(), "reserved");
        drop(reservation);
        assert!(overlay.insert_new(plain("t")).is_ok());
        assert!(overlay.reserve("a", &renamed, None).is_ok(), "its own name");
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

    #[test]
    fn a_directory_is_gone_when_its_marker_is_to_be_deleted_and_no_entry_is_at_or_below_it() {
        let overlay = test_overlay(true);
        overlay.install(Vec::new(), vec![tombstone(&["Up/"])]);
        assert!(overlay.dir_dead("up"));
        assert!(overlay.dead_above("UP/f"));
        assert!(!overlay.dead_above("up"));
        assert!(!overlay.dir_dead("other"));

        overlay.install(vec![kept("up/Down/f")], Vec::new());
        assert!(!overlay.dir_dead("up"), "an entry is below it");
        assert!(!overlay.dead_above("up/down/f"));
    }

    #[test]
    fn a_directory_with_an_entry_of_its_own_is_not_gone_whatever_is_to_be_deleted() {
        let overlay = test_overlay(false);
        overlay.install(vec![dir("d")], vec![tombstone(&["d/", "d/f"])]);
        assert!(!overlay.dir_dead("d"));
        assert!(overlay.tombstoned("d/f"));
    }

    #[test]
    fn a_file_at_the_name_of_a_directory_does_not_keep_it() {
        for fold in [false, true] {
            let overlay = test_overlay(fold);
            overlay.install(vec![kept("d")], vec![tombstone(&["d/"])]);
            assert!(overlay.dir_dead("d"), "fold {fold}");
            assert!(overlay.dead_above("d/f"), "fold {fold}");
        }
        let overlay = test_overlay(true);
        overlay.install(vec![kept("D")], vec![tombstone(&["d/"])]);
        assert!(overlay.dir_dead("d"));
    }

    #[test]
    fn nothing_is_made_below_a_directory_that_is_gone() {
        let overlay = test_overlay(false);
        overlay.install(Vec::new(), vec![tombstone(&["d/"])]);
        assert!(matches!(
            overlay.insert_new(plain("d/x/f")),
            Err(SmbError::PathNotFound)
        ));
        assert!(matches!(
            overlay.reserve("d/f", &plain("x"), None),
            Err(SmbError::PathNotFound)
        ));
        let ahead = Arc::new(ReadAhead::new());
        assert!(matches!(
            overlay.take_found(found_file("d/f"), &ahead),
            Err(SmbError::NotFound)
        ));
        let _made = overlay.insert_new(dir("d")).unwrap();
        assert!(overlay.insert_new(plain("d/f")).is_ok());
    }

    #[test]
    fn exact_keys_to_delete_are_found_by_their_spelling() {
        let overlay = test_overlay(true);
        overlay.install(Vec::new(), vec![tombstone(&["Dir/A.txt"])]);
        assert!(overlay.to_delete("Dir/A.txt"));
        assert!(!overlay.to_delete("Dir/a.txt"));
        assert!(overlay.tombstoned("Dir/a.txt"));
    }

    #[test]
    fn names_below_a_directory_held_for_a_rename_are_not_made_and_its_entries_stay() {
        let overlay = test_overlay(true);
        let idle = overlay.insert_new(plain("D/idle")).unwrap();
        let subtree = overlay.hold_below("d").unwrap();
        drop(idle);
        assert_eq!(
            overlay.len(),
            1,
            "the hold keeps an entry with nothing to keep"
        );

        assert!(matches!(
            overlay.insert_new(plain("d/g")),
            Err(SmbError::Sharing)
        ));
        let renamed = plain("x");
        let _x = overlay.insert_new(Arc::clone(&renamed)).unwrap();
        assert!(matches!(
            overlay.reserve("D/h", &renamed, None),
            Err(SmbError::Sharing)
        ));
        assert!(
            overlay.insert_new(plain("dd")).is_ok(),
            "beside the directory"
        );
        for other in ["d", "d/e", ""] {
            assert!(
                matches!(overlay.hold_below(other), Err(SmbError::Sharing)),
                "{other}"
            );
        }

        drop(subtree);
        assert_eq!(overlay.len(), 1, "the entry the hold kept is let go");
        assert!(overlay.insert_new(plain("d/g")).is_ok());
    }

    #[test]
    fn a_frozen_rename_makes_no_entry_for_an_object_of_the_bucket_below_the_directory() {
        let overlay = test_overlay(false);
        let ahead = Arc::new(ReadAhead::new());
        let mut subtree = overlay.hold_below("d").unwrap();
        let before = overlay.take_found(found_file("d/a"), &ahead).unwrap();
        subtree.freeze("e", NO_LIMIT).unwrap();
        assert!(matches!(
            overlay.take_found(found_file("d/b"), &ahead),
            Err(SmbError::Sharing)
        ));
        let again = overlay.take_found(found_file("d/a"), &ahead).unwrap();
        assert!(Arc::ptr_eq(&again.entry, &before.entry));
        drop((before, again));
        assert_eq!(overlay.len(), 1, "the freeze took a hold on the entry");
        drop(subtree);
        assert_eq!(overlay.len(), 0);
        assert!(overlay.take_found(found_file("d/b"), &ahead).is_ok());
    }

    #[test]
    fn a_frozen_rename_fences_the_directory_it_moves_to_until_it_thaws_or_ends() {
        let overlay = test_overlay(true);
        let ahead = Arc::new(ReadAhead::new());
        let mut subtree = overlay.hold_below("d").unwrap();
        subtree.freeze("E", NO_LIMIT).unwrap();

        assert!(matches!(
            overlay.insert_new(plain("e/x")),
            Err(SmbError::Sharing)
        ));
        let renamed = plain("m");
        let _m = overlay.insert_new(Arc::clone(&renamed)).unwrap();
        assert!(matches!(
            overlay.reserve("e/y", &renamed, None),
            Err(SmbError::Sharing)
        ));
        assert!(matches!(
            overlay.take_found(found_file("e/z"), &ahead),
            Err(SmbError::Sharing)
        ));
        assert!(
            overlay.reserve("e", &renamed, None).is_ok(),
            "the name of the directory itself is not below it"
        );

        subtree.thaw();
        assert!(
            overlay.insert_new(plain("e/x")).is_ok(),
            "the fence is lifted"
        );
        assert!(overlay.take_found(found_file("d/b"), &ahead).is_ok());
        assert!(matches!(
            overlay.insert_new(plain("d/c")),
            Err(SmbError::Sharing)
        ));

        subtree.freeze("e2", NO_LIMIT).unwrap();
        drop(subtree);
        assert!(overlay.insert_new(plain("e2/x")).is_ok());
        assert!(overlay.insert_new(plain("d/c")).is_ok());
    }

    #[test]
    fn a_freeze_refuses_more_entries_than_a_rename_takes_before_it_holds_any() {
        let overlay = test_overlay(false);
        let ahead = Arc::new(ReadAhead::new());
        let _held: Vec<Held> = ["d/a", "d/b"]
            .into_iter()
            .map(|key| overlay.insert_new(kept(key)).unwrap())
            .collect();
        let mut subtree = overlay.hold_below("d").unwrap();
        let later: Vec<Held> = ["d/c", "d/d"]
            .into_iter()
            .map(|key| overlay.take_found(found_file(key), &ahead).unwrap())
            .collect();

        assert!(matches!(
            subtree.freeze("e", 3),
            Err(SmbError::AccessDenied)
        ));
        assert_eq!(
            subtree.entries().len(),
            2,
            "the entries made since are not held"
        );
        assert!(later.iter().all(|held| held.entry.state().handles == 1));
        {
            let index = overlay.lock();
            assert!(index.frozen.is_empty());
            assert_eq!(index.moving.len(), 1, "only the directory is held");
        }

        subtree.freeze("e", 4).unwrap();
        assert_eq!(subtree.entries().len(), 4);
        assert!(later.iter().all(|held| held.entry.state().handles == 2));
    }

    #[test]
    fn a_rename_cannot_fence_the_place_another_rename_holds() {
        let overlay = test_overlay(false);
        let mut first = overlay.hold_below("a").unwrap();
        let mut second = overlay.hold_below("b").unwrap();
        first.freeze("z", NO_LIMIT).unwrap();
        assert!(matches!(
            second.freeze("z", NO_LIMIT),
            Err(SmbError::Sharing)
        ));
        assert!(matches!(
            second.freeze("a/z", NO_LIMIT),
            Err(SmbError::Sharing)
        ));
        drop(first);
        second.freeze("z", NO_LIMIT).unwrap();
    }

    #[test]
    fn a_case_only_rename_fences_nothing_beyond_the_directory() {
        let overlay = test_overlay(true);
        let mut subtree = overlay.hold_below("docs").unwrap();
        subtree.freeze("DOCS", NO_LIMIT).unwrap();
        for beside in ["DOCS", "doc", "docsx", "x/docs"] {
            assert!(overlay.insert_new(plain(beside)).is_ok(), "{beside}");
        }
        {
            let index = overlay.lock();
            assert_eq!(index.moving.len(), 1);
            assert_eq!(index.frozen.len(), 1);
        }
        subtree.thaw();
        assert!(matches!(
            overlay.insert_new(plain("docs/x")),
            Err(SmbError::Sharing)
        ));
        drop(subtree);
        assert!(overlay.insert_new(plain("docs/x")).is_ok());
    }

    #[test]
    fn keys_inside_a_directory_held_for_a_rename_are_not_deleted_until_it_is_let_go() {
        let overlay = test_overlay(false);
        let id = RecordId::parse(&"c".repeat(32)).unwrap();
        overlay.unlinked(&kept("d/old"), &["d/old".to_owned()], &id);
        overlay.unlinked(&kept("other"), &["other".to_owned()], &id);
        let owner = moved("e/x", "z", &["d/gone"]);
        let _owner = overlay.insert_new(Arc::clone(&owner)).unwrap();
        overlay.track(&owner);
        let later = Instant::now() + Duration::from_secs(6);

        let subtree = overlay.hold_below("d").unwrap();
        assert_eq!(claimed(&overlay, later), ["other"]);
        let claim = overlay.claim_gone(&["d/gone".to_owned()], &owner);
        assert_eq!(claim.busy, ["d/gone"]);
        assert!(claim.claimed.keys().is_empty());
        drop(claim);

        drop(subtree);
        assert_eq!(claimed(&overlay, later), ["d/old", "other"]);
        let claim = overlay.claim_gone(&["d/gone".to_owned()], &owner);
        assert_eq!(claim.claimed.keys(), ["d/gone"]);
    }

    #[test]
    fn the_marker_of_a_directory_held_for_a_rename_is_not_inside_it() {
        let overlay = test_overlay(false);
        let id = RecordId::parse(&"c".repeat(32)).unwrap();
        overlay.unlinked(&kept("m/"), &["m/".to_owned()], &id);
        let _subtree = overlay.hold_below("m").unwrap();
        let later = Instant::now() + Duration::from_secs(6);
        assert_eq!(claimed(&overlay, later), ["m/"]);
    }

    #[test]
    fn an_entry_that_waits_for_a_key_inside_a_held_directory_wakes_when_it_is_let_go() {
        let overlay = test_overlay(false);
        let owner = moved("e", "e", &["d/old"]);
        let _owner = overlay.insert_new(Arc::clone(&owner)).unwrap();
        overlay.track(&owner);
        let subtree = overlay.hold_below("d").unwrap();
        let later = Instant::now() + Duration::from_secs(60);
        while overlay.queue().pop_due(later).is_some() {}
        owner.state().queued = false;
        assert!(matches!(
            overlay.claim(Arc::clone(&owner), later),
            Claim::Skip
        ));
        assert!(owner.state().queued, "it waits in the overlay");
        assert!(overlay.queue().pop_due(later).is_none());

        drop(subtree);
        let woke = overlay
            .queue()
            .pop_due(later)
            .expect("the directory was let go");
        assert!(Arc::ptr_eq(&woke, &owner));
        assert!(matches!(
            overlay.claim(woke, later),
            Claim::Run(_, _, false)
        ));
    }

    #[test]
    fn a_hold_sees_the_requests_that_delete_inside_the_directory() {
        let overlay = test_overlay(false);
        let id = RecordId::parse(&"c".repeat(32)).unwrap();
        overlay.unlinked(&kept("d/old"), &["d/old".to_owned()], &id);
        overlay.unlinked(&kept("other"), &["other".to_owned()], &id);
        let later = Instant::now() + Duration::from_secs(6);
        let claim = overlay.claim_tombs(later).unwrap();
        assert_eq!(claim.keys(), ["d/old", "other"]);

        let subtree = overlay.hold_below("d").unwrap();
        assert!(subtree.deleting());
        drop(claim);
        assert!(!subtree.deleting());
    }

    fn batch_of(entries: &[&Arc<Entry>]) -> (Arc<Batch>, BatchRecord) {
        let members = entries
            .iter()
            .map(|entry| {
                Entry::record(&mut entry.state(), "", std::time::SystemTime::UNIX_EPOCH).unwrap()
            })
            .collect();
        let record = BatchRecord {
            id: RecordId::parse(&"9".repeat(32)).unwrap(),
            members,
        };
        let batch = Arc::new(Batch::new(record.clone()));
        for entry in entries {
            entry.state().batch = Some(Arc::clone(&batch));
        }
        (batch, record)
    }

    #[test]
    fn an_entry_of_a_batch_stays_until_the_batch_is_released_and_leaves_then_if_idle() {
        let overlay = test_overlay(false);
        let idle = overlay.insert_new(plain("a")).unwrap();
        let busy = overlay.insert_new(kept("b")).unwrap();
        let (a, b) = (Arc::clone(&idle.entry), Arc::clone(&busy.entry));
        let (batch, _) = batch_of(&[&a, &b]);
        drop((idle, busy));
        assert_eq!(overlay.len(), 2, "the batch holds both");

        overlay.release_batch(&[Arc::clone(&a), Arc::clone(&b)], &batch);
        assert_eq!(overlay.len(), 1, "only the entry with a record stays");
        assert!(a.state().batch.is_none() && b.state().batch.is_none());
    }

    #[test]
    fn a_failed_batch_fails_the_entries_that_still_wait_for_it_and_wakes_what_waits_on_it() {
        let overlay = test_overlay(false);
        let first = overlay.insert_new(kept("a")).unwrap();
        let second = overlay.insert_new(kept("b")).unwrap();
        let idle = overlay.insert_new(plain("c")).unwrap();
        let (a, b, c) = (
            Arc::clone(&first.entry),
            Arc::clone(&second.entry),
            Arc::clone(&idle.entry),
        );
        let (batch, _) = batch_of(&[&a, &c]);
        let (later, _) = batch_of(&[&b]);
        drop((first, second, idle));
        {
            let mut index = overlay.lock();
            a.state().queued = true;
            index.park(&a, &[batch.key().to_owned()]);
        }
        let before = queued(&overlay);

        let failure = S3Error::InvalidResponse("not recorded");
        overlay.fail_batch(&[a.clone(), b.clone(), c.clone()], &batch, &failure);
        assert!(a.state().failure.is_some());
        assert!(
            b.state().failure.is_none() && b.state().in_batch(&later),
            "a later batch holds it"
        );
        assert_eq!(overlay.len(), 2, "the idle entry left");
        assert_eq!(queued(&overlay), before + 1, "the entry that waited wakes");
    }

    #[test]
    fn an_entry_that_goes_back_to_its_batch_is_no_longer_covered_by_a_tombstone_record() {
        let dir = scratch_dir();
        let cache = CacheDir::open(&dir.path().join("c"), "identity").unwrap();
        let overlay = test_overlay(false);
        let (a, b) = (kept("a"), kept("b"));
        let (batch, record) = batch_of(&[&a, &b]);
        cache.write_record(&record.id, &record.encode()).unwrap();
        let id = record.members[0].id.clone();

        let left = overlay.left_batch(&batch, &id).unwrap();
        assert!(overlay.left_batch(&batch, &id).is_none(), "it left once");
        assert_eq!(overlay.lock().covered.len(), 1);
        overlay.rejoin_batch(&cache, left).unwrap();
        assert!(overlay.lock().covered.is_empty());
        assert!(
            overlay.left_batch(&batch, &id).is_some(),
            "it is a member again"
        );
    }

    #[test]
    fn a_failed_batch_lets_an_idle_entry_with_an_open_handle_go_when_the_handle_closes() {
        let overlay = test_overlay(false);
        let open = overlay.insert_new(plain("c")).unwrap();
        let c = Arc::clone(&open.entry);
        let (batch, _) = batch_of(&[&c]);

        let failure = S3Error::InvalidResponse("not recorded");
        overlay.fail_batch(&[Arc::clone(&c)], &batch, &failure);
        assert!(c.state().batch.is_none());
        assert_eq!(overlay.len(), 1, "the handle holds it");
        drop(open);
        assert_eq!(overlay.len(), 0);
    }

    #[test]
    fn the_record_of_a_batch_is_written_without_the_entries_that_left_it_before_their_tombstone_goes()
     {
        let dir = scratch_dir();
        let cache = CacheDir::open(&dir.path().join("c"), "identity").unwrap();
        let overlay = test_overlay(false);
        let (a, b, c) = (kept("a"), kept("b"), kept("c"));
        let (batch, record) = batch_of(&[&a, &b, &c]);
        cache.write_record(&record.id, &record.encode()).unwrap();
        let ids = [record.members[0].id.clone(), record.members[1].id.clone()];
        for (entry, id, key) in [(&a, &ids[0], "k"), (&b, &ids[1], "l")] {
            let tomb = TombstoneRecord {
                id: id.clone(),
                keys: vec![key.to_owned()],
            };
            cache.write_record(id, &tomb.encode()).unwrap();
            overlay.unlinked(entry, &[key.to_owned()], id);
            overlay.left_batch(&batch, id).unwrap();
        }

        let on_disk = || cache.batch_members(&record.id).unwrap().len();
        assert_eq!(
            on_disk(),
            3,
            "the record on disk still lists the entries that left"
        );
        cache.hooks.record_ops.lock().unwrap().clear();
        overlay
            .drop_tombs(&cache, &["k".to_owned(), "l".to_owned()])
            .unwrap();
        assert_eq!(on_disk(), 1, "the tombstone records went after it");
        for id in &ids {
            assert!(!dir.path().join("c/records").join(id.as_str()).exists());
        }
        // One rewrite of the batch record for both entries, and it comes before
        // the first tombstone record goes.
        let ops = cache.hooks.record_ops.lock().unwrap().clone();
        let batch_writes: Vec<usize> = ops
            .iter()
            .enumerate()
            .filter(|(_, (op, id))| *op == RecordOp::Write && *id == record.id)
            .map(|(at, _)| at)
            .collect();
        let removals: Vec<usize> = ops
            .iter()
            .enumerate()
            .filter(|(_, (op, id))| *op == RecordOp::Remove && ids.contains(id))
            .map(|(at, _)| at)
            .collect();
        assert_eq!(batch_writes.len(), 1, "{ops:?}");
        assert_eq!(removals.len(), 2, "{ops:?}");
        assert!(batch_writes[0] < removals[0], "{ops:?}");
    }
}
