//! Renaming a directory: every object below it becomes an entry at its new
//! key, and one batch record makes the whole move durable before the rename
//! answers. The entries then copy their objects and delete the old keys in
//! the background, once records of their own have replaced the batch.

use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io;
use std::sync::{Arc, Mutex, PoisonError};

use tokio::task::{JoinError, JoinSet, spawn_blocking};
use tracing::{error, warn};

use crate::error::{SmbError, SmbResult};
use crate::path::is_valid_component;

use super::backend::Shared;
use super::cache::Known;
use super::cachedir::{CacheDir, new_id};
use super::change::{persist_held, recount_source};
use super::client::ListRequest;
use super::data::disk_error;
use super::entry::{Base, Entry, Sealed, State};
use super::error::S3Error;
use super::job::FULL_DISK_REST;
use super::keys::{
    FileStamp, MAX_KEY_LEN, Row, RowKind, Slot, dir_prefix, join_key, last_name, parent_key,
    path_below, slot,
};
use super::object::{Metadata, ObjectHead};
use super::outcome;
use super::overlay::{Held, Moved, Subtree};
use super::record::{BatchRecord, EntryRecord, MAX_RECORD_LEN, RecordId};
use super::rename::gone_after;
use super::retry::Retry;
use super::xml::ListedObject;

/// The entries a directory rename moved, while their records are the batch
/// record and nothing else. The entries get no job before the batch has gone.
///
/// A line of the batch record stands for an entry only while it is the newest
/// record the entry has: an entry that leaves the batch for a state with no
/// record of its own is taken out of the record on disk first.
pub(super) struct Batch {
    /// What the entries wait on: a name no key spells.
    key: String,
    state: Mutex<BatchState>,
}

struct BatchState {
    record: BatchRecord,
    disk: Disk,
    /// How many times the record was written or removed.
    writes: u64,
}

/// How the batch record on disk stands.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Disk {
    /// It lists the entries of the batch.
    Current,
    /// It differs from the entries of the batch: it lists entries that left
    /// with a tombstone record standing for them, or lacks one that came back
    /// and whose write failed. The next write puts it right.
    Stale,
    /// It is removed because the last entry left.
    Removed,
    /// It is removed because every entry has a record of its own, and the batch
    /// is over.
    Finished,
}

/// How an entry left a batch.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Leave {
    /// In memory only: a tombstone record stands for the entry.
    Covered,
    /// The record on disk was written without the entry.
    Rewritten,
    /// The entry was the last, and the record was removed with it.
    Emptied,
}

/// An entry that left a batch, with what puts it back.
pub(super) struct Left {
    batch: Arc<Batch>,
    /// Where the entry stood in the record.
    at: usize,
    member: EntryRecord,
    /// The number of times the record had been written when the entry left,
    /// counting the write that took the entry out of it, if there was one.
    writes: u64,
    how: Leave,
}

impl Left {
    pub(super) fn id(&self) -> &RecordId {
        &self.member.id
    }
}

impl Batch {
    pub(super) fn new(record: BatchRecord) -> Batch {
        Batch {
            key: format!("\0batch {}", record.id),
            state: Mutex::new(BatchState {
                record,
                disk: Disk::Current,
                writes: 0,
            }),
        }
    }

    /// The name the entries of the batch wait on.
    pub(super) fn key(&self) -> &str {
        &self.key
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, BatchState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Takes the entry `id` out of the batch record, as it leaves the batch
    /// for a state that has no record of its own. The record is rewritten
    /// without the entry, or removed when none is left. Returns what puts the
    /// entry back, or `None` if it was not a member.
    ///
    /// # Errors
    ///
    /// Fails when the record cannot be written. The entry stays in the batch.
    pub(super) fn cancel(
        self: &Arc<Self>,
        cache: &CacheDir,
        id: &RecordId,
    ) -> SmbResult<Option<Left>> {
        let mut state = self.lock();
        if state.is_over() {
            return Ok(None);
        }
        let Some(at) = state.record.members.iter().position(|m| m.id == *id) else {
            return Ok(None);
        };
        let member = state.record.members.remove(at);
        if let Err(e) = write(cache, &mut state) {
            state.record.members.insert(at, member);
            return Err(disk_error(e));
        }
        Ok(Some(Left {
            batch: Arc::clone(self),
            at,
            member,
            writes: state.writes,
            how: if state.disk == Disk::Removed {
                Leave::Emptied
            } else {
                Leave::Rewritten
            },
        }))
    }

    /// Takes the entry `id` out of the batch in memory, as it leaves the batch
    /// for a tombstone record that stands for it. The record of the batch is
    /// written without the entry by [`flush`](Self::flush), before that
    /// tombstone record goes. Returns what puts the entry back, or `None` if
    /// it was not a member.
    pub(super) fn cover(self: &Arc<Self>, id: &RecordId) -> Option<Left> {
        let mut state = self.lock();
        if state.is_over() {
            return None;
        }
        let at = state.record.members.iter().position(|m| m.id == *id)?;
        let member = state.record.members.remove(at);
        state.disk = Disk::Stale;
        Some(Left {
            batch: Arc::clone(self),
            at,
            member,
            writes: state.writes,
            how: Leave::Covered,
        })
    }

    /// Puts an entry that left the batch back where it was. If the record on
    /// disk was written without the entry, it is written with it.
    ///
    /// # Errors
    ///
    /// Fails when the record cannot be written. The entry is a member in
    /// memory all the same, and the record is written again by the next
    /// [`flush`](Self::flush).
    pub(super) fn rejoin(left: Left, cache: &CacheDir) -> io::Result<()> {
        let Left {
            batch,
            at,
            member,
            writes,
            how,
        } = left;
        let mut state = batch.lock();
        let over = match state.disk {
            Disk::Finished => true,
            Disk::Removed => how != Leave::Emptied,
            Disk::Current | Disk::Stale => false,
        };
        if over || state.record.members.iter().any(|held| held.id == member.id) {
            return Ok(());
        }
        let at = at.min(state.record.members.len());
        state.record.members.insert(at, member);
        if how == Leave::Covered && state.writes == writes {
            return Ok(());
        }
        // A write that fails leaves the record to the next flush.
        state.disk = Disk::Stale;
        write(cache, &mut state)
    }

    /// Writes the record of the batch again if it differs from the entries of
    /// the batch: without the entries that left it since it was written, and
    /// with those whose return it could not write.
    pub(super) fn flush(&self, cache: &CacheDir) -> io::Result<()> {
        let mut state = self.lock();
        if state.disk != Disk::Stale {
            return Ok(());
        }
        write(cache, &mut state)
    }

    /// Removes the batch record, once every entry has a record of its own.
    fn finish(&self, cache: &CacheDir) -> io::Result<()> {
        let mut state = self.lock();
        if !state.is_over() {
            cache.remove_record(&state.record.id)?;
        }
        state.disk = Disk::Finished;
        Ok(())
    }
}

impl BatchState {
    /// Whether the record is removed.
    fn is_over(&self) -> bool {
        matches!(self.disk, Disk::Removed | Disk::Finished)
    }
}

/// Writes the record of a batch as `state` has it, or removes it when no entry
/// is left.
fn write(cache: &CacheDir, state: &mut BatchState) -> io::Result<()> {
    if state.record.members.is_empty() {
        cache.remove_record(&state.record.id)?;
        state.disk = Disk::Removed;
    } else {
        cache.write_record(&state.record.id, &state.record.encode())?;
        state.disk = Disk::Current;
    }
    state.writes += 1;
    Ok(())
}

impl Shared {
    /// Moves the directory of `source` to the key `to`. A rename of a
    /// directory looks up the directory, the parent of the new name and the
    /// new name, then lists every key below the directory, one request for
    /// each page. When names match without regard to case, a rename that
    /// changes the case of the name only skips the lookup of the new name,
    /// which the store would answer with the directory itself, and lists the
    /// parent instead. The listing starts once the requests in flight that
    /// delete keys below the directory have ended. The entries and the batch
    /// record are then made in one step, and the call answers. The objects
    /// follow in the background. The work runs as a task of its own, so a
    /// request that is dropped does not leave it half done. The lookups and
    /// listings share the deadline `retry` has.
    ///
    /// # Errors
    ///
    /// Fails with `AccessDenied` if the directory holds more than
    /// `max_dir_rename_objects` objects or a key that cannot be moved, with
    /// `InvalidParameter` if `to` is below the directory, with `Exists` if
    /// `to` is taken meanwhile, and with `Sharing` if another rename overlaps
    /// it, a directory below it is still being made, or the keys below it keep
    /// changing while they are listed. The wait for the requests that delete
    /// keys below the directory fails with `Io` if it outlasts the deadline.
    pub(super) async fn rename_dir(
        self: &Arc<Self>,
        source: Held,
        to: String,
        retry: &Retry,
    ) -> SmbResult<()> {
        let (shared, retry) = (Arc::clone(self), retry.clone());
        tokio::spawn(async move { shared.move_dir(source, &to, &retry).await })
            .await
            .map_err(|e| SmbError::Io(io::Error::other(e)))?
    }

    async fn move_dir(self: &Arc<Self>, source: Held, to: &str, retry: &Retry) -> SmbResult<()> {
        let from = source.entry.state().key.clone();
        if from == to {
            return Ok(());
        }
        let fold = self.case_insensitive;
        if slot(to, fold).starts_with(&slot(&dir_prefix(&from), fold)) {
            return Err(SmbError::InvalidParameter);
        }
        let mut subtree = self.overlay.hold_below(&from)?;
        self.await_deletes(&subtree, retry).await?;
        for _ in 0..ATTEMPTS {
            let listed = self.list_below(&from, retry).await?;
            #[cfg(test)]
            super::jobs::pause(&self.jobs.pause_listed).await;
            subtree.freeze(to, self.max_dir_rename_objects)?;
            let heads = self.cached_heads(&listed);
            let (shared, held, entries) = (Arc::clone(self), source.another(), subtree.entries());
            let (name, target) = (from.clone(), to.to_owned());
            let moved = spawn_blocking(move || {
                commit_dir(&shared, &held, &entries, &name, &target, &listed, &heads)
            })
            .await
            .map_err(|e| SmbError::Io(io::Error::other(e)))??;
            if let Some(committed) = moved {
                drop(subtree);
                self.finish_move(committed);
                return Ok(());
            }
            subtree.thaw();
        }
        Err(SmbError::Sharing)
    }

    /// Waits until no request deletes a key inside the directory `subtree`
    /// holds. None starts while it is held, so a listing made after this shows
    /// the bucket as those deletes left it. Fails with `Io` once `retry` runs
    /// out of time.
    pub(super) async fn await_deletes(&self, subtree: &Subtree, retry: &Retry) -> SmbResult<()> {
        self.await_clear(retry, || Ok((!subtree.deleting()).then_some(())))
            .await
    }

    /// Starts the tasks that give the entries of a move records of their own
    /// and read the metadata of their objects. The worker waits for them. If
    /// the first ends in a panic, the entries fail; a panic in the second is
    /// logged.
    fn finish_move(self: &Arc<Self>, committed: Committed) {
        let Committed { batch, members } = committed;
        let members: Arc<[Arc<Entry>]> = members.into();
        let (shared, guard) = (Arc::clone(self), self.jobs.begin_dissolve());
        tokio::spawn(async move {
            let recording = tokio::spawn(dissolve(
                Arc::clone(&shared),
                Arc::clone(&batch),
                Arc::clone(&members),
            ));
            let reading = tokio::spawn(read_bases(Arc::clone(&shared), Arc::clone(&members)));
            let (recorded, read) = tokio::join!(recording, reading);
            if let Err(e) = recorded {
                error!(error = %e, "the entries of a renamed directory could not be recorded");
                shared
                    .overlay
                    .fail_batch(&members, &batch, &S3Error::transport(e));
            }
            if let Err(e) = read {
                error!(error = %e, "the times of the objects of a renamed directory could not be read");
            }
            // The cache directory stays locked while the backend state lives:
            // let go of it before the worker is told the tasks are over.
            drop(shared);
            drop(guard);
        });
    }

    /// The description the metadata cache holds of each file in `listed` that
    /// it holds one of for the object the listing describes.
    fn cached_heads(&self, listed: &[ListedObject]) -> Vec<Option<Arc<ObjectHead>>> {
        let mut cache = self.cache();
        listed
            .iter()
            .map(|object| {
                let stamp = FileStamp {
                    size: object.size,
                    etag: object.etag.clone(),
                    last_modified: object.last_modified,
                };
                cache.head_for_row(&object.key, &stamp)
            })
            .collect()
    }

    /// Every object below the directory `dir`, all pages of the listing.
    /// Fails with `AccessDenied` as soon as there are more than a move may
    /// take, with room for the keys to delete among them.
    async fn list_below(&self, dir: &str, retry: &Retry) -> SmbResult<Vec<ListedObject>> {
        let prefix = dir_prefix(dir);
        let limit = self
            .max_dir_rename_objects
            .saturating_add(self.overlay.hidden_below(&prefix))
            .saturating_add(1);
        let mut found: Vec<ListedObject> = Vec::new();
        let mut token: Option<String> = None;
        loop {
            let request = ListRequest {
                prefix: &prefix,
                delimited: false,
                continuation_token: token.as_deref(),
                max_keys: None,
            };
            let page = self
                .client
                .list_objects(&request, retry.clone())
                .await
                .map_err(S3Error::into_smb_error)?;
            found.extend(page.objects);
            if found.len() > limit {
                return Err(SmbError::AccessDenied);
            }
            token = page.next_token;
            if token.is_none() {
                return Ok(found);
            }
        }
    }
}

/// How many times a rename lists the directory before it fails with `Sharing`,
/// when each move finds the entries below it not as the listing left them.
const ATTEMPTS: usize = 3;

/// What a move made: the batch record that holds the entries until they have
/// records of their own.
struct Committed {
    batch: Arc<Batch>,
    members: Vec<Arc<Entry>>,
}

/// An entry the move changes, with the record it has in the batch.
struct Step {
    moved: Moved,
    record: EntryRecord,
    /// The data file the record claims, and whether it is the first record of
    /// the entry.
    data: Option<(Arc<File>, bool)>,
}

/// The part of `key` below the directory `from`, if it is below it.
fn below<'a>(key: &'a str, from: &str) -> Option<&'a str> {
    let rest = key.get(from.len()..)?.strip_prefix('/')?;
    (!rest.is_empty()).then_some(rest)
}

/// Whether every name in `path`, which is below a directory and may end in
/// `/`, is one a client can open.
fn can_open(path: &str) -> bool {
    path.strip_suffix('/')
        .unwrap_or(path)
        .split('/')
        .all(is_valid_component)
}

/// The directories between `from` and the keys `keys`, which are below it,
/// that are not in `named`.
fn implied_dirs<'a>(
    from: &str,
    keys: impl IntoIterator<Item = &'a str>,
    named: &HashSet<Slot>,
    fold: bool,
) -> Vec<String> {
    let mut seen: HashSet<Slot> = HashSet::new();
    let mut dirs: Vec<String> = Vec::new();
    for key in keys {
        let Some(rest) = below(key, from) else {
            continue;
        };
        let mut names: Vec<&str> = rest.trim_end_matches('/').split('/').collect();
        names.pop();
        let mut dir = from.to_owned();
        for name in names {
            dir = join_key(&dir, name);
            let held = slot(&dir, fold);
            if !named.contains(&held) && seen.insert(held) {
                dirs.push(dir.clone());
            }
        }
    }
    dirs
}

/// The step of moving `entry`, which is `fresh` when it was made for an
/// object of the bucket, to `to`: where it goes, the keys it owns to delete
/// after, and the record the batch holds for it. A directory always has its
/// marker object to put. `None` if the entry has left the overlay.
///
/// # Errors
///
/// Fails with `Sharing` for a directory whose marker object is being put by
/// the open that made it.
fn step(shared: &Shared, entry: &Arc<Entry>, fresh: bool, to: &str) -> SmbResult<Option<Step>> {
    let is_dir = entry.is_dir();
    let new_key = if is_dir {
        dir_prefix(to)
    } else {
        to.to_owned()
    };
    // The index is asked before the state of the entry is locked, as the
    // lock order has it.
    let may_exist = shared.overlay.tombstoned(&new_key);
    let mut state = entry.state();
    if state.detached {
        return Ok(None);
    }
    if state.creating {
        return Err(SmbError::Sharing);
    }
    let old = state.key.clone();
    let old_key = if is_dir {
        dir_prefix(&old)
    } else {
        old.clone()
    };
    let in_bucket = state.in_bucket();
    let gone = gone_after(&state.gone, &old_key, in_bucket || is_dir, &new_key);

    let mut record =
        Entry::record(&mut state, &shared.prefix, shared.built).map_err(SmbError::Io)?;
    record.key = to.to_owned();
    record.path = path_below(&shared.prefix, to);
    record.gone.clone_from(&gone);
    record.remote = may_exist;
    record.generation += 1;
    record.marker_pending = is_dir;
    let sealed = record.local.as_ref().map(|local| Sealed {
        generation: record.generation,
        len: local.len,
    });
    let source = record.source().map(str::to_owned);
    let data = state
        .local()
        .map(|local| (Arc::clone(&local.file), state.sealed().is_none()));
    drop(state);
    Ok(Some(Step {
        moved: Moved {
            entry: Arc::clone(entry),
            from: (!fresh).then_some(old),
            to: to.to_owned(),
            gone,
            may_exist,
            sealed,
            source,
        },
        record,
        data,
    }))
}

/// The entry for an object of the bucket below the directory: it starts from
/// the object. `head` is what the metadata cache held of it.
fn fresh_entry(
    shared: &Shared,
    object: &ListedObject,
    head: Option<Arc<ObjectHead>>,
) -> Arc<Entry> {
    let listed = || {
        Arc::new(ObjectHead {
            size: object.size,
            etag: object.etag.clone(),
            last_modified: object.last_modified,
            metadata: Metadata::default(),
        })
    };
    let mut state;
    if let Some(dir) = object.key.strip_suffix('/') {
        state = State::new(dir.to_owned(), true);
        state.base = Some(Base::listed(
            &shared.ahead,
            object.key.clone(),
            listed(),
            false,
        ));
    } else {
        state = State::new(object.key.clone(), false);
        state.base = Some(match head {
            Some(head) => Base::new(&shared.ahead, object.key.clone(), head, true),
            None => Base::listed(&shared.ahead, object.key.clone(), listed(), true),
        });
    }
    state.may_exist = true;
    Entry::from_state(state)
}

/// The steps that move the entries below the directory `from` to the
/// directory `to`: those of `existing` in the overlay, one for each object of
/// `listed` that none of them holds, one for each directory that only keys
/// imply, and, last, the one of `root`. `None` if an entry has left the
/// overlay since it was found.
///
/// # Errors
///
/// Fails with `AccessDenied` for more entries than a move may take, and for a
/// key a move cannot carry: one with a name no client could open, one that
/// lands on a name another takes, or one that spells the name of an entry
/// otherwise.
fn steps_for(
    shared: &Shared,
    root: &Arc<Entry>,
    from: &str,
    to: &str,
    existing: &[Arc<Entry>],
    listed: &[ListedObject],
    heads: &[Option<Arc<ObjectHead>>],
) -> SmbResult<Option<Vec<Step>>> {
    let fold = shared.case_insensitive;
    let held_keys: HashMap<Slot, String> = existing
        .iter()
        .map(|entry| {
            let key = entry.state().write_key();
            (slot(&key, fold), key)
        })
        .collect();
    let mut named: HashSet<Slot> = existing
        .iter()
        .filter(|entry| entry.is_dir())
        .map(|entry| slot(&entry.state().key, fold))
        .collect();
    let mut keys: Vec<String> = existing
        .iter()
        .map(|entry| entry.state().key.clone())
        .collect();
    let mut deleted: Vec<&str> = Vec::new();
    let mut objects: Vec<(&ListedObject, Option<Arc<ObjectHead>>)> = Vec::new();
    for (object, head) in listed.iter().zip(heads) {
        let Some(rest) = below(&object.key, from) else {
            continue;
        };
        if shared.overlay.to_delete(&object.key) {
            deleted.push(&object.key);
            continue;
        }
        if !can_open(rest) {
            return Err(SmbError::AccessDenied);
        }
        keys.push(object.key.clone());
        // An entry that holds the key stands for the object. Another spelling
        // of the key in a held slot is a different object, which would land
        // on the name the entry takes.
        match held_keys.get(&slot(&object.key, fold)) {
            Some(held) if *held == object.key => continue,
            Some(_) => return Err(SmbError::AccessDenied),
            None => {}
        }
        if let Some(dir) = object.key.strip_suffix('/') {
            named.insert(slot(dir, fold));
        }
        objects.push((object, head.clone()));
    }
    if objects.len() + existing.len() > shared.max_dir_rename_objects {
        return Err(SmbError::AccessDenied);
    }

    // The directories the keys imply have a marker object to put at their new
    // place. A directory that only keys to be deleted imply is still there,
    // unless its own marker is to be deleted too.
    let mut implied = implied_dirs(from, keys.iter().map(String::as_str), &named, fold);
    named.extend(implied.iter().map(|dir| slot(dir, fold)));
    implied.extend(
        implied_dirs(from, deleted, &named, fold)
            .into_iter()
            .filter(|dir| {
                !shared.overlay.tombstoned(&dir_prefix(dir))
                    && below(dir, from).is_some_and(can_open)
            }),
    );

    let mut taken: HashSet<Slot> = HashSet::new();
    taken.insert(slot(to, fold));
    let mut place = |key: &str| -> SmbResult<String> {
        let name = below(key, from).ok_or(SmbError::Sharing)?;
        let new = join_key(to, name);
        if dir_prefix(&new).len() > MAX_KEY_LEN {
            return Err(SmbError::NameInvalid);
        }
        if !taken.insert(slot(&new, fold)) {
            return Err(SmbError::AccessDenied);
        }
        Ok(new)
    };
    let mut steps: Vec<Step> =
        Vec::with_capacity(existing.len() + objects.len() + implied.len() + 1);
    for entry in existing {
        let old = entry.state().key.clone();
        let Some(moved) = step(shared, entry, false, &place(&old)?)? else {
            return Ok(None);
        };
        steps.push(moved);
    }
    for (object, head) in &objects {
        let name = object.key.strip_suffix('/').unwrap_or(&object.key);
        let new = place(name)?;
        let entry = fresh_entry(shared, object, head.clone());
        steps.extend(step(shared, &entry, true, &new)?);
    }
    for dir in &implied {
        let new = place(dir)?;
        let entry = Entry::from_state(State::new(dir.clone(), true));
        steps.extend(step(shared, &entry, true, &new)?);
    }
    let Some(last) = step(shared, root, false, to)? else {
        return Ok(None);
    };
    steps.push(last);
    Ok(Some(steps))
}

/// Moves the directory of `held` from `from` to `to`, with the entries
/// `held_entries` the rename holds and the objects `listed` below it: the
/// batch record is written, and then the entries are at their new keys.
/// Returns `None`, having changed nothing, when the entries below the
/// directory are not as the listing left them.
fn commit_dir(
    shared: &Arc<Shared>,
    held: &Held,
    held_entries: &[Arc<Entry>],
    from: &str,
    to: &str,
    listed: &[ListedObject],
    heads: &[Option<Arc<ObjectHead>>],
) -> SmbResult<Option<Committed>> {
    let cache = shared.local()?;
    let root = &held.entry;
    let order: Vec<&Arc<Entry>> = std::iter::once(root).chain(held_entries).collect();
    let locks = Entry::lock_all(&order);
    {
        let state = root.state();
        if state.key != from {
            return Err(SmbError::NotFound);
        }
        state.attached()?;
    }
    // An entry that was renamed away or deleted since it was held is not the
    // directory's any more.
    let existing: Vec<Arc<Entry>> = held_entries
        .iter()
        .filter(|entry| {
            let state = entry.state();
            !state.detached && below(&state.key, from).is_some()
        })
        .cloned()
        .collect();
    let tombs = shared.overlay.lock_tombs();
    let reserved = shared.overlay.reserve(to, root, None)?;
    #[cfg(test)]
    super::jobs::pause_blocking(&shared.jobs.pause_reserved);

    let Some(steps) = steps_for(shared, root, from, to, &existing, listed, heads)? else {
        return Ok(None);
    };
    let mut records = Vec::with_capacity(steps.len());
    let mut files = Vec::new();
    let mut moves: Vec<Moved> = Vec::with_capacity(steps.len());
    for step in steps {
        records.push(step.record);
        files.extend(step.data);
        moves.push(step.moved);
    }
    let record = BatchRecord {
        id: new_id().map_err(SmbError::Io)?,
        members: records,
    };
    let text = record.encode();
    if text.len() as u64 > MAX_RECORD_LEN {
        return Err(SmbError::AccessDenied);
    }
    let mut first = false;
    for (file, is_first) in &files {
        file.sync_all().map_err(disk_error)?;
        first |= is_first;
    }
    if first {
        cache.sync_data_dir().map_err(disk_error)?;
    }
    // The names below the directory and below its new place are fenced and the
    // entries are locked, so what holds now holds when the move is made. The
    // fence keeps `moved_dir` from failing once the batch record is written,
    // and the branch for a failure guards it, since the record is already on
    // disk.
    if !shared.overlay.can_move_dir(&moves, &existing) {
        return Ok(None);
    }
    cache.write_record(&record.id, &text).map_err(disk_error)?;

    let batch = Arc::new(Batch::new(record));
    if !shared.overlay.moved_dir(&moves, &batch, &existing) {
        error!("the entries of a directory could not be moved after its batch record was written");
        batch.finish(cache).map_err(disk_error)?;
        return Ok(None);
    }
    let members: Vec<Arc<Entry>> = moves.into_iter().map(|moved| moved.entry).collect();
    drop(reserved);
    drop(tombs);
    drop(locks);

    announce(shared, from, to, root);
    Ok(Some(Committed { batch, members }))
}

/// Lets the caches and the keys to delete know of the move: the directory is
/// in its new place, and the marker key it takes is not to be deleted.
fn announce(shared: &Shared, from: &str, to: &str, root: &Arc<Entry>) {
    {
        let mut cache = shared.cache();
        cache.put_known(to, Known::Dir(None), tokio::time::Instant::now());
        cache.add_row(
            parent_key(to),
            Row {
                name: last_name(to).to_owned(),
                kind: RowKind::Dir,
            },
        );
    }
    shared.deleted(from);
    if let Err(e) = outcome::take_over(shared, root, &dir_prefix(to), &shared.jobs.stop) {
        warn!(error = %e, "the keys to delete that name the marker of a moved directory could not be let go; its job lets them go");
    }
}

/// Gives the entries of a batch records of their own, takes the batch away,
/// and lets the entries run. A full disk makes it rest and try again. A
/// backend that ends first leaves the batch for the next one to read.
async fn dissolve(shared: Arc<Shared>, batch: Arc<Batch>, members: Arc<[Arc<Entry>]>) {
    #[cfg(test)]
    super::jobs::pause(&shared.jobs.pause_batch).await;
    #[cfg(test)]
    shared
        .jobs
        .panic_dissolve
        .check("a test made the dissolve task panic");
    let mut next = 0;
    loop {
        let (task_shared, task_batch, task_members) = (
            Arc::clone(&shared),
            Arc::clone(&batch),
            Arc::clone(&members),
        );
        let written = spawn_blocking(move || {
            let result = write_members(&task_shared, &task_batch, &task_members, &mut next);
            (next, result)
        })
        .await;
        let failure = match written {
            Ok((_, Ok(true))) => {
                shared.overlay.release_batch(&members, &batch);
                return;
            }
            Ok((_, Ok(false))) => return,
            Ok((at, Err(SmbError::DiskFull))) => {
                next = at;
                warn!(
                    "the disk of the cache directory is full; the entries of a renamed directory are recorded again after a rest"
                );
                tokio::select! {
                    () = tokio::time::sleep(FULL_DISK_REST) => continue,
                    () = shared.jobs.stop.stopped() => return,
                }
            }
            Ok((_, Err(e))) => S3Error::cache(e),
            Err(e) => S3Error::transport(e),
        };
        error!(
            error = %failure,
            "the entries of a renamed directory could not be recorded; they are tried again when the next backend is built"
        );
        shared.overlay.fail_batch(&members, &batch, &failure);
        return;
    }
}

/// Writes the record of each of `members` from the one at `next` on, and then
/// removes the batch record. Returns `false` without finishing when the
/// backend ends. `next` is where the work stopped if it fails.
fn write_members(
    shared: &Shared,
    batch: &Arc<Batch>,
    members: &[Arc<Entry>],
    next: &mut usize,
) -> SmbResult<bool> {
    let cache = shared.local()?;
    // A batch record that lacks an entry that came back must list it before
    // any entry has a record of its own, and whether or not the backend ends.
    batch.flush(cache).map_err(disk_error)?;
    while let Some(entry) = members.get(*next) {
        if shared.jobs.stop.is_stopped() {
            return Ok(false);
        }
        record_member(shared, batch, entry)?;
        *next += 1;
    }
    batch.finish(cache).map_err(disk_error)?;
    Ok(true)
}

/// Writes the record of `entry`, unless it has nothing to keep, another batch
/// holds it now, or it left the overlay: the id of an entry that was unlinked
/// or replaced names a tombstone record. An entry that has a record of an
/// earlier place and nothing left to do, as after a rename back, loses that
/// record.
fn record_member(shared: &Shared, batch: &Arc<Batch>, entry: &Arc<Entry>) -> SmbResult<()> {
    let _io = entry.lock_io();
    let _seal = entry.lock_seal();
    let (idle, id) = {
        let state = entry.state();
        if state.detached || !state.in_batch(batch) || !state.pending() {
            return Ok(());
        }
        (!state.has_work(), state.id.clone())
    };
    if idle {
        if let Some(id) = id {
            shared.local()?.remove_record(&id).map_err(disk_error)?;
        }
        entry.state().settled();
        recount_source(shared, entry);
        return Ok(());
    }
    match persist_held(shared, entry, true) {
        Ok(()) => {}
        Err(SmbError::AccessDenied) => {
            if !entry.state().detached {
                warn!("the record of a moved entry could not be written");
            }
        }
        Err(e) => return Err(e),
    }
    Ok(())
}

/// Reads the metadata of the objects that the files of `members` copy from
/// and a listing described, a few at a time, so their times show before their
/// jobs run. The copy job reads the metadata of a base that is still bare.
async fn read_bases(shared: Arc<Shared>, members: Arc<[Arc<Entry>]>) {
    let limit = shared.jobs.concurrency * 4;
    let mut reading: JoinSet<()> = JoinSet::new();
    for entry in members.iter() {
        let key = {
            let state = entry.state();
            match &state.base {
                Some(base) if base.bare && !state.is_dir() && !state.detached => base.key.clone(),
                _ => continue,
            }
        };
        while reading.len() >= limit {
            logged(reading.join_next().await);
        }
        if shared.jobs.stop.is_stopped() {
            break;
        }
        reading.spawn(read_base(Arc::clone(&shared), Arc::clone(entry), key));
    }
    while let Some(ended) = reading.join_next().await {
        logged(Some(ended));
    }
}

/// Logs the panic of a task of `read_bases`, if that is how it ended.
fn logged(ended: Option<Result<(), JoinError>>) {
    if let Some(Err(e)) = ended {
        error!(error = %e, "the times of an object of a renamed directory could not be read");
    }
}

/// Gives `entry` the metadata of the object `key` it copies from, if the
/// object is the one the listing described. The copy job deals with a base
/// that differs.
async fn read_base(shared: Arc<Shared>, entry: Arc<Entry>, key: String) {
    #[cfg(test)]
    shared
        .jobs
        .panic_read_base
        .check("a test made a read of an object panic");
    let Ok(found) = shared
        .client
        .head_object(&key, Retry::until(&shared.jobs.stop))
        .await
    else {
        return;
    };
    let mut state = entry.state();
    let same = state
        .base
        .as_ref()
        .is_some_and(|base| base.head.same_object(&found));
    if same && !state.detached {
        state.complete_base(&shared.ahead, &key, Arc::new(found));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::s3::cachedir::RecordOp;

    fn named(dirs: &[&str]) -> HashSet<Slot> {
        dirs.iter().map(|dir| slot(dir, false)).collect()
    }

    #[test]
    fn a_key_is_below_a_directory_by_a_slash_and_a_name() {
        assert_eq!(below("a/b", "a"), Some("b"));
        assert_eq!(below("a/b/c/", "a"), Some("b/c/"));
        assert_eq!(below("a/", "a"), None);
        assert_eq!(below("a", "a"), None);
        assert_eq!(below("ab/c", "a"), None);
        assert_eq!(below("x", "a/b"), None);
    }

    #[test]
    fn the_directories_between_a_root_and_its_keys_are_those_no_marker_names() {
        let keys = ["d/a/b/f", "d/a/g", "d/c/", "d/h"];
        let dirs = implied_dirs("d", keys, &named(&["d/c"]), false);
        assert_eq!(dirs, ["d/a", "d/a/b"]);
        let dirs = implied_dirs("d", keys, &named(&["d/a", "d/c"]), false);
        assert_eq!(dirs, ["d/a/b"]);
        assert!(implied_dirs("d", ["d/f"], &named(&[]), false).is_empty());
    }

    #[test]
    fn directories_that_differ_in_case_are_one_directory_when_case_is_ignored() {
        let dirs = implied_dirs("d", ["d/A/f", "d/a/g"], &named(&[]), true);
        assert_eq!(dirs.len(), 1);
        assert!(implied_dirs("d", ["d/A/f"], &named(&["d/a"]), true).is_empty());
        assert_eq!(
            implied_dirs("d", ["d/A/f", "d/a/g"], &named(&[]), false).len(),
            2
        );
    }

    fn member(path: &str) -> EntryRecord {
        let mut state = State::new(path.to_owned(), false);
        Entry::record(&mut state, "", std::time::SystemTime::UNIX_EPOCH).unwrap()
    }

    /// How many entries the batch record on disk lists, if it is there.
    fn listed(cache: &CacheDir, record: &BatchRecord) -> Option<usize> {
        cache.batch_members(&record.id).map(|ids| ids.len())
    }

    fn written(cache: &CacheDir, members: Vec<EntryRecord>) -> (Arc<Batch>, BatchRecord) {
        let record = BatchRecord {
            id: new_id().unwrap(),
            members,
        };
        cache.write_record(&record.id, &record.encode()).unwrap();
        (Arc::new(Batch::new(record.clone())), record)
    }

    /// How many times the record `id` was written since the log was cleared.
    fn writes_of(cache: &CacheDir, id: &RecordId) -> usize {
        let ops = cache.hooks.record_ops.lock().unwrap();
        ops.iter()
            .filter(|(op, held)| *op == RecordOp::Write && held == id)
            .count()
    }

    /// The ids of the members of the batch record on disk, in order.
    fn listed_ids(cache: &CacheDir, record: &BatchRecord) -> Vec<RecordId> {
        cache
            .batch_members(&record.id)
            .expect("the record is there")
    }

    #[test]
    fn a_batch_record_is_rewritten_without_a_canceled_entry_and_removed_with_the_last() {
        let temp = tempfile::tempdir().unwrap();
        let cache = CacheDir::open(temp.path(), "identity").unwrap();
        let (a, b) = (member("d/a"), member("d/b"));
        let (batch, record) = written(&cache, vec![a.clone(), b.clone()]);

        batch.cancel(&cache, &a.id).unwrap();
        assert_eq!(listed(&cache, &record), Some(1));
        batch.cancel(&cache, &a.id).unwrap();
        assert_eq!(listed(&cache, &record), Some(1), "twice is once");
        batch.cancel(&cache, &b.id).unwrap();
        assert_eq!(
            listed(&cache, &record),
            None,
            "the last entry takes it along"
        );
        batch.cancel(&cache, &b.id).unwrap();
    }

    #[test]
    fn an_entry_stays_in_the_batch_when_its_record_cannot_be_written_without_it() {
        let temp = tempfile::tempdir().unwrap();
        let cache = CacheDir::open(temp.path(), "identity").unwrap();
        let (a, b) = (member("d/a"), member("d/b"));
        let (batch, record) = written(&cache, vec![a.clone(), b]);

        cache
            .hooks
            .record_writes
            .store(1, std::sync::atomic::Ordering::SeqCst);
        assert!(batch.cancel(&cache, &a.id).is_err());
        assert_eq!(listed(&cache, &record), Some(2));
        batch.cancel(&cache, &a.id).unwrap();
        assert_eq!(listed(&cache, &record), Some(1), "it was still a member");
    }

    #[test]
    fn entries_covered_by_tombstones_leave_the_batch_record_in_one_rewrite() {
        let temp = tempfile::tempdir().unwrap();
        let cache = CacheDir::open(temp.path(), "identity").unwrap();
        let members = vec![member("d/a"), member("d/b"), member("d/c")];
        let (batch, record) = written(&cache, members.clone());
        cache.hooks.record_ops.lock().unwrap().clear();

        batch.cover(&members[0].id).unwrap();
        batch.cover(&members[1].id).unwrap();
        assert_eq!(listed(&cache, &record), Some(3), "nothing is written yet");
        assert_eq!(writes_of(&cache, &record.id), 0);
        batch.flush(&cache).unwrap();
        assert_eq!(listed(&cache, &record), Some(1));
        assert_eq!(writes_of(&cache, &record.id), 1, "one rewrite for both");
        cache.remove_record(&record.id).unwrap();
        batch.flush(&cache).unwrap();
        assert_eq!(
            listed(&cache, &record),
            None,
            "a flush with nothing new writes nothing"
        );
        assert_eq!(writes_of(&cache, &record.id), 1);
    }

    #[test]
    fn a_canceled_member_goes_back_where_it_stood_and_the_record_says_so() {
        let temp = tempfile::tempdir().unwrap();
        let cache = CacheDir::open(temp.path(), "identity").unwrap();
        let members = vec![member("d/a"), member("d/b"), member("d/c")];
        let ids: Vec<RecordId> = members.iter().map(|m| m.id.clone()).collect();
        let (batch, record) = written(&cache, members);

        let left = batch.cancel(&cache, &ids[1]).unwrap().unwrap();
        assert_eq!(
            listed_ids(&cache, &record),
            [ids[0].clone(), ids[2].clone()]
        );
        Batch::rejoin(left, &cache).unwrap();
        assert_eq!(listed_ids(&cache, &record), ids);
    }

    #[test]
    fn the_last_member_that_left_brings_the_record_back() {
        let temp = tempfile::tempdir().unwrap();
        let cache = CacheDir::open(temp.path(), "identity").unwrap();
        let only = member("d/a");
        let (batch, record) = written(&cache, vec![only.clone()]);

        let left = batch.cancel(&cache, &only.id).unwrap().unwrap();
        assert_eq!(listed(&cache, &record), None);
        Batch::rejoin(left, &cache).unwrap();
        assert_eq!(listed_ids(&cache, &record), [only.id]);
    }

    #[test]
    fn a_covered_member_goes_back_without_a_write_unless_the_record_was_written_meanwhile() {
        let temp = tempfile::tempdir().unwrap();
        let cache = CacheDir::open(temp.path(), "identity").unwrap();
        let members = vec![member("d/a"), member("d/b"), member("d/c")];
        let ids: Vec<RecordId> = members.iter().map(|m| m.id.clone()).collect();
        let (batch, record) = written(&cache, members);
        cache.hooks.record_ops.lock().unwrap().clear();

        let left = batch.cover(&ids[0]).unwrap();
        Batch::rejoin(left, &cache).unwrap();
        assert_eq!(writes_of(&cache, &record.id), 0);
        assert_eq!(listed_ids(&cache, &record), ids);

        let left = batch.cover(&ids[0]).unwrap();
        batch.cover(&ids[2]).unwrap();
        batch.flush(&cache).unwrap();
        assert_eq!(listed_ids(&cache, &record), [ids[1].clone()]);
        Batch::rejoin(left, &cache).unwrap();
        assert_eq!(
            listed_ids(&cache, &record),
            [ids[0].clone(), ids[1].clone()]
        );
    }

    #[test]
    fn a_member_does_not_go_back_into_a_batch_that_is_over() {
        let temp = tempfile::tempdir().unwrap();
        let cache = CacheDir::open(temp.path(), "identity").unwrap();
        let members = vec![member("d/a"), member("d/b")];
        let (batch, record) = written(&cache, members.clone());
        let left = batch.cover(&members[0].id).unwrap();
        batch.finish(&cache).unwrap();
        Batch::rejoin(left, &cache).unwrap();
        assert_eq!(listed(&cache, &record), None);

        let only = member("d/c");
        let (batch, record) = written(&cache, vec![only.clone()]);
        let left = batch.cancel(&cache, &only.id).unwrap().unwrap();
        batch.finish(&cache).unwrap();
        Batch::rejoin(left, &cache).unwrap();
        assert_eq!(listed(&cache, &record), None, "the record stays removed");
    }
}
