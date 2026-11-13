//! Changes to the files and directories of a writable backend.
//!
//! Each change runs as one task on a blocking thread, so a request that is
//! dropped halfway leaves nothing half done. The task takes the `io` and
//! `seal` locks of the entry that protect what it changes, in that order, and
//! keeps them until the data file or the record is whole again. A change to an
//! entry that left the overlay fails.

use std::fs::File;
use std::io;
use std::sync::{Arc, MutexGuard};
use std::time::SystemTime;

use tokio::task::spawn_blocking;
use tracing::{debug, warn};

use crate::backend::{FileTimes, VALID_SET_ATTRIBUTES};
use crate::error::{SmbError, SmbResult};
use crate::utils::now_filetime;

use super::backend::Shared;
use super::cache::Known;
use super::cachedir::CacheDir;
use super::data::disk_error;
use super::entry::{Base, Entry, Local, Own, Sealed, State};
use super::error::S3Error;
use super::keys::{RowKind, dir_prefix};
use super::object::{Metadata, ObjectHead};
use super::outcome;
use super::overlay::{Held, TombsHeld};
use super::payload::Payload;
use super::ranges::RangeSet;
use super::record::{EntryRecord, LocalRecord, RecordId};
use super::retry::Retry;
use super::unlink::drop_superseded;

/// Runs `work` on a blocking thread, for `held`: the entry stays in the
/// overlay until it is done, even if the request that asked for it is
/// dropped.
async fn blocking<T: Send + 'static>(
    shared: &Arc<Shared>,
    held: &Held,
    work: impl FnOnce(&Shared, &Arc<Entry>) -> SmbResult<T> + Send + 'static,
) -> SmbResult<T> {
    let (shared, task) = (Arc::clone(shared), held.another());
    spawn_blocking(move || work(&shared, &task.entry))
        .await
        .map_err(|e| SmbError::Io(io::Error::other(e)))?
}

/// Runs `apply` on the state of the entry if the entry is still in the
/// overlay. If it is not, the record just written for it, `record`, is
/// removed.
fn commit<T>(
    cache: &CacheDir,
    entry: &Entry,
    record: Option<&RecordId>,
    apply: impl FnOnce(&mut State) -> T,
) -> SmbResult<T> {
    let mut state = entry.state();
    match state.attached() {
        Ok(()) => Ok(apply(&mut state)),
        Err(e) => {
            drop(state);
            if let Some(id) = record {
                let _ = cache.remove_record(id);
            }
            Err(e)
        }
    }
}

/// [`commit`] for a change that may have written `record`. If it did, the
/// state also notes the record, and the overlay counts the source of the entry
/// again and drops the key of the entry from the keys to delete. A caller that
/// holds the lock of the keys to delete passes it as `tombs`.
fn commit_record(
    shared: &Shared,
    entry: &Arc<Entry>,
    record: Option<&EntryRecord>,
    tombs: TombsHeld<'_>,
    apply: impl FnOnce(&mut State),
) -> SmbResult<()> {
    let cache = shared.local()?;
    commit(cache, entry, record.map(|record| &record.id), |state| {
        apply(state);
        if let Some(record) = record {
            state.set_recorded(record);
        }
    })?;
    if record.is_some() {
        recount_source(shared, entry);
        superseded(shared, entry, tombs);
    }
    Ok(())
}

/// Writes `data` at `offset`, making the local data of the entry if it has
/// none. Bytes between the end of the file and `offset` read as zeros.
pub(super) async fn write(
    shared: &Arc<Shared>,
    held: &Held,
    offset: u64,
    data: Vec<u8>,
) -> SmbResult<u32> {
    if held.entry.is_dir() {
        return Err(SmbError::IsDirectory);
    }
    let len = u32::try_from(data.len()).map_err(|_| SmbError::InvalidParameter)?;
    if len == 0 {
        return Ok(0);
    }
    offset
        .checked_add(u64::from(len))
        .ok_or(SmbError::InvalidParameter)?;
    blocking(shared, held, move |shared, entry| {
        write_data(shared, entry, offset, &data)
    })
    .await?;
    Ok(len)
}

fn write_data(shared: &Shared, entry: &Entry, offset: u64, data: &[u8]) -> SmbResult<()> {
    let cache = shared.local()?;
    let _io = entry.lock_io();
    let file = ensure_local(cache, entry, None)?;
    let end = offset + data.len() as u64;
    if let Err(e) = cache.write_data(&file, data, offset) {
        // Part of the bytes may be in the file. The next flush has to sync
        // them, and a file the write made longer is cut back.
        let mut state = entry.state();
        state.bump();
        let len = state.local().map(|local| local.len);
        drop(state);
        if let Some(len) = len.filter(|&len| end > len) {
            let _ = file.set_len(len);
        }
        return Err(disk_error(e));
    }
    let now = now_filetime();
    commit(cache, entry, None, |state| {
        if let Some(local) = state.local_mut() {
            if offset > local.len {
                local.present.insert(local.len..offset);
            }
            local.present.insert(offset..end);
            local.len = local.len.max(end);
        }
        state.wrote(shared.built, now);
    })
}

/// The data file of the entry, made if the entry has none: `len` bytes long
/// with none of them present, or as long as the entry. The caller holds the
/// `io` lock.
pub(super) fn ensure_local(
    cache: &CacheDir,
    entry: &Entry,
    len: Option<u64>,
) -> SmbResult<Arc<File>> {
    let (id, len) = {
        let mut state = entry.state();
        if entry.is_dir() {
            return Err(SmbError::IsDirectory);
        }
        state.attached()?;
        if let Some(local) = state.local() {
            return Ok(Arc::clone(&local.file));
        }
        let len = len.unwrap_or_else(|| state.size());
        (state.id().map_err(SmbError::Io)?, len)
    };
    let file = Arc::new(cache.create_data(&id, len).map_err(disk_error)?);
    let mut state = entry.state();
    if let Err(e) = state.attached() {
        drop(state);
        let _ = cache.remove_data(&id);
        return Err(e);
    }
    state.set_local(Local {
        file: Arc::clone(&file),
        len,
        present: RangeSet::new(),
    });
    Ok(file)
}

/// Sets the length of the file to `len`. Bytes added read as zeros.
pub(super) async fn truncate(shared: &Arc<Shared>, held: &Held, len: u64) -> SmbResult<()> {
    blocking(shared, held, move |shared, entry| {
        set_len(shared, entry, len, false)
    })
    .await
}

/// Empties the file, as an open that overwrites it does.
pub(super) async fn overwrite(shared: &Arc<Shared>, held: &Held) -> SmbResult<()> {
    blocking(shared, held, |shared, entry| {
        set_len(shared, entry, 0, true)
    })
    .await
}

/// Sets the length of the file to `new_len`. With `force`, a file already
/// `new_len` long still counts as written: its write and change times move.
fn set_len(shared: &Shared, entry: &Arc<Entry>, new_len: u64, force: bool) -> SmbResult<()> {
    let cache = shared.local()?;
    let _io = entry.lock_io();
    let old_len = {
        let state = entry.state();
        state.attached()?;
        state.size()
    };
    if new_len == old_len && !force {
        return Ok(());
    }
    let now = now_filetime();
    // The bytes that stay are those of the base.
    let file = ensure_local(cache, entry, Some(new_len.min(old_len)))?;

    if new_len >= old_len {
        if new_len > old_len {
            file.set_len(new_len).map_err(disk_error)?;
        }
        return commit(cache, entry, None, |state| {
            if let Some(local) = state.local_mut().filter(|_| new_len > old_len) {
                local.len = new_len;
                local.present.insert(old_len..new_len);
            }
            state.wrote(shared.built, now);
        });
    }

    // The file shrinks. A record that claims bytes past the new length is
    // replaced first, so no record claims bytes that are gone.
    let _seal = entry.lock_seal();
    let sealed_len = entry.state().sealed().map(|sealed| sealed.len);
    let mut replaced = None;
    if sealed_len.is_some_and(|len| new_len < len) {
        let record = {
            let mut state = entry.state();
            state.attached()?;
            let mut record =
                Entry::record(&mut state, &shared.prefix, shared.built).map_err(SmbError::Io)?;
            let mut present = state
                .local()
                .map(|local| local.present.clone())
                .unwrap_or_default();
            present.truncate(new_len);
            record.local = Some(LocalRecord {
                len: new_len,
                present,
            });
            record.generation = state.generation + 1;
            record.times[2] = now;
            record.times[3] = now;
            record.meta_pending = true;
            record
        };
        file.sync_all().map_err(disk_error)?;
        write_record(cache, &record)?;
        replaced = Some(record);
    }
    file.set_len(new_len).map_err(disk_error)?;
    commit_record(shared, entry, replaced.as_ref(), None, |state| {
        if let Some(local) = state.local_mut() {
            local.len = new_len;
            local.present.truncate(new_len);
        }
        state.wrote(shared.built, now);
        if let Some(record) = &replaced {
            state.set_sealed(Sealed {
                generation: record.generation,
                len: new_len,
            });
        }
    })
}

fn write_record(cache: &CacheDir, record: &EntryRecord) -> SmbResult<()> {
    cache
        .write_record(&record.id, &record.encode())
        .map_err(disk_error)
}

/// Makes the local data of the entry durable and records it. An entry
/// without local data has nothing to do.
pub(super) async fn flush(shared: &Arc<Shared>, held: &Held) -> SmbResult<()> {
    if held.entry.state().local().is_none() {
        return Ok(());
    }
    blocking(shared, held, |shared, entry| seal(shared, entry, false)).await
}

/// Writes the record of the entry once the data it claims is on disk. The
/// record says what the entry held when this started, so it never claims a
/// byte the data file did not have by then. The first record of an entry
/// also syncs, on Unix hosts, the directory of the data files.
///
/// A record sealed at the current generation is not written again unless
/// `force`.
pub(super) fn seal(shared: &Shared, entry: &Arc<Entry>, force: bool) -> SmbResult<()> {
    let _seal = entry.lock_seal();
    seal_held(shared, entry, force)
}

/// [`seal`] for a caller that holds the `seal` lock of the entry.
pub(super) fn seal_held(shared: &Shared, entry: &Arc<Entry>, force: bool) -> SmbResult<()> {
    seal_with(shared, entry, force, None, None)
}

/// [`seal_held`] that also makes `gone`, when given, the keys the entry owns to
/// delete: the record says so, and the entry takes it in once the record is
/// written. A caller that holds the lock of the keys to delete passes it as
/// `tombs`.
fn seal_with(
    shared: &Shared,
    entry: &Arc<Entry>,
    force: bool,
    gone: Option<Vec<String>>,
    tombs: TombsHeld<'_>,
) -> SmbResult<()> {
    let cache = shared.local()?;
    let (file, mut record, first) = {
        let mut state = entry.state();
        state.attached()?;
        let Some(local) = state.local() else {
            return Ok(());
        };
        let file = Arc::clone(&local.file);
        let sealed = state.sealed();
        if !force && sealed.is_some_and(|sealed| sealed.generation == state.generation) {
            return Ok(());
        }
        let record =
            Entry::record(&mut state, &shared.prefix, shared.built).map_err(SmbError::Io)?;
        (file, record, sealed.is_none())
    };
    if let Some(gone) = &gone {
        record.gone.clone_from(gone);
    }
    let sealed = Sealed {
        generation: record.generation,
        len: record.local.as_ref().map_or(0, |local| local.len),
    };
    file.sync_all().map_err(disk_error)?;
    if first {
        cache.sync_data_dir().map_err(disk_error)?;
    }
    write_record(cache, &record)?;
    commit_record(shared, entry, Some(&record), tombs, |state| {
        state.set_sealed(sealed);
        if let Some(gone) = gone {
            state.gone = gone;
        }
    })
}

/// Recounts the key the entry copies from after a record write or removal
/// changed it, and wakes the entries that wait for a key it let go.
pub(super) fn recount_source(shared: &Shared, entry: &Arc<Entry>) {
    let changed = {
        let state = entry.state();
        state.counted.source.as_deref() != state.source()
    };
    if changed {
        shared.overlay.track(entry);
    }
}

/// Writes the record of the entry as it is now, sealing its local data if it
/// has some.
pub(super) fn persist(shared: &Shared, entry: &Arc<Entry>, force: bool) -> SmbResult<()> {
    let _seal = entry.lock_seal();
    persist_held(shared, entry, force)
}

/// [`persist`] for a caller that holds the `seal` lock of the entry.
pub(super) fn persist_held(shared: &Shared, entry: &Arc<Entry>, force: bool) -> SmbResult<()> {
    persist_with(shared, entry, force, None, None)
}

/// [`persist_held`] for a caller that holds the lock of the keys to delete,
/// which it passes as `tombs`.
pub(super) fn persist_locked(
    shared: &Shared,
    entry: &Arc<Entry>,
    tombs: &MutexGuard<'_, ()>,
) -> SmbResult<()> {
    persist_with(shared, entry, true, None, Some(tombs))
}

/// [`persist_held`] that also makes `gone`, when given, the keys the entry owns
/// to delete: the record says so, and the entry takes it in once the record is
/// written. If the record cannot be written the entry is as it was. A caller
/// that holds the lock of the keys to delete passes it as `tombs`.
pub(super) fn persist_with(
    shared: &Shared,
    entry: &Arc<Entry>,
    force: bool,
    gone: Option<Vec<String>>,
    tombs: TombsHeld<'_>,
) -> SmbResult<()> {
    if entry.state().local().is_some() {
        seal_with(shared, entry, force, gone, tombs)
    } else {
        record_with(shared, entry, gone, tombs)
    }
}

/// Takes the key of the entry off the record of the keys to delete that names
/// it, now that the entry has a record of its own. The caller holds the
/// `seal` lock of the entry, so the entry stays in the overlay meanwhile, and
/// passes the lock of the keys to delete as `tombs` if it holds it.
pub(super) fn superseded(shared: &Shared, entry: &Entry, tombs: TombsHeld<'_>) {
    let key = {
        let state = entry.state();
        if state.detached || state.is_dir() {
            return;
        }
        state.key.clone()
    };
    if shared.overlay.tomb_named(&key) {
        drop_superseded(shared, &[key], tombs);
    }
}

/// [`outcome::take_over`] for the marker object of the new directory `key` of
/// `held`, which has just been put.
pub(super) async fn take_over_marker(
    shared: &Arc<Shared>,
    held: &Held,
    key: &str,
) -> SmbResult<bool> {
    let marker = dir_prefix(key);
    blocking(shared, held, move |shared, entry| {
        outcome::take_over(shared, entry, &marker, &shared.jobs.stop)
    })
    .await
}

/// Writes the record of the entry as it is now.
pub(super) async fn record(shared: &Arc<Shared>, held: &Held) -> SmbResult<()> {
    blocking(shared, held, record_now).await
}

/// Writes the record of the entry as it is now, on the calling thread.
pub(super) fn record_now(shared: &Shared, entry: &Arc<Entry>) -> SmbResult<()> {
    let _seal = entry.lock_seal();
    record_held(shared, entry)
}

/// [`record_now`] for a caller that holds the `seal` lock of the entry.
pub(super) fn record_held(shared: &Shared, entry: &Arc<Entry>) -> SmbResult<()> {
    record_with(shared, entry, None, None)
}

/// [`record_held`] that also makes `gone`, when given, the keys the entry owns
/// to delete, as [`persist_with`] does.
fn record_with(
    shared: &Shared,
    entry: &Arc<Entry>,
    gone: Option<Vec<String>>,
    tombs: TombsHeld<'_>,
) -> SmbResult<()> {
    let cache = shared.local()?;
    let mut record = {
        let mut state = entry.state();
        state.attached()?;
        Entry::record(&mut state, &shared.prefix, shared.built).map_err(SmbError::Io)?
    };
    if let Some(gone) = &gone {
        record.gone.clone_from(gone);
    }
    write_record(cache, &record)?;
    commit_record(shared, entry, Some(&record), tombs, |state| {
        if let Some(gone) = gone {
            state.gone = gone;
        }
    })
}

/// Puts the marker object of the directory `key` with `metadata`, and makes
/// the metadata cache hold the directory. A marker the store refuses because
/// the directory is there already counts as put, and the answer is `None`.
pub(super) async fn store_marker(
    shared: &Shared,
    key: &str,
    metadata: Metadata,
    retry: Retry,
) -> Result<Option<Arc<ObjectHead>>, S3Error> {
    let put = shared
        .client
        .put_object(&dir_prefix(key), Payload::empty(), &metadata, retry)
        .await;
    let head = match put {
        Ok(etag) => Some(Arc::new(ObjectHead {
            size: 0,
            etag,
            last_modified: SystemTime::now(),
            metadata,
        })),
        Err(e) if e.code() == Some("ExistingObjectIsDirectory") => {
            debug!(key, "the store has a directory where a marker was to go");
            None
        }
        Err(e) => return Err(e),
    };
    shared.remember(key, Known::Dir(head.clone()), RowKind::Dir);
    Ok(head)
}

/// Notes that the marker object of the new directory `key` is in the bucket,
/// as `head` describes it, or that the store has the directory without one.
/// If nothing about the directory changed since `generation`, the directory
/// has nothing left to keep: its record is removed and its own times are
/// dropped. Otherwise its record is rewritten.
///
/// A directory changes only through the `seal` lock, which is held here, so
/// the generation cannot move while this runs.
///
/// Returns whether the directory took the marker in: a directory that moved to
/// another key meanwhile took nothing in, and its marker at the new key is
/// still to be put.
pub(super) async fn marker_put(
    shared: &Arc<Shared>,
    held: &Held,
    generation: u64,
    key: &str,
    head: Option<Arc<ObjectHead>>,
) -> SmbResult<bool> {
    let marker = dir_prefix(key);
    blocking(shared, held, move |shared, entry| {
        let cache = shared.local()?;
        let _seal = entry.lock_seal();
        let (unchanged, id, keeps_keys) = {
            let mut state = entry.state();
            state.attached()?;
            if !state.is_write_key(&marker) {
                state.creating = false;
                return Ok(false);
            }
            (
                state.generation == generation,
                state.id.clone(),
                !state.gone.is_empty(),
            )
        };
        let gone = match id.filter(|_| unchanged && !keeps_keys) {
            Some(id) => match cache.remove_record(&id) {
                Ok(()) => true,
                Err(e) => {
                    warn!(error = %e, "the record of a new directory could not be removed");
                    false
                }
            },
            None => false,
        };
        let record = {
            let mut state = entry.state();
            state.creating = false;
            state.set_marker_pending(false);
            state.may_exist = true;
            state.base = head.map(|head| Base::new(&shared.ahead, marker, head, false));
            if gone || (unchanged && keeps_keys) {
                state.own = None;
            }
            if gone {
                state.recorded = false;
                return Ok(true);
            }
            Entry::record(&mut state, &shared.prefix, shared.built).map_err(SmbError::Io)?
        };
        write_record(cache, &record)?;
        entry.state().recorded = true;
        Ok(true)
    })
    .await
}

/// Takes back a directory made but not put: its record is removed, and the
/// entry holds nothing. If the record cannot be removed, the entry stays as it
/// is. A directory that was deleted meanwhile keeps its record, which is the
/// tombstone record of its keys to delete by then.
pub(super) async fn abandon(shared: &Arc<Shared>, held: &Held) -> SmbResult<()> {
    blocking(shared, held, |shared, entry| {
        let cache = shared.local()?;
        let _seal = entry.lock_seal();
        let id = {
            let state = entry.state();
            if state.detached {
                return Ok(());
            }
            state.id.clone()
        };
        if let Some(id) = id {
            cache.remove_record(&id).map_err(disk_error)?;
        }
        let mut state = entry.state();
        state.creating = false;
        state.set_marker_pending(false);
        state.own = None;
        state.recorded = false;
        Ok(())
    })
    .await
}

/// Sets the times of the entry. Times not given stay.
pub(super) async fn set_times(
    shared: &Arc<Shared>,
    held: &Held,
    times: FileTimes,
) -> SmbResult<()> {
    if times == FileTimes::default() {
        return Ok(());
    }
    blocking(shared, held, move |shared, entry| {
        change_own(shared, entry, |own| apply_times(own, times))
    })
    .await
}

pub(super) fn apply_times(own: &mut Own, times: FileTimes) {
    for (slot, time) in own.times.iter_mut().zip([
        times.creation_time,
        times.last_access_time,
        times.last_write_time,
        times.change_time,
    ]) {
        if let Some(time) = time {
            *slot = time;
        }
    }
}

/// Sets the attributes of the entry to `attributes`, less those a client
/// cannot set.
pub(super) async fn set_attributes(
    shared: &Arc<Shared>,
    held: &Held,
    attributes: u32,
) -> SmbResult<()> {
    blocking(shared, held, move |shared, entry| {
        change_own(shared, entry, |own| apply_attributes(own, attributes))
    })
    .await
}

pub(super) fn apply_attributes(own: &mut Own, attributes: u32) {
    own.attributes = attributes & VALID_SET_ATTRIBUTES;
}

/// Changes the times or attributes of the entry, and its change time unless
/// `change` sets that. An entry without local data has its record written
/// before this returns; with local data, the record follows at the next
/// flush.
fn change_own(shared: &Shared, entry: &Arc<Entry>, change: impl FnOnce(&mut Own)) -> SmbResult<()> {
    let cache = shared.local()?;
    let _io = entry.lock_io();
    let _seal = entry.lock_seal();
    let (own, record) = {
        let mut state = entry.state();
        state.attached()?;
        let current = state.own_or_base(shared.built);
        let mut own = current;
        change(&mut own);
        if !own.changed_from(&current) {
            return Ok(());
        }
        if state.local().is_some() {
            state.own = Some(own);
            state.bump();
            return Ok(());
        }
        let mut record =
            Entry::record(&mut state, &shared.prefix, shared.built).map_err(SmbError::Io)?;
        record.times = own.times;
        record.attributes = own.attributes;
        record.meta_pending = true;
        record.generation += 1;
        (own, record)
    };
    write_record(cache, &record)?;
    commit_record(shared, entry, Some(&record), None, |state| {
        state.own = Some(own);
        state.bump();
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn times_and_attributes_not_given_stay() {
        let mut own = Own {
            times: [1, 2, 3, 4],
            attributes: 0x21,
        };
        apply_times(
            &mut own,
            FileTimes {
                last_write_time: Some(30),
                ..FileTimes::default()
            },
        );
        assert_eq!(own.times, [1, 2, 30, 4]);
        apply_times(
            &mut own,
            FileTimes {
                creation_time: Some(10),
                last_access_time: Some(20),
                change_time: Some(40),
                ..FileTimes::default()
            },
        );
        assert_eq!(own.times, [10, 20, 30, 40]);
        apply_times(&mut own, FileTimes::default());
        assert_eq!(own.times, [10, 20, 30, 40]);
    }

    #[test]
    fn attributes_a_client_cannot_set_are_dropped() {
        let mut own = Own {
            times: [0; 4],
            attributes: 0,
        };
        apply_attributes(&mut own, 0x21 | 0x10 | 0x80);
        assert_eq!(own.attributes, 0x21);
        apply_attributes(&mut own, 0);
        assert_eq!(own.attributes, 0);
    }
}
