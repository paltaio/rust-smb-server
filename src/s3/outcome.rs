//! The changes a job makes to its entry and to the cache directory, each run
//! on a blocking thread.
//!
//! A change to the data file or the record takes the `io` and `seal` locks of
//! the entry, in that order, and the state lock only for short reads and
//! writes of the state.

use std::io;
use std::ops::Range;
use std::sync::Arc;

use bytes::Bytes;
use tracing::warn;

use crate::error::{SmbError, SmbResult};

use super::backend::Shared;
use super::change::{
    ensure_local, persist, persist_held, persist_with, record_held, recount_source,
};
use super::data::disk_error;
use super::entry::{Body, Entry, Landing, Upload};
use super::error::S3Error;
use super::object::ObjectHead;
use super::ranges::RangeSet;
use super::record::RecordId;
use super::retry::Stop;
use super::unlink::drop_record;

/// The parts of `range` that a fill writes into a file of `len` bytes that
/// holds `present`: the bytes it does not hold yet, below its length now.
/// A byte written since the fill asked for the bytes of `range` is held, so
/// it stays as it was written.
pub(super) fn to_fill(present: &RangeSet, len: u64, range: &Range<u64>) -> Vec<Range<u64>> {
    let end = range.end.min(len);
    if range.start >= end {
        return Vec::new();
    }
    present
        .segments(range.start..end)
        .into_iter()
        .filter(|(_, held)| !held)
        .map(|(piece, _)| piece)
        .collect()
}

/// Adds `data`, the bytes of `range` of the base, to the local data of the
/// entry, and notes the bytes written as present. Only the parts [`to_fill`]
/// gives are written. Without `data`, `range` is zeros the file has already.
/// Returns whether the entry holds more bytes than before.
pub(super) fn fill(
    shared: &Shared,
    entry: &Entry,
    range: &Range<u64>,
    data: Option<&Bytes>,
) -> SmbResult<bool> {
    let cache = shared.local()?;
    let _io = entry.lock_io();
    let (file, pieces) = {
        let state = entry.state();
        state.attached()?;
        let Some(local) = state.local() else {
            return Ok(false);
        };
        (
            Arc::clone(&local.file),
            to_fill(&local.present, local.len, range),
        )
    };
    if let Some(data) = data {
        for piece in &pieces {
            let from = usize::try_from(piece.start - range.start)
                .map_err(|_| SmbError::InvalidParameter)?;
            let to =
                usize::try_from(piece.end - range.start).map_err(|_| SmbError::InvalidParameter)?;
            let bytes = data.get(from..to).ok_or(SmbError::InvalidParameter)?;
            cache
                .write_data(&file, bytes, piece.start)
                .map_err(disk_error)?;
        }
    }
    let mut state = entry.state();
    let Some(local) = state
        .local_mut()
        .filter(|local| Arc::ptr_eq(&local.file, &file))
    else {
        return Ok(false);
    };
    let grew = !pieces.is_empty();
    for piece in pieces {
        local.present.insert(piece);
    }
    Ok(grew)
}

/// Runs `work` with the `io` and `seal` locks of `entry` and of the entries
/// that own `key` to delete, which are taken in one order, and passes it those
/// entries. Returns `None`, having run nothing, if the entry left the overlay,
/// is at another key, or the job was stopped: such an entry takes no key over.
fn taking<T>(
    shared: &Shared,
    entry: &Arc<Entry>,
    key: &str,
    stop: &Stop,
    work: impl FnOnce(&[Arc<Entry>]) -> SmbResult<T>,
) -> SmbResult<Option<T>> {
    let owners = shared.overlay.owners(key, entry);
    let locking: Vec<&Arc<Entry>> = std::iter::once(entry).chain(&owners).collect();
    let _locks = Entry::lock_all(&locking);
    {
        let state = entry.state();
        if state.detached || !state.is_write_key(key) || stop.is_stopped() {
            return Ok(None);
        }
    }
    work(&owners).map(Some)
}

/// Gets the entry ready for the first request that writes `key`, which is its
/// key, or for a directory the key of its marker object: the key is noted as
/// one that may exist in the bucket, and the record is written again when the
/// key was not noted before, or when a fill added bytes (`filled`) that the
/// record does not claim yet. Then the entries that own `key` to delete, and
/// the records of keys to delete that name it, let it go. All of it happens
/// under the `io` and `seal` locks of the entry and of those owners. Returns
/// whether the key may have existed before, or `None`, having changed nothing,
/// if the entry left the overlay, is at another key, or the job was stopped.
///
/// # Errors
///
/// Fails when an owner cannot record that it let the key go. The owner is as
/// it was then, and the entry writes nothing: a full disk is `DiskFull`, and
/// any other failure has failed the owner.
pub(super) fn before_store(
    shared: &Shared,
    entry: &Arc<Entry>,
    key: &str,
    filled: bool,
    stop: &Stop,
) -> SmbResult<Option<bool>> {
    taking(shared, entry, key, stop, |owners| {
        let existed = std::mem::replace(&mut entry.state().may_exist, true);
        if !existed || filled {
            persist_held(shared, entry, true)?;
        }
        release_key(shared, owners, key)?;
        Ok(existed)
    })
}

/// Takes `key`, the key of an object that `entry` has stored, off the keys that
/// other entries own to delete and off the keys to delete that no entry owns.
/// Returns whether it did: an entry that left the overlay, is at another key or
/// was stopped takes nothing over.
///
/// # Errors
///
/// As [`before_store`].
pub(super) fn take_over(
    shared: &Shared,
    entry: &Arc<Entry>,
    key: &str,
    stop: &Stop,
) -> SmbResult<bool> {
    let taken = taking(shared, entry, key, stop, |owners| {
        release_key(shared, owners, key)
    })?;
    Ok(taken.is_some())
}

/// Makes `owners` and the records of keys to delete let go of `key`.
fn release_key(shared: &Shared, owners: &[Arc<Entry>], key: &str) -> SmbResult<()> {
    for owner in owners {
        match taken_over_held(shared, owner, &[key.to_owned()]) {
            Ok(()) | Err(SmbError::AccessDenied) => {}
            Err(e) => return Err(e),
        }
    }
    if let Some(cache) = shared.local.as_deref()
        && shared.overlay.tomb_named(key)
    {
        shared
            .overlay
            .drop_tombs(cache, &[key.to_owned()])
            .map_err(disk_error)?;
    }
    Ok(())
}

/// Gives a file that copies from its base an empty data file of the same
/// length, so a fill can bring the bytes in.
pub(super) fn local_copy(shared: &Shared, entry: &Entry) -> SmbResult<()> {
    let cache = shared.local()?;
    let _io = entry.lock_io();
    ensure_local(cache, entry, None)?;
    Ok(())
}

/// Notes that the object at `key`, as `head` describes it, holds the content
/// the job stored for `generation`. The entry takes that in at once. Returns
/// whether it did: an entry that moved to another key meanwhile does not.
///
/// If nothing changed the entry since `generation`, the bucket has all it
/// held: its local data and times go, and with them its record and data file
/// unless it still has keys to delete, in which case the record is written
/// again with the new base. If the entry changed, it keeps its local data and
/// gets a record with the new base. The generation is compared under the `io`
/// and `seal` locks, which every change takes, so it cannot move meanwhile.
/// The key the entry copied from is let go of once its record no longer names
/// it.
pub(super) fn landed(
    shared: &Shared,
    entry: &Arc<Entry>,
    generation: u64,
    key: &str,
    head: Arc<ObjectHead>,
) -> SmbResult<bool> {
    let cache = shared.local()?;
    let io = entry.lock_io();
    let _seal = entry.lock_seal();
    let (landing, id, keeps_keys) = {
        let mut state = entry.state();
        state.attached()?;
        let landing = state.landed(&shared.ahead, generation, key, head);
        (landing, state.id.clone(), !state.gone.is_empty())
    };
    match landing {
        Landing::Moved => return Ok(false),
        Landing::Newer => {
            drop(io);
            persist_held(shared, entry, true)?;
            return Ok(true);
        }
        Landing::Whole => {}
    }
    if keeps_keys {
        entry.state().stored();
        if id.is_some() {
            record_held(shared, entry)?;
        }
    } else if let Some(id) = &id {
        cache.remove_record(id).map_err(SmbError::Io)?;
    }
    if let Some(id) = &id
        && let Err(e) = cache.remove_data(id)
    {
        warn!(error = %e, "a data file that is no longer needed could not be removed");
    }
    if !keeps_keys {
        entry.state().settled();
    }
    recount_source(shared, entry);
    Ok(true)
}

/// Writes the record of the entry again, or removes it and the local data if
/// the entry has nothing left to do. `gone`, when given, is what the entry owns
/// to delete from now on: the entry and the index take it in once the disk has
/// it, so if the disk fails nothing changes. The caller holds the `io` and
/// `seal` locks of the entry.
fn rest(shared: &Shared, entry: &Arc<Entry>, gone: Option<Vec<String>>) -> SmbResult<()> {
    let cache = shared.local()?;
    let (idle, id, recorded, batch) = {
        let state = entry.state();
        let owned = gone.as_deref().unwrap_or(&state.gone);
        (
            !state.writes() && owned.is_empty(),
            state.id.clone(),
            state.recorded,
            state.batch.clone(),
        )
    };
    if idle {
        // A batch that lists the entry must not bring back what it had.
        drop_record(shared, cache, batch.as_ref(), id.as_ref(), recorded)?;
        let mut state = entry.state();
        if let Some(gone) = gone {
            state.gone = gone;
        }
        state.batch = None;
        state.settled();
    } else {
        persist_with(shared, entry, true, gone, None)?;
    }
    shared.overlay.track(entry);
    if idle {
        shared.overlay.leave_if_idle(entry);
    }
    Ok(())
}

/// Notes that the keys `removed` are gone from the bucket, or are not the
/// entry's to delete: they leave the entry's record. An entry with nothing
/// left to do drops its record and local data.
pub(super) fn deleted(shared: &Shared, entry: &Arc<Entry>, removed: &[String]) -> SmbResult<()> {
    let _io = entry.lock_io();
    let _seal = entry.lock_seal();
    deleted_held(shared, entry, removed)
}

/// [`deleted`] for a caller that holds the `io` and `seal` locks of the entry.
fn deleted_held(shared: &Shared, entry: &Arc<Entry>, removed: &[String]) -> SmbResult<()> {
    let gone = {
        let state = entry.state();
        state.attached()?;
        state
            .gone
            .iter()
            .filter(|key| !removed.contains(key))
            .cloned()
            .collect()
    };
    rest(shared, entry, Some(gone))
}

/// [`deleted`] for the owner of keys that another entry takes over. If the
/// record of the owner cannot be written nothing changes: a full disk is
/// `DiskFull`, and any other failure fails the owner for good, as a call that
/// waits for it reports.
pub(super) fn taken_over(shared: &Shared, owner: &Arc<Entry>, keys: &[String]) -> SmbResult<()> {
    let _io = owner.lock_io();
    let _seal = owner.lock_seal();
    taken_over_held(shared, owner, keys)
}

/// [`taken_over`] for a caller that holds the `io` and `seal` locks of the
/// owner.
fn taken_over_held(shared: &Shared, owner: &Arc<Entry>, keys: &[String]) -> SmbResult<()> {
    match deleted_held(shared, owner, keys) {
        Err(e) if !matches!(e, SmbError::AccessDenied | SmbError::DiskFull) => {
            let failure = S3Error::cache(e);
            owner.state().failure = Some(failure.clone());
            shared.overlay.touch();
            Err(SmbError::Io(io::Error::other(failure)))
        }
        done => done,
    }
}

/// Drops the times and attributes of the entry that the store cannot take,
/// if nothing changed it since `generation`.
pub(super) fn dropped(shared: &Shared, entry: &Arc<Entry>, generation: u64) -> SmbResult<()> {
    let _io = entry.lock_io();
    let _seal = entry.lock_seal();
    {
        let mut state = entry.state();
        state.attached()?;
        if state.generation != generation {
            return Ok(());
        }
        state.own = None;
        state.uploaded = generation;
    }
    rest(shared, entry, None)
}

/// Notes the multipart upload of the entry, or with `None` that it has
/// none, in the record of the entry.
pub(super) fn note_upload(
    shared: &Shared,
    entry: &Arc<Entry>,
    upload: Option<Upload>,
) -> SmbResult<()> {
    {
        let mut state = entry.state();
        state.attached()?;
        if let Body::File { upload: held, .. } = &mut state.body {
            *held = upload;
        }
    }
    persist(shared, entry, true)
}

/// Notes that the job of the entry failed for good with `error`, in the
/// record of the entry.
pub(super) fn failed(shared: &Shared, entry: &Arc<Entry>, error: S3Error) -> SmbResult<()> {
    entry.state().failure = Some(error);
    persist(shared, entry, true)
}

/// Moves the data file and the record of the entry to the conflicts
/// directory and takes the entry out of the overlay. Returns the id the files
/// have there. The entry keeps `error`, which a call that waits for the entry
/// reports. If the files cannot be moved, the call fails and the entry stays
/// as it is.
///
/// # Errors
///
/// Fails with `AccessDenied`, having moved nothing, if the entry left the
/// overlay: its id names the tombstone record of its keys to delete then.
pub(super) fn conflict(
    shared: &Shared,
    entry: &Arc<Entry>,
    error: S3Error,
) -> SmbResult<Option<RecordId>> {
    let cache = shared.local()?;
    let _io = entry.lock_io();
    let _seal = entry.lock_seal();
    let id = {
        let state = entry.state();
        state.attached()?;
        state.id.clone()
    };
    let moved = id
        .map(|id| cache.keep_conflict(&id).map_err(SmbError::Io))
        .transpose()?;
    {
        let mut state = entry.state();
        state.failure = Some(error);
        state.gone.clear();
    }
    shared.overlay.evict(entry);
    Ok(moved)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ranges(ranges: &[(u64, u64)]) -> Vec<Range<u64>> {
        ranges.iter().map(|&(start, end)| start..end).collect()
    }

    #[test]
    fn a_fill_writes_only_the_bytes_the_file_does_not_hold() {
        let present: RangeSet = ranges(&[(100, 110), (150, 160)]).into_iter().collect();
        assert_eq!(
            to_fill(&present, 1000, &(0..200)),
            ranges(&[(0, 100), (110, 150), (160, 200)])
        );
        assert_eq!(to_fill(&present, 1000, &(100..110)), ranges(&[]));
        assert_eq!(to_fill(&present, 1000, &(105..120)), ranges(&[(110, 120)]));
    }

    #[test]
    fn a_fill_stops_at_the_length_the_file_has_now() {
        let present: RangeSet = ranges(&[(10, 20)]).into_iter().collect();
        assert_eq!(
            to_fill(&present, 50, &(0..100)),
            ranges(&[(0, 10), (20, 50)])
        );
        assert_eq!(to_fill(&present, 15, &(0..100)), ranges(&[(0, 10)]));
        assert_eq!(to_fill(&present, 10, &(10..100)), ranges(&[]));
        assert_eq!(to_fill(&present, 0, &(0..100)), ranges(&[]));
    }
}
