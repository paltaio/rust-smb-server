//! The changes a job makes to its entry and to the cache directory, each run
//! on a blocking thread.
//!
//! A change to the data file or the record takes the `io` and `seal` locks of
//! the entry, in that order, and the state lock only for short reads and
//! writes of the state.

use std::ops::Range;
use std::sync::Arc;

use bytes::Bytes;
use tracing::warn;

use crate::error::{SmbError, SmbResult};

use super::backend::Shared;
use super::change::{record_now, seal_held};
use super::data::disk_error;
use super::entry::{Body, Entry};
use super::error::S3Error;
use super::object::ObjectHead;
use super::ranges::RangeSet;
use super::record::RecordId;

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

/// Gets the record of the entry ready for the first request that writes its
/// key: the key is noted as one that may exist in the bucket, and the record
/// is written again when that is news, or when a fill added bytes (`filled`)
/// that the record does not claim yet.
pub(super) fn before_store(shared: &Shared, entry: &Entry, filled: bool) -> SmbResult<()> {
    let first = !std::mem::replace(&mut entry.state().may_exist, true);
    if first || filled {
        super::change::seal(shared, entry, true)
    } else {
        Ok(())
    }
}

/// Notes that the object at `key`, as `head` describes it, holds the content
/// the job stored for `generation`, and that `deleted` are no longer in the
/// bucket. The entry takes that in at once.
///
/// If nothing changed the entry since `generation`, its record goes, then its
/// data file, and then its local data is dropped: the bucket has the content.
/// If the record cannot be removed, the entry keeps the record and its local
/// data, and the call fails. If the entry changed, it keeps its local data and
/// gets a record with the new base. The generation is compared under the `io`
/// and `seal` locks, which every change takes, so it cannot move meanwhile.
pub(super) fn landed(
    shared: &Shared,
    entry: &Entry,
    generation: u64,
    key: &str,
    head: Arc<ObjectHead>,
    deleted: &[String],
) -> SmbResult<()> {
    let cache = shared.local()?;
    let io = entry.lock_io();
    let seal = entry.lock_seal();
    let (stored, id) = {
        let mut state = entry.state();
        state.attached()?;
        let stored = state.landed(&shared.ahead, generation, key, head, deleted);
        (stored, state.id.clone())
    };
    if stored {
        if let Some(id) = &id {
            cache.remove_record(id).map_err(SmbError::Io)?;
            if let Err(e) = cache.remove_data(id) {
                warn!(error = %e, "a data file that is no longer needed could not be removed");
            }
        }
        entry.state().settled();
        return Ok(());
    }
    drop(io);
    let sealed = seal_held(shared, entry, true);
    drop(seal);
    sealed
}

/// Notes the multipart upload `id` of the entry, or with `None` that it has
/// none, in the record of the entry.
pub(super) fn upload_id(shared: &Shared, entry: &Entry, id: Option<String>) -> SmbResult<()> {
    {
        let mut state = entry.state();
        state.attached()?;
        if let Body::File { upload_id, .. } = &mut state.body {
            *upload_id = id;
        }
    }
    super::change::seal(shared, entry, true)
}

/// Notes that the job of the entry failed for good with `error`, in the
/// record of the entry.
pub(super) fn failed(shared: &Shared, entry: &Entry, error: S3Error) -> SmbResult<()> {
    let has_local = {
        let mut state = entry.state();
        state.failure = Some(error);
        state.local().is_some()
    };
    if has_local {
        super::change::seal(shared, entry, true)
    } else {
        record_now(shared, entry)
    }
}

/// Moves the data file and the record of the entry to the conflicts
/// directory and takes the entry out of the overlay. Returns the id the files
/// have there. The entry keeps `error`, which a call that waits for the entry
/// reports. If the files cannot be moved, the call fails and the entry stays
/// as it is.
pub(super) fn conflict(
    shared: &Shared,
    entry: &Arc<Entry>,
    error: S3Error,
) -> SmbResult<Option<RecordId>> {
    let cache = shared.local()?;
    let _io = entry.lock_io();
    let _seal = entry.lock_seal();
    let id = entry.state().id.clone();
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
