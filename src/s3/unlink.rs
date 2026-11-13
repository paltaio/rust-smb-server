//! Deleting a file or an empty directory: its entry leaves the overlay, and the
//! keys it may have in the bucket become keys to delete.

use std::io;
use std::sync::Arc;

use tokio::task::spawn_blocking;
use tracing::warn;

use crate::error::{SmbError, SmbResult};
use crate::path::SmbPath;

use super::backend::Shared;
use super::cachedir::CacheDir;
use super::data::disk_error;
use super::dirmove::{Batch, Left};
use super::entry::State;
use super::overlay::{Held, TombsHeld};
use super::record::{RecordId, TombstoneRecord};

/// The keys of the entry `state` that it deletes when it leaves: the keys it
/// owns to delete, and its own key if the bucket may hold it. A directory
/// always deletes its marker key, which hides the directory even where the
/// bucket has no marker object.
pub(super) fn keys_to_delete(state: &State) -> Vec<String> {
    let mut keys: Vec<String> = Vec::new();
    let own = state.write_key();
    let candidates = state
        .gone
        .iter()
        .map(String::as_str)
        .chain((state.is_dir() || state.in_bucket()).then_some(own.as_str()));
    for key in candidates {
        if !keys.iter().any(|held| held == key) {
            keys.push(key.to_owned());
        }
    }
    keys
}

/// [`write_tombs`] for an entry that may be in a batch of a directory rename,
/// which must not bring it back. With keys to delete, the tombstone record
/// stands for the entry, and the batch record is written without it before
/// that record goes. Without, the batch record is written without the entry
/// first. Returns what puts the entry back in the batch, if it was in one.
///
/// # Errors
///
/// Fails when a record cannot be written. The entry is in its batch then.
pub(super) fn leave_batch(
    shared: &Shared,
    cache: &CacheDir,
    batch: Option<&Arc<Batch>>,
    id: &RecordId,
    recorded: bool,
    keys: &[String],
) -> SmbResult<Option<Left>> {
    if keys.is_empty() {
        return drop_record(shared, cache, batch, Some(id), recorded);
    }
    write_tombs(cache, id, recorded, keys)?;
    Ok(batch.and_then(|batch| shared.overlay.left_batch(batch, id)))
}

/// Takes the entry `id`, which has nothing left to keep, out of the batch
/// record that lists it, and then removes its own record if it has one. The
/// batch record is written without the entry first, so it cannot bring back
/// what the entry had. Returns what puts the entry back in the batch, if it
/// was in one.
///
/// # Errors
///
/// Fails when a record cannot be written or removed. The entry is a member of
/// its batch again then, in the record too.
pub(super) fn drop_record(
    shared: &Shared,
    cache: &CacheDir,
    batch: Option<&Arc<Batch>>,
    id: Option<&RecordId>,
    recorded: bool,
) -> SmbResult<Option<Left>> {
    let left = match (batch, id) {
        (Some(batch), Some(id)) => batch.cancel(cache, id)?,
        _ => None,
    };
    let removed = match id {
        Some(id) => write_tombs(cache, id, recorded, &[]),
        None => Ok(()),
    };
    if let Err(e) = removed {
        if let Some(left) = left
            && let Err(rejoin) = shared.overlay.rejoin_batch(cache, left)
        {
            warn!(error = %rejoin, "the record of a directory rename could not be written again");
        }
        return Err(e);
    }
    Ok(left)
}

/// Turns the record `id` of an entry that leaves into the tombstone record of
/// `keys`, or removes it when there are no keys and the entry had a record.
pub(super) fn write_tombs(
    cache: &CacheDir,
    id: &RecordId,
    recorded: bool,
    keys: &[String],
) -> SmbResult<()> {
    if keys.is_empty() {
        if recorded {
            cache.remove_record(id).map_err(disk_error)?;
        }
        return Ok(());
    }
    let record = TombstoneRecord {
        id: id.clone(),
        keys: keys.to_vec(),
    };
    cache.write_record(id, &record.encode()).map_err(disk_error)
}

/// Takes `keys`, which entries hold, off the records of the keys to delete. A
/// caller that holds the lock of the keys to delete passes it as `tombs`.
pub(super) fn drop_superseded(shared: &Shared, keys: &[String], tombs: TombsHeld<'_>) {
    if keys.is_empty() {
        return;
    }
    let Some(cache) = shared.local.as_deref() else {
        return;
    };
    let dropped = match tombs {
        Some(held) => shared.overlay.drop_tombs_held(held, cache, keys),
        None => shared.overlay.drop_tombs(cache, keys),
    };
    if let Err(e) = dropped {
        warn!(error = %e, "the record of a key to delete could not be updated");
    }
}

/// Takes the keys of `keys` that an entry with a record holds off the records
/// of the keys to delete: the entry stores its own content there.
pub(super) fn supersede(shared: &Shared, keys: &[String]) {
    drop_superseded(shared, &shared.overlay.recorded_at(keys), None);
}

impl Shared {
    /// Deletes the file or the empty directory at `path`. The change is
    /// local: the entry leaves the overlay, a record notes the keys to
    /// delete, and the worker deletes them later. The requests are the lookup
    /// of the name and, for a directory, one listing of the keys below it,
    /// which starts once the requests in flight that delete keys below the
    /// directory have ended. No name can be made below the directory between
    /// the check and the delete.
    ///
    /// # Errors
    ///
    /// Fails with `NotEmpty` if a directory has an entry of the overlay or an
    /// object below it, with `AccessDenied` for the share root, and with
    /// `Sharing` if the directory, or one above or below it, is being renamed
    /// or deleted. The wait for the requests that delete keys below the
    /// directory fails with `Io` if it outlasts the deadline.
    pub(super) async fn unlink(self: &Arc<Self>, path: &SmbPath) -> SmbResult<()> {
        self.local()?;
        if path.is_root() {
            return Err(SmbError::AccessDenied);
        }
        let retry = self.retry();
        let held = self.locate(path, &retry).await?;
        let mut fence = None;
        if held.entry.is_dir() {
            let key = held.entry.state().key.clone();
            let below = self.overlay.hold_below(&key)?;
            self.await_deletes(&below, &retry).await?;
            if !self.is_empty(&key, &retry).await? {
                return Err(SmbError::NotEmpty);
            }
            fence = Some(below);
        }
        let shared = Arc::clone(self);
        spawn_blocking(move || {
            let done = unlink_entry(&shared, &held);
            drop(fence);
            done
        })
        .await
        .map_err(|e| SmbError::Io(io::Error::other(e)))?
    }
}

/// The record transition of an unlink: the record of the entry becomes a
/// tombstone record with the same id, or goes if the entry has no key to
/// delete; then the entry leaves the overlay. A directory that an entry of the
/// overlay was made below since the check stays. The keys to delete of a
/// directory include its marker key, which hides the directory even where the
/// bucket has no marker object.
fn unlink_entry(shared: &Shared, held: &Held) -> SmbResult<()> {
    let cache = shared.local()?;
    let entry = &held.entry;
    let _io = entry.lock_io();
    let _seal = entry.lock_seal();
    let tombs = shared.overlay.lock_tombs();
    if entry.is_dir() {
        let key = {
            let state = entry.state();
            state.attached()?;
            state.key.clone()
        };
        if shared.overlay.spelling(&key).is_some() {
            return Err(SmbError::NotEmpty);
        }
    }
    let (id, recorded, batch) = {
        let mut state = entry.state();
        state.attached()?;
        state.bump();
        (
            state.id().map_err(SmbError::Io)?,
            state.recorded,
            state.batch.clone(),
        )
    };
    let keys = shared.overlay.tomb_keys(entry, None);
    leave_batch(shared, cache, batch.as_ref(), &id, recorded, &keys)?;
    if let Err(e) = cache.remove_data(&id) {
        warn!(error = %e, "a data file that is no longer needed could not be removed");
    }
    shared.overlay.unlinked(entry, &keys, &id);
    drop(tombs);
    supersede(shared, &keys);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::s3::entry::Base;

    fn state(key: &str) -> State {
        State::new(key.to_owned(), false)
    }

    #[test]
    fn a_file_that_never_reached_the_bucket_has_no_key_to_delete() {
        assert!(keys_to_delete(&state("new")).is_empty());
    }

    #[test]
    fn a_file_in_the_bucket_has_its_key_to_delete_once() {
        let mut file = state("a");
        file.may_exist = true;
        file.base = Some(Base::at("a"));
        file.gone = vec!["a".to_owned()];
        assert_eq!(keys_to_delete(&file), ["a"]);
    }

    #[test]
    fn a_renamed_file_has_the_keys_it_owns_and_its_own_key_to_delete() {
        let mut file = state("c");
        file.base = Some(Base::at("a"));
        file.gone = vec!["b".to_owned()];
        assert_eq!(keys_to_delete(&file), ["b"]);
        file.may_exist = true;
        assert_eq!(keys_to_delete(&file), ["b", "c"]);
    }

    #[test]
    fn the_base_key_is_not_a_key_the_file_deletes() {
        let mut file = state("c");
        file.base = Some(Base::at("a"));
        assert!(keys_to_delete(&file).is_empty());
        file.base = Some(Base::at("c"));
        assert_eq!(keys_to_delete(&file), ["c"]);
    }
}
