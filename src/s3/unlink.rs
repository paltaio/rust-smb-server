//! Deleting a file: its entry leaves the overlay, and the keys it may have in
//! the bucket become keys to delete.

use std::io;
use std::sync::Arc;

use tokio::task::spawn_blocking;
use tracing::warn;

use crate::error::{SmbError, SmbResult};
use crate::path::SmbPath;

use super::backend::Shared;
use super::cachedir::CacheDir;
use super::data::disk_error;
use super::entry::State;
use super::overlay::Held;
use super::record::{RecordId, TombstoneRecord};

/// The keys of the entry `state` that it deletes when it leaves: the keys it
/// owns to delete, and its own key if the bucket may hold it.
pub(super) fn keys_to_delete(state: &State) -> Vec<String> {
    let mut keys: Vec<String> = Vec::new();
    let candidates = state
        .gone
        .iter()
        .map(String::as_str)
        .chain(state.in_bucket().then_some(state.key.as_str()));
    for key in candidates {
        if !keys.iter().any(|held| held == key) {
            keys.push(key.to_owned());
        }
    }
    keys
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

/// Takes `keys`, which entries hold, off the records of the keys to delete.
pub(super) fn drop_superseded(shared: &Shared, keys: &[String]) {
    if keys.is_empty() {
        return;
    }
    if let Some(cache) = shared.local.as_deref()
        && let Err(e) = shared.overlay.drop_tombs(cache, keys)
    {
        warn!(error = %e, "the record of a key to delete could not be updated");
    }
}

/// Takes the keys of `keys` that an entry with a record holds off the records
/// of the keys to delete: the entry stores its own content there.
pub(super) fn supersede(shared: &Shared, keys: &[String]) {
    drop_superseded(shared, &shared.overlay.recorded_at(keys));
}

impl Shared {
    /// Deletes the file at `path`. The change is local: the entry leaves the
    /// overlay, a record notes the keys to delete, and the worker deletes
    /// them later. The only request is the lookup of the file.
    pub(super) async fn unlink(self: &Arc<Self>, path: &SmbPath) -> SmbResult<()> {
        self.local()?;
        if path.is_root() {
            return Err(SmbError::AccessDenied);
        }
        let held = self.locate(path, &self.retry()).await?;
        if held.entry.is_dir() {
            return Err(SmbError::AccessDenied);
        }
        let shared = Arc::clone(self);
        spawn_blocking(move || unlink_file(&shared, &held))
            .await
            .map_err(|e| SmbError::Io(io::Error::other(e)))?
    }
}

/// The record transition of an unlink: the record of the entry becomes a
/// tombstone record with the same id, or goes if the entry has no key to
/// delete; then the entry leaves the overlay.
fn unlink_file(shared: &Shared, held: &Held) -> SmbResult<()> {
    let cache = shared.local()?;
    let entry = &held.entry;
    let _io = entry.lock_io();
    let _seal = entry.lock_seal();
    let tombs = shared.overlay.lock_tombs();
    let (id, recorded) = {
        let mut state = entry.state();
        state.attached()?;
        state.bump();
        (state.id().map_err(SmbError::Io)?, state.recorded)
    };
    let keys = shared.overlay.tomb_keys(entry, None);
    write_tombs(cache, &id, recorded, &keys)?;
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
