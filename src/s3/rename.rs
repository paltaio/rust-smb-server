//! Renaming a file: its entry takes the new key, the old key becomes a key
//! the entry deletes once its content is at the new one, and the entry it
//! replaces, if any, gives its keys up to be deleted.

use std::io;
use std::sync::Arc;

use tokio::task::spawn_blocking;
use tracing::warn;

use crate::error::{SmbError, SmbResult};
use crate::path::SmbPath;

use super::backend::Shared;
use super::data::disk_error;
use super::entry::{Entry, Sealed, State};
use super::keys::{child_key, path_below};
use super::overlay::{Held, Moving};
use super::record::RecordId;
use super::unlink::{supersede, write_tombs};

impl Shared {
    /// Renames the file at `from` to `to`. The change is local: the only
    /// requests are the lookups of the two names and of the parent of `to`.
    ///
    /// # Errors
    ///
    /// Fails with `Exists` if another file has the name and `replace` is not
    /// set, with `AccessDenied` if a directory has it, and with
    /// `PathNotFound` if the parent of `to` is not a directory.
    pub(super) async fn rename(
        self: &Arc<Self>,
        from: &SmbPath,
        to: &SmbPath,
        replace: bool,
    ) -> SmbResult<()> {
        self.local()?;
        if from.is_root() || to.is_root() {
            return Err(SmbError::AccessDenied);
        }
        let retry = self.retry();
        let source = self.locate(from, &retry).await?;
        if source.entry.is_dir() {
            return Err(SmbError::AccessDenied);
        }
        let parent = self.parent_dir(to, &retry).await?;
        let name = to.file_name().ok_or(SmbError::NameInvalid)?;
        let key = child_key(&parent.key, name)?;
        let mut attempts = 0;
        loop {
            let target = match self.locate(to, &retry).await {
                Ok(target) => Some(target),
                Err(SmbError::NotFound) => None,
                Err(e) => return Err(e),
            };
            let target = match target {
                Some(target) if Arc::ptr_eq(&target.entry, &source.entry) => None,
                Some(target) if target.entry.is_dir() => return Err(SmbError::AccessDenied),
                Some(_) if !replace => return Err(SmbError::Exists),
                other => other,
            };
            let (shared, moving, key) = (Arc::clone(self), source.another(), key.clone());
            let done = spawn_blocking(move || rename_file(&shared, &moving, &key, target))
                .await
                .map_err(|e| SmbError::Io(io::Error::other(e)))?;
            // A name that another change took since the lookup is looked up
            // again, to be replaced.
            attempts += 1;
            if !(replace && matches!(done, Err(SmbError::Exists)) && attempts < RENAME_ATTEMPTS) {
                return done;
            }
        }
    }
}

/// How often a rename that replaces looks up its name again after another
/// change took it.
const RENAME_ATTEMPTS: u32 = 3;

/// The keys `entry` owns to delete after it moves from `old` to `to`: those
/// it owned, and `old` if the bucket may hold it, less `to`.
pub(super) fn gone_after(owned: &[String], old: &str, old_exists: bool, to: &str) -> Vec<String> {
    let mut gone: Vec<String> = Vec::new();
    for key in owned
        .iter()
        .map(String::as_str)
        .chain(old_exists.then_some(old))
    {
        if key != to && !gone.iter().any(|held| held == key) {
            gone.push(key.to_owned());
        }
    }
    gone
}

/// The ETag the key `to` had when `state`, the entry that held it, was
/// replaced, if the entry knows it. A multipart upload over the key tells its
/// own object from this one. `None` while the entry has a job, which can store
/// a newer version, and when `to` differs from the entry's key in case only.
fn prior_etag(state: &State, to: &str) -> Option<String> {
    if state.job.is_some() || state.key != to {
        return None;
    }
    state.prior.clone()
}

/// The entry a rename replaces: its record becomes a tombstone record of
/// `keys`.
struct Replaced<'a> {
    entry: &'a Arc<Entry>,
    id: RecordId,
    /// The entry had a record.
    recorded: bool,
    keys: Vec<String>,
}

/// Moves the entry of `source` to `to`, in this order: the record of the
/// entry `replaced`, which becomes a tombstone record of its keys to delete
/// or goes; the record of the moved entry, with its new key; the overlay.
fn rename_file(shared: &Shared, source: &Held, to: &str, replaced: Option<Held>) -> SmbResult<()> {
    let cache = shared.local()?;
    let entry = &source.entry;
    let other = replaced.as_ref().map(|held| &held.entry);
    let order: Vec<&Arc<Entry>> = std::iter::once(entry).chain(other).collect();
    let _locks = Entry::lock_all(&order);

    let gone = {
        let state = entry.state();
        state.attached()?;
        if state.key == to {
            return Ok(());
        }
        gone_after(&state.gone, &state.key, state.in_bucket(), to)
    };
    let tombs = shared.overlay.lock_tombs();
    let Some(_reserved) = shared.overlay.reserve(to, entry, other) else {
        return Err(SmbError::Exists);
    };
    #[cfg(test)]
    super::jobs::pause_blocking(&shared.jobs.pause_reserved);

    // The replaced entry first: its job stops, and its keys go.
    let mut replacing = None;
    let (mut prior, mut may_exist) = (None, shared.overlay.tombstoned(to));
    if let Some(x) = other {
        let (id, recorded) = {
            let mut state = x.state();
            state.attached()?;
            state.bump();
            prior = prior_etag(&state, to);
            may_exist |= state.in_bucket();
            (state.id().map_err(SmbError::Io)?, state.recorded)
        };
        let moving = Moving {
            entry,
            to,
            gone: &gone,
        };
        let keys = shared.overlay.tomb_keys(x, Some(moving));
        write_tombs(cache, &id, recorded, &keys)?;
        replacing = Some(Replaced {
            entry: x,
            id,
            recorded,
            keys,
        });
    }

    let moved = move_record(shared, entry, to, &gone, may_exist);
    let moved = match moved {
        Ok(moved) => moved,
        Err(e) => {
            drop(tombs);
            if let Some(x) = &replacing {
                restore(shared, x);
            }
            return Err(e);
        }
    };
    if let Some(x) = &replacing
        && let Err(e) = cache.remove_data(&x.id)
    {
        warn!(error = %e, "a data file that is no longer needed could not be removed");
    }
    let keys = replacing
        .as_ref()
        .map(|x| x.keys.clone())
        .unwrap_or_default();
    shared.overlay.renamed(
        entry,
        to,
        |state| {
            state.gone = gone;
            state.may_exist = may_exist;
            state.prior = prior;
            state.bump();
            if let Some(sealed) = moved.sealed {
                state.set_sealed(sealed);
            }
            state.recorded = moved.recorded;
            state.recorded_source = moved.source;
        },
        replacing
            .as_ref()
            .map(|x| (x.entry, x.keys.as_slice(), &x.id)),
    );
    drop(tombs);
    super::change::superseded(shared, entry);
    supersede(shared, &keys);
    Ok(())
}

/// Puts the record of the replaced entry back as it was before a rename that
/// failed: the record is written again if the entry had one, and the
/// tombstone record that took its id goes if not.
fn restore(shared: &Shared, x: &Replaced<'_>) {
    let restored = if x.recorded {
        super::change::persist_held(shared, x.entry, true)
    } else {
        shared
            .local()
            .and_then(|cache| cache.remove_record(&x.id).map_err(disk_error))
    };
    if let Err(e) = restored {
        warn!(error = %e, "the record of an entry that was not replaced could not be written again");
    }
}

/// What the record of a moved entry says.
struct Moved {
    /// What the record seals.
    sealed: Option<Sealed>,
    /// A record is on disk.
    recorded: bool,
    /// The key the record says the content is copied from.
    source: Option<String>,
}

/// Writes the record of `entry` as it is with the key `to`, or removes it if
/// the entry would have nothing to keep.
fn move_record(
    shared: &Shared,
    entry: &Arc<Entry>,
    to: &str,
    gone: &[String],
    may_exist: bool,
) -> SmbResult<Moved> {
    let cache = shared.local()?;
    let (record, id, recorded, first, file) = {
        let mut state = entry.state();
        state.attached()?;
        let work = state.local().is_some()
            || state.own.is_some()
            || state.base.as_ref().is_some_and(|base| base.key != to)
            || !gone.is_empty();
        let record = work.then(|| Entry::record(&mut state, &shared.prefix, shared.built));
        (
            record,
            state.id.clone(),
            state.recorded,
            state.sealed().is_none(),
            state.local().map(|local| Arc::clone(&local.file)),
        )
    };
    let Some(record) = record else {
        if let (true, Some(id)) = (recorded, id) {
            cache.remove_record(&id).map_err(disk_error)?;
        }
        return Ok(Moved {
            sealed: None,
            recorded: false,
            source: None,
        });
    };
    let mut record = record.map_err(SmbError::Io)?;
    record.key = to.to_owned();
    record.path = path_below(&shared.prefix, to);
    record.gone = gone.to_vec();
    record.remote = may_exist;
    record.generation += 1;
    if let Some(file) = file {
        file.sync_all().map_err(disk_error)?;
        if first {
            cache.sync_data_dir().map_err(disk_error)?;
        }
    }
    cache
        .write_record(&record.id, &record.encode())
        .map_err(disk_error)?;
    let sealed = record.local.as_ref().map(|local| Sealed {
        generation: record.generation,
        len: local.len,
    });
    Ok(Moved {
        sealed,
        recorded: true,
        source: record.source().map(str::to_owned),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keys(keys: &[&str]) -> Vec<String> {
        keys.iter().map(|key| (*key).to_owned()).collect()
    }

    #[test]
    fn the_old_key_is_to_be_deleted_when_the_bucket_may_hold_it() {
        assert_eq!(gone_after(&[], "a", true, "b"), keys(&["a"]));
        assert!(gone_after(&[], "a", false, "b").is_empty());
    }

    #[test]
    fn a_chain_of_renames_keeps_the_keys_it_passed_and_not_the_one_it_ends_at() {
        let first = gone_after(&[], "a", true, "b");
        let second = gone_after(&first, "b", false, "c");
        assert_eq!(second, keys(&["a"]));
        let third = gone_after(&second, "c", true, "a");
        assert_eq!(third, keys(&["c"]));
    }

    #[test]
    fn a_key_is_to_be_deleted_once() {
        assert_eq!(
            gone_after(&keys(&["a", "b"]), "b", true, "c"),
            keys(&["a", "b"])
        );
    }

    #[test]
    fn the_etag_a_key_had_is_unknown_while_the_entry_that_held_it_has_a_job() {
        let mut state = State::new("to".to_owned(), false);
        assert_eq!(prior_etag(&state, "to"), None);
        state.prior = Some("\"p\"".to_owned());
        assert_eq!(prior_etag(&state, "to").as_deref(), Some("\"p\""));
        assert_eq!(prior_etag(&state, "TO"), None, "another spelling");
        state.job = Some(crate::s3::retry::Stop::new());
        assert_eq!(prior_etag(&state, "to"), None);
    }
}
