//! Opens, and the creation of files and directories.

use std::io;
use std::sync::Arc;

use tokio::task::spawn_blocking;
use tracing::warn;

use crate::backend::{FILE_ATTRIBUTE_READONLY, Handle, OpenAction, OpenIntent, OpenOptions};
use crate::error::{SmbError, SmbResult};
use crate::path::SmbPath;
use crate::utils::now_filetime;

use super::backend::{Shared, changes};
use super::cachedir::new_id;
use super::change;
use super::data::disk_error;
use super::entry::Entry;
use super::handle::S3Handle;
use super::keys::child_key;
use super::meta;
use super::overlay::{Fence, Held, Writes};
use super::retry::Retry;

/// How many times an open looks again after it finds a name taken that it
/// found free.
const ATTEMPTS: usize = 4;

type Opened = (Box<dyn Handle>, OpenAction);

impl Shared {
    pub(super) async fn open(
        self: &Arc<Self>,
        path: &SmbPath,
        opts: OpenOptions,
    ) -> SmbResult<Opened> {
        if self.read_only && changes(&opts) {
            return Err(SmbError::AccessDenied);
        }
        if path.is_root() {
            return self.open_root(opts);
        }
        let retry = self.retry();
        for _ in 0..ATTEMPTS {
            match self.locate(path, &retry).await {
                Ok(held) => return self.open_existing(held, opts).await,
                Err(SmbError::NotFound) if creates(opts.intent) && !self.read_only => {
                    if let Some(opened) = self.create(path, opts, &retry).await? {
                        return Ok(opened);
                    }
                }
                Err(e) => return Err(e),
            }
        }
        Err(SmbError::Sharing)
    }

    fn open_root(self: &Arc<Self>, opts: OpenOptions) -> SmbResult<Opened> {
        let action = dir_action(&opts)?;
        Ok((Box::new(S3Handle::root(Arc::clone(self))), action))
    }

    async fn open_existing(self: &Arc<Self>, held: Held, opts: OpenOptions) -> SmbResult<Opened> {
        let is_dir = held.entry.is_dir();
        let attributes = held.entry.state().own_or_base(self.built).attributes;
        let truncates = matches!(
            opts.intent,
            OpenIntent::Truncate | OpenIntent::OverwriteOrCreate
        );
        let action = if is_dir {
            dir_action(&opts)?
        } else {
            if opts.intent == OpenIntent::Create {
                return Err(SmbError::Exists);
            }
            if opts.directory {
                return Err(SmbError::NotADirectory);
            }
            if attributes & FILE_ATTRIBUTE_READONLY != 0 && (opts.write || truncates) {
                return Err(SmbError::AccessDenied);
            }
            if truncates {
                change::overwrite(self, &held).await?;
                OpenAction::Overwritten
            } else {
                OpenAction::Opened
            }
        };
        Ok((Box::new(S3Handle::entry(Arc::clone(self), held)), action))
    }

    /// Makes the file or directory at `path`, which is not there. `None` if
    /// somebody made it first.
    async fn create(
        self: &Arc<Self>,
        path: &SmbPath,
        opts: OpenOptions,
        retry: &Retry,
    ) -> SmbResult<Option<Opened>> {
        let parent = self.parent_dir(path, retry).await?;
        let name = path.file_name().ok_or(SmbError::NameInvalid)?;
        let key = child_key(&parent.key, name)?;
        #[cfg(test)]
        super::jobs::pause(&self.jobs.pause_create).await;
        let now = now_filetime();
        let held = if opts.directory {
            self.create_dir(key, now, retry).await?
        } else {
            self.create_file(key, now).await?
        };
        Ok(held.map(|held| {
            let handle: Box<dyn Handle> = Box::new(S3Handle::entry(Arc::clone(self), held));
            (handle, OpenAction::Created)
        }))
    }

    /// Makes the file `key`: its data file and its entry. The work runs on
    /// a thread of its own, so an open that is dropped does not leave a data
    /// file without an entry.
    async fn create_file(self: &Arc<Self>, key: String, now: u64) -> SmbResult<Option<Held>> {
        let local = Arc::clone(self.local.as_ref().ok_or(SmbError::AccessDenied)?);
        let overlay = Arc::clone(&self.overlay);
        let id = new_id().map_err(SmbError::Io)?;
        spawn_blocking(move || {
            let file = local.create_data(&id, 0).map_err(disk_error)?;
            let held = overlay.insert_new(Entry::created_file(key, id.clone(), now, file));
            if held.is_err() {
                // The name is taken or cannot be made; the file made for this
                // one is removed.
                let _ = local.remove_data(&id);
            }
            created(held)
        })
        .await
        .map_err(|e| SmbError::Io(io::Error::other(e)))?
    }

    /// Makes the directory `key`: its entry and record, then its marker
    /// object, before the open answers. The work runs as a task of its own, so
    /// an open that is dropped does not leave it half done.
    async fn create_dir(
        self: &Arc<Self>,
        key: String,
        now: u64,
        retry: &Retry,
    ) -> SmbResult<Option<Held>> {
        let Some(held) = created(self.overlay.insert_new(Entry::created_dir(key, now)))? else {
            return Ok(None);
        };
        let task = tokio::spawn({
            let (shared, held, retry) = (Arc::clone(self), held.another(), retry.clone());
            async move { shared.put_marker(&held, retry).await }
        });
        match task.await {
            Ok(Ok(())) => Ok(Some(held)),
            Ok(Err(e)) => Err(e),
            Err(e) => Err(SmbError::Io(io::Error::other(e))),
        }
    }

    /// Writes the record of the new directory, puts its marker object, and
    /// makes the directory known to the cache. A marker the store refuses
    /// because the directory is there already counts as put. Once the marker
    /// is put, keys to delete that name it are let go; if that fails, the open
    /// goes on and the job of the directory puts the marker again and lets
    /// them go. If the record or the marker fails, the open fails, the record
    /// is removed, and the keys to delete stay; a record that cannot be
    /// removed stays, with a warning in the log.
    async fn put_marker(self: &Arc<Self>, held: &Held, retry: Retry) -> SmbResult<()> {
        let (key, metadata, generation) = {
            let state = held.entry.state();
            let own = state.own_or_base(self.built);
            let metadata = meta::marker_metadata(own.times, own.attributes);
            (state.key.clone(), metadata, state.generation)
        };
        let put = async {
            change::record(self, held).await?;
            // The marker key is noted as written until the keys to delete
            // that name it are let go.
            let _writes = self.await_marker_write(held, &retry).await?;
            let head = change::store_marker(self, &key, metadata, retry.clone())
                .await
                .map_err(|e| {
                    if !matches!(e.http_status(), Some(400..=499)) {
                        self.forget_file(&key);
                    }
                    e.into_smb_error()
                })?;
            let taken = change::take_over_marker(self, held, &key).await;
            Ok::<_, SmbError>((head, taken))
        };
        let (head, taken) = match put.await {
            Ok(put) => put,
            Err(e) => {
                if let Err(abandoned) = change::abandon(self, held).await {
                    warn!(error = %abandoned, "the record of a directory that was not made is still there");
                }
                return Err(e);
            }
        };
        match taken {
            Ok(true) => {
                // A rename refuses a directory whose open has not answered, so
                // the entry is still at `key`; if it is not, it keeps its
                // marker to put and its job puts it.
                if let Err(e) = change::marker_put(self, held, generation, &key, head).await {
                    warn!(error = %e, "the record of a new directory was not updated");
                }
            }
            // The directory was deleted while its marker was put, or the
            // backend ends: the keys to delete stay as they are.
            Ok(false) => {}
            Err(e) => {
                warn!(error = %e, "the keys to delete that name a new directory could not be let go; its job puts the marker again");
                held.entry.state().creating = false;
            }
        }
        Ok(())
    }
}

impl Shared {
    /// Notes that the marker object of the new directory of `held` is about to
    /// be put, as a job notes its writes, once no request in flight deletes or
    /// writes that key: a delete that lands after the marker would take it
    /// away. Waits for that until the deadline of `retry`. The note ends when
    /// the value returned is dropped.
    async fn await_marker_write(&self, held: &Held, retry: &Retry) -> SmbResult<Writes> {
        let key = held.entry.state().write_key();
        self.await_clear(retry, || {
            match self
                .overlay
                .begin_marker_write(&held.entry, &key, &self.jobs.stop)
            {
                Ok(writes) => Ok(Some(writes)),
                Err(Fence::Blocked) => Ok(None),
                Err(Fence::Gone) => Err(SmbError::AccessDenied),
                Err(Fence::Stopped) => Err(SmbError::Io(io::Error::other("the backend has ended"))),
            }
        })
        .await
    }
}

/// `made`, the result of putting a new entry in the overlay, with a name that
/// was taken by another create as `None`.
fn created(made: SmbResult<Held>) -> SmbResult<Option<Held>> {
    match made {
        Ok(held) => Ok(Some(held)),
        Err(SmbError::Exists) => Ok(None),
        Err(e) => Err(e),
    }
}

/// What an open of an existing directory does, or why it fails.
fn dir_action(opts: &OpenOptions) -> SmbResult<OpenAction> {
    if opts.non_directory {
        return Err(SmbError::IsDirectory);
    }
    match opts.intent {
        OpenIntent::Create => Err(SmbError::Exists),
        OpenIntent::Truncate | OpenIntent::OverwriteOrCreate => Err(SmbError::IsDirectory),
        OpenIntent::Open | OpenIntent::OpenOrCreate => Ok(OpenAction::Opened),
    }
}

/// Whether the intent makes a file that is missing.
fn creates(intent: OpenIntent) -> bool {
    matches!(
        intent,
        OpenIntent::Create | OpenIntent::OpenOrCreate | OpenIntent::OverwriteOrCreate
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_some_intents_make_what_is_missing() {
        assert!(creates(OpenIntent::Create));
        assert!(creates(OpenIntent::OpenOrCreate));
        assert!(creates(OpenIntent::OverwriteOrCreate));
        assert!(!creates(OpenIntent::Open));
        assert!(!creates(OpenIntent::Truncate));
    }
}
