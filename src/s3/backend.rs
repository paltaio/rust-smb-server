//! The backend: a bucket served as a share.

use std::fmt;
use std::io;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, SystemTime};

use async_trait::async_trait;

use crate::backend::{
    BackendCapabilities, Handle, OpenAction, OpenIntent, OpenOptions, ShareBackend, VolumeInfo,
};
use crate::error::{SmbError, SmbResult};
use crate::path::SmbPath;

use super::cache::MetaCache;
use super::cachedir::CacheDir;
use super::client::S3Client;
use super::entry::Own;
use super::error::S3Error;
use super::jobs::{Guard, Jobs};
use super::overlay::Overlay;
use super::readahead::ReadAhead;
use super::retry::Retry;

/// Serves the objects of an S3 bucket as files and directories.
///
/// A file is an object, and its key is the path of the file below the
/// prefix. A directory is an object with a zero-length body and a key that
/// ends in `/`, or just the common prefix of the keys below it. A name that
/// is both an object and a directory is the directory. Keys that no client
/// could open, such as one with a `:` in a name or an empty path component,
/// are left out of listings.
///
/// A file or directory has the times and attributes in the user metadata of
/// its object: `mtime`, `btime`, `atime` and `ctime` as Unix seconds with up
/// to nine fraction digits, and `smb-attributes` as hexadecimal. The write
/// time is `mtime`, else `src_last_modified_millis` (Unix milliseconds), else
/// the time the store last modified the object; a value that does not parse
/// counts as missing. The other times default to the write time. A directory
/// with no marker object has the time the backend was built. Listings read
/// the metadata of the entries the backend has not seen yet, up to
/// [`listing_metadata_max`](crate::S3BackendBuilder::listing_metadata_max) of
/// them.
///
/// What the backend reads from the store is kept for
/// [`metadata_ttl`](crate::S3BackendBuilder::metadata_ttl). Clones share the
/// connection pool and that cache.
///
/// A read of a file requests the chunks of
/// [`read_chunk`](crate::S3BackendBuilder::read_chunk) bytes that hold its
/// bytes, and keeps them for later reads while a handle that reads their
/// version is open. A chunk not kept is requested for the ETag the file last
/// saw. If the object has another ETag by then, the read looks the object up
/// again and reads that version, and the file reports that version's size and
/// times from then on. An object without an ETag is read as asked for, with
/// no chunks, and a read fails once the answer has an ETag, or a size or
/// modification time that differs from what the file was opened with.
///
/// A writable backend keeps what clients change in its cache directory: the
/// bytes written to a file, and the times and attributes set on files and
/// directories. Bytes written and size changes reach the disk when a client
/// flushes the file, when the last handle open on the file closes, or when
/// the backend starts to store it. The record of a closed file is written in
/// the background. After a restart a file has what was last recorded: one
/// made and never recorded is gone, and an object changed and never recorded
/// reads as the bucket has it. A truncate below the length last recorded is
/// recorded at once. Times and attributes reach
/// the disk at once, except those of a file the backend holds bytes of, which
/// reach it when the file is recorded. The share root keeps its times and
/// attributes in memory. A read returns the bytes written and gets the rest
/// from the store; it fails when it needs bytes of the store and the object
/// under the file changed since the file was opened. If the backend stored
/// the file meanwhile, the read returns the bytes from the object it stored.
/// What the backend holds shows in lookups and listings at once. A directory
/// made through the share has its marker object put in the store before the
/// open returns. A file that is deleted or renamed is gone or has its new
/// name in the share at once, and the bucket follows in the background.
///
/// A directory can be deleted when nothing is below it, and renamed with
/// everything below it. The share shows the result at once. The objects of a
/// renamed directory are copied and the old keys deleted in the background,
/// and the directory and every directory below it have a marker object in
/// the new place. Both calls wait for the requests in flight that delete keys
/// below the directory, and fail with an I/O error once
/// [`request_timeout`](crate::S3BackendBuilder::request_timeout) has passed.
/// Both fail with `AccessDenied` for the share root. A delete fails with
/// `NotEmpty` if the backend holds a change below the directory, or the
/// bucket has an object there that is not to be deleted. A rename fails with
/// `AccessDenied` and changes nothing if the directory holds more than
/// [`max_dir_rename_objects`](crate::S3BackendBuilder::max_dir_rename_objects)
/// objects, if a key below it cannot move, or if the move is too large for
/// one record in the cache directory. A key cannot move if no client could
/// open its name, if another key lands on the same name, or, when the rename
/// changes only the case of the name, if a directory of the new spelling is
/// beside it. Both fail with `Sharing` if the directory, one above it or one
/// below it is being renamed or deleted; a rename also if a directory below
/// it is still being made, or if the keys below it keep changing while they
/// are listed. While a directory is being renamed or checked for a delete, a
/// create or a rename that lands below it fails with `Sharing`. While a
/// rename moves the entries, so does an open of an existing name below it
/// that the backend holds nothing of.
///
/// A file the backend holds bytes of is stored in the bucket in the
/// background, [`upload_delay`](crate::S3BackendBuilder::upload_delay) after
/// its last change, open or not. A file of up to
/// [`part_size`](crate::S3BackendBuilder::part_size) bytes goes up in one
/// request, a larger one as a multipart upload. The object gets the times and
/// attributes of the file and keeps the other metadata it had. A file that has
/// not changed since it was stored loses the bytes the backend held, and is
/// read from the bucket. After a change to a file, the upload under way
/// starts no more requests, a multipart upload is aborted, and a request
/// already sent may still store the earlier content. Another upload starts
/// after the delay. Times and attributes set on a file the backend holds no
/// bytes of are stored by copying the object onto itself with the new
/// metadata, and those set on a directory by putting its marker object, which
/// a directory without one gets. If the store refuses to copy an object onto
/// itself, an object of up to `part_size` bytes is read and put again, and the
/// times and attributes of a larger one are not stored, with a warning in the
/// log.
///
/// Before it stores a file that was changed in part, the backend reads the
/// rest of its bytes from the object. If the object has changed or is gone by
/// then, the file moves to the `conflicts` directory of the cache directory
/// with an error in the log, and the bucket keeps what it has. If the move
/// fails, the file stays and shows in [`failures`](S3Backend::failures). A
/// file whose bytes are all local replaces the object with no check of what
/// the bucket holds.
///
/// An upload, or the delete of the old keys of a renamed file, fails for good
/// when the store refuses a request in a way trying again cannot fix, or when
/// the cache directory cannot be read or written. It is logged, shows in
/// [`failures`](S3Backend::failures), and is tried again when the next backend
/// is built on the cache directory. That backend stores the files and
/// directory markers an earlier one left without waiting for the upload
/// delay, and aborts the multipart uploads the earlier one left running. A
/// bucket should have a lifecycle rule that aborts incomplete multipart
/// uploads. [`sync`](S3Backend::sync) waits until what the backend holds for
/// the bucket has reached it.
///
/// A renamed file is stored at its new key, and the old key is deleted once
/// the new key holds its content. A file the backend holds no bytes of is
/// copied within the bucket with the metadata the object had, in parts above
/// 5 GiB. The object of a deleted file is deleted in the background, in
/// batches, once no file has been deleted for
/// [`upload_delay`](crate::S3BackendBuilder::upload_delay), and at most a
/// minute after the first of them was due. A file made again under the exact
/// name of one that was deleted replaces the object, and the object is not
/// deleted. Before the backend deletes an object it puts a marker object for
/// each directory above it that would be left with no object, so a directory
/// does not vanish with its last file. If the store answers the marker with
/// `ObjectParentIsFile` or `ExistingObjectIsDirectory`, the directory is left
/// without a marker; if it refuses the marker any other way, the object stays
/// in the bucket and [`sync`](S3Backend::sync) fails (`OperationAborted` is
/// tried again).
///
/// Files renamed in a ring, as when two names swap through a third, are
/// stored in turn. For each ring, the backend downloads one file and uploads
/// it again, and that file has to fit in the free space of the cache
/// directory.
///
/// When names match without regard to case, which is the default, a job that
/// stores a file or a directory marker and a request that deletes keys wait
/// for each other if their keys differ in case only, and for a file that still
/// copies from such a key. Creating a directory waits the same way for the
/// requests in flight, and fails with an I/O error once
/// [`request_timeout`](crate::S3BackendBuilder::request_timeout) has passed.
/// Keys that differ in case only can go out in one delete request. A store
/// that treats such names as one name keeps the object under its old spelling
/// when a file is renamed to a new spelling of its name. Before it deletes an
/// object whose name differs in case only from the name of a file the backend
/// holds, and when it has just stored a file under a name that differs in case
/// only from an object it is to delete, the backend asks the store for both
/// names: if they have the same size, ETag and modification time and are not
/// both listed, they are one object, and it is not deleted. With
/// [`case_insensitive(false)`](crate::S3BackendBuilder::case_insensitive) the
/// store has to keep case.
///
/// Dropping the last clone ends the uploads. The cache directory stays locked
/// until the handles opened through the backend are closed and the requests
/// in flight and the saves of closed files have ended. A change made through
/// a handle after the last clone
/// is dropped is not stored by this backend; the next backend built on the
/// cache directory stores what the directory records.
///
/// Build one with [`S3Backend::builder`].
#[derive(Clone)]
pub struct S3Backend {
    pub(super) shared: Arc<Shared>,
    /// Ends the worker when the last clone is dropped.
    pub(super) _worker: Arc<Guard>,
}

pub(super) struct Shared {
    pub(super) client: S3Client,
    /// The key of the share root: the prefix without its trailing `/`, or
    /// empty.
    pub(super) prefix: String,
    pub(super) case_insensitive: bool,
    pub(super) request_timeout: Duration,
    pub(super) listing_metadata_max: usize,
    /// Most HEAD requests a listing has in flight.
    pub(super) head_concurrency: usize,
    /// The time of the share root and of directories without a marker.
    pub(super) built: SystemTime,
    pub(super) cache: Mutex<MetaCache>,
    /// The size of the requests that read file data.
    pub(super) read_chunk: u64,
    /// The most objects a renamed directory may hold.
    pub(super) max_dir_rename_objects: usize,
    /// The chunks read requests brought, shared by every handle.
    pub(super) ahead: Arc<ReadAhead>,
    pub(super) read_only: bool,
    /// What the backend holds for the paths that differ from the bucket, or
    /// may.
    pub(super) overlay: Arc<Overlay>,
    /// The cache directory of a writable backend.
    pub(super) local: Option<Arc<CacheDir>>,
    /// The times and attributes of the share root, which the backend keeps
    /// in memory.
    pub(super) root_own: Mutex<Own>,
    /// What the background jobs run with.
    pub(super) jobs: Arc<Jobs>,
}

impl Shared {
    /// The deadline of the store requests one call makes.
    pub(super) fn retry(&self) -> Retry {
        Retry::within(self.request_timeout)
    }

    /// Calls `check` until it answers `Some`, and again each time the overlay
    /// changes. A `check` that fails fails the wait. Fails with `Io` once the
    /// deadline of `retry` has passed.
    pub(super) async fn await_clear<T>(
        &self,
        retry: &Retry,
        mut check: impl FnMut() -> SmbResult<Option<T>>,
    ) -> SmbResult<T> {
        let mut progress = self.overlay.subscribe();
        loop {
            if let Some(done) = check()? {
                return Ok(done);
            }
            #[cfg(test)]
            self.jobs
                .waits
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let changed = progress.changed();
            let woken = match retry.deadline() {
                Some(deadline) => tokio::time::timeout_at(deadline, changed)
                    .await
                    .map_err(|_| S3Error::DeadlineExceeded.into_smb_error())?,
                None => changed.await,
            };
            woken.map_err(|e| SmbError::Io(io::Error::other(e)))?;
        }
    }

    /// The cache. Never held across an await.
    pub(super) fn cache(&self) -> MutexGuard<'_, MetaCache> {
        self.cache.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The cache directory. A backend that is read-only has none, and
    /// changes fail as refused.
    pub(super) fn local(&self) -> SmbResult<&CacheDir> {
        self.local.as_deref().ok_or(SmbError::AccessDenied)
    }

    /// The times and attributes of the share root.
    pub(super) fn root_own(&self) -> MutexGuard<'_, Own> {
        self.root_own.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl S3Backend {
    /// Waits until the files the backend holds bytes of, the times, attributes
    /// and names it has not stored, the directories whose marker objects it has
    /// not put, and the objects it is to delete are stored in or deleted from
    /// the bucket. Only what the backend holds when the call begins counts. A
    /// file that keeps changing delays the call, as it delays its upload. The
    /// call waits as long as the uploads take, through failures that trying
    /// again may fix and through a full disk of the cache directory.
    ///
    /// # Errors
    ///
    /// Fails with the error of one of those files or directories whose upload
    /// failed for good, or whose changes moved to the `conflicts` directory of
    /// the cache directory because the object changed or is gone in the
    /// bucket, or with the error of an object the store refuses to delete.
    /// Fails with [`S3Error::Stopped`] if the background worker has ended.
    pub async fn sync(&self) -> Result<(), S3Error> {
        self.shared.sync().await
    }

    /// The paths of the files and directories whose upload, or whose delete
    /// of keys they own, failed for good, with the error of each. A path has
    /// `/` between its names and no `/` before the first. A renamed file is on
    /// the list with its new path.
    ///
    /// A file or directory on the list keeps what the backend holds for it,
    /// which clients still see. It gets no other upload until the next backend
    /// is built on the cache directory, which tries it again. A file that
    /// moved to the `conflicts` directory is not on the list. Nor is the
    /// object of a file that was deleted, or replaced by a rename, when the
    /// store refuses to delete it: that is logged and fails
    /// [`sync`](Self::sync).
    #[must_use]
    pub fn failures(&self) -> Vec<(String, S3Error)> {
        self.shared.overlay.failures(&self.shared.prefix)
    }
}

impl fmt::Debug for S3Backend {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("S3Backend")
            .field("client", &self.shared.client)
            .field("prefix", &self.shared.prefix)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
impl S3Backend {
    /// Empties the listing cache and bounds it to `rows` rows.
    pub(crate) fn limit_listing_rows(&self, rows: usize) {
        self.shared.cache().limit_rows(rows);
    }

    /// Drops the chunks kept for reads and bounds them to `per_version` for
    /// one version of an object and `bytes` in all.
    pub(crate) fn limit_read_chunks(&self, per_version: usize, bytes: usize) {
        self.shared.ahead.limit(per_version, bytes);
    }

    /// The bytes of chunks kept for reads.
    pub(crate) fn read_chunk_bytes(&self) -> usize {
        self.shared.ahead.held()
    }

    /// The reads that wait for a chunk another read is fetching.
    pub(crate) fn read_chunk_waiters(&self) -> usize {
        self.shared.ahead.waiting()
    }

    /// Whether the store holds the keys `a` and `b`, which differ in case
    /// only, as one object.
    pub(crate) async fn one_object(&self, a: &str, b: &str) -> bool {
        self.shared
            .one_object(a, b, &self.shared.jobs.stop)
            .await
            .expect("the store answers")
            .is_some()
    }

    /// The files and directories the overlay holds.
    pub(crate) fn overlay_len(&self) -> usize {
        self.shared.overlay.len()
    }

    /// How many times a job was put off because a key stood in its way.
    pub(crate) fn parks(&self) -> usize {
        self.shared.overlay.parks()
    }

    /// How many jobs wait for the slot of `key` to clear.
    pub(crate) fn waiting_for(&self, key: &str) -> usize {
        self.shared.overlay.waiting_for(key)
    }

    /// Whether a job writes a key of the slot of `key`, a file copies from
    /// one, or a request deletes one.
    pub(crate) fn key_in_use(&self, key: &str) -> bool {
        self.shared.overlay.in_use(key)
    }

    /// What tests make the cache directory do.
    pub(crate) fn hooks(&self) -> &super::cachedir::Hooks {
        &self
            .shared
            .local
            .as_ref()
            .expect("a writable backend")
            .hooks
    }

    /// Keeps the worker from starting jobs, or lets it start them again.
    pub(crate) fn hold_uploads(&self, held: bool) {
        self.shared
            .jobs
            .held
            .store(held, std::sync::atomic::Ordering::SeqCst);
        self.shared.overlay.queue().wake();
    }

    /// Keeps the worker from deleting keys no entry owns, or lets it delete
    /// them again.
    pub(crate) fn hold_sweeps(&self, held: bool) {
        self.shared
            .jobs
            .sweeps_held
            .store(held, std::sync::atomic::Ordering::SeqCst);
        self.shared.overlay.queue().wake();
    }

    /// Makes the next job that has hashed a file wait: it notifies the first
    /// `Notify`, and goes on when the second is notified.
    pub(crate) fn pause_after_hash(&self) -> (Arc<tokio::sync::Notify>, Arc<tokio::sync::Notify>) {
        gates(&self.shared.jobs.pause)
    }

    /// Makes the next job whose request has stored a file wait, as
    /// [`pause_after_hash`](Self::pause_after_hash) does. If the backend is
    /// dropped meanwhile, the job ends without noting what it stored.
    pub(crate) fn pause_after_store(&self) -> (Arc<tokio::sync::Notify>, Arc<tokio::sync::Notify>) {
        gates(&self.shared.jobs.pause_stored)
    }

    /// Makes the next lookup that found an object wait before it takes a hold
    /// on the entry for it, as [`pause_after_hash`](Self::pause_after_hash)
    /// does.
    pub(crate) fn pause_after_lookup(
        &self,
    ) -> (Arc<tokio::sync::Notify>, Arc<tokio::sync::Notify>) {
        gates(&self.shared.jobs.pause_found)
    }

    /// Makes the next rename wait after it has reserved its name, as
    /// [`pause_after_hash`](Self::pause_after_hash) does.
    pub(crate) fn pause_after_reserve(
        &self,
    ) -> (Arc<tokio::sync::Notify>, Arc<tokio::sync::Notify>) {
        gates(&self.shared.jobs.pause_reserved)
    }

    /// Makes the next directory rename wait once its batch record is written
    /// and its entries are at their new keys, before the entries get records
    /// of their own, as [`pause_after_hash`](Self::pause_after_hash) does. If
    /// the backend is dropped meanwhile, the entries are left to the batch
    /// record.
    pub(crate) fn pause_after_batch(&self) -> (Arc<tokio::sync::Notify>, Arc<tokio::sync::Notify>) {
        gates(&self.shared.jobs.pause_batch)
    }

    /// Makes the next create wait once it has checked the directory it is in
    /// and before it enters the overlay, as
    /// [`pause_after_hash`](Self::pause_after_hash) does.
    pub(crate) fn pause_before_create(
        &self,
    ) -> (Arc<tokio::sync::Notify>, Arc<tokio::sync::Notify>) {
        gates(&self.shared.jobs.pause_create)
    }

    /// Makes the next directory rename wait once it has read the keys below
    /// the directory, as [`pause_after_hash`](Self::pause_after_hash) does.
    pub(crate) fn pause_after_listing(
        &self,
    ) -> (Arc<tokio::sync::Notify>, Arc<tokio::sync::Notify>) {
        gates(&self.shared.jobs.pause_listed)
    }

    /// Makes the next task that records a closed file wait before it takes
    /// the locks of the file, as [`pause_after_hash`](Self::pause_after_hash)
    /// does.
    pub(crate) fn pause_before_close_seal(
        &self,
    ) -> (Arc<tokio::sync::Notify>, Arc<tokio::sync::Notify>) {
        gates(&self.shared.jobs.pause_close)
    }

    /// How many tasks that record closed files are running.
    pub(crate) fn saves(&self) -> tokio::sync::watch::Receiver<usize> {
        self.shared.jobs.saves.subscribe()
    }

    /// Makes the task that records the entries of the next moved directory
    /// panic.
    pub(crate) fn panic_dissolve(&self) {
        self.shared.jobs.panic_dissolve.raise();
    }

    /// Makes the tasks that read the metadata of the objects of a moved
    /// directory panic.
    pub(crate) fn panic_read_base(&self) {
        self.shared.jobs.panic_read_base.raise();
    }

    /// How many times a call waited for requests in flight or keys to clear.
    pub(crate) fn waits(&self) -> usize {
        self.shared
            .jobs
            .waits
            .load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Lowers the size of the largest object one copy request takes.
    pub(crate) fn limit_copy(&self, bytes: u64) {
        self.shared.jobs.limit_copy(bytes);
    }

    /// Makes the next job that has stored an entry's content wait before it
    /// deletes the keys the entry owns, as
    /// [`pause_after_hash`](Self::pause_after_hash) does.
    pub(crate) fn pause_after_landing(
        &self,
    ) -> (Arc<tokio::sync::Notify>, Arc<tokio::sync::Notify>) {
        gates(&self.shared.jobs.pause_landed)
    }

    /// Whether the worker has ended, which it does after the last clone of
    /// the backend is dropped.
    pub(crate) fn worker_exited(&self) -> tokio::sync::watch::Receiver<bool> {
        self.shared.jobs.exited.subscribe()
    }

    /// Makes the worker panic.
    pub(crate) fn panic_worker(&self) {
        self.shared.jobs.panic_worker.raise();
        self.shared.overlay.queue().wake();
    }

    /// Holds the `io` lock of the entry the overlay has for `key` until the
    /// returned value is dropped.
    pub(crate) fn hold_io(&self, key: &str) -> Option<IoHold> {
        let entry = self.shared.overlay.peek(key)?;
        let (locked, wait) = std::sync::mpsc::channel();
        let (release, released) = std::sync::mpsc::channel::<()>();
        let thread = std::thread::spawn(move || {
            let _io = entry.lock_io();
            let _ = locked.send(());
            let _ = released.recv();
        });
        wait.recv().ok()?;
        Some(IoHold {
            release: Some(release),
            thread: Some(thread),
        })
    }
}

/// Puts up new gates in `slot`.
#[cfg(test)]
fn gates(
    slot: &Mutex<Option<super::jobs::Gates>>,
) -> (Arc<tokio::sync::Notify>, Arc<tokio::sync::Notify>) {
    let gates = (
        Arc::new(tokio::sync::Notify::new()),
        Arc::new(tokio::sync::Notify::new()),
    );
    *slot.lock().unwrap_or_else(PoisonError::into_inner) = Some(gates.clone());
    gates
}

/// A hold on the `io` lock of an entry.
#[cfg(test)]
pub(crate) struct IoHold {
    release: Option<std::sync::mpsc::Sender<()>>,
    thread: Option<std::thread::JoinHandle<()>>,
}

#[cfg(test)]
impl Drop for IoHold {
    fn drop(&mut self) {
        self.release.take();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// Whether an open with `opts` may change the share.
pub(super) fn changes(opts: &OpenOptions) -> bool {
    opts.write || opts.write_attributes || opts.delete_on_close || opts.intent != OpenIntent::Open
}

#[async_trait]
impl ShareBackend for S3Backend {
    async fn open(
        &self,
        path: &SmbPath,
        opts: OpenOptions,
    ) -> SmbResult<(Box<dyn Handle>, OpenAction)> {
        self.shared.open(path, opts).await
    }

    async fn unlink(&self, path: &SmbPath) -> SmbResult<()> {
        self.shared.unlink(path).await
    }

    async fn rename(&self, from: &SmbPath, to: &SmbPath, replace_if_exists: bool) -> SmbResult<()> {
        self.shared.rename(from, to, replace_if_exists).await
    }

    fn capabilities(&self) -> BackendCapabilities {
        BackendCapabilities {
            is_read_only: self.shared.read_only,
            case_sensitive: !self.shared.case_insensitive,
            ..BackendCapabilities::default()
        }
    }

    async fn volume_info(&self) -> SmbResult<VolumeInfo> {
        let Some(local) = self.shared.local.clone() else {
            return Ok(VolumeInfo::default());
        };
        tokio::task::spawn_blocking(move || local.volume_info())
            .await
            .map_err(|e| SmbError::Io(io::Error::other(e)))?
            .map_err(SmbError::Io)
    }
}
