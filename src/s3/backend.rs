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
/// flushes the file, and closing does not flush: after a restart a file has
/// what its last flush recorded. A truncate below the length last flushed is
/// recorded at once. Times and attributes reach the disk at once, except
/// those of a file the backend holds bytes of, which reach it at the next
/// flush. The share root keeps its times and attributes in memory. A read
/// returns the bytes written and gets the rest from the store; it fails when
/// it needs bytes of the store and the object under the file changed since
/// the file was opened. What the backend holds shows in lookups and listings
/// at once. A directory made through the share has its marker object put in
/// the store before the open returns. Deletes and renames are refused, and
/// the bytes of files are not put in the store.
///
/// Build one with [`S3Backend::builder`].
#[derive(Clone)]
pub struct S3Backend {
    pub(super) shared: Arc<Shared>,
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
}

impl Shared {
    /// The deadline of the store requests one call makes.
    pub(super) fn retry(&self) -> Retry {
        Retry::within(self.request_timeout)
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

    /// The files and directories the overlay holds.
    pub(crate) fn overlay_len(&self) -> usize {
        self.shared.overlay.len()
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

    async fn unlink(&self, _path: &SmbPath) -> SmbResult<()> {
        Err(SmbError::AccessDenied)
    }

    async fn rename(
        &self,
        _from: &SmbPath,
        _to: &SmbPath,
        _replace_if_exists: bool,
    ) -> SmbResult<()> {
        Err(SmbError::AccessDenied)
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
