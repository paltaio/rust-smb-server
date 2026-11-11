//! The backend: a bucket served as a share.

use std::fmt;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, SystemTime};

use async_trait::async_trait;

use crate::backend::{
    BackendCapabilities, Handle, OpenAction, OpenIntent, OpenOptions, ShareBackend,
};
use crate::error::{SmbError, SmbResult};
use crate::path::SmbPath;

use super::cache::MetaCache;
use super::client::S3Client;
use super::handle::S3Handle;
use super::lookup::Found;
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
}

/// Whether an open with `opts` may change the share.
fn changes(opts: &OpenOptions) -> bool {
    opts.write || opts.write_attributes || opts.delete_on_close || opts.intent != OpenIntent::Open
}

#[async_trait]
impl ShareBackend for S3Backend {
    async fn open(
        &self,
        path: &SmbPath,
        opts: OpenOptions,
    ) -> SmbResult<(Box<dyn Handle>, OpenAction)> {
        if changes(&opts) {
            return Err(SmbError::AccessDenied);
        }
        let found = self.shared.lookup(path, &self.shared.retry()).await?;
        match &found {
            Found::Dir(_) if opts.non_directory => return Err(SmbError::IsDirectory),
            Found::File(_) if opts.directory => return Err(SmbError::NotADirectory),
            _ => {}
        }
        Ok((
            Box::new(S3Handle::new(Arc::clone(&self.shared), found)),
            OpenAction::Opened,
        ))
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
            is_read_only: true,
            case_sensitive: !self.shared.case_insensitive,
            ..BackendCapabilities::default()
        }
    }
}
