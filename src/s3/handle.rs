//! An open file or directory.

use std::any::Any;
use std::io;
use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use tracing::debug;

use crate::backend::{DirEntry, FileInfo, FileTimes, Handle};
use crate::error::{SmbError, SmbResult};

use super::backend::Shared;
use super::error::S3Error;
use super::list::list_entries;
use super::lookup::Found;
use super::object::{ByteRange, ObjectHead};

/// A file or directory as it was when it was opened.
pub(super) struct S3Handle {
    shared: Arc<Shared>,
    node: Found,
}

impl S3Handle {
    pub(super) fn new(shared: Arc<Shared>, node: Found) -> Self {
        S3Handle { shared, node }
    }
}

/// Whether the object a GET returned is the one that was opened, going by its
/// size, modification time and ETag.
fn same_version(got: &ObjectHead, opened: &ObjectHead) -> bool {
    got.size == opened.size && got.last_modified == opened.last_modified && got.etag == opened.etag
}

#[async_trait]
impl Handle for S3Handle {
    async fn read(&self, offset: u64, len: u32) -> SmbResult<Bytes> {
        let Found::File(file) = &self.node else {
            return Err(SmbError::IsDirectory);
        };
        let size = file.head.size;
        if len == 0 || offset >= size {
            return Ok(Bytes::new());
        }
        let range = ByteRange::new(offset, u64::from(len).min(size - offset))
            .map_err(S3Error::into_smb_error)?;
        // A GET pins the version of an object with an ETag. For one without,
        // a different size or modification time, or an ETag the GET now
        // reports, marks another version.
        let etag = Some(file.head.etag.as_str()).filter(|etag| !etag.is_empty());
        let got = self
            .shared
            .client
            .get_object(&file.key, range, etag, self.shared.retry())
            .await;
        match got {
            Ok(object) if etag.is_some() || same_version(&object.head, &file.head) => {
                Ok(object.data)
            }
            Ok(_) => {
                debug!("an object without an ETag changed after it was opened");
                self.shared.forget_file(&file.key);
                Err(SmbError::Io(io::Error::other(
                    "the object changed after it was opened",
                )))
            }
            Err(e) => {
                if e.is_precondition_failed() || e.is_no_such_key() {
                    self.shared.forget_file(&file.key);
                }
                Err(e.into_smb_error())
            }
        }
    }

    async fn write(&self, _offset: u64, _data: &[u8]) -> SmbResult<u32> {
        Err(SmbError::AccessDenied)
    }

    async fn write_owned(&self, _offset: u64, _data: Vec<u8>) -> SmbResult<u32> {
        Err(SmbError::AccessDenied)
    }

    async fn flush(&self) -> SmbResult<()> {
        Ok(())
    }

    async fn stat(&self) -> SmbResult<FileInfo> {
        Ok(self.node.info(&self.shared))
    }

    async fn set_times(&self, _times: FileTimes) -> SmbResult<()> {
        Err(SmbError::AccessDenied)
    }

    async fn set_attributes(&self, _attributes: u32) -> SmbResult<()> {
        Err(SmbError::AccessDenied)
    }

    async fn truncate(&self, _len: u64) -> SmbResult<()> {
        Err(SmbError::AccessDenied)
    }

    async fn list_dir(&self, pattern: Option<&str>) -> SmbResult<Vec<DirEntry>> {
        match &self.node {
            Found::File(_) => Err(SmbError::NotADirectory),
            Found::Dir(dir) => list_entries(&self.shared, dir, pattern).await,
        }
    }

    async fn close(self: Box<Self>) -> SmbResult<()> {
        Ok(())
    }

    async fn dir_is_empty(&self) -> SmbResult<bool> {
        match &self.node {
            Found::File(_) => Err(SmbError::NotADirectory),
            Found::Dir(dir) => self.shared.is_empty(&dir.key, &self.shared.retry()).await,
        }
    }

    fn as_any(&self) -> Option<&(dyn Any + Send + Sync)> {
        Some(self)
    }
}
