//! An open file or directory.

use std::any::Any;
use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;

use crate::backend::{DirEntry, FileInfo, FileTimes, Handle};
use crate::error::{SmbError, SmbResult};

use super::backend::Shared;
use super::list::list_entries;
use super::lookup::{DirRef, Found};
use super::meta;
use super::read::OpenFile;

/// An open file or directory.
pub(super) struct S3Handle {
    shared: Arc<Shared>,
    node: Node,
}

enum Node {
    Dir(DirRef),
    File(OpenFile),
}

impl S3Handle {
    pub(super) fn new(shared: Arc<Shared>, found: Found) -> Self {
        let node = match found {
            Found::Dir(dir) => Node::Dir(dir),
            Found::File(file) => Node::File(OpenFile::new(&shared.ahead, file)),
        };
        S3Handle { shared, node }
    }
}

#[async_trait]
impl Handle for S3Handle {
    async fn read(&self, offset: u64, len: u32) -> SmbResult<Bytes> {
        match &self.node {
            Node::Dir(_) => Err(SmbError::IsDirectory),
            Node::File(file) => file.read(&self.shared, offset, len).await,
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
        Ok(match &self.node {
            Node::Dir(dir) => meta::dir_info(&dir.name, dir.marker.as_deref(), self.shared.built),
            Node::File(file) => file.info(),
        })
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
            Node::File(_) => Err(SmbError::NotADirectory),
            Node::Dir(dir) => list_entries(&self.shared, dir, pattern).await,
        }
    }

    async fn close(self: Box<Self>) -> SmbResult<()> {
        Ok(())
    }

    async fn dir_is_empty(&self) -> SmbResult<bool> {
        match &self.node {
            Node::File(_) => Err(SmbError::NotADirectory),
            Node::Dir(dir) => self.shared.is_empty(&dir.key, &self.shared.retry()).await,
        }
    }

    fn as_any(&self) -> Option<&(dyn Any + Send + Sync)> {
        Some(self)
    }
}
