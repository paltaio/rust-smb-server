//! An open file or directory.

use std::any::Any;
use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;

use crate::backend::{DirEntry, FileInfo, FileTimes, Handle};
use crate::error::{SmbError, SmbResult};

use super::backend::Shared;
use super::change::{self, apply_attributes, apply_times};
use super::entry::Own;
use super::list::list_entries;
use super::lookup::DirRef;
use super::meta;
use super::overlay::Held;

/// An open file or directory.
pub(super) struct S3Handle {
    shared: Arc<Shared>,
    node: Node,
}

enum Node {
    /// The share root.
    Root,
    /// An entry of the overlay.
    Entry(Held),
}

impl S3Handle {
    pub(super) fn root(shared: Arc<Shared>) -> Self {
        S3Handle {
            shared,
            node: Node::Root,
        }
    }

    /// A handle on the entry `held`. The data file of the entry, if it has
    /// one, stays open while a handle is open on the entry, so the handle's
    /// reads and writes do not open it each time, and reach it if an upload
    /// takes it out of the cache directory meanwhile.
    pub(super) async fn entry(shared: Arc<Shared>, held: Held) -> Self {
        held.entry.state().opened();
        let handle = S3Handle {
            shared,
            node: Node::Entry(held),
        };
        if let Node::Entry(held) = &handle.node {
            change::open_data(&handle.shared, held).await;
        }
        handle
    }

    /// The directory the handle is on.
    fn dir(&self) -> SmbResult<DirRef> {
        match &self.node {
            Node::Root => Ok(self.shared.root()),
            Node::Entry(held) => {
                if !held.entry.is_dir() {
                    return Err(SmbError::NotADirectory);
                }
                Ok(held.entry.state().dir_ref())
            }
        }
    }

    /// The held entry of a file. The root and directories are not files.
    fn file(&self) -> SmbResult<&Held> {
        match &self.node {
            Node::Entry(held) if !held.entry.is_dir() => Ok(held),
            _ => Err(SmbError::IsDirectory),
        }
    }
}

#[async_trait]
impl Handle for S3Handle {
    async fn read(&self, offset: u64, len: u32) -> SmbResult<Bytes> {
        self.file()?.entry.read(&self.shared, offset, len).await
    }

    async fn write(&self, offset: u64, data: &[u8]) -> SmbResult<u32> {
        self.write_owned(offset, data.to_vec()).await
    }

    async fn write_owned(&self, offset: u64, data: Vec<u8>) -> SmbResult<u32> {
        self.shared.local()?;
        change::write(&self.shared, self.file()?, offset, data).await
    }

    async fn flush(&self) -> SmbResult<()> {
        match &self.node {
            Node::Entry(held) if self.shared.local.is_some() => {
                change::flush(&self.shared, held).await
            }
            _ => Ok(()),
        }
    }

    async fn stat(&self) -> SmbResult<FileInfo> {
        Ok(match &self.node {
            Node::Root => {
                let own = *self.shared.root_own();
                meta::entry_info("", true, 0, own.times, own.attributes)
            }
            Node::Entry(held) => held.entry.info(self.shared.built),
        })
    }

    async fn set_times(&self, times: FileTimes) -> SmbResult<()> {
        self.shared.local()?;
        match &self.node {
            Node::Root => {
                change_root(&self.shared, |own| apply_times(own, times));
                Ok(())
            }
            Node::Entry(held) => change::set_times(&self.shared, held, times).await,
        }
    }

    async fn set_attributes(&self, attributes: u32) -> SmbResult<()> {
        self.shared.local()?;
        match &self.node {
            Node::Root => {
                change_root(&self.shared, |own| apply_attributes(own, attributes));
                Ok(())
            }
            Node::Entry(held) => change::set_attributes(&self.shared, held, attributes).await,
        }
    }

    async fn truncate(&self, len: u64) -> SmbResult<()> {
        self.shared.local()?;
        change::truncate(&self.shared, self.file()?, len).await
    }

    async fn list_dir(&self, pattern: Option<&str>) -> SmbResult<Vec<DirEntry>> {
        list_entries(&self.shared, &self.dir()?, pattern).await
    }

    async fn close(self: Box<Self>) -> SmbResult<()> {
        let mut handle = *self;
        if let Node::Entry(held) = std::mem::replace(&mut handle.node, Node::Root) {
            change::close_file(&handle.shared, held);
        }
        Ok(())
    }

    async fn dir_is_empty(&self) -> SmbResult<bool> {
        let dir = self.dir()?;
        self.shared.is_empty(&dir.key, &self.shared.retry()).await
    }

    fn as_any(&self) -> Option<&(dyn Any + Send + Sync)> {
        Some(self)
    }
}

impl Drop for S3Handle {
    fn drop(&mut self) {
        if let Node::Entry(held) = &self.node {
            held.entry.state().closed();
        }
    }
}

/// Changes the times and attributes of the share root, and its change time
/// unless `change` sets that.
fn change_root(shared: &Shared, change: impl FnOnce(&mut Own)) {
    let mut own = shared.root_own();
    let before = *own;
    change(&mut own);
    own.changed_from(&before);
}
