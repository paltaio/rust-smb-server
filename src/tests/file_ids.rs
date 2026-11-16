//! A backend wrapper that gives every file a stable file id.

use std::any::Any;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use bytes::Bytes;

use crate::backend::{
    BackendCapabilities, DirEntry, DirWatch, FileInfo, FileTimes, Handle, OpenAction, OpenOptions,
    ShareBackend, VolumeInfo,
};
use crate::ea::Ea;
use crate::error::SmbResult;
use crate::path::SmbPath;
use crate::stream::{StreamInfo, StreamName};

/// Wraps `inner` and reports a nonzero `file_index` from handles and
/// listings, whatever the inner backend reports. Files and directories get
/// the ids 1, 2, 3 and so on, in the order the wrapper first sees them.
///
/// A table maps each path to its id. A create gives its path a new id, an
/// open that finds the path takes its id, an unlink drops it, and a rename
/// moves the ids of the entry and of everything below it to the new path
/// and drops those of the entry it replaces. A handle keeps the id it was
/// opened with, so it reports the same id after a rename. A listing gives
/// each entry the id of the path of the directory handle plus the entry's
/// name; a directory handle lists under the path it was opened with.
///
/// The table is updated after the inner call returns, so calls that run at
/// the same time can give one file two ids: a create and an open of one
/// name, or an open that returns after a rename of its file. Tests that need
/// exact ids run those calls one after another. The inner backend gets 0 as
/// the file index of `remove_stream` and `rename_stream`, since the index
/// the server passes is one of these ids.
///
/// Handles it returns have no `as_any`. Clones share the table.
#[derive(Clone)]
pub(crate) struct FileIds<B> {
    inner: B,
    ids: Arc<Mutex<Ids>>,
}

#[derive(Default)]
struct Ids {
    last: u64,
    by_path: HashMap<String, u64>,
}

impl Ids {
    /// The id of `path`, given one if it has none.
    fn get(&mut self, path: &str) -> u64 {
        match self.by_path.get(path) {
            Some(&id) => id,
            None => self.fresh(path),
        }
    }

    /// A new id for `path`, replacing any it had.
    fn fresh(&mut self, path: &str) -> u64 {
        self.last += 1;
        self.by_path.insert(path.to_string(), self.last);
        self.last
    }

    /// A new id for the new entry `path`, which has no entries below it.
    fn create(&mut self, path: &str) -> u64 {
        self.forget(path);
        self.fresh(path)
    }

    /// Drops the ids of `path` and of the paths below it.
    fn forget(&mut self, path: &str) {
        let below = format!("{path}\\");
        self.by_path
            .retain(|key, _| key != path && !key.starts_with(&below));
    }

    /// Moves the ids of `from` and of the paths below it to `to`, which
    /// loses its own.
    fn rename(&mut self, from: &str, to: &str) {
        if from == to {
            return;
        }
        self.forget(to);
        let below = format!("{from}\\");
        self.by_path = std::mem::take(&mut self.by_path)
            .into_iter()
            .map(|(key, id)| {
                if key == from {
                    (to.to_string(), id)
                } else if let Some(rest) = key.strip_prefix(&below) {
                    (format!("{to}\\{rest}"), id)
                } else {
                    (key, id)
                }
            })
            .collect();
    }
}

fn child(dir: &str, name: &str) -> String {
    if dir.is_empty() {
        name.to_string()
    } else {
        format!("{dir}\\{name}")
    }
}

impl<B: ShareBackend> FileIds<B> {
    pub(crate) fn new(inner: B) -> Self {
        Self {
            inner,
            ids: Arc::default(),
        }
    }

    fn wrap(&self, handle: Box<dyn Handle>, path: String, id: u64) -> Box<dyn Handle> {
        Box::new(FileIdsHandle {
            inner: handle,
            path,
            id,
            ids: Arc::clone(&self.ids),
        })
    }
}

#[async_trait]
impl<B: ShareBackend> ShareBackend for FileIds<B> {
    async fn open(
        &self,
        path: &SmbPath,
        opts: OpenOptions,
    ) -> SmbResult<(Box<dyn Handle>, OpenAction)> {
        let (handle, action) = self.inner.open(path, opts).await?;
        let path = path.display_backslash();
        let id = {
            let mut ids = self.ids.lock().unwrap();
            if action == OpenAction::Created {
                ids.create(&path)
            } else {
                ids.get(&path)
            }
        };
        Ok((self.wrap(handle, path, id), action))
    }

    async fn unlink(&self, path: &SmbPath) -> SmbResult<()> {
        self.inner.unlink(path).await?;
        self.ids.lock().unwrap().forget(&path.display_backslash());
        Ok(())
    }

    async fn rename(&self, from: &SmbPath, to: &SmbPath, replace_if_exists: bool) -> SmbResult<()> {
        self.inner.rename(from, to, replace_if_exists).await?;
        self.ids
            .lock()
            .unwrap()
            .rename(&from.display_backslash(), &to.display_backslash());
        Ok(())
    }

    fn capabilities(&self) -> BackendCapabilities {
        self.inner.capabilities()
    }

    async fn volume_info(&self) -> SmbResult<VolumeInfo> {
        self.inner.volume_info().await
    }

    async fn open_stream(
        &self,
        file: Box<dyn Handle>,
        path: &SmbPath,
        stream: &StreamName,
        opts: OpenOptions,
    ) -> SmbResult<(Box<dyn Handle>, OpenAction)> {
        let (handle, action) = self.inner.open_stream(file, path, stream, opts).await?;
        let path = path.display_backslash();
        let id = self.ids.lock().unwrap().get(&path);
        Ok((self.wrap(handle, path, id), action))
    }

    async fn remove_stream(
        &self,
        path: &SmbPath,
        _file_index: u64,
        stream: &StreamName,
    ) -> SmbResult<()> {
        self.inner.remove_stream(path, 0, stream).await
    }

    async fn rename_stream(
        &self,
        path: &SmbPath,
        _file_index: u64,
        from: Option<&StreamName>,
        to: Option<&StreamName>,
        replace_if_exists: bool,
    ) -> SmbResult<()> {
        self.inner
            .rename_stream(path, 0, from, to, replace_if_exists)
            .await
    }

    async fn copy_range(
        &self,
        src: &dyn Handle,
        src_offset: u64,
        dst: &dyn Handle,
        dst_offset: u64,
        len: u64,
    ) -> SmbResult<u64> {
        self.inner
            .copy_range(src, src_offset, dst, dst_offset, len)
            .await
    }

    async fn clone_range(
        &self,
        src: &dyn Handle,
        src_offset: u64,
        dst: &dyn Handle,
        dst_offset: u64,
        len: u64,
    ) -> SmbResult<()> {
        self.inner
            .clone_range(src, src_offset, dst, dst_offset, len)
            .await
    }
}

struct FileIdsHandle {
    inner: Box<dyn Handle>,
    /// The path the handle was opened with.
    path: String,
    id: u64,
    ids: Arc<Mutex<Ids>>,
}

impl FileIdsHandle {
    /// `entries` with the ids of their paths below this directory.
    fn indexed(&self, mut entries: Vec<DirEntry>) -> Vec<DirEntry> {
        let mut ids = self.ids.lock().unwrap();
        for entry in &mut entries {
            entry.info.file_index = ids.get(&child(&self.path, &entry.info.name));
        }
        entries
    }
}

#[async_trait]
impl Handle for FileIdsHandle {
    async fn read(&self, offset: u64, len: u32) -> SmbResult<Bytes> {
        self.inner.read(offset, len).await
    }

    async fn write(&self, offset: u64, data: &[u8]) -> SmbResult<u32> {
        self.inner.write(offset, data).await
    }

    async fn write_owned(&self, offset: u64, data: Vec<u8>) -> SmbResult<u32> {
        self.inner.write_owned(offset, data).await
    }

    async fn flush(&self) -> SmbResult<()> {
        self.inner.flush().await
    }

    async fn stat(&self) -> SmbResult<FileInfo> {
        let mut info = self.inner.stat().await?;
        info.file_index = self.id;
        Ok(info)
    }

    async fn set_times(&self, times: FileTimes) -> SmbResult<()> {
        self.inner.set_times(times).await
    }

    async fn set_attributes(&self, attributes: u32) -> SmbResult<()> {
        self.inner.set_attributes(attributes).await
    }

    async fn truncate(&self, len: u64) -> SmbResult<()> {
        self.inner.truncate(len).await
    }

    async fn list_dir(&self, pattern: Option<&str>) -> SmbResult<Vec<DirEntry>> {
        Ok(self.indexed(self.inner.list_dir(pattern).await?))
    }

    async fn list_dir_sized(
        &self,
        pattern: Option<&str>,
        ea_size: bool,
    ) -> SmbResult<Vec<DirEntry>> {
        Ok(self.indexed(self.inner.list_dir_sized(pattern, ea_size).await?))
    }

    async fn close(self: Box<Self>) -> SmbResult<()> {
        self.inner.close().await
    }

    async fn link_count(&self) -> SmbResult<u32> {
        self.inner.link_count().await
    }

    async fn dir_is_empty(&self) -> SmbResult<bool> {
        self.inner.dir_is_empty().await
    }

    async fn watch(&self) -> SmbResult<Option<Box<dyn DirWatch>>> {
        self.inner.watch().await
    }

    async fn streams(&self) -> SmbResult<Vec<StreamInfo>> {
        self.inner.streams().await
    }

    async fn peek_streams(
        &self,
        entries: &[(&str, &[(StreamName, u32)])],
    ) -> SmbResult<Vec<Vec<Option<(u64, Bytes)>>>> {
        self.inner.peek_streams(entries).await
    }

    async fn eas(&self) -> SmbResult<Vec<Ea>> {
        self.inner.eas().await
    }

    async fn set_eas(&self, eas: &[Ea]) -> SmbResult<()> {
        self.inner.set_eas(eas).await
    }

    fn as_any(&self) -> Option<&(dyn Any + Send + Sync)> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::OpenIntent;
    use crate::tests::memfs::MemFsBackend;
    use crate::tests::recorder::{INDEX, Recorder, call_everything, forwarded_calls};
    use crate::tests::util::{dir_opts, opts, path};

    /// The id the wrapper reports for the entry `name`, through a new
    /// handle.
    async fn id_of(ids: &FileIds<MemFsBackend>, name: &str) -> u64 {
        let (handle, _) = ids.open(&path(name), OpenOptions::default()).await.unwrap();
        handle.stat().await.unwrap().file_index
    }

    /// The ids a listing of the directory `dir` gives, by entry name.
    async fn listed_ids(ids: &FileIds<MemFsBackend>, dir: &str) -> Vec<(String, u64)> {
        let (handle, _) = ids
            .open(&path(dir), dir_opts(OpenIntent::Open))
            .await
            .unwrap();
        let mut listed: Vec<_> = handle
            .list_dir(None)
            .await
            .unwrap()
            .into_iter()
            .map(|entry| (entry.info.name, entry.info.file_index))
            .collect();
        listed.sort();
        listed
    }

    #[tokio::test]
    async fn an_id_is_nonzero_and_stable_across_opens_and_listings() {
        let files = MemFsBackend::new()
            .with_dir("d")
            .with_file("d\\seeded", b"");
        let ids = FileIds::new(files);
        let (created, action) = ids
            .open(&path("d\\f"), opts(OpenIntent::Create))
            .await
            .unwrap();
        assert_eq!(action, OpenAction::Created);
        let id = created.stat().await.unwrap().file_index;
        assert_ne!(id, 0);
        assert_eq!(id_of(&ids, "d\\f").await, id);
        let seeded = id_of(&ids, "d\\seeded").await;
        assert_eq!(
            listed_ids(&ids, "d").await,
            [("f".to_string(), id), ("seeded".to_string(), seeded)]
        );
    }

    #[tokio::test]
    async fn different_entries_get_different_ids() {
        let files = MemFsBackend::new()
            .with_dir("d")
            .with_file("a", b"")
            .with_file("b", b"");
        let ids = FileIds::new(files);
        let all = [
            id_of(&ids, "").await,
            id_of(&ids, "d").await,
            id_of(&ids, "a").await,
            id_of(&ids, "b").await,
        ];
        assert!(all.iter().all(|&id| id != 0));
        let mut unique = all.to_vec();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(unique.len(), all.len());
    }

    #[tokio::test]
    async fn a_rename_keeps_the_id_of_the_file() {
        let files = MemFsBackend::new().with_file("a", b"x");
        let ids = FileIds::new(files);
        let id = id_of(&ids, "a").await;

        ids.rename(&path("a"), &path("b"), false).await.unwrap();
        assert_eq!(id_of(&ids, "b").await, id);
        assert_eq!(listed_ids(&ids, "").await, [("b".to_string(), id)]);
    }

    #[tokio::test]
    async fn a_handle_keeps_its_id_through_a_rename() {
        let ids = FileIds::new(Recorder::default());
        let (handle, _) = ids.open(&path("a"), OpenOptions::default()).await.unwrap();
        let id = handle.stat().await.unwrap().file_index;
        assert_ne!(id, 0);

        ids.rename(&path("a"), &path("b"), false).await.unwrap();
        assert_eq!(handle.stat().await.unwrap().file_index, id);
    }

    #[tokio::test]
    async fn a_directory_rename_keeps_the_ids_below_it() {
        let files = MemFsBackend::new()
            .with_dir("d")
            .with_dir("d\\sub")
            .with_file("d\\sub\\f", b"")
            .with_file("d\\g", b"");
        let ids = FileIds::new(files);
        let dir = id_of(&ids, "d").await;
        let sub = id_of(&ids, "d\\sub").await;
        let f = id_of(&ids, "d\\sub\\f").await;
        let g = id_of(&ids, "d\\g").await;

        ids.rename(&path("d"), &path("e"), false).await.unwrap();
        assert_eq!(id_of(&ids, "e").await, dir);
        assert_eq!(id_of(&ids, "e\\sub\\f").await, f);
        assert_eq!(
            listed_ids(&ids, "e").await,
            [("g".to_string(), g), ("sub".to_string(), sub)]
        );
    }

    #[tokio::test]
    async fn a_rename_over_a_file_drops_the_id_of_the_replaced_file() {
        let files = MemFsBackend::new().with_file("a", b"").with_file("b", b"");
        let ids = FileIds::new(files);
        let a = id_of(&ids, "a").await;
        let b = id_of(&ids, "b").await;

        ids.rename(&path("a"), &path("b"), true).await.unwrap();
        assert_eq!(id_of(&ids, "b").await, a);
        let (created, _) = ids
            .open(&path("a"), opts(OpenIntent::Create))
            .await
            .unwrap();
        let fresh = created.stat().await.unwrap().file_index;
        assert!(fresh != a && fresh != b);
    }

    #[tokio::test]
    async fn a_rename_of_an_unseen_file_over_a_known_one_gives_the_target_a_new_id() {
        let files = MemFsBackend::new().with_file("a", b"").with_file("b", b"");
        let ids = FileIds::new(files);
        let replaced = id_of(&ids, "b").await;

        ids.rename(&path("a"), &path("b"), true).await.unwrap();
        assert_ne!(id_of(&ids, "b").await, replaced);
    }

    #[tokio::test]
    async fn a_refused_rename_changes_no_id() {
        let files = MemFsBackend::new().with_file("a", b"").with_file("b", b"");
        let ids = FileIds::new(files);
        let a = id_of(&ids, "a").await;
        let b = id_of(&ids, "b").await;
        assert!(ids.rename(&path("a"), &path("b"), false).await.is_err());
        assert_eq!((id_of(&ids, "a").await, id_of(&ids, "b").await), (a, b));
    }

    #[tokio::test]
    async fn a_file_recreated_outside_the_wrapper_after_an_unlink_gets_a_new_id() {
        let files = MemFsBackend::new().with_file("f", b"");
        let ids = FileIds::new(files.clone());
        let before = id_of(&ids, "f").await;

        ids.unlink(&path("f")).await.unwrap();
        files.clone().with_file("f", b"new");
        assert_ne!(id_of(&ids, "f").await, before);
    }

    #[tokio::test]
    async fn an_overwrite_keeps_the_id() {
        let files = MemFsBackend::new().with_file("f", b"abc");
        let ids = FileIds::new(files);
        let id = id_of(&ids, "f").await;
        let (overwritten, action) = ids
            .open(&path("f"), opts(OpenIntent::OverwriteOrCreate))
            .await
            .unwrap();
        assert_eq!(action, OpenAction::Overwritten);
        assert_eq!(overwritten.stat().await.unwrap().file_index, id);
    }

    #[tokio::test]
    async fn a_create_gives_a_new_id_to_a_path_deleted_outside_the_wrapper() {
        let files = MemFsBackend::new().with_file("f", b"abc");
        let ids = FileIds::new(files.clone());
        let id = id_of(&ids, "f").await;
        files.remove("f");
        let (created, action) = ids
            .open(&path("f"), opts(OpenIntent::Create))
            .await
            .unwrap();
        assert_eq!(action, OpenAction::Created);
        assert_ne!(created.stat().await.unwrap().file_index, id);
    }

    #[tokio::test]
    async fn forwards_every_call_it_does_not_change() {
        let recorder = Recorder::default();
        let ids = FileIds::new(recorder.clone());
        let seen = call_everything(&ids).await;
        assert_eq!(recorder.calls(), forwarded_calls(str::to_string, 0));
        assert!(seen.case_sensitive);
        // The file and its stream share one id, the entries listed under the
        // file another, and the inner backend's own index appears nowhere.
        assert_eq!(seen.stat_index, seen.stream_index);
        assert_eq!(seen.listed_index, seen.sized_index);
        for id in [seen.stat_index, seen.listed_index] {
            assert!(id != 0 && id != INDEX);
        }
        assert_ne!(seen.stat_index, seen.listed_index);
    }
}
