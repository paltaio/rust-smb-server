//! A backend wrapper that folds names and list patterns to lower case and
//! reports no file ids.

use std::any::Any;

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

/// Wraps `inner` and folds every component of every path and every list
/// pattern with `str::to_lowercase` before the inner backend sees it, so
/// `Foo` and `foo` are one entry there, and an inner backend that honors
/// patterns matches without regard to case. Listings and `stat` give the
/// names as the inner backend stores them, folded. It reports
/// `case_sensitive: false`, and `file_index` 0 from handles and listings.
///
/// Handles it returns have no `as_any`.
#[derive(Clone)]
pub(crate) struct Folding<B> {
    inner: B,
}

impl<B: ShareBackend> Folding<B> {
    pub(crate) fn new(inner: B) -> Self {
        Self { inner }
    }

    fn wrap(handle: Box<dyn Handle>) -> Box<dyn Handle> {
        Box::new(FoldingHandle { inner: handle })
    }
}

/// `path` with every component in lower case.
fn fold(path: &SmbPath) -> SmbResult<SmbPath> {
    path.components()
        .iter()
        .try_fold(SmbPath::root(), |folded, name| {
            folded.join(&name.to_lowercase())
        })
}

#[async_trait]
impl<B: ShareBackend> ShareBackend for Folding<B> {
    async fn open(
        &self,
        path: &SmbPath,
        opts: OpenOptions,
    ) -> SmbResult<(Box<dyn Handle>, OpenAction)> {
        let (handle, action) = self.inner.open(&fold(path)?, opts).await?;
        Ok((Self::wrap(handle), action))
    }

    async fn unlink(&self, path: &SmbPath) -> SmbResult<()> {
        self.inner.unlink(&fold(path)?).await
    }

    async fn rename(&self, from: &SmbPath, to: &SmbPath, replace_if_exists: bool) -> SmbResult<()> {
        self.inner
            .rename(&fold(from)?, &fold(to)?, replace_if_exists)
            .await
    }

    fn capabilities(&self) -> BackendCapabilities {
        BackendCapabilities {
            case_sensitive: false,
            ..self.inner.capabilities()
        }
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
        let (handle, action) = self
            .inner
            .open_stream(file, &fold(path)?, stream, opts)
            .await?;
        Ok((Self::wrap(handle), action))
    }

    async fn remove_stream(
        &self,
        path: &SmbPath,
        file_index: u64,
        stream: &StreamName,
    ) -> SmbResult<()> {
        self.inner
            .remove_stream(&fold(path)?, file_index, stream)
            .await
    }

    async fn rename_stream(
        &self,
        path: &SmbPath,
        file_index: u64,
        from: Option<&StreamName>,
        to: Option<&StreamName>,
        replace_if_exists: bool,
    ) -> SmbResult<()> {
        self.inner
            .rename_stream(&fold(path)?, file_index, from, to, replace_if_exists)
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

struct FoldingHandle {
    inner: Box<dyn Handle>,
}

/// `entries` with no file ids.
fn unindexed(mut entries: Vec<DirEntry>) -> Vec<DirEntry> {
    for entry in &mut entries {
        entry.info.file_index = 0;
    }
    entries
}

#[async_trait]
impl Handle for FoldingHandle {
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
        info.file_index = 0;
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
        let pattern = pattern.map(str::to_lowercase);
        Ok(unindexed(self.inner.list_dir(pattern.as_deref()).await?))
    }

    async fn list_dir_sized(
        &self,
        pattern: Option<&str>,
        ea_size: bool,
    ) -> SmbResult<Vec<DirEntry>> {
        let pattern = pattern.map(str::to_lowercase);
        Ok(unindexed(
            self.inner
                .list_dir_sized(pattern.as_deref(), ea_size)
                .await?,
        ))
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
    use crate::error::SmbError;
    use crate::tests::memfs::MemFsBackend;
    use crate::tests::recorder::{INDEX, Recorder, call_everything, forwarded_calls};
    use crate::tests::util::{dir_opts, opts, path};

    #[tokio::test]
    async fn names_that_differ_in_case_reach_one_inner_entry() {
        let files = MemFsBackend::new();
        let folding = Folding::new(files.clone());
        let (created, action) = folding
            .open(&path("Foo"), opts(OpenIntent::Create))
            .await
            .unwrap();
        assert_eq!(action, OpenAction::Created);
        created.write(0, b"abc").await.unwrap();
        assert_eq!(files.contents("foo"), Some(b"abc".to_vec()));

        let (opened, action) = folding
            .open(&path("fOO"), OpenOptions::default())
            .await
            .unwrap();
        assert_eq!(action, OpenAction::Opened);
        assert_eq!(
            opened.read(0, 10).await.unwrap(),
            Bytes::from_static(b"abc")
        );
        assert!(matches!(
            folding.open(&path("FOO"), opts(OpenIntent::Create)).await,
            Err(SmbError::Exists)
        ));

        folding.unlink(&path("fOo")).await.unwrap();
        assert_eq!(files.contents("foo"), None);
    }

    #[tokio::test]
    async fn every_component_of_a_path_is_folded() {
        let files = MemFsBackend::new();
        let folding = Folding::new(files.clone());
        folding
            .open(&path("Top"), dir_opts(OpenIntent::Create))
            .await
            .unwrap();
        folding
            .open(&path("TOP\\Sub"), dir_opts(OpenIntent::Create))
            .await
            .unwrap();
        folding
            .open(&path("Top\\SUB\\Leaf.TXT"), opts(OpenIntent::Create))
            .await
            .unwrap();
        assert_eq!(files.contents("top\\sub\\leaf.txt"), Some(Vec::new()));
        folding
            .open(&path("tOP\\sUb\\leaf.txt"), OpenOptions::default())
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn rename_folds_both_paths() {
        let files = MemFsBackend::new();
        let folding = Folding::new(files.clone());
        for name in ["Alpha", "Beta"] {
            folding
                .open(&path(name), opts(OpenIntent::Create))
                .await
                .unwrap();
        }
        assert!(matches!(
            folding.rename(&path("ALPHA"), &path("bEtA"), false).await,
            Err(SmbError::Exists)
        ));
        folding
            .rename(&path("ALPHA"), &path("bEtA"), true)
            .await
            .unwrap();
        assert_eq!(files.contents("alpha"), None);
        assert_eq!(files.contents("beta"), Some(Vec::new()));
    }

    #[tokio::test]
    async fn list_patterns_are_folded_and_none_stays_none() {
        let recorder = Recorder::default();
        let folding = Folding::new(recorder.clone());
        let (dir, _) = folding
            .open(&SmbPath::root(), dir_opts(OpenIntent::Open))
            .await
            .unwrap();
        dir.list_dir(Some("A*.TXT")).await.unwrap();
        dir.list_dir(None).await.unwrap();
        dir.list_dir_sized(Some("B?.Txt"), false).await.unwrap();
        dir.list_dir_sized(None, true).await.unwrap();
        assert_eq!(
            recorder.calls()[1..],
            [
                "list_dir Some(\"a*.txt\")",
                "list_dir None",
                "list_dir_sized Some(\"b?.txt\") false",
                "list_dir_sized None true",
            ]
        );
    }

    #[tokio::test]
    async fn a_name_that_grows_past_the_limit_when_folded_is_invalid() {
        let folding = Folding::new(MemFsBackend::new());
        let fits = path(&"\u{130}".repeat(127));
        folding.open(&fits, opts(OpenIntent::Create)).await.unwrap();
        let grows = path(&"\u{130}".repeat(128));
        assert!(matches!(
            folding.open(&grows, opts(OpenIntent::Create)).await,
            Err(SmbError::NameInvalid)
        ));
    }

    #[tokio::test]
    async fn forwards_every_call_it_does_not_change() {
        let recorder = Recorder::default();
        let folding = Folding::new(recorder.clone());
        let seen = call_everything(&folding).await;
        assert_eq!(recorder.calls(), forwarded_calls(str::to_lowercase, INDEX));
        assert!(!seen.case_sensitive);
        assert_eq!(
            [
                seen.stat_index,
                seen.listed_index,
                seen.sized_index,
                seen.stream_index
            ],
            [0; 4]
        );
    }
}
