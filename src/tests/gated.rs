//! A backend wrapper that parks chosen calls until the test lets them go.

use std::any::Any;
use std::future::Future;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use tokio::sync::Notify;

use crate::backend::{
    BackendCapabilities, DirEntry, DirWatch, FileInfo, FileTimes, Handle, OpenAction, OpenOptions,
    ShareBackend, VolumeInfo,
};
use crate::ea::Ea;
use crate::error::SmbResult;
use crate::path::SmbPath;
use crate::stream::{StreamInfo, StreamName};
use crate::tests::util::path;

/// How long a test waits for a call to reach its gate, and a parked call
/// waits to be released, before the test fails.
const GATE_TIMEOUT: Duration = Duration::from_secs(30);

/// A call a gate can park.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Op {
    Open,
    Unlink,
    /// Matched on the source path.
    Rename,
    Stat,
    /// `list_dir` and `list_dir_sized`.
    ListDir,
    Read,
    /// `write` and `write_owned`.
    Write,
    Truncate,
}

/// Wraps `inner` and parks calls at gates the test arms.
///
/// Each gate matches one [`Op`], optionally on one path: the opened path,
/// the rename source, or for handle calls the path the handle was opened
/// with. It parks the first matching call, before or after the inner call,
/// and is then used up. Arm one gate per call to park several. A call no
/// gate matches passes straight through. A parked call that is not released
/// within 30 s panics. Clones share the gates.
///
/// Handles it returns have no `as_any`.
#[derive(Clone)]
pub(crate) struct Gated<B> {
    inner: B,
    gates: Arc<Gates>,
}

impl<B: ShareBackend> Gated<B> {
    pub(crate) fn new(inner: B) -> Self {
        Self {
            inner,
            gates: Arc::default(),
        }
    }

    /// A gate that parks the next `op` before it reaches the inner backend.
    pub(crate) fn arm(&self, op: Op) -> Gate {
        self.gates.arm(op, None, false)
    }

    /// A gate that parks the next `op` on `path` before it reaches the
    /// inner backend.
    pub(crate) fn arm_at(&self, op: Op, path: &str) -> Gate {
        self.gates.arm(op, Some(path), false)
    }

    /// A gate that parks the next `op` after the inner backend has answered.
    pub(crate) fn arm_after(&self, op: Op) -> Gate {
        self.gates.arm(op, None, true)
    }

    /// A gate that parks the next `op` on `path` after the inner backend
    /// has answered.
    pub(crate) fn arm_after_at(&self, op: Op, path: &str) -> Gate {
        self.gates.arm(op, Some(path), true)
    }

    fn wrap(&self, handle: Box<dyn Handle>, path: &SmbPath) -> Box<dyn Handle> {
        Box::new(GatedHandle {
            inner: handle,
            path: path.clone(),
            gates: Arc::clone(&self.gates),
        })
    }
}

/// The test's end of one gate.
pub(crate) struct Gate {
    armed: Arc<Armed>,
}

impl Gate {
    /// Waits until a call is parked here.
    pub(crate) async fn reached(&self) {
        tokio::time::timeout(GATE_TIMEOUT, self.armed.reached.notified())
            .await
            .expect("a call reaches the gate");
    }

    /// Lets the parked call go. Released before a call arrives, the gate
    /// lets that call through without parking it.
    pub(crate) fn release(&self) {
        self.armed.go.notify_one();
    }
}

struct Armed {
    op: Op,
    path: Option<SmbPath>,
    after: bool,
    reached: Notify,
    go: Notify,
}

/// The gates that wait for a call.
#[derive(Default)]
struct Gates {
    armed: Mutex<Vec<Arc<Armed>>>,
}

impl Gates {
    fn arm(&self, op: Op, at: Option<&str>, after: bool) -> Gate {
        let armed = Arc::new(Armed {
            op,
            path: at.map(path),
            after,
            reached: Notify::new(),
            go: Notify::new(),
        });
        self.armed.lock().unwrap().push(Arc::clone(&armed));
        Gate { armed }
    }

    /// Parks the call at the first gate that matches it, which is used up.
    async fn pass(&self, op: Op, path: &SmbPath, after: bool) {
        let gate = {
            let mut armed = self.armed.lock().unwrap();
            let at = armed.iter().position(|gate| {
                gate.op == op
                    && gate.after == after
                    && gate.path.as_ref().is_none_or(|gate_path| gate_path == path)
            });
            at.map(|at| armed.remove(at))
        };
        if let Some(gate) = gate {
            gate.reached.notify_one();
            tokio::time::timeout(GATE_TIMEOUT, gate.go.notified())
                .await
                .expect("the test releases the gate");
        }
    }

    /// Runs `call` between the gates for `op` on `path`.
    async fn around<T: Send>(
        &self,
        op: Op,
        path: &SmbPath,
        call: impl Future<Output = T> + Send,
    ) -> T {
        self.pass(op, path, false).await;
        let result = call.await;
        self.pass(op, path, true).await;
        result
    }
}

#[async_trait]
impl<B: ShareBackend> ShareBackend for Gated<B> {
    async fn open(
        &self,
        path: &SmbPath,
        opts: OpenOptions,
    ) -> SmbResult<(Box<dyn Handle>, OpenAction)> {
        let (handle, action) = self
            .gates
            .around(Op::Open, path, self.inner.open(path, opts))
            .await?;
        Ok((self.wrap(handle, path), action))
    }

    async fn unlink(&self, path: &SmbPath) -> SmbResult<()> {
        self.gates
            .around(Op::Unlink, path, self.inner.unlink(path))
            .await
    }

    async fn rename(&self, from: &SmbPath, to: &SmbPath, replace_if_exists: bool) -> SmbResult<()> {
        self.gates
            .around(
                Op::Rename,
                from,
                self.inner.rename(from, to, replace_if_exists),
            )
            .await
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
        Ok((self.wrap(handle, path), action))
    }

    async fn remove_stream(
        &self,
        path: &SmbPath,
        file_index: u64,
        stream: &StreamName,
    ) -> SmbResult<()> {
        self.inner.remove_stream(path, file_index, stream).await
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
            .rename_stream(path, file_index, from, to, replace_if_exists)
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

struct GatedHandle {
    inner: Box<dyn Handle>,
    path: SmbPath,
    gates: Arc<Gates>,
}

impl GatedHandle {
    async fn around<T: Send>(&self, op: Op, call: impl Future<Output = T> + Send) -> T {
        self.gates.around(op, &self.path, call).await
    }
}

#[async_trait]
impl Handle for GatedHandle {
    async fn read(&self, offset: u64, len: u32) -> SmbResult<Bytes> {
        self.around(Op::Read, self.inner.read(offset, len)).await
    }

    async fn write(&self, offset: u64, data: &[u8]) -> SmbResult<u32> {
        self.around(Op::Write, self.inner.write(offset, data)).await
    }

    async fn write_owned(&self, offset: u64, data: Vec<u8>) -> SmbResult<u32> {
        self.around(Op::Write, self.inner.write_owned(offset, data))
            .await
    }

    async fn flush(&self) -> SmbResult<()> {
        self.inner.flush().await
    }

    async fn stat(&self) -> SmbResult<FileInfo> {
        self.around(Op::Stat, self.inner.stat()).await
    }

    async fn set_times(&self, times: FileTimes) -> SmbResult<()> {
        self.inner.set_times(times).await
    }

    async fn set_attributes(&self, attributes: u32) -> SmbResult<()> {
        self.inner.set_attributes(attributes).await
    }

    async fn truncate(&self, len: u64) -> SmbResult<()> {
        self.around(Op::Truncate, self.inner.truncate(len)).await
    }

    async fn list_dir(&self, pattern: Option<&str>) -> SmbResult<Vec<DirEntry>> {
        self.around(Op::ListDir, self.inner.list_dir(pattern)).await
    }

    async fn list_dir_sized(
        &self,
        pattern: Option<&str>,
        ea_size: bool,
    ) -> SmbResult<Vec<DirEntry>> {
        self.around(Op::ListDir, self.inner.list_dir_sized(pattern, ea_size))
            .await
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

    async fn open_shared(
        gated: &Gated<MemFsBackend>,
        name: &str,
        opts: OpenOptions,
    ) -> Arc<dyn Handle> {
        let (handle, _) = gated.open(&path(name), opts).await.unwrap();
        Arc::from(handle)
    }

    #[tokio::test]
    async fn an_armed_open_parks_before_the_inner_backend_until_released() {
        let files = MemFsBackend::new();
        let gated = Gated::new(files.clone());
        let gate = gated.arm_at(Op::Open, "f");
        let opening = tokio::spawn({
            let gated = gated.clone();
            async move {
                gated
                    .open(&path("f"), opts(OpenIntent::Create))
                    .await
                    .map(|(_, action)| action)
            }
        });
        gate.reached().await;
        assert!(!opening.is_finished());
        assert_eq!(files.contents("f"), None);
        assert_eq!(files.open_handles(), 0);

        gate.release();
        assert_eq!(opening.await.unwrap().unwrap(), OpenAction::Created);
        assert_eq!(files.contents("f"), Some(Vec::new()));
        assert_eq!(files.open_handles(), 1);
    }

    #[tokio::test]
    async fn an_after_gate_parks_once_the_inner_call_has_answered() {
        let files = MemFsBackend::new();
        let gated = Gated::new(files.clone());
        let gate = gated.arm_after_at(Op::Open, "f");
        let opening = tokio::spawn({
            let gated = gated.clone();
            async move {
                gated
                    .open(&path("f"), opts(OpenIntent::Create))
                    .await
                    .map(|(_, action)| action)
            }
        });
        gate.reached().await;
        assert!(!opening.is_finished());
        assert_eq!(files.contents("f"), Some(Vec::new()));
        assert_eq!(files.open_handles(), 1);

        gate.release();
        assert_eq!(opening.await.unwrap().unwrap(), OpenAction::Created);
    }

    #[tokio::test]
    async fn an_after_gate_parks_a_call_whose_inner_call_failed() {
        let gated = Gated::new(MemFsBackend::new());
        let gate = gated.arm_after_at(Op::Open, "missing");
        let opening = tokio::spawn({
            let gated = gated.clone();
            async move {
                gated
                    .open(&path("missing"), OpenOptions::default())
                    .await
                    .map(drop)
            }
        });
        gate.reached().await;
        assert!(!opening.is_finished());

        gate.release();
        assert!(matches!(opening.await.unwrap(), Err(SmbError::NotFound)));
    }

    #[tokio::test]
    async fn a_gate_ignores_the_calls_of_other_ops() {
        let files = MemFsBackend::new()
            .with_file("f", b"abc")
            .with_file("r", b"")
            .with_file("u", b"");
        let gated = Gated::new(files);
        let gate = gated.arm(Op::Stat);
        let f = open_shared(&gated, "f", OpenOptions::default()).await;
        f.read(0, 3).await.unwrap();
        f.write(0, b"x").await.unwrap();
        f.truncate(2).await.unwrap();
        gated.rename(&path("r"), &path("r2"), false).await.unwrap();
        gated.unlink(&path("u")).await.unwrap();
        let dir = open_shared(&gated, "", dir_opts(OpenIntent::Open)).await;
        dir.list_dir(None).await.unwrap();

        let stat = tokio::spawn(async move { f.stat().await.map(drop) });
        gate.reached().await;
        gate.release();
        stat.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn a_gate_with_a_path_ignores_other_paths() {
        let files = MemFsBackend::new().with_file("f", b"").with_file("g", b"");
        let gated = Gated::new(files.clone());
        let f = open_shared(&gated, "f", OpenOptions::default()).await;
        let g = open_shared(&gated, "g", OpenOptions::default()).await;
        let gate = gated.arm_at(Op::Stat, "f");
        g.stat().await.unwrap();
        let stat = tokio::spawn(async move { f.stat().await.map(drop) });
        gate.reached().await;
        assert!(!stat.is_finished());
        gate.release();
        stat.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn a_rename_gate_matches_the_source() {
        let files = MemFsBackend::new().with_file("a", b"").with_file("b", b"");
        let gated = Gated::new(files.clone());
        let gate = gated.arm_at(Op::Rename, "a");
        gated.rename(&path("b"), &path("c"), false).await.unwrap();
        let renaming = tokio::spawn({
            let gated = gated.clone();
            async move { gated.rename(&path("a"), &path("d"), false).await }
        });
        gate.reached().await;
        assert!(!renaming.is_finished());
        assert!(files.contents("a").is_some());
        gate.release();
        renaming.await.unwrap().unwrap();
        assert_eq!(files.contents("a"), None);
        assert!(files.contents("d").is_some());
    }

    #[tokio::test]
    async fn one_gate_parks_one_call() {
        let files = MemFsBackend::new().with_file("f", b"");
        let gated = Gated::new(files.clone());
        let f = open_shared(&gated, "f", OpenOptions::default()).await;
        let first = gated.arm(Op::Stat);
        let second = gated.arm(Op::Stat);
        let stat_first = tokio::spawn({
            let f = Arc::clone(&f);
            async move { f.stat().await.map(drop) }
        });
        first.reached().await;
        let stat_second = tokio::spawn({
            let f = Arc::clone(&f);
            async move { f.stat().await.map(drop) }
        });
        second.reached().await;
        f.stat().await.unwrap();
        assert!(!stat_first.is_finished());
        assert!(!stat_second.is_finished());

        second.release();
        stat_second.await.unwrap().unwrap();
        assert!(!stat_first.is_finished());
        first.release();
        stat_first.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn a_gate_released_early_lets_the_call_through() {
        let files = MemFsBackend::new().with_file("f", b"abc");
        let gated = Gated::new(files.clone());
        let f = open_shared(&gated, "f", OpenOptions::default()).await;
        let gate = gated.arm(Op::Stat);
        gate.release();
        assert_eq!(f.stat().await.unwrap().end_of_file, 3);
        gate.reached().await;
    }

    async fn call(
        op: Op,
        gated: Gated<MemFsBackend>,
        file: Arc<dyn Handle>,
        dir: Arc<dyn Handle>,
        name: String,
    ) -> SmbResult<()> {
        match op {
            Op::Open => gated
                .open(&path(&name), opts(OpenIntent::OpenOrCreate))
                .await
                .map(drop),
            Op::Unlink => gated.unlink(&path(&name)).await,
            Op::Rename => {
                gated
                    .rename(&path(&name), &path(&format!("{name}2")), false)
                    .await
            }
            Op::Stat => file.stat().await.map(drop),
            Op::ListDir => dir.list_dir(None).await.map(drop),
            Op::Read => file.read(0, 1).await.map(drop),
            Op::Write => file.write(0, b"x").await.map(drop),
            Op::Truncate => file.truncate(0).await,
        }
    }

    #[tokio::test]
    async fn every_op_parks_before_and_after_the_inner_call() {
        let files = MemFsBackend::new().with_file("f", b"abc");
        let gated = Gated::new(files.clone());
        let file = open_shared(&gated, "f", OpenOptions::default()).await;
        let dir = open_shared(&gated, "", dir_opts(OpenIntent::Open)).await;
        let ops = [
            Op::Open,
            Op::Unlink,
            Op::Rename,
            Op::Stat,
            Op::ListDir,
            Op::Read,
            Op::Write,
            Op::Truncate,
        ];
        for (n, (after, op)) in [false, true]
            .into_iter()
            .flat_map(|after| ops.into_iter().map(move |op| (after, op)))
            .enumerate()
        {
            let name = format!("n{n}");
            files.clone().with_file(&name, b"");
            let gate = if after {
                gated.arm_after(op)
            } else {
                gated.arm(op)
            };
            let call = tokio::spawn(call(
                op,
                gated.clone(),
                Arc::clone(&file),
                Arc::clone(&dir),
                name,
            ));
            gate.reached().await;
            assert!(!call.is_finished(), "{op:?}, after {after}");
            gate.release();
            call.await.unwrap().unwrap();
        }
    }

    #[tokio::test]
    async fn a_sized_listing_and_an_owned_write_use_the_gates_of_their_ops() {
        let files = MemFsBackend::new().with_file("f", b"");
        let gated = Gated::new(files.clone());
        let file = open_shared(&gated, "f", OpenOptions::default()).await;
        let dir = open_shared(&gated, "", dir_opts(OpenIntent::Open)).await;

        let gate = gated.arm(Op::ListDir);
        let listing = tokio::spawn(async move { dir.list_dir_sized(None, true).await.map(drop) });
        gate.reached().await;
        assert!(!listing.is_finished());
        gate.release();
        listing.await.unwrap().unwrap();

        let gate = gated.arm(Op::Write);
        let writing = tokio::spawn(async move { file.write_owned(0, b"xy".to_vec()).await });
        gate.reached().await;
        assert!(!writing.is_finished());
        assert_eq!(files.contents("f"), Some(Vec::new()));
        gate.release();
        assert_eq!(writing.await.unwrap().unwrap(), 2);
        assert_eq!(files.contents("f"), Some(b"xy".to_vec()));
    }

    #[tokio::test]
    async fn forwards_every_call_it_does_not_park() {
        let recorder = Recorder::default();
        let gated = Gated::new(recorder.clone());
        let seen = call_everything(&gated).await;
        assert_eq!(recorder.calls(), forwarded_calls(str::to_string, INDEX));
        assert!(seen.case_sensitive);
        assert_eq!(
            [
                seen.stat_index,
                seen.listed_index,
                seen.sized_index,
                seen.stream_index
            ],
            [INDEX; 4]
        );
    }
}
