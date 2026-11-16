//! A backend wrapper that fails or cuts short the opens, unlinks, renames,
//! writes, flushes, truncates, closes, listings, stats and reads that pass
//! through it.

use std::any::Any;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use bytes::Bytes;

use crate::backend::{
    BackendCapabilities, DirEntry, DirWatch, FileInfo, FileTimes, Handle, OpenAction, OpenIntent,
    OpenOptions, ShareBackend, VolumeInfo,
};
use crate::ea::Ea;
use crate::error::{SmbError, SmbResult};
use crate::path::SmbPath;
use crate::stream::{StreamInfo, StreamName};

/// Wraps `inner` and fails chosen opens, unlinks, renames, writes, flushes,
/// truncates, closes, listings and stats, and cuts reads and writes short. The
/// unlink, rename, flush, close and stat faults exist with the `encryption`
/// feature.
///
/// A fault hits the nth call from the moment it is set and then clears. A
/// call it hits fails without reaching the inner backend; a torn write
/// applies its first bytes there first, and a failed close closes the handle
/// all the same. `write` and `write_owned` count as writes; `list_dir` and
/// `list_dir_sized` count as listings. `open_stream` is neither counted nor
/// faulted. Short reads, short writes, a reported file size, the offset from
/// which writes are dropped and the length from which truncates are dropped
/// stay in force until changed.
/// The counters count every call that reaches this backend, a clone of it or
/// one of their handles, faulted or not. Opens, listings, reads, writes and
/// truncates are logged as asked for, before a short-read or short-write
/// limit cuts them.
/// Clones share the faults, the counters and the logs.
///
/// Handles it returns have no `as_any`.
#[derive(Clone)]
pub(crate) struct Faulty<B> {
    inner: B,
    state: Arc<Mutex<State>>,
}

#[derive(Default)]
struct State {
    opens: usize,
    unlinks: usize,
    renames: usize,
    writes: usize,
    truncates: usize,
    open_log: Vec<(String, OpenIntent)>,
    list_log: Vec<(Option<String>, bool)>,
    reads: Vec<(u64, u32)>,
    write_log: Vec<(u64, usize)>,
    truncate_log: Vec<u64>,
    open_fault: Option<OpenFault>,
    unlink_fault: Option<Fault>,
    rename_fault: Option<Fault>,
    write_fault: Option<Fault>,
    flush_fault: Option<Fault>,
    truncate_fault: Option<Fault>,
    close_fault: Option<Fault>,
    list_fault: Option<Fault>,
    stat_fault: Option<Fault>,
    max_read: Option<u32>,
    max_write: Option<usize>,
    size: Option<u64>,
    sink_from: Option<u64>,
    sink_truncate_from: Option<u64>,
}

struct Fault {
    /// Calls left, counting the one that fails.
    left: usize,
    /// Bytes of a write that reach the inner backend before it fails.
    applied: usize,
    error: SmbError,
}

impl Fault {
    fn new(nth: usize, error: SmbError) -> Self {
        assert!(nth > 0, "calls count from 1");
        Self {
            left: nth,
            applied: 0,
            error,
        }
    }

    /// Counts a call; true if it is the one that fails.
    fn hit(&mut self) -> bool {
        self.left -= 1;
        self.left == 0
    }
}

type OpenFilter = Box<dyn Fn(&SmbPath, &OpenOptions) -> bool + Send>;

/// A fault that counts only the opens `when` accepts.
struct OpenFault {
    when: OpenFilter,
    fault: Fault,
}

impl State {
    /// The error the next open fails with, if any.
    fn next_open(&mut self, path: &SmbPath, opts: &OpenOptions) -> Option<SmbError> {
        self.opens += 1;
        self.open_log.push((path.display_backslash(), opts.intent));
        let slot = self.open_fault.as_mut()?;
        if !(slot.when)(path, opts) || !slot.fault.hit() {
            return None;
        }
        self.open_fault.take().map(|slot| slot.fault.error)
    }

    /// The error the next listing fails with, if any.
    fn next_listing(&mut self, pattern: Option<&str>, ea_size: bool) -> Option<SmbError> {
        self.list_log.push((pattern.map(str::to_string), ea_size));
        due(&mut self.list_fault).map(|fault| fault.error)
    }

    /// The error the next unlink fails with, if any.
    fn next_unlink(&mut self) -> Option<SmbError> {
        self.unlinks += 1;
        due(&mut self.unlink_fault).map(|fault| fault.error)
    }

    /// The error the next rename fails with, if any.
    fn next_rename(&mut self) -> Option<SmbError> {
        self.renames += 1;
        due(&mut self.rename_fault).map(|fault| fault.error)
    }

    /// What the next write does, given where it goes and the bytes it
    /// carries.
    fn next_write(&mut self, offset: u64, len: usize) -> Plan {
        self.writes += 1;
        self.write_log.push((offset, len));
        if let Some(fault) = due(&mut self.write_fault) {
            return Plan::Fail(fault.applied.min(len), fault.error);
        }
        if self.sink_from.is_some_and(|from| offset >= from) {
            return Plan::Sink;
        }
        match self.max_write {
            Some(max) if max < len => Plan::Short(max),
            _ => Plan::Pass,
        }
    }
}

/// The fault of `slot` if it is the one for this call.
fn due(slot: &mut Option<Fault>) -> Option<Fault> {
    if slot.as_mut()?.hit() {
        slot.take()
    } else {
        None
    }
}

/// What a write does.
enum Plan {
    Pass,
    /// Apply that many bytes, then fail.
    Fail(usize, SmbError),
    /// Apply and report that many bytes.
    Short(usize),
    /// Report every byte written and apply none.
    Sink,
}

impl<B: ShareBackend> Faulty<B> {
    pub(crate) fn new(inner: B) -> Self {
        Self {
            inner,
            state: Arc::default(),
        }
    }

    /// Fails the `nth` open from now (1 is the next one) with `error`,
    /// counting only the opens for which `when` is true of the path and the
    /// options. The failed open creates nothing.
    pub(crate) fn fail_open(
        &self,
        nth: usize,
        when: impl Fn(&SmbPath, &OpenOptions) -> bool + Send + 'static,
        error: SmbError,
    ) {
        self.state.lock().unwrap().open_fault = Some(OpenFault {
            when: Box::new(when),
            fault: Fault::new(nth, error),
        });
    }

    /// Fails the `nth` unlink from now (1 is the next one) with `error`.
    #[cfg(feature = "encryption")]
    pub(crate) fn fail_unlink(&self, nth: usize, error: SmbError) {
        self.state.lock().unwrap().unlink_fault = Some(Fault::new(nth, error));
    }

    /// Fails the `nth` rename from now (1 is the next one) with `error`.
    #[cfg(feature = "encryption")]
    pub(crate) fn fail_rename(&self, nth: usize, error: SmbError) {
        self.state.lock().unwrap().rename_fault = Some(Fault::new(nth, error));
    }

    /// Fails the `nth` write from now (1 is the next one) with `error`,
    /// without applying any of it.
    pub(crate) fn fail_write(&self, nth: usize, error: SmbError) {
        self.tear_write(nth, 0, error);
    }

    /// Applies the first `applied` bytes of the `nth` write from now, then
    /// fails it with `error`. A write of fewer bytes applies all of them.
    pub(crate) fn tear_write(&self, nth: usize, applied: usize, error: SmbError) {
        self.state.lock().unwrap().write_fault = Some(Fault {
            applied,
            ..Fault::new(nth, error)
        });
    }

    /// Fails the `nth` flush from now (1 is the next one) with `error`.
    #[cfg(feature = "encryption")]
    pub(crate) fn fail_flush(&self, nth: usize, error: SmbError) {
        self.state.lock().unwrap().flush_fault = Some(Fault::new(nth, error));
    }

    /// Fails the `nth` truncate from now (1 is the next one) with `error`.
    pub(crate) fn fail_truncate(&self, nth: usize, error: SmbError) {
        self.state.lock().unwrap().truncate_fault = Some(Fault::new(nth, error));
    }

    /// Fails the `nth` close from now (1 is the next one) with `error`. The
    /// handle is closed in the inner backend first.
    #[cfg(feature = "encryption")]
    pub(crate) fn fail_close(&self, nth: usize, error: SmbError) {
        self.state.lock().unwrap().close_fault = Some(Fault::new(nth, error));
    }

    /// Fails the `nth` listing from now (1 is the next one) with `error`.
    pub(crate) fn fail_listing(&self, nth: usize, error: SmbError) {
        self.state.lock().unwrap().list_fault = Some(Fault::new(nth, error));
    }

    /// Fails the `nth` `stat` of a handle from now (1 is the next one) with
    /// `error`.
    #[cfg(feature = "encryption")]
    pub(crate) fn fail_stat(&self, nth: usize, error: SmbError) {
        self.state.lock().unwrap().stat_fault = Some(Fault::new(nth, error));
    }

    /// Makes every read return at most `max` bytes, or lifts the limit.
    pub(crate) fn short_reads(&self, max: Option<u32>) {
        self.state.lock().unwrap().max_read = max;
    }

    /// Makes every write apply and report at most `max` bytes, or lifts the
    /// limit. A limit of 0 reports 0 without reaching the inner backend.
    pub(crate) fn short_writes(&self, max: Option<usize>) {
        self.state.lock().unwrap().max_write = max;
    }

    /// Makes `stat` of a file handle report `size` as its size, or lifts the
    /// override. Reads and writes are unaffected.
    pub(crate) fn report_size(&self, size: Option<u64>) {
        self.state.lock().unwrap().size = size;
    }

    /// Makes every write at or past `offset` report all its bytes written
    /// without reaching the inner backend, or lifts the override. Faults
    /// still take precedence.
    pub(crate) fn sink_writes_from(&self, offset: Option<u64>) {
        self.state.lock().unwrap().sink_from = offset;
    }

    /// Makes every truncate to `len` bytes or more report success without
    /// reaching the inner backend, or lifts the override. Faults still take
    /// precedence.
    pub(crate) fn sink_truncates_from(&self, len: Option<u64>) {
        self.state.lock().unwrap().sink_truncate_from = len;
    }

    /// Opens seen so far.
    pub(crate) fn opens(&self) -> usize {
        self.state.lock().unwrap().opens
    }

    /// Unlinks seen so far.
    pub(crate) fn unlinks(&self) -> usize {
        self.state.lock().unwrap().unlinks
    }

    /// Renames seen so far.
    pub(crate) fn renames(&self) -> usize {
        self.state.lock().unwrap().renames
    }

    /// Writes seen so far.
    pub(crate) fn writes(&self) -> usize {
        self.state.lock().unwrap().writes
    }

    /// Truncates seen so far.
    pub(crate) fn truncates(&self) -> usize {
        self.state.lock().unwrap().truncates
    }

    /// The path and intent of each open seen so far.
    pub(crate) fn open_calls(&self) -> Vec<(String, OpenIntent)> {
        self.state.lock().unwrap().open_log.clone()
    }

    /// The pattern and the EA flag of each listing seen so far, as asked
    /// for. `list_dir` counts as a listing without the flag.
    pub(crate) fn list_calls(&self) -> Vec<(Option<String>, bool)> {
        self.state.lock().unwrap().list_log.clone()
    }

    /// The offset and length of each read seen so far, as asked for.
    pub(crate) fn reads(&self) -> Vec<(u64, u32)> {
        self.state.lock().unwrap().reads.clone()
    }

    /// The offset and length of each write seen so far, as asked for.
    pub(crate) fn write_calls(&self) -> Vec<(u64, usize)> {
        self.state.lock().unwrap().write_log.clone()
    }

    /// The length of each truncate seen so far, as asked for.
    pub(crate) fn truncate_calls(&self) -> Vec<u64> {
        self.state.lock().unwrap().truncate_log.clone()
    }

    fn wrap(&self, handle: Box<dyn Handle>) -> Box<dyn Handle> {
        Box::new(FaultyHandle {
            inner: handle,
            state: Arc::clone(&self.state),
        })
    }
}

#[async_trait]
impl<B: ShareBackend> ShareBackend for Faulty<B> {
    async fn open(
        &self,
        path: &SmbPath,
        opts: OpenOptions,
    ) -> SmbResult<(Box<dyn Handle>, OpenAction)> {
        let fault = self.state.lock().unwrap().next_open(path, &opts);
        if let Some(error) = fault {
            return Err(error);
        }
        let (handle, action) = self.inner.open(path, opts).await?;
        Ok((self.wrap(handle), action))
    }

    async fn unlink(&self, path: &SmbPath) -> SmbResult<()> {
        let fault = self.state.lock().unwrap().next_unlink();
        if let Some(error) = fault {
            return Err(error);
        }
        self.inner.unlink(path).await
    }

    async fn rename(&self, from: &SmbPath, to: &SmbPath, replace_if_exists: bool) -> SmbResult<()> {
        let fault = self.state.lock().unwrap().next_rename();
        if let Some(error) = fault {
            return Err(error);
        }
        self.inner.rename(from, to, replace_if_exists).await
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
        Ok((self.wrap(handle), action))
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

struct FaultyHandle {
    inner: Box<dyn Handle>,
    state: Arc<Mutex<State>>,
}

#[async_trait]
impl Handle for FaultyHandle {
    async fn read(&self, offset: u64, len: u32) -> SmbResult<Bytes> {
        let max = {
            let mut state = self.state.lock().unwrap();
            state.reads.push((offset, len));
            state.max_read
        };
        match max {
            Some(0) if len > 0 => Ok(Bytes::new()),
            Some(max) if max < len => self.inner.read(offset, max).await,
            _ => self.inner.read(offset, len).await,
        }
    }

    async fn write(&self, offset: u64, data: &[u8]) -> SmbResult<u32> {
        let plan = self.state.lock().unwrap().next_write(offset, data.len());
        match plan {
            Plan::Pass => self.inner.write(offset, data).await,
            Plan::Fail(applied, error) => {
                if applied > 0 {
                    self.inner.write(offset, &data[..applied]).await?;
                }
                Err(error)
            }
            Plan::Short(0) => Ok(0),
            Plan::Short(max) => self.inner.write(offset, &data[..max]).await,
            Plan::Sink => Ok(data.len() as u32),
        }
    }

    async fn write_owned(&self, offset: u64, mut data: Vec<u8>) -> SmbResult<u32> {
        let plan = self.state.lock().unwrap().next_write(offset, data.len());
        match plan {
            Plan::Pass => self.inner.write_owned(offset, data).await,
            Plan::Fail(applied, error) => {
                if applied > 0 {
                    data.truncate(applied);
                    self.inner.write_owned(offset, data).await?;
                }
                Err(error)
            }
            Plan::Short(0) => Ok(0),
            Plan::Short(max) => {
                data.truncate(max);
                self.inner.write_owned(offset, data).await
            }
            Plan::Sink => Ok(data.len() as u32),
        }
    }

    async fn flush(&self) -> SmbResult<()> {
        let fault = due(&mut self.state.lock().unwrap().flush_fault);
        match fault {
            Some(fault) => Err(fault.error),
            None => self.inner.flush().await,
        }
    }

    async fn stat(&self) -> SmbResult<FileInfo> {
        let fault = due(&mut self.state.lock().unwrap().stat_fault);
        if let Some(fault) = fault {
            return Err(fault.error);
        }
        let mut info = self.inner.stat().await?;
        if let Some(size) = self.state.lock().unwrap().size
            && !info.is_directory
        {
            info.end_of_file = size;
            info.allocation_size = size;
        }
        Ok(info)
    }

    async fn set_times(&self, times: FileTimes) -> SmbResult<()> {
        self.inner.set_times(times).await
    }

    async fn set_attributes(&self, attributes: u32) -> SmbResult<()> {
        self.inner.set_attributes(attributes).await
    }

    async fn truncate(&self, len: u64) -> SmbResult<()> {
        let (fault, sunk) = {
            let mut state = self.state.lock().unwrap();
            state.truncates += 1;
            state.truncate_log.push(len);
            let sunk = state.sink_truncate_from.is_some_and(|from| len >= from);
            (due(&mut state.truncate_fault), sunk)
        };
        match fault {
            Some(fault) => Err(fault.error),
            None if sunk => Ok(()),
            None => self.inner.truncate(len).await,
        }
    }

    async fn list_dir(&self, pattern: Option<&str>) -> SmbResult<Vec<DirEntry>> {
        let fault = self.state.lock().unwrap().next_listing(pattern, false);
        match fault {
            Some(error) => Err(error),
            None => self.inner.list_dir(pattern).await,
        }
    }

    async fn list_dir_sized(
        &self,
        pattern: Option<&str>,
        ea_size: bool,
    ) -> SmbResult<Vec<DirEntry>> {
        let fault = self.state.lock().unwrap().next_listing(pattern, ea_size);
        match fault {
            Some(error) => Err(error),
            None => self.inner.list_dir_sized(pattern, ea_size).await,
        }
    }

    async fn close(self: Box<Self>) -> SmbResult<()> {
        let fault = due(&mut self.state.lock().unwrap().close_fault);
        let closed = self.inner.close().await;
        match fault {
            Some(fault) => Err(fault.error),
            None => closed,
        }
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
    use crate::tests::memfs::MemFsBackend;
    use crate::tests::recorder::{INDEX, Recorder, call_everything, forwarded_calls};
    use crate::tests::util::{dir_opts, opts, path};

    /// A writable handle on the file `f`, seeded with `data`, behind a
    /// faulty backend.
    async fn faulty_file(data: &[u8]) -> (MemFsBackend, Faulty<MemFsBackend>, Box<dyn Handle>) {
        let files = MemFsBackend::new().with_file("f", data);
        let faulty = Faulty::new(files.clone());
        let (handle, _) = faulty
            .open(&path("f"), opts(OpenIntent::Open))
            .await
            .unwrap();
        (files, faulty, handle)
    }

    fn io_error() -> SmbError {
        SmbError::Io(std::io::Error::other("injected"))
    }

    #[tokio::test]
    async fn fails_the_nth_open_the_selector_accepts() {
        let files = MemFsBackend::new().with_dir("d");
        let faulty = Faulty::new(files.clone());
        faulty.fail_open(
            2,
            |at, open| {
                open.intent == OpenIntent::Create && at.display_backslash().starts_with("d\\")
            },
            SmbError::DiskFull,
        );
        faulty
            .open(&path("y"), opts(OpenIntent::Create))
            .await
            .unwrap();
        faulty
            .open(&path("d\\a"), opts(OpenIntent::Create))
            .await
            .unwrap();
        faulty
            .open(&path("d\\a"), opts(OpenIntent::Open))
            .await
            .unwrap();
        assert!(matches!(
            faulty.open(&path("d\\b"), opts(OpenIntent::Create)).await,
            Err(SmbError::DiskFull)
        ));
        assert_eq!(files.contents("d\\b"), None);
        faulty
            .open(&path("d\\b"), opts(OpenIntent::Create))
            .await
            .unwrap();
        assert_eq!(files.contents("d\\b"), Some(Vec::new()));
        assert_eq!(faulty.opens(), 5);
        assert_eq!(
            faulty.open_calls().last(),
            Some(&("d\\b".to_string(), OpenIntent::Create))
        );
    }

    #[tokio::test]
    async fn fails_the_nth_write_with_the_chosen_error() {
        let (files, faulty, handle) = faulty_file(b"").await;
        faulty.fail_write(3, SmbError::DiskFull);
        assert_eq!(handle.write(0, b"aa").await.unwrap(), 2);
        assert_eq!(handle.write(2, b"bb").await.unwrap(), 2);
        assert!(matches!(
            handle.write(4, b"cc").await,
            Err(SmbError::DiskFull)
        ));
        assert_eq!(files.contents("f"), Some(b"aabb".to_vec()));
        assert_eq!(handle.write(4, b"dd").await.unwrap(), 2);
        assert_eq!(files.contents("f"), Some(b"aabbdd".to_vec()));
        assert_eq!(faulty.writes(), 4);
    }

    #[tokio::test]
    async fn a_torn_write_applies_a_prefix_then_fails() {
        let (files, faulty, handle) = faulty_file(b"").await;
        faulty.tear_write(1, 4, SmbError::DiskFull);
        assert!(matches!(
            handle.write(0, b"0123456789").await,
            Err(SmbError::DiskFull)
        ));
        assert_eq!(files.contents("f"), Some(b"0123".to_vec()));

        faulty.tear_write(1, 3, io_error());
        assert!(matches!(
            handle.write_owned(4, b"456789".to_vec()).await,
            Err(SmbError::Io(_))
        ));
        assert_eq!(files.contents("f"), Some(b"0123456".to_vec()));

        faulty.tear_write(1, 100, SmbError::DiskFull);
        assert!(handle.write(7, b"789").await.is_err());
        assert_eq!(files.contents("f"), Some(b"0123456789".to_vec()));
        assert_eq!(faulty.writes(), 3);
    }

    #[tokio::test]
    async fn logs_each_truncate_and_drops_the_ones_from_the_sink_length() {
        let (files, faulty, handle) = faulty_file(b"abcdef").await;
        faulty.sink_truncates_from(Some(10));
        handle.truncate(8).await.unwrap();
        handle.truncate(10).await.unwrap();
        handle.truncate(1 << 40).await.unwrap();
        assert_eq!(faulty.truncate_calls(), [8, 10, 1 << 40]);
        assert_eq!(files.contents("f"), Some(b"abcdef\0\0".to_vec()));

        faulty.fail_truncate(1, SmbError::DiskFull);
        assert!(matches!(handle.truncate(20).await, Err(SmbError::DiskFull)));
        faulty.sink_truncates_from(None);
        handle.truncate(4).await.unwrap();
        assert_eq!(files.contents("f"), Some(b"abcd".to_vec()));
        assert_eq!(faulty.truncates(), 5);
    }

    #[tokio::test]
    async fn logs_each_listing_as_asked_for() {
        let files = MemFsBackend::new().with_dir("d").with_file("d\\a", b"");
        let faulty = Faulty::new(files);
        let (dir, _) = faulty
            .open(&path("d"), dir_opts(OpenIntent::Open))
            .await
            .unwrap();
        assert!(faulty.list_calls().is_empty());
        dir.list_dir(Some("a*")).await.unwrap();
        dir.list_dir_sized(None, true).await.unwrap();
        faulty.fail_listing(1, io_error());
        assert!(dir.list_dir_sized(Some("b"), false).await.is_err());
        faulty.fail_listing(1, io_error());
        assert!(dir.list_dir(None).await.is_err());
        assert_eq!(
            faulty.list_calls(),
            [
                (Some("a*".to_string()), false),
                (None, true),
                (Some("b".to_string()), false),
                (None, false)
            ]
        );
    }

    #[tokio::test]
    async fn short_reads_return_fewer_bytes_with_the_right_data() {
        let data: Vec<u8> = (0..100).collect();
        let (_, faulty, handle) = faulty_file(&data).await;
        faulty.short_reads(Some(30));
        assert_eq!(handle.read(0, 100).await.unwrap(), data[..30]);
        assert_eq!(handle.read(30, 100).await.unwrap(), data[30..60]);
        assert_eq!(handle.read(90, 100).await.unwrap(), data[90..]);
        assert_eq!(handle.read(0, 10).await.unwrap(), data[..10]);

        faulty.short_reads(Some(0));
        assert!(handle.read(0, 100).await.unwrap().is_empty());
        faulty.short_reads(None);
        assert_eq!(handle.read(0, 100).await.unwrap(), data);
    }

    #[tokio::test]
    async fn logs_each_read_as_asked_for() {
        let data: Vec<u8> = (0..100).collect();
        let (_, faulty, handle) = faulty_file(&data).await;
        assert!(faulty.reads().is_empty());
        faulty.short_reads(Some(30));
        handle.read(0, 100).await.unwrap();
        handle.read(90, 5).await.unwrap();
        faulty.short_reads(None);
        handle.read(10, 20).await.unwrap();
        assert_eq!(faulty.reads(), [(0, 100), (90, 5), (10, 20)]);
    }

    #[tokio::test]
    async fn reports_the_size_it_is_given_for_files_and_reads_and_writes_are_unaffected() {
        let (files, faulty, handle) = faulty_file(b"abc").await;
        assert_eq!(handle.stat().await.unwrap().end_of_file, 3);
        faulty.report_size(Some(1 << 40));
        let info = handle.stat().await.unwrap();
        assert_eq!((info.end_of_file, info.allocation_size), (1 << 40, 1 << 40));
        assert_eq!(handle.read(0, 10).await.unwrap(), b"abc"[..]);
        handle.write(3, b"d").await.unwrap();
        assert_eq!(files.contents("f"), Some(b"abcd".to_vec()));
        faulty.report_size(None);
        assert_eq!(handle.stat().await.unwrap().end_of_file, 4);
    }

    #[tokio::test]
    async fn short_writes_apply_and_report_fewer_bytes() {
        let (files, faulty, handle) = faulty_file(b"").await;
        let data: Vec<u8> = (0..20).collect();
        faulty.short_writes(Some(7));
        assert_eq!(handle.write(0, &data).await.unwrap(), 7);
        assert_eq!(files.contents("f"), Some(data[..7].to_vec()));
        assert_eq!(handle.write_owned(7, data[7..].to_vec()).await.unwrap(), 7);
        assert_eq!(files.contents("f"), Some(data[..14].to_vec()));
        assert_eq!(handle.write(14, &data[14..]).await.unwrap(), 6);
        assert_eq!(files.contents("f"), Some(data.clone()));
        assert_eq!(faulty.writes(), 3);

        faulty.short_writes(Some(0));
        assert_eq!(handle.write(20, b"zz").await.unwrap(), 0);
        assert_eq!(handle.write_owned(20, b"zz".to_vec()).await.unwrap(), 0);
        assert_eq!(files.contents("f"), Some(data));

        faulty.short_writes(None);
        assert_eq!(handle.write(20, b"zz").await.unwrap(), 2);
    }

    #[tokio::test]
    async fn logs_each_write_as_asked_for_and_drops_the_writes_past_the_sink_offset() {
        let (files, faulty, handle) = faulty_file(b"").await;
        faulty.short_writes(Some(2));
        assert_eq!(handle.write(0, b"abcd").await.unwrap(), 2);
        faulty.short_writes(None);
        faulty.sink_writes_from(Some(10));
        assert_eq!(handle.write(8, b"ef").await.unwrap(), 2);
        assert_eq!(handle.write_owned(10, b"gh".to_vec()).await.unwrap(), 2);
        assert_eq!(handle.write(1 << 40, b"xyz").await.unwrap(), 3);
        assert_eq!(
            faulty.write_calls(),
            [(0, 4), (8, 2), (10, 2), (1 << 40, 3)]
        );
        assert_eq!(files.contents("f"), Some(b"ab\0\0\0\0\0\0ef".to_vec()));

        faulty.fail_write(1, SmbError::DiskFull);
        assert!(matches!(
            handle.write(12, b"ij").await,
            Err(SmbError::DiskFull)
        ));
        faulty.sink_writes_from(None);
        assert_eq!(handle.write(10, b"kl").await.unwrap(), 2);
        assert_eq!(files.contents("f"), Some(b"ab\0\0\0\0\0\0efkl".to_vec()));
        assert_eq!(faulty.writes(), 6);
    }

    #[tokio::test]
    async fn a_fault_takes_precedence_over_a_short_write() {
        let (files, faulty, handle) = faulty_file(b"").await;
        faulty.short_writes(Some(1));
        faulty.fail_write(2, SmbError::DiskFull);
        assert_eq!(handle.write(0, b"ab").await.unwrap(), 1);
        assert!(handle.write(1, b"bc").await.is_err());
        assert_eq!(files.contents("f"), Some(b"a".to_vec()));
    }

    #[tokio::test]
    async fn forwards_every_call_it_does_not_change() {
        let recorder = Recorder::default();
        let faulty = Faulty::new(recorder.clone());
        let seen = call_everything(&faulty).await;
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
        assert_eq!(
            (
                faulty.opens(),
                faulty.unlinks(),
                faulty.renames(),
                faulty.writes(),
                faulty.truncates()
            ),
            (2, 1, 1, 2, 1)
        );
    }
}
