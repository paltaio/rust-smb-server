//! A backend that logs every call it receives and answers with fixed
//! values, and the checks that a wrapper forwards each call.

use std::any::Any;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use bytes::Bytes;

use crate::backend::{
    BackendCapabilities, DirChange, DirChangeKind, DirEntry, DirWatch, FileInfo, FileTimes, Handle,
    OpenAction, OpenIntent, OpenOptions, ShareBackend, VolumeInfo,
};
use crate::ea::Ea;
use crate::error::SmbResult;
use crate::path::SmbPath;
use crate::stream::{StreamInfo, StreamName};
use crate::tests::util::{opts, path};

/// The file index its handles and listings report.
pub(crate) const INDEX: u64 = 99;

/// The serial number its volume reports.
const SERIAL: u32 = 0x5eed;

/// `call_everything` opens `FILE` and `OTHER`, opens a stream of `FILE`,
/// then renames `FILE` over `OTHER`.
const FILE: &str = "Dir\\File.TXT";
/// The file `call_everything` opens second and has `FILE` renamed over.
const OTHER: &str = "Dir\\Other.TXT";

/// The stream `call_everything` opens.
const STREAM: &str = "Data";

/// Logs each call as one line, with the arguments a wrapper could swap or
/// change: paths, offsets and the bytes written. A `copy_range` or
/// `clone_range` line names its two handles by the path each was opened
/// with, which the recorder reads with `stat` on each. It overrides every
/// trait method, so a call a wrapper leaves to a trait default shows up as a
/// missing line. Its handles report [`INDEX`] as the file index, name the
/// path they were opened with in `stat`, and offer `as_any`. Clones share the
/// log.
#[derive(Clone, Default)]
pub(crate) struct Recorder {
    log: Arc<Mutex<Vec<String>>>,
}

impl Recorder {
    /// The calls so far, in order.
    pub(crate) fn calls(&self) -> Vec<String> {
        self.log.lock().unwrap().clone()
    }

    fn record(&self, call: String) {
        self.log.lock().unwrap().push(call);
    }

    fn handle(&self, path: &SmbPath) -> Box<dyn Handle> {
        Box::new(RecorderHandle {
            recorder: self.clone(),
            path: path.display_backslash(),
        })
    }
}

fn info(name: &str) -> FileInfo {
    let mut info = FileInfo::new(name);
    info.end_of_file = 7;
    info.file_index = INDEX;
    info
}

#[async_trait]
impl ShareBackend for Recorder {
    async fn open(
        &self,
        path: &SmbPath,
        opts: OpenOptions,
    ) -> SmbResult<(Box<dyn Handle>, OpenAction)> {
        self.record(format!("open {} {opts:?}", path.display_backslash()));
        Ok((self.handle(path), OpenAction::Opened))
    }

    async fn unlink(&self, path: &SmbPath) -> SmbResult<()> {
        self.record(format!("unlink {}", path.display_backslash()));
        Ok(())
    }

    async fn rename(&self, from: &SmbPath, to: &SmbPath, replace_if_exists: bool) -> SmbResult<()> {
        self.record(format!(
            "rename {} {} {replace_if_exists}",
            from.display_backslash(),
            to.display_backslash()
        ));
        Ok(())
    }

    fn capabilities(&self) -> BackendCapabilities {
        self.record("capabilities".to_string());
        BackendCapabilities {
            is_read_only: false,
            case_sensitive: true,
            named_streams: true,
            extended_attributes: true,
            block_cloning: true,
        }
    }

    async fn volume_info(&self) -> SmbResult<VolumeInfo> {
        self.record("volume_info".to_string());
        Ok(VolumeInfo {
            serial_number: SERIAL,
            ..VolumeInfo::default()
        })
    }

    async fn open_stream(
        &self,
        file: Box<dyn Handle>,
        path: &SmbPath,
        stream: &StreamName,
        opts: OpenOptions,
    ) -> SmbResult<(Box<dyn Handle>, OpenAction)> {
        self.record(format!(
            "open_stream {} {} {opts:?}",
            path.display_backslash(),
            stream.as_str()
        ));
        file.close().await?;
        Ok((self.handle(path), OpenAction::Created))
    }

    async fn remove_stream(
        &self,
        path: &SmbPath,
        file_index: u64,
        stream: &StreamName,
    ) -> SmbResult<()> {
        self.record(format!(
            "remove_stream {} {file_index} {}",
            path.display_backslash(),
            stream.as_str()
        ));
        Ok(())
    }

    async fn rename_stream(
        &self,
        path: &SmbPath,
        file_index: u64,
        from: Option<&StreamName>,
        to: Option<&StreamName>,
        replace_if_exists: bool,
    ) -> SmbResult<()> {
        self.record(format!(
            "rename_stream {} {file_index} {:?} {:?} {replace_if_exists}",
            path.display_backslash(),
            from.map(StreamName::as_str),
            to.map(StreamName::as_str)
        ));
        Ok(())
    }

    async fn copy_range(
        &self,
        src: &dyn Handle,
        src_offset: u64,
        dst: &dyn Handle,
        dst_offset: u64,
        len: u64,
    ) -> SmbResult<u64> {
        let src = src.stat().await?.name;
        let dst = dst.stat().await?.name;
        self.record(format!(
            "copy_range {src} {src_offset} {dst} {dst_offset} {len}"
        ));
        Ok(len)
    }

    async fn clone_range(
        &self,
        src: &dyn Handle,
        src_offset: u64,
        dst: &dyn Handle,
        dst_offset: u64,
        len: u64,
    ) -> SmbResult<()> {
        let src = src.stat().await?.name;
        let dst = dst.stat().await?.name;
        self.record(format!(
            "clone_range {src} {src_offset} {dst} {dst_offset} {len}"
        ));
        Ok(())
    }
}

struct RecorderHandle {
    recorder: Recorder,
    /// The path the handle was opened with.
    path: String,
}

#[async_trait]
impl Handle for RecorderHandle {
    async fn read(&self, offset: u64, len: u32) -> SmbResult<Bytes> {
        self.recorder.record(format!("read {offset} {len}"));
        Ok(Bytes::from_static(b"data"))
    }

    async fn write(&self, offset: u64, data: &[u8]) -> SmbResult<u32> {
        self.recorder
            .record(format!("write {offset} {}", data.escape_ascii()));
        Ok(data.len() as u32)
    }

    async fn write_owned(&self, offset: u64, data: Vec<u8>) -> SmbResult<u32> {
        self.recorder
            .record(format!("write_owned {offset} {}", data.escape_ascii()));
        Ok(data.len() as u32)
    }

    async fn flush(&self) -> SmbResult<()> {
        self.recorder.record("flush".to_string());
        Ok(())
    }

    async fn stat(&self) -> SmbResult<FileInfo> {
        self.recorder.record("stat".to_string());
        Ok(info(&self.path))
    }

    async fn set_times(&self, times: FileTimes) -> SmbResult<()> {
        self.recorder.record(format!("set_times {times:?}"));
        Ok(())
    }

    async fn set_attributes(&self, attributes: u32) -> SmbResult<()> {
        self.recorder.record(format!("set_attributes {attributes}"));
        Ok(())
    }

    async fn truncate(&self, len: u64) -> SmbResult<()> {
        self.recorder.record(format!("truncate {len}"));
        Ok(())
    }

    async fn list_dir(&self, pattern: Option<&str>) -> SmbResult<Vec<DirEntry>> {
        self.recorder.record(format!("list_dir {pattern:?}"));
        Ok(vec![DirEntry { info: info("x") }])
    }

    async fn list_dir_sized(
        &self,
        pattern: Option<&str>,
        ea_size: bool,
    ) -> SmbResult<Vec<DirEntry>> {
        self.recorder
            .record(format!("list_dir_sized {pattern:?} {ea_size}"));
        Ok(vec![DirEntry { info: info("x") }])
    }

    async fn close(self: Box<Self>) -> SmbResult<()> {
        self.recorder.record("close".to_string());
        Ok(())
    }

    async fn link_count(&self) -> SmbResult<u32> {
        self.recorder.record("link_count".to_string());
        Ok(3)
    }

    async fn dir_is_empty(&self) -> SmbResult<bool> {
        self.recorder.record("dir_is_empty".to_string());
        Ok(true)
    }

    async fn watch(&self) -> SmbResult<Option<Box<dyn DirWatch>>> {
        self.recorder.record("watch".to_string());
        Ok(Some(Box::new(OneBatch { sent: false })))
    }

    async fn streams(&self) -> SmbResult<Vec<StreamInfo>> {
        self.recorder.record("streams".to_string());
        Ok(vec![StreamInfo::new(STREAM.parse()?, 5, 6)])
    }

    async fn peek_streams(
        &self,
        entries: &[(&str, &[(StreamName, u32)])],
    ) -> SmbResult<Vec<Vec<Option<(u64, Bytes)>>>> {
        self.recorder.record(format!("peek_streams {entries:?}"));
        Ok(vec![vec![Some((8, Bytes::from_static(b"peek")))]])
    }

    async fn eas(&self) -> SmbResult<Vec<Ea>> {
        self.recorder.record("eas".to_string());
        Ok(vec![Ea::new("attr", b"value".to_vec())])
    }

    async fn set_eas(&self, eas: &[Ea]) -> SmbResult<()> {
        self.recorder.record(format!("set_eas {eas:?}"));
        Ok(())
    }

    fn as_any(&self) -> Option<&(dyn Any + Send + Sync)> {
        self.recorder.record("as_any".to_string());
        Some(self)
    }
}

/// A watch that reports one change and stops.
struct OneBatch {
    sent: bool,
}

#[async_trait]
impl DirWatch for OneBatch {
    async fn next(&mut self) -> Option<Vec<DirChange>> {
        if self.sent {
            return None;
        }
        self.sent = true;
        Some(vec![DirChange::new("seen", DirChangeKind::Added, false)])
    }
}

/// Answers a wrapper may alter, as `call_everything` received them.
pub(crate) struct Seen {
    pub(crate) case_sensitive: bool,
    /// File index of the handle's `stat`.
    pub(crate) stat_index: u64,
    /// File index of the entry `list_dir` returns.
    pub(crate) listed_index: u64,
    /// File index of the entry `list_dir_sized` returns.
    pub(crate) sized_index: u64,
    /// File index of the stream handle's `stat`.
    pub(crate) stream_index: u64,
}

/// The options every open of `call_everything` carries.
fn options() -> OpenOptions {
    opts(OpenIntent::OpenOrCreate)
}

/// Calls every method of `backend` and of its handles once, and checks the
/// answers a wrapper must not change: they come back as the recorder gave
/// them. `backend` must wrap a [`Recorder`]. The `as_any` of its handles is
/// `None`.
pub(crate) async fn call_everything<B: ShareBackend>(backend: &B) -> Seen {
    let caps = backend.capabilities();
    assert!(!caps.is_read_only);
    assert!(caps.named_streams && caps.extended_attributes && caps.block_cloning);
    let volume = backend.volume_info().await.unwrap();
    assert_eq!(volume.serial_number, SERIAL);

    let (file, action) = backend.open(&path(FILE), options()).await.unwrap();
    assert_eq!(action, OpenAction::Opened);
    assert!(file.as_any().is_none());
    assert_eq!(file.read(5, 4).await.unwrap(), Bytes::from_static(b"data"));
    assert_eq!(file.write(1, b"abc").await.unwrap(), 3);
    assert_eq!(file.write_owned(2, b"abcd".to_vec()).await.unwrap(), 4);
    file.flush().await.unwrap();
    let stat = file.stat().await.unwrap();
    assert!(stat.name.eq_ignore_ascii_case(FILE));
    assert_eq!(stat.end_of_file, 7);
    file.set_times(FileTimes {
        last_write_time: Some(5),
        ..FileTimes::default()
    })
    .await
    .unwrap();
    file.set_attributes(0x20).await.unwrap();
    file.truncate(9).await.unwrap();
    let listed = file.list_dir(Some("*.TXT")).await.unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].info.name, "x");
    let sized = file.list_dir_sized(None, true).await.unwrap();
    assert_eq!(sized.len(), 1);
    assert_eq!(sized[0].info.name, "x");
    assert_eq!(file.link_count().await.unwrap(), 3);
    assert!(file.dir_is_empty().await.unwrap());
    let mut watch = file.watch().await.unwrap().expect("the inner watch");
    assert_eq!(
        watch.next().await,
        Some(vec![DirChange::new("seen", DirChangeKind::Added, false)])
    );
    assert_eq!(watch.next().await, None);
    let streams = file.streams().await.unwrap();
    assert_eq!(streams.len(), 1);
    assert_eq!(streams[0].name.as_str(), STREAM);
    let stream: StreamName = STREAM.parse().unwrap();
    let peeked = file
        .peek_streams(&[("x", &[(stream.clone(), 4)])])
        .await
        .unwrap();
    assert_eq!(peeked, [[Some((8, Bytes::from_static(b"peek")))]]);
    let eas = file.eas().await.unwrap();
    assert_eq!(eas, [Ea::new("attr", b"value".to_vec())]);
    file.set_eas(&[Ea::new("attr", b"new".to_vec())])
        .await
        .unwrap();

    let (other, _) = backend.open(&path(OTHER), options()).await.unwrap();
    assert_eq!(
        backend.copy_range(&*file, 1, &*other, 2, 3).await.unwrap(),
        3
    );
    backend.clone_range(&*file, 4, &*other, 5, 6).await.unwrap();
    backend
        .remove_stream(&path(FILE), INDEX, &stream)
        .await
        .unwrap();
    backend
        .rename_stream(&path(FILE), INDEX, Some(&stream), None, true)
        .await
        .unwrap();
    let (on_stream, action) = backend
        .open_stream(file, &path(FILE), &stream, options())
        .await
        .unwrap();
    assert_eq!(action, OpenAction::Created);
    let stream_stat = on_stream.stat().await.unwrap();
    on_stream.close().await.unwrap();

    backend.unlink(&path(OTHER)).await.unwrap();
    backend
        .rename(&path(FILE), &path(OTHER), true)
        .await
        .unwrap();
    other.close().await.unwrap();

    Seen {
        case_sensitive: caps.case_sensitive,
        stat_index: stat.file_index,
        listed_index: listed[0].info.file_index,
        sized_index: sized[0].info.file_index,
        stream_index: stream_stat.file_index,
    }
}

/// The log `call_everything` leaves on a [`Recorder`] under a wrapper that
/// forwards every call. `fold` is applied to the paths and list patterns
/// the inner backend sees, and `stream_index` is the file index it sees in
/// the calls that carry one.
pub(crate) fn forwarded_calls(fold: fn(&str) -> String, stream_index: u64) -> Vec<String> {
    let file = fold(FILE);
    let other = fold(OTHER);
    let opts = format!("{:?}", options());
    // `copy_range` and `clone_range` read the path of each handle with
    // `stat` before they log.
    [
        "capabilities".to_string(),
        "volume_info".to_string(),
        format!("open {file} {opts}"),
        "read 5 4".to_string(),
        "write 1 abc".to_string(),
        "write_owned 2 abcd".to_string(),
        "flush".to_string(),
        "stat".to_string(),
        format!(
            "set_times {:?}",
            FileTimes {
                last_write_time: Some(5),
                ..FileTimes::default()
            }
        ),
        "set_attributes 32".to_string(),
        "truncate 9".to_string(),
        format!("list_dir {:?}", Some(fold("*.TXT"))),
        "list_dir_sized None true".to_string(),
        "link_count".to_string(),
        "dir_is_empty".to_string(),
        "watch".to_string(),
        "streams".to_string(),
        format!("peek_streams [(\"x\", [(StreamName(\"{STREAM}\"), 4)])]"),
        "eas".to_string(),
        format!("set_eas {:?}", [Ea::new("attr", b"new".to_vec())]),
        format!("open {other} {opts}"),
        "stat".to_string(),
        "stat".to_string(),
        format!("copy_range {file} 1 {other} 2 3"),
        "stat".to_string(),
        "stat".to_string(),
        format!("clone_range {file} 4 {other} 5 6"),
        format!("remove_stream {file} {stream_index} {STREAM}"),
        format!("rename_stream {file} {stream_index} Some(\"{STREAM}\") None true"),
        format!("open_stream {file} {STREAM} {opts}"),
        "close".to_string(),
        "stat".to_string(),
        "close".to_string(),
        format!("unlink {other}"),
        format!("rename {file} {other} true"),
        "close".to_string(),
    ]
    .to_vec()
}
