//! Named streams of [`LocalFsBackend`](super::LocalFsBackend) on Linux.
//!
//! Each named stream of a file or directory is one of its extended
//! attributes, named `user.DosStream.<name>:$DATA` and holding the
//! stream's data followed by one NUL byte. Writes read and rewrite the
//! whole value, so a stream holds at most 65535 bytes, and less where the
//! filesystem has less room for extended attributes.
//!
//! A stream handle keeps a descriptor of its file, so it follows the file
//! through renames, and the stream itself through renames of the stream.

use std::collections::HashMap;
use std::fs::File;
use std::io;
use std::os::unix::fs::FileExt as _;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, Weak};

use async_trait::async_trait;
use bytes::Bytes;
use cap_std::fs::{Dir, Metadata, OpenOptions as CapOpenOptions};
use rustix::fs::XattrFlags;
use rustix::io::Errno;
use tokio::task::spawn_blocking;
use tracing::debug;

use super::local::{
    file_index, file_info_from_metadata, file_key, host_file_times, io_to_smb, join_to_io,
    link_count, set_read_only,
};
use crate::backend::{
    DirEntry, FILE_ATTRIBUTE_ARCHIVE, FILE_ATTRIBUTE_READONLY, FileInfo, FileTimes, Handle,
    OpenAction, OpenIntent,
};
use crate::error::{SmbError, SmbResult};
use crate::stream::{StreamInfo, StreamName};

const PREFIX: &str = "user.DosStream.";
const SUFFIX: &str = ":$DATA";

/// Longest value of an extended attribute (XATTR_SIZE_MAX).
const MAX_VALUE: usize = 65536;

/// Longest stream an extended attribute holds, with the NUL after it.
const MAX_STREAM: usize = MAX_VALUE - 1;

/// Longest name of an extended attribute (XATTR_NAME_MAX).
const MAX_NAME: usize = 255;

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

// ---------------------------------------------------------------------------
// Extended attributes
// ---------------------------------------------------------------------------

/// The extended attribute that holds the stream `stream`.
fn attr_name(stream: &str) -> io::Result<String> {
    let name = format!("{PREFIX}{stream}{SUFFIX}");
    if name.len() > MAX_NAME {
        return Err(io::ErrorKind::InvalidFilename.into());
    }
    Ok(name)
}

/// The error a stream request answers for `e`. A filesystem without
/// extended attributes refuses access: a stream request must not fail
/// with STATUS_NOT_SUPPORTED.
fn to_smb(e: io::Error) -> SmbError {
    match e.raw_os_error().map(Errno::from_raw_os_error) {
        Some(Errno::NODATA) => SmbError::NotFound,
        Some(Errno::TOOBIG | Errno::NOSPC) => SmbError::DiskFull,
        Some(Errno::NOTSUP) => SmbError::AccessDenied,
        _ => io_to_smb(e),
    }
}

/// A value read with `read` into a buffer of the size `query` reports,
/// again if it grew in between.
fn read_sized(
    query: impl Fn() -> rustix::io::Result<usize>,
    read: impl Fn(&mut [u8]) -> rustix::io::Result<usize>,
) -> io::Result<Vec<u8>> {
    for _ in 0..8 {
        let mut buf = vec![0; query()?];
        if buf.is_empty() {
            return Ok(buf);
        }
        match read(&mut buf) {
            Ok(len) => {
                buf.truncate(len);
                return Ok(buf);
            }
            Err(Errno::RANGE) => continue,
            Err(e) => return Err(e.into()),
        }
    }
    Err(Errno::RANGE.into())
}

/// The named streams of the file `fd` is open on, spelled as stored.
/// Attributes whose names are not valid stream names are left out.
fn stream_names(fd: &File) -> io::Result<Vec<StreamName>> {
    let list = read_sized(
        || rustix::fs::flistxattr_query(fd),
        |buf| rustix::fs::flistxattr(fd, buf),
    )?;
    Ok(list
        .split(|&b| b == 0)
        .filter_map(|attr| {
            let name = std::str::from_utf8(attr)
                .ok()?
                .strip_prefix(PREFIX)?
                .strip_suffix(SUFFIX)?;
            name.parse().ok()
        })
        .collect())
}

/// One named stream as stored: the attributes whose names differ only in
/// case. Of those, the one whose name sorts first in byte order is the
/// stream; the others stay out of sight, and go when the name is freed.
struct Stored {
    name: StreamName,
    others: Vec<StreamName>,
}

/// The named streams of the file `fd` is open on, in the order the
/// filesystem lists them.
fn streams_of(fd: &File) -> io::Result<Vec<Stored>> {
    let mut out: Vec<Stored> = Vec::new();
    for name in stream_names(fd)? {
        match out.iter_mut().find(|s| s.name.matches(&name)) {
            Some(stored) => {
                let mut name = name;
                if name.as_str() < stored.name.as_str() {
                    std::mem::swap(&mut stored.name, &mut name);
                }
                stored.others.push(name);
            }
            None => out.push(Stored {
                name,
                others: Vec::new(),
            }),
        }
    }
    Ok(out)
}

/// The stream of `stored` that `stream` names, whatever its case.
fn find<'a>(stored: &'a [Stored], stream: &StreamName) -> Option<&'a Stored> {
    stored.iter().find(|s| s.name.matches(stream))
}

/// Removes the attributes `stored` hides behind its stream. One that
/// fails to go is logged.
fn remove_others(fd: &File, stored: &Stored) {
    for other in &stored.others {
        if let Err(e) = attr_name(other.as_str()).and_then(|attr| remove(fd, &attr)) {
            debug!(error = %e, stream = other.as_str(), "attribute of a removed stream left");
        }
    }
}

/// The data of the stream kept in `attr`: its value without the last byte.
fn get(fd: &File, attr: &str) -> io::Result<Vec<u8>> {
    let mut value = read_sized(
        || rustix::fs::fgetxattr_query(fd, attr),
        |buf| rustix::fs::fgetxattr(fd, attr, buf),
    )?;
    value.pop();
    Ok(value)
}

/// Size of the stream kept in `attr`.
fn size(fd: &File, attr: &str) -> io::Result<u64> {
    Ok(rustix::fs::fgetxattr_query(fd, attr)?.saturating_sub(1) as u64)
}

/// Keeps `data` as the stream in `attr`.
fn set(fd: &File, attr: &str, mut data: Vec<u8>, flags: XattrFlags) -> io::Result<()> {
    if data.len() > MAX_STREAM {
        return Err(io::ErrorKind::StorageFull.into());
    }
    data.push(0);
    Ok(rustix::fs::fsetxattr(fd, attr, &data, flags)?)
}

fn remove(fd: &File, attr: &str) -> io::Result<()> {
    Ok(rustix::fs::fremovexattr(fd, attr)?)
}

/// Sets the last write time of the file `fd` is open on to now. Changes of
/// extended attributes leave it alone.
fn touch(fd: &File) {
    use rustix::fs::{Timespec, Timestamps, UTIME_NOW, UTIME_OMIT};
    let times = Timestamps {
        last_access: Timespec {
            tv_sec: 0,
            tv_nsec: UTIME_OMIT,
        },
        last_modification: Timespec {
            tv_sec: 0,
            tv_nsec: UTIME_NOW,
        },
    };
    if let Err(e) = rustix::fs::futimens(fd, &times) {
        debug!(error = %e, "last write time of a file with a changed stream not set");
    }
}

/// True if the filesystem of `root` stores user extended attributes.
pub(super) fn supported(root: &Dir) -> bool {
    let Ok(fd) = super::local::dir_as_file(root) else {
        return false;
    };
    matches!(
        rustix::fs::fgetxattr_query(&fd, PREFIX),
        Ok(_) | Err(Errno::NODATA | Errno::RANGE)
    )
}

/// The named streams of the file `fd` is open on, none where its
/// filesystem has no extended attributes.
pub(super) fn list(fd: &File) -> io::Result<Vec<StreamInfo>> {
    let stored = match streams_of(fd) {
        Err(e) if e.raw_os_error() == Some(Errno::NOTSUP.raw_os_error()) => return Ok(Vec::new()),
        stored => stored?,
    };
    let mut out = Vec::with_capacity(stored.len());
    for Stored { name, .. } in stored {
        match size(fd, &attr_name(name.as_str())?) {
            Ok(size) => out.push(StreamInfo::new(name, size, size)),
            // Removed since the names were read.
            Err(e) if e.raw_os_error() == Some(Errno::NODATA.raw_os_error()) => {}
            Err(e) => return Err(e),
        }
    }
    Ok(out)
}

/// Like [`list`], with a backend error.
pub(super) fn list_smb(fd: &File) -> SmbResult<Vec<StreamInfo>> {
    list(fd).map_err(to_smb)
}

// ---------------------------------------------------------------------------
// Open streams
// ---------------------------------------------------------------------------

/// The files with named streams open through one backend, by host
/// identity.
#[derive(Default)]
pub(super) struct OpenStreams {
    files: Mutex<HashMap<(u64, u64), Weak<StreamFile>>>,
}

impl OpenStreams {
    /// The entry of the file with host identity `key`.
    fn file(self: &Arc<Self>, key: (u64, u64)) -> Arc<StreamFile> {
        let mut files = lock(&self.files);
        if let Some(file) = files.get(&key).and_then(Weak::upgrade) {
            return file;
        }
        let file = Arc::new(StreamFile {
            key,
            owner: Arc::downgrade(self),
            open: Mutex::default(),
        });
        files.insert(key, Arc::downgrade(&file));
        file
    }
}

/// One file with named streams open or being changed. Its lock is held
/// over every read and change of the file's streams, so a write's
/// read-modify-write of a value and a rename see each other whole. An
/// entry lives as long as a handle on one of the file's streams, which
/// holds the file open, so its host identity stays the file's.
struct StreamFile {
    key: (u64, u64),
    owner: Weak<OpenStreams>,
    open: Mutex<OpenNames>,
}

impl Drop for StreamFile {
    fn drop(&mut self) {
        if let Some(owner) = self.owner.upgrade() {
            let mut files = lock(&owner.files);
            if files.get(&self.key).is_some_and(|f| f.strong_count() == 0) {
                files.remove(&self.key);
            }
        }
    }
}

/// The stream each handle of a file is on, by handle id, spelled as
/// stored.
#[derive(Default)]
struct OpenNames {
    next: u64,
    names: HashMap<u64, StreamName>,
}

impl OpenNames {
    fn add(&mut self, name: StreamName) -> u64 {
        self.next += 1;
        self.names.insert(self.next, name);
        self.next
    }

    /// Moves the handles on the stream `from` to the stream `to`.
    fn rename(&mut self, from: &StreamName, to: &StreamName) {
        for name in self.names.values_mut() {
            if name == from {
                *name = to.clone();
            }
        }
    }
}

/// Opens the file or directory at `rel` below `root` for reading, or for
/// writing too with `write`.
fn open_base(root: &Dir, rel: &Path, write: bool) -> io::Result<(File, Metadata, (u64, u64))> {
    let mut opts = CapOpenOptions::new();
    opts.read(true).write(write);
    let file = root.open_with(rel, &opts)?.into_std();
    let md = Metadata::from_file(&file)?;
    let key = file_key(&md).ok_or(io::ErrorKind::Unsupported)?;
    Ok((file, md, key))
}

/// Where a backend keeps the files of its share.
#[derive(Clone)]
pub(super) struct Place {
    pub root: Arc<Dir>,
    pub root_dev: Option<u64>,
    pub read_only: bool,
    pub open: Arc<OpenStreams>,
}

impl Place {
    /// Opens the file at `rel`, for writing too with `write`, and takes its
    /// entry among the open streams. A file at `rel` whose id is not `id`
    /// is not found, unless `id` is `0`.
    fn base(
        &self,
        rel: &Path,
        id: u64,
        write: bool,
    ) -> io::Result<(File, Metadata, Arc<StreamFile>)> {
        let (base, md, key) = open_base(&self.root, rel, write)?;
        if id != 0 && id != file_index(self.root_dev, Some(key)) {
            return Err(io::ErrorKind::NotFound.into());
        }
        Ok((base, md, self.open.file(key)))
    }

    /// Opens the named stream `stream` of the file at `rel`, which has the
    /// id `id`, for `intent`.
    pub(super) async fn open_stream(
        self,
        rel: PathBuf,
        name: String,
        id: u64,
        stream: StreamName,
        intent: OpenIntent,
    ) -> SmbResult<(Box<dyn Handle>, OpenAction)> {
        spawn_blocking(move || -> io::Result<_> {
            let (base, md, file) = self.base(&rel, id, false)?;
            let mut open = lock(&file.open);
            let stored = streams_of(&base)?;
            let existing = find(&stored, &stream).map(|s| s.name.clone());
            let attr = attr_name(existing.as_ref().unwrap_or(&stream).as_str())?;
            let action = match (intent, &existing) {
                (OpenIntent::Open | OpenIntent::Truncate, None) => {
                    return Err(io::ErrorKind::NotFound.into());
                }
                (OpenIntent::Create, Some(_)) => return Err(io::ErrorKind::AlreadyExists.into()),
                (OpenIntent::Open | OpenIntent::OpenOrCreate, Some(_)) => OpenAction::Opened,
                (_, Some(_)) => {
                    set(&base, &attr, Vec::new(), XattrFlags::REPLACE)?;
                    touch(&base);
                    OpenAction::Overwritten
                }
                (_, None) => {
                    set(&base, &attr, Vec::new(), XattrFlags::CREATE)?;
                    OpenAction::Created
                }
            };
            let handle_id = open.add(existing.unwrap_or(stream));
            drop(open);
            let handle: Box<dyn Handle> = Box::new(StreamHandle {
                file,
                id: handle_id,
                base: Arc::new(base),
                is_dir: md.is_dir(),
                name,
                root_dev: self.root_dev,
                read_only: self.read_only,
            });
            Ok((handle, action))
        })
        .await
        .map_err(join_to_io)
        .map_err(to_smb)?
        .map_err(to_smb)
    }

    /// Removes the named stream `stream` of the file at `rel`, which has
    /// the id `id`.
    pub(super) async fn remove_stream(
        self,
        rel: PathBuf,
        id: u64,
        stream: StreamName,
    ) -> SmbResult<()> {
        spawn_blocking(move || -> io::Result<()> {
            let (base, _, file) = self.base(&rel, id, false)?;
            let _open = lock(&file.open);
            let stored = streams_of(&base)?;
            let found = find(&stored, &stream).ok_or(io::ErrorKind::NotFound)?;
            remove(&base, &attr_name(found.name.as_str())?)?;
            remove_others(&base, found);
            Ok(())
        })
        .await
        .map_err(join_to_io)
        .map_err(to_smb)?
        .map_err(to_smb)
    }

    /// Renames a stream of the file at `rel`, which has the id `id`, as
    /// [`ShareBackend::rename_stream`](crate::ShareBackend::rename_stream)
    /// says. A step that fails undoes the ones before it.
    pub(super) async fn rename_stream(
        self,
        rel: PathBuf,
        id: u64,
        from: Option<StreamName>,
        to: Option<StreamName>,
        replace: bool,
    ) -> SmbResult<()> {
        spawn_blocking(move || -> io::Result<()> {
            let moves_data = from.is_none() || to.is_none();
            let (base, md, file) = self.base(&rel, id, moves_data)?;
            let mut open = lock(&file.open);
            let stored = streams_of(&base)?;
            let source = match &from {
                Some(from) => Some(find(&stored, from).ok_or(io::ErrorKind::NotFound)?),
                None => None,
            };
            match (source, to) {
                (Some(source), Some(to)) => {
                    let target = Target::new(&base, &stored, to, replace)?;
                    let data = get(&base, &attr_name(source.name.as_str())?)?;
                    target.fill(&base, data)?;
                    if let Err(e) = remove(&base, &attr_name(source.name.as_str())?) {
                        target.undo(&base);
                        return Err(e);
                    }
                    remove_others(&base, source);
                    open.rename(&source.name, &target.name);
                }
                (None, Some(to)) => {
                    let target = Target::new(&base, &stored, to, replace)?;
                    let len = usize::try_from(md.len())
                        .ok()
                        .filter(|&len| len <= MAX_STREAM)
                        .ok_or(io::ErrorKind::StorageFull)?;
                    let mut data = vec![0; len];
                    base.read_exact_at(&mut data, 0)?;
                    target.fill(&base, data)?;
                    if let Err(e) = base.set_len(0) {
                        target.undo(&base);
                        return Err(e);
                    }
                }
                (Some(source), None) => {
                    if !replace {
                        return Err(io::ErrorKind::AlreadyExists.into());
                    }
                    let attr = attr_name(source.name.as_str())?;
                    let data = get(&base, &attr)?;
                    let moved = base
                        .write_all_at(&data, 0)
                        .and_then(|()| base.set_len(data.len() as u64))
                        .and_then(|()| remove(&base, &attr));
                    if let Err(e) = moved {
                        if let Err(e) = base.set_len(0) {
                            debug!(error = %e, "default stream not emptied again");
                        }
                        return Err(e);
                    }
                    remove_others(&base, source);
                }
                (None, None) => return Ok(()),
            }
            touch(&base);
            Ok(())
        })
        .await
        .map_err(join_to_io)
        .map_err(to_smb)?
        .map_err(to_smb)
    }
}

/// The named stream a rename moves data into: `name`, replacing the
/// attributes of a stream of that name, if any, kept in `replaced` with
/// their values so a failed rename puts them back.
struct Target {
    name: StreamName,
    replaced: Vec<(StreamName, Vec<u8>)>,
}

impl Target {
    /// The target `to` among the streams `stored` of the file `fd` is open
    /// on; one that exists is replaced only with `replace`.
    fn new(fd: &File, stored: &[Stored], to: StreamName, replace: bool) -> io::Result<Self> {
        let mut replaced = Vec::new();
        if let Some(existing) = find(stored, &to) {
            if !replace {
                return Err(io::ErrorKind::AlreadyExists.into());
            }
            for name in std::iter::once(&existing.name).chain(&existing.others) {
                let value = get(fd, &attr_name(name.as_str())?)?;
                replaced.push((name.clone(), value));
            }
        }
        Ok(Self { name: to, replaced })
    }

    /// True if an attribute of the replaced stream has the target's name.
    fn reuses_name(&self) -> bool {
        self.replaced.iter().any(|(name, _)| *name == self.name)
    }

    /// Keeps `data` in the target, and removes the replaced stream's other
    /// attributes.
    fn fill(&self, fd: &File, data: Vec<u8>) -> io::Result<()> {
        let flags = if self.reuses_name() {
            XattrFlags::REPLACE
        } else {
            XattrFlags::CREATE
        };
        set(fd, &attr_name(self.name.as_str())?, data, flags)?;
        for (name, _) in self.replaced.iter().filter(|(name, _)| *name != self.name) {
            if let Err(e) = attr_name(name.as_str()).and_then(|attr| remove(fd, &attr)) {
                self.undo(fd);
                return Err(e);
            }
        }
        Ok(())
    }

    /// Puts back what [`Target::fill`] changed.
    fn undo(&self, fd: &File) {
        if !self.reuses_name() {
            let removed = attr_name(self.name.as_str()).and_then(|attr| remove(fd, &attr));
            if let Err(e) = removed {
                debug!(error = %e, stream = self.name.as_str(), "stream rename not undone");
            }
        }
        for (name, value) in &self.replaced {
            let restored = attr_name(name.as_str())
                .and_then(|attr| set(fd, &attr, value.clone(), XattrFlags::empty()));
            if let Err(e) = restored {
                debug!(error = %e, stream = name.as_str(), "replaced stream not put back");
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Handle
// ---------------------------------------------------------------------------

/// The handle of a named stream open.
struct StreamHandle {
    file: Arc<StreamFile>,
    /// The handle's id among the file's stream handles.
    id: u64,
    /// The file or directory the stream belongs to, open for reading.
    base: Arc<File>,
    is_dir: bool,
    /// The file's name, as `FileInfo` reports it.
    name: String,
    root_dev: Option<u64>,
    /// The backend is read-only.
    read_only: bool,
}

impl Drop for StreamHandle {
    fn drop(&mut self) {
        lock(&self.file.open).names.remove(&self.id);
    }
}

impl StreamHandle {
    /// Runs `f` on the file and the attribute of the handle's stream, with
    /// the file's streams locked.
    async fn locked<T: Send + 'static>(
        &self,
        f: impl FnOnce(&File, &str) -> io::Result<T> + Send + 'static,
    ) -> SmbResult<T> {
        let file = Arc::clone(&self.file);
        let base = Arc::clone(&self.base);
        let id = self.id;
        spawn_blocking(move || {
            let open = lock(&file.open);
            let stream = open.names.get(&id).ok_or(io::ErrorKind::NotFound)?;
            f(&base, &attr_name(stream.as_str())?)
        })
        .await
        .map_err(join_to_io)
        .map_err(to_smb)?
        .map_err(to_smb)
    }

    /// Runs `f` on the file, outside the lock of its streams.
    async fn on_base<T: Send + 'static>(
        &self,
        f: impl FnOnce(&File) -> io::Result<T> + Send + 'static,
    ) -> SmbResult<T> {
        let base = Arc::clone(&self.base);
        spawn_blocking(move || f(&base))
            .await
            .map_err(join_to_io)
            .map_err(io_to_smb)?
            .map_err(io_to_smb)
    }
}

#[async_trait]
impl Handle for StreamHandle {
    async fn read(&self, offset: u64, len: u32) -> SmbResult<Bytes> {
        self.locked(move |fd, attr| {
            let data = get(fd, attr)?;
            let start = usize::try_from(offset)
                .unwrap_or(usize::MAX)
                .min(data.len());
            let end = start.saturating_add(len as usize).min(data.len());
            Ok(Bytes::copy_from_slice(&data[start..end]))
        })
        .await
    }

    async fn write(&self, offset: u64, data: &[u8]) -> SmbResult<u32> {
        self.write_owned(offset, data.to_vec()).await
    }

    async fn write_owned(&self, offset: u64, data: Vec<u8>) -> SmbResult<u32> {
        if self.read_only {
            return Err(SmbError::AccessDenied);
        }
        if data.is_empty() {
            return Ok(0);
        }
        self.locked(move |fd, attr| {
            let start = usize::try_from(offset)
                .ok()
                .filter(|&start| start.saturating_add(data.len()) <= MAX_STREAM)
                .ok_or(io::ErrorKind::StorageFull)?;
            let end = start + data.len();
            let mut value = get(fd, attr)?;
            if value.len() < end {
                value.resize(end, 0);
            }
            value[start..end].copy_from_slice(&data);
            set(fd, attr, value, XattrFlags::REPLACE)?;
            touch(fd);
            Ok(data.len() as u32)
        })
        .await
    }

    async fn flush(&self) -> SmbResult<()> {
        self.on_base(|fd| fd.sync_all()).await
    }

    async fn stat(&self) -> SmbResult<FileInfo> {
        let name = self.name.clone();
        let root_dev = self.root_dev;
        self.locked(move |fd, attr| {
            let md = Metadata::from_file(fd)?;
            let mut info = file_info_from_metadata(name, &md, root_dev);
            info.end_of_file = size(fd, attr)?;
            info.allocation_size = info.end_of_file;
            Ok(info)
        })
        .await
    }

    async fn set_times(&self, times: FileTimes) -> SmbResult<()> {
        if self.read_only {
            return Err(SmbError::AccessDenied);
        }
        let times = host_file_times(times)?;
        self.on_base(move |fd| fd.set_times(times)).await
    }

    async fn set_attributes(&self, attributes: u32) -> SmbResult<()> {
        if attributes & !(FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_ARCHIVE) != 0 {
            return Err(SmbError::NotSupported);
        }
        if self.read_only {
            return Err(SmbError::AccessDenied);
        }
        let read_only = attributes & FILE_ATTRIBUTE_READONLY != 0;
        match self.is_dir {
            true if read_only => Err(SmbError::NotSupported),
            true => Ok(()),
            false => self.on_base(move |fd| set_read_only(fd, read_only)).await,
        }
    }

    async fn truncate(&self, len: u64) -> SmbResult<()> {
        if self.read_only {
            return Err(SmbError::AccessDenied);
        }
        self.locked(move |fd, attr| {
            let len = usize::try_from(len)
                .ok()
                .filter(|&len| len <= MAX_STREAM)
                .ok_or(io::ErrorKind::StorageFull)?;
            let mut value = get(fd, attr)?;
            value.resize(len, 0);
            set(fd, attr, value, XattrFlags::REPLACE)?;
            touch(fd);
            Ok(())
        })
        .await
    }

    async fn list_dir(&self, _pattern: Option<&str>) -> SmbResult<Vec<DirEntry>> {
        Err(SmbError::NotADirectory)
    }

    async fn close(self: Box<Self>) -> SmbResult<()> {
        Ok(())
    }

    async fn link_count(&self) -> SmbResult<u32> {
        let is_dir = self.is_dir;
        self.on_base(move |fd| {
            let md = Metadata::from_file(fd)?;
            let links = link_count(&md).map_or(1, |n| u32::try_from(n).unwrap_or(u32::MAX));
            Ok(if is_dir { links.min(1) } else { links })
        })
        .await
    }

    async fn dir_is_empty(&self) -> SmbResult<bool> {
        Err(SmbError::NotADirectory)
    }

    async fn streams(&self) -> SmbResult<Vec<StreamInfo>> {
        let base = Arc::clone(&self.base);
        spawn_blocking(move || list(&base))
            .await
            .map_err(join_to_io)
            .map_err(to_smb)?
            .map_err(to_smb)
    }
}

#[cfg(test)]
mod tests;
