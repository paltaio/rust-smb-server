//! Named streams of [`LocalFsBackend`](super::LocalFsBackend) on Linux.
//!
//! Each named stream of a file or directory is one of its extended
//! attributes, named `user.DosStream.<name>:$DATA` and holding the
//! stream's data followed by one NUL byte, or, once it outgrows what an
//! extended attribute holds there, a file in the stream store (see
//! [`spill`]). A spilled stream stays in the store until it is removed or
//! truncated to zero.
//!
//! A stream handle keeps a descriptor of its file, so it follows the file
//! through renames, and the stream itself through renames of the stream.

mod spill;

use std::collections::HashMap;
use std::fs::File;
use std::io;
use std::os::unix::fs::{FileExt as _, MetadataExt as _};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use cap_std::fs::{Dir, Metadata};
use rustix::fs::XattrFlags;
use rustix::io::Errno;
use tokio::task::spawn_blocking;
use tracing::debug;

pub(super) use spill::Store;

use super::local::{
    file_index, file_info_from_metadata, host_file_times, io_to_smb, join_to_io, link_count,
    set_host_attributes,
};
use super::open_streams::{OpenStreams, StreamFile, lock, open_base, open_entry, touch};
use crate::backend::{DirEntry, FileInfo, FileTimes, Handle, OpenAction, OpenIntent, OpenOptions};
use crate::error::{SmbError, SmbResult};
use crate::stream::{StreamInfo, StreamName};
use spill::{MAX_COPY, Spilled, fill};

const PREFIX: &str = "user.DosStream.";
const SUFFIX: &str = ":$DATA";

/// Longest value of an extended attribute (XATTR_SIZE_MAX).
const MAX_VALUE: usize = 65536;

/// Longest stream an extended attribute holds, with the NUL after it.
const MAX_STREAM: usize = MAX_VALUE - 1;

/// Longest name of an extended attribute (XATTR_NAME_MAX).
const MAX_NAME: usize = 255;

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

/// True if `e` says an extended attribute has no room for a value.
fn is_full(e: &io::Error) -> bool {
    e.kind() == io::ErrorKind::StorageFull
        || matches!(
            e.raw_os_error().map(Errno::from_raw_os_error),
            Some(Errno::TOOBIG | Errno::NOSPC)
        )
}

/// A value read with `read` into a buffer of the size `query` reports,
/// again if it grew in between.
pub(super) fn read_sized(
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

/// The named streams kept in extended attributes of the file `fd` is open
/// on, spelled as stored. Attributes whose names are not valid stream
/// names are left out.
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

// ---------------------------------------------------------------------------
// Streams as stored
// ---------------------------------------------------------------------------

/// Most named streams one file has. Past it, the rest are not listed, and
/// a new stream fails with STATUS_DISK_FULL.
const MAX_STREAMS: usize = 4096;

/// Where one name of a stream is kept: an extended attribute, or a file
/// in the spill store.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Variant {
    name: StreamName,
    spilled: bool,
}

/// One named stream as stored: the names that differ only in case. Of
/// those, the one that sorts first in byte order is the stream, a spilled
/// one before an attribute spelled the same; the others stay out of
/// sight, and go when the name is freed.
struct Stored {
    main: Variant,
    others: Vec<Variant>,
}

/// The named streams of one file and where they are kept.
struct View {
    stored: Vec<Stored>,
    /// Where each stream is in `stored`, by its name in lowercase.
    at: HashMap<String, usize>,
    spilled: Option<Spilled>,
}

impl View {
    /// The streams of the file `fd` is open on, its attributes in the
    /// order the filesystem lists them, then the spilled streams of
    /// `spilled`.
    fn load(fd: &File, spilled: Option<Spilled>) -> io::Result<Self> {
        let attrs = stream_names(fd)?;
        let spilled_names = spilled
            .as_ref()
            .map(|s| s.names.clone())
            .unwrap_or_default();
        let variants = attrs
            .into_iter()
            .map(|name| Variant {
                name,
                spilled: false,
            })
            .chain(spilled_names.into_iter().map(|name| Variant {
                name,
                spilled: true,
            }));
        let mut stored: Vec<Stored> = Vec::new();
        let mut at: HashMap<String, usize> = HashMap::new();
        for variant in variants {
            let key = variant.name.as_str().to_lowercase();
            match at.get(&key) {
                Some(&i) => {
                    let group = &mut stored[i];
                    let mut variant = variant;
                    let first = variant.name.as_str() < group.main.name.as_str()
                        || (variant.name == group.main.name && variant.spilled);
                    if first {
                        std::mem::swap(&mut group.main, &mut variant);
                    }
                    group.others.push(variant);
                }
                None if stored.len() < MAX_STREAMS => {
                    at.insert(key, stored.len());
                    stored.push(Stored {
                        main: variant,
                        others: Vec::new(),
                    });
                }
                None => {}
            }
        }
        if stored.len() == MAX_STREAMS {
            debug!("named streams of a file past {MAX_STREAMS} left out");
        }
        Ok(Self {
            stored,
            at,
            spilled,
        })
    }

    /// The stream that `stream` names, whatever its case.
    fn find(&self, stream: &StreamName) -> Option<&Stored> {
        let at = *self.at.get(&stream.as_str().to_lowercase())?;
        Some(&self.stored[at])
    }

    fn spilled(&self) -> io::Result<&Spilled> {
        self.spilled.as_ref().ok_or(io::ErrorKind::NotFound.into())
    }

    /// Size and allocation size of the stream kept as `v`.
    fn size(&self, fd: &File, v: &Variant) -> io::Result<(u64, u64)> {
        if v.spilled {
            let md = self.spilled()?.open(&v.name, false)?.metadata()?;
            Ok((md.len(), md.blocks() * 512))
        } else {
            let size = size(fd, &attr_name(v.name.as_str())?)?;
            Ok((size, size))
        }
    }

    /// Removes the stream kept as `v`.
    fn remove(&self, fd: &File, v: &Variant) -> io::Result<()> {
        if v.spilled {
            self.spilled()?.remove(&v.name)
        } else {
            remove(fd, &attr_name(v.name.as_str())?)
        }
    }

    /// Removes the hidden names of `stored`. One that fails to go is
    /// logged.
    fn remove_others(&self, fd: &File, stored: &Stored) {
        for other in &stored.others {
            if let Err(e) = self.remove(fd, other) {
                debug!(error = %e, stream = other.name.as_str(), "name of a removed stream left");
            }
        }
    }
}

/// The named streams of the file `fd` is open on, none where its
/// filesystem has no extended attributes.
pub(super) fn list(fd: &File, store: &Store) -> io::Result<Vec<StreamInfo>> {
    let access = Access::new(fd, store);
    let view = match access.view() {
        Err(e) if e.raw_os_error() == Some(Errno::NOTSUP.raw_os_error()) => return Ok(Vec::new()),
        view => view?,
    };
    let mut out = Vec::with_capacity(view.stored.len());
    for stored in &view.stored {
        match view.size(fd, &stored.main) {
            Ok((size, allocation)) => {
                out.push(StreamInfo::new(stored.main.name.clone(), size, allocation));
            }
            // Removed since the names were read.
            Err(e)
                if e.kind() == io::ErrorKind::NotFound
                    || e.raw_os_error() == Some(Errno::NODATA.raw_os_error()) => {}
            Err(e) => return Err(e),
        }
    }
    Ok(out)
}

/// Like [`list`], with a backend error.
pub(super) fn list_smb(fd: &File, store: &Store) -> SmbResult<Vec<StreamInfo>> {
    list(fd, store).map_err(to_smb)
}

/// The size and up to the given number of first bytes of each stream
/// `entries` names of each entry of `dir` it names, `None` where the entry
/// has no such stream or it cannot be read. Each entry is opened once,
/// with [`open_entry`], and its streams are read with its entry among the
/// open streams locked.
pub(super) fn peek_entries(
    dir: &Dir,
    open: &Arc<OpenStreams>,
    store: &Store,
    entries: &[(String, Vec<(StreamName, u32)>)],
) -> Vec<Vec<Option<(u64, Bytes)>>> {
    entries
        .iter()
        .map(|(name, streams)| {
            peek_entry(dir, open, store, name, streams).unwrap_or_else(|e| {
                debug!(error = %e, name, "streams of a listed entry not read");
                vec![None; streams.len()]
            })
        })
        .collect()
}

/// [`peek_entries`] for the entry `name`.
fn peek_entry(
    dir: &Dir,
    open: &Arc<OpenStreams>,
    store: &Store,
    name: &str,
    streams: &[(StreamName, u32)],
) -> io::Result<Vec<Option<(u64, Bytes)>>> {
    let (base, key) = open_entry(dir, name)?;
    let file = open.file(key);
    let _open = lock(&file.open);
    let access = Access::new(&base, store);
    let view = access.view()?;
    Ok(streams
        .iter()
        .map(|(stream, max)| {
            peek(&base, &view, stream, *max).unwrap_or_else(|e| {
                debug!(error = %e, name, stream = stream.as_str(), "stream of a listed entry not read");
                None
            })
        })
        .collect())
}

/// The size of the stream `stream` of the file `fd` is open on, whose
/// streams `view` holds, and up to `max` bytes from its start.
fn peek(fd: &File, view: &View, stream: &StreamName, max: u32) -> io::Result<Option<(u64, Bytes)>> {
    let Some(found) = view.find(stream) else {
        return Ok(None);
    };
    let main = &found.main;
    let (size, data) = if main.spilled {
        let spilled = view.spilled()?.open(&main.name, false)?;
        let size = spilled.metadata()?.len();
        let mut data = vec![0; (max as u64).min(size) as usize];
        let read = spilled.read_at(&mut data, 0)?;
        data.truncate(read);
        (size, Bytes::from(data))
    } else if max == 0 {
        (view.size(fd, main)?.0, Bytes::new())
    } else {
        // The whole value is read; only its start is kept.
        let data = get(fd, &attr_name(main.name.as_str())?)?;
        let head = &data[..data.len().min(max as usize)];
        (data.len() as u64, Bytes::copy_from_slice(head))
    };
    Ok(Some((size, data)))
}

/// Reads and changes the streams of one file, with its entry among the
/// open streams locked. The store is held from its first use to the end.
struct Access<'a> {
    fd: &'a File,
    store: &'a Store,
    held: std::cell::OnceCell<spill::Held>,
}

impl<'a> Access<'a> {
    fn new(fd: &'a File, store: &'a Store) -> Self {
        Self {
            fd,
            store,
            held: std::cell::OnceCell::new(),
        }
    }

    /// The store, held, made with `create`. `None` when it is missing, or
    /// for reading (`!create`) when it cannot be used.
    fn held(&self, create: bool) -> io::Result<Option<&spill::Held>> {
        if let Some(held) = self.held.get() {
            return Ok(Some(held));
        }
        let held = match self.store.hold(create) {
            Ok(held) => held,
            // A store that cannot be used leaves streams in extended
            // attributes: reads see none spilled, and spills fail.
            Err(e) if e.kind() == io::ErrorKind::PermissionDenied => {
                spill::warn_unusable(&e);
                if create {
                    return Err(io::ErrorKind::StorageFull.into());
                }
                None
            }
            Err(e) => return Err(e),
        };
        Ok(held.map(|held| self.held.get_or_init(|| held)))
    }

    /// The streams as stored, the spilled ones where the file's record
    /// points, also for a copy without an entry of its own.
    fn view(&self) -> io::Result<View> {
        let spilled = match self.held(false)? {
            Some(held) => self.store.find(held, self.fd, MAX_STREAMS)?,
            None => None,
        };
        View::load(self.fd, spilled)
    }

    /// The streams as stored, the spilled ones in an entry of the file's
    /// own: a copy claims one first.
    fn own_view(&self) -> io::Result<View> {
        let spilled = match self.held(false)? {
            Some(held) => self.store.find_own(held, self.fd, MAX_STREAMS)?,
            None => None,
        };
        View::load(self.fd, spilled)
    }

    /// The file's own store entry, made if it has none.
    fn own(&self) -> io::Result<Spilled> {
        let held = self.held(true)?.ok_or(io::ErrorKind::NotFound)?;
        self.store.own(held, self.fd, MAX_STREAMS)
    }

    /// Moves the stream `stream`, an attribute holding `data`, to the
    /// store, and returns its file there.
    fn spill(&self, stream: &StreamName, data: &[u8]) -> io::Result<File> {
        let own = self.own()?;
        let file = own.put(stream, |file| file.write_all_at(data, 0))?;
        if let Err(e) = remove(self.fd, &attr_name(stream.as_str())?) {
            let _ = own.remove(stream);
            return Err(e);
        }
        Ok(file)
    }

    /// Makes the stream `stream` holding `data`: an attribute where one
    /// holds it, else a file in the store. True if it went to the store.
    fn create(&self, stream: &StreamName, data: Vec<u8>) -> io::Result<bool> {
        let attr = attr_name(stream.as_str())?;
        match set(self.fd, &attr, data.clone(), XattrFlags::CREATE) {
            Ok(()) => Ok(false),
            Err(e) if is_full(&e) => {
                self.own()?
                    .put(stream, |file| file.write_all_at(&data, 0))?;
                Ok(true)
            }
            Err(e) => Err(e),
        }
    }

    /// Makes the new stream `stream`, empty, on a file with room for one
    /// more.
    fn create_new(&self, view: &View, stream: &StreamName) -> io::Result<()> {
        if view.stored.len() >= MAX_STREAMS {
            return Err(io::ErrorKind::StorageFull.into());
        }
        self.create(stream, Vec::new()).map(drop)
    }

    /// Removes the stream `stream` [`Access::create`] made.
    fn uncreate(&self, stream: &StreamName, spilled: bool) {
        let removed = if spilled {
            self.own().and_then(|own| own.remove(stream))
        } else {
            attr_name(stream.as_str()).and_then(|attr| remove(self.fd, &attr))
        };
        if let Err(e) = removed {
            debug!(error = %e, stream = stream.as_str(), "stream rename not undone");
        }
    }

    /// Writes `data` at `offset` of the stream `stream`.
    fn write(&self, stream: &StreamName, offset: u64, data: &[u8]) -> io::Result<()> {
        let view = self.view()?;
        let main = &view.find(stream).ok_or(io::ErrorKind::NotFound)?.main;
        if main.spilled {
            let view = self.own_view()?;
            let main = &view.find(stream).ok_or(io::ErrorKind::NotFound)?.main;
            view.spilled()?
                .open(&main.name, true)?
                .write_all_at(data, offset)?;
        } else {
            let attr = attr_name(main.name.as_str())?;
            let value = get(self.fd, &attr)?;
            let end = offset
                .checked_add(data.len() as u64)
                .ok_or(io::ErrorKind::StorageFull)?;
            let stored = match usize::try_from(end).ok().filter(|&end| end <= MAX_STREAM) {
                Some(end) => {
                    let mut new = value.clone();
                    if new.len() < end {
                        new.resize(end, 0);
                    }
                    new[offset as usize..end].copy_from_slice(data);
                    set(self.fd, &attr, new, XattrFlags::REPLACE)
                }
                None => Err(io::ErrorKind::StorageFull.into()),
            };
            match stored {
                Ok(()) => {}
                Err(e) if is_full(&e) => {
                    self.spill(&main.name, &value)?.write_all_at(data, offset)?;
                }
                Err(e) => return Err(e),
            }
        }
        touch(self.fd);
        Ok(())
    }

    /// Sets the size of the stream `stream` to `len`. A spilled stream cut
    /// to zero goes back to an attribute where one holds it.
    fn truncate(&self, stream: &StreamName, len: u64) -> io::Result<()> {
        let view = self.view()?;
        let main = &view.find(stream).ok_or(io::ErrorKind::NotFound)?.main;
        if main.spilled {
            let view = self.own_view()?;
            let main = &view.find(stream).ok_or(io::ErrorKind::NotFound)?.main;
            let spilled = view.spilled()?;
            spilled.open(&main.name, true)?.set_len(len)?;
            if len == 0 {
                let attr = attr_name(main.name.as_str())?;
                match set(self.fd, &attr, Vec::new(), XattrFlags::empty()) {
                    Ok(()) => {
                        if let Err(e) = spilled.remove(&main.name) {
                            debug!(error = %e, "emptied stream left in the store");
                        }
                    }
                    Err(e) if is_full(&e) => {}
                    Err(e) => return Err(e),
                }
            }
        } else {
            let attr = attr_name(main.name.as_str())?;
            let value = get(self.fd, &attr)?;
            let stored = match usize::try_from(len).ok().filter(|&len| len <= MAX_STREAM) {
                Some(len) => {
                    let mut new = value.clone();
                    new.resize(len, 0);
                    set(self.fd, &attr, new, XattrFlags::REPLACE)
                }
                None => Err(io::ErrorKind::StorageFull.into()),
            };
            match stored {
                Ok(()) => {}
                Err(e) if is_full(&e) => self.spill(&main.name, &value)?.set_len(len)?,
                Err(e) => return Err(e),
            }
        }
        touch(self.fd);
        Ok(())
    }
}

/// The names of a stream a rename replaces, set aside until the rename is
/// done, so a failed rename puts them back.
struct Aside {
    attrs: Vec<(StreamName, Vec<u8>)>,
    spilled: Vec<StreamName>,
}

impl Aside {
    /// Sets aside every name of `stored`, if any; one that exists is
    /// replaced only with `replace`.
    fn take(fd: &File, view: &View, stored: Option<&Stored>, replace: bool) -> io::Result<Self> {
        let mut aside = Self {
            attrs: Vec::new(),
            spilled: Vec::new(),
        };
        let Some(stored) = stored else {
            return Ok(aside);
        };
        if !replace {
            return Err(io::ErrorKind::AlreadyExists.into());
        }
        for v in std::iter::once(&stored.main).chain(&stored.others) {
            let taken = if v.spilled {
                view.spilled()
                    .and_then(|s| s.set_aside(&v.name))
                    .map(|()| aside.spilled.push(v.name.clone()))
            } else {
                attr_name(v.name.as_str()).and_then(|attr| {
                    let value = get(fd, &attr)?;
                    remove(fd, &attr)?;
                    aside.attrs.push((v.name.clone(), value));
                    Ok(())
                })
            };
            if let Err(e) = taken {
                aside.put_back(fd, view);
                return Err(e);
            }
        }
        Ok(aside)
    }

    fn put_back(&self, fd: &File, view: &View) {
        for (name, value) in &self.attrs {
            let restored = attr_name(name.as_str())
                .and_then(|attr| set(fd, &attr, value.clone(), XattrFlags::empty()));
            if let Err(e) = restored {
                debug!(error = %e, stream = name.as_str(), "replaced stream not put back");
            }
        }
        for name in &self.spilled {
            if let Err(e) = view.spilled().and_then(|s| s.restore(name)) {
                debug!(error = %e, stream = name.as_str(), "replaced stream not put back");
            }
        }
    }

    fn drop_all(&self, view: &View) {
        for name in &self.spilled {
            if let Err(e) = view.spilled().and_then(|s| s.drop_aside(name)) {
                debug!(error = %e, stream = name.as_str(), "replaced stream left in the store");
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Open streams
// ---------------------------------------------------------------------------

/// Where a backend keeps the files of its share and their streams.
#[derive(Clone)]
pub(super) struct Place {
    pub root: Arc<Dir>,
    pub root_dev: Option<u64>,
    pub read_only: bool,
    pub open: Arc<OpenStreams>,
    pub store: Arc<Store>,
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
    /// id `id`, for `opts.intent`.
    pub(super) async fn open_stream(
        self,
        rel: PathBuf,
        name: String,
        id: u64,
        stream: StreamName,
        opts: OpenOptions,
    ) -> SmbResult<(Box<dyn Handle>, OpenAction)> {
        let intent = opts.intent;
        spawn_blocking(move || -> io::Result<_> {
            let (base, md, file) = self.base(&rel, id, false)?;
            let mut open = lock(&file.open);
            let access = Access::new(&base, &self.store);
            let view = access.view()?;
            let existing = view.find(&stream).map(|s| s.main.name.clone());
            let action = match (intent, &existing) {
                (OpenIntent::Open | OpenIntent::Truncate, None) => {
                    return Err(io::ErrorKind::NotFound.into());
                }
                (OpenIntent::Create, Some(_)) => return Err(io::ErrorKind::AlreadyExists.into()),
                (OpenIntent::Open | OpenIntent::OpenOrCreate, Some(_)) => OpenAction::Opened,
                (_, Some(existing)) => {
                    access.truncate(existing, 0)?;
                    OpenAction::Overwritten
                }
                (_, None) => {
                    access.create_new(&view, &stream)?;
                    OpenAction::Created
                }
            };
            drop(view);
            drop(access);
            let handle_id = open.add(existing.unwrap_or(stream));
            drop(open);
            let handle: Box<dyn Handle> = Box::new(StreamHandle {
                file,
                id: handle_id,
                base: Arc::new(base),
                store: Arc::clone(&self.store),
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
            let access = Access::new(&base, &self.store);
            let view = access.view()?;
            let found = view.find(&stream).ok_or(io::ErrorKind::NotFound)?;
            let spilled = std::iter::once(&found.main)
                .chain(&found.others)
                .any(|v| v.spilled);
            let view = if spilled { access.own_view()? } else { view };
            let found = view.find(&stream).ok_or(io::ErrorKind::NotFound)?;
            view.remove(&base, &found.main)?;
            view.remove_others(&base, found);
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
            let access = Access::new(&base, &self.store);
            // A rename may change any spilled stream of the file, so a copy
            // takes an entry of its own first.
            let view = access.own_view()?;
            let source = match &from {
                Some(from) => Some(view.find(from).ok_or(io::ErrorKind::NotFound)?),
                None => None,
            };
            match (source, to) {
                (Some(source), Some(to)) => {
                    let aside = Aside::take(&base, &view, view.find(&to), replace)?;
                    let src = &source.main;
                    let moved = if src.spilled {
                        view.spilled().and_then(|s| s.rename(&src.name, &to))
                    } else {
                        attr_name(src.name.as_str()).and_then(|attr| {
                            let data = get(&base, &attr)?;
                            let spilled = access.create(&to, data)?;
                            if let Err(e) = remove(&base, &attr) {
                                access.uncreate(&to, spilled);
                                return Err(e);
                            }
                            Ok(())
                        })
                    };
                    if let Err(e) = moved {
                        aside.put_back(&base, &view);
                        return Err(e);
                    }
                    view.remove_others(&base, source);
                    aside.drop_all(&view);
                    open.rename(&src.name, &to);
                }
                (None, Some(to)) => {
                    if view.find(&to).is_none() && view.stored.len() >= MAX_STREAMS {
                        return Err(io::ErrorKind::StorageFull.into());
                    }
                    let aside = Aside::take(&base, &view, view.find(&to), replace)?;
                    let made = match usize::try_from(md.len())
                        .ok()
                        .filter(|&len| len <= MAX_STREAM)
                    {
                        Some(len) => {
                            let mut data = vec![0; len];
                            base.read_exact_at(&mut data, 0)
                                .and_then(|()| access.create(&to, data))
                        }
                        None => access
                            .own()
                            .and_then(|own| {
                                own.put(&to, |file| fill(file, &base, Some(MAX_COPY)).map(drop))
                            })
                            .map(|_| true),
                    };
                    let spilled = match made {
                        Ok(spilled) => spilled,
                        Err(e) => {
                            aside.put_back(&base, &view);
                            return Err(e);
                        }
                    };
                    if let Err(e) = base.set_len(0) {
                        access.uncreate(&to, spilled);
                        aside.put_back(&base, &view);
                        return Err(e);
                    }
                    aside.drop_all(&view);
                }
                (Some(source), None) => {
                    if !replace {
                        return Err(io::ErrorKind::AlreadyExists.into());
                    }
                    let src = &source.main;
                    let written = if src.spilled {
                        view.spilled()
                            .and_then(|s| s.open(&src.name, false))
                            .and_then(|from| fill(&base, &from, Some(MAX_COPY)))
                    } else {
                        attr_name(src.name.as_str())
                            .and_then(|attr| get(&base, &attr))
                            .and_then(|data| {
                                base.write_all_at(&data, 0).map(|()| data.len() as u64)
                            })
                    };
                    let moved = written
                        .and_then(|len| base.set_len(len))
                        .and_then(|()| view.remove(&base, src));
                    if let Err(e) = moved {
                        if let Err(e) = base.set_len(0) {
                            debug!(error = %e, "default stream not emptied again");
                        }
                        return Err(e);
                    }
                    view.remove_others(&base, source);
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
    store: Arc<Store>,
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
    /// Runs `f` on the file's streams and the handle's stream, with the
    /// file's streams locked.
    async fn locked<T: Send + 'static>(
        &self,
        f: impl FnOnce(&Access<'_>, &StreamName) -> io::Result<T> + Send + 'static,
    ) -> SmbResult<T> {
        let file = Arc::clone(&self.file);
        let base = Arc::clone(&self.base);
        let store = Arc::clone(&self.store);
        let id = self.id;
        spawn_blocking(move || {
            let open = lock(&file.open);
            let stream = open.names.get(&id).ok_or(io::ErrorKind::NotFound)?;
            f(&Access::new(&base, &store), stream)
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
        self.locked(move |access, stream| {
            let view = access.view()?;
            let main = &view.find(stream).ok_or(io::ErrorKind::NotFound)?.main;
            if main.spilled {
                let mut buf = vec![0; len as usize];
                let n = view
                    .spilled()?
                    .open(&main.name, false)?
                    .read_at(&mut buf, offset)?;
                buf.truncate(n);
                return Ok(Bytes::from(buf));
            }
            let data = get(access.fd, &attr_name(main.name.as_str())?)?;
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
        self.locked(move |access, stream| {
            access.write(stream, offset, &data)?;
            Ok(data.len() as u32)
        })
        .await
    }

    async fn flush(&self) -> SmbResult<()> {
        self.locked(|access, stream| {
            let view = access.view()?;
            let main = &view.find(stream).ok_or(io::ErrorKind::NotFound)?.main;
            if main.spilled {
                view.spilled()?.open(&main.name, false)?.sync_data()?;
            }
            access.fd.sync_all()
        })
        .await
    }

    async fn stat(&self) -> SmbResult<FileInfo> {
        let name = self.name.clone();
        let root_dev = self.root_dev;
        self.locked(move |access, stream| {
            let md = Metadata::from_file(access.fd)?;
            let mut info = file_info_from_metadata(name, &md, root_dev);
            let view = access.view()?;
            let main = &view.find(stream).ok_or(io::ErrorKind::NotFound)?.main;
            (info.end_of_file, info.allocation_size) = view.size(access.fd, main)?;
            info.ea_size =
                super::eas::size(&super::eas::Source::File(access.fd)).unwrap_or_else(|e| {
                    debug!(error = %e, "extended attribute size not read");
                    0
                });
            Ok(info)
        })
        .await
    }

    async fn set_times(&self, times: FileTimes) -> SmbResult<()> {
        if self.read_only {
            return Err(SmbError::AccessDenied);
        }
        let times = host_file_times(times);
        self.on_base(move |fd| fd.set_times(times)).await
    }

    async fn set_attributes(&self, attributes: u32) -> SmbResult<()> {
        if self.read_only {
            return Err(SmbError::AccessDenied);
        }
        let is_dir = self.is_dir;
        self.on_base(move |fd| set_host_attributes(fd, attributes, is_dir))
            .await
    }

    async fn truncate(&self, len: u64) -> SmbResult<()> {
        if self.read_only {
            return Err(SmbError::AccessDenied);
        }
        self.locked(move |access, stream| access.truncate(stream, len))
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
        let store = Arc::clone(&self.store);
        spawn_blocking(move || list(&base, &store))
            .await
            .map_err(join_to_io)
            .map_err(to_smb)?
            .map_err(to_smb)
    }
}

#[cfg(test)]
mod tests;
