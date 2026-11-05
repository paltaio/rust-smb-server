//! Named streams of [`LocalFsBackend`](super::LocalFsBackend) on macOS.
//!
//! Each named stream of a file or directory is one of its extended
//! attributes, so the host sees what clients set as it would see it on a
//! local copy. `AFP_AfpInfo` is `com.apple.FinderInfo`, read and written in
//! the 60-byte AfpInfo layout that holds those 32 bytes, and
//! `AFP_Resource` is `com.apple.ResourceFork`, read and written in place.
//! Every other stream is the attribute [`from_sfm`] names.
//!
//! A stream handle keeps a descriptor of its file, so it follows the file
//! through renames, and the stream itself through renames of the stream.

use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::fs::File;
use std::io;
use std::os::fd::AsRawFd as _;
use std::os::unix::fs::FileExt as _;
use std::path::PathBuf;
use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use cap_std::fs::{Dir, Metadata};
use tokio::task::spawn_blocking;
use tracing::debug;

use super::local::{
    file_index, file_info_from_metadata, host_file_times, io_to_smb, join_to_io, link_count,
    set_host_attributes,
};
use super::open_streams::{OpenStreams, StreamFile, lock, open_base, open_entry, touch};
use crate::backend::{DirEntry, FileInfo, FileTimes, Handle, OpenAction, OpenIntent, OpenOptions};
use crate::error::{SmbError, SmbResult};
use crate::stream::{StreamInfo, StreamName, from_sfm, to_sfm};

const AFP_INFO: &str = "AFP_AfpInfo";
const AFP_RESOURCE: &str = "AFP_Resource";
const FINDER_INFO: &str = "com.apple.FinderInfo";
const RESOURCE_FORK: &str = "com.apple.ResourceFork";

/// Size of an `AFP_AfpInfo` stream.
const AFP_INFO_SIZE: usize = 60;

/// Where `AFP_AfpInfo` holds the 32 bytes of `com.apple.FinderInfo`.
const FINDER_INFO_AT: std::ops::Range<usize> = 16..48;

/// Longest name of an extended attribute, in bytes (XATTR_MAXNAMELEN).
const MAX_NAME: usize = 127;

/// Most data a stream other than `AFP_AfpInfo` and `AFP_Resource` holds.
/// Its value is read and written whole, so this bounds what one request
/// reads, copies and holds in memory.
const MAX_PLAIN: u64 = 1 << 20;

/// Most data a write or size change leaves in `AFP_Resource`, which is read
/// and written in place. A fork cut short is held in memory while it is
/// written again.
const MAX_FORK: u64 = 16 << 20;

/// Most named streams one file has. Past it, the rest are not listed, and
/// a new stream fails with STATUS_DISK_FULL.
const MAX_STREAMS: usize = 4096;

// ---------------------------------------------------------------------------
// Extended attributes
// ---------------------------------------------------------------------------

/// The length a call returned, or the error it set when it returned -1.
fn checked(r: isize) -> io::Result<usize> {
    usize::try_from(r).map_err(|_| io::Error::last_os_error())
}

/// Size of the value of `name`.
fn value_size(fd: &File, name: &CStr) -> io::Result<usize> {
    // SAFETY: `name` is NUL-terminated and outlives the call; a null value
    // with size 0 asks for the size only.
    checked(unsafe {
        libc::fgetxattr(fd.as_raw_fd(), name.as_ptr(), std::ptr::null_mut(), 0, 0, 0)
    })
}

/// Reads the value of `name` into `buf`, from `position` of the resource
/// fork, which alone takes a position other than 0. Returns the bytes
/// read, which for the resource fork stop at its end.
fn read_value(fd: &File, name: &CStr, buf: &mut [u8], position: u32) -> io::Result<usize> {
    if buf.is_empty() {
        return Ok(0);
    }
    // SAFETY: `buf` is valid for writes of `buf.len()` bytes and `name` is
    // NUL-terminated; both outlive the call.
    checked(unsafe {
        libc::fgetxattr(
            fd.as_raw_fd(),
            name.as_ptr(),
            buf.as_mut_ptr().cast(),
            buf.len(),
            position,
            0,
        )
    })
}

/// Writes `data` as the value of `name`, or, for the resource fork, at
/// `position` of it, which leaves the rest of the fork as it is.
/// XATTR_NOFOLLOW is never passed: the descriptor calls refuse it with
/// EINVAL, and have no path to follow.
fn write_value(
    fd: &File,
    name: &CStr,
    data: &[u8],
    position: u32,
    flags: libc::c_int,
) -> io::Result<()> {
    // SAFETY: `data` is valid for reads of `data.len()` bytes and `name` is
    // NUL-terminated; both outlive the call.
    let r = unsafe {
        libc::fsetxattr(
            fd.as_raw_fd(),
            name.as_ptr(),
            data.as_ptr().cast(),
            data.len(),
            position,
            flags,
        )
    };
    if r != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn remove_value(fd: &File, name: &CStr) -> io::Result<()> {
    // SAFETY: `name` is NUL-terminated and outlives the call.
    if unsafe { libc::fremovexattr(fd.as_raw_fd(), name.as_ptr(), 0) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Like [`remove_value`]; a value already gone is no error.
fn remove_if_any(fd: &File, name: &CStr) -> io::Result<()> {
    match remove_value(fd, name) {
        Err(e) if is_missing(&e) => Ok(()),
        removed => removed,
    }
}

/// The names of the extended attributes of the file `fd` is open on, each
/// followed by a NUL.
fn list_names(fd: &File) -> io::Result<Vec<u8>> {
    for _ in 0..8 {
        // SAFETY: a null buffer with size 0 asks for the size only.
        let size =
            checked(unsafe { libc::flistxattr(fd.as_raw_fd(), std::ptr::null_mut(), 0, 0) })?;
        let mut buf = vec![0u8; size];
        if buf.is_empty() {
            return Ok(buf);
        }
        // SAFETY: `buf` is valid for writes of `buf.len()` bytes and
        // outlives the call.
        let read =
            unsafe { libc::flistxattr(fd.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len(), 0) };
        match checked(read) {
            Ok(len) => {
                buf.truncate(len);
                return Ok(buf);
            }
            Err(e) if e.raw_os_error() == Some(libc::ERANGE) => continue,
            Err(e) => return Err(e),
        }
    }
    Err(io::Error::from_raw_os_error(libc::ERANGE))
}

/// The whole value of `name`, read again if it grew in between.
fn get(fd: &File, name: &CStr) -> io::Result<Vec<u8>> {
    for _ in 0..8 {
        let mut buf = vec![0u8; value_size(fd, name)?];
        match read_value(fd, name, &mut buf, 0) {
            Ok(len) => {
                buf.truncate(len);
                return Ok(buf);
            }
            Err(e) if e.raw_os_error() == Some(libc::ERANGE) => continue,
            Err(e) => return Err(e),
        }
    }
    Err(io::Error::from_raw_os_error(libc::ERANGE))
}

/// True if `e` says the file has no such extended attribute.
fn is_missing(e: &io::Error) -> bool {
    e.raw_os_error() == Some(libc::ENOATTR)
}

/// The error for data a stream cannot hold, which
/// STATUS_INVALID_PARAMETER answers.
fn bad_data() -> io::Error {
    io::ErrorKind::InvalidData.into()
}

/// The error a stream request answers for `e`. A filesystem without
/// extended attributes refuses access: a stream request must not fail
/// with STATUS_NOT_SUPPORTED.
fn to_smb(e: io::Error) -> SmbError {
    if e.kind() == io::ErrorKind::InvalidData {
        return SmbError::InvalidParameter;
    }
    match e.raw_os_error() {
        Some(libc::ENOATTR) => SmbError::NotFound,
        Some(libc::E2BIG | libc::ENOSPC) => SmbError::DiskFull,
        Some(libc::ENOTSUP | libc::EOPNOTSUPP) => SmbError::AccessDenied,
        _ => io_to_smb(e),
    }
}

/// True if the volume of `root` keeps extended attributes itself. Others,
/// such as FAT and exFAT, have them only through `._` files beside each
/// file.
pub(super) fn supported(root: &Dir) -> bool {
    use std::os::fd::AsFd as _;

    #[repr(C)]
    struct Reply {
        length: u32,
        capabilities: libc::vol_capabilities_attr_t,
    }

    let mut request = libc::attrlist {
        bitmapcount: libc::ATTR_BIT_MAP_COUNT,
        reserved: 0,
        commonattr: 0,
        volattr: libc::ATTR_VOL_INFO | libc::ATTR_VOL_CAPABILITIES,
        dirattr: 0,
        fileattr: 0,
        forkattr: 0,
    };
    let mut reply = Reply {
        length: 0,
        capabilities: libc::vol_capabilities_attr_t {
            capabilities: [0; 4],
            valid: [0; 4],
        },
    };
    // SAFETY: `request` and `reply` are live locals the call reads and
    // writes, and `reply` is `size_of::<Reply>()` bytes long.
    let r = unsafe {
        libc::fgetattrlist(
            root.as_fd().as_raw_fd(),
            (&raw mut request).cast(),
            (&raw mut reply).cast(),
            std::mem::size_of::<Reply>(),
            0,
        )
    };
    let interfaces = libc::VOL_CAPABILITIES_INTERFACES;
    let bit = libc::VOL_CAP_INT_EXTENDED_ATTR;
    r == 0
        && reply.capabilities.valid[interfaces] & bit != 0
        && reply.capabilities.capabilities[interfaces] & bit != 0
}

// ---------------------------------------------------------------------------
// Streams as stored
// ---------------------------------------------------------------------------

/// How a stream's data is kept in its extended attribute.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    /// `AFP_AfpInfo` in `com.apple.FinderInfo`.
    FinderInfo,
    /// `AFP_Resource` in `com.apple.ResourceFork`.
    ResourceFork,
    /// Any other stream, as the value.
    Plain,
}

impl Kind {
    /// Most data a stream of this kind holds.
    fn max(self) -> u64 {
        match self {
            Kind::FinderInfo => AFP_INFO_SIZE as u64,
            Kind::ResourceFork => MAX_FORK,
            Kind::Plain => MAX_PLAIN,
        }
    }
}

/// A named stream and the extended attribute that holds it.
#[derive(Debug, Clone)]
struct Attr {
    name: StreamName,
    xattr: CString,
    kind: Kind,
}

/// True if `a` and `b` name the same stream.
fn same_stream(a: &str, b: &str) -> bool {
    a.to_lowercase() == b.to_lowercase()
}

impl Attr {
    /// The attribute that holds the stream `name`. A name that maps to a
    /// name too long for an attribute, or to the attribute of
    /// `AFP_AfpInfo` or `AFP_Resource`, is invalid, as is one that holds a
    /// character [`from_sfm`] gives itself: each attribute has one stream
    /// name.
    fn of(name: &StreamName) -> io::Result<Self> {
        let (xattr, kind) = if same_stream(name.as_str(), AFP_INFO) {
            (FINDER_INFO.to_string(), Kind::FinderInfo)
        } else if same_stream(name.as_str(), AFP_RESOURCE) {
            (RESOURCE_FORK.to_string(), Kind::ResourceFork)
        } else {
            let xattr = from_sfm(name.as_str());
            if xattr.len() > MAX_NAME
                || to_sfm(&xattr) != name.as_str()
                || same_stream(&xattr, FINDER_INFO)
                || same_stream(&xattr, RESOURCE_FORK)
            {
                return Err(io::ErrorKind::InvalidFilename.into());
            }
            (xattr, Kind::Plain)
        };
        Ok(Self {
            name: name.clone(),
            xattr: CString::new(xattr).map_err(|_| io::ErrorKind::InvalidFilename)?,
            kind,
        })
    }

    /// The stream the attribute `xattr` holds, `None` when no stream name
    /// leads to it.
    fn listed(xattr: &[u8]) -> Option<Self> {
        let xattr = std::str::from_utf8(xattr).ok()?;
        let name = match xattr {
            FINDER_INFO => AFP_INFO.to_string(),
            RESOURCE_FORK => AFP_RESOURCE.to_string(),
            xattr => to_sfm(xattr),
        };
        let attr = Self::of(&name.parse().ok()?).ok()?;
        (attr.xattr.as_bytes() == xattr.as_bytes()).then_some(attr)
    }
}

/// One named stream as stored: the attributes whose streams differ only
/// in case. Of those, the one whose name sorts first in byte order is the
/// stream; the others stay out of sight, and go when the name is freed.
struct Stored {
    main: Attr,
    others: Vec<Attr>,
}

/// The named streams of one file.
struct View {
    stored: Vec<Stored>,
    /// Where each stream is in `stored`, by its name in lowercase.
    at: HashMap<String, usize>,
}

impl View {
    /// The streams of the file `fd` is open on, in the order the
    /// filesystem lists its attributes.
    fn load(fd: &File) -> io::Result<Self> {
        let names = list_names(fd)?;
        let mut stored: Vec<Stored> = Vec::new();
        let mut at: HashMap<String, usize> = HashMap::new();
        for attr in names.split(|&b| b == 0).filter_map(Attr::listed) {
            let key = attr.name.as_str().to_lowercase();
            match at.get(&key) {
                Some(&i) => {
                    let group = &mut stored[i];
                    let mut attr = attr;
                    if attr.name.as_str() < group.main.name.as_str() {
                        std::mem::swap(&mut group.main, &mut attr);
                    }
                    group.others.push(attr);
                }
                None if stored.len() < MAX_STREAMS => {
                    at.insert(key, stored.len());
                    stored.push(Stored {
                        main: attr,
                        others: Vec::new(),
                    });
                }
                None => {}
            }
        }
        if stored.len() == MAX_STREAMS {
            debug!("named streams of a file past {MAX_STREAMS} left out");
        }
        Ok(Self { stored, at })
    }

    /// The stream that `stream` names, whatever its case.
    fn find(&self, stream: &StreamName) -> Option<&Stored> {
        let at = *self.at.get(&stream.as_str().to_lowercase())?;
        Some(&self.stored[at])
    }
}

/// Removes the hidden names of `stored`. One that fails to go is logged.
fn remove_others(fd: &File, stored: &Stored) {
    for other in &stored.others {
        if let Err(e) = remove_value(fd, &other.xattr) {
            debug!(error = %e, stream = other.name.as_str(), "name of a removed stream left");
        }
    }
}

/// The `AFP_AfpInfo` stream that holds the Finder info `finder_info`,
/// zeros where it is missing or short.
fn afp_info(finder_info: &[u8]) -> [u8; AFP_INFO_SIZE] {
    let mut info = [0u8; AFP_INFO_SIZE];
    info[..4].copy_from_slice(b"AFP\0");
    // Version 0x100, then a backup time of "never", both big-endian.
    info[4..8].copy_from_slice(&[0, 0, 1, 0]);
    info[12..16].copy_from_slice(&[0x80, 0, 0, 0]);
    let len = finder_info.len().min(FINDER_INFO_AT.len());
    info[FINDER_INFO_AT][..len].copy_from_slice(&finder_info[..len]);
    info
}

/// The Finder info that the `AFP_AfpInfo` stream `data` holds. A stream
/// that is not 60 bytes starting with `AFP\0` is refused.
fn finder_info(data: &[u8]) -> io::Result<&[u8]> {
    if data.len() != AFP_INFO_SIZE || !data.starts_with(b"AFP\0") {
        return Err(bad_data());
    }
    Ok(&data[FINDER_INFO_AT])
}

/// Stores the Finder info `info`, which all zeros removes.
fn set_finder_info(fd: &File, attr: &Attr, info: &[u8]) -> io::Result<()> {
    if info.iter().all(|&b| b == 0) {
        remove_if_any(fd, &attr.xattr)
    } else {
        write_value(fd, &attr.xattr, info, 0, 0)
    }
}

/// `data[offset..][..len]`, cut at the end of `data`.
fn slice(data: &[u8], offset: u64, len: u32) -> Bytes {
    let start = usize::try_from(offset)
        .unwrap_or(usize::MAX)
        .min(data.len());
    let end = start.saturating_add(len as usize).min(data.len());
    Bytes::copy_from_slice(&data[start..end])
}

/// The end of `len` bytes at `offset` of the stream `attr` holds, when the
/// stream may reach it.
fn end_within_limit(attr: &Attr, offset: u64, len: usize) -> io::Result<u64> {
    offset
        .checked_add(len as u64)
        .filter(|&end| end <= attr.kind.max())
        .ok_or(io::ErrorKind::StorageFull.into())
}

/// The whole value of the attribute of `attr`. A value larger than a
/// stream of its kind holds, which only the host can make, fails with
/// `too_large`.
fn get_bounded(fd: &File, attr: &Attr, too_large: io::ErrorKind) -> io::Result<Vec<u8>> {
    if value_size(fd, &attr.xattr)? as u64 > attr.kind.max() {
        return Err(too_large.into());
    }
    get(fd, &attr.xattr)
}

/// Size of the stream `attr` holds: the value's for a plain stream, which
/// has to exist; an `AFP_AfpInfo` stream is 60 bytes, and an
/// `AFP_Resource` stream without a value is empty.
fn size(fd: &File, attr: &Attr) -> io::Result<u64> {
    match (attr.kind, value_size(fd, &attr.xattr)) {
        (Kind::FinderInfo, Ok(_)) => Ok(AFP_INFO_SIZE as u64),
        (_, Ok(len)) => Ok(len as u64),
        (Kind::FinderInfo, Err(e)) if is_missing(&e) => Ok(AFP_INFO_SIZE as u64),
        (Kind::ResourceFork, Err(e)) if is_missing(&e) => Ok(0),
        (_, Err(e)) => Err(e),
    }
}

/// Reads up to `len` bytes at `offset` of the stream `attr` holds.
fn read(fd: &File, attr: &Attr, offset: u64, len: u32) -> io::Result<Bytes> {
    match attr.kind {
        Kind::FinderInfo => {
            let info = match get(fd, &attr.xattr) {
                Err(e) if is_missing(&e) => Vec::new(),
                info => info?,
            };
            Ok(slice(&afp_info(&info), offset, len))
        }
        Kind::ResourceFork => {
            let Ok(position) = u32::try_from(offset) else {
                return Ok(Bytes::new());
            };
            let mut buf = vec![0u8; len as usize];
            match read_value(fd, &attr.xattr, &mut buf, position) {
                Ok(read) => buf.truncate(read),
                Err(e) if is_missing(&e) => buf.clear(),
                Err(e) => return Err(e),
            }
            Ok(Bytes::from(buf))
        }
        // Clients report STATUS_ACCESS_DENIED as a plain access error, and
        // macOS does not move the attribute to a `._` file for it.
        Kind::Plain => Ok(slice(
            &get_bounded(fd, attr, io::ErrorKind::PermissionDenied)?,
            offset,
            len,
        )),
    }
}

/// Writes `data` at `offset` of the stream `attr` holds. `AFP_AfpInfo`
/// takes its 60 bytes whole.
fn write(fd: &File, attr: &Attr, offset: u64, data: &[u8]) -> io::Result<()> {
    match attr.kind {
        Kind::FinderInfo => {
            if offset != 0 {
                return Err(bad_data());
            }
            set_finder_info(fd, attr, finder_info(data)?)?;
        }
        Kind::ResourceFork => {
            end_within_limit(attr, offset, data.len())?;
            write_value(fd, &attr.xattr, data, offset as u32, 0)?;
        }
        Kind::Plain => {
            let end = end_within_limit(attr, offset, data.len())? as usize;
            let mut value = get_bounded(fd, attr, io::ErrorKind::StorageFull)?;
            if value.len() < end {
                value.resize(end, 0);
            }
            value[offset as usize..end].copy_from_slice(data);
            write_value(fd, &attr.xattr, &value, 0, libc::XATTR_REPLACE)?;
        }
    }
    touch(fd);
    Ok(())
}

/// Sets the size of the stream `attr` holds to `len`. `AFP_AfpInfo` keeps
/// its 60 bytes unless cut to zero, which removes the Finder info, and
/// cannot grow past them.
fn truncate(fd: &File, attr: &Attr, len: u64) -> io::Result<()> {
    if len > attr.kind.max() {
        return Err(io::ErrorKind::StorageFull.into());
    }
    match attr.kind {
        Kind::FinderInfo if len != 0 => return Ok(()),
        Kind::FinderInfo => remove_if_any(fd, &attr.xattr)?,
        Kind::ResourceFork => {
            let current = size(fd, attr)?;
            if len == current {
                return Ok(());
            }
            if len == 0 {
                remove_if_any(fd, &attr.xattr)?;
            } else if len < current {
                shrink_fork(fd, attr, len as usize)?;
            } else {
                write_value(fd, &attr.xattr, &[0], (len - 1) as u32, 0)?;
            }
        }
        Kind::Plain => {
            let mut value = get_bounded(fd, attr, io::ErrorKind::StorageFull)?;
            value.resize(len as usize, 0);
            write_value(fd, &attr.xattr, &value, 0, libc::XATTR_REPLACE)?;
        }
    }
    touch(fd);
    Ok(())
}

/// Cuts the resource fork `attr` holds to `len` bytes. A write leaves the
/// rest of the fork, so the fork is removed and its first `len` bytes
/// written again; a failed write puts the whole fork back. A crash
/// between the removal and the write loses the fork.
fn shrink_fork(fd: &File, attr: &Attr, len: usize) -> io::Result<()> {
    let fork = get_bounded(fd, attr, io::ErrorKind::StorageFull)?;
    remove_value(fd, &attr.xattr)?;
    let Err(e) = write_value(fd, &attr.xattr, &fork[..len.min(fork.len())], 0, 0) else {
        return Ok(());
    };
    // A partial write leaves part of the fork, which the whole one
    // replaces from the start.
    if let Err(e) =
        remove_if_any(fd, &attr.xattr).and_then(|()| write_value(fd, &attr.xattr, &fork, 0, 0))
    {
        debug!(error = %e, "resource fork lost while cut short");
    }
    Err(e)
}

/// The data of the stream `attr` holds, which a rename moves.
fn data(fd: &File, attr: &Attr) -> io::Result<Vec<u8>> {
    let value = get_bounded(fd, attr, io::ErrorKind::StorageFull)?;
    if attr.kind == Kind::FinderInfo {
        return Ok(afp_info(&value).to_vec());
    }
    Ok(value)
}

/// Makes the stream `attr` holds, which does not exist, with `data`.
/// `AFP_AfpInfo` takes valid AfpInfo whose Finder info is not all zeros,
/// and `AFP_Resource` data that is not empty: neither exists otherwise.
fn put_new(fd: &File, attr: &Attr, data: &[u8]) -> io::Result<()> {
    if attr.kind != Kind::FinderInfo && data.len() as u64 > attr.kind.max() {
        return Err(io::ErrorKind::StorageFull.into());
    }
    match attr.kind {
        Kind::FinderInfo => {
            let info = finder_info(data)?;
            if info.iter().all(|&b| b == 0) {
                return Err(bad_data());
            }
            write_value(fd, &attr.xattr, info, 0, libc::XATTR_CREATE)
        }
        Kind::ResourceFork if data.is_empty() => Err(bad_data()),
        _ => write_value(fd, &attr.xattr, data, 0, libc::XATTR_CREATE),
    }
}

/// The named streams of the file `fd` is open on, none where its
/// filesystem has no extended attributes.
pub(super) fn list(fd: &File) -> io::Result<Vec<StreamInfo>> {
    let view = match View::load(fd) {
        Err(e) if matches!(e.raw_os_error(), Some(libc::ENOTSUP | libc::EOPNOTSUPP)) => {
            return Ok(Vec::new());
        }
        view => view?,
    };
    let mut out = Vec::with_capacity(view.stored.len());
    for stored in &view.stored {
        match value_size(fd, &stored.main.xattr) {
            Ok(len) => {
                let size = match stored.main.kind {
                    Kind::FinderInfo => AFP_INFO_SIZE as u64,
                    _ => len as u64,
                };
                out.push(StreamInfo::new(stored.main.name.clone(), size, size));
            }
            // Removed since the names were read.
            Err(e) if is_missing(&e) => {}
            Err(e) => return Err(e),
        }
    }
    Ok(out)
}

/// Like [`list`], with a backend error.
pub(super) fn list_smb(fd: &File) -> SmbResult<Vec<StreamInfo>> {
    list(fd).map_err(to_smb)
}

/// The values of a stream a rename replaces, set aside until the rename
/// is done, so a failed rename puts them back.
struct Aside(Vec<(CString, Vec<u8>)>);

impl Aside {
    /// Sets aside every name of `stored`, if any; one that exists is
    /// replaced only with `replace`.
    fn take(fd: &File, stored: Option<&Stored>, replace: bool) -> io::Result<Self> {
        let mut aside = Self(Vec::new());
        let Some(stored) = stored else {
            return Ok(aside);
        };
        if !replace {
            return Err(io::ErrorKind::AlreadyExists.into());
        }
        for attr in std::iter::once(&stored.main).chain(&stored.others) {
            let taken = get_bounded(fd, attr, io::ErrorKind::StorageFull).and_then(|value| {
                remove_value(fd, &attr.xattr)?;
                aside.0.push((attr.xattr.clone(), value));
                Ok(())
            });
            if let Err(e) = taken {
                aside.put_back(fd);
                return Err(e);
            }
        }
        Ok(aside)
    }

    fn put_back(&self, fd: &File) {
        for (xattr, value) in &self.0 {
            if let Err(e) = write_value(fd, xattr, value, 0, 0) {
                debug!(error = %e, attr = ?xattr, "replaced stream not put back");
            }
        }
    }
}

/// The size and up to the given number of first bytes of each stream
/// `entries` names of each entry of `dir` it names, `None` where the entry
/// has no such stream or it cannot be read. Each entry is opened once,
/// with [`open_entry`]. `AFP_AfpInfo` and `AFP_Resource` are read from
/// their attributes without listing the others.
pub(super) fn peek_entries(
    dir: &Dir,
    entries: &[(String, Vec<(StreamName, u32)>)],
) -> Vec<Vec<Option<(u64, Bytes)>>> {
    entries
        .iter()
        .map(|(name, streams)| match open_entry(dir, name) {
            Ok((base, _)) => {
                let mut view = None;
                streams
                    .iter()
                    .map(|(stream, max)| {
                        peek(&base, &mut view, stream, *max).unwrap_or_else(|e| {
                            debug!(error = %e, name, stream = stream.as_str(), "stream of a listed entry not read");
                            None
                        })
                    })
                    .collect()
            }
            Err(e) => {
                debug!(error = %e, name, "streams of a listed entry not read");
                vec![None; streams.len()]
            }
        })
        .collect()
}

/// The size of the stream `stream` of the file `fd` is open on and up to
/// `max` bytes from its start. `view` holds the file's streams once a
/// stream other than `AFP_AfpInfo` and `AFP_Resource` needed them.
fn peek(
    fd: &File,
    view: &mut Option<View>,
    stream: &StreamName,
    max: u32,
) -> io::Result<Option<(u64, Bytes)>> {
    let attr = Attr::of(stream)?;
    let attr = match attr.kind {
        Kind::Plain => {
            if view.is_none() {
                *view = Some(View::load(fd)?);
            }
            match view.as_ref().and_then(|view| view.find(stream)) {
                Some(found) => found.main.clone(),
                None => return Ok(None),
            }
        }
        Kind::FinderInfo | Kind::ResourceFork => attr,
    };
    match value_size(fd, &attr.xattr) {
        Err(e) if is_missing(&e) => return Ok(None),
        found => found?,
    };
    let size = size(fd, &attr)?;
    let data = if max == 0 {
        Bytes::new()
    } else {
        read(fd, &attr, 0, max)?
    };
    Ok(Some((size, data)))
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
}

impl Place {
    /// Opens the file at `rel`, for writing too with `write`, and takes its
    /// entry among the open streams. A file at `rel` whose id is not `id`
    /// is not found, unless `id` is `0`.
    fn base(
        &self,
        rel: &std::path::Path,
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
            let attr = Attr::of(&stream)?;
            let view = View::load(&base)?;
            let existing = view.find(&stream).map(|s| s.main.clone());
            let action = match (intent, &existing) {
                (OpenIntent::Open | OpenIntent::Truncate, None) => {
                    return Err(io::ErrorKind::NotFound.into());
                }
                (OpenIntent::Create, Some(_)) => return Err(io::ErrorKind::AlreadyExists.into()),
                (OpenIntent::Open | OpenIntent::OpenOrCreate, Some(_)) => OpenAction::Opened,
                (_, Some(existing)) => {
                    truncate(&base, existing, 0)?;
                    OpenAction::Overwritten
                }
                (_, None) => {
                    if view.stored.len() >= MAX_STREAMS {
                        return Err(io::ErrorKind::StorageFull.into());
                    }
                    match attr.kind {
                        Kind::Plain => write_value(&base, &attr.xattr, &[], 0, libc::XATTR_CREATE)?,
                        Kind::ResourceFork if md.is_dir() => {
                            return Err(io::ErrorKind::PermissionDenied.into());
                        }
                        // Stored with the first write.
                        Kind::ResourceFork | Kind::FinderInfo => {}
                    }
                    OpenAction::Created
                }
            };
            let handle_id = open.add(existing.map_or(stream, |e| e.name));
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
            Attr::of(&stream)?;
            let (base, _, file) = self.base(&rel, id, false)?;
            let _open = lock(&file.open);
            let view = View::load(&base)?;
            let found = view.find(&stream).ok_or(io::ErrorKind::NotFound)?;
            remove_value(&base, &found.main.xattr)?;
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
            if let Some(from) = &from {
                Attr::of(from)?;
            }
            let moves_data = from.is_none() || to.is_none();
            let (base, md, file) = self.base(&rel, id, moves_data)?;
            let mut open = lock(&file.open);
            let view = View::load(&base)?;
            let source = match &from {
                Some(from) => Some(view.find(from).ok_or(io::ErrorKind::NotFound)?),
                None => None,
            };
            match (source, to) {
                (Some(source), Some(to)) => {
                    let target = Attr::of(&to)?;
                    let moved = data(&base, &source.main)?;
                    let aside = Aside::take(&base, view.find(&to), replace)?;
                    if let Err(e) = put_new(&base, &target, &moved) {
                        aside.put_back(&base);
                        return Err(e);
                    }
                    if let Err(e) = remove_value(&base, &source.main.xattr) {
                        if let Err(e) = remove_value(&base, &target.xattr) {
                            debug!(error = %e, "stream rename not undone");
                        }
                        aside.put_back(&base);
                        return Err(e);
                    }
                    remove_others(&base, source);
                    open.rename(&source.main.name, &to);
                }
                (None, Some(to)) => {
                    if view.find(&to).is_none() && view.stored.len() >= MAX_STREAMS {
                        return Err(io::ErrorKind::StorageFull.into());
                    }
                    let target = Attr::of(&to)?;
                    if md.len() > target.kind.max() {
                        return Err(io::ErrorKind::StorageFull.into());
                    }
                    let mut moved = vec![0u8; md.len() as usize];
                    base.read_exact_at(&mut moved, 0)?;
                    let aside = Aside::take(&base, view.find(&to), replace)?;
                    if let Err(e) = put_new(&base, &target, &moved) {
                        aside.put_back(&base);
                        return Err(e);
                    }
                    if let Err(e) = base.set_len(0) {
                        if let Err(e) = remove_value(&base, &target.xattr) {
                            debug!(error = %e, "stream rename not undone");
                        }
                        aside.put_back(&base);
                        return Err(e);
                    }
                }
                (Some(source), None) => {
                    if !replace {
                        return Err(io::ErrorKind::AlreadyExists.into());
                    }
                    let moved = data(&base, &source.main)?;
                    let written = base
                        .write_all_at(&moved, 0)
                        .and_then(|()| base.set_len(moved.len() as u64))
                        .and_then(|()| remove_value(&base, &source.main.xattr));
                    if let Err(e) = written {
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
        f: impl FnOnce(&File, &Attr) -> io::Result<T> + Send + 'static,
    ) -> SmbResult<T> {
        let file = Arc::clone(&self.file);
        let base = Arc::clone(&self.base);
        let id = self.id;
        spawn_blocking(move || {
            let open = lock(&file.open);
            let stream = open.names.get(&id).ok_or(io::ErrorKind::NotFound)?;
            f(&base, &Attr::of(stream)?)
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
        self.locked(move |fd, attr| read(fd, attr, offset, len))
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
            write(fd, attr, offset, &data)?;
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
        self.locked(move |fd, attr| truncate(fd, attr, len)).await
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
