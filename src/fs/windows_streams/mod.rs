//! Named streams of [`LocalFsBackend`](super::LocalFsBackend) on Windows.
//!
//! Each named stream is an NTFS alternate data stream of its file or
//! directory, opened with `NtCreateFile` relative to a handle of the file
//! that cap-std opened inside the share, under the name `:name:$DATA`. A
//! stream name holds no `\`, and the open does not follow reparse points,
//! so it cannot leave that file. NTFS compares stream names by their
//! uppercase forms and keeps the spelling a stream was made with; a stream
//! handle follows the file through renames and the stream through renames
//! of the stream.

use std::fs::File;
use std::io;
use std::os::windows::fs::FileExt as _;
use std::os::windows::io::{AsRawHandle as _, FromRawHandle as _};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use cap_std::fs::{Dir, Metadata, OpenOptions as CapOpenOptions};
use tokio::task::spawn_blocking;
use tracing::debug;
use windows_sys::Wdk::Foundation::OBJECT_ATTRIBUTES;
use windows_sys::Wdk::Storage::FileSystem::{
    FILE_CREATE, FILE_NON_DIRECTORY_FILE, FILE_OPEN, FILE_OPEN_IF, FILE_OPEN_REPARSE_POINT,
    FILE_OVERWRITE, FILE_OVERWRITE_IF, FILE_SYNCHRONOUS_IO_NONALERT, FileStreamInformation,
    NtCreateFile, NtQueryInformationFile,
};
use windows_sys::Win32::Foundation::{
    HANDLE, NTSTATUS, OBJ_CASE_INSENSITIVE, RtlNtStatusToDosError, UNICODE_STRING,
};
use windows_sys::Win32::Storage::FileSystem::{
    DELETE, FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_REPARSE_POINT, FILE_ATTRIBUTE_TAG_INFO,
    FILE_DISPOSITION_INFO, FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_READ_ATTRIBUTES,
    FILE_READ_DATA, FILE_RENAME_INFO, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
    FILE_STANDARD_INFO, FILE_WRITE_ATTRIBUTES, FileAttributeTagInfo, FileDispositionInfo,
    FileRenameInfo, FileStandardInfo, GetFileInformationByHandleEx, GetVolumeInformationByHandleW,
    SYNCHRONIZE, SetFileInformationByHandle,
};
use windows_sys::Win32::System::IO::IO_STATUS_BLOCK;

use super::local::{
    file_index, file_info_from_metadata, file_key, host_file_times, io_to_smb, join_to_io,
    link_count, set_host_attributes,
};
use crate::backend::{DirEntry, FileInfo, FileTimes, Handle, OpenAction, OpenIntent, OpenOptions};
use crate::error::{SmbError, SmbResult};
use crate::path::is_valid_component;
use crate::stream::{StreamInfo, StreamName};

/// The volume stores named streams (MS-FSCC 2.5.1).
const FILE_NAMED_STREAMS: u32 = 0x0004_0000;

/// `FILE_FLAG_BACKUP_SEMANTICS`, which opens directories as well as files.
const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;

/// `FILE_CREATED`, `FILE_OVERWRITTEN` and `FILE_SUPERSEDED` in the
/// information of an `NtCreateFile` that succeeded.
const FILE_CREATED: usize = 2;
const FILE_OVERWRITTEN: usize = 3;
const FILE_SUPERSEDED: usize = 0;

const STATUS_BUFFER_OVERFLOW: NTSTATUS = 0x8000_0005_u32 as NTSTATUS;
const STATUS_END_OF_FILE: NTSTATUS = 0xC000_0011_u32 as NTSTATUS;
const STATUS_INFO_LENGTH_MISMATCH: NTSTATUS = 0xC000_0004_u32 as NTSTATUS;
const STATUS_BUFFER_TOO_SMALL: NTSTATUS = 0xC000_0023_u32 as NTSTATUS;

const ERROR_INVALID_FUNCTION: i32 = 1;
const ERROR_SHARING_VIOLATION: i32 = 32;
const ERROR_NOT_SUPPORTED: i32 = 50;
const ERROR_INVALID_PARAMETER: i32 = 87;
const ERROR_FILE_SYSTEM_LIMITATION: i32 = 665;

/// Most named streams one file has. Past it, the rest are not listed, and
/// a new stream fails with STATUS_DISK_FULL.
const MAX_STREAMS: usize = 4096;

/// Longest entry of a stream listing: the fixed part and `:name:$DATA`
/// with a name of 255 units, padded to 8 bytes.
const MAX_ENTRY: usize = (24_usize + 2 * (1 + 255 + 6)).next_multiple_of(8);

/// Most bytes a stream listing reads: the default stream and 4096 named
/// streams, each with the longest name.
const MAX_LISTING: usize = (MAX_STREAMS + 1) * MAX_ENTRY;

const SHARE_ALL: u32 = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;

// ---------------------------------------------------------------------------
// Host calls
// ---------------------------------------------------------------------------

/// The error an NTSTATUS stands for.
fn nt_error(status: NTSTATUS) -> io::Error {
    // SAFETY: a pure conversion of a status code.
    let code = unsafe { RtlNtStatusToDosError(status) };
    io::Error::from_raw_os_error(code as i32)
}

/// The error a stream request answers for `e`. A volume without named
/// streams refuses access: a stream request must not fail with
/// STATUS_NOT_SUPPORTED. A stream past what the volume holds fills the
/// disk.
fn to_smb(e: io::Error) -> SmbError {
    match e.raw_os_error() {
        Some(ERROR_INVALID_FUNCTION | ERROR_NOT_SUPPORTED) => SmbError::AccessDenied,
        Some(ERROR_INVALID_PARAMETER) => SmbError::InvalidParameter,
        Some(ERROR_FILE_SYSTEM_LIMITATION) => SmbError::DiskFull,
        _ => io_to_smb(e),
    }
}

/// The error for a request the volume or the stream's state refuses,
/// which STATUS_INVALID_PARAMETER answers.
fn refused() -> io::Error {
    io::Error::from_raw_os_error(ERROR_INVALID_PARAMETER)
}

/// The named streams of a share's volume.
#[derive(Debug, Clone, Copy)]
pub(super) struct Volume {
    /// The volume is ReFS, which cannot rename streams.
    pub refs: bool,
}

/// The file system flags and name of the volume `handle` is on.
fn volume_of(handle: HANDLE) -> Option<(u32, String)> {
    let mut flags = 0u32;
    let mut name = [0u16; 64];
    // SAFETY: `handle` is open for the call, `flags` is a live local and
    // `name` a live buffer of the length passed; the other buffers are
    // null with size 0.
    let ok = unsafe {
        GetVolumeInformationByHandleW(
            handle,
            std::ptr::null_mut(),
            0,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut flags,
            name.as_mut_ptr(),
            name.len() as u32,
        )
    };
    let len = name.iter().position(|&u| u == 0).unwrap_or(name.len());
    (ok != 0).then(|| (flags, String::from_utf16_lossy(&name[..len])))
}

/// The named streams of the volume of `root`, `None` when it has none.
pub(super) fn volume(root: &Dir) -> Option<Volume> {
    use std::os::windows::io::AsHandle as _;
    let (flags, name) = volume_of(root.as_handle().as_raw_handle() as HANDLE)?;
    (flags & FILE_NAMED_STREAMS != 0).then(|| Volume {
        refs: name.eq_ignore_ascii_case("ReFS"),
    })
}

/// `c` as NTFS compares it: its uppercase form where that is one
/// character, else itself.
fn upcase(c: char) -> char {
    let mut upper = c.to_uppercase();
    match (upper.next(), upper.next()) {
        (Some(u), None) => u,
        _ => c,
    }
}

/// True if NTFS takes `a` and `b` for the same stream name: their
/// characters compare by uppercase form, one by one.
fn same_name(a: &StreamName, b: &StreamName) -> bool {
    a.as_str()
        .chars()
        .map(upcase)
        .eq(b.as_str().chars().map(upcase))
}

/// `:name:$DATA`, or `::$DATA` for the default stream, in UTF-16.
fn object_name(stream: Option<&StreamName>) -> Vec<u16> {
    let name = stream.map_or("", StreamName::as_str);
    format!(":{name}:$DATA").encode_utf16().collect()
}

/// Opens the stream `stream` of the file `base` is open on, the default
/// stream when `None`, with `access`, `share` and `disposition`. Returns
/// the handle and what the open did.
fn open_relative(
    base: &File,
    stream: Option<&StreamName>,
    access: u32,
    share: u32,
    disposition: u32,
) -> io::Result<(File, usize)> {
    nt_open(
        base.as_raw_handle() as HANDLE,
        object_name(stream),
        access,
        share,
        disposition,
        FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT | FILE_OPEN_REPARSE_POINT,
    )
}

/// Opens `name` relative to the open handle `root` with `access`, `share`,
/// `disposition` and `options`. Returns the handle and what the open did.
fn nt_open(
    root: HANDLE,
    mut name: Vec<u16>,
    access: u32,
    share: u32,
    disposition: u32,
    options: u32,
) -> io::Result<(File, usize)> {
    let bytes = u16::try_from(name.len() * 2).map_err(|_| io::ErrorKind::InvalidFilename)?;
    let unicode = UNICODE_STRING {
        Length: bytes,
        MaximumLength: bytes,
        Buffer: name.as_mut_ptr(),
    };
    let attributes = OBJECT_ATTRIBUTES {
        Length: std::mem::size_of::<OBJECT_ATTRIBUTES>() as u32,
        RootDirectory: root,
        ObjectName: &unicode,
        Attributes: OBJ_CASE_INSENSITIVE,
        SecurityDescriptor: std::ptr::null(),
        SecurityQualityOfService: std::ptr::null(),
    };
    let mut handle: HANDLE = std::ptr::null_mut();
    let mut status_block = IO_STATUS_BLOCK::default();
    // SAFETY: every pointer refers to a live local that outlives the call:
    // `attributes` names `unicode`, whose buffer is `name`, and the root
    // is an open handle the caller holds. The call writes only `handle`
    // and `status_block`.
    let status = unsafe {
        NtCreateFile(
            &mut handle,
            access | SYNCHRONIZE,
            &attributes,
            &mut status_block,
            std::ptr::null(),
            FILE_ATTRIBUTE_NORMAL,
            share,
            disposition,
            options,
            std::ptr::null(),
            0,
        )
    };
    if status < 0 {
        return Err(nt_error(status));
    }
    // SAFETY: the call succeeded, so `handle` is an open handle that
    // nothing else owns.
    let file = unsafe { File::from_raw_handle(handle as _) };
    Ok((file, status_block.Information))
}

/// The disposition of `intent`.
fn disposition(intent: OpenIntent) -> u32 {
    match intent {
        OpenIntent::Open => FILE_OPEN,
        OpenIntent::Create => FILE_CREATE,
        OpenIntent::OpenOrCreate => FILE_OPEN_IF,
        OpenIntent::OverwriteOrCreate => FILE_OVERWRITE_IF,
        OpenIntent::Truncate => FILE_OVERWRITE,
    }
}

/// Size and allocation size of the stream `file` is open on.
fn sizes(file: &File) -> io::Result<(u64, u64)> {
    let mut info = FILE_STANDARD_INFO::default();
    // SAFETY: `info` is a live local of the size passed.
    let ok = unsafe {
        GetFileInformationByHandleEx(
            file.as_raw_handle() as HANDLE,
            FileStandardInfo,
            (&raw mut info).cast(),
            std::mem::size_of::<FILE_STANDARD_INFO>() as u32,
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok((info.EndOfFile as u64, info.AllocationSize as u64))
}

/// Marks the stream `file` is open on for deletion when its last handle
/// closes.
fn delete_on_close(file: &File) -> io::Result<()> {
    let info = FILE_DISPOSITION_INFO { DeleteFile: true };
    // SAFETY: `info` is a live local of the size passed.
    let ok = unsafe {
        SetFileInformationByHandle(
            file.as_raw_handle() as HANDLE,
            FileDispositionInfo,
            (&raw const info).cast(),
            std::mem::size_of::<FILE_DISPOSITION_INFO>() as u32,
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// A name no stream has, for a stream a rename replaces while the rename
/// runs.
fn aside_name() -> io::Result<StreamName> {
    let mut id = [0u8; 8];
    crate::utils::fill_random(&mut id).map_err(|e| io::Error::other(e.to_string()))?;
    let hex: String = id.iter().map(|b| format!("{b:02x}")).collect();
    format!("smb-server-replaced-{hex}")
        .parse()
        .map_err(|_| io::ErrorKind::InvalidFilename.into())
}

/// Renames the stream `file` is open on to `to`, the default stream when
/// `None`.
fn rename(file: &File, to: Option<&StreamName>, replace: bool) -> io::Result<()> {
    let name = object_name(to);
    let offset = std::mem::offset_of!(FILE_RENAME_INFO, FileName);
    // The name, then a NUL that `FileNameLength` leaves out.
    let size = offset + (name.len() + 1) * 2;
    // u64 units keep the structure aligned; zeros give the NUL.
    let mut buf = vec![0u64; size.div_ceil(8)];
    let info = buf.as_mut_ptr().cast::<FILE_RENAME_INFO>();
    // SAFETY: `buf` holds `size` bytes, aligned for `FILE_RENAME_INFO`:
    // the fixed part, then `name.len()` UTF-16 units and a NUL from
    // `FileName` on.
    unsafe {
        (*info).Anonymous.ReplaceIfExists = replace;
        (*info).RootDirectory = std::ptr::null_mut();
        (*info).FileNameLength = (name.len() * 2) as u32;
        std::ptr::copy_nonoverlapping(
            name.as_ptr(),
            (&raw mut (*info).FileName).cast::<u16>(),
            name.len(),
        );
    }
    // SAFETY: `buf` is live and holds `size` bytes of the structure.
    let ok = unsafe {
        SetFileInformationByHandle(
            file.as_raw_handle() as HANDLE,
            FileRenameInfo,
            buf.as_ptr().cast(),
            size as u32,
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// The named streams of the file `file` is open on, none where its volume
/// has none.
pub(super) fn list(file: &File) -> io::Result<Vec<StreamInfo>> {
    let mut len = 4096;
    let (buf, filled) = loop {
        // u64 units keep the entries aligned.
        let mut buf = vec![0u64; len / 8];
        let mut status_block = IO_STATUS_BLOCK::default();
        // SAFETY: `buf` is live and `len` bytes long; the call writes no
        // more than that, and the count of bytes written to
        // `status_block`.
        let status = unsafe {
            NtQueryInformationFile(
                file.as_raw_handle() as HANDLE,
                &mut status_block,
                buf.as_mut_ptr().cast(),
                len as u32,
                FileStreamInformation,
            )
        };
        match status {
            0 => break (buf, status_block.Information),
            STATUS_END_OF_FILE => return Ok(Vec::new()),
            STATUS_BUFFER_OVERFLOW | STATUS_BUFFER_TOO_SMALL | STATUS_INFO_LENGTH_MISMATCH
                if len < MAX_LISTING =>
            {
                len = (len * 2).min(MAX_LISTING.next_multiple_of(8));
            }
            STATUS_BUFFER_OVERFLOW => {
                debug!("named streams of a file past {MAX_STREAMS} left out");
                break (buf, status_block.Information);
            }
            // A volume without named streams, such as FAT, refuses the
            // query with STATUS_INVALID_PARAMETER.
            status => {
                return match volume_of(file.as_raw_handle() as HANDLE) {
                    Some((flags, _)) if flags & FILE_NAMED_STREAMS == 0 => Ok(Vec::new()),
                    _ => Err(nt_error(status)),
                };
            }
        }
    };
    // SAFETY: `buf` is live and `buf.len() * 8` bytes long.
    let bytes = unsafe { std::slice::from_raw_parts(buf.as_ptr().cast::<u8>(), buf.len() * 8) };
    Ok(parse_listing(&bytes[..filled.min(bytes.len())]))
}

/// The named streams in a FILE_STREAM_INFORMATION list (MS-FSCC 2.4.49).
/// An entry that does not fit whole ends the list.
fn parse_listing(buf: &[u8]) -> Vec<StreamInfo> {
    let field = |at: usize, len: usize| buf.get(at..at.checked_add(len)?);
    let u32_at = |at: usize| field(at, 4).map(|b| u32::from_le_bytes(b.try_into().unwrap()));
    let u64_at = |at: usize| field(at, 8).map(|b| u64::from_le_bytes(b.try_into().unwrap()));
    let mut out = Vec::new();
    let mut at = 0usize;
    while out.len() < MAX_STREAMS {
        let (Some(next), Some(len), Some(size), Some(allocation)) =
            (u32_at(at), u32_at(at + 4), u64_at(at + 8), u64_at(at + 16))
        else {
            break;
        };
        let Some(name) = field(at + 24, len as usize) else {
            break;
        };
        let units: Vec<u16> = name
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        let named = String::from_utf16(&units).ok().and_then(|name| {
            let name = name.strip_prefix(':')?.strip_suffix(":$DATA")?;
            name.parse::<StreamName>().ok()
        });
        if let Some(name) = named {
            out.push(StreamInfo::new(name, size, allocation));
        }
        // Past the end, no entry fits, and `at + 24` cannot overflow
        // before that.
        match at.checked_add(next as usize) {
            Some(after) if next != 0 && after < buf.len() => at = after,
            _ => break,
        }
    }
    out
}

/// Like [`list`], with a backend error.
pub(super) fn list_smb(file: &File) -> SmbResult<Vec<StreamInfo>> {
    list(file).map_err(to_smb)
}

/// The size and up to the given number of first bytes of each stream
/// `entries` names of each entry of `dir` it names, `None` where the entry
/// has no such stream or it cannot be read. Each entry is opened once,
/// with [`open_entry`], and its streams relative to it.
pub(super) fn peek_entries(
    dir: &Dir,
    entries: &[(String, Vec<(StreamName, u32)>)],
) -> Vec<Vec<Option<(u64, Bytes)>>> {
    entries
        .iter()
        .map(|(name, streams)| match open_entry(dir, name) {
            Ok(base) => streams
                .iter()
                .map(|(stream, max)| {
                    peek(&base, stream, *max).unwrap_or_else(|e| {
                        debug!(error = %e, name, stream = stream.as_str(), "stream of a listed entry not read");
                        None
                    })
                })
                .collect(),
            Err(e) => {
                debug!(error = %e, name, "streams of a listed entry not read");
                vec![None; streams.len()]
            }
        })
        .collect()
}

/// Opens the entry `name` of `dir` for its attributes, to open its streams
/// through, without following a reparse point there. A symlink or a
/// junction is opened through cap-std instead, which follows it only to a
/// target below `dir`; other reparse points, such as deduplicated,
/// compressed or cloud files, keep the first handle.
fn open_entry(dir: &Dir, name: &str) -> io::Result<File> {
    use cap_primitives::fs::OpenOptionsExt as _;
    use std::os::windows::io::AsHandle as _;
    if !is_valid_component(name) {
        return Err(io::ErrorKind::InvalidFilename.into());
    }
    let (file, _) = nt_open(
        dir.as_handle().as_raw_handle() as HANDLE,
        name.encode_utf16().collect(),
        FILE_READ_ATTRIBUTES,
        SHARE_ALL,
        FILE_OPEN,
        FILE_SYNCHRONOUS_IO_NONALERT | FILE_OPEN_REPARSE_POINT,
    )?;
    if !is_link(&file)? {
        return Ok(file);
    }
    let mut opts = CapOpenOptions::new();
    opts.read(true)
        .access_mode(FILE_READ_ATTRIBUTES | SYNCHRONIZE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS);
    Ok(dir.open_with(name, &opts)?.into_std())
}

/// True if `file` is open on a symlink or a junction itself.
fn is_link(file: &File) -> io::Result<bool> {
    const IO_REPARSE_TAG_MOUNT_POINT: u32 = 0xA000_0003;
    const IO_REPARSE_TAG_SYMLINK: u32 = 0xA000_000C;
    let mut info = FILE_ATTRIBUTE_TAG_INFO::default();
    // SAFETY: `info` is a live local of the size passed.
    let ok = unsafe {
        GetFileInformationByHandleEx(
            file.as_raw_handle() as HANDLE,
            FileAttributeTagInfo,
            (&raw mut info).cast(),
            std::mem::size_of::<FILE_ATTRIBUTE_TAG_INFO>() as u32,
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(info.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
        && matches!(
            info.ReparseTag,
            IO_REPARSE_TAG_MOUNT_POINT | IO_REPARSE_TAG_SYMLINK
        ))
}

/// The size of the stream `stream` of the file `base` is open on and up to
/// `max` bytes from its start.
fn peek(base: &File, stream: &StreamName, max: u32) -> io::Result<Option<(u64, Bytes)>> {
    let access = if max == 0 {
        FILE_READ_ATTRIBUTES
    } else {
        FILE_READ_DATA | FILE_READ_ATTRIBUTES
    };
    let file = match open_relative(base, Some(stream), access, SHARE_ALL, FILE_OPEN) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        file => file?.0,
    };
    let (size, _) = sizes(&file)?;
    let mut data = vec![0; (max as u64).min(size) as usize];
    let mut read = 0;
    while read < data.len() {
        match file.seek_read(&mut data[read..], read as u64)? {
            0 => break,
            n => read += n,
        }
    }
    data.truncate(read);
    Ok(Some((size, Bytes::from(data))))
}

// ---------------------------------------------------------------------------
// Open streams
// ---------------------------------------------------------------------------

/// Where a backend keeps the files of its share.
#[derive(Clone)]
pub(super) struct Place {
    pub root: Arc<Dir>,
    pub root_dev: Option<u64>,
    pub read_only: bool,
    pub volume: Volume,
}

impl Place {
    /// Opens the file or directory at `rel` for its attributes, to open its
    /// streams through. A file at `rel` whose id is not `id` is not found,
    /// unless `id` is `0`.
    fn base(&self, rel: &Path, id: u64) -> io::Result<(File, Metadata)> {
        use cap_primitives::fs::OpenOptionsExt as _;
        let mut opts = CapOpenOptions::new();
        opts.read(true)
            .access_mode(FILE_READ_ATTRIBUTES | SYNCHRONIZE)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS);
        let base = self.root.open_with(rel, &opts)?.into_std();
        let md = Metadata::from_file(&base)?;
        if id != 0 && id != file_index(self.root_dev, file_key(&md)) {
            return Err(io::ErrorKind::NotFound.into());
        }
        Ok((base, md))
    }

    /// Opens the named stream `stream` of the file at `rel`, which has the
    /// id `id`, as `opts` says.
    pub(super) async fn open_stream(
        self,
        rel: PathBuf,
        name: String,
        id: u64,
        stream: StreamName,
        opts: OpenOptions,
    ) -> SmbResult<(Box<dyn Handle>, OpenAction)> {
        spawn_blocking(move || -> io::Result<_> {
            let (base, md) = self.base(&rel, id)?;
            let mut access = FILE_READ_ATTRIBUTES;
            if opts.read {
                access |= FILE_GENERIC_READ;
            }
            if opts.write || opts.intent != OpenIntent::Open {
                access |= FILE_GENERIC_WRITE;
            }
            if opts.write_attributes {
                access |= FILE_WRITE_ATTRIBUTES;
            }
            if opts.intent != OpenIntent::Open && opts.intent != OpenIntent::Truncate {
                let streams = list(&base)?;
                if streams.len() >= MAX_STREAMS
                    && !streams.iter().any(|s| same_name(&s.name, &stream))
                {
                    return Err(io::ErrorKind::StorageFull.into());
                }
            }
            let (file, done) = open_relative(
                &base,
                Some(&stream),
                access,
                SHARE_ALL,
                disposition(opts.intent),
            )?;
            let action = match done {
                FILE_CREATED => OpenAction::Created,
                FILE_OVERWRITTEN | FILE_SUPERSEDED => OpenAction::Overwritten,
                _ => OpenAction::Opened,
            };
            let handle: Box<dyn Handle> = Box::new(StreamHandle {
                file: Arc::new(file),
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
            let (base, _) = self.base(&rel, id)?;
            let (file, _) = open_relative(&base, Some(&stream), DELETE, SHARE_ALL, FILE_OPEN)?;
            delete_on_close(&file)
        })
        .await
        .map_err(join_to_io)
        .map_err(to_smb)?
        .map_err(to_smb)
    }

    /// Renames a stream of the file at `rel`, which has the id `id`, as
    /// [`ShareBackend::rename_stream`](crate::ShareBackend::rename_stream)
    /// says, through a handle on the stream it renames.
    pub(super) async fn rename_stream(
        self,
        rel: PathBuf,
        id: u64,
        from: Option<StreamName>,
        to: Option<StreamName>,
        replace: bool,
    ) -> SmbResult<()> {
        spawn_blocking(move || -> io::Result<()> {
            let (base, _) = self.base(&rel, id)?;
            // ReFS refuses stream renames itself, with
            // STATUS_INVALID_PARAMETER or STATUS_OBJECT_TYPE_MISMATCH.
            if self.volume.refs {
                return Err(refused());
            }
            let Some(to) = to else {
                let (source, _) = open_relative(
                    &base,
                    from.as_ref(),
                    DELETE | FILE_READ_ATTRIBUTES,
                    SHARE_ALL,
                    FILE_OPEN,
                )?;
                // NTFS refuses to move data into the default stream while
                // another handle is open on it, `base` included.
                drop(base);
                return rename(&source, None, replace);
            };
            // NTFS fails to replace a stream spelled in another case, so a
            // stream the rename replaces, which is empty, moves out of the
            // way to a name of its own first, goes once the rename is done,
            // and comes back if it fails; handles on it follow it. It is
            // opened before the source, whose handle would conflict, sharing
            // delete access only, so one open elsewhere for its data fails
            // the rename before anything changes, with
            // STATUS_INVALID_PARAMETER as NTFS fails it.
            let streams = list(&base)?;
            if let Some(from) = &from
                && !streams.iter().any(|s| same_name(&s.name, from))
            {
                return Err(io::ErrorKind::NotFound.into());
            }
            let aside = match streams.into_iter().find(|s| same_name(&s.name, &to)) {
                None => None,
                Some(_) if !replace => return Err(io::ErrorKind::AlreadyExists.into()),
                Some(replaced) => {
                    let target = match open_relative(
                        &base,
                        Some(&replaced.name),
                        DELETE,
                        FILE_SHARE_DELETE,
                        FILE_OPEN,
                    ) {
                        Ok((target, _)) => target,
                        Err(e) if e.raw_os_error() == Some(ERROR_SHARING_VIOLATION) => {
                            return Err(refused());
                        }
                        Err(e) => return Err(e),
                    };
                    rename(&target, Some(&aside_name()?), false)?;
                    Some((target, replaced.name))
                }
            };
            let renamed = open_relative(
                &base,
                from.as_ref(),
                DELETE | FILE_READ_ATTRIBUTES,
                SHARE_ALL,
                FILE_OPEN,
            )
            .and_then(|(source, _)| rename(&source, Some(&to), false));
            if let Some((target, name)) = aside {
                let settled = match &renamed {
                    Ok(()) => delete_on_close(&target),
                    Err(_) => rename(&target, Some(&name), false),
                };
                if let Err(e) = settled {
                    debug!(error = %e, stream = name.as_str(), "replaced stream left aside");
                }
            }
            renamed
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

/// The handle of a named stream open: an NTFS handle on the stream.
struct StreamHandle {
    file: Arc<File>,
    /// The stream belongs to a directory.
    is_dir: bool,
    /// The file's name, as `FileInfo` reports it.
    name: String,
    root_dev: Option<u64>,
    /// The backend is read-only.
    read_only: bool,
}

impl StreamHandle {
    async fn run<T: Send + 'static>(
        &self,
        f: impl FnOnce(&File) -> io::Result<T> + Send + 'static,
    ) -> SmbResult<T> {
        let file = Arc::clone(&self.file);
        spawn_blocking(move || f(&file))
            .await
            .map_err(join_to_io)
            .map_err(to_smb)?
            .map_err(to_smb)
    }
}

#[async_trait]
impl Handle for StreamHandle {
    async fn read(&self, offset: u64, len: u32) -> SmbResult<Bytes> {
        self.run(move |file| {
            let mut buf = vec![0u8; len as usize];
            let read = file.seek_read(&mut buf, offset)?;
            buf.truncate(read);
            Ok(Bytes::from(buf))
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
        self.run(move |file| {
            let written = file.seek_write(&data, offset)?;
            Ok(u32::try_from(written).unwrap_or(u32::MAX))
        })
        .await
    }

    async fn flush(&self) -> SmbResult<()> {
        self.run(|file| file.sync_all()).await
    }

    async fn stat(&self) -> SmbResult<FileInfo> {
        let name = self.name.clone();
        let root_dev = self.root_dev;
        let is_dir = self.is_dir;
        self.run(move |file| {
            let md = Metadata::from_file(file)?;
            let mut info = file_info_from_metadata(name, &md, root_dev);
            info.is_directory = is_dir;
            (info.end_of_file, info.allocation_size) = sizes(file)?;
            // A volume with streams and without extended attributes, such
            // as ReFS, may refuse the query; the file then has none.
            info.ea_size = super::windows_eas::size(file).unwrap_or(0);
            Ok(info)
        })
        .await
    }

    async fn set_times(&self, times: FileTimes) -> SmbResult<()> {
        if self.read_only {
            return Err(SmbError::AccessDenied);
        }
        let times = host_file_times(times);
        self.run(move |file| file.set_times(times)).await
    }

    async fn set_attributes(&self, attributes: u32) -> SmbResult<()> {
        if self.read_only {
            return Err(SmbError::AccessDenied);
        }
        let is_dir = self.is_dir;
        self.run(move |file| set_host_attributes(file, attributes, is_dir))
            .await
    }

    async fn truncate(&self, len: u64) -> SmbResult<()> {
        if self.read_only {
            return Err(SmbError::AccessDenied);
        }
        self.run(move |file| file.set_len(len)).await
    }

    async fn list_dir(&self, _pattern: Option<&str>) -> SmbResult<Vec<DirEntry>> {
        Err(SmbError::NotADirectory)
    }

    async fn close(self: Box<Self>) -> SmbResult<()> {
        Ok(())
    }

    async fn link_count(&self) -> SmbResult<u32> {
        let is_dir = self.is_dir;
        self.run(move |file| {
            let md = Metadata::from_file(file)?;
            let links = link_count(&md).map_or(1, |n| u32::try_from(n).unwrap_or(u32::MAX));
            Ok(if is_dir { links.min(1) } else { links })
        })
        .await
    }

    async fn dir_is_empty(&self) -> SmbResult<bool> {
        Err(SmbError::NotADirectory)
    }

    async fn streams(&self) -> SmbResult<Vec<StreamInfo>> {
        self.run(list).await
    }
}

#[cfg(test)]
mod tests;
