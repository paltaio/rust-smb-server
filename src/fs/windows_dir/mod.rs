//! Directory handles of [`LocalFsBackend`](super::LocalFsBackend) on
//! Windows.
//!
//! A [`Dir`] holds an open directory handle, and every name below it is
//! looked up relative to an open handle with `NtCreateFile`, one name at a
//! time. No handle is turned back into a path.
//!
//! A lookup never leaves the directory it starts from, on a local volume
//! and on an SMB share alike. A path with a prefix or a root is refused. A
//! name followed by `..` cancels out, as Windows reads paths; any other
//! `..` goes back to a directory the same lookup opened, and never above
//! the one it started from. Each name on the way is opened without
//! following a reparse point, and its reparse tag decides what it is: a
//! symlink is followed when its target is relative, at most 40 links in one
//! lookup, and a junction, whose target is absolute, is not followed. A file
//! in the middle of a path fails with ERROR_DIRECTORY.
//!
//! A lookup holds the directory it starts from and each directory on its
//! way open with FILE_TRAVERSE and without delete sharing, so none of them
//! can be renamed or deleted until the lookup ends; a rename or delete of
//! one in that time fails with a sharing violation. The server's account
//! needs traverse rights on the share's directories. A directory
//! [`Dir::open_dir`] opens shares delete access, and is opened again this
//! way at the start of each lookup from it; a lookup whose new handle is
//! not open on the same directory fails as not found. A directory
//! [`Dir::open_ambient_dir`] opens is held for as long as it is open.
//!
//! An SMB share opens a name relative to a handle by the path of that
//! handle, so a second handle of a file opened through an open one may be
//! open on whatever has the old name now. [`reopen`] checks the new handle
//! is open on the same file, and fails as not found if it is not.
//!
//! A link of a kind other than a symlink or a junction fails as a special
//! file, which clients see as STATUS_IO_REPARSE_TAG_NOT_HANDLED.
//!
//! Each listing reads a handle of the directory of its own, so listings of
//! one open directory do not share a position.
//!
//! A rename refused with STATUS_ACCESS_DENIED, as a directory rename is
//! while something has an entry below it open, is tried again for up to
//! [`RENAME_WAIT`].
//!
//! The SMB client of Windows can send a create as the open of another
//! spelling of the name that another program has open, and can drop a
//! rename to the spelling the handle was opened by, so a share root on
//! another machine can store a name in another case than the one asked
//! for. There, each create and rename reads back the name the server
//! stored, and a name stored in another spelling is renamed to
//! `~smb-<32 hex digits>` in its directory, then to the name asked for, as
//! [`RootVolume::settle`] says.

use std::collections::VecDeque;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::io;
use std::os::windows::ffi::{OsStrExt as _, OsStringExt as _};
use std::os::windows::fs::OpenOptionsExt as _;
use std::os::windows::io::{AsHandle, AsRawHandle as _, BorrowedHandle, FromRawHandle as _};
use std::path::{Component, Path};
use std::sync::Arc;
#[cfg(test)]
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use tracing::{debug, error, warn};
use windows_sys::Wdk::Foundation::OBJECT_ATTRIBUTES;
use windows_sys::Wdk::Storage::FileSystem::{
    FILE_CREATE, FILE_DIRECTORY_FILE, FILE_INFORMATION_CLASS, FILE_NON_DIRECTORY_FILE, FILE_OPEN,
    FILE_OPEN_FOR_BACKUP_INTENT, FILE_OPEN_IF, FILE_OPEN_REPARSE_POINT,
    FILE_RENAME_POSIX_SEMANTICS, FILE_RENAME_REPLACE_IF_EXISTS, FILE_SYNCHRONOUS_IO_NONALERT,
    FileBasicInformation, FileDispositionInformation, FileFsDeviceInformation,
    FileFullDirectoryInformation, FileNormalizedNameInformation, FileRenameInformation,
    FileRenameInformationEx, NtCreateFile, NtQueryDirectoryFile, NtQueryInformationFile,
    NtQueryVolumeInformationFile, NtSetInformationFile,
};
use windows_sys::Win32::Foundation::{
    GENERIC_READ, GENERIC_WRITE, HANDLE, NTSTATUS, OBJ_CASE_INSENSITIVE, STATUS_ACCESS_DENIED,
    STATUS_CANNOT_DELETE, STATUS_INVALID_INFO_CLASS, STATUS_INVALID_PARAMETER,
    STATUS_NOT_SUPPORTED, STATUS_OBJECT_NAME_INVALID, UNICODE_STRING,
};
use windows_sys::Win32::Storage::FileSystem::{
    BY_HANDLE_FILE_INFORMATION, DELETE, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_HIDDEN,
    FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_READONLY, FILE_ATTRIBUTE_REPARSE_POINT,
    FILE_ATTRIBUTE_TAG_INFO, FILE_BASIC_INFO, FILE_DISPOSITION_INFO, FILE_FLAG_BACKUP_SEMANTICS,
    FILE_ID_INFO, FILE_LIST_DIRECTORY, FILE_READ_ATTRIBUTES, FILE_RENAME_INFO, FILE_SHARE_DELETE,
    FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_TRAVERSE, FILE_WRITE_ATTRIBUTES, FileAttributeTagInfo,
    FileIdInfo, GetFileInformationByHandle, GetFileInformationByHandleEx, SYNCHRONIZE,
};
use windows_sys::Win32::System::IO::{DeviceIoControl, IO_STATUS_BLOCK};
use windows_sys::Win32::System::Ioctl::FSCTL_GET_REPARSE_POINT;

use super::local::{filetime_to_system_time, is_hidden, special_file};
pub(crate) use crate::host::{
    ERROR_INVALID_FUNCTION, ERROR_INVALID_PARAMETER, ERROR_NOT_SUPPORTED, nt_error, refuses_posix,
};
use crate::host::{delete_posix, dos_error};
use crate::utils::utf16le_to_units;

/// Every kind of sharing.
pub(crate) const SHARE_ALL: u32 = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;

/// The access a lookup holds each directory on its way with. FILE_TRAVERSE
/// is outside GENERIC_READ, so an SMB client cannot serve the open from
/// another open of the directory, which may share delete access.
const HOLD_ACCESS: u32 = FILE_TRAVERSE | FILE_READ_ATTRIBUTES;

/// The sharing a lookup holds each directory on its way with.
const HOLD_SHARE: u32 = FILE_SHARE_READ | FILE_SHARE_WRITE;

/// Most links one lookup follows.
const MAX_LINKS: u32 = 40;

const IO_REPARSE_TAG_MOUNT_POINT: u32 = 0xA000_0003;
const IO_REPARSE_TAG_SYMLINK: u32 = 0xA000_000C;

/// The bit of a reparse tag that marks a link to another name.
const NAME_SURROGATE: u32 = 0x2000_0000;

/// The flag of a symlink whose target is relative to its directory.
const SYMLINK_FLAG_RELATIVE: u32 = 1;

/// Most bytes a reparse point holds.
const MAX_REPARSE: usize = 16 << 10;

/// Bytes one call of a listing reads.
const LISTING: usize = 64 << 10;

/// Offsets in a FILE_FULL_DIR_INFORMATION entry (MS-FSCC 2.4.17).
const DIR_CREATION_TIME: usize = 8;
const DIR_LAST_ACCESS_TIME: usize = 16;
const DIR_LAST_WRITE_TIME: usize = 24;
const DIR_END_OF_FILE: usize = 40;
const DIR_ATTRIBUTES: usize = 56;
const DIR_NAME_LENGTH: usize = 60;
const DIR_EA_SIZE: usize = 64;
const DIR_NAME: usize = 68;

/// The attributes FileBasicInformation sets (MS-FSCC 2.6).
const SETTABLE_ATTRIBUTES: u32 = 0x31A7;

/// The options of each open of a lookup on its way.
const WALK_OPTIONS: u32 =
    FILE_SYNCHRONOUS_IO_NONALERT | FILE_OPEN_REPARSE_POINT | FILE_OPEN_FOR_BACKUP_INTENT;

const STATUS_NO_MORE_FILES: NTSTATUS = 0x8000_0006_u32 as NTSTATUS;
const STATUS_NO_SUCH_FILE: NTSTATUS = 0xC000_000F_u32 as NTSTATUS;

/// `FILE_CREATED` in the information of an `NtCreateFile` that succeeded.
pub(crate) const FILE_CREATED: usize = 2;

/// The device of a volume is on another machine (MS-FSCC 2.5.10).
const FILE_REMOTE_DEVICE: u32 = 0x10;

/// Longest path FileNormalizedNameInformation reports, in UTF-16 units.
const MAX_PATH_UNITS: usize = 32767;

/// Longest time a rename refused with STATUS_ACCESS_DENIED is tried again,
/// from its first refusal.
pub(crate) const RENAME_WAIT: Duration = Duration::from_secs(1);

const ERROR_ACCESS_DENIED: i32 = 5;
pub(crate) const ERROR_SHARING_VIOLATION: i32 = 32;
pub(crate) const ERROR_DIR_NOT_EMPTY: i32 = 145;
const ERROR_DIRECTORY: i32 = 267;
const ERROR_TOO_MANY_LINKS: i32 = 1142;

// ---------------------------------------------------------------------------
// NT calls
// ---------------------------------------------------------------------------

/// Opens `name` relative to the open handle `root` with `access`, `share`,
/// `disposition` and `options`, making it with `attributes` where the
/// disposition makes it; an empty name opens `root` again. Returns the
/// handle and what the open did, or the status it failed with.
fn nt_create(
    root: HANDLE,
    mut name: Vec<u16>,
    access: u32,
    share: u32,
    disposition: u32,
    options: u32,
    attributes: u32,
) -> Result<(fs::File, usize), NTSTATUS> {
    let bytes = u16::try_from(name.len() * 2).map_err(|_| STATUS_OBJECT_NAME_INVALID)?;
    let unicode = UNICODE_STRING {
        Length: bytes,
        MaximumLength: bytes,
        Buffer: name.as_mut_ptr(),
    };
    let object = OBJECT_ATTRIBUTES {
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
    // `object` names `unicode`, whose buffer is `name` and holds `bytes`
    // bytes, and the root is an open handle the caller holds. The call
    // writes only `handle` and `status_block`.
    let status = unsafe {
        NtCreateFile(
            &mut handle,
            access | SYNCHRONIZE,
            &object,
            &mut status_block,
            std::ptr::null(),
            attributes,
            share,
            disposition,
            options,
            std::ptr::null(),
            0,
        )
    };
    if status < 0 {
        return Err(status);
    }
    // SAFETY: the call succeeded, so `handle` is an open handle that
    // nothing else owns.
    let file = unsafe { fs::File::from_raw_handle(handle as _) };
    Ok((file, status_block.Information))
}

/// Opens `name` relative to the open handle `root` with `access`, `share`,
/// `disposition` and `options`; an empty name opens `root` again. Returns
/// the handle and what the open did.
pub(crate) fn nt_open(
    root: HANDLE,
    name: Vec<u16>,
    access: u32,
    share: u32,
    disposition: u32,
    options: u32,
) -> io::Result<(fs::File, usize)> {
    nt_create(
        root,
        name,
        access,
        share,
        disposition,
        options,
        FILE_ATTRIBUTE_NORMAL,
    )
    .map_err(nt_error)
}

/// The volume serial number and 128-bit file id of the file `file` is
/// open on.
fn file_id(file: &fs::File) -> io::Result<(u64, [u8; 16])> {
    let mut info = FILE_ID_INFO::default();
    // SAFETY: `info` is a live local of the size passed, and the handle is
    // open for the call.
    let ok = unsafe {
        GetFileInformationByHandleEx(
            file.as_raw_handle(),
            FileIdInfo,
            (&raw mut info).cast(),
            std::mem::size_of::<FILE_ID_INFO>() as u32,
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok((info.VolumeSerialNumber, info.FileId.Identifier))
}

/// The volume serial number and 64-bit file index of the file `file` is
/// open on.
fn file_index_of(file: &fs::File) -> io::Result<(u32, u64)> {
    let md = Metadata::from_file(file)?;
    match (md.volume_serial_number, md.file_index) {
        (Some(volume), Some(index)) => Ok((volume, index)),
        _ => Err(io::ErrorKind::Unsupported.into()),
    }
}

/// True if `a` and `b` are open on the same file or directory: the same
/// volume serial number and 128-bit file id, or where the volume does not
/// report those, the same serial number and file index. Handles of named
/// streams count as their file.
pub(crate) fn same_file(a: &fs::File, b: &fs::File) -> io::Result<bool> {
    if let (Ok(a), Ok(b)) = (file_id(a), file_id(b)) {
        return Ok(a == b);
    }
    Ok(file_index_of(a)? == file_index_of(b)?)
}

/// The error for a handle that turned out to be open on another file than
/// the one it was opened through.
pub(crate) fn moved() -> io::Error {
    io::Error::new(
        io::ErrorKind::NotFound,
        "the file is no longer under the name it was opened by",
    )
}

/// A second handle of the file or directory `file` is open on, opened by
/// an empty name relative to it with `access`, `share` and `options`. An
/// SMB share opens it by the path `file` was opened by, which may name
/// another file by now; a handle open on another file fails as not found.
fn reopen_checked(file: &fs::File, access: u32, share: u32, options: u32) -> io::Result<fs::File> {
    let (new, _) = nt_open(
        file.as_raw_handle(),
        Vec::new(),
        access,
        share,
        FILE_OPEN,
        options,
    )?;
    if !same_file(file, &new)? {
        return Err(moved());
    }
    Ok(new)
}

/// A second handle of the file or directory `file` is open on, with
/// `access` and FILE_READ_ATTRIBUTES. It is a handle of its own, with its
/// own position in a directory listing. One that would be open on another
/// file, as on an SMB share after the file was renamed, fails as not found.
pub(crate) fn reopen(file: &fs::File, access: u32) -> io::Result<fs::File> {
    reopen_checked(
        file,
        access | FILE_READ_ATTRIBUTES,
        SHARE_ALL,
        FILE_SYNCHRONOUS_IO_NONALERT | FILE_OPEN_REPARSE_POINT,
    )
}

/// A buffer of `len` bytes aligned to 8, as the calls that fill or read
/// FILE_FULL_EA_INFORMATION, FILE_FULL_DIR_INFORMATION and reparse data
/// need.
pub(crate) fn aligned(len: usize) -> Vec<u64> {
    vec![0; len.div_ceil(8)]
}

/// The first `len` bytes of `words`.
pub(crate) fn bytes_of(words: &[u64], len: usize) -> Vec<u8> {
    let mut out: Vec<u8> = words.iter().flat_map(|w| w.to_ne_bytes()).collect();
    out.truncate(len);
    out
}

fn u16_at(buf: &[u8], at: usize) -> Option<u16> {
    let bytes = buf.get(at..at.checked_add(2)?)?;
    Some(u16::from_le_bytes(bytes.try_into().ok()?))
}

fn u32_at(buf: &[u8], at: usize) -> Option<u32> {
    let bytes = buf.get(at..at.checked_add(4)?)?;
    Some(u32::from_le_bytes(bytes.try_into().ok()?))
}

fn u64_at(buf: &[u8], at: usize) -> Option<u64> {
    let bytes = buf.get(at..at.checked_add(8)?)?;
    Some(u64::from_le_bytes(bytes.try_into().ok()?))
}

/// The attributes and the reparse tag of the file `file` is open on; the
/// tag is 0 unless it is a reparse point.
fn attribute_tag(file: &fs::File) -> io::Result<(u32, u32)> {
    let mut info = FILE_ATTRIBUTE_TAG_INFO::default();
    // SAFETY: `info` is a live local of the size passed, and the handle is
    // open for the call.
    let ok = unsafe {
        GetFileInformationByHandleEx(
            file.as_raw_handle(),
            FileAttributeTagInfo,
            (&raw mut info).cast(),
            std::mem::size_of::<FILE_ATTRIBUTE_TAG_INFO>() as u32,
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    let tag = if info.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        info.ReparseTag
    } else {
        0
    };
    Ok((info.FileAttributes, tag))
}

/// True for the attributes and reparse tag of a link to another name, such
/// as a symlink or a junction.
fn links(attributes: u32, tag: u32) -> bool {
    attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 && tag & NAME_SURROGATE != 0
}

/// True if `file` is open on a symlink or a junction itself.
pub(crate) fn is_link(file: &fs::File) -> io::Result<bool> {
    let (attributes, tag) = attribute_tag(file)?;
    Ok(links(attributes, tag))
}

/// The relative target of the symlink `link` is open on. A junction or a
/// symlink with an absolute target leads outside the share.
fn link_target(link: &fs::File) -> io::Result<OsString> {
    let mut buf = aligned(MAX_REPARSE);
    let mut returned = 0u32;
    // SAFETY: the handle is open for the call, `buf` is a live buffer of
    // `MAX_REPARSE` bytes, aligned to 8 as a `u64` buffer is, `returned` is
    // a live local, and there is no input buffer and no OVERLAPPED, as the
    // handle is synchronous.
    let ok = unsafe {
        DeviceIoControl(
            link.as_raw_handle(),
            FSCTL_GET_REPARSE_POINT,
            std::ptr::null(),
            0,
            buf.as_mut_ptr().cast(),
            MAX_REPARSE as u32,
            &mut returned,
            std::ptr::null_mut(),
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    let data = bytes_of(&buf, returned as usize);
    let invalid = || io::Error::new(io::ErrorKind::InvalidData, "a link without a target");
    match u32_at(&data, 0).ok_or_else(invalid)? {
        IO_REPARSE_TAG_SYMLINK => {}
        IO_REPARSE_TAG_MOUNT_POINT => return Err(escape()),
        _ => return Err(special_file()),
    }
    // SymbolicLinkReparseBuffer: the substitute name's offset and length,
    // the print name's, the flags, then the names.
    if u32_at(&data, 16).ok_or_else(invalid)? & SYMLINK_FLAG_RELATIVE == 0 {
        return Err(escape());
    }
    let offset = 20 + usize::from(u16_at(&data, 8).ok_or_else(invalid)?);
    let len = usize::from(u16_at(&data, 10).ok_or_else(invalid)?);
    let name = data.get(offset..offset + len).ok_or_else(invalid)?;
    let units = utf16le_to_units(name).ok_or_else(invalid)?;
    Ok(OsString::from_wide(&units))
}

/// Sets the information `info` of the class `class` of the file `file` is
/// open on.
fn set_info<T>(file: &fs::File, class: FILE_INFORMATION_CLASS, info: &T) -> Result<(), NTSTATUS> {
    let mut status_block = IO_STATUS_BLOCK::default();
    // SAFETY: `info` is a live value of the size passed, laid out as the
    // structure of `class`, and the handle is open for the call.
    let status = unsafe {
        NtSetInformationFile(
            file.as_raw_handle(),
            &mut status_block,
            std::ptr::from_ref(info).cast(),
            std::mem::size_of::<T>() as u32,
            class,
        )
    };
    if status < 0 { Err(status) } else { Ok(()) }
}

/// Gives the file `file` is open on, with FILE_WRITE_ATTRIBUTES access,
/// the attributes `attributes`, its times left as they are.
fn set_attributes(file: &fs::File, attributes: u32) -> Result<(), NTSTATUS> {
    let attributes = attributes & SETTABLE_ATTRIBUTES;
    // 0 leaves a time unchanged, and attributes of 0 would too.
    let info = FILE_BASIC_INFO {
        CreationTime: 0,
        LastAccessTime: 0,
        LastWriteTime: 0,
        ChangeTime: 0,
        FileAttributes: if attributes == 0 {
            FILE_ATTRIBUTE_NORMAL
        } else {
            attributes
        },
    };
    set_info(file, FileBasicInformation, &info)
}

/// Marks the file or directory `file` is open on, with DELETE access, to be
/// deleted when its last handle closes; its name stays until then. A
/// read-only file, open with FILE_WRITE_ATTRIBUTES access too, loses its
/// READONLY attribute for it, and gets it back if it still cannot be
/// deleted. A directory with entries fails with
/// STATUS_DIRECTORY_NOT_EMPTY.
pub(crate) fn delete_on_close(file: &fs::File) -> Result<(), NTSTATUS> {
    let mark = || {
        set_info(
            file,
            FileDispositionInformation,
            &FILE_DISPOSITION_INFO { DeleteFile: true },
        )
    };
    match mark() {
        Err(STATUS_CANNOT_DELETE) => {}
        marked => return marked,
    }
    let Ok((attributes, _)) = attribute_tag(file) else {
        return Err(STATUS_CANNOT_DELETE);
    };
    if attributes & FILE_ATTRIBUTE_READONLY == 0
        || set_attributes(file, attributes & !FILE_ATTRIBUTE_READONLY).is_err()
    {
        return Err(STATUS_CANNOT_DELETE);
    }
    mark().inspect_err(|_| {
        if let Err(status) = set_attributes(file, attributes) {
            debug!(error = %nt_error(status), "READONLY not set back on a file that was not deleted");
        }
    })
}

/// Opens the entry `name` of the directory `dir` is open on, a link there
/// itself, to delete it with [`delete_on_close`].
pub(crate) fn open_to_delete(dir: &fs::File, name: &OsStr) -> Result<fs::File, NTSTATUS> {
    let (file, _) = nt_create(
        dir.as_raw_handle(),
        name.encode_wide().collect(),
        DELETE | FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES,
        SHARE_ALL,
        FILE_OPEN,
        WALK_OPTIONS,
        FILE_ATTRIBUTE_NORMAL,
    )?;
    Ok(file)
}

/// Gives the file `file` is open on the name `name` in the directory
/// `dir` is open on, through FILE_RENAME_INFORMATION of the information
/// class `class` with `flags`.
fn set_name(
    file: &fs::File,
    dir: HANDLE,
    name: &[u16],
    class: FILE_INFORMATION_CLASS,
    flags: u32,
) -> Result<(), NTSTATUS> {
    let offset = std::mem::offset_of!(FILE_RENAME_INFO, FileName);
    // The name, then a NUL that the length passed counts and
    // `FileNameLength` leaves out.
    let size = offset + (name.len() + 1) * 2;
    let name_bytes = u32::try_from(name.len() * 2).map_err(|_| STATUS_OBJECT_NAME_INVALID)?;
    // u64 units keep the structure aligned; zeros give the NUL.
    let mut buf = aligned(size);
    let info = buf.as_mut_ptr().cast::<FILE_RENAME_INFO>();
    // SAFETY: `buf` holds `size` bytes, aligned for `FILE_RENAME_INFO`:
    // the fixed part, then `name.len()` UTF-16 units and a NUL from
    // `FileName` on.
    unsafe {
        (*info).Anonymous.Flags = flags;
        (*info).RootDirectory = dir;
        (*info).FileNameLength = name_bytes;
        std::ptr::copy_nonoverlapping(
            name.as_ptr(),
            (&raw mut (*info).FileName).cast::<u16>(),
            name.len(),
        );
    }
    let mut status_block = IO_STATUS_BLOCK::default();
    // SAFETY: `buf` is live and holds `size` bytes of the structure, whose
    // root is an open handle the caller holds, and the handle of `file` is
    // open for the call.
    let status = unsafe {
        NtSetInformationFile(
            file.as_raw_handle(),
            &mut status_block,
            buf.as_ptr().cast(),
            size as u32,
            class,
        )
    };
    if status < 0 { Err(status) } else { Ok(()) }
}

/// A name of 32 lowercase hex digits from 128 random bits.
pub(crate) fn random_name() -> io::Result<String> {
    let mut id = [0u8; 16];
    crate::utils::fill_random(&mut id).map_err(|e| io::Error::other(e.to_string()))?;
    Ok(id.iter().map(|b| format!("{b:02x}")).collect())
}

/// `c` as NTFS compares it: its uppercase form where that is one
/// character, else itself.
pub(crate) fn upcase(c: char) -> char {
    let mut upper = c.to_uppercase();
    match (upper.next(), upper.next()) {
        (Some(u), None) => u,
        _ => c,
    }
}

/// True if the UTF-16 names `a` and `b` are one name to NTFS: their
/// characters compare by uppercase form, one by one.
fn same_name(a: &[u16], b: &[u16]) -> bool {
    let chars = |units: &[u16]| {
        char::decode_utf16(units.iter().copied())
            .map(|c| c.map(upcase))
            .collect::<Vec<_>>()
    };
    chars(a) == chars(b)
}

/// The last name of the path `path`, separated by `\`.
pub(crate) fn last_component(path: &[u16]) -> &[u16] {
    path.rsplit(|&unit| unit == u16::from(b'\\'))
        .next()
        .unwrap_or(path)
}

// ---------------------------------------------------------------------------
// Names on remote roots
// ---------------------------------------------------------------------------

/// A step of [`RootVolume::settle`], which [`SETTLE`] can fail.
#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Step {
    /// The stored name is read.
    Check,
    /// A handle with DELETE access is opened.
    Reopen,
    /// The entry is renamed to the temporary name.
    Aside,
    /// The entry is renamed to the name asked for.
    Requested,
    /// The entry is renamed back to the spelling it had.
    Restore,
}

/// What runs before each step of [`RootVolume::settle`], with the name
/// asked for; an error it returns fails the step.
#[cfg(test)]
type SettleHook = Box<dyn Fn(Step, &[u16]) -> Option<io::Error> + Send>;

/// Runs before each step of [`RootVolume::settle`].
#[cfg(test)]
pub(crate) static SETTLE: std::sync::Mutex<Option<SettleHook>> = std::sync::Mutex::new(None);

/// The error [`SETTLE`] fails `step` with.
#[cfg(test)]
fn settle_hook(step: Step, name: &[u16]) -> Option<io::Error> {
    SETTLE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .as_ref()
        .and_then(|f| f(step, name))
}

/// Runs `$run`, a step of [`RootVolume::settle`] for the name `$name`,
/// unless [`SETTLE`] fails it.
macro_rules! step {
    ($step:ident, $name:expr, $run:expr) => {{
        #[cfg(test)]
        let refused = settle_hook(Step::$step, $name);
        #[cfg(not(test))]
        let refused: Option<io::Error> = None;
        match refused {
            Some(e) => Err(e),
            None => $run,
        }
    }};
}

/// FILE_FS_DEVICE_INFORMATION (MS-FSCC 2.5.10).
#[repr(C)]
#[derive(Default)]
struct DeviceInfo {
    device_type: u32,
    characteristics: u32,
}

/// True if `file` is open on a volume of another machine, as through a UNC
/// path or a mapped drive.
fn is_remote(file: &fs::File) -> io::Result<bool> {
    let mut info = DeviceInfo::default();
    let mut status_block = IO_STATUS_BLOCK::default();
    // SAFETY: `info` is a live local of the size passed, laid out as
    // FILE_FS_DEVICE_INFORMATION, and the handle is open for the call.
    let status = unsafe {
        NtQueryVolumeInformationFile(
            file.as_raw_handle(),
            &mut status_block,
            (&raw mut info).cast(),
            std::mem::size_of::<DeviceInfo>() as u32,
            FileFsDeviceInformation,
        )
    };
    if status < 0 {
        return Err(nt_error(status));
    }
    Ok(info.characteristics & FILE_REMOTE_DEVICE != 0)
}

/// The path of the file `file` is open on, spelled as the file system
/// stores its names; `None` where the file system does not report it.
/// SMB servers refuse the query on dialects before 3.1.1 (MS-SMB2
/// 3.3.5.20.1).
fn normalized_name(file: &fs::File) -> io::Result<Option<Vec<u16>>> {
    let len = 4 + MAX_PATH_UNITS * 2;
    let mut buf = aligned(len);
    let mut status_block = IO_STATUS_BLOCK::default();
    // SAFETY: `buf` is a live buffer of at least `len` bytes, aligned to 8
    // as a `u64` buffer is, and the handle is open for the call, which
    // writes no more than `len` bytes there.
    let status = unsafe {
        NtQueryInformationFile(
            file.as_raw_handle(),
            &mut status_block,
            buf.as_mut_ptr().cast(),
            len as u32,
            FileNormalizedNameInformation,
        )
    };
    match status {
        STATUS_NOT_SUPPORTED | STATUS_INVALID_INFO_CLASS | STATUS_INVALID_PARAMETER => {
            return Ok(None);
        }
        s if s < 0 => return Err(nt_error(s)),
        _ => {}
    }
    // FILE_NAME_INFORMATION: the length of the name in bytes, then the name.
    let data = bytes_of(&buf, len);
    let invalid = || io::Error::new(io::ErrorKind::InvalidData, "a name without its length");
    let name_len = u32_at(&data, 0).ok_or_else(invalid)? as usize;
    let name = data.get(4..4 + name_len).ok_or_else(invalid)?;
    Ok(Some(utf16le_to_units(name).ok_or_else(invalid)?))
}

/// The name of the entry of the directory `dir` is open on that `name`
/// matches under the directory's case rule, read through a handle of the
/// directory of its own.
fn listed_name(dir: &fs::File, name: &[u16]) -> io::Result<Vec<u16>> {
    // A literal pattern also matches an entry whose 8.3 short name it is.
    for entry in Entries::new(reopen(dir, FILE_LIST_DIRECTORY)?, name.to_vec()) {
        let listed: Vec<u16> = entry?.name.encode_wide().collect();
        if same_name(&listed, name) {
            return Ok(listed);
        }
    }
    Err(io::ErrorKind::NotFound.into())
}

/// What the directories of one backend know about the volume of its share
/// root.
pub(crate) struct RootVolume {
    /// The share root is on another machine.
    remote: bool,
    /// The file system refused FileNormalizedNameInformation.
    no_normalized_names: AtomicBool,
    /// The volume refused a rename with POSIX semantics.
    no_posix_renames: AtomicBool,
    /// Names corrected so far.
    #[cfg(test)]
    corrections: AtomicUsize,
    /// Runs before each rename on a remote root.
    #[cfg(test)]
    before_rename: std::sync::OnceLock<RenameHook>,
}

/// What runs before a rename on a remote root opens its source, with the
/// directory of the target relative to the directory the rename is looked
/// up from, the target's last name, and whether the rename changes only the
/// case of the name. A handle it returns stays open until the rename
/// returns. The SMB client gives a later open of the same file the
/// spelling of an open that is already there.
#[cfg(test)]
pub(crate) type RenameHook = Box<dyn Fn(&Path, &OsStr, bool) -> Option<fs::File> + Send + Sync>;

impl RootVolume {
    /// The volume of the share root `root` is open on.
    fn of(root: &fs::File) -> io::Result<Self> {
        Ok(Self {
            remote: is_remote(root)?,
            no_normalized_names: AtomicBool::new(false),
            no_posix_renames: AtomicBool::new(false),
            #[cfg(test)]
            corrections: AtomicUsize::new(0),
            #[cfg(test)]
            before_rename: std::sync::OnceLock::new(),
        })
    }

    /// Makes `hook` run before each rename on a remote root.
    #[cfg(test)]
    pub(crate) fn before_rename(&self, hook: RenameHook) {
        assert!(
            self.before_rename.set(hook).is_ok(),
            "a rename hook is in place already"
        );
    }

    /// True if the share root is on another machine, as through a UNC path
    /// or a mapped drive.
    pub(crate) fn is_remote(&self) -> bool {
        self.remote
    }

    /// How many names have been corrected so far.
    #[cfg(test)]
    pub(crate) fn corrections(&self) -> usize {
        self.corrections.load(Ordering::Relaxed)
    }

    /// The path of the file `file` is open on, as [`normalized_name`]
    /// reads it; `None` once the file system refused the query.
    pub(crate) fn normalized(&self, file: &fs::File) -> io::Result<Option<Vec<u16>>> {
        if self.no_normalized_names.load(Ordering::Relaxed) {
            return Ok(None);
        }
        let name = normalized_name(file)?;
        if name.is_none() {
            self.no_normalized_names.store(true, Ordering::Relaxed);
        }
        Ok(name)
    }

    /// The name, as the file system stores it, of the entry `file` is open
    /// on, which is `name` under the case rule of the directory `dir` is
    /// open on, where it is.
    fn stored_name(&self, file: &fs::File, dir: &fs::File, name: &[u16]) -> io::Result<Vec<u16>> {
        match self.normalized(file)? {
            Some(path) => Ok(last_component(&path).to_vec()),
            None => listed_name(dir, name),
        }
    }

    /// Gives the file `file` is open on the name `name` in the directory
    /// `dir` is open on, replacing a file there with `replace`.
    ///
    /// A plain rename refused with ERROR_ACCESS_DENIED, such as one onto a
    /// file open elsewhere, is tried with POSIX semantics too, unless the
    /// volume refused those before. A refusal with STATUS_ACCESS_DENIED is
    /// tried again as [`Wait`] says, then fails.
    fn rename(
        &self,
        file: &fs::File,
        dir: HANDLE,
        name: &[u16],
        replace: bool,
    ) -> Result<(), NTSTATUS> {
        let flags = if replace {
            FILE_RENAME_REPLACE_IF_EXISTS
        } else {
            0
        };
        let mut wait = Wait::default();
        loop {
            let refused = match set_name(file, dir, name, FileRenameInformation, flags) {
                Err(status) if dos_error(status) == ERROR_ACCESS_DENIED => status,
                renamed => return renamed,
            };
            if !self.no_posix_renames.load(Ordering::Relaxed) {
                let posix = set_name(
                    file,
                    dir,
                    name,
                    FileRenameInformationEx,
                    flags | FILE_RENAME_POSIX_SEMANTICS,
                );
                match posix {
                    Ok(()) => return Ok(()),
                    Err(status) if dos_error(status) == ERROR_DIR_NOT_EMPTY => return Err(status),
                    Err(status) if refuses_posix(status) => {
                        self.no_posix_renames.store(true, Ordering::Relaxed);
                    }
                    Err(_) => {}
                }
            }
            if refused != STATUS_ACCESS_DENIED || !wait.again() {
                return Err(refused);
            }
        }
    }

    /// Makes the name the file system stored for what `file` made or
    /// renamed under the name `requested` equal `requested`, on a share
    /// root on another machine; `names` reads and changes that name.
    ///
    /// The stored name is read back; one in another spelling gets a DELETE
    /// handle, is renamed to `~smb-<32 hex digits>`, then to `requested`,
    /// and is read back again. A refused rename is tried again as [`Wait`]
    /// says, and so is a reopen refused with a sharing violation. Between
    /// the two renames the entry lists under the temporary name.
    ///
    /// A name that cannot be made right is reported as `made` says: a
    /// case-only rename fails with the error that stopped the correction,
    /// and a create or a move to another name succeeds under the stored
    /// spelling, with a warning. When the second rename fails, the entry
    /// goes back to the spelling it had first; if that fails too, it stays
    /// under the temporary name, and the call fails with the error of the
    /// second rename. A create whose name another entry took in the
    /// meantime fails with [`Collided`], which names where the entry was
    /// left.
    pub(crate) fn settle(
        &self,
        names: &dyn Names,
        made: Made,
        requested: &[u16],
        file: &fs::File,
    ) -> io::Result<()> {
        let stored = match step!(Check, requested, names.stored(file)) {
            Ok(stored) if stored == requested => return Ok(()),
            Ok(stored) => stored,
            Err(e) => return unsettled(made, requested, None, e),
        };
        let handle = match step!(Reopen, requested, names.reopen()) {
            Ok(handle) => handle,
            Err(e) => return unsettled(made, requested, Some(&stored), e),
        };
        let aside: Vec<u16> = match random_name() {
            Ok(hex) => format!("~smb-{hex}").encode_utf16().collect(),
            Err(e) => return unsettled(made, requested, Some(&stored), e),
        };
        if let Err(e) = step!(Aside, requested, names.rename(&handle, &aside)) {
            return unsettled(made, requested, Some(&stored), e);
        }
        if let Err(e) = step!(Requested, requested, names.rename(&handle, requested)) {
            if made == Made::Created && e.kind() == io::ErrorKind::AlreadyExists {
                return Err(io::Error::other(Collided { aside }));
            }
            return match step!(Restore, requested, names.rename(&handle, &stored)) {
                Ok(()) => unsettled(made, requested, Some(&stored), e),
                Err(back) => {
                    error!(
                        requested = %String::from_utf16_lossy(requested),
                        left = %String::from_utf16_lossy(&aside),
                        error = %e,
                        back = %back,
                        "an entry was left under a temporary name"
                    );
                    Err(e)
                }
            };
        }
        match names.stored(&handle) {
            Ok(now) if now == requested => {
                #[cfg(test)]
                self.corrections.fetch_add(1, Ordering::Relaxed);
                Ok(())
            }
            Ok(now) => unsettled(made, requested, Some(&now), nt_error(STATUS_ACCESS_DENIED)),
            Err(e) => unsettled(made, requested, None, e),
        }
    }
}

/// What a call that gave an entry its name did, which decides how a name
/// stored in another spelling that cannot be corrected is reported.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Made {
    /// It made the entry.
    Created,
    /// It moved the entry to another name.
    Moved,
    /// It changed only the case of the name, in the same directory.
    CaseOnly,
}

/// The outcome of a call whose entry keeps the name `stored`, `None` when
/// unknown, in place of `requested`, as `e` stopped its correction.
fn unsettled(
    made: Made,
    requested: &[u16],
    stored: Option<&[u16]>,
    e: io::Error,
) -> io::Result<()> {
    if made == Made::CaseOnly {
        return Err(e);
    }
    warn!(
        requested = %String::from_utf16_lossy(requested),
        stored = %stored.map(String::from_utf16_lossy).unwrap_or_default(),
        error = %e,
        "a name keeps the spelling the server stored"
    );
    Ok(())
}

/// How [`RootVolume::settle`] reads and changes the name of an entry or a
/// named stream.
pub(crate) trait Names {
    /// The name the file system stores, read through `file`.
    fn stored(&self, file: &fs::File) -> io::Result<Vec<u16>>;

    /// A handle with DELETE access, to rename through.
    fn reopen(&self) -> io::Result<fs::File>;

    /// Renames what `file` is open on to `name`, in the directory it is in
    /// or among the streams of its file, without replacing anything.
    fn rename(&self, file: &fs::File, name: &[u16]) -> io::Result<()>;
}

/// An entry of a directory a create or a rename named.
struct EntryNames<'a> {
    volume: &'a RootVolume,
    /// The directory the entry is in.
    dir: &'a fs::File,
    /// The name it was given.
    requested: &'a [u16],
    /// The handle the call made or renamed it through.
    made: &'a fs::File,
    /// `made` has DELETE access.
    deletable: bool,
}

impl Names for EntryNames<'_> {
    fn stored(&self, file: &fs::File) -> io::Result<Vec<u16>> {
        self.volume.stored_name(file, self.dir, self.requested)
    }

    fn reopen(&self) -> io::Result<fs::File> {
        if self.deletable {
            return self.made.try_clone();
        }
        let mut wait = Wait::default();
        loop {
            match reopen_checked(
                self.made,
                DELETE | FILE_READ_ATTRIBUTES,
                SHARE_ALL,
                FILE_SYNCHRONOUS_IO_NONALERT | FILE_OPEN_REPARSE_POINT,
            ) {
                Err(e) if e.raw_os_error() == Some(ERROR_SHARING_VIOLATION) && wait.again() => {}
                reopened => return reopened,
            }
        }
    }

    fn rename(&self, file: &fs::File, name: &[u16]) -> io::Result<()> {
        self.volume
            .rename(file, self.dir.as_raw_handle(), name, false)
            .map_err(nt_error)
    }
}

/// The error of a create whose name another entry took while the name was
/// corrected. The entry it made is left under `aside`, in its directory or
/// among the streams of its file.
#[derive(Debug)]
pub(crate) struct Collided {
    pub(crate) aside: Vec<u16>,
}

impl std::fmt::Display for Collided {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("another entry took the name while it was corrected")
    }
}

impl std::error::Error for Collided {}

/// Where the entry of a create that failed with [`Collided`] was left.
pub(crate) fn collided(e: &io::Error) -> Option<&Collided> {
    e.get_ref()?.downcast_ref::<Collided>()
}

/// The pauses between the tries of a refused call: 1, 2, 4, 8, 16 and
/// 32 ms, then 50 ms each, until [`RENAME_WAIT`] has passed since the
/// first refusal. Each pause sleeps the thread the call runs on.
#[derive(Default)]
pub(crate) struct Wait {
    first: Option<Instant>,
    pauses: u32,
}

impl Wait {
    /// Called after each refusal: sleeps until the next try and returns
    /// true, or returns false once [`RENAME_WAIT`] has passed since the
    /// first refusal.
    pub(crate) fn again(&mut self) -> bool {
        let first = *self.first.get_or_insert_with(Instant::now);
        let Some(left) = RENAME_WAIT
            .checked_sub(first.elapsed())
            .filter(|left| !left.is_zero())
        else {
            return false;
        };
        let pause = match self.pauses {
            n @ 0..=5 => Duration::from_millis(1 << n),
            _ => Duration::from_millis(50),
        };
        self.pauses += 1;
        std::thread::sleep(pause.min(left));
        true
    }
}

/// The error for a path that leads outside the directory it is looked up
/// from.
fn escape() -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        "a path leads outside the share",
    )
}

/// The error for a path that names the directory it is looked up from,
/// where a name in it is needed.
fn no_name() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, "the path has no name")
}

// ---------------------------------------------------------------------------
// Lookups
// ---------------------------------------------------------------------------

/// A lookup of a path below a directory, one name at a time. It holds the
/// directory it starts from and each directory on its way until it ends.
struct Walk<'a> {
    /// The directory the lookup starts from.
    start: &'a Dir,
    /// The start, held for the lookup, when the `Dir` itself is not held.
    pin: Option<fs::File>,
    /// The directories opened on the way, the one reached last on top.
    opened: Vec<fs::File>,
    /// The names left to look up, `..` among them.
    pending: VecDeque<OsString>,
    /// The links followed so far.
    links: u32,
}

impl<'a> Walk<'a> {
    fn new(start: &'a Dir, path: &Path) -> io::Result<Self> {
        let pin = if start.held {
            None
        } else {
            Some(reopen_checked(
                &start.file,
                HOLD_ACCESS,
                HOLD_SHARE,
                WALK_OPTIONS,
            )?)
        };
        let mut walk = Self {
            start,
            pin,
            opened: Vec::new(),
            pending: VecDeque::new(),
            links: 0,
        };
        walk.push_front(path)?;
        Ok(walk)
    }

    /// The directory reached so far.
    fn dir_file(&self) -> &fs::File {
        self.opened
            .last()
            .or(self.pin.as_ref())
            .unwrap_or(&self.start.file)
    }

    /// The handle of the directory reached so far.
    fn dir(&self) -> HANDLE {
        self.dir_file().as_raw_handle()
    }

    /// True while the lookup is in the directory it started from.
    fn at_start(&self) -> bool {
        self.opened.is_empty()
    }

    /// Puts the names of `path` before those left to look up.
    fn push_front(&mut self, path: &Path) -> io::Result<()> {
        let mut names: Vec<OsString> = Vec::new();
        for component in path.components() {
            match component {
                Component::Prefix(_) | Component::RootDir => return Err(escape()),
                Component::CurDir => {}
                Component::ParentDir if names.last().is_some_and(|name| name != "..") => {
                    names.pop();
                }
                Component::ParentDir => names.push("..".into()),
                Component::Normal(name) => names.push(name.to_os_string()),
            }
        }
        for name in names.into_iter().rev() {
            self.pending.push_front(name);
        }
        Ok(())
    }

    /// Puts the target of the link `link` is open on before the names left
    /// to look up.
    fn follow(&mut self, link: &fs::File) -> io::Result<()> {
        self.links += 1;
        if self.links > MAX_LINKS {
            return Err(io::Error::from_raw_os_error(ERROR_TOO_MANY_LINKS));
        }
        let target = link_target(link)?;
        self.push_front(Path::new(&target))
    }

    /// Goes to the directory that holds the last name, and returns that
    /// name; `None` when the path ends at a directory itself.
    fn reach_last(&mut self) -> io::Result<Option<OsString>> {
        while let Some(name) = self.pending.pop_front() {
            if name == ".." {
                self.opened.pop().ok_or_else(escape)?;
                continue;
            }
            if self.at_start() && self.start.reserves(&name) {
                return Err(io::ErrorKind::NotFound.into());
            }
            if self.pending.is_empty() {
                return Ok(Some(name));
            }
            let (next, _) = nt_open(
                self.dir(),
                name.encode_wide().collect(),
                HOLD_ACCESS,
                HOLD_SHARE,
                FILE_OPEN,
                WALK_OPTIONS,
            )?;
            let (attributes, tag) = attribute_tag(&next)?;
            if links(attributes, tag) {
                self.follow(&next)?;
            } else if attributes & FILE_ATTRIBUTE_DIRECTORY == 0 {
                return Err(io::Error::from_raw_os_error(ERROR_DIRECTORY));
            } else {
                self.opened.push(next);
                #[cfg(test)]
                if let Some(f) = lock_hook().as_ref() {
                    f(&name);
                }
            }
        }
        Ok(None)
    }

    /// Goes to the directory that holds the last name, which the path must
    /// have.
    fn reach_name(&mut self) -> io::Result<Vec<u16>> {
        let name = self.reach_last()?.ok_or_else(no_name)?;
        Ok(name.encode_wide().collect())
    }

    /// Opens what the path names with `access`, `disposition` and
    /// `options`, without following a reparse point there, sharing all
    /// access. With `follow`, a link there is followed and what it leads to
    /// opened instead. Also returns whether what it opened is the directory
    /// the lookup started from. On a remote root, a file it makes gets the
    /// name asked for, as [`RootVolume::settle`] says.
    fn open(
        &mut self,
        access: u32,
        disposition: u32,
        options: u32,
        follow: bool,
    ) -> io::Result<(fs::File, bool)> {
        loop {
            let name = self.reach_last()?;
            let wide: Vec<u16> = match &name {
                Some(name) => name.encode_wide().collect(),
                None => Vec::new(),
            };
            let (file, done) = nt_open(
                self.dir(),
                wide.clone(),
                access,
                SHARE_ALL,
                disposition,
                options | FILE_OPEN_REPARSE_POINT,
            )?;
            if follow && name.is_some() && is_link(&file)? {
                self.follow(&file)?;
                continue;
            }
            let volume = &self.start.volume;
            if done == FILE_CREATED && volume.remote && name.is_some() {
                let names = EntryNames {
                    volume,
                    dir: self.dir_file(),
                    requested: &wide,
                    made: &file,
                    deletable: false,
                };
                volume.settle(&names, Made::Created, &wide, &file)?;
            }
            return Ok((file, name.is_none() && self.at_start()));
        }
    }
}

/// What a lookup runs each time it has opened a directory on its way,
/// with that directory's name.
#[cfg(test)]
type Hook = Box<dyn Fn(&OsStr) + Send>;

/// Runs in a lookup each time it has opened a directory on its way.
#[cfg(test)]
pub(crate) static AFTER_COMPONENT: std::sync::Mutex<Option<Hook>> = std::sync::Mutex::new(None);

#[cfg(test)]
fn lock_hook() -> std::sync::MutexGuard<'static, Option<Hook>> {
    AFTER_COMPONENT
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

// ---------------------------------------------------------------------------
// Dir
// ---------------------------------------------------------------------------

/// What [`Dir::open_ambient_dir`] takes to open a path of the host.
pub(crate) struct AmbientAuthority;

/// The authority to open a path of the host.
pub(crate) fn ambient_authority() -> AmbientAuthority {
    AmbientAuthority
}

/// An open directory, which names below it are looked up from.
pub(crate) struct Dir {
    file: fs::File,
    /// The handle shares no delete access, so the directory is not renamed
    /// or removed while it is open, and lookups from it hold nothing more
    /// at their start.
    held: bool,
    /// A name lookups refuse in this directory, and whether it is matched
    /// with regard to case.
    reserved: Option<(&'static str, bool)>,
    /// The volume of the directory [`Dir::open_ambient_dir`] opened, which
    /// this one was reached from.
    volume: Arc<RootVolume>,
}

impl Dir {
    /// Opens the directory at `path` of the host. The handle shares read
    /// and write access but not delete access, so the directory is not
    /// renamed or removed while it is open.
    pub(crate) fn open_ambient_dir(
        path: impl AsRef<Path>,
        _authority: AmbientAuthority,
    ) -> io::Result<Self> {
        let file = fs::OpenOptions::new()
            .read(true)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
            .open(path)?;
        if !file.metadata()?.is_dir() {
            return Err(io::Error::from_raw_os_error(ERROR_DIRECTORY));
        }
        let volume = Arc::new(RootVolume::of(&file)?);
        Ok(Self {
            file,
            held: true,
            reserved: None,
            volume,
        })
    }

    /// The volume of the directory [`Dir::open_ambient_dir`] opened, which
    /// this one was reached from.
    pub(crate) fn volume(&self) -> &RootVolume {
        &self.volume
    }

    /// Makes lookups refuse `name` in this directory as not found, matched
    /// without regard to case unless `case_sensitive`, and in a directory
    /// [`Dir::open_dir`] opens when it is this one.
    pub(crate) fn reserve(self, name: &'static str, case_sensitive: bool) -> Self {
        Self {
            reserved: Some((name, case_sensitive)),
            ..self
        }
    }

    /// True if lookups refuse `name` in this directory.
    fn reserves(&self, name: &OsStr) -> bool {
        self.reserved.is_some_and(|(reserved, case_sensitive)| {
            name.to_str()
                .is_some_and(|name| is_hidden(name, reserved, case_sensitive))
        })
    }

    /// This directory, held: open without delete sharing, so it is not
    /// renamed or removed while the result is open. Lookups from the result
    /// hold nothing more at their start. Fails as not found where the
    /// directory is no longer under the name it was opened by on an SMB
    /// share.
    pub(crate) fn pin(&self) -> io::Result<Dir> {
        let file = if self.held {
            self.file.try_clone()?
        } else {
            reopen_checked(&self.file, HOLD_ACCESS, HOLD_SHARE, WALK_OPTIONS)?
        };
        Ok(Self {
            file,
            held: true,
            reserved: self.reserved,
            volume: Arc::clone(&self.volume),
        })
    }

    /// Metadata of this directory.
    pub(crate) fn dir_metadata(&self) -> io::Result<Metadata> {
        Metadata::from_file(&self.file)
    }

    /// Metadata of what `path` names, a link there followed.
    pub(crate) fn metadata(&self, path: impl AsRef<Path>) -> io::Result<Metadata> {
        self.stat(path.as_ref(), true)
    }

    /// Metadata of what `path` names, a link there itself.
    pub(crate) fn symlink_metadata(&self, path: impl AsRef<Path>) -> io::Result<Metadata> {
        self.stat(path.as_ref(), false)
    }

    fn stat(&self, path: &Path, follow: bool) -> io::Result<Metadata> {
        let (file, _) = Walk::new(self, path)?.open(
            FILE_READ_ATTRIBUTES,
            FILE_OPEN,
            FILE_SYNCHRONOUS_IO_NONALERT,
            follow,
        )?;
        Metadata::from_file(&file)
    }

    /// Opens what `path` names as `options` say, a link there followed.
    pub(crate) fn open_with(
        &self,
        path: impl AsRef<Path>,
        options: &OpenOptions,
    ) -> io::Result<File> {
        let (file, _) = self.open_file(path.as_ref(), options)?;
        Ok(File(file))
    }

    /// Opens the directory `path` names as `options` say, a link there
    /// followed. The result shares delete access, and lookups from it hold
    /// it for as long as they run.
    pub(crate) fn open_dir(
        &self,
        path: impl AsRef<Path>,
        options: &OpenOptions,
    ) -> io::Result<Dir> {
        let (file, at_start) = self.open_file(path.as_ref(), options)?;
        if !Metadata::from_file(&file)?.is_dir() {
            return Err(io::ErrorKind::NotADirectory.into());
        }
        Ok(Self {
            file,
            held: false,
            reserved: self.reserved.filter(|_| at_start),
            volume: Arc::clone(&self.volume),
        })
    }

    /// Opens what `path` names as `options` say, a link there followed.
    /// Also returns whether it is this directory.
    fn open_file(&self, path: &Path, options: &OpenOptions) -> io::Result<(fs::File, bool)> {
        let access = options.access()?;
        let disposition = options.disposition()?;
        let mut create = FILE_SYNCHRONOUS_IO_NONALERT;
        if options.flags & FILE_FLAG_BACKUP_SEMANTICS == 0 {
            create |= FILE_NON_DIRECTORY_FILE;
        } else if access & GENERIC_READ != 0 {
            create |= FILE_OPEN_FOR_BACKUP_INTENT;
        }
        Walk::new(self, path)?.open(access | FILE_READ_ATTRIBUTES, disposition, create, true)
    }

    /// Makes the directory `path` names. On a remote root it gets the name
    /// asked for, as [`RootVolume::settle`] says.
    pub(crate) fn create_dir(&self, path: impl AsRef<Path>) -> io::Result<()> {
        let mut walk = Walk::new(self, path.as_ref())?;
        let Some(name) = walk.reach_last()? else {
            return Err(io::ErrorKind::AlreadyExists.into());
        };
        let name: Vec<u16> = name.encode_wide().collect();
        let remote = self.volume.remote;
        let access = if remote {
            FILE_LIST_DIRECTORY | DELETE | FILE_READ_ATTRIBUTES
        } else {
            FILE_LIST_DIRECTORY
        };
        let (made, _) = nt_open(
            walk.dir(),
            name.clone(),
            access,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            FILE_CREATE,
            FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT | FILE_OPEN_FOR_BACKUP_INTENT,
        )?;
        if remote {
            let names = EntryNames {
                volume: &self.volume,
                dir: walk.dir_file(),
                requested: &name,
                made: &made,
                deletable: true,
            };
            self.volume.settle(&names, Made::Created, &name, &made)?;
        }
        Ok(())
    }

    /// Opens the plain directory `name` in this directory, made hidden when
    /// it is missing, for listing, without delete sharing. Anything else at
    /// the name, a link to a directory included, fails with
    /// ERROR_DIRECTORY.
    pub(crate) fn hold_dir(&self, name: &str) -> io::Result<fs::File> {
        let (file, _) = nt_create(
            self.file.as_raw_handle(),
            name.encode_utf16().collect(),
            HOLD_ACCESS | FILE_LIST_DIRECTORY,
            HOLD_SHARE,
            FILE_OPEN_IF,
            FILE_DIRECTORY_FILE | WALK_OPTIONS,
            FILE_ATTRIBUTE_HIDDEN,
        )
        .map_err(nt_error)?;
        let (attributes, _) = attribute_tag(&file)?;
        if attributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)
            != FILE_ATTRIBUTE_DIRECTORY
        {
            return Err(io::Error::from_raw_os_error(ERROR_DIRECTORY));
        }
        Ok(file)
    }

    /// Opens the entry `path` names, a link there itself, to delete it: a
    /// directory with `is_dir`, else a file. The directory that holds it
    /// stays held until the result is dropped.
    pub(crate) fn open_removal(
        &self,
        path: impl AsRef<Path>,
        is_dir: bool,
    ) -> io::Result<Removal<'_>> {
        let mut walk = Walk::new(self, path.as_ref())?;
        let name = walk.reach_name()?;
        let (access, kind) = if is_dir {
            (
                DELETE | FILE_READ_ATTRIBUTES | FILE_LIST_DIRECTORY,
                FILE_DIRECTORY_FILE,
            )
        } else {
            (
                DELETE | FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES,
                FILE_NON_DIRECTORY_FILE,
            )
        };
        let (file, _) = nt_open(
            walk.dir(),
            name.clone(),
            access,
            SHARE_ALL,
            FILE_OPEN,
            kind | WALK_OPTIONS,
        )?;
        Ok(Removal {
            walk,
            name,
            file,
            is_dir,
        })
    }

    /// Renames what `from` names, a link there itself, to what `to` names
    /// below `to_dir`, replacing a file there.
    ///
    /// A target the plain rename refuses with ERROR_ACCESS_DENIED, such as
    /// a file open elsewhere, is replaced with POSIX semantics where the
    /// volume has them. A rename refused with STATUS_ACCESS_DENIED, as a
    /// directory rename is while something has an entry below it open, is
    /// tried again for up to [`RENAME_WAIT`]. On a remote root the entry
    /// gets the name asked for, as [`RootVolume::settle`] says.
    pub(crate) fn rename(
        &self,
        from: impl AsRef<Path>,
        to_dir: &Dir,
        to: impl AsRef<Path>,
    ) -> io::Result<()> {
        let mut source = Walk::new(self, from.as_ref())?;
        let from_name = source.reach_name()?;
        let mut target = Walk::new(to_dir, to.as_ref())?;
        let to_name = target.reach_name()?;
        let remote = self.volume.remote;
        let in_place = remote
            && same_name(&from_name, &to_name)
            && (source.dir() == target.dir() || same_file(source.dir_file(), target.dir_file())?);
        #[cfg(test)]
        let _held = match self.volume.before_rename.get() {
            Some(hook) if remote => {
                let to = to.as_ref();
                let parent = to.parent().unwrap_or(Path::new(""));
                hook(parent, &OsString::from_wide(&to_name), in_place)
            }
            _ => None,
        };
        let (file, _) = nt_open(
            source.dir(),
            from_name.clone(),
            DELETE | FILE_READ_ATTRIBUTES,
            SHARE_ALL,
            FILE_OPEN,
            WALK_OPTIONS,
        )?;
        self.volume
            .rename(&file, target.dir(), &to_name, true)
            .map_err(nt_error)?;
        if !remote {
            return Ok(());
        }
        let made = if in_place {
            Made::CaseOnly
        } else {
            Made::Moved
        };
        let names = EntryNames {
            volume: &self.volume,
            dir: target.dir_file(),
            requested: &to_name,
            made: &file,
            deletable: true,
        };
        self.volume.settle(&names, made, &to_name, &file)
    }

    /// The entries of this directory, without `.` and `..`.
    pub(crate) fn entries(&self) -> io::Result<Entries> {
        self.entries_matching(None)
    }

    /// The entries of this directory whose names match the NT wildcard
    /// `pattern`, every entry for `None` or an empty pattern, without `.`
    /// and `..`.
    pub(crate) fn entries_matching(&self, pattern: Option<&str>) -> io::Result<Entries> {
        Ok(Entries::new(
            reopen(&self.file, FILE_LIST_DIRECTORY)?,
            pattern.unwrap_or("").encode_utf16().collect(),
        ))
    }
}

impl AsHandle for Dir {
    fn as_handle(&self) -> BorrowedHandle<'_> {
        self.file.as_handle()
    }
}

/// An entry [`Dir::open_removal`] opened to delete it, with DELETE access,
/// sharing all access.
pub(crate) struct Removal<'a> {
    /// The lookup that reached it, which holds the directory it is in.
    walk: Walk<'a>,
    /// Its name in that directory.
    name: Vec<u16>,
    file: fs::File,
    is_dir: bool,
}

impl Removal<'_> {
    /// Deletes the entry with POSIX semantics: its name goes at once, while
    /// other handles of it stay open, a read-only file included. A volume
    /// without them refuses as [`refuses_posix`](crate::host::refuses_posix)
    /// tells.
    pub(crate) fn delete_posix(&self) -> Result<(), NTSTATUS> {
        delete_posix(&self.file, !self.is_dir)
    }

    /// Marks the entry to be deleted when its last handle closes, as
    /// [`delete_on_close`] does.
    pub(crate) fn delete_on_close(&self) -> Result<(), NTSTATUS> {
        delete_on_close(&self.file)
    }

    /// Moves the entry to `name` in the directory `dir` is open on, unless
    /// that name is taken.
    pub(crate) fn move_to(&self, dir: &fs::File, name: &[u16]) -> Result<(), NTSTATUS> {
        set_name(
            &self.file,
            dir.as_raw_handle(),
            name,
            FileRenameInformation,
            0,
        )
    }

    /// True if the directory has entries other than `.` and `..`.
    pub(crate) fn has_entries(&self) -> io::Result<bool> {
        Ok(entries_of(&self.file)?.next().transpose()?.is_some())
    }

    /// The entry's name as the file system stores it, which may differ in
    /// case from the name it was opened by.
    pub(crate) fn stored_name(&self) -> io::Result<Vec<u16>> {
        self.walk
            .start
            .volume
            .stored_name(&self.file, self.walk.dir_file(), &self.name)
    }

    /// Moves the entry back to `name` in the directory that held it, unless
    /// that name is taken.
    pub(crate) fn move_back(&self, name: &[u16]) -> Result<(), NTSTATUS> {
        set_name(&self.file, self.walk.dir(), name, FileRenameInformation, 0)
    }
}

/// The entries of the directory `dir` is open on, with FILE_LIST_DIRECTORY
/// access, read through `dir` itself, without `.` and `..`.
pub(crate) fn entries_of(dir: &fs::File) -> io::Result<Entries> {
    Ok(Entries::new(dir.try_clone()?, Vec::new()))
}

/// A file [`Dir::open_with`] opened.
pub(crate) struct File(fs::File);

impl File {
    pub(crate) fn into_std(self) -> fs::File {
        self.0
    }
}

impl std::ops::Deref for File {
    type Target = fs::File;

    fn deref(&self) -> &fs::File {
        &self.0
    }
}

/// How [`Dir::open_with`] opens a file.
#[derive(Default)]
pub(crate) struct OpenOptions {
    read: bool,
    write: bool,
    create_new: bool,
    flags: u32,
    access: Option<u32>,
}

impl OpenOptions {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Asks for read access.
    pub(crate) fn read(&mut self, read: bool) -> &mut Self {
        self.read = read;
        self
    }

    /// Asks for write access.
    pub(crate) fn write(&mut self, write: bool) -> &mut Self {
        self.write = write;
        self
    }

    /// Makes a new file, and fails if the name exists. Needs write access.
    pub(crate) fn create_new(&mut self, create_new: bool) -> &mut Self {
        self.create_new = create_new;
        self
    }

    /// Sets `FILE_FLAG_*` flags: with `FILE_FLAG_BACKUP_SEMANTICS`, the
    /// open reaches directories too.
    pub(crate) fn custom_flags(&mut self, flags: u32) -> &mut Self {
        self.flags = flags;
        self
    }

    /// Asks for the access mask `access` in place of the one read and
    /// write ask for.
    pub(crate) fn access_mode(&mut self, access: u32) -> &mut Self {
        self.access = Some(access);
        self
    }

    fn access(&self) -> io::Result<u32> {
        match (self.access, self.read, self.write) {
            (Some(access), ..) => Ok(access),
            (None, true, false) => Ok(GENERIC_READ),
            (None, false, true) => Ok(GENERIC_WRITE),
            (None, true, true) => Ok(GENERIC_READ | GENERIC_WRITE),
            (None, false, false) => Err(io::Error::from_raw_os_error(ERROR_INVALID_PARAMETER)),
        }
    }

    fn disposition(&self) -> io::Result<u32> {
        match (self.create_new, self.write) {
            (false, _) => Ok(FILE_OPEN),
            (true, true) => Ok(FILE_CREATE),
            (true, false) => Err(io::Error::from_raw_os_error(ERROR_INVALID_PARAMETER)),
        }
    }
}

// ---------------------------------------------------------------------------
// Metadata
// ---------------------------------------------------------------------------

/// What a file is, as its attributes and reparse tag tell.
#[derive(Clone, Copy)]
pub(crate) struct FileType {
    attributes: u32,
    reparse_tag: u32,
}

impl FileType {
    /// True for a directory that is not a link.
    pub(crate) fn is_dir(&self) -> bool {
        !self.is_symlink() && self.attributes & FILE_ATTRIBUTE_DIRECTORY != 0
    }

    /// True for a symlink, a junction or another link to a name.
    pub(crate) fn is_symlink(&self) -> bool {
        links(self.attributes, self.reparse_tag)
    }
}

/// A time of a file, as [`Metadata`] reports it.
pub(crate) struct SystemTime(std::time::SystemTime);

impl SystemTime {
    pub(crate) fn into_std(self) -> std::time::SystemTime {
        self.0
    }
}

/// The permissions of a file.
pub(crate) struct Permissions {
    readonly: bool,
}

impl Permissions {
    /// True for a file with the read-only attribute.
    pub(crate) fn readonly(&self) -> bool {
        self.readonly
    }
}

/// Metadata of a file or directory. The volume serial number, file index
/// and link count are those of an open handle, and missing from the
/// metadata of a listing.
pub(crate) struct Metadata {
    attributes: u32,
    reparse_tag: u32,
    len: u64,
    created: u64,
    accessed: u64,
    written: u64,
    volume_serial_number: Option<u32>,
    file_index: Option<u64>,
    number_of_links: Option<u32>,
}

impl Metadata {
    /// Metadata of the file or directory `file` is open on.
    pub(crate) fn from_file(file: &fs::File) -> io::Result<Self> {
        let mut info = BY_HANDLE_FILE_INFORMATION::default();
        // SAFETY: `info` is a live local of the size the call fills, and the
        // handle is open for the call.
        let ok = unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut info) };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        let reparse_tag = if info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            attribute_tag(file)?.1
        } else {
            0
        };
        let ticks = |t: windows_sys::Win32::Foundation::FILETIME| {
            (u64::from(t.dwHighDateTime) << 32) | u64::from(t.dwLowDateTime)
        };
        Ok(Self {
            attributes: info.dwFileAttributes,
            reparse_tag,
            len: (u64::from(info.nFileSizeHigh) << 32) | u64::from(info.nFileSizeLow),
            created: ticks(info.ftCreationTime),
            accessed: ticks(info.ftLastAccessTime),
            written: ticks(info.ftLastWriteTime),
            volume_serial_number: Some(info.dwVolumeSerialNumber),
            file_index: Some(
                (u64::from(info.nFileIndexHigh) << 32) | u64::from(info.nFileIndexLow),
            ),
            number_of_links: Some(info.nNumberOfLinks),
        })
    }

    pub(crate) fn file_type(&self) -> FileType {
        FileType {
            attributes: self.attributes,
            reparse_tag: self.reparse_tag,
        }
    }

    /// True for a directory that is not a link.
    pub(crate) fn is_dir(&self) -> bool {
        self.file_type().is_dir()
    }

    /// The size of the file's data.
    pub(crate) fn len(&self) -> u64 {
        self.len
    }

    pub(crate) fn permissions(&self) -> Permissions {
        Permissions {
            readonly: self.attributes & FILE_ATTRIBUTE_READONLY != 0,
        }
    }

    pub(crate) fn modified(&self) -> io::Result<SystemTime> {
        time(self.written)
    }

    pub(crate) fn accessed(&self) -> io::Result<SystemTime> {
        time(self.accessed)
    }

    pub(crate) fn created(&self) -> io::Result<SystemTime> {
        time(self.created)
    }

    /// The `FILE_ATTRIBUTE_*` bits of the file.
    pub(crate) fn file_attributes(&self) -> u32 {
        self.attributes
    }

    pub(crate) fn volume_serial_number(&self) -> Option<u32> {
        self.volume_serial_number
    }

    pub(crate) fn file_index(&self) -> Option<u64> {
        self.file_index
    }

    pub(crate) fn number_of_links(&self) -> Option<u32> {
        self.number_of_links
    }
}

/// The time of the FILETIME `ft`.
fn time(ft: u64) -> io::Result<SystemTime> {
    filetime_to_system_time(ft)
        .map(SystemTime)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "a time out of range"))
}

// ---------------------------------------------------------------------------
// Listings
// ---------------------------------------------------------------------------

/// An entry of a directory listing.
pub(crate) struct DirEntry {
    name: OsString,
    attributes: u32,
    /// The size of the entry's extended attributes, or its reparse tag
    /// when it is a reparse point.
    ea_size: u32,
    len: u64,
    created: u64,
    accessed: u64,
    written: u64,
}

impl DirEntry {
    pub(crate) fn file_name(&self) -> OsString {
        self.name.clone()
    }

    /// What the entry is, a link itself.
    pub(crate) fn file_type(&self) -> io::Result<FileType> {
        Ok(FileType {
            attributes: self.attributes,
            reparse_tag: self.reparse_tag(),
        })
    }

    /// Metadata of the entry as the listing reports it, a link itself.
    pub(crate) fn metadata(&self) -> io::Result<Metadata> {
        Ok(Metadata {
            attributes: self.attributes,
            reparse_tag: self.reparse_tag(),
            len: self.len,
            created: self.created,
            accessed: self.accessed,
            written: self.written,
            volume_serial_number: None,
            file_index: None,
            number_of_links: None,
        })
    }

    /// The size of the entry's extended attributes as the listing reports
    /// it, `None` for a reparse point, whose listing carries its reparse
    /// tag there.
    pub(crate) fn ea_size(&self) -> Option<u32> {
        (self.attributes & FILE_ATTRIBUTE_REPARSE_POINT == 0).then_some(self.ea_size)
    }

    fn reparse_tag(&self) -> u32 {
        if self.attributes & FILE_ATTRIBUTE_REPARSE_POINT == 0 {
            0
        } else {
            self.ea_size
        }
    }
}

/// How far a listing has read.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Listing {
    /// No call has been made.
    Unstarted,
    /// Calls have read entries.
    Reading,
    /// The listing reached its end or failed.
    Finished,
}

/// The entries of a directory, read from a handle of its own.
pub(crate) struct Entries {
    handle: fs::File,
    /// The NT wildcard the names match, every name when empty.
    filter: Vec<u16>,
    buf: Vec<u64>,
    /// The entries the last call read.
    listed: Vec<u8>,
    /// Where the next entry in `listed` starts.
    at: Option<usize>,
    state: Listing,
}

impl Entries {
    /// The entries read from `handle`, whose names match the NT wildcard
    /// `filter` in UTF-16, every entry for an empty one.
    fn new(handle: fs::File, filter: Vec<u16>) -> Self {
        Self {
            handle,
            filter,
            buf: aligned(LISTING),
            listed: Vec::new(),
            at: None,
            state: Listing::Unstarted,
        }
    }

    /// Reads the next entries into `listed`; false at the end.
    fn fill(&mut self) -> io::Result<bool> {
        let bytes =
            u16::try_from(self.filter.len() * 2).map_err(|_| io::ErrorKind::InvalidFilename)?;
        let filter = UNICODE_STRING {
            Length: bytes,
            MaximumLength: bytes,
            Buffer: self.filter.as_mut_ptr(),
        };
        let mut status_block = IO_STATUS_BLOCK::default();
        let first = self.state == Listing::Unstarted;
        // SAFETY: `buf` is a live buffer of `LISTING` bytes, aligned to 8
        // as a `u64` buffer is; `status_block` and `filter`, whose buffer
        // is `self.filter` of `bytes` bytes, are live for the call, which
        // is synchronous.
        let status = unsafe {
            NtQueryDirectoryFile(
                self.handle.as_raw_handle(),
                std::ptr::null_mut(),
                None,
                std::ptr::null(),
                &mut status_block,
                self.buf.as_mut_ptr().cast(),
                LISTING as u32,
                FileFullDirectoryInformation,
                false,
                if first && bytes != 0 {
                    &filter
                } else {
                    std::ptr::null()
                },
                first,
            )
        };
        self.state = Listing::Reading;
        match status {
            STATUS_NO_MORE_FILES | STATUS_NO_SUCH_FILE => Ok(false),
            s if s < 0 => Err(nt_error(s)),
            _ if status_block.Information == 0 => Ok(false),
            _ => {
                self.listed = bytes_of(&self.buf, status_block.Information.min(LISTING));
                self.at = Some(0);
                Ok(true)
            }
        }
    }

    /// The entry at `at` in `listed`, and where the one after it starts.
    fn entry_at(&self, at: usize) -> Option<(DirEntry, Option<usize>)> {
        let listed = &self.listed;
        let field = |offset: usize| u32_at(listed, at.checked_add(offset)?);
        let quad = |offset: usize| u64_at(listed, at.checked_add(offset)?);
        let next = field(0)? as usize;
        let name_at = at.checked_add(DIR_NAME)?;
        let name_len = field(DIR_NAME_LENGTH)? as usize;
        let name = listed.get(name_at..name_at.checked_add(name_len)?)?;
        let units = utf16le_to_units(name)?;
        let entry = DirEntry {
            name: OsString::from_wide(&units),
            attributes: field(DIR_ATTRIBUTES)?,
            ea_size: field(DIR_EA_SIZE)?,
            len: quad(DIR_END_OF_FILE)?,
            created: quad(DIR_CREATION_TIME)?,
            accessed: quad(DIR_LAST_ACCESS_TIME)?,
            written: quad(DIR_LAST_WRITE_TIME)?,
        };
        let after = if next == 0 {
            None
        } else {
            at.checked_add(next)
        };
        Some((entry, after))
    }
}

impl Iterator for Entries {
    type Item = io::Result<DirEntry>;

    fn next(&mut self) -> Option<io::Result<DirEntry>> {
        loop {
            if let Some(at) = self.at {
                let parsed = self.entry_at(at);
                self.at = parsed.as_ref().and_then(|(_, after)| *after);
                match parsed {
                    Some((entry, _)) if entry.name != "." && entry.name != ".." => {
                        return Some(Ok(entry));
                    }
                    _ => continue,
                }
            }
            if self.state == Listing::Finished {
                return None;
            }
            match self.fill() {
                Ok(true) => {}
                Ok(false) => {
                    self.state = Listing::Finished;
                    return None;
                }
                Err(e) => {
                    self.state = Listing::Finished;
                    return Some(Err(e));
                }
            }
        }
    }
}

#[cfg(test)]
pub(super) mod tests;
