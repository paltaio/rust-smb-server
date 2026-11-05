//! Extended attributes of [`LocalFsBackend`](super::LocalFsBackend) on
//! Windows.
//!
//! The extended attributes of a file or directory are its NTFS extended
//! attributes, read with `NtQueryEaFile` and written with `NtSetEaFile`
//! through a second handle of the file, opened relative to the one cap-std
//! opened inside the share. NTFS keeps names in uppercase, compares them
//! without regard to case and applies a set as a whole or not at all.

use std::collections::HashMap;
use std::fs::File;
use std::io;
use std::os::windows::io::{AsRawHandle as _, FromRawHandle as _};

use cap_std::fs::Dir;
use windows_sys::Wdk::Foundation::OBJECT_ATTRIBUTES;
use windows_sys::Wdk::Storage::FileSystem::{
    FILE_OPEN, FILE_OPEN_REPARSE_POINT, FILE_SYNCHRONOUS_IO_NONALERT, FileEaInformation,
    FileFullDirectoryInformation, NtCreateFile, NtQueryDirectoryFile, NtQueryEaFile,
    NtQueryInformationFile, NtSetEaFile,
};
use windows_sys::Win32::Foundation::{HANDLE, NTSTATUS, RtlNtStatusToDosError, UNICODE_STRING};
use windows_sys::Win32::Storage::FileSystem::{
    FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_REPARSE_POINT, FILE_LIST_DIRECTORY, FILE_READ_ATTRIBUTES,
    FILE_READ_EA, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_WRITE_EA,
    GetVolumeInformationByHandleW, SYNCHRONIZE,
};
use windows_sys::Win32::System::IO::IO_STATUS_BLOCK;

use crate::ea::{self, Ea};
use crate::error::SmbError;

/// The volume stores extended attributes (MS-FSCC 2.5.1).
const FILE_SUPPORTS_EXTENDED_ATTRIBUTES: u32 = 0x0080_0000;

const STATUS_BUFFER_OVERFLOW: NTSTATUS = 0x8000_0005_u32 as NTSTATUS;
const STATUS_NO_EAS_ON_FILE: NTSTATUS = 0xC000_0052_u32 as NTSTATUS;
const STATUS_EA_TOO_LARGE: NTSTATUS = 0xC000_0050_u32 as NTSTATUS;
const STATUS_EAS_NOT_SUPPORTED: NTSTATUS = 0xC000_004F_u32 as NTSTATUS;
const STATUS_INVALID_EA_NAME: NTSTATUS = 0x8000_0013_u32 as NTSTATUS;
const STATUS_NO_MORE_FILES: NTSTATUS = 0x8000_0006_u32 as NTSTATUS;
const STATUS_NO_SUCH_FILE: NTSTATUS = 0xC000_000F_u32 as NTSTATUS;

/// Bytes one call of a listing reads.
const LISTING: usize = 64 << 10;

/// Most bytes a listing of a file's attributes reads.
const MAX_LIST: usize = 1 << 20;

/// Offsets in a FILE_FULL_DIR_INFORMATION entry.
const DIR_ATTRIBUTES: usize = 56;
const DIR_NAME_LENGTH: usize = 60;
const DIR_EA_SIZE: usize = 64;
const DIR_NAME: usize = 68;

/// True if the volume of `root` stores extended attributes.
pub(super) fn supported(root: &Dir) -> bool {
    use std::os::windows::io::AsHandle as _;
    let mut flags = 0u32;
    // SAFETY: the handle is open for the call and `flags` is a live local;
    // every other argument is a null pointer, with a size of 0 where one
    // goes with it, which the call takes as nothing to fill.
    let ok = unsafe {
        GetVolumeInformationByHandleW(
            root.as_handle().as_raw_handle() as HANDLE,
            std::ptr::null_mut(),
            0,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut flags,
            std::ptr::null_mut(),
            0,
        )
    };
    ok != 0 && flags & FILE_SUPPORTS_EXTENDED_ATTRIBUTES != 0
}

/// A failed NTSTATUS as an error. The EA statuses stay distinct, so
/// [`to_smb`] can tell them apart.
fn nt_error(status: NTSTATUS) -> io::Error {
    match status {
        STATUS_EA_TOO_LARGE | STATUS_EAS_NOT_SUPPORTED | STATUS_INVALID_EA_NAME => {
            io::Error::other(NtStatus(status))
        }
        _ => {
            // SAFETY: a pure conversion of a status code.
            let code = unsafe { RtlNtStatusToDosError(status) };
            io::Error::from_raw_os_error(code as i32)
        }
    }
}

/// An NTSTATUS the Win32 error codes have no single code for.
#[derive(Debug)]
struct NtStatus(NTSTATUS);

impl std::fmt::Display for NtStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "NTSTATUS {:#010x}", self.0 as u32)
    }
}

impl std::error::Error for NtStatus {}

/// The error a set answers for `e`.
fn to_smb(e: io::Error) -> SmbError {
    match e
        .get_ref()
        .and_then(|inner| inner.downcast_ref::<NtStatus>())
    {
        Some(NtStatus(STATUS_EA_TOO_LARGE)) => SmbError::EaTooLarge,
        Some(NtStatus(STATUS_INVALID_EA_NAME)) => SmbError::EaNameInvalid,
        Some(_) => SmbError::NotSupported,
        None => super::local::io_to_smb(e),
    }
}

/// A second handle of the file or directory `file` is open on, with
/// `access`.
pub(super) fn reopen(file: &File, access: u32) -> io::Result<File> {
    let empty = UNICODE_STRING {
        Length: 0,
        MaximumLength: 0,
        Buffer: std::ptr::null_mut(),
    };
    let attributes = OBJECT_ATTRIBUTES {
        Length: std::mem::size_of::<OBJECT_ATTRIBUTES>() as u32,
        RootDirectory: file.as_raw_handle() as HANDLE,
        ObjectName: &empty,
        Attributes: 0,
        SecurityDescriptor: std::ptr::null(),
        SecurityQualityOfService: std::ptr::null(),
    };
    let mut handle: HANDLE = std::ptr::null_mut();
    let mut status_block = IO_STATUS_BLOCK::default();
    // SAFETY: `attributes` is a live local naming the live local `empty`,
    // and its root is the open handle `file` holds; the call writes only
    // `handle` and `status_block`.
    let status = unsafe {
        NtCreateFile(
            &mut handle,
            access | SYNCHRONIZE,
            &attributes,
            &mut status_block,
            std::ptr::null(),
            FILE_ATTRIBUTE_NORMAL,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            FILE_OPEN,
            FILE_SYNCHRONOUS_IO_NONALERT | FILE_OPEN_REPARSE_POINT,
            std::ptr::null(),
            0,
        )
    };
    if status < 0 {
        return Err(nt_error(status));
    }
    // SAFETY: the call succeeded, so `handle` is an open handle that
    // nothing else owns.
    Ok(unsafe { File::from_raw_handle(handle as _) })
}

/// A buffer of `len` bytes aligned to 8, as the calls that fill or read
/// FILE_FULL_EA_INFORMATION and FILE_FULL_DIR_INFORMATION entries need.
fn aligned(len: usize) -> Vec<u64> {
    vec![0; len.div_ceil(8)]
}

/// The first `len` bytes of `words`.
fn bytes_of(words: &[u64], len: usize) -> Vec<u8> {
    let mut out: Vec<u8> = words.iter().flat_map(|w| w.to_ne_bytes()).collect();
    out.truncate(len);
    out
}

/// The FILE_FULL_EA_INFORMATION list of every attribute of `file`.
fn query(file: &File) -> io::Result<Vec<u8>> {
    let handle = reopen(file, FILE_READ_EA)?;
    let mut len = 1 << 17;
    loop {
        let mut buf = aligned(len);
        let mut status_block = IO_STATUS_BLOCK::default();
        // SAFETY: `buf` is a live buffer of at least `len` bytes, aligned
        // to 8 as a `u64` buffer is, and `status_block` a live local; no
        // list or index is passed.
        let status = unsafe {
            NtQueryEaFile(
                handle.as_raw_handle() as HANDLE,
                &mut status_block,
                buf.as_mut_ptr().cast(),
                len as u32,
                false,
                std::ptr::null(),
                0,
                std::ptr::null(),
                true,
            )
        };
        match status {
            STATUS_NO_EAS_ON_FILE => return Ok(Vec::new()),
            STATUS_BUFFER_OVERFLOW if len < MAX_LIST => len *= 2,
            s if s < 0 => return Err(nt_error(s)),
            _ => return Ok(bytes_of(&buf, status_block.Information.min(len))),
        }
    }
}

/// The entries of a FILE_FULL_EA_INFORMATION list from NTFS that clients
/// can be sent; the rest are left out.
fn parse(buf: &[u8]) -> Vec<Ea> {
    let mut out = Vec::new();
    let mut at = 0usize;
    while let Some(header) = buf.get(at..at + 8) {
        let next = u32::from_le_bytes(header[0..4].try_into().expect("four bytes")) as usize;
        let name_len = usize::from(header[5]);
        let value_len = usize::from(u16::from_le_bytes([header[6], header[7]]));
        let name_at = at + 8;
        let value_at = name_at + name_len + 1;
        let (Some(name), Some(value)) = (
            buf.get(name_at..name_at + name_len),
            buf.get(value_at..value_at + value_len),
        ) else {
            break;
        };
        let name = std::str::from_utf8(name)
            .ok()
            .filter(|n| ea::valid_name(n.as_bytes()));
        if let Some(name) = name
            && !value.is_empty()
        {
            let mut ea = Ea::new(name, value.to_vec());
            ea.needed = header[4] & ea::FILE_NEED_EA != 0;
            out.push(ea);
        }
        if next == 0 {
            break;
        }
        at += next;
    }
    out
}

/// The extended attributes of the file `file` is open on.
pub(super) fn list(file: &File) -> io::Result<Vec<Ea>> {
    Ok(parse(&query(file)?))
}

/// [`FileInfo::ea_size`](crate::FileInfo::ea_size) of the file `file` is
/// open on, also through a handle of one of its named streams: the size
/// NTFS reports, which counts its attributes that way.
pub(super) fn size(file: &File) -> io::Result<u32> {
    let mut info = 0u32;
    let mut status_block = IO_STATUS_BLOCK::default();
    // SAFETY: `info` is a live local of the size passed, the layout of
    // FILE_EA_INFORMATION.
    let status = unsafe {
        NtQueryInformationFile(
            file.as_raw_handle() as HANDLE,
            &mut status_block,
            (&raw mut info).cast(),
            4,
            FileEaInformation,
        )
    };
    if status < 0 {
        return Err(nt_error(status));
    }
    Ok(info)
}

/// Sets, replaces or, with an empty value, removes each of `eas` on the
/// file `file` is open on, all or none.
pub(super) fn set(file: &File, eas: &[Ea]) -> Result<(), SmbError> {
    let handle = reopen(file, FILE_WRITE_EA).map_err(to_smb)?;
    let list = ea::encode_full_list(eas);
    let mut buf = aligned(list.len());
    for (word, chunk) in buf.iter_mut().zip(list.chunks(8)) {
        let mut bytes = [0; 8];
        bytes[..chunk.len()].copy_from_slice(chunk);
        *word = u64::from_ne_bytes(bytes);
    }
    let mut status_block = IO_STATUS_BLOCK::default();
    // SAFETY: `buf` is a live buffer of at least the length passed,
    // aligned to 8 as a `u64` buffer is, and `status_block` a live local.
    let status = unsafe {
        NtSetEaFile(
            handle.as_raw_handle() as HANDLE,
            &mut status_block,
            buf.as_ptr().cast(),
            list.len() as u32,
        )
    };
    if status < 0 {
        return Err(to_smb(nt_error(status)));
    }
    Ok(())
}

/// The names of the entries of the directory `dir` is open on that match
/// `pattern`, every entry for `None`, that have extended attributes, each
/// with [`FileInfo::ea_size`](crate::FileInfo::ea_size) as NTFS lists it,
/// or `None` for a reparse point, whose listing carries its reparse tag
/// there.
pub(super) fn listing_sizes(
    dir: &Dir,
    pattern: Option<&str>,
) -> io::Result<HashMap<String, Option<u32>>> {
    let dir = super::local::dir_as_file(dir)?;
    let handle = reopen(&dir, FILE_LIST_DIRECTORY)?;
    let mut units: Vec<u16> = pattern.unwrap_or("").encode_utf16().collect();
    let bytes = u16::try_from(units.len() * 2).map_err(|_| io::ErrorKind::InvalidFilename)?;
    let filter = UNICODE_STRING {
        Length: bytes,
        MaximumLength: bytes,
        Buffer: units.as_mut_ptr(),
    };
    let mut out = HashMap::new();
    let mut buf = aligned(LISTING);
    let mut first = true;
    loop {
        let mut status_block = IO_STATUS_BLOCK::default();
        // SAFETY: `buf` is a live buffer of `LISTING` bytes, aligned to 8
        // as a `u64` buffer is; `status_block` and `filter`, whose buffer
        // is `units`, are live locals. The call is synchronous.
        let status = unsafe {
            NtQueryDirectoryFile(
                handle.as_raw_handle() as HANDLE,
                std::ptr::null_mut(),
                None,
                std::ptr::null(),
                &mut status_block,
                buf.as_mut_ptr().cast(),
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
        first = false;
        match status {
            STATUS_NO_MORE_FILES | STATUS_NO_SUCH_FILE => return Ok(out),
            s if s < 0 => return Err(nt_error(s)),
            _ => {}
        }
        let listed = bytes_of(&buf, status_block.Information.min(LISTING));
        let mut at = 0usize;
        while let Some(entry) = listed.get(at..at + DIR_NAME) {
            let field = |off: usize| {
                u32::from_le_bytes(entry[off..off + 4].try_into().expect("four bytes"))
            };
            let next = field(0) as usize;
            let name_len = field(DIR_NAME_LENGTH) as usize;
            let size = match field(DIR_ATTRIBUTES) & FILE_ATTRIBUTE_REPARSE_POINT {
                0 => Some(field(DIR_EA_SIZE)),
                _ => None,
            };
            if size != Some(0)
                && let Some(name) = listed.get(at + DIR_NAME..at + DIR_NAME + name_len)
            {
                let units: Vec<u16> = name
                    .chunks_exact(2)
                    .map(|c| u16::from_le_bytes([c[0], c[1]]))
                    .collect();
                if let Ok(name) = String::from_utf16(&units) {
                    out.insert(name, size);
                }
            }
            if next == 0 {
                break;
            }
            at += next;
        }
    }
}

/// [`FileInfo::ea_size`](crate::FileInfo::ea_size) of the entry `name` of
/// `dir`, opened as a CREATE opens it, following a reparse point inside
/// the share.
pub(super) fn entry_size(dir: &Dir, name: &str) -> io::Result<u32> {
    use cap_primitives::fs::OpenOptionsExt as _;
    const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
    let mut opts = cap_std::fs::OpenOptions::new();
    opts.read(true)
        .access_mode(FILE_READ_ATTRIBUTES)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS);
    size(&dir.open_with(name, &opts)?.into_std())
}
