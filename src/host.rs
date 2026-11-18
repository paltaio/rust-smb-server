//! Host file system calls the local and S3 backends share.

#[cfg(windows)]
use std::ffi::c_void;
#[cfg(windows)]
use std::fs::File;
#[cfg(windows)]
use std::io;
#[cfg(windows)]
use std::os::windows::io::{AsHandle, AsRawHandle as _};

#[cfg(windows)]
use windows_sys::Wdk::Storage::FileSystem::{FileDispositionInformationEx, NtSetInformationFile};
#[cfg(windows)]
use windows_sys::Win32::Foundation::{NTSTATUS, RtlNtStatusToDosError};
#[cfg(windows)]
use windows_sys::Win32::Storage::FileSystem::{
    FILE_DISPOSITION_FLAG_DELETE, FILE_DISPOSITION_FLAG_IGNORE_READONLY_ATTRIBUTE,
    FILE_DISPOSITION_FLAG_POSIX_SEMANTICS, FILE_DISPOSITION_INFO_EX,
};
#[cfg(windows)]
use windows_sys::Win32::System::IO::{DeviceIoControl, IO_STATUS_BLOCK};
#[cfg(windows)]
use windows_sys::Win32::System::Ioctl::{FILE_SET_SPARSE_BUFFER, FSCTL_SET_SPARSE};

#[cfg(any(unix, windows))]
use crate::backend::VolumeInfo;

/// Longest name `SmbPath` accepts, in UTF-16 code units.
const MAX_NAME_LENGTH: u32 = 255;

#[cfg(windows)]
pub(crate) const ERROR_INVALID_FUNCTION: i32 = 1;
#[cfg(windows)]
pub(crate) const ERROR_NOT_SUPPORTED: i32 = 50;
#[cfg(windows)]
pub(crate) const ERROR_INVALID_PARAMETER: i32 = 87;

/// The Win32 error code an NTSTATUS stands for.
#[cfg(windows)]
pub(crate) fn dos_error(status: NTSTATUS) -> i32 {
    // SAFETY: a pure conversion of a status code.
    unsafe { RtlNtStatusToDosError(status) as i32 }
}

/// The error an NTSTATUS stands for.
#[cfg(windows)]
pub(crate) fn nt_error(status: NTSTATUS) -> io::Error {
    io::Error::from_raw_os_error(dos_error(status))
}

/// True if `status` is how a volume refuses a delete with POSIX semantics:
/// ERROR_INVALID_PARAMETER, ERROR_NOT_SUPPORTED or ERROR_INVALID_FUNCTION.
#[cfg(windows)]
pub(crate) fn refuses_posix(status: NTSTATUS) -> bool {
    matches!(
        dos_error(status),
        ERROR_INVALID_PARAMETER | ERROR_NOT_SUPPORTED | ERROR_INVALID_FUNCTION
    )
}

/// Deletes the file or directory `file` is open on, with DELETE access,
/// with POSIX semantics: its name goes at once, while other handles of it
/// stay open. With `ignore_readonly` a read-only file goes too. A volume
/// without POSIX deletes, such as an SMB share, refuses as
/// [`refuses_posix`] tells.
#[cfg(windows)]
pub(crate) fn delete_posix(file: &File, ignore_readonly: bool) -> Result<(), NTSTATUS> {
    let mut flags = FILE_DISPOSITION_FLAG_DELETE | FILE_DISPOSITION_FLAG_POSIX_SEMANTICS;
    if ignore_readonly {
        flags |= FILE_DISPOSITION_FLAG_IGNORE_READONLY_ATTRIBUTE;
    }
    let info = FILE_DISPOSITION_INFO_EX { Flags: flags };
    let mut status_block = IO_STATUS_BLOCK::default();
    // SAFETY: `info` is a live FILE_DISPOSITION_INFO_EX of the size passed,
    // the layout of FileDispositionInformationEx, and the handle stays open
    // for the call.
    let status = unsafe {
        NtSetInformationFile(
            file.as_raw_handle(),
            &mut status_block,
            (&raw const info).cast(),
            size_of::<FILE_DISPOSITION_INFO_EX>() as u32,
            FileDispositionInformationEx,
        )
    };
    if status < 0 { Err(status) } else { Ok(()) }
}

/// The volume `st` describes, in units of its own block size. `fsid` is the
/// filesystem id the serial number is made from.
#[cfg(unix)]
pub(crate) fn volume_info(st: &rustix::fs::StatVfs, fsid: u64) -> VolumeInfo {
    // f_blocks, f_bfree and f_bavail count f_frsize units.
    let unit = [st.f_frsize, st.f_bsize]
        .into_iter()
        .find(|&u| u > 0)
        .unwrap_or(512);
    let max_name_length = u32::try_from(st.f_namemax)
        .ok()
        .filter(|&n| n > 0)
        .map_or(MAX_NAME_LENGTH, |n| n.min(MAX_NAME_LENGTH));
    VolumeInfo {
        total_allocation_units: st.f_blocks,
        caller_available_allocation_units: st.f_bavail,
        actual_available_allocation_units: st.f_bfree,
        sectors_per_allocation_unit: 1,
        bytes_per_sector: u32::try_from(unit).unwrap_or(u32::MAX),
        serial_number: (fsid ^ (fsid >> 32)) as u32,
        label: None,
        max_name_length,
    }
}

/// Size and identity of the volume `file` is open on.
#[cfg(windows)]
pub(crate) fn volume_info_of(file: &impl AsHandle) -> io::Result<VolumeInfo> {
    use windows_sys::Wdk::Storage::FileSystem::{
        FileFsFullSizeInformation, NtQueryVolumeInformationFile,
    };
    use windows_sys::Win32::Storage::FileSystem::GetVolumeInformationByHandleW;
    use windows_sys::Win32::System::IO::IO_STATUS_BLOCK;

    /// FILE_FS_FULL_SIZE_INFORMATION (MS-FSCC 2.5.4).
    #[repr(C)]
    #[derive(Default)]
    struct FullSize {
        total: i64,
        caller_available: i64,
        actual_available: i64,
        sectors_per_unit: u32,
        bytes_per_sector: u32,
    }

    let handle = file.as_handle().as_raw_handle();
    let mut serial = 0u32;
    let mut max_component = 0u32;
    // SAFETY: `handle` stays open while `file` is borrowed, and every non-null
    // pointer refers to a live local.
    let ok = unsafe {
        GetVolumeInformationByHandleW(
            handle,
            std::ptr::null_mut(),
            0,
            &mut serial,
            &mut max_component,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            0,
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }

    let mut size = FullSize::default();
    // SAFETY: IO_STATUS_BLOCK is plain data, valid when zeroed.
    let mut iosb: IO_STATUS_BLOCK = unsafe { std::mem::zeroed() };
    // SAFETY: as above; `size` matches the layout of the requested class.
    let status = unsafe {
        NtQueryVolumeInformationFile(
            handle,
            &mut iosb,
            (&raw mut size).cast(),
            size_of::<FullSize>() as u32,
            FileFsFullSizeInformation,
        )
    };
    if status < 0 {
        return Err(io::Error::other(format!(
            "NtQueryVolumeInformationFile failed with {status:#010x}"
        )));
    }

    Ok(VolumeInfo {
        total_allocation_units: u64::try_from(size.total).unwrap_or(0),
        caller_available_allocation_units: u64::try_from(size.caller_available).unwrap_or(0),
        actual_available_allocation_units: u64::try_from(size.actual_available).unwrap_or(0),
        sectors_per_allocation_unit: size.sectors_per_unit,
        bytes_per_sector: size.bytes_per_sector,
        serial_number: serial,
        label: None,
        max_name_length: max_component.clamp(1, MAX_NAME_LENGTH),
    })
}

/// Sets or clears the sparse attribute of `file`.
#[cfg(windows)]
pub(crate) fn set_sparse(file: &File, sparse: bool) -> io::Result<()> {
    control(
        file,
        FSCTL_SET_SPARSE,
        &FILE_SET_SPARSE_BUFFER { SetSparse: sparse },
    )
}

/// Sends the control code `code` with `input` to the file `file` is open on.
#[cfg(windows)]
pub(crate) fn control<T>(file: &File, code: u32, input: &T) -> io::Result<()> {
    let mut returned = 0u32;
    // SAFETY: the handle stays open for the call, `input` is a live value of
    // the size passed, `returned` is a live local, and there is no output
    // buffer and no OVERLAPPED, as the handle is synchronous.
    let ok = unsafe {
        DeviceIoControl(
            file.as_raw_handle(),
            code,
            std::ptr::from_ref(input).cast::<c_void>(),
            size_of::<T>() as u32,
            std::ptr::null_mut(),
            0,
            &mut returned,
            std::ptr::null_mut(),
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}
