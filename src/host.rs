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
use windows_sys::Win32::System::IO::DeviceIoControl;
#[cfg(windows)]
use windows_sys::Win32::System::Ioctl::{FILE_SET_SPARSE_BUFFER, FSCTL_SET_SPARSE};

#[cfg(any(unix, windows))]
use crate::backend::VolumeInfo;

/// Longest name `SmbPath` accepts, in UTF-16 code units.
const MAX_NAME_LENGTH: u32 = 255;

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
