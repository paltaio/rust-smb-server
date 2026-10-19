//! Host queries about the volume and directory behind a share: size, free
//! space, serial number and the case rule of name lookups.

use std::io;

use cap_std::fs::Dir;

use crate::backend::VolumeInfo;

/// Longest name `SmbPath` accepts, in UTF-16 code units.
const MAX_NAME_LENGTH: u32 = 255;

/// Size and identity of the volume holding `dir`. `root_dev` is the host
/// device of `dir`, used for the serial number where the host reports no
/// filesystem id.
#[cfg(unix)]
pub(super) fn volume_info(dir: &Dir, root_dev: Option<u64>) -> io::Result<VolumeInfo> {
    let st = rustix::fs::fstatvfs(dir)?;
    // f_blocks, f_bfree and f_bavail count f_frsize units.
    let unit = [st.f_frsize, st.f_bsize]
        .into_iter()
        .find(|&u| u > 0)
        .unwrap_or(512);
    let id = if st.f_fsid != 0 {
        st.f_fsid
    } else {
        root_dev.unwrap_or(0)
    };
    let max_name_length = u32::try_from(st.f_namemax)
        .ok()
        .filter(|&n| n > 0)
        .map_or(MAX_NAME_LENGTH, |n| n.min(MAX_NAME_LENGTH));
    Ok(VolumeInfo {
        total_allocation_units: st.f_blocks,
        caller_available_allocation_units: st.f_bavail,
        actual_available_allocation_units: st.f_bfree,
        sectors_per_allocation_unit: 1,
        bytes_per_sector: u32::try_from(unit).unwrap_or(u32::MAX),
        serial_number: (id ^ (id >> 32)) as u32,
        label: None,
        max_name_length,
    })
}

/// Size and identity of the volume holding `dir`.
#[cfg(windows)]
pub(super) fn volume_info(dir: &Dir, _root_dev: Option<u64>) -> io::Result<VolumeInfo> {
    use std::os::windows::io::{AsHandle as _, AsRawHandle as _};
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

    let handle = dir.as_handle().as_raw_handle();
    let mut serial = 0u32;
    let mut max_component = 0u32;
    // SAFETY: `handle` stays open while `dir` is borrowed, and every non-null
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

/// Whether names in `dir` are looked up case-sensitively. On Linux, FAT
/// and exFAT volumes and directories with the casefold flag are
/// case-insensitive.
#[cfg(target_os = "linux")]
pub(super) fn is_case_sensitive(dir: &Dir) -> bool {
    const MSDOS_SUPER_MAGIC: i128 = 0x4d44;
    const EXFAT_SUPER_MAGIC: i128 = 0x2011_BAB0;
    const FS_CASEFOLD_FL: u32 = 0x4000_0000;

    if let Ok(st) = rustix::fs::fstatfs(dir)
        && matches!(i128::from(st.f_type), MSDOS_SUPER_MAGIC | EXFAT_SUPER_MAGIC)
    {
        return false;
    }
    // The flags ioctl needs a descriptor opened for reading.
    match dir.open(".") {
        Ok(file) => rustix::fs::ioctl_getflags(&file)
            .map_or(true, |flags| flags.bits() & FS_CASEFOLD_FL == 0),
        Err(_) => true,
    }
}

/// Whether names in `dir` are looked up case-sensitively, as the volume
/// reports it.
#[cfg(target_os = "macos")]
pub(super) fn is_case_sensitive(dir: &Dir) -> bool {
    use std::os::fd::AsRawFd as _;
    // SAFETY: fpathconf only reads the descriptor, which `dir` keeps open.
    unsafe { libc::fpathconf(dir.as_raw_fd(), libc::_PC_CASE_SENSITIVE) == 1 }
}

/// Whether names in `dir` are looked up case-sensitively: only in
/// directories with the per-directory case-sensitive flag.
#[cfg(windows)]
pub(super) fn is_case_sensitive(dir: &Dir) -> bool {
    use std::os::windows::io::{AsHandle as _, AsRawHandle as _};
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_CASE_SENSITIVE_INFO, FileCaseSensitiveInfo, GetFileInformationByHandleEx,
    };
    const FILE_CS_FLAG_CASE_SENSITIVE_DIR: u32 = 0x1;

    let mut info = FILE_CASE_SENSITIVE_INFO::default();
    // SAFETY: the handle stays open while `dir` is borrowed, and `info` is a
    // live local of the size passed.
    let ok = unsafe {
        GetFileInformationByHandleEx(
            dir.as_handle().as_raw_handle(),
            FileCaseSensitiveInfo,
            (&raw mut info).cast(),
            size_of::<FILE_CASE_SENSITIVE_INFO>() as u32,
        )
    };
    ok != 0 && info.Flags & FILE_CS_FLAG_CASE_SENSITIVE_DIR != 0
}

/// Whether names in `dir` are looked up case-sensitively.
#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
pub(super) fn is_case_sensitive(_dir: &Dir) -> bool {
    true
}
