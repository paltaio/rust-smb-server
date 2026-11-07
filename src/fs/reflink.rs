//! FICLONERANGE between two open files, and the check that the filesystem
//! of a share root clones.

use std::fs::File;
use std::os::fd::AsRawFd as _;
use std::os::unix::fs::FileExt as _;

use cap_std::fs::Dir;
use rustix::fs::{Mode, OFlags};
use rustix::io::Errno;

/// Makes `len` bytes at `dst_offset` of `dst` share their storage with the
/// `len` bytes at `src_offset` of `src` (ioctl_ficlonerange(2)). A `len` of 0
/// clones to the end of `src`.
pub(super) fn clone_range(
    src: &File,
    src_offset: u64,
    dst: &File,
    dst_offset: u64,
    len: u64,
) -> Result<(), Errno> {
    let range = libc::file_clone_range {
        src_fd: i64::from(src.as_raw_fd()),
        src_offset,
        src_length: len,
        dest_offset: dst_offset,
    };
    // SAFETY: FICLONERANGE reads one `file_clone_range` through the pointer,
    // which is to a live local, and uses the descriptor in it only during the
    // call, while `src` keeps it open.
    let rc = unsafe { libc::ioctl(dst.as_raw_fd(), libc::FICLONERANGE, &raw const range) };
    if rc == 0 {
        return Ok(());
    }
    let error = std::io::Error::last_os_error();
    Err(Errno::from_io_error(&error).unwrap_or(Errno::IO))
}

/// Whether the filesystem of `dir` clones ranges between its files.
pub(super) fn supported(dir: &Dir) -> bool {
    let temporary = || {
        rustix::fs::openat(
            dir,
            c".",
            OFlags::TMPFILE | OFlags::RDWR | OFlags::CLOEXEC,
            Mode::RUSR | Mode::WUSR,
        )
        .map(File::from)
    };
    let (Ok(src), Ok(dst)) = (temporary(), temporary()) else {
        return false;
    };
    src.write_all_at(&[0; 1 << 16], 0).is_ok()
        && src.sync_data().is_ok()
        && clone_range(&src, 0, &dst, 0, 0).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use cap_std::ambient_authority;

    fn open(dir: &std::path::Path) -> Dir {
        Dir::open_ambient_dir(dir, ambient_authority()).unwrap()
    }

    #[test]
    fn the_check_leaves_nothing_in_the_directory() {
        let td = tempfile::tempdir().unwrap();
        supported(&open(td.path()));
        assert_eq!(std::fs::read_dir(td.path()).unwrap().count(), 0);
    }
}
