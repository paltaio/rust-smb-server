//! FSCTL_DUPLICATE_EXTENTS_TO_FILE between two open files of
//! [`LocalFsBackend`](super::LocalFsBackend) on Windows, and the check that
//! the volume of a share root clones.
//!
//! ReFS clones ranges whose offsets and length are multiples of the cluster
//! size, under 4 GiB to a call; a range goes in pieces of at most 1 GiB.

use std::ffi::c_void;
use std::fs::File;
use std::io;
use std::os::windows::fs::MetadataExt as _;
use std::os::windows::io::AsRawHandle as _;

use cap_std::fs::{Dir, Metadata};
use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_SPARSE_FILE;
use windows_sys::Win32::System::IO::DeviceIoControl;
use windows_sys::Win32::System::Ioctl::{
    DUPLICATE_EXTENTS_DATA, FILE_SET_SPARSE_BUFFER, FSCTL_DUPLICATE_EXTENTS_TO_FILE,
    FSCTL_SET_SPARSE,
};
use windows_sys::Win32::System::SystemServices::FILE_SUPPORTS_BLOCK_REFCOUNTING;

use super::local::{file_key, io_to_smb};
use super::volume::{volume_info_of, volume_of};
use super::windows_streams::{
    ERROR_INVALID_FUNCTION, ERROR_INVALID_PARAMETER, ERROR_NOT_SUPPORTED, refused,
};
use crate::error::{SmbError, SmbResult};

/// Most bytes of one call.
const PIECE: u64 = 1 << 30;

/// True if the volume of `root` reports block cloning (MS-FSCC 2.5.1).
pub(super) fn supported(root: &Dir) -> bool {
    volume_of(root).is_some_and(|(flags, _)| flags & FILE_SUPPORTS_BLOCK_REFCOUNTING != 0)
}

/// Makes `len` bytes at `dst_offset` of `dst` share their storage with the
/// `len` bytes at `src_offset` of `src`.
///
/// A sparse source makes the target sparse first, as ReFS refuses to clone a
/// sparse file into one that is not. A call that fails with
/// [`SmbError::NotSupported`], [`SmbError::InvalidParameter`] or
/// [`SmbError::NotSameDevice`] leaves the data of `dst` as it was; any other
/// error may follow a clone of part of the range.
pub(super) fn clone_range(
    src: &File,
    src_offset: u64,
    dst: &File,
    dst_offset: u64,
    len: u64,
) -> SmbResult<()> {
    if !same_volume(src, dst).map_err(clone_error)? {
        return Err(SmbError::NotSameDevice);
    }
    let cluster = volume_info_of(dst).map_err(io_to_smb)?.allocation_unit();
    let made_sparse =
        is_sparse(src).map_err(clone_error)? && !is_sparse(dst).map_err(clone_error)?;
    if made_sparse {
        set_sparse(dst, true).map_err(clone_error)?;
    }
    let cloned = clone_pieces(src, src_offset, dst, dst_offset, len, cluster);
    if made_sparse
        && cloned
            .as_ref()
            .is_err_and(SmbError::leaves_target_unchanged)
    {
        // Best effort: the call fails with the error of the clone either way.
        let _ = set_sparse(dst, false);
    }
    cloned
}

/// Clones the range in pieces of at most [`PIECE`] bytes.
fn clone_pieces(
    src: &File,
    src_offset: u64,
    dst: &File,
    dst_offset: u64,
    len: u64,
    cluster: u64,
) -> SmbResult<()> {
    let piece = PIECE - PIECE % cluster;
    let mut done = 0;
    while done < len {
        let count = (len - done).min(piece);
        let from = src_offset.saturating_add(done);
        let to = dst_offset.saturating_add(done);
        clone_piece(src, from, dst, to, count, cluster)
            .map_err(clone_error)
            .map_err(|error| if done > 0 { after_pieces(error) } else { error })?;
        done += count;
    }
    Ok(())
}

/// The error of a piece that follows cloned ones: an error that promises an
/// untouched target becomes an I/O error.
fn after_pieces(error: SmbError) -> SmbError {
    if error.leaves_target_unchanged() {
        SmbError::Io(io::Error::other(error))
    } else {
        error
    }
}

/// Clones `count` bytes, a multiple of `cluster` unless the range ends both
/// files.
fn clone_piece(
    src: &File,
    src_offset: u64,
    dst: &File,
    dst_offset: u64,
    count: u64,
    cluster: u64,
) -> io::Result<()> {
    let signed = |n: u64| i64::try_from(n).map_err(|_| refused());
    let mut byte_count = count;
    if !count.is_multiple_of(cluster) {
        // ReFS refuses a length that is not a cluster multiple, even one that
        // reaches the end of the file. Rounded up to the cluster it clones to
        // the end, so the ends are read again here: a file that grew since the
        // caller checked would be cloned past the range.
        let ends = |file: &File, offset: u64| -> io::Result<bool> {
            Ok(file.metadata()?.len() == offset.saturating_add(count))
        };
        if !ends(src, src_offset)? || !ends(dst, dst_offset)? {
            return Err(refused());
        }
        byte_count = count.next_multiple_of(cluster);
    }
    let data = DUPLICATE_EXTENTS_DATA {
        FileHandle: src.as_raw_handle(),
        SourceFileOffset: signed(src_offset)?,
        TargetFileOffset: signed(dst_offset)?,
        ByteCount: signed(byte_count)?,
    };
    control(dst, FSCTL_DUPLICATE_EXTENTS_TO_FILE, &data)
}

/// True if `a` and `b` are on one volume, or the volumes cannot be compared.
fn same_volume(a: &File, b: &File) -> io::Result<bool> {
    let volume = |file| Metadata::from_file(file).map(|md| file_key(&md).map(|(volume, _)| volume));
    Ok(match (volume(a)?, volume(b)?) {
        (Some(a), Some(b)) => a == b,
        _ => true,
    })
}

/// True if `file` has the sparse attribute.
fn is_sparse(file: &File) -> io::Result<bool> {
    Ok(file.metadata()?.file_attributes() & FILE_ATTRIBUTE_SPARSE_FILE != 0)
}

/// Sets or clears the sparse attribute of `file`.
fn set_sparse(file: &File, sparse: bool) -> io::Result<()> {
    control(
        file,
        FSCTL_SET_SPARSE,
        &FILE_SET_SPARSE_BUFFER { SetSparse: sparse },
    )
}

/// Sends the control code `code` with `input` to the file `file` is open on.
fn control<T>(file: &File, code: u32, input: &T) -> io::Result<()> {
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

/// The error of a clone call: a volume or file that cannot clone is not
/// supported, and ranges the volume refuses are invalid. Other errors go
/// through `io_to_smb`.
fn clone_error(e: io::Error) -> SmbError {
    match e.raw_os_error() {
        Some(ERROR_INVALID_FUNCTION | ERROR_NOT_SUPPORTED) => SmbError::NotSupported,
        Some(ERROR_INVALID_PARAMETER) => SmbError::InvalidParameter,
        _ => io_to_smb(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::windows::fs::FileExt as _;

    use cap_std::ambient_authority;
    use tempfile::TempDir;

    use crate::tests::data::pattern;

    const ERROR_NOT_SAME_DEVICE: i32 = 17;

    /// A new directory on a volume that clones, and the volume's cluster
    /// size. `None`, after a note on stderr, when the temporary directory is
    /// on a volume that does not.
    fn cloning_dir() -> Option<(TempDir, u64)> {
        let td = tempfile::tempdir().unwrap();
        let dir = Dir::open_ambient_dir(td.path(), ambient_authority()).unwrap();
        if !supported(&dir) {
            eprintln!("skipping: {} does not clone", td.path().display());
            return None;
        }
        let cluster = volume_info_of(&dir).unwrap().allocation_unit();
        Some((td, cluster))
    }

    fn open(dir: &TempDir, name: &str, content: &[u8]) -> File {
        std::fs::write(dir.path().join(name), content).unwrap();
        File::options()
            .read(true)
            .write(true)
            .open(dir.path().join(name))
            .unwrap()
    }

    fn read_at(file: &File, offset: u64, len: usize) -> Vec<u8> {
        let mut buf = vec![0; len];
        file.seek_read(&mut buf, offset).unwrap();
        buf
    }

    #[test]
    fn a_sparse_source_makes_the_target_sparse() {
        let Some((td, cluster)) = cloning_dir() else {
            return;
        };
        let size = 2 * cluster as usize;
        let src = open(&td, "s", &pattern(size, 0));
        set_sparse(&src, true).unwrap();
        let dst = open(&td, "t", &vec![0; size]);
        assert!(!is_sparse(&dst).unwrap());
        clone_range(&src, 0, &dst, 0, size as u64).unwrap();
        assert!(is_sparse(&dst).unwrap());
        assert_eq!(
            std::fs::read(td.path().join("t")).unwrap(),
            pattern(size, 0)
        );
    }

    #[test]
    fn a_range_longer_than_a_piece_is_cloned_whole() {
        let Some((td, cluster)) = cloning_dir() else {
            return;
        };
        let size = PIECE + cluster + 1000;
        let (src, dst) = (open(&td, "s", &[]), open(&td, "t", &[]));
        for file in [&src, &dst] {
            set_sparse(file, true).unwrap();
            file.set_len(size).unwrap();
        }
        let marks = [
            (0, cluster as usize),
            (PIECE - cluster, cluster as usize),
            (PIECE + cluster, 1000),
        ];
        for (at, len) in marks {
            src.seek_write(&pattern(len, 0), at).unwrap();
        }
        clone_range(&src, 0, &dst, 0, size).unwrap();
        for (at, len) in marks {
            assert_eq!(read_at(&dst, at, len), pattern(len, 0), "{at}");
        }
        assert_eq!(read_at(&dst, cluster, 16), [0; 16]);
        assert_eq!(dst.metadata().unwrap().len(), size);
    }

    #[test]
    fn a_length_short_of_a_cluster_is_cloned_only_when_it_ends_both_files() {
        let Some((td, cluster)) = cloning_dir() else {
            return;
        };
        let size = 3 * cluster as usize + 1000;
        let src = open(&td, "s", &pattern(size, 0));
        let longer = open(&td, "longer", &vec![0; 4 * cluster as usize]);
        let cloned = clone_range(&src, 0, &longer, 0, size as u64);
        assert!(
            matches!(cloned, Err(SmbError::InvalidParameter)),
            "{cloned:?}"
        );
        assert_eq!(
            std::fs::read(td.path().join("longer")).unwrap(),
            vec![0; 4 * cluster as usize]
        );
        let same = open(&td, "same", &vec![0; size]);
        clone_range(&src, 0, &same, 0, size as u64).unwrap();
        assert_eq!(
            std::fs::read(td.path().join("same")).unwrap(),
            pattern(size, 0)
        );
    }

    #[test]
    fn a_refused_clone_leaves_the_target_without_the_sparse_attribute() {
        let Some((td, cluster)) = cloning_dir() else {
            return;
        };
        let size = 2 * cluster as usize;
        let src = open(&td, "s", &pattern(size, 0));
        set_sparse(&src, true).unwrap();
        let dst = open(&td, "t", &vec![0; 8 * cluster as usize]);
        let cloned = clone_range(&src, 0, &dst, 0, 4 * cluster);
        assert!(matches!(cloned, Err(SmbError::NotSupported)), "{cloned:?}");
        assert!(!is_sparse(&dst).unwrap());
        assert_eq!(
            std::fs::read(td.path().join("t")).unwrap(),
            vec![0; 8 * cluster as usize]
        );
    }

    #[test]
    fn a_source_on_another_volume_is_refused_before_the_target_changes() {
        let Some((td, cluster)) = cloning_dir() else {
            return;
        };
        let exe = std::env::current_exe().unwrap();
        let other = tempfile::tempdir_in(exe.parent().unwrap()).unwrap();
        let size = 2 * cluster as usize;
        let src = open(&other, "s", &pattern(size, 0));
        let dst = open(&td, "t", &vec![0; size]);
        if same_volume(&src, &dst).unwrap() {
            eprintln!("skipping: {} is on one volume", other.path().display());
            return;
        }
        set_sparse(&src, true).unwrap();
        let cloned = clone_range(&src, 0, &dst, 0, size as u64);
        assert!(matches!(cloned, Err(SmbError::NotSameDevice)), "{cloned:?}");
        assert!(!is_sparse(&dst).unwrap());
        assert_eq!(std::fs::read(td.path().join("t")).unwrap(), vec![0; size]);
    }

    #[test]
    fn errors_after_cloned_pieces_do_not_promise_an_untouched_target() {
        for error in [
            SmbError::NotSupported,
            SmbError::InvalidParameter,
            SmbError::NotSameDevice,
        ] {
            assert!(matches!(after_pieces(error), SmbError::Io(_)));
        }
        assert!(matches!(
            after_pieces(SmbError::DiskFull),
            SmbError::DiskFull
        ));
    }

    #[test]
    fn clone_errors_are_told_apart() {
        let error = |code| clone_error(io::Error::from_raw_os_error(code));
        assert!(matches!(
            error(ERROR_INVALID_FUNCTION),
            SmbError::NotSupported
        ));
        assert!(matches!(error(ERROR_NOT_SUPPORTED), SmbError::NotSupported));
        assert!(matches!(
            error(ERROR_INVALID_PARAMETER),
            SmbError::InvalidParameter
        ));
        assert!(matches!(
            error(ERROR_NOT_SAME_DEVICE),
            SmbError::NotSameDevice
        ));
    }
}
