//! Files of local data in the cache directory.

use std::fs::{File, OpenOptions};
use std::io;
use std::path::Path;

use crate::error::SmbError;

/// Options for a file only the owner may read and write.
pub(super) fn private_options() -> OpenOptions {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        let mut options = OpenOptions::new();
        options.mode(0o600);
        options
    }
    #[cfg(not(unix))]
    {
        OpenOptions::new()
    }
}

/// Makes the data file at `path`, `len` bytes of holes. A file that is there
/// is emptied.
pub(super) fn create(path: &Path, len: u64) -> io::Result<File> {
    let file = private_options()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(path)?;
    mark_sparse(&file);
    if let Err(e) = file.set_len(len) {
        drop(file);
        let _ = std::fs::remove_file(path);
        return Err(e);
    }
    Ok(file)
}

/// Marks `file` sparse where the host needs that for holes: a failure leaves
/// the file as it is, which stores zeros instead of holes.
#[cfg(windows)]
fn mark_sparse(file: &File) {
    if let Err(e) = crate::host::set_sparse(file, true) {
        tracing::debug!(error = %e, "a data file was not made sparse");
    }
}

#[cfg(not(windows))]
fn mark_sparse(_file: &File) {}

pub(super) fn read_at(file: &File, buf: &mut [u8], offset: u64) -> io::Result<usize> {
    #[cfg(unix)]
    {
        std::os::unix::fs::FileExt::read_at(file, buf, offset)
    }
    #[cfg(windows)]
    {
        std::os::windows::fs::FileExt::seek_read(file, buf, offset)
    }
}

fn write_at(file: &File, data: &[u8], offset: u64) -> io::Result<usize> {
    #[cfg(unix)]
    {
        std::os::unix::fs::FileExt::write_at(file, data, offset)
    }
    #[cfg(windows)]
    {
        std::os::windows::fs::FileExt::seek_write(file, data, offset)
    }
}

/// Fills `buf` from `offset`. What lies past the end of the file reads as
/// zeros.
pub(super) fn read_full_at(file: &File, buf: &mut [u8], offset: u64) -> io::Result<()> {
    let mut done = 0;
    while done < buf.len() {
        match read_at(file, &mut buf[done..], offset + done as u64) {
            Ok(0) => break,
            Ok(n) => done += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    buf[done..].fill(0);
    Ok(())
}

/// Writes all of `data` at `offset`.
pub(super) fn write_all_at(file: &File, data: &[u8], offset: u64) -> io::Result<()> {
    let mut done = 0;
    while done < data.len() {
        match write_at(file, &data[done..], offset + done as u64) {
            Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
            Ok(n) => done += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

/// The error a failed disk operation fails a request with.
pub(super) fn disk_error(e: io::Error) -> SmbError {
    match e.kind() {
        io::ErrorKind::StorageFull | io::ErrorKind::FileTooLarge => SmbError::DiskFull,
        io::ErrorKind::QuotaExceeded => SmbError::QuotaExceeded,
        _ => SmbError::Io(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_full_disk_and_a_quota_have_their_own_errors() {
        assert!(matches!(
            disk_error(io::ErrorKind::StorageFull.into()),
            SmbError::DiskFull
        ));
        assert!(matches!(
            disk_error(io::ErrorKind::FileTooLarge.into()),
            SmbError::DiskFull
        ));
        assert!(matches!(
            disk_error(io::ErrorKind::QuotaExceeded.into()),
            SmbError::QuotaExceeded
        ));
        assert!(matches!(disk_error(io::Error::other("x")), SmbError::Io(_)));
        assert!(matches!(
            disk_error(io::ErrorKind::PermissionDenied.into()),
            SmbError::Io(_)
        ));
    }

    #[test]
    fn a_data_file_has_its_length_and_reads_holes_as_zeros() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("data");
        let file = create(&path, 100).unwrap();
        assert_eq!(file.metadata().unwrap().len(), 100);
        write_all_at(&file, b"abc", 10).unwrap();
        let mut buf = [1u8; 20];
        read_full_at(&file, &mut buf, 5).unwrap();
        assert_eq!(&buf[..5], &[0; 5]);
        assert_eq!(&buf[5..8], b"abc");
        assert_eq!(&buf[8..], &[0; 12]);
        let mut past = [1u8; 8];
        read_full_at(&file, &mut past, 96).unwrap();
        assert_eq!(past, [0; 8]);
        let again = create(&path, 7).unwrap();
        assert_eq!(again.metadata().unwrap().len(), 7);
        let mut buf = [1u8; 4];
        read_full_at(&again, &mut buf, 10).unwrap();
        assert_eq!(buf, [0; 4]);
    }

    #[cfg(unix)]
    #[test]
    fn a_data_file_of_holes_takes_few_blocks() {
        use std::os::unix::fs::MetadataExt as _;
        let dir = tempfile::tempdir().unwrap();
        let file = create(&dir.path().join("data"), 64 << 20).unwrap();
        write_all_at(&file, b"x", 10 << 20).unwrap();
        let meta = file.metadata().unwrap();
        assert_eq!(meta.len(), 64 << 20);
        assert!(meta.blocks() * 512 < 8 << 20, "{} blocks", meta.blocks());
    }

    #[cfg(windows)]
    #[test]
    fn a_data_file_is_marked_sparse() {
        use std::os::windows::fs::MetadataExt as _;
        const FILE_ATTRIBUTE_SPARSE_FILE: u32 = 0x200;
        let dir = tempfile::tempdir().unwrap();
        let file = create(&dir.path().join("data"), 1 << 20).unwrap();
        let attributes = file.metadata().unwrap().file_attributes();
        assert_ne!(attributes & FILE_ATTRIBUTE_SPARSE_FILE, 0);
    }
}
