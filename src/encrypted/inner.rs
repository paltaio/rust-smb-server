//! Whole reads and writes on the handles of the inner backend, which may
//! move fewer bytes than asked for.

use std::io;

use crate::backend::Handle;
use crate::error::{SmbError, SmbResult};

/// Closes a handle that was only read from. A close that fails changes
/// nothing there, so its error is dropped.
pub(super) async fn close_after_reading(handle: Box<dyn Handle>) {
    let _ = handle.close().await;
}

/// Reads exactly `len` bytes at `offset`, asking again for what a short read
/// left. A read that returns nothing before `len` bytes are in fails with
/// `Io`.
pub(super) async fn read_full(handle: &dyn Handle, offset: u64, len: usize) -> SmbResult<Vec<u8>> {
    let mut out = Vec::with_capacity(len);
    while out.len() < len {
        let missing = len - out.len();
        let at = offset
            .checked_add(out.len() as u64)
            .ok_or(SmbError::InvalidParameter)?;
        let got = handle
            .read(at, u32::try_from(missing).unwrap_or(u32::MAX))
            .await?;
        if got.is_empty() {
            return Err(SmbError::Io(io::ErrorKind::UnexpectedEof.into()));
        }
        out.extend_from_slice(&got[..got.len().min(missing)]);
    }
    Ok(out)
}

/// Writes all of `data` at `offset`, continuing after a short write. A write
/// that takes nothing fails with `Io`.
pub(super) async fn write_full(handle: &dyn Handle, offset: u64, data: &[u8]) -> SmbResult<()> {
    let mut done = 0;
    while done < data.len() {
        let at = offset
            .checked_add(done as u64)
            .ok_or(SmbError::InvalidParameter)?;
        let taken = handle.write(at, &data[done..]).await?;
        if taken == 0 {
            return Err(SmbError::Io(io::ErrorKind::WriteZero.into()));
        }
        done += usize::try_from(taken)
            .unwrap_or(usize::MAX)
            .min(data.len() - done);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::{OpenIntent, ShareBackend};
    use crate::tests::faulty::Faulty;
    use crate::tests::memfs::MemFsBackend;
    use crate::tests::util::{opts, path};

    async fn file(files: &MemFsBackend, name: &str) -> Box<dyn Handle> {
        let faulty = Faulty::new(files.clone());
        faulty.short_reads(Some(4));
        faulty.short_writes(Some(3));
        faulty
            .open(&path(name), opts(OpenIntent::OpenOrCreate))
            .await
            .unwrap()
            .0
    }

    #[tokio::test]
    async fn reads_continue_after_short_reads() {
        let files = MemFsBackend::new().with_file("f", b"0123456789");
        let handle = file(&files, "f").await;
        assert_eq!(read_full(&*handle, 2, 7).await.unwrap(), b"2345678");
        assert_eq!(read_full(&*handle, 0, 0).await.unwrap(), b"");
    }

    #[tokio::test]
    async fn a_read_past_the_end_fails() {
        let files = MemFsBackend::new().with_file("f", b"0123");
        let handle = file(&files, "f").await;
        let Err(SmbError::Io(error)) = read_full(&*handle, 2, 5).await else {
            panic!("a short file is not read in full");
        };
        assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
    }

    #[tokio::test]
    async fn writes_continue_after_short_writes() {
        let files = MemFsBackend::new();
        let handle = file(&files, "f").await;
        write_full(&*handle, 0, b"0123456789").await.unwrap();
        write_full(&*handle, 4, b"abc").await.unwrap();
        write_full(&*handle, 0, b"").await.unwrap();
        assert_eq!(files.contents("f").unwrap(), b"0123abc789");
    }

    #[tokio::test]
    async fn a_write_that_takes_nothing_fails() {
        let files = MemFsBackend::new();
        let faulty = Faulty::new(files.clone());
        faulty.short_writes(Some(0));
        let (handle, _) = faulty
            .open(&path("f"), opts(OpenIntent::Create))
            .await
            .unwrap();
        let Err(SmbError::Io(error)) = write_full(&*handle, 0, b"x").await else {
            panic!("a write of nothing is an error");
        };
        assert_eq!(error.kind(), io::ErrorKind::WriteZero);
        assert_eq!(files.contents("f").unwrap(), b"");
    }
}
