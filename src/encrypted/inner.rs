//! Whole reads and writes on the handles of the inner backend, which may
//! move fewer bytes than asked for.

use std::io;

use super::format::{BlockShift, HEADER_LEN};
use super::names::MAX_SIDE_OBJECT_LEN;
use crate::backend::{Handle, OpenAction, OpenIntent, OpenOptions, ShareBackend};
use crate::error::{SmbError, SmbResult};
use crate::path::SmbPath;

/// Most bytes one inner read or write of stored blocks moves, before it is
/// cut down to whole blocks.
const MAX_CALL: u64 = 4 << 20;

/// Closes a handle that was only read from. A close that fails changes
/// nothing there, so its error is dropped.
pub(super) async fn close_after_reading(handle: Box<dyn Handle>) {
    let _ = handle.close().await;
}

pub(super) fn is_missing(error: &SmbError) -> bool {
    matches!(
        error,
        SmbError::NotFound | SmbError::PathNotFound | SmbError::NotADirectory
    )
}

/// The content of the side object at `path`. `None` when it is missing, a
/// directory, or longer than `MAX_SIDE_OBJECT_LEN`, which is then not read.
pub(super) async fn read_side_object<B: ShareBackend>(
    inner: &B,
    path: &SmbPath,
) -> SmbResult<Option<Vec<u8>>> {
    let opts = OpenOptions {
        non_directory: true,
        ..OpenOptions::default()
    };
    let handle = match inner.open(path, opts).await {
        Ok((handle, _)) => handle,
        Err(error) if is_missing(&error) || matches!(error, SmbError::IsDirectory) => {
            return Ok(None);
        }
        Err(error) => return Err(error),
    };
    let content = side_object_content(handle.as_ref()).await;
    close_after_reading(handle).await;
    content
}

async fn side_object_content(handle: &dyn Handle) -> SmbResult<Option<Vec<u8>>> {
    let info = handle.stat().await?;
    if info.is_directory || info.end_of_file > MAX_SIDE_OBJECT_LEN as u64 {
        return Ok(None);
    }
    let len = usize::try_from(info.end_of_file).expect("a side object is at most 1024 bytes");
    read_full(handle, 0, len).await.map(Some)
}

/// Makes the side object at `path` hold `content`. A new object gets the
/// content. An object that is there already is read and left alone when it
/// holds the same bytes, and rewritten otherwise.
pub(super) async fn write_side_object<B: ShareBackend>(
    inner: &B,
    path: &SmbPath,
    content: &[u8],
) -> SmbResult<()> {
    let opts = OpenOptions {
        write: true,
        non_directory: true,
        intent: OpenIntent::OpenOrCreate,
        ..OpenOptions::default()
    };
    let (handle, action) = inner.open(path, opts).await?;
    match fill_side_object(handle.as_ref(), action, content).await {
        Ok(true) => handle.close().await,
        Ok(false) => {
            close_after_reading(handle).await;
            Ok(())
        }
        Err(error) => {
            let _ = handle.close().await;
            Err(error)
        }
    }
}

/// Writes `content` to the side object on `handle`. `action` says whether the
/// object is new. Returns false, writing nothing, when the object already
/// held `content`.
async fn fill_side_object(
    handle: &dyn Handle,
    action: OpenAction,
    content: &[u8],
) -> SmbResult<bool> {
    if action != OpenAction::Created {
        let held = handle.stat().await?.end_of_file == content.len() as u64
            && read_full(handle, 0, content.len()).await? == content;
        if held {
            return Ok(false);
        }
        handle.truncate(0).await?;
    }
    write_full(handle, 0, content).await?;
    Ok(true)
}

/// Appends `len` bytes read at `offset` to `out`, asking again for what a
/// short read left. A read that returns nothing before all `len` bytes are
/// in fails with `Io`.
async fn read_append(
    handle: &dyn Handle,
    offset: u64,
    out: &mut Vec<u8>,
    len: usize,
) -> SmbResult<()> {
    let start = out.len();
    while out.len() - start < len {
        let done = out.len() - start;
        let missing = len - done;
        let at = offset
            .checked_add(done as u64)
            .ok_or(SmbError::InvalidParameter)?;
        let got = handle
            .read(at, u32::try_from(missing).unwrap_or(u32::MAX))
            .await?;
        if got.is_empty() {
            return Err(SmbError::Io(io::ErrorKind::UnexpectedEof.into()));
        }
        out.extend_from_slice(&got[..got.len().min(missing)]);
    }
    Ok(())
}

/// Reads exactly `len` bytes at `offset`, asking again for what a short read
/// left. A read that returns nothing before all `len` bytes are in fails with
/// `Io`.
pub(super) async fn read_full(handle: &dyn Handle, offset: u64, len: usize) -> SmbResult<Vec<u8>> {
    let mut out = Vec::with_capacity(len);
    read_append(handle, offset, &mut out, len).await?;
    Ok(out)
}

/// The most stored bytes of one inner call: 4 MiB cut down to whole stored
/// blocks, and at least one block.
fn call_len(shift: BlockShift) -> usize {
    let block = shift.stored_block_size();
    let len = (MAX_CALL / block * block).max(block);
    usize::try_from(len).expect("a call of a few MiB fits in memory")
}

/// Reads `len` stored bytes at `offset`, where a block starts, and the run
/// ends where a block ends. Each inner call asks for whole blocks, at most
/// `call_len`, and so ends on a block boundary. Short reads are continued as
/// in `read_full`.
pub(super) async fn read_blocks(
    handle: &dyn Handle,
    shift: BlockShift,
    offset: u64,
    len: usize,
) -> SmbResult<Vec<u8>> {
    let call = call_len(shift);
    let mut out = Vec::with_capacity(len);
    while out.len() < len {
        let at = offset
            .checked_add(out.len() as u64)
            .ok_or(SmbError::InvalidParameter)?;
        let chunk = (len - out.len()).min(call);
        read_append(handle, at, &mut out, chunk).await?;
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

/// Writes all of `data` at `offset`, in inner calls of at most `call_len`
/// bytes. Every call but the last ends where a stored block ends. Short
/// writes are continued as in `write_full`.
pub(super) async fn write_blocks(
    handle: &dyn Handle,
    shift: BlockShift,
    offset: u64,
    data: &[u8],
) -> SmbResult<()> {
    let call = call_len(shift) as u64;
    let block = shift.stored_block_size();
    let header = HEADER_LEN as u64;
    let mut done = 0;
    while done < data.len() {
        let at = offset
            .checked_add(done as u64)
            .ok_or(SmbError::InvalidParameter)?;
        let reach = at.checked_add(call).ok_or(SmbError::InvalidParameter)?;
        // A call is a block or more, so the last boundary within reach is
        // past `at`.
        let boundary = header + (reach - header) / block * block;
        let take = usize::try_from(boundary - at)
            .unwrap_or(usize::MAX)
            .min(data.len() - done);
        write_full(handle, at, &data[done..done + take]).await?;
        done += take;
    }
    Ok(())
}

/// Checks the inner calls `calls`, as offset and length: they follow each
/// other from `from` to `to`, hold at most `MAX_CALL` bytes, and each ends at
/// `to` or where a stored block of `block` bytes ends. `context` names the
/// case in a failure.
#[cfg(test)]
#[track_caller]
pub(super) fn assert_calls(calls: &[(u64, usize)], block: u64, from: u64, to: u64, context: &str) {
    let mut next = from;
    for &(at, count) in calls {
        assert_eq!(at, next, "{context}: calls follow each other");
        next = at + count as u64;
        assert!(
            count as u64 <= MAX_CALL,
            "{context}: {count} bytes in one call"
        );
        assert!(
            next == to || (next - HEADER_LEN as u64).is_multiple_of(block),
            "{context}: a call ends at {next}, inside a block"
        );
    }
    assert_eq!(next, to, "{context}");
}

#[cfg(test)]
mod tests {
    use super::super::testing::injected;
    use super::*;
    use crate::backend::{OpenIntent, ShareBackend};
    use crate::tests::faulty::Faulty;
    use crate::tests::memfs::MemFsBackend;
    use crate::tests::util::{opts, path};

    #[tokio::test]
    async fn a_side_object_is_read_up_to_1024_bytes_and_no_further() {
        let files = MemFsBackend::new()
            .with_file("exact", &[7; 1024])
            .with_file("over", &[7; 1025])
            .with_dir("dir");
        let faulty = Faulty::new(files.clone());

        let read = read_side_object(&faulty, &path("exact")).await.unwrap();
        assert_eq!(read, Some(vec![7; 1024]));
        assert_eq!(faulty.reads(), [(0, 1024)]);

        assert_eq!(
            read_side_object(&faulty, &path("over")).await.unwrap(),
            None
        );
        assert_eq!(faulty.reads().len(), 1, "an object over 1024 is not read");
        for none in ["dir", "missing", "exact\\below"] {
            let read = read_side_object(&faulty, &path(none)).await.unwrap();
            assert_eq!(read, None, "{none}");
        }

        faulty.fail_open(1, |_, _| true, injected());
        assert!(matches!(
            read_side_object(&faulty, &path("exact")).await,
            Err(SmbError::Io(_))
        ));
        assert_eq!(files.open_handles(), 0);
    }

    #[test]
    fn a_call_holds_whole_blocks_and_at_most_4_mib() {
        for (bits, blocks) in [(13, 510), (16, 63), (20, 3)] {
            let shift = BlockShift::new(bits).unwrap();
            let block = usize::try_from(shift.stored_block_size()).unwrap();
            assert_eq!(call_len(shift), blocks * block, "shift {bits}");
            assert!(call_len(shift) <= 4 << 20);
            assert!(call_len(shift) + block > 4 << 20);
        }
    }

    #[tokio::test]
    async fn blocks_are_read_in_calls_that_end_on_block_boundaries() {
        let shift = BlockShift::new(13).unwrap();
        let data: Vec<u8> = (0..9_000_024u32).map(|i| (i % 251) as u8).collect();
        let files = MemFsBackend::new().with_file("f", &data);
        let faulty = Faulty::new(files);
        let (handle, _) = faulty
            .open(&path("f"), opts(OpenIntent::Open))
            .await
            .unwrap();

        let got = read_blocks(&*handle, shift, 24, 9_000_000).await.unwrap();
        assert_eq!(got, data[24..]);
        assert_eq!(
            faulty.reads(),
            [
                (24, 4_192_200),
                (24 + 4_192_200, 4_192_200),
                (24 + 8_384_400, 615_600)
            ]
        );
        assert!(
            read_blocks(&*handle, shift, 24, 0)
                .await
                .unwrap()
                .is_empty()
        );
        assert_eq!(faulty.reads().len(), 3);
    }

    #[tokio::test]
    async fn short_reads_of_blocks_continue_inside_their_call() {
        let shift = BlockShift::new(13).unwrap();
        let data: Vec<u8> = (0..20_000u32).map(|i| (i % 251) as u8).collect();
        let files = MemFsBackend::new().with_file("f", &data);
        let faulty = Faulty::new(files);
        faulty.short_reads(Some(7_000));
        let (handle, _) = faulty
            .open(&path("f"), opts(OpenIntent::Open))
            .await
            .unwrap();

        let got = read_blocks(&*handle, shift, 24, 19_976).await.unwrap();
        assert_eq!(got, data[24..]);
        assert_eq!(
            faulty.reads(),
            [(24, 19_976), (7_024, 12_976), (14_024, 5_976)]
        );

        faulty.short_reads(Some(0));
        let Err(SmbError::Io(error)) = read_blocks(&*handle, shift, 24, 100).await else {
            panic!("a read that returns nothing fails");
        };
        assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
    }

    #[tokio::test]
    async fn blocks_are_written_in_calls_that_end_on_block_boundaries() {
        let shift = BlockShift::new(13).unwrap();
        let data: Vec<u8> = (0..9_000_024u32).map(|i| (i % 251) as u8).collect();
        let files = MemFsBackend::new();
        let faulty = Faulty::new(files.clone());
        let (handle, _) = faulty
            .open(&path("f"), opts(OpenIntent::Create))
            .await
            .unwrap();

        write_blocks(&*handle, shift, 0, &data).await.unwrap();
        assert_eq!(
            faulty.write_calls(),
            [(0, 4_184_004), (4_184_004, 4_192_200), (8_376_204, 623_820)]
        );
        assert_eq!(files.contents("f").unwrap(), data);

        write_blocks(&*handle, shift, 0, b"").await.unwrap();
        assert_eq!(faulty.write_calls().len(), 3);
    }

    #[tokio::test]
    async fn a_call_of_any_run_ends_on_a_block_boundary_and_holds_at_most_4_mib() {
        for bits in [13, 16, 20] {
            let shift = BlockShift::new(bits).unwrap();
            let block = shift.stored_block_size();
            let len = 9 * (1 << 20) + 17;
            let data = vec![1u8; len];
            let header = HEADER_LEN as u64;
            for offset in [
                0,
                5,
                header,
                header + block - 1,
                header + block,
                header + 3 * block + 9,
            ] {
                let files = MemFsBackend::new();
                let faulty = Faulty::new(files.clone());
                faulty.sink_writes_from(Some(0));
                let (handle, _) = faulty
                    .open(&path("f"), opts(OpenIntent::Create))
                    .await
                    .unwrap();
                write_blocks(&*handle, shift, offset, &data).await.unwrap();

                assert_calls(
                    &faulty.write_calls(),
                    block,
                    offset,
                    offset + len as u64,
                    &format!("shift {bits}, offset {offset}"),
                );
            }
        }
    }

    #[tokio::test]
    async fn short_writes_of_blocks_continue_inside_their_call() {
        let shift = BlockShift::new(13).unwrap();
        let data: Vec<u8> = (0..19_976u32).map(|i| (i % 251) as u8).collect();
        let files = MemFsBackend::new();
        let faulty = Faulty::new(files.clone());
        faulty.short_writes(Some(7_000));
        let (handle, _) = faulty
            .open(&path("f"), opts(OpenIntent::Create))
            .await
            .unwrap();

        write_blocks(&*handle, shift, 24, &data).await.unwrap();
        assert_eq!(
            faulty.write_calls(),
            [(24, 19_976), (7_024, 12_976), (14_024, 5_976)]
        );
        assert_eq!(files.contents("f").unwrap()[24..], data[..]);

        faulty.short_writes(Some(0));
        let Err(SmbError::Io(error)) = write_blocks(&*handle, shift, 24, b"x").await else {
            panic!("a write that takes nothing fails");
        };
        assert_eq!(error.kind(), io::ErrorKind::WriteZero);
    }
}
