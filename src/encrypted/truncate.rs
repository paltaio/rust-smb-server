//! Setting the length of a file. A shorter file ends in a block that is
//! rewritten when the cut falls inside one. A longer file reads zeros past its
//! old end. Whatever the new length, at most one block is read and written.

use bytes::Bytes;
use tokio::sync::RwLock;

use super::change::{Attempt, Change, Normal, OsRandom, Random, Taken};
use super::content::Opened;
use super::handle::EncryptedHandle;
use super::node::{FileMeta, HeaderState};
use super::size::{block_range, stored_size};
use super::write::{Sealed, seal_alone};
use crate::backend::ShareBackend;
use crate::error::{SmbError, SmbResult};

/// A file of `old.logical` bytes, kept in `old.end` stored bytes, that is to
/// have `len` bytes, kept in `target` stored bytes.
#[derive(Clone, Copy)]
struct Resize {
    old: Normal,
    len: u64,
    target: u64,
}

impl<B: ShareBackend> EncryptedHandle<B> {
    /// Sets the length of the file to `len`. Bytes added read as zeros.
    pub(super) async fn truncate_file(&self, file: &RwLock<FileMeta>, len: u64) -> SmbResult<()> {
        self.truncate_with(file, len, &mut OsRandom).await
    }

    async fn truncate_with(
        &self,
        file: &RwLock<FileMeta>,
        len: u64,
        random: &mut dyn Random,
    ) -> SmbResult<()> {
        let target =
            stored_size(self.shared.settings.block_shift, len).ok_or(SmbError::InvalidParameter)?;
        self.change_file(file, Change::Truncate { len, target }, random)
            .await
    }

    /// One try at a truncate to `len` bytes, which take `target` stored
    /// bytes, under the lock of the file. The stored file is normalized
    /// first.
    pub(super) async fn truncate_once(
        &self,
        meta: &mut FileMeta,
        len: u64,
        target: u64,
        random: &mut dyn Random,
    ) -> SmbResult<Attempt> {
        let old = self.normalize().await?;
        if len == 0 {
            if old.logical > 0 {
                self.inner.truncate(0).await?;
            }
            meta.header = HeaderState::Absent;
            return Ok(Attempt::Done);
        }
        if len == old.logical {
            return Ok(Attempt::Done);
        }
        let taken = self.take_header(meta, old.end, random).await?;
        let size = Resize { old, len, target };
        let attempt = if len < old.logical {
            self.shrink(&taken, size, random).await
        } else {
            self.extend(&taken, size, random).await
        };
        let done = matches!(attempt, Ok(Attempt::Done));
        taken.put_back(meta, done);
        attempt
    }

    /// Cuts the file to `size.len` bytes. A new last block that keeps part of
    /// an old one is sealed first, and written after the cut.
    async fn shrink(
        &self,
        taken: &Taken,
        size: Resize,
        random: &mut dyn Random,
    ) -> SmbResult<Attempt> {
        let shift = self.shared.settings.block_shift;
        let kept = size.len & (shift.block_size() - 1);
        if kept == 0 {
            self.inner.truncate(size.target).await?;
            return Ok(Attempt::Done);
        }
        let index = size.len >> shift.get();
        let old = match self.read_block(taken, size.old, index, kept).await? {
            Ok(old) => old,
            Err(attempt) => return Ok(attempt),
        };
        let range = block_range(shift, size.len, index, index).ok_or(SmbError::InvalidParameter)?;
        let bytes = seal_alone(&taken.cipher, index, old, &range, random)?;
        self.inner.truncate(range.offset).await?;
        let block = Sealed::alone(bytes, range.offset, None);
        self.store(&block, range.offset).await?;
        Ok(Attempt::Done)
    }

    /// Makes the file longer, to `size.len` bytes. An empty file gets its new
    /// header. A last block that is partial is padded with zeros to the end of
    /// the block or to the new length. The stored file is then extended to
    /// the new length, and the inner backend reads what it adds as zeros.
    async fn extend(
        &self,
        taken: &Taken,
        size: Resize,
        random: &mut dyn Random,
    ) -> SmbResult<Attempt> {
        let shift = self.shared.settings.block_shift;
        if taken.fresh {
            let header = Sealed::alone(taken.header.as_bytes().to_vec(), 0, None);
            self.store(&header, 0).await?;
            self.grow(size.target, 0).await?;
            return Ok(Attempt::Done);
        }
        let partial = size.old.logical & (shift.block_size() - 1);
        if partial == 0 {
            self.grow(size.target, size.old.end).await?;
            return Ok(Attempt::Done);
        }
        let index = size.old.logical >> shift.get();
        let old = match self.read_block(taken, size.old, index, partial).await? {
            Ok(old) => old,
            Err(attempt) => return Ok(attempt),
        };
        let range = block_range(shift, size.len, index, index).ok_or(SmbError::InvalidParameter)?;
        let bytes = seal_alone(&taken.cipher, index, old, &range, random)?;
        let pad_end = range.offset + range.stored_len;
        let block = Sealed::alone(bytes, range.offset, Some(pad_end));
        self.store(&block, size.old.end).await?;
        if size.target > pad_end {
            self.grow(size.target, pad_end).await?;
        }
        Ok(Attempt::Done)
    }

    /// Reads the first `len` bytes of block `index` of the file in `old`. A
    /// block that does not open gives the attempt that ends the change.
    async fn read_block(
        &self,
        taken: &Taken,
        old: Normal,
        index: u64,
        len: u64,
    ) -> SmbResult<Result<Bytes, Attempt>> {
        let bits = self.shared.settings.block_shift.get();
        let len = u32::try_from(len).expect("a block is at most 1 MiB");
        let read = self
            .read_range(&taken.cipher, old.logical, index << bits, len)
            .await?;
        Ok(match read {
            Opened::Data(bytes) => Ok(bytes),
            Opened::Corrupt(block) => Err(Attempt::Corrupt {
                block,
                used: taken.header.file_id(),
            }),
        })
    }

    /// Extends the stored file to `target` bytes. A failure cuts it back to
    /// `safe_end`, best effort, and returns the error of the extension.
    async fn grow(&self, target: u64, safe_end: u64) -> SmbResult<()> {
        if let Err(error) = self.inner.truncate(target).await {
            let _ = self.inner.truncate(safe_end).await;
            return Err(error);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;
    use std::io;
    use std::sync::Arc;

    use super::super::format::{BlockShift, MAX_STORED_SIZE, OVERHEAD};
    use super::super::header::Header;
    use super::super::node::HeaderKind;
    use super::super::size::logical_size;
    use super::super::testing::{
        B, Counting, Down, H, assert_err, assert_io, assert_no_wait, at, block_reads, drop_at,
        faulty_file, faulty_file_in, gated_file, header_reads, key_schedule, layer_over, new_file,
        nonce_at, open, open_file, other_file_id, read_all, resized, settle, shift, stored,
        stored_file, stored_file_with_id, stored_len, writes_since,
    };
    use super::*;
    use crate::backend::{Handle, OpenAction, OpenIntent};
    use crate::tests::data::{apply, pattern};
    use crate::tests::gated::{Gated, Op};
    use crate::tests::logs::Logs;
    use crate::tests::memfs::MemFsBackend;

    // Inner writes are counted from 1: the first is the marker the layer
    // writes when it is built.

    #[tokio::test]
    async fn a_shrink_keeps_the_data_before_the_cut_and_stores_the_size_of_its_length() {
        for (old_len, cuts) in [
            (
                3 * B + 100,
                vec![
                    1,
                    B - 1,
                    B,
                    B + 1,
                    2 * B - 1,
                    2 * B,
                    3 * B,
                    3 * B + 1,
                    3 * B + 99,
                ],
            ),
            (2 * B, vec![1, B - 1, B, B + 1, 2 * B - 1]),
            (B, vec![1, B - 1]),
        ] {
            for len in cuts {
                let plain = pattern(old_len, 1);
                let (files, faulty, layer) = faulty_file(&stored(&plain)).await;
                let handle = open_file(&layer, "f").await;
                let before = files.contents("f").unwrap();
                let cell = format!("from {old_len} to {len}");

                handle.truncate(len as u64).await.unwrap();

                let block = len / B;
                if len % B == 0 {
                    assert_eq!(faulty.truncate_calls(), [stored_len(len) as u64], "{cell}");
                    assert_eq!(writes_since(&faulty, 1), [], "{cell}");
                    assert_eq!(block_reads(&faulty), [], "{cell}");
                } else {
                    let old_block = (old_len - block * B).min(B);
                    assert_eq!(
                        block_reads(&faulty),
                        [(at(block) as u64, (old_block + OVERHEAD) as u32)],
                        "{cell}"
                    );
                    assert_eq!(faulty.truncate_calls(), [at(block) as u64], "{cell}");
                    assert_eq!(
                        writes_since(&faulty, 1),
                        [(at(block) as u64, len % B + OVERHEAD)],
                        "{cell}"
                    );
                }
                let after = files.contents("f").unwrap();
                assert_eq!(after.len(), stored_len(len), "{cell}");
                assert_eq!(after[..at(block)], before[..at(block)], "{cell}");
                if len % B != 0 {
                    assert_ne!(
                        nonce_at(&after, at(block)),
                        nonce_at(&before, at(block)),
                        "{cell}"
                    );
                }
                assert_eq!(read_all(&handle).await, plain[..len], "{cell}");
                assert_eq!(
                    handle.stat().await.unwrap().end_of_file,
                    len as u64,
                    "{cell}"
                );
            }
        }
    }

    #[tokio::test]
    async fn a_shrink_into_a_hole_seals_the_zeros_that_stay() {
        let len = 3 * B + 10;
        let mut plain = pattern(len, 1);
        let mut bytes = stored(&plain);
        bytes[at(1)..at(2)].fill(0);
        plain[B..2 * B].fill(0);
        let (files, _, layer) = faulty_file(&bytes).await;
        let handle = open_file(&layer, "f").await;

        handle.truncate(B as u64 + 5).await.unwrap();
        assert_eq!(read_all(&handle).await, plain[..B + 5]);
        let after = files.contents("f").unwrap();
        assert_eq!(after.len(), stored_len(B + 5));
        assert!(after[at(1)..].iter().any(|&byte| byte != 0));
    }

    #[tokio::test]
    async fn an_extension_pads_a_partial_last_block_and_leaves_the_rest_to_the_inner_backend() {
        let cases = [
            (1, 2),
            (100, 101),
            (100, B - 1),
            (100, B),
            (100, B + 1),
            (100, 3 * B),
            (B + 100, B + 300),
            (B + 100, 2 * B),
            (B + 100, 2 * B + 1),
            (B + 100, 5 * B + 7),
        ];
        for (old_len, len) in cases {
            let plain = pattern(old_len, 1);
            let (files, faulty, layer) = faulty_file(&stored(&plain)).await;
            let handle = open_file(&layer, "f").await;
            let before = files.contents("f").unwrap();
            let cell = format!("from {old_len} to {len}");

            handle.truncate(len as u64).await.unwrap();

            let block = old_len / B;
            let old_end = before.len();
            let pad_end = at(block) + (len - block * B).min(B) + OVERHEAD;
            assert_eq!(
                block_reads(&faulty),
                [(at(block) as u64, (old_len - block * B + OVERHEAD) as u32)],
                "{cell}"
            );
            assert_eq!(
                writes_since(&faulty, 1),
                [
                    (old_end as u64, pad_end - old_end),
                    (at(block) as u64, old_end - at(block))
                ],
                "{cell}: the part from the old end on first"
            );
            let sparse = len > (block + 1) * B;
            let truncates = if sparse {
                vec![stored_len(len) as u64]
            } else {
                vec![]
            };
            assert_eq!(faulty.truncate_calls(), truncates, "{cell}");

            let after = files.contents("f").unwrap();
            assert_eq!(after.len(), stored_len(len), "{cell}");
            assert_eq!(after[..at(block)], before[..at(block)], "{cell}");
            assert_ne!(
                nonce_at(&after, at(block)),
                nonce_at(&before, at(block)),
                "{cell}"
            );
            assert!(after[pad_end..].iter().all(|&byte| byte == 0), "{cell}");
            assert_eq!(read_all(&handle).await, resized(&plain, len), "{cell}");
            assert_eq!(
                handle.stat().await.unwrap().end_of_file,
                len as u64,
                "{cell}"
            );
        }
    }

    #[tokio::test]
    async fn an_extension_of_a_file_that_ends_in_a_whole_block_is_one_inner_truncate() {
        for (old_len, len) in [(B, B + 1), (B, 3 * B), (2 * B, 4 * B + 5)] {
            let plain = pattern(old_len, 1);
            let (files, faulty, layer) = faulty_file(&stored(&plain)).await;
            let handle = open_file(&layer, "f").await;
            let before = files.contents("f").unwrap();
            let cell = format!("from {old_len} to {len}");

            handle.truncate(len as u64).await.unwrap();

            assert_eq!(faulty.truncate_calls(), [stored_len(len) as u64], "{cell}");
            assert_eq!(writes_since(&faulty, 1), [], "{cell}");
            assert_eq!(block_reads(&faulty), [], "{cell}");
            let after = files.contents("f").unwrap();
            assert_eq!(after[..before.len()], before[..], "{cell}");
            assert!(after[before.len()..].iter().all(|&byte| byte == 0));
            assert_eq!(read_all(&handle).await, resized(&plain, len), "{cell}");
        }
    }

    #[tokio::test]
    async fn an_extension_of_an_empty_file_writes_a_header_and_leaves_every_block_a_hole() {
        for len in [1, B - 1, B, B + 1, 3 * B + 5] {
            let (files, faulty, handle) = new_file().await;

            handle.truncate(len as u64).await.unwrap();

            assert_eq!(writes_since(&faulty, 1), [(0, H)], "to {len}");
            assert_eq!(
                faulty.truncate_calls(),
                [stored_len(len) as u64],
                "to {len}"
            );
            assert_eq!(block_reads(&faulty), [], "to {len}");
            let after = files.contents("f").unwrap();
            assert_eq!(after.len(), stored_len(len), "to {len}");
            assert!(Header::parse(&after[..H], shift()).is_ok(), "to {len}");
            assert!(after[H..].iter().all(|&byte| byte == 0), "to {len}");
            assert_eq!(handle.node().header().await, Some(HeaderKind::Present));
            assert_eq!(read_all(&handle).await, vec![0; len], "to {len}");
            assert_eq!(header_reads(&faulty), 0, "to {len}: the header is not read");
        }
    }

    #[tokio::test]
    async fn an_extension_10_gib_past_the_end_writes_at_most_one_block_whatever_the_file_was() {
        const FAR: u64 = 10 << 30;
        let target = stored_size(shift(), FAR).unwrap();

        // A new file: its header.
        let (_files, faulty, handle) = new_file().await;
        faulty.sink_truncates_from(Some(1 << 30));
        handle.truncate(FAR).await.unwrap();
        assert_eq!(writes_since(&faulty, 1), [(0, H)]);
        assert_eq!(faulty.truncate_calls(), [target]);

        // A partial last block: the block, padded to its end.
        let (_files, faulty, layer) = faulty_file(&stored(&pattern(100, 1))).await;
        let handle = open_file(&layer, "f").await;
        faulty.sink_truncates_from(Some(1 << 30));
        handle.truncate(FAR).await.unwrap();
        let old_end = at(0) + 100 + OVERHEAD;
        assert_eq!(
            writes_since(&faulty, 1),
            [
                (old_end as u64, at(1) - old_end),
                (at(0) as u64, old_end - at(0))
            ]
        );
        assert_eq!(faulty.truncate_calls(), [target]);

        // A whole last block: nothing is written.
        let (_files, faulty, layer) = faulty_file(&stored(&pattern(B, 1))).await;
        let handle = open_file(&layer, "f").await;
        faulty.sink_truncates_from(Some(1 << 30));
        handle.truncate(FAR).await.unwrap();
        assert_eq!(writes_since(&faulty, 1), []);
        assert_eq!(faulty.truncate_calls(), [target]);
    }

    #[tokio::test]
    async fn a_truncate_to_the_size_the_file_has_does_nothing() {
        for len in [1, B - 1, B, B + 1, 3 * B + 100] {
            let (files, faulty, layer) = faulty_file(&stored(&pattern(len, 1))).await;
            let handle = open_file(&layer, "f").await;
            let before = files.contents("f").unwrap();
            handle.truncate(len as u64).await.unwrap();
            assert_eq!(files.contents("f").unwrap(), before, "len {len}");
            assert_eq!(
                (
                    faulty.reads().len(),
                    writes_since(&faulty, 1).len(),
                    faulty.truncates()
                ),
                (0, 0, 0),
                "len {len}"
            );
            assert_eq!(handle.node().header().await, Some(HeaderKind::Unknown));
        }
    }

    #[tokio::test]
    async fn a_truncation_to_zero_is_one_inner_truncate_and_drops_the_header() {
        let (files, faulty, handle) = new_file().await;
        handle.write(0, &pattern(2 * B + 5, 1)).await.unwrap();
        let first_id = files.contents("f").unwrap()[8..H].to_vec();
        let writes = writes_since(&faulty, 1).len();

        handle.truncate(0).await.unwrap();
        assert_eq!(faulty.truncate_calls(), [0]);
        assert_eq!(
            (writes_since(&faulty, 1).len(), block_reads(&faulty)),
            (writes, vec![])
        );
        assert_eq!(files.contents("f"), Some(Vec::new()));
        assert_eq!(handle.node().header().await, Some(HeaderKind::Absent));
        assert!(handle.read(0, 10).await.unwrap().is_empty());
        assert_eq!(handle.stat().await.unwrap().end_of_file, 0);

        handle.write(0, b"abc").await.unwrap();
        assert_ne!(files.contents("f").unwrap()[8..H], first_id[..]);
        assert_eq!(read_all(&handle).await, b"abc");

        handle.truncate(0).await.unwrap();
        // An empty file has nothing to cut.
        handle.truncate(0).await.unwrap();
        assert_eq!(faulty.truncate_calls(), [0, 0]);
        assert_eq!(handle.node().header().await, Some(HeaderKind::Absent));
    }

    #[tokio::test]
    async fn a_truncate_waits_for_every_other_holder_of_the_file_lock() {
        let (_files, _, layer) = faulty_file(&stored(&pattern(100, 1))).await;
        let handle = Arc::new(open_file(&layer, "f").await);
        let reading = handle.node().file().unwrap().read().await;
        let truncate = tokio::spawn({
            let handle = Arc::clone(&handle);
            async move { handle.truncate(10).await }
        });
        settle().await;
        assert!(!truncate.is_finished());
        drop(reading);
        truncate.await.unwrap().unwrap();
        assert_eq!(read_all(&*handle).await, pattern(10, 1));
    }

    /// A file that holds `plain` and two handles of it that have read its
    /// header, behind `Gated`.
    async fn gated_pair(
        plain: &[u8],
    ) -> (
        Gated<MemFsBackend>,
        Arc<EncryptedHandle<Gated<MemFsBackend>>>,
        Arc<EncryptedHandle<Gated<MemFsBackend>>>,
    ) {
        let (_, gated, layer) = gated_file(&stored(plain)).await;
        let a = Arc::new(open_file(&layer, "f").await);
        let b = Arc::new(open_file(&layer, "f").await);
        assert!(Arc::ptr_eq(a.node(), b.node()));
        assert_eq!(a.read(0, 1).await.unwrap().len(), 1);
        (gated, a, b)
    }

    #[tokio::test]
    async fn a_write_racing_a_truncate_waits_for_the_one_that_holds_the_lock() {
        let plain = pattern(3 * B + 100, 1);
        let cut = B + 10;

        // The truncate holds the lock, parked at the read of its block.
        let (gated, a, b) = gated_pair(&plain).await;
        let gate = gated.arm(Op::Read);
        let truncate = tokio::spawn({
            let a = Arc::clone(&a);
            async move { a.truncate(cut as u64).await }
        });
        gate.reached().await;
        let write = tokio::spawn({
            let b = Arc::clone(&b);
            async move { b.write(2 * B as u64, b"xyz").await }
        });
        settle().await;
        assert!(!write.is_finished(), "the write waits for the truncate");
        gate.release();
        truncate.await.unwrap().unwrap();
        assert_eq!(write.await.unwrap().unwrap(), 3);
        let mut model = plain[..cut].to_vec();
        apply(&mut model, 2 * B, b"xyz");
        assert_eq!(read_all(&*a).await, model, "the truncate came first");

        // The write holds the lock, parked at the read of its block.
        let (gated, a, b) = gated_pair(&plain).await;
        let gate = gated.arm(Op::Read);
        let write = tokio::spawn({
            let a = Arc::clone(&a);
            async move { a.write(2 * B as u64 + 1, b"w").await }
        });
        gate.reached().await;
        let truncate = tokio::spawn({
            let b = Arc::clone(&b);
            async move { b.truncate(cut as u64).await }
        });
        settle().await;
        assert!(!truncate.is_finished(), "the truncate waits for the write");
        gate.release();
        assert_eq!(write.await.unwrap().unwrap(), 1);
        truncate.await.unwrap().unwrap();
        assert_eq!(read_all(&*a).await, plain[..cut], "the write came first");
    }

    #[tokio::test]
    async fn a_truncating_open_leaves_the_other_handle_with_an_empty_file_and_a_new_file_id() {
        let files = MemFsBackend::new();
        let layer = layer_over(files.clone()).await;
        let (first, _) = open(&layer, "f", OpenIntent::Create).await;
        first.write(0, &pattern(2 * B + 5, 1)).await.unwrap();
        assert_eq!(first.read(0, 10).await.unwrap().len(), 10);
        let old_id = files.contents("f").unwrap()[8..H].to_vec();
        assert_eq!(first.node().header().await, Some(HeaderKind::Present));

        let (second, action) = open(&layer, "f", OpenIntent::Truncate).await;
        assert_eq!(action, OpenAction::Overwritten);
        assert!(Arc::ptr_eq(first.node(), second.node()));
        assert_eq!(files.contents("f"), Some(Vec::new()));
        assert_eq!(first.node().header().await, Some(HeaderKind::Absent));
        assert!(first.read(0, 100).await.unwrap().is_empty());
        assert_eq!(first.stat().await.unwrap().end_of_file, 0);

        let data = pattern(B, 3);
        assert_eq!(first.write(0, &data).await.unwrap(), B as u32);
        assert_ne!(files.contents("f").unwrap()[8..H], old_id[..]);
        assert_eq!(read_all(&second).await, data);
        assert_eq!(first.node().header().await, Some(HeaderKind::Present));

        let again = layer_over(files.clone()).await;
        assert_eq!(read_all(&open_file(&again, "f").await).await, data);
    }

    #[tokio::test]
    async fn a_shrink_into_a_corrupt_block_fails_and_changes_nothing() {
        let logs = Logs::new();
        let len = 3 * B + 100;
        let plain = pattern(len, 1);
        let mut bytes = stored(&plain);
        bytes[at(1) + 40] ^= 0x80;
        let (files, faulty, layer) = faulty_file(&bytes).await;
        let handle = open_file(&layer, "f").await;

        for cut in [B + 10, B + 1, 2 * B - 1] {
            assert_io(
                handle.truncate(cut as u64).await,
                io::ErrorKind::InvalidData,
            );
        }
        assert_eq!(files.contents("f").unwrap(), bytes);
        assert_eq!((writes_since(&faulty, 1).len(), faulty.truncates()), (0, 0));
        let warnings = logs.warnings();
        assert_eq!(warnings.len(), 3, "{warnings:?}");
        assert!(warnings.iter().all(|line| line.contains("block=1")));
        assert_eq!(
            header_reads(&faulty),
            1 + 3,
            "one load, then one reload for each truncate"
        );

        // A cut at a block edge reads no block. A cut inside a block that
        // opens rewrites it. Both succeed.
        handle.truncate(2 * B as u64).await.unwrap();
        handle.truncate(B as u64 - 5).await.unwrap();
        assert_eq!(read_all(&handle).await, plain[..B - 5]);
    }

    #[tokio::test]
    async fn a_shrink_to_a_block_edge_over_a_corrupt_later_block_succeeds_without_reading_it() {
        let len = 3 * B + 100;
        let plain = pattern(len, 1);
        let mut bytes = stored(&plain);
        bytes[at(2) + 40] ^= 0x80;
        for cut in [B, 2 * B] {
            let (_files, faulty, layer) = faulty_file(&bytes).await;
            let handle = open_file(&layer, "f").await;
            handle.truncate(cut as u64).await.unwrap();
            assert_eq!(block_reads(&faulty), [], "cut {cut}");
            assert_eq!(writes_since(&faulty, 1), [], "cut {cut}");
            assert_eq!(read_all(&handle).await, plain[..cut], "cut {cut}");
        }
    }

    #[tokio::test]
    async fn an_extension_needs_only_the_last_partial_block_to_open() {
        let len = 2 * B + 100;
        let plain = pattern(len, 1);

        let mut bytes = stored(&plain);
        bytes[at(2) + 40] ^= 0x80;
        let (files, faulty, layer) = faulty_file(&bytes).await;
        let handle = open_file(&layer, "f").await;
        for to in [2 * B + 101, 2 * B + 5000, 5 * B] {
            assert_io(handle.truncate(to as u64).await, io::ErrorKind::InvalidData);
        }
        assert_eq!(files.contents("f").unwrap(), bytes);
        assert_eq!((writes_since(&faulty, 1).len(), faulty.truncates()), (0, 0));

        let mut bytes = stored(&plain);
        bytes[at(0) + 40] ^= 0x80;
        let (_files, _, layer) = faulty_file(&bytes).await;
        let handle = open_file(&layer, "f").await;
        handle.truncate(5 * B as u64).await.unwrap();
        assert_eq!(
            handle.read(2 * B as u64, 100).await.unwrap(),
            plain[2 * B..]
        );

        let plain = pattern(2 * B, 1);
        let mut bytes = stored(&plain);
        bytes[at(1) + 40] ^= 0x80;
        let (_files, faulty, layer) = faulty_file(&bytes).await;
        let handle = open_file(&layer, "f").await;
        handle.truncate(5 * B as u64).await.unwrap();
        assert_eq!(block_reads(&faulty), []);
        assert_eq!(handle.read(0, B as u32).await.unwrap(), plain[..B]);
    }

    #[tokio::test]
    async fn a_file_replaced_from_outside_is_truncated_once_the_header_reloads() {
        let logs = Logs::new();
        let old = pattern(2 * B + 10, 1);
        let new = pattern(2 * B + 10, 2);
        let (files, faulty, layer) = faulty_file(&stored(&old)).await;
        let handle = open_file(&layer, "f").await;
        handle.truncate(B as u64 + 5).await.unwrap();
        let loaded = header_reads(&faulty);

        let replaced = stored_file_with_id(&key_schedule(), shift(), other_file_id(), &new);
        files.clone().with_file("f", &replaced);
        handle.truncate(B as u64 + 2).await.unwrap();

        assert_eq!(read_all(&handle).await, new[..B + 2]);
        assert_eq!(header_reads(&faulty), loaded + 1);
        assert_eq!(files.contents("f").unwrap()[8..H], other_file_id()[..]);
        assert!(logs.warnings().is_empty());
    }

    #[tokio::test]
    async fn a_replaced_file_that_is_corrupt_too_fails_a_truncate_after_one_reload() {
        let logs = Logs::new();
        let len = 2 * B + 10;
        let (files, faulty, layer) = faulty_file(&stored(&pattern(len, 1))).await;
        let handle = open_file(&layer, "f").await;
        handle.truncate(len as u64 - 1).await.unwrap();
        let loaded = header_reads(&faulty);
        let blocks = block_reads(&faulty).len();

        let mut replaced =
            stored_file_with_id(&key_schedule(), shift(), other_file_id(), &pattern(len, 2));
        replaced[at(1) + 40] ^= 0x80;
        files.clone().with_file("f", &replaced);
        assert_io(
            handle.truncate(B as u64 + 5).await,
            io::ErrorKind::InvalidData,
        );
        assert_eq!(header_reads(&faulty), loaded + 1, "one reload");
        assert_eq!(
            block_reads(&faulty).len(),
            blocks + 2,
            "a failure, one retry"
        );
        assert_eq!(files.contents("f").unwrap(), replaced);
        assert_eq!(logs.warnings().len(), 1);
    }

    #[tokio::test]
    async fn a_torn_header_and_a_header_alone_are_cut_before_a_truncate() {
        let alone = stored(&[1])[..H].to_vec();
        for bytes in [vec![9; 1], vec![9; 10], vec![9; 23], alone] {
            for len in [0, B + 5] {
                let (files, faulty, layer) = faulty_file(&bytes).await;
                let handle = open_file(&layer, "f").await;
                let cell = format!("{} stored bytes, to {len}", bytes.len());

                handle.truncate(len as u64).await.unwrap();

                let expected = if len == 0 {
                    vec![0]
                } else {
                    vec![0, stored_len(len) as u64]
                };
                assert_eq!(faulty.truncate_calls(), expected, "{cell}");
                let after = files.contents("f").unwrap();
                assert_eq!(after.len(), stored_len(len), "{cell}");
                assert_eq!(read_all(&handle).await, vec![0; len], "{cell}");
                if len > 0 {
                    assert!(Header::parse(&after[..H], shift()).is_ok(), "{cell}");
                }
            }
        }
    }

    #[tokio::test]
    async fn a_fragment_after_the_last_block_is_cut_before_a_truncate() {
        let plain = pattern(B, 1);
        for extra in [1, 7, OVERHEAD] {
            let mut bytes = stored(&plain);
            bytes.extend(vec![7; extra]);
            for len in [B, 3 * B + 7] {
                let (files, faulty, layer) = faulty_file(&bytes).await;
                let handle = open_file(&layer, "f").await;
                let cell = format!("extra {extra}, to {len}");

                handle.truncate(len as u64).await.unwrap();

                assert_eq!(faulty.truncate_calls()[0], stored_len(B) as u64, "{cell}");
                let after = files.contents("f").unwrap();
                assert_eq!(after.len(), stored_len(len), "{cell}");
                if len > B {
                    assert!(
                        after[at(1)..].iter().all(|&byte| byte == 0),
                        "{cell}: no byte of the fragment is left in the hole"
                    );
                }
                assert_eq!(read_all(&handle).await, resized(&plain, len), "{cell}");
            }
        }
    }

    #[tokio::test]
    async fn a_truncate_whose_stored_size_passes_the_largest_one_is_invalid() {
        let edge = logical_size(shift(), MAX_STORED_SIZE).size;
        let (files, faulty, handle) = new_file().await;
        faulty.sink_truncates_from(Some(1 << 32));

        handle.truncate(edge).await.unwrap();
        assert_eq!(
            faulty.truncate_calls(),
            [stored_size(shift(), edge).unwrap()]
        );
        assert!(faulty.truncate_calls()[0] <= MAX_STORED_SIZE);

        let calls = (writes_since(&faulty, 1).len(), faulty.truncates());
        let stored_before = files.contents("f").unwrap();
        let _writing = handle.node().file().unwrap().write().await;
        for len in [edge + 1, edge + 100, 1 << 63, u64::MAX] {
            assert_err(
                assert_no_wait(handle.truncate(len)).await,
                SmbError::InvalidParameter,
            );
        }
        assert_eq!((writes_since(&faulty, 1).len(), faulty.truncates()), calls);
        assert_eq!(files.contents("f").unwrap(), stored_before);
    }

    #[tokio::test]
    async fn a_stored_file_that_claims_more_than_the_largest_size_refuses_the_truncate() {
        let (_files, faulty, layer) = faulty_file(&stored(&pattern(10, 1))).await;
        let handle = open_file(&layer, "f").await;
        faulty.report_size(Some(u64::MAX));
        assert_err(handle.truncate(5).await, SmbError::InvalidParameter);
        assert_err(
            handle.truncate(50 * B as u64).await,
            SmbError::InvalidParameter,
        );
        assert_eq!((writes_since(&faulty, 1).len(), faulty.truncates()), (0, 0));
    }

    #[tokio::test]
    async fn a_failed_extension_after_the_padded_block_is_whole_keeps_the_padded_block() {
        let plain = pattern(B + 100, 1);
        let bytes = stored(&plain);
        let (files, faulty, layer) = faulty_file(&bytes).await;
        let handle = open_file(&layer, "f").await;

        faulty.fail_truncate(1, SmbError::DiskFull);
        assert_err(handle.truncate(4 * B as u64 + 7).await, SmbError::DiskFull);
        assert_eq!(
            faulty.truncate_calls(),
            [stored_len(4 * B + 7) as u64, at(2) as u64]
        );
        assert_eq!(files.contents("f").unwrap().len(), at(2));
        assert_eq!(read_all(&handle).await, resized(&plain, 2 * B));
        assert_eq!(handle.node().header().await, Some(HeaderKind::Present));

        handle.truncate(4 * B as u64 + 7).await.unwrap();
        assert_eq!(read_all(&handle).await, resized(&plain, 4 * B + 7));
    }

    #[tokio::test]
    async fn a_failed_extension_of_an_empty_file_leaves_it_empty_and_caches_no_header() {
        for fail_write in [true, false] {
            let (files, faulty, handle) = new_file().await;
            if fail_write {
                faulty.tear_write(1, 10, SmbError::DiskFull);
            } else {
                faulty.fail_truncate(1, SmbError::DiskFull);
            }
            assert_err(handle.truncate(3 * B as u64).await, SmbError::DiskFull);
            assert_eq!(files.contents("f"), Some(Vec::new()), "write {fail_write}");
            assert_eq!(handle.node().header().await, Some(HeaderKind::Absent));
            assert!(handle.read(0, 10).await.unwrap().is_empty());

            handle.truncate(3 * B as u64).await.unwrap();
            assert_eq!(read_all(&handle).await, vec![0; 3 * B]);
            assert_eq!(handle.node().header().await, Some(HeaderKind::Present));
        }
    }

    #[tokio::test]
    async fn a_failed_extension_of_a_file_that_ends_in_a_whole_block_changes_nothing() {
        let plain = pattern(2 * B, 1);
        let bytes = stored(&plain);
        let (files, faulty, layer) = faulty_file(&bytes).await;
        let handle = open_file(&layer, "f").await;
        let len = 5 * B + 3;

        faulty.fail_truncate(1, SmbError::DiskFull);
        assert_err(handle.truncate(len as u64).await, SmbError::DiskFull);
        assert_eq!(
            faulty.truncate_calls(),
            [stored_len(len) as u64, bytes.len() as u64]
        );
        assert_eq!(writes_since(&faulty, 1), []);
        assert_eq!(files.contents("f").unwrap(), bytes);
        assert_eq!(read_all(&handle).await, plain);
        assert_eq!(handle.node().header().await, Some(HeaderKind::Present));

        handle.truncate(len as u64).await.unwrap();
        assert_eq!(read_all(&handle).await, resized(&plain, len));
    }

    #[tokio::test]
    async fn a_truncate_dropped_between_the_header_and_the_extension_leaves_an_empty_file() {
        let (files, gated, layer) = gated_file(b"").await;
        let handle = open_file(&layer, "f").await;
        let file = handle.node().file().unwrap();

        let gate = gated.arm(Op::Truncate);
        drop_at(&gate, handle.truncate(3 * B as u64)).await;
        assert!(file.try_write().is_ok(), "the lock is free");
        let stored_after = files.contents("f").unwrap();
        assert_eq!(stored_after.len(), H);
        assert_eq!(handle.node().header().await, Some(HeaderKind::Absent));
        assert!(handle.read(0, 10).await.unwrap().is_empty());
        assert_eq!(handle.stat().await.unwrap().end_of_file, 0);

        assert_eq!(handle.write(0, b"abc").await.unwrap(), 3);
        let after = files.contents("f").unwrap();
        assert_ne!(after[8..H], stored_after[8..H]);
        assert_eq!(read_all(&handle).await, b"abc");
        assert_eq!(handle.node().header().await, Some(HeaderKind::Present));
    }

    #[tokio::test]
    async fn a_failed_shrink_after_the_cut_leaves_the_file_at_the_block_edge() {
        let plain = pattern(2 * B + 10, 1);
        let (files, faulty, layer) = faulty_file(&stored(&plain)).await;
        let handle = open_file(&layer, "f").await;

        // A prefix of the new block reaches the stored file, and is cut off.
        faulty.tear_write(1, 30, SmbError::DiskFull);
        assert_err(handle.truncate(B as u64 + 5).await, SmbError::DiskFull);
        assert_eq!(faulty.truncate_calls(), [at(1) as u64, at(1) as u64]);
        assert_eq!(files.contents("f").unwrap().len(), at(1));
        assert_eq!(read_all(&handle).await, plain[..B]);
        assert_eq!(handle.node().header().await, Some(HeaderKind::Present));

        handle.truncate(10).await.unwrap();
        assert_eq!(read_all(&handle).await, plain[..10]);
    }

    #[tokio::test]
    async fn every_block_size_shrinks_and_extends_to_the_stored_size_of_the_new_length() {
        for bits in [13, 16, 20] {
            let shift = BlockShift::new(bits).unwrap();
            let b = shift.block_len();
            let plain = pattern(2 * b + 100, 1);
            let lens = [b, b + 1, 2 * b - 1, 2 * b + 300, 5 * b + 7];
            for len in lens {
                let bytes = stored_file(&key_schedule(), shift, &plain);
                let (files, _, layer) = faulty_file_in(shift, &bytes).await;
                let handle = open_file(&layer, "f").await;

                handle.truncate(len as u64).await.unwrap();

                let cell = format!("shift {bits}, to {len}");
                let after = files.contents("f").unwrap();
                assert_eq!(
                    Some(after.len() as u64),
                    stored_size(shift, len as u64),
                    "{cell}"
                );
                assert!(read_all(&handle).await == resized(&plain, len), "{cell}");
            }
        }
    }

    #[tokio::test]
    async fn every_block_a_truncate_seals_draws_one_nonce_and_a_new_header_one_file_id() {
        let (_files, _, handle) = new_file().await;
        let file = handle.node().file().unwrap();
        let mut random = Counting::default();

        // From nothing: a file id, no block.
        handle
            .truncate_with(file, 3 * B as u64 + 5, &mut random)
            .await
            .unwrap();
        assert_eq!((random.ids, &random.draws[..]), (1, &[][..]));
        // Past a partial last block: it is sealed again.
        handle
            .truncate_with(file, 5 * B as u64 + 7, &mut random)
            .await
            .unwrap();
        assert_eq!(random.draws, [1]);
        // To a block edge, and from one: no block is sealed.
        handle
            .truncate_with(file, 2 * B as u64, &mut random)
            .await
            .unwrap();
        handle
            .truncate_with(file, 4 * B as u64, &mut random)
            .await
            .unwrap();
        assert_eq!(random.draws, [1]);
        // Into a block.
        handle
            .truncate_with(file, B as u64 + 1, &mut random)
            .await
            .unwrap();
        assert_eq!(random.draws, [1, 1]);
        // To zero, and from zero.
        handle.truncate_with(file, 0, &mut random).await.unwrap();
        handle.truncate_with(file, 10, &mut random).await.unwrap();
        assert_eq!((random.ids, &random.draws[..]), (2, &[1, 1][..]));
    }

    #[tokio::test]
    async fn a_block_rewritten_by_a_truncate_gets_a_new_nonce_every_time() {
        let (files, _, handle) = new_file().await;
        handle.write(0, &pattern(B + 200, 1)).await.unwrap();
        let mut seen = HashSet::new();
        for len in (B + 100..B + 200).rev() {
            handle.truncate(len as u64).await.unwrap();
            assert!(seen.insert(nonce_at(&files.contents("f").unwrap(), at(1))));
        }
        assert_eq!(read_all(&handle).await, pattern(B + 200, 1)[..B + 100]);
    }

    #[tokio::test]
    async fn a_generator_that_does_not_answer_fails_a_truncate_before_anything_is_stored() {
        let plain = pattern(B + 100, 1);
        let bytes = stored(&plain);
        let (files, faulty, layer) = faulty_file(&bytes).await;
        let handle = open_file(&layer, "f").await;
        let file = handle.node().file().unwrap();

        for len in [B as u64 + 50, B as u64 + 300, 3 * B as u64] {
            assert_io(
                handle.truncate_with(file, len, &mut Down).await,
                io::ErrorKind::Other,
            );
        }
        assert_eq!(files.contents("f").unwrap(), bytes);
        assert_eq!((writes_since(&faulty, 1).len(), faulty.truncates()), (0, 0));

        // A cut at a block edge draws nothing.
        handle
            .truncate_with(file, B as u64, &mut Down)
            .await
            .unwrap();
        handle
            .truncate_with(file, 3 * B as u64, &mut Down)
            .await
            .unwrap();
        assert_eq!(read_all(&handle).await, resized(&plain[..B], 3 * B));

        let (files, faulty, handle) = new_file().await;
        let file = handle.node().file().unwrap();
        assert_io(
            handle.truncate_with(file, 5, &mut Down).await,
            io::ErrorKind::Other,
        );
        assert_eq!(files.contents("f"), Some(Vec::new()));
        assert_eq!((writes_since(&faulty, 1).len(), faulty.truncates()), (0, 0));
        assert_eq!(handle.node().header().await, Some(HeaderKind::Absent));
        handle.truncate_with(file, 0, &mut Down).await.unwrap();
    }

    #[tokio::test]
    async fn a_file_with_an_unusable_header_refuses_a_size_change_but_not_a_truncation_to_zero() {
        let good = stored(&pattern(B + 10, 1));
        let mut bad_magic = good.clone();
        bad_magic[0] ^= 1;
        let mut bad_version = good.clone();
        bad_version[4] = 9;
        let mut whole_blocks = stored(&pattern(2 * B, 1));
        whole_blocks[0] ^= 1;
        let cases = [
            (bad_magic, io::ErrorKind::InvalidData),
            (bad_version, io::ErrorKind::Unsupported),
            (whole_blocks, io::ErrorKind::InvalidData),
            (vec![0x55; 100], io::ErrorKind::InvalidData),
        ];
        for (bytes, kind) in &cases {
            let (files, faulty, layer) = faulty_file(bytes).await;
            let handle = open_file(&layer, "f").await;
            let logical = logical_size(shift(), bytes.len() as u64).size;

            for len in [5, logical - 1, logical + 1, 10 * B as u64] {
                assert_io(handle.truncate(len).await, *kind);
            }
            assert_eq!(files.contents("f").unwrap(), *bytes);
            assert_eq!((writes_since(&faulty, 1).len(), faulty.truncates()), (0, 0));
            assert_eq!(handle.node().header().await, Some(HeaderKind::Unknown));

            handle.truncate(logical).await.unwrap();
            handle.truncate(0).await.unwrap();
            assert_eq!(files.contents("f"), Some(Vec::new()));
            assert_eq!(handle.node().header().await, Some(HeaderKind::Absent));
            handle.truncate(5).await.unwrap();
            assert_eq!(read_all(&handle).await, vec![0; 5]);
        }
    }

    #[tokio::test]
    async fn a_truncate_dropped_between_the_cut_and_the_rewrite_leaves_the_file_at_the_block_edge()
    {
        let plain = pattern(2 * B + 10, 1);
        let bytes = stored(&plain);
        let (files, gated, layer) = gated_file(&bytes).await;
        let handle = open_file(&layer, "f").await;
        assert_eq!(handle.read(0, 10).await.unwrap(), plain[..10]);
        let file = handle.node().file().unwrap();

        let gate = gated.arm(Op::Write);
        drop_at(&gate, handle.truncate(B as u64 + 5)).await;
        assert!(file.try_write().is_ok(), "the lock is free");
        assert_eq!(handle.node().header().await, Some(HeaderKind::Unknown));
        assert_eq!(files.contents("f").unwrap(), bytes[..at(1)]);

        assert_eq!(read_all(&handle).await, plain[..B]);
        handle.truncate(5).await.unwrap();
        assert_eq!(read_all(&handle).await, plain[..5]);
    }
}
