//! The contents of a file through its handle: the header of the stored file
//! and the reads of its blocks.

use std::io;

use bytes::Bytes;
use tokio::sync::{RwLock, RwLockReadGuard, RwLockWriteGuard};
use tracing::warn;

use super::block::FileCipher;
use super::format::{FILE_ID_LEN, HEADER_LEN, OVERHEAD};
use super::handle::EncryptedHandle;
use super::header::{Header, HeaderError};
use super::inner::{read_blocks, read_full};
use super::node::{FileMeta, HeaderState};
use super::size::{block_range, logical_size};
use crate::backend::ShareBackend;
use crate::error::{SmbError, SmbResult};
use crate::path::SmbPath;

/// What opening the blocks of a read gave.
pub(super) enum Opened {
    Data(Bytes),
    /// The index of the first block that does not open.
    Corrupt(u64),
}

fn io_error(kind: io::ErrorKind, message: &str) -> SmbError {
    SmbError::Io(io::Error::new(kind, message))
}

/// The stored file holds more than a header and the header is not read.
fn needs_header(stored: u64, state: &HeaderState) -> bool {
    stored > HEADER_LEN as u64 && !matches!(state, HeaderState::Present(..))
}

impl<B: ShareBackend> EncryptedHandle<B> {
    /// Reads `len` bytes of the file at `offset`. Returns fewer only at the
    /// end of the file.
    pub(super) async fn read_file(
        &self,
        file: &RwLock<FileMeta>,
        offset: u64,
        len: u32,
    ) -> SmbResult<Bytes> {
        let mut reloaded = false;
        loop {
            let (meta, stored) = self.lock_for_reading(file).await?;
            // Without a header the stored file holds no data.
            let HeaderState::Present(header, cipher) = &meta.header else {
                return Ok(Bytes::new());
            };
            let logical = logical_size(self.shared.settings.block_shift, stored).size;
            if len == 0 || offset >= logical {
                return Ok(Bytes::new());
            }
            let block = match self.read_range(cipher, logical, offset, len).await? {
                Opened::Data(bytes) => return Ok(bytes),
                Opened::Corrupt(block) => block,
            };
            let used = header.file_id();
            drop(meta);
            if !reloaded && self.reload_header(file, used).await? {
                reloaded = true;
                continue;
            }
            return Err(self.block_error(block));
        }
    }

    pub(super) async fn stored_size(&self) -> SmbResult<u64> {
        Ok(self.inner.stat().await?.end_of_file)
    }

    /// Takes the lock of the file for reading, and returns it with the size
    /// of the stored file. The header is loaded when the file holds more
    /// than a header.
    async fn lock_for_reading<'a>(
        &self,
        file: &'a RwLock<FileMeta>,
    ) -> SmbResult<(RwLockReadGuard<'a, FileMeta>, u64)> {
        let meta = file.read().await;
        let stored = self.stored_size().await?;
        if !needs_header(stored, &meta.header) {
            return Ok((meta, stored));
        }
        drop(meta);
        let mut meta = file.write().await;
        let stored = self.stored_size().await?;
        if needs_header(stored, &meta.header) {
            self.load_header(&mut meta, stored).await?;
        }
        Ok((RwLockWriteGuard::downgrade(meta), stored))
    }

    /// Reads the header of the stored file, which has `stored` bytes, into
    /// `meta`. A file of no more than a header has none. A header that is not
    /// valid fails with `Io`, and an error of the inner read is returned as it
    /// is. Either leaves the state unknown.
    pub(super) async fn load_header(&self, meta: &mut FileMeta, stored: u64) -> SmbResult<()> {
        if stored <= HEADER_LEN as u64 {
            meta.header = HeaderState::Absent;
            return Ok(());
        }
        match self.read_header().await {
            Ok((header, cipher)) => {
                meta.header = HeaderState::Present(header, cipher);
                Ok(())
            }
            Err(error) => {
                meta.header = HeaderState::Unknown;
                Err(error)
            }
        }
    }

    /// Reads the header at the start of the stored file and builds the cipher
    /// of its key. A header that is not valid fails with `Io`.
    pub(super) async fn read_header(&self) -> SmbResult<(Header, Box<FileCipher>)> {
        let bytes = read_full(&*self.inner, 0, HEADER_LEN).await?;
        let header = Header::parse(&bytes, self.shared.settings.block_shift)
            .map_err(|error| self.header_error(error))?;
        let cipher = FileCipher::new(&self.shared.keys, header);
        Ok((header, Box::new(cipher)))
    }

    /// Reads the header again after a block of the file with id `used` did
    /// not open. True when the stored file has a different file id, or none.
    async fn reload_header(
        &self,
        file: &RwLock<FileMeta>,
        used: [u8; FILE_ID_LEN],
    ) -> SmbResult<bool> {
        let mut meta = file.write().await;
        self.reload(&mut meta, used).await
    }

    /// `reload_header` for a caller that holds the lock of the file.
    pub(super) async fn reload(
        &self,
        meta: &mut FileMeta,
        used: [u8; FILE_ID_LEN],
    ) -> SmbResult<bool> {
        let stored = self.stored_size().await?;
        self.load_header(meta, stored).await?;
        Ok(match &meta.header {
            HeaderState::Present(now, _) => now.file_id() != used,
            HeaderState::Unknown | HeaderState::Absent => true,
        })
    }

    /// Reads and opens the blocks that hold the `len` bytes at `offset` of a
    /// file of `logical` bytes, and returns those bytes. `offset` is inside
    /// the file and `len` is not 0.
    pub(super) async fn read_range(
        &self,
        cipher: &FileCipher,
        logical: u64,
        offset: u64,
        len: u32,
    ) -> SmbResult<Opened> {
        let shift = self.shared.settings.block_shift;
        let end = offset.saturating_add(u64::from(len)).min(logical);
        let first = offset >> shift.get();
        let last = (end - 1) >> shift.get();
        let range = block_range(shift, logical, first, last).ok_or(SmbError::InvalidParameter)?;
        let stored_len =
            usize::try_from(range.stored_len).map_err(|_| SmbError::InvalidParameter)?;
        let plain_len = usize::try_from(range.plain_len).map_err(|_| SmbError::InvalidParameter)?;

        let sealed = read_blocks(&*self.inner, shift, range.offset, stored_len).await?;
        let mut plain = vec![0u8; plain_len];
        let blocks = sealed
            .chunks(shift.block_len() + OVERHEAD)
            .zip(plain.chunks_mut(shift.block_len()));
        for ((stored, out), index) in blocks.zip(first..) {
            if cipher.open_block(index, stored, out).is_err() {
                return Ok(Opened::Corrupt(index));
            }
        }
        let skip = (offset & (shift.block_size() - 1)) as usize;
        let take = (end - offset) as usize;
        Ok(Opened::Data(Bytes::from(plain).slice(skip..skip + take)))
    }

    /// The path of the file as its names are spelled, and the path it is
    /// stored under, which are one path while names are stored as the client
    /// spells them.
    fn paths(&self) -> (SmbPath, SmbPath) {
        let stored = self.node.path();
        let path = self.plain.clone().unwrap_or_else(|| stored.clone());
        (path, stored)
    }

    /// Logs a block that does not open and returns the error that fails the
    /// call.
    pub(super) fn block_error(&self, block: u64) -> SmbError {
        let (path, stored) = self.paths();
        warn!(path = %path, stored = %stored, block, "block fails authentication");
        io_error(io::ErrorKind::InvalidData, "block fails authentication")
    }

    /// Logs an unusable header and returns the error that fails the call.
    fn header_error(&self, error: HeaderError) -> SmbError {
        let (path, stored) = self.paths();
        match error {
            HeaderError::Invalid => {
                warn!(path = %path, stored = %stored, "file header is invalid");
                io_error(io::ErrorKind::InvalidData, "invalid file header")
            }
            HeaderError::Unsupported => {
                warn!(path = %path, stored = %stored, "file header has an unknown version or suite");
                io_error(io::ErrorKind::Unsupported, "unsupported file header")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::ops::Range;
    use std::sync::Arc;

    use super::super::backend::EncryptedBackend;
    use super::super::format::{BlockShift, MAX_STORED_SIZE, NONCE_LEN};
    use super::super::node::HeaderKind;
    use super::super::size::stored_size;
    use super::super::testing::{
        B, H, assert_io, block_reads, clear_blocks, drop_at, faulty_file, file_id, gated_file,
        header_reads, key_schedule, layer_over, open, open_dir, open_file, other_file_id, settle,
        shift, stored, stored_file, stored_file_with_id,
    };
    use super::*;
    use crate::backend::{Handle, OpenAction, OpenIntent};
    use crate::ntstatus::STATUS_UNEXPECTED_IO_ERROR;
    use crate::tests::data::nonzero_pattern;
    use crate::tests::faulty::Faulty;
    use crate::tests::gated::{Gated, Op};
    use crate::tests::logs::Logs;
    use crate::tests::memfs::MemFsBackend;

    /// The stored bytes of block `index` of a file of `logical` bytes.
    fn block_at(logical: usize, index: u64) -> Range<usize> {
        let range = block_range(shift(), logical as u64, index, index).unwrap();
        let start = range.offset as usize;
        start..start + range.stored_len as usize
    }

    /// The bytes a read of `len` bytes at `offset` of `plain` returns.
    fn expected(plain: &[u8], offset: usize, len: u32) -> &[u8] {
        let start = offset.min(plain.len());
        let end = offset.saturating_add(len as usize).min(plain.len());
        &plain[start..end]
    }

    /// A backend over a store that holds the file `f` with the stored bytes
    /// `bytes`.
    async fn layer_with(bytes: &[u8]) -> (MemFsBackend, EncryptedBackend<MemFsBackend>) {
        let files = MemFsBackend::new();
        let layer = layer_over(files.clone()).await;
        files.clone().with_file("f", bytes);
        (files, layer)
    }

    #[tokio::test]
    async fn a_read_returns_the_bytes_up_to_the_request_or_the_end_of_the_file() {
        let plain = nonzero_pattern(3 * B + 100);
        let end = plain.len();
        let (_, layer) = layer_with(&stored(&plain)).await;
        let handle = open_file(&layer, "f").await;

        let offsets = [
            0,
            1,
            B - 1,
            B,
            B + 1,
            2 * B - 1,
            2 * B,
            3 * B - 1,
            3 * B,
            end - 1,
            end,
            end + 1,
            end + B,
        ];
        let lens = [
            0,
            1,
            2,
            B as u32 - 1,
            B as u32,
            B as u32 + 1,
            2 * B as u32,
            end as u32,
            u32::MAX,
        ];
        for offset in offsets {
            for len in lens {
                let got = handle.read(offset as u64, len).await.unwrap();
                assert_eq!(
                    got,
                    expected(&plain, offset, len),
                    "offset {offset}, len {len}"
                );
            }
        }
    }

    #[tokio::test]
    async fn a_file_of_one_byte_and_a_file_of_whole_blocks_read_in_full() {
        for len in [1, B - 1, B, 2 * B] {
            let plain = nonzero_pattern(len);
            let (_, layer) = layer_with(&stored(&plain)).await;
            let handle = open_file(&layer, "f").await;
            assert_eq!(handle.read(0, u32::MAX).await.unwrap(), plain, "len {len}");
            assert!(handle.read(len as u64, 1).await.unwrap().is_empty());
        }
    }

    #[tokio::test]
    async fn blocks_of_zero_bytes_read_as_zeros_whole_or_partial() {
        let len = 4 * B + 50;
        let mut plain = nonzero_pattern(len);
        let mut bytes = stored(&plain);
        for index in [1, 3, 4] {
            bytes[block_at(len, index)].fill(0);
        }
        plain[B..2 * B].fill(0);
        plain[3 * B..].fill(0);
        let (_, layer) = layer_with(&bytes).await;
        let handle = open_file(&layer, "f").await;

        let reads = [
            (0, len),
            (B - 1, 2),
            (B + 5, 10),
            (2 * B - 1, 2),
            (3 * B - 3, 6),
            (4 * B, 50),
            (4 * B + 10, 100),
        ];
        for (offset, count) in reads {
            let got = handle.read(offset as u64, count as u32).await.unwrap();
            assert_eq!(got, expected(&plain, offset, count as u32), "at {offset}");
        }
    }

    #[tokio::test]
    async fn a_file_of_nothing_but_zero_blocks_reads_as_zeros() {
        let len = 2 * B + 10;
        let mut bytes = stored(&nonzero_pattern(len));
        bytes[H..].fill(0);
        let (_, layer) = layer_with(&bytes).await;
        let handle = open_file(&layer, "f").await;
        assert_eq!(handle.read(0, u32::MAX).await.unwrap(), vec![0; len]);
        assert_eq!(handle.read(B as u64 - 1, 3).await.unwrap(), vec![0; 3]);
    }

    #[tokio::test]
    async fn a_block_that_fails_authentication_fails_its_reads_with_one_warning_each() {
        let logs = Logs::new();
        let len = 3 * B + 100;
        let plain = nonzero_pattern(len);
        let mut bytes = stored(&plain);
        let block = block_at(len, 2);
        bytes[block.start + NONCE_LEN + 5] ^= 1;
        let files = MemFsBackend::new();
        let layer = layer_over(files.clone()).await;
        files
            .clone()
            .with_dir("vault")
            .with_file("vault\\data.bin", &bytes);
        let handle = open_file(&layer, "vault\\data.bin").await;

        let Err(error) = handle.read(0, len as u32).await else {
            panic!("a block that fails authentication fails the read");
        };
        assert!(matches!(&error, SmbError::Io(e) if e.kind() == io::ErrorKind::InvalidData));
        assert_eq!(error.to_nt_status(), STATUS_UNEXPECTED_IO_ERROR);
        let warnings = logs.warnings();
        assert_eq!(warnings.len(), 1, "{warnings:?}");
        let line = &warnings[0];
        assert!(line.contains("path=vault\\data.bin"), "{line}");
        assert!(line.contains("stored=vault\\data.bin"), "{line}");
        assert!(line.contains("block=2"), "{line}");

        assert_eq!(handle.read(0, 2 * B as u32).await.unwrap(), plain[..2 * B]);
        assert_eq!(
            handle.read(3 * B as u64, 100).await.unwrap(),
            plain[3 * B..]
        );
        assert_eq!(logs.warnings().len(), 1, "reads of the other blocks work");

        assert_io(
            handle.read(2 * B as u64 + 1, 10).await,
            io::ErrorKind::InvalidData,
        );
        assert_eq!(logs.warnings().len(), 2);
    }

    #[tokio::test]
    async fn a_changed_byte_of_a_block_or_of_the_header_fails_the_read() {
        let len = 2 * B + 10;
        let plain = nonzero_pattern(len);
        let good = stored(&plain);
        let block = block_at(len, 1);
        let at = [
            block.start,
            block.start + NONCE_LEN + 100,
            block.end - 1,
            8,
            H - 1,
        ];
        for at in at {
            let mut bytes = good.clone();
            bytes[at] ^= 0x10;
            let (_, layer) = layer_with(&bytes).await;
            let handle = open_file(&layer, "f").await;
            assert_io(handle.read(B as u64, 1).await, io::ErrorKind::InvalidData);
        }
    }

    #[tokio::test]
    async fn a_block_moved_to_another_index_does_not_open() {
        let len = 3 * B;
        let plain = nonzero_pattern(len);
        let mut bytes = stored(&plain);
        let (from, to) = (block_at(len, 0), block_at(len, 2));
        let moved = bytes[from].to_vec();
        bytes[to].copy_from_slice(&moved);
        let (_, layer) = layer_with(&bytes).await;
        let handle = open_file(&layer, "f").await;
        assert_eq!(handle.read(0, 2 * B as u32).await.unwrap(), plain[..2 * B]);
        assert_io(
            handle.read(2 * B as u64, 1).await,
            io::ErrorKind::InvalidData,
        );
    }

    #[tokio::test]
    async fn a_file_replaced_from_outside_is_read_once_the_header_reloads() {
        let logs = Logs::new();
        let old = nonzero_pattern(2 * B + 10);
        let new: Vec<u8> = old.iter().map(|byte| byte ^ 0x5a).collect();
        let (files, faulty, layer) = faulty_file(&stored(&old)).await;
        let handle = open_file(&layer, "f").await;

        assert_eq!(handle.read(0, 100).await.unwrap(), old[..100]);
        assert_eq!(header_reads(&faulty), 1);

        let replaced = stored_file_with_id(&key_schedule(), shift(), other_file_id(), &new);
        files.clone().with_file("f", &replaced);
        assert_eq!(handle.read(0, 100).await.unwrap(), new[..100]);
        assert_eq!(header_reads(&faulty), 2);
        assert!(logs.warnings().is_empty());

        assert_eq!(handle.read(B as u64, 100).await.unwrap(), new[B..B + 100]);
        assert_eq!(header_reads(&faulty), 2, "the new header is kept");
    }

    #[tokio::test]
    async fn a_block_that_is_corrupt_for_good_fails_after_one_reload() {
        let logs = Logs::new();
        let len = 2 * B + 10;
        let mut bytes = stored(&nonzero_pattern(len));
        bytes[block_at(len, 1).start + 40] ^= 0x80;
        let (_files, faulty, layer) = faulty_file(&bytes).await;
        let handle = open_file(&layer, "f").await;

        assert_io(handle.read(B as u64, 10).await, io::ErrorKind::InvalidData);
        assert_eq!(header_reads(&faulty), 2, "one load and one reload");
        assert_eq!(block_reads(&faulty).len(), 1, "the header did not change");
        assert_eq!(logs.warnings().len(), 1);
    }

    #[tokio::test]
    async fn a_replaced_file_that_is_corrupt_too_fails_after_one_retry() {
        let logs = Logs::new();
        let len = 2 * B + 10;
        let old = nonzero_pattern(len);
        let (files, faulty, layer) = faulty_file(&stored(&old)).await;
        let handle = open_file(&layer, "f").await;
        assert_eq!(handle.read(0, 10).await.unwrap(), old[..10]);

        let mut replaced = stored_file_with_id(&key_schedule(), shift(), other_file_id(), &old);
        replaced[block_at(len, 0).start + 40] ^= 0x80;
        files.clone().with_file("f", &replaced);
        assert_io(handle.read(0, 10).await, io::ErrorKind::InvalidData);
        assert_eq!(header_reads(&faulty), 2, "one load and one reload");
        assert_eq!(
            block_reads(&faulty).len(),
            3,
            "one read, the failure, one retry"
        );
        assert_eq!(logs.warnings().len(), 1);
    }

    #[tokio::test]
    async fn a_file_emptied_from_outside_reads_as_empty_and_reads_again_when_it_refills() {
        let plain = nonzero_pattern(B + 10);
        let (files, faulty, layer) = faulty_file(&stored(&plain)).await;
        let handle = open_file(&layer, "f").await;
        assert_eq!(handle.read(0, 10).await.unwrap(), plain[..10]);
        let loaded = header_reads(&faulty);

        let header_only = stored(&plain)[..H].to_vec();
        for emptied in [Vec::new(), vec![9; 10], header_only] {
            files.clone().with_file("f", &emptied);
            assert!(handle.read(0, 10).await.unwrap().is_empty());
        }
        assert_eq!(header_reads(&faulty), loaded, "nothing to read");

        let again = nonzero_pattern(B);
        let refilled = stored_file_with_id(&key_schedule(), shift(), other_file_id(), &again);
        files.clone().with_file("f", &refilled);
        assert_eq!(handle.read(0, 10).await.unwrap(), again[..10]);
    }

    #[tokio::test]
    async fn a_new_file_reads_a_header_written_outside_the_layer() {
        let files = MemFsBackend::new();
        let layer = layer_over(files.clone()).await;
        let (handle, action) = open(&layer, "f", OpenIntent::Create).await;
        assert_eq!(action, OpenAction::Created);
        assert_eq!(handle.node().header().await, Some(HeaderKind::Absent));
        assert!(handle.read(0, 10).await.unwrap().is_empty());
        assert_eq!(handle.node().header().await, Some(HeaderKind::Absent));

        let plain = nonzero_pattern(B + 5);
        files.clone().with_file("f", &stored(&plain));
        assert_eq!(handle.read(B as u64 - 2, 10).await.unwrap(), plain[B - 2..]);
        assert_eq!(handle.node().header().await, Some(HeaderKind::Present));
    }

    #[tokio::test]
    async fn an_invalid_header_in_a_file_with_data_fails_the_read_and_stays_unknown() {
        let logs = Logs::new();
        let good = stored(&nonzero_pattern(B + 10));
        let mut bad_magic = good.clone();
        bad_magic[0] ^= 1;
        let mut bad_shift = good.clone();
        bad_shift[6] = 16;
        let mut bad_reserved = good.clone();
        bad_reserved[7] = 1;
        let mut zero_id = good.clone();
        zero_id[8..H].fill(0);
        let cases = [bad_magic, bad_shift, bad_reserved, zero_id, vec![0x55; 100]];
        for bytes in &cases {
            let (_, layer) = layer_with(bytes).await;
            let handle = open_file(&layer, "f").await;
            assert_io(handle.read(0, 10).await, io::ErrorKind::InvalidData);
            assert_eq!(handle.node().header().await, Some(HeaderKind::Unknown));
        }
        let warnings = logs.warnings();
        assert_eq!(warnings.len(), cases.len(), "{warnings:?}");
        for line in &warnings {
            assert!(line.contains("file header is invalid"), "{line}");
            assert!(line.contains("path=f stored=f"), "{line}");
        }
    }

    #[tokio::test]
    async fn an_unknown_version_or_suite_is_unsupported() {
        let logs = Logs::new();
        let good = stored(&nonzero_pattern(B + 10));
        for at in [4, 5] {
            let mut bytes = good.clone();
            bytes[at] = 9;
            let (_, layer) = layer_with(&bytes).await;
            let handle = open_file(&layer, "f").await;
            assert_io(handle.read(0, 10).await, io::ErrorKind::Unsupported);
            assert_eq!(handle.node().header().await, Some(HeaderKind::Unknown));
        }
        let warnings = logs.warnings();
        assert_eq!(warnings.len(), 2, "{warnings:?}");
        assert!(
            warnings
                .iter()
                .all(|line| line.contains("unknown version or suite"))
        );
    }

    #[tokio::test]
    async fn a_header_that_is_repaired_reads_on_the_next_call() {
        let plain = nonzero_pattern(B + 10);
        let good = stored(&plain);
        let mut bad = good.clone();
        bad[0] ^= 1;
        let (files, layer) = layer_with(&bad).await;
        let handle = open_file(&layer, "f").await;
        assert_io(handle.read(0, 10).await, io::ErrorKind::InvalidData);

        files.clone().with_file("f", &good);
        assert_eq!(handle.read(0, 10).await.unwrap(), plain[..10]);
        assert_eq!(handle.node().header().await, Some(HeaderKind::Present));
    }

    #[tokio::test]
    async fn short_inner_reads_give_the_full_result() {
        let plain = nonzero_pattern(3 * B + 100);
        for max in [5, 1000] {
            let (_files, faulty, layer) = faulty_file(&stored(&plain)).await;
            faulty.short_reads(Some(max));
            let handle = open_file(&layer, "f").await;
            for (offset, len) in [
                (0, plain.len()),
                (B - 3, 10),
                (2 * B, B + 100),
                (3 * B, 100),
            ] {
                let got = handle.read(offset as u64, len as u32).await.unwrap();
                assert_eq!(got, plain[offset..offset + len], "max {max}, at {offset}");
            }
        }
    }

    #[tokio::test]
    async fn an_inner_read_that_returns_nothing_fails_the_read() {
        let logs = Logs::new();
        let plain = nonzero_pattern(2 * B + 10);
        let (_files, faulty, layer) = faulty_file(&stored(&plain)).await;
        let handle = open_file(&layer, "f").await;

        faulty.short_reads(Some(0));
        assert_io(handle.read(0, 10).await, io::ErrorKind::UnexpectedEof);
        assert_eq!(handle.node().header().await, Some(HeaderKind::Unknown));

        faulty.short_reads(None);
        assert_eq!(handle.read(0, 10).await.unwrap(), plain[..10]);
        faulty.short_reads(Some(0));
        assert_io(
            handle.read(B as u64, 10).await,
            io::ErrorKind::UnexpectedEof,
        );
        assert_eq!(handle.node().header().await, Some(HeaderKind::Present));
        assert!(
            logs.warnings().is_empty(),
            "a short file is not a corrupt block"
        );

        faulty.short_reads(None);
        assert_eq!(handle.read(B as u64, 10).await.unwrap(), plain[B..B + 10]);
    }

    #[tokio::test]
    async fn a_stored_file_shorter_than_its_stat_size_fails_the_read() {
        let logs = Logs::new();
        let len = 2 * B + 10;
        let plain = nonzero_pattern(len);
        let bytes = stored(&plain);
        let (files, gated, layer) = gated_file(&bytes).await;
        let handle = Arc::new(open_file(&layer, "f").await);
        assert_eq!(handle.read(0, 10).await.unwrap(), plain[..10]);

        let gate = gated.arm_after(Op::Stat);
        let read = tokio::spawn({
            let handle = Arc::clone(&handle);
            async move { handle.read(B as u64, 10).await }
        });
        gate.reached().await;
        files.clone().with_file("f", &bytes[..H + B + OVERHEAD + 5]);
        gate.release();
        assert_io(read.await.unwrap(), io::ErrorKind::UnexpectedEof);
        assert!(
            logs.warnings().is_empty(),
            "a short file is not a corrupt block"
        );

        files.clone().with_file("f", &bytes);
        assert_eq!(handle.read(B as u64, 10).await.unwrap(), plain[B..B + 10]);
    }

    /// The stored bytes of files of abnormal sizes, with the size a client
    /// sees and the bytes it reads.
    fn abnormal_files() -> Vec<(&'static str, Vec<u8>, Vec<u8>)> {
        let head = stored(&[1])[..H].to_vec();
        let block = nonzero_pattern(B);
        let with_junk = |junk: usize| [stored(&block), vec![7; junk]].concat();
        vec![
            ("empty", Vec::new(), Vec::new()),
            ("one_byte", vec![7], Vec::new()),
            ("torn_header", head[..H - 1].to_vec(), Vec::new()),
            ("header", head.clone(), Vec::new()),
            (
                "header_and_one_byte",
                [head.clone(), vec![7]].concat(),
                Vec::new(),
            ),
            (
                "header_and_overhead",
                [head, vec![7; 28]].concat(),
                Vec::new(),
            ),
            ("block", stored(&block), block.clone()),
            ("block_and_one_byte", with_junk(1), block.clone()),
            ("block_and_overhead", with_junk(28), block.clone()),
            (
                "partial",
                stored(&nonzero_pattern(B + 3)),
                nonzero_pattern(B + 3),
            ),
        ]
    }

    /// A backend over a store that holds `abnormal_files`.
    async fn layer_with_abnormal_files() -> EncryptedBackend<MemFsBackend> {
        let files = MemFsBackend::new();
        let layer = layer_over(files.clone()).await;
        for (name, bytes, _) in abnormal_files() {
            files.clone().with_file(name, &bytes);
        }
        layer
    }

    #[tokio::test]
    async fn abnormal_stored_sizes_read_as_their_plaintext() {
        let layer = layer_with_abnormal_files().await;
        for (name, _, plain) in &abnormal_files() {
            let handle = open_file(&layer, name).await;
            assert_eq!(
                handle.read(0, u32::MAX).await.unwrap(),
                plain,
                "read of {name}"
            );
            let past = plain.len() as u64;
            assert!(
                handle.read(past, 10).await.unwrap().is_empty(),
                "past {name}"
            );
        }
    }

    #[tokio::test]
    async fn abnormal_stored_sizes_show_their_plaintext_size_in_stat_and_listings() {
        let layer = layer_with_abnormal_files().await;
        let root = open_dir(&layer, "").await;
        let listed = root.list_dir(None).await.unwrap();
        for (name, _, plain) in &abnormal_files() {
            let want = plain.len() as u64;
            let entry = listed
                .iter()
                .find(|entry| entry.info.name == *name)
                .unwrap();
            assert_eq!(
                (entry.info.end_of_file, entry.info.allocation_size),
                (want, want),
                "listing of {name}"
            );
            let info = open_file(&layer, name).await.stat().await.unwrap();
            assert_eq!(
                (info.end_of_file, info.allocation_size),
                (want, want),
                "stat of {name}"
            );
        }
    }

    #[tokio::test]
    async fn a_stored_file_of_no_more_than_a_header_is_read_without_touching_it() {
        for bytes in [vec![7; 10], stored(&[1])[..H].to_vec()] {
            let (_files, faulty, layer) = faulty_file(&bytes).await;
            let handle = open_file(&layer, "f").await;
            assert!(handle.read(0, 10).await.unwrap().is_empty());
            assert!(faulty.reads().is_empty(), "{} stored bytes", bytes.len());
        }
    }

    #[tokio::test]
    async fn one_inner_call_moves_whole_blocks_and_at_most_4_mib() {
        for (bits, len) in [(13, 9 * 1024 * 1024 + 17), (20, 7 * 1024 * 1024 + 1)] {
            let shift = BlockShift::new(bits).unwrap();
            let stored_block = shift.block_len() + OVERHEAD;
            let plain = nonzero_pattern(len);
            let bytes = stored_file(&key_schedule(), shift, &plain);
            let files = MemFsBackend::new();
            let faulty = Faulty::new(files.clone());
            let layer = clear_blocks(faulty.clone(), shift).await;
            files.clone().with_file("f", &bytes);
            let handle = open_file(&layer, "f").await;

            let got = handle.read(0, len as u32).await.unwrap();
            assert!(got[..] == plain[..], "shift {bits}");
            let calls = block_reads(&faulty);
            assert!(calls.len() >= 2, "shift {bits}");
            let end = bytes.len() as u64;
            for &(offset, count) in &calls {
                assert!(count <= 4 << 20, "shift {bits}: {count} bytes");
                let from = offset - H as u64;
                let to = from + u64::from(count);
                assert_eq!(from % stored_block as u64, 0, "shift {bits}: start");
                assert!(
                    to.is_multiple_of(stored_block as u64) || to + H as u64 == end,
                    "shift {bits}: end"
                );
            }
            let total: u64 = calls.iter().map(|&(_, count)| u64::from(count)).sum();
            assert_eq!(total, end - H as u64, "shift {bits}");
        }
    }

    /// The stored bytes of a file of `blocks` full blocks that are holes.
    fn holes(shift: BlockShift, blocks: usize) -> Vec<u8> {
        let header = Header::new(shift, file_id()).unwrap();
        let mut bytes = header.as_bytes().to_vec();
        bytes.resize(H + blocks * (shift.block_len() + OVERHEAD), 0);
        bytes
    }

    #[tokio::test]
    async fn a_read_asks_the_inner_backend_for_the_blocks_it_covers_whatever_the_file_size() {
        const LEN: usize = 1 << 20;
        for bits in [13, 16, 20] {
            let shift = BlockShift::new(bits).unwrap();
            let block = shift.block_len();
            let limit = (LEN + 2 * (block + OVERHEAD)) as u64;
            let huge = stored_size(shift, 10 << 30).unwrap();
            for offset in [0, 1] {
                let files = MemFsBackend::new();
                let faulty = Faulty::new(files.clone());
                let layer = clear_blocks(faulty.clone(), shift).await;
                files.clone().with_file("f", &holes(shift, LEN / block + 1));
                faulty.report_size(Some(huge));
                let handle = open_file(&layer, "f").await;
                let before = faulty.reads().len();

                let got = handle.read(offset, LEN as u32).await.unwrap();
                assert!(
                    got.len() == LEN && got.iter().all(|&byte| byte == 0),
                    "shift {bits}, offset {offset}"
                );
                let asked: u64 = faulty.reads()[before..]
                    .iter()
                    .map(|&(_, count)| u64::from(count))
                    .sum();
                assert!(asked <= limit, "shift {bits}, offset {offset}: {asked}");
            }
        }
    }

    #[tokio::test]
    async fn offsets_near_the_largest_values_return_empty_or_an_error() {
        let plain = nonzero_pattern(2 * B + 10);
        let (_files, faulty, layer) = faulty_file(&stored(&plain)).await;
        let handle = open_file(&layer, "f").await;
        let beyond = [u64::MAX, u64::MAX - 5, 1 << 63, (1 << 63) - 1, 1 << 62];
        let lens = [0, 1, 10, u32::MAX];
        for offset in beyond {
            for len in lens {
                let got = handle.read(offset, len).await.unwrap();
                assert!(got.is_empty(), "offset {offset}, len {len}");
            }
        }

        // The stored file is the same, but it claims to be as large as a
        // stored file can be, so the offsets above are inside it.
        faulty.report_size(Some(MAX_STORED_SIZE));
        let logical = logical_size(shift(), MAX_STORED_SIZE).size;
        for offset in [u64::MAX, u64::MAX - 5, 1 << 63, logical] {
            for len in lens {
                let got = handle.read(offset, len).await.unwrap();
                assert!(got.is_empty(), "offset {offset}, len {len}");
            }
        }
        for offset in [1 << 62, logical - 1, logical - 10] {
            for len in [1, 10, 1 << 20] {
                let got = handle.read(offset, len).await;
                assert!(
                    matches!(got, Err(SmbError::Io(_))),
                    "offset {offset}, len {len}: {got:?}"
                );
            }
        }
    }

    #[tokio::test]
    async fn a_read_dropped_while_the_header_loads_leaves_the_file_readable() {
        let plain = nonzero_pattern(2 * B + 10);
        let (_, gated, layer) = gated_file(&stored(&plain)).await;
        let handle = open_file(&layer, "f").await;
        let file = handle.node().file().unwrap();

        let gate = gated.arm(Op::Read);
        drop_at(&gate, handle.read(0, 100)).await;
        assert!(file.try_write().is_ok(), "the lock is free");
        assert_eq!(handle.node().header().await, Some(HeaderKind::Unknown));

        assert_eq!(handle.read(0, 100).await.unwrap(), plain[..100]);
        assert_eq!(handle.node().header().await, Some(HeaderKind::Present));
    }

    #[tokio::test]
    async fn a_read_dropped_while_the_size_is_read_for_the_header_load_leaves_the_file_readable() {
        let plain = nonzero_pattern(2 * B + 10);
        let (_, gated, layer) = gated_file(&stored(&plain)).await;
        let handle = open_file(&layer, "f").await;
        let file = handle.node().file().unwrap();

        // The first stat is under the shared lock and the second under the
        // exclusive lock that loads the header.
        let shared = gated.arm(Op::Stat);
        let exclusive = gated.arm(Op::Stat);
        drop_at(&shared, handle.read(0, 100)).await;
        assert!(file.try_write().is_ok(), "the lock is free");

        let mut read = Box::pin(handle.read(0, 100));
        shared.release();
        tokio::select! {
            biased;
            _ = &mut read => panic!("the read ended before it reached the gate"),
            () = exclusive.reached() => {}
        }
        drop(read);
        assert!(file.try_write().is_ok(), "the lock is free");
        assert_eq!(handle.node().header().await, Some(HeaderKind::Unknown));

        assert_eq!(handle.read(0, 100).await.unwrap(), plain[..100]);
        assert_eq!(handle.node().header().await, Some(HeaderKind::Present));
    }

    #[tokio::test]
    async fn a_read_dropped_while_the_blocks_are_read_leaves_the_header_and_the_file_as_they_were()
    {
        let plain = nonzero_pattern(2 * B + 10);
        let (_, gated, layer) = gated_file(&stored(&plain)).await;
        let handle = open_file(&layer, "f").await;
        assert_eq!(handle.read(0, 10).await.unwrap(), plain[..10]);
        let file = handle.node().file().unwrap();

        let gate = gated.arm(Op::Read);
        drop_at(&gate, handle.read(B as u64, 100)).await;
        assert!(file.try_write().is_ok(), "the lock is free");
        assert_eq!(handle.node().header().await, Some(HeaderKind::Present));

        assert_eq!(handle.read(B as u64, 100).await.unwrap(), plain[B..B + 100]);
        assert_eq!(handle.node().header().await, Some(HeaderKind::Present));
    }

    #[tokio::test]
    async fn a_read_waits_for_a_writer_of_the_file() {
        let plain = nonzero_pattern(B);
        let (_, layer) = layer_with(&stored(&plain)).await;
        let handle = Arc::new(open_file(&layer, "f").await);
        let writing = handle.node().file().unwrap().write().await;

        let read = tokio::spawn({
            let handle = Arc::clone(&handle);
            async move { handle.read(0, 10).await }
        });
        settle().await;
        assert!(!read.is_finished());
        drop(writing);
        assert_eq!(read.await.unwrap().unwrap(), plain[..10]);
    }

    #[tokio::test]
    async fn two_readers_of_a_file_whose_header_is_unread_load_it_once() {
        let plain = nonzero_pattern(3 * B + 7);
        let files = MemFsBackend::new();
        let faulty = Faulty::new(files.clone());
        let gated = Gated::new(faulty.clone());
        let layer = layer_over(gated.clone()).await;
        files.clone().with_file("f", &stored(&plain));
        let a = open_file(&layer, "f").await;
        let b = open_file(&layer, "f").await;
        assert!(Arc::ptr_eq(a.node(), b.node()));

        let first = gated.arm(Op::Stat);
        let second = gated.arm(Op::Stat);
        let read_a = tokio::spawn(async move { a.read(0, 100).await });
        first.reached().await;
        let read_b = tokio::spawn(async move { b.read(B as u64, 100).await });
        second.reached().await;
        first.release();
        settle().await;
        assert!(
            !read_a.is_finished(),
            "the first reader waits for the second"
        );
        second.release();

        assert_eq!(read_a.await.unwrap().unwrap(), plain[..100]);
        assert_eq!(read_b.await.unwrap().unwrap(), plain[B..B + 100]);
        assert_eq!(header_reads(&faulty), 1);
    }
}
