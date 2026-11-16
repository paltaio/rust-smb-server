//! Writes to the contents of a file. The blocks a write covers are sealed
//! under fresh nonces. A block the data covers only in part is read first; a
//! failure there stores nothing.

use std::ops::Range;

use bytes::Bytes;
use tokio::sync::RwLock;

use super::block::FileCipher;
use super::change::{Attempt, Change, Normal, OsRandom, Random, random_error};
use super::content::Opened;
use super::format::{BlockShift, FILE_ID_LEN, HEADER_LEN, NONCE_LEN, OVERHEAD};
use super::handle::EncryptedHandle;
use super::header::Header;
use super::inner::write_blocks;
use super::node::FileMeta;
use super::size::{BlockRange, block_range, stored_size};
use crate::backend::ShareBackend;
use crate::error::{SmbError, SmbResult};

/// What reading the old blocks of a write gave.
enum Gathered {
    /// The old plaintext of the blocks that keep bytes, by block index.
    Old(Vec<(u64, Bytes)>),
    /// The index of the first block that does not open.
    Corrupt(u64),
}

/// Where the bytes of a write fall among the blocks of a file.
struct Span<'a> {
    shift: BlockShift,
    /// Bytes of the file before the write.
    logical: u64,
    data: &'a [u8],
    /// Where the data starts and ends in the file. The data is not empty.
    offset: u64,
    end: u64,
    /// The blocks the data touches.
    first: u64,
    last: u64,
    /// The old partial last block, when the data starts after it.
    pad: Option<u64>,
}

impl<'a> Span<'a> {
    fn new(shift: BlockShift, logical: u64, offset: u64, data: &'a [u8]) -> Self {
        let bits = shift.get();
        let end = offset + data.len() as u64;
        let first = offset >> bits;
        let old_last = logical >> bits;
        let partial = logical & (shift.block_size() - 1) != 0;
        Self {
            shift,
            logical,
            data,
            offset,
            end,
            first,
            last: (end - 1) >> bits,
            pad: (partial && first > old_last).then_some(old_last),
        }
    }

    fn new_logical(&self) -> u64 {
        self.logical.max(self.end)
    }

    /// Where block `index` starts in the plaintext.
    fn start(&self, index: u64) -> u64 {
        index << self.shift.get()
    }

    /// Plaintext bytes of block `index` after the write.
    fn plain_len(&self, index: u64) -> u64 {
        (self.new_logical() - self.start(index)).min(self.shift.block_size())
    }

    /// The data covers all of block `index`.
    fn covered(&self, index: u64) -> bool {
        let start = self.start(index);
        self.offset <= start && self.end >= start + self.plain_len(index)
    }

    /// Bytes block `index` holds before the write and keeps after it; `None`
    /// when the data replaces the block or the file has no such block.
    fn kept(&self, index: u64) -> Option<u32> {
        let start = self.start(index);
        if start >= self.logical || self.covered(index) {
            return None;
        }
        let kept = (self.logical - start).min(self.shift.block_size());
        Some(u32::try_from(kept).expect("a block is at most 1 MiB"))
    }

    /// The old blocks the write reads: the pad, then the first and the last
    /// block of the data.
    fn blocks_to_read(&self) -> Vec<u64> {
        let mut blocks: Vec<u64> = self.pad.into_iter().collect();
        blocks.push(self.first);
        if self.last != self.first {
            blocks.push(self.last);
        }
        blocks
    }

    /// The part of the data that falls in `plain`, the block that starts at
    /// `start`, copied over it.
    fn lay_over(&self, plain: &mut [u8], start: u64) {
        let from = self.offset.max(start);
        let to = self.end.min(start + plain.len() as u64);
        if from < to {
            plain[(from - start) as usize..(to - start) as usize].copy_from_slice(
                &self.data[(from - self.offset) as usize..(to - self.offset) as usize],
            );
        }
    }
}

/// The stored bytes of a change: a lead, which is the header of a new file or
/// the padded last block of the old one, and then the run of blocks the data
/// touches.
pub(super) struct Sealed {
    bytes: Vec<u8>,
    /// Bytes of `bytes` before the run.
    lead: usize,
    /// Where the lead and the run go in the stored file.
    lead_at: u64,
    run_at: u64,
    /// Where the padded block ends, when the lead is one.
    pad_end: Option<u64>,
}

/// One inner write: `range` of the sealed bytes at stored offset `at`.
struct Step {
    at: u64,
    range: Range<usize>,
    /// The end of the padded block, once this step is done.
    pad_end: Option<u64>,
}

impl Sealed {
    /// `bytes` as one piece stored at `at`: a header, or a block. `pad_end`
    /// is where the block ends when it is the padded last block of the old
    /// file.
    pub(super) fn alone(bytes: Vec<u8>, at: u64, pad_end: Option<u64>) -> Self {
        let lead = bytes.len();
        Self {
            bytes,
            lead,
            lead_at: at,
            run_at: at + lead as u64,
            pad_end,
        }
    }

    /// The inner writes that store the bytes, in order: the lead, then the
    /// run, as one write when they are next to each other. A write that
    /// crosses `stored_end`, the end of the stored file before the write, is
    /// two: the part from `stored_end` on first, then the part below it.
    fn steps(&self, stored_end: u64) -> Vec<Step> {
        let total = self.bytes.len();
        let lead_end = self.lead_at + self.lead as u64;
        let pieces = if self.lead == 0 {
            vec![(self.run_at, 0..total, None)]
        } else if lead_end == self.run_at {
            vec![(self.lead_at, 0..total, self.pad_end)]
        } else {
            vec![
                (self.lead_at, 0..self.lead, self.pad_end),
                (self.run_at, self.lead..total, None),
            ]
        };
        let mut steps = Vec::with_capacity(3);
        for (at, range, pad_end) in pieces {
            let len = (range.end - range.start) as u64;
            if at < stored_end && stored_end < at + len {
                let cut = range.start + (stored_end - at) as usize;
                steps.push(Step {
                    at: stored_end,
                    range: cut..range.end,
                    pad_end: None,
                });
                steps.push(Step {
                    at,
                    range: range.start..cut,
                    pad_end,
                });
            } else {
                steps.push(Step { at, range, pad_end });
            }
        }
        steps
    }
}

/// The plaintext of a block of `len` bytes: `old`, cut or followed by zeros.
fn padded(old: Option<Bytes>, len: usize) -> Vec<u8> {
    let mut plain = Vec::with_capacity(len);
    if let Some(old) = old {
        plain.extend_from_slice(&old);
    }
    plain.resize(len, 0);
    plain
}

/// Seals block `index` into `slot`: `old`, cut or followed by zeros to the
/// plaintext length the slot holds.
fn seal_padded(
    cipher: &FileCipher,
    index: u64,
    nonce: &[u8; NONCE_LEN],
    old: Option<Bytes>,
    slot: &mut [u8],
) {
    let plain = padded(old, slot.len() - OVERHEAD);
    cipher
        .seal_block(index, nonce, &plain, slot)
        .expect("slots are sized by the caller");
}

/// The stored bytes of block `index`, which is where `range` says: `old`, cut
/// or followed by zeros to the length of the block, under a nonce drawn from
/// `random`.
pub(super) fn seal_alone(
    cipher: &FileCipher,
    index: u64,
    old: Bytes,
    range: &BlockRange,
    random: &mut dyn Random,
) -> SmbResult<Vec<u8>> {
    let len = usize::try_from(range.stored_len).map_err(|_| SmbError::InvalidParameter)?;
    let mut nonce = [[0u8; NONCE_LEN]];
    random.nonces(&mut nonce).map_err(random_error)?;
    let mut bytes = vec![0u8; len];
    seal_padded(cipher, index, &nonce[0], Some(old), &mut bytes);
    Ok(bytes)
}

/// Seals the blocks `span` touches into one buffer, after `header` when the
/// file is new, or after the padded last block of the old file. `old` holds
/// the old plaintext of the blocks that keep bytes. One draw gives the nonces
/// of every block.
fn seal(
    cipher: &FileCipher,
    header: Option<&Header>,
    span: &Span<'_>,
    mut old: Vec<(u64, Bytes)>,
    random: &mut dyn Random,
) -> SmbResult<Sealed> {
    let shift = span.shift;
    let stored_block = shift.block_len() + OVERHEAD;
    let new_logical = span.new_logical();
    let run =
        block_range(shift, new_logical, span.first, span.last).ok_or(SmbError::InvalidParameter)?;
    let pad = match span.pad {
        Some(index) => {
            let range =
                block_range(shift, new_logical, index, index).ok_or(SmbError::InvalidParameter)?;
            Some((index, range))
        }
        None => None,
    };
    let lead = if header.is_some() {
        HEADER_LEN
    } else if pad.is_some() {
        stored_block
    } else {
        0
    };
    let run_len = usize::try_from(run.stored_len).map_err(|_| SmbError::InvalidParameter)?;
    let blocks =
        usize::try_from(span.last - span.first + 1).map_err(|_| SmbError::InvalidParameter)?;
    let total = lead
        .checked_add(run_len)
        .ok_or(SmbError::InvalidParameter)?;

    let mut nonces = vec![[0u8; NONCE_LEN]; blocks + usize::from(pad.is_some())];
    random.nonces(&mut nonces).map_err(random_error)?;
    let (pad_nonce, run_nonces) = nonces.split_at(usize::from(pad.is_some()));

    let mut take_old = |index: u64| {
        let at = old.iter().position(|(kept, _)| *kept == index)?;
        Some(old.swap_remove(at).1)
    };
    let mut bytes = vec![0u8; total];
    let (lead_bytes, run_bytes) = bytes.split_at_mut(lead);
    if let Some(header) = header {
        lead_bytes.copy_from_slice(header.as_bytes());
    }
    if let (Some((index, _)), [nonce]) = (&pad, pad_nonce) {
        seal_padded(cipher, *index, nonce, take_old(*index), lead_bytes);
    }
    for ((slot, nonce), index) in run_bytes
        .chunks_mut(stored_block)
        .zip(run_nonces)
        .zip(span.first..)
    {
        let plain_len = slot.len() - OVERHEAD;
        let start = span.start(index);
        let sealed = if span.covered(index) {
            let from = (start - span.offset) as usize;
            cipher.seal_block(index, nonce, &span.data[from..from + plain_len], slot)
        } else {
            let mut plain = padded(take_old(index), plain_len);
            span.lay_over(&mut plain, start);
            cipher.seal_block(index, nonce, &plain, slot)
        };
        sealed.expect("slots are sized by the span");
    }

    Ok(Sealed {
        bytes,
        lead,
        lead_at: match (header, &pad) {
            (Some(_), _) => 0,
            (None, Some((_, range))) => range.offset,
            (None, None) => run.offset,
        },
        run_at: run.offset,
        pad_end: pad.map(|(_, range)| range.offset + range.stored_len),
    })
}

impl<B: ShareBackend> EncryptedHandle<B> {
    /// Writes `data` at `offset` of the file: all of it, or an error.
    pub(super) async fn write_file(
        &self,
        file: &RwLock<FileMeta>,
        offset: u64,
        data: &[u8],
    ) -> SmbResult<u32> {
        self.write_with(file, offset, data, &mut OsRandom).await
    }

    async fn write_with(
        &self,
        file: &RwLock<FileMeta>,
        offset: u64,
        data: &[u8],
        random: &mut dyn Random,
    ) -> SmbResult<u32> {
        if data.is_empty() {
            return Ok(0);
        }
        let shift = self.shared.settings.block_shift;
        let accepted = u32::try_from(data.len()).map_err(|_| SmbError::InvalidParameter)?;
        if offset
            .checked_add(u64::from(accepted))
            .is_none_or(|end| stored_size(shift, end).is_none())
        {
            return Err(SmbError::InvalidParameter);
        }
        self.change_file(file, Change::Write { offset, data }, random)
            .await?;
        Ok(accepted)
    }

    /// One try at a write, under the lock of the file. The stored file is
    /// normalized first.
    pub(super) async fn write_once(
        &self,
        meta: &mut FileMeta,
        offset: u64,
        data: &[u8],
        random: &mut dyn Random,
    ) -> SmbResult<Attempt> {
        let Normal { logical, end } = self.normalize().await?;
        let taken = self.take_header(meta, end, random).await?;
        let span = Span::new(self.shared.settings.block_shift, logical, offset, data);
        let lead = taken.fresh.then_some(&taken.header);
        let attempt = self
            .rewrite(
                &span,
                lead,
                taken.header.file_id(),
                &taken.cipher,
                end,
                random,
            )
            .await;
        let done = matches!(attempt, Ok(Attempt::Done));
        taken.put_back(meta, done);
        attempt
    }

    /// Reads the old blocks `span` keeps bytes of, seals the new ones and
    /// stores them, in a stored file of `stored_end` bytes. `lead` is the
    /// header of a new file, which goes into the stored file too. `used` is
    /// the id of the file `cipher` belongs to.
    async fn rewrite(
        &self,
        span: &Span<'_>,
        lead: Option<&Header>,
        used: [u8; FILE_ID_LEN],
        cipher: &FileCipher,
        stored_end: u64,
        random: &mut dyn Random,
    ) -> SmbResult<Attempt> {
        let old = match self.gather(cipher, span).await? {
            Gathered::Old(old) => old,
            Gathered::Corrupt(block) => return Ok(Attempt::Corrupt { block, used }),
        };
        let sealed = seal(cipher, lead, span, old, random)?;
        self.store(&sealed, stored_end).await?;
        Ok(Attempt::Done)
    }

    /// Reads and opens the old blocks `span` keeps bytes of.
    async fn gather(&self, cipher: &FileCipher, span: &Span<'_>) -> SmbResult<Gathered> {
        let mut old = Vec::new();
        for index in span.blocks_to_read() {
            let Some(len) = span.kept(index) else {
                continue;
            };
            match self
                .read_range(cipher, span.logical, span.start(index), len)
                .await?
            {
                Opened::Data(bytes) => old.push((index, bytes)),
                Opened::Corrupt(block) => return Ok(Gathered::Corrupt(block)),
            }
        }
        Ok(Gathered::Old(old))
    }

    /// Writes `sealed` into the stored file, which has `stored_end` bytes.
    ///
    /// What goes past the end of the stored file is written before what
    /// overwrites old bytes. A write that fails at or past `safe_end` cuts the
    /// stored file back to it. `safe_end` is the old end, and the end of the
    /// padded block once that block is whole; no block that held data is cut.
    /// A write that fails below the old end cuts nothing, and the blocks it
    /// overwrites can be torn.
    pub(super) async fn store(&self, sealed: &Sealed, stored_end: u64) -> SmbResult<()> {
        let shift = self.shared.settings.block_shift;
        let mut safe_end = stored_end;
        for step in sealed.steps(stored_end) {
            let bytes = &sealed.bytes[step.range];
            if let Err(error) = write_blocks(&*self.inner, shift, step.at, bytes).await {
                if step.at >= safe_end {
                    // Best effort; the write error is the one returned.
                    let _ = self.inner.truncate(safe_end).await;
                }
                return Err(error);
            }
            if let Some(end) = step.pad_end {
                safe_end = end;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;
    use std::io;
    use std::sync::Arc;

    use super::super::format::MAX_STORED_SIZE;
    use super::super::inner::assert_calls;
    use super::super::node::HeaderKind;
    use super::super::size::logical_size;
    use super::super::testing::{
        B, BITS, C, Counting, Down, H, assert_err, assert_io, assert_no_wait, at, block_reads,
        clear_blocks, drop_at, faulty_file, faulty_file_in, file_id, gated_file, header_reads,
        key_schedule, layer_over, new_file, nonce_at, open, open_file, other_file_id, read_all,
        settle, shift, stored, stored_file, stored_file_with_id, stored_len, writes_since,
    };
    use super::*;
    use crate::backend::{Handle, OpenAction, OpenIntent};
    use crate::tests::data::{apply, pattern};
    use crate::tests::faulty::Faulty;
    use crate::tests::gated::{Gated, Op};
    use crate::tests::logs::Logs;
    use crate::tests::memfs::MemFsBackend;

    #[tokio::test]
    async fn data_written_at_the_block_edges_reads_back_and_leaves_the_stored_size_of_its_length() {
        let offsets = [0, 1, B - 1, B, B + 1, 2 * B - 1, 2 * B, 3 * B + 40];
        let lens = [1, 2, B - 1, B, B + 1, 2 * B + 3];
        for offset in offsets {
            for len in lens {
                let (files, _, handle) = new_file().await;
                let mut model = pattern(3 * B + 100, 1);
                let written = handle.write_owned(0, model.clone()).await.unwrap();
                assert_eq!(written, model.len() as u32);
                assert_eq!(read_all(&handle).await, model, "offset {offset}");

                let data = pattern(len, 2);
                assert_eq!(
                    handle.write(offset as u64, &data).await.unwrap(),
                    len as u32
                );
                apply(&mut model, offset, &data);
                assert_eq!(read_all(&handle).await, model, "offset {offset}, len {len}");
                assert_eq!(
                    files.contents("f").unwrap().len(),
                    stored_len(model.len()),
                    "offset {offset}, len {len}"
                );
            }
        }
    }

    #[tokio::test]
    async fn a_file_built_from_small_writes_in_order_reads_back() {
        let (files, _, handle) = new_file().await;
        let mut model = Vec::new();
        let mut offset = 0;
        for (n, len) in [1, 7, B - 8, 1, B, 5 * B + 3, 2].into_iter().enumerate() {
            let data = pattern(len, n as u8);
            handle.write(offset as u64, &data).await.unwrap();
            apply(&mut model, offset, &data);
            offset += len;
            assert_eq!(read_all(&handle).await, model, "after write {n}");
            assert_eq!(files.contents("f").unwrap().len(), stored_len(model.len()));
        }
    }

    #[tokio::test]
    async fn writes_inside_holes_and_one_block_past_the_end_read_back() {
        let (files, _, handle) = new_file().await;
        let mut model = Vec::new();
        for (offset, len) in [
            (0, 100),
            (4 * B + 10, 20),
            (2 * B + 7, 30),
            (3 * B, B),
            (4 * B + 30 + B, 10),
            (B + 3, 1),
        ] {
            let data = pattern(len, len as u8);
            handle.write(offset as u64, &data).await.unwrap();
            apply(&mut model, offset, &data);
            assert_eq!(read_all(&handle).await, model, "write at {offset}");
        }
        assert_eq!(files.contents("f").unwrap().len(), stored_len(model.len()));
    }

    #[tokio::test]
    async fn the_blocks_of_a_gap_are_stored_as_zeros_and_read_as_zeros() {
        let (files, faulty, handle) = new_file().await;
        handle.write(0, &pattern(10, 1)).await.unwrap();
        let data = pattern(10, 2);
        handle.write(5 * B as u64 + 3, &data).await.unwrap();

        let bytes = files.contents("f").unwrap();
        let hole = &bytes[at(1)..at(5)];
        assert!(hole.iter().all(|&byte| byte == 0));
        let model = {
            let mut model = pattern(10, 1);
            apply(&mut model, 5 * B + 3, &data);
            model
        };
        assert_eq!(read_all(&handle).await, model);
        assert_eq!(
            handle.read(B as u64, 4 * B as u32).await.unwrap(),
            vec![0; 4 * B]
        );
        let sent: usize = faulty.write_calls().iter().map(|&(_, len)| len).sum();
        assert!(sent < 3 * C, "the gap is not sent: {sent} bytes");
    }

    #[tokio::test]
    async fn a_write_10_gib_past_the_end_sends_nothing_of_the_gap() {
        const FAR: u64 = 10 << 30;
        let run_at = H as u64 + (FAR >> BITS) * C as u64;
        let run_len = 5 + 100 + OVERHEAD;
        let end = FAR + 5 + 100;
        let data = pattern(100, 3);

        // A new file: a header and the block.
        let (_files, faulty, handle) = new_file().await;
        faulty.sink_writes_from(Some(1 << 30));
        let before = faulty.write_calls().len();
        assert_eq!(handle.write(FAR + 5, &data).await.unwrap(), 100);
        assert_eq!(writes_since(&faulty, before), [(0, H), (run_at, run_len)]);
        assert_eq!(run_at + run_len as u64, stored_size(shift(), end).unwrap());

        // A file with a partial last block: its pad, then the block.
        let (_files, faulty, handle) = new_file().await;
        handle.write(0, &pattern(100, 1)).await.unwrap();
        faulty.sink_writes_from(Some(1 << 30));
        let before = faulty.write_calls().len();
        handle.write(FAR + 5, &data).await.unwrap();
        let old_end = at(0) + 100 + OVERHEAD;
        assert_eq!(
            writes_since(&faulty, before),
            [
                (old_end as u64, at(1) - old_end),
                (at(0) as u64, old_end - at(0)),
                (run_at, run_len),
            ]
        );

        // A file of whole blocks needs no pad.
        let (_files, faulty, handle) = new_file().await;
        handle.write(0, &pattern(B, 1)).await.unwrap();
        faulty.sink_writes_from(Some(1 << 30));
        let before = faulty.write_calls().len();
        handle.write(FAR + 5, &data).await.unwrap();
        assert_eq!(writes_since(&faulty, before), [(run_at, run_len)]);
    }

    #[tokio::test]
    async fn a_write_past_a_partial_last_block_pads_it_with_zeros_to_the_end_of_the_block() {
        let plain = pattern(B / 2 + 5, 1);
        for offset in [B / 2 + 5, B / 2 + 9, B, B + 3, 2 * B, 3 * B + 7] {
            let (files, faulty, layer) = faulty_file(&stored(&plain)).await;
            let handle = open_file(&layer, "f").await;
            let before = files.contents("f").unwrap();
            let calls = faulty.write_calls().len();

            let data = pattern(10, 2);
            handle.write(offset as u64, &data).await.unwrap();
            let mut model = plain.clone();
            apply(&mut model, offset, &data);
            assert_eq!(read_all(&handle).await, model, "offset {offset}");

            let after = files.contents("f").unwrap();
            assert_eq!(after.len(), stored_len(model.len()), "offset {offset}");
            assert_eq!(after[..H], before[..H], "the header is kept");
            let first = offset >> BITS;
            if first > 0 {
                assert_ne!(
                    nonce_at(&after, at(0)),
                    nonce_at(&before, at(0)),
                    "offset {offset}"
                );
                let pad = handle
                    .read(plain.len() as u64, (B - plain.len()) as u32)
                    .await;
                assert_eq!(pad.unwrap(), vec![0; B - plain.len()], "offset {offset}");
            }
            if first > 1 {
                assert!(
                    after[at(1)..at(first)].iter().all(|&byte| byte == 0),
                    "offset {offset}: the gap is stored as zeros"
                );
            }
            let expected_calls = if first >= 2 { 3 } else { 2 };
            assert_eq!(
                writes_since(&faulty, calls).len(),
                expected_calls,
                "offset {offset}"
            );
        }
    }

    #[tokio::test]
    async fn a_header_only_file_gets_a_new_file_id_on_its_first_write() {
        let planted = stored(&[1])[..H].to_vec();
        for offset in [0, 5, B + 3] {
            let (files, _, layer) = faulty_file(&planted).await;
            let handle = open_file(&layer, "f").await;
            let data = pattern(10, 4);
            handle.write(offset as u64, &data).await.unwrap();

            let bytes = files.contents("f").unwrap();
            assert_eq!(bytes[..8], planted[..8]);
            assert_ne!(bytes[8..H], file_id()[..], "offset {offset}");
            let mut model = Vec::new();
            apply(&mut model, offset, &data);
            assert_eq!(read_all(&handle).await, model, "offset {offset}");
            assert_eq!(bytes.len(), stored_len(model.len()));
            assert_eq!(handle.node().header().await, Some(HeaderKind::Present));
        }
    }

    #[tokio::test]
    async fn a_torn_header_is_cut_off_before_the_write() {
        for junk in [1, 10, 23] {
            let (files, faulty, layer) = faulty_file(&vec![9; junk]).await;
            let handle = open_file(&layer, "f").await;
            let data = pattern(5, 4);
            handle.write(3, &data).await.unwrap();

            let bytes = files.contents("f").unwrap();
            assert_eq!(bytes[..4], b"smbe"[..], "junk {junk}");
            assert_eq!(bytes.len(), stored_len(8));
            assert_eq!(read_all(&handle).await, [&[0; 3][..], &data].concat());
            assert_eq!(faulty.truncates(), 1, "junk {junk}");
        }
    }

    #[tokio::test]
    async fn a_fragment_after_the_last_block_is_cut_off_before_the_write() {
        let plain = pattern(B, 1);
        for extra in [1, 7, OVERHEAD] {
            let mut bytes = stored(&plain);
            bytes.extend(vec![7; extra]);
            for offset in [10, B, B + 5, 3 * B + 7] {
                let (files, faulty, layer) = faulty_file(&bytes).await;
                let handle = open_file(&layer, "f").await;
                let data = pattern(9, 2);
                handle.write(offset as u64, &data).await.unwrap();

                let mut model = plain.clone();
                apply(&mut model, offset, &data);
                assert_eq!(
                    read_all(&handle).await,
                    model,
                    "extra {extra}, offset {offset}"
                );
                let after = files.contents("f").unwrap();
                assert_eq!(after.len(), stored_len(model.len()));
                assert_eq!(faulty.truncates(), 1);
                let first = offset >> BITS;
                if first > 0 {
                    assert_eq!(after[..at(1)], bytes[..at(1)], "block 0 is kept");
                }
                if first > 1 {
                    assert!(
                        after[at(1)..at(first)].iter().all(|&byte| byte == 0),
                        "extra {extra}, offset {offset}: no byte of the fragment is left in the gap"
                    );
                }
            }
        }
    }

    #[tokio::test]
    async fn a_stored_file_of_a_normal_size_is_not_cut() {
        let plain = pattern(2 * B + 40, 1);
        let (_files, faulty, layer) = faulty_file(&stored(&plain)).await;
        let handle = open_file(&layer, "f").await;
        handle.write(5, b"abc").await.unwrap();
        handle.write(2 * B as u64 + 40, b"abc").await.unwrap();
        assert_eq!(faulty.truncates(), 0);
    }

    #[tokio::test]
    async fn a_write_that_is_empty_returns_0_and_takes_no_lock() {
        let (_files, faulty, layer) = faulty_file(&stored(&pattern(10, 1))).await;
        let handle = open_file(&layer, "f").await;
        let _writing = handle.node().file().unwrap().write().await;
        let before = (faulty.write_calls().len(), faulty.reads().len());
        assert_eq!(assert_no_wait(handle.write(3, b"")).await.unwrap(), 0);
        assert_eq!((faulty.write_calls().len(), faulty.reads().len()), before);
    }

    #[tokio::test]
    async fn a_write_waits_for_every_other_holder_of_the_file_lock() {
        let (_files, _, layer) = faulty_file(&stored(&pattern(10, 1))).await;
        let handle = Arc::new(open_file(&layer, "f").await);
        let reading = handle.node().file().unwrap().read().await;
        let write = tokio::spawn({
            let handle = Arc::clone(&handle);
            async move { handle.write(0, b"x").await }
        });
        settle().await;
        assert!(!write.is_finished());
        drop(reading);
        assert_eq!(write.await.unwrap().unwrap(), 1);
        let plain = pattern(10, 1);
        assert_eq!(
            handle.read(0, 3).await.unwrap(),
            [b'x', plain[1], plain[2]][..]
        );
    }

    #[tokio::test]
    async fn two_handles_writing_different_bytes_of_one_block_both_land() {
        let plain = pattern(3 * B + 100, 1);
        let (_, gated, layer) = gated_file(&stored(&plain)).await;
        let a = Arc::new(open_file(&layer, "f").await);
        let b = Arc::new(open_file(&layer, "f").await);
        assert!(Arc::ptr_eq(a.node(), b.node()));
        assert_eq!(a.read(0, 1).await.unwrap().len(), 1);

        let gate = gated.arm(Op::Read);
        let first = tokio::spawn({
            let a = Arc::clone(&a);
            async move { a.write(100, b"aaaa").await }
        });
        gate.reached().await;
        let second = tokio::spawn({
            let b = Arc::clone(&b);
            async move { b.write(5000, b"bbbb").await }
        });
        settle().await;
        assert!(
            !second.is_finished(),
            "the second write waits for the first"
        );
        gate.release();
        assert_eq!(first.await.unwrap().unwrap(), 4);
        assert_eq!(second.await.unwrap().unwrap(), 4);

        let mut model = plain;
        apply(&mut model, 100, b"aaaa");
        apply(&mut model, 5000, b"bbbb");
        assert_eq!(read_all(&*a).await, model);
    }

    #[tokio::test]
    async fn a_write_is_never_cut_short_whatever_the_inner_backend_takes() {
        let plain = pattern(3 * B + 100, 1);
        for max in [1, 5, 1000, 100_000] {
            let (files, faulty, layer) = faulty_file(&stored(&plain)).await;
            faulty.short_writes(Some(max));
            let handle = open_file(&layer, "f").await;
            let data = pattern(2 * B + 17, 2);
            let mut model = plain.clone();
            for offset in [10, 2 * B + 50, 5 * B + 3] {
                let taken = handle.write(offset as u64, &data).await.unwrap();
                assert_eq!(taken, data.len() as u32, "max {max}, offset {offset}");
                apply(&mut model, offset, &data);
            }
            assert_eq!(read_all(&handle).await, model, "max {max}");
            assert_eq!(files.contents("f").unwrap().len(), stored_len(model.len()));
        }
    }

    #[tokio::test]
    async fn an_inner_backend_that_takes_nothing_fails_the_write_and_leaves_the_file_as_it_was() {
        let plain = pattern(3 * B + 100, 1);
        let bytes = stored(&plain);
        let (files, faulty, layer) = faulty_file(&bytes).await;
        let handle = open_file(&layer, "f").await;
        faulty.short_writes(Some(0));

        assert_io(handle.write(5, b"abc").await, io::ErrorKind::WriteZero);
        assert_io(
            handle.write(plain.len() as u64, b"abc").await,
            io::ErrorKind::WriteZero,
        );
        assert_io(
            handle.write(6 * B as u64, b"abc").await,
            io::ErrorKind::WriteZero,
        );
        assert_eq!(files.contents("f").unwrap(), bytes);

        faulty.short_writes(None);
        assert_eq!(handle.write(5, b"abc").await.unwrap(), 3);
    }

    #[tokio::test]
    async fn a_write_whose_stored_end_passes_the_largest_stored_size_is_invalid() {
        let edge = logical_size(shift(), MAX_STORED_SIZE).size;
        let (files, faulty, handle) = new_file().await;
        faulty.sink_writes_from(Some(1 << 32));
        let before = faulty.write_calls().len();

        assert_eq!(handle.write(edge - 1, b"x").await.unwrap(), 1);
        let last = *writes_since(&faulty, before).last().unwrap();
        let end = last.0 + last.1 as u64;
        assert_eq!(Some(end), stored_size(shift(), edge));
        assert!(end <= MAX_STORED_SIZE);

        let before = faulty.write_calls().len();
        let stored_before = files.contents("f").unwrap();
        for (offset, len) in [
            (edge, 1),
            (edge - 1, 2),
            (edge - 10, 20),
            (1 << 63, 1),
            (u64::MAX, 1),
            (u64::MAX - 5, 10),
            (u64::MAX - 5, 5),
        ] {
            assert_err(
                handle.write(offset, &vec![1; len]).await,
                SmbError::InvalidParameter,
            );
        }
        assert_eq!(writes_since(&faulty, before), []);
        assert_eq!(faulty.truncates(), 0);
        assert_eq!(files.contents("f").unwrap(), stored_before);
    }

    #[tokio::test]
    async fn an_offset_that_is_invalid_is_refused_before_the_lock_is_taken() {
        let (_files, _, layer) = faulty_file(&stored(&pattern(10, 1))).await;
        let handle = open_file(&layer, "f").await;
        let _writing = handle.node().file().unwrap().write().await;
        assert_err(
            assert_no_wait(handle.write(u64::MAX, b"x")).await,
            SmbError::InvalidParameter,
        );
    }

    #[tokio::test]
    async fn a_stored_file_that_claims_more_than_the_largest_size_refuses_the_write() {
        let (_files, faulty, layer) = faulty_file(&stored(&pattern(10, 1))).await;
        let handle = open_file(&layer, "f").await;
        faulty.report_size(Some(u64::MAX));
        let writes = faulty.write_calls().len();
        assert_err(handle.write(0, b"x").await, SmbError::InvalidParameter);
        assert_eq!(
            (faulty.truncates(), faulty.write_calls().len()),
            (0, writes)
        );
    }

    #[tokio::test]
    async fn a_block_rewritten_gets_a_new_nonce_and_the_nonces_of_one_write_differ() {
        let (files, _, handle) = new_file().await;
        let data = pattern(4 * B + 9, 1);
        handle.write(0, &data).await.unwrap();
        let first = files.contents("f").unwrap();
        handle.write(0, &data).await.unwrap();
        let second = files.contents("f").unwrap();

        assert_eq!(first[..H], second[..H], "the header is the same");
        for index in 0..5 {
            assert_ne!(
                nonce_at(&first, at(index)),
                nonce_at(&second, at(index)),
                "block {index}"
            );
            assert_ne!(
                first[at(index) + NONCE_LEN..at(index) + 20],
                second[at(index) + NONCE_LEN..at(index) + 20],
                "block {index}: the same bytes give other ciphertext"
            );
        }
        let nonces: HashSet<_> = (0..5).map(|index| nonce_at(&first, at(index))).collect();
        assert_eq!(nonces.len(), 5);
        assert!(
            nonces
                .iter()
                .all(|nonce| nonce.iter().any(|&byte| byte != 0))
        );

        let mut seen = HashSet::new();
        for _ in 0..100 {
            handle.write(B as u64 + 1, b"x").await.unwrap();
            let bytes = files.contents("f").unwrap();
            assert!(seen.insert(nonce_at(&bytes, at(1))));
        }
    }

    #[tokio::test]
    async fn one_draw_gives_the_nonces_of_every_block_a_write_seals() {
        let (_files, _, handle) = new_file().await;
        let file = handle.node().file().unwrap();
        let mut random = Counting::default();

        // Four blocks of a new file, and its file id.
        let data = pattern(3 * B + 5, 1);
        handle
            .write_with(file, 0, &data, &mut random)
            .await
            .unwrap();
        // Blocks 3 to 5 of a file that has a header.
        let data = pattern(2 * B, 2);
        handle
            .write_with(file, (3 * B + 5) as u64, &data, &mut random)
            .await
            .unwrap();
        // Block 9 and the padded block 5 before it.
        handle
            .write_with(file, (9 * B) as u64, b"0123456789", &mut random)
            .await
            .unwrap();
        // One block, partly covered.
        handle.write_with(file, 0, b"x", &mut random).await.unwrap();

        assert_eq!(random.draws, [4, 3, 2, 1]);
        assert_eq!(random.ids, 1);
    }

    #[tokio::test]
    async fn a_generator_that_does_not_answer_fails_the_write_before_anything_is_stored() {
        let (files, faulty, handle) = new_file().await;
        let file = handle.node().file().unwrap();
        let before = faulty.write_calls().len();
        assert_io(
            handle.write_with(file, 0, b"abc", &mut Down).await,
            io::ErrorKind::Other,
        );
        assert_eq!(writes_since(&faulty, before), []);
        assert_eq!(files.contents("f"), Some(Vec::new()));
        assert_eq!(handle.node().header().await, Some(HeaderKind::Absent));
        assert_eq!(handle.write(0, b"abc").await.unwrap(), 3);

        let bytes = files.contents("f").unwrap();
        assert_io(
            handle.write_with(file, 1, b"zz", &mut Down).await,
            io::ErrorKind::Other,
        );
        assert_eq!(files.contents("f"), Some(bytes));
        assert_eq!(handle.node().header().await, Some(HeaderKind::Present));
        assert_eq!(read_all(&handle).await, b"abc");
    }

    #[tokio::test]
    async fn a_partial_write_over_a_corrupt_block_fails_and_stores_nothing() {
        let logs = Logs::new();
        let len = 3 * B + 100;
        let plain = pattern(len, 1);
        let mut bytes = stored(&plain);
        bytes[at(1) + 40] ^= 0x80;
        let (files, faulty, layer) = faulty_file(&bytes).await;
        let handle = open_file(&layer, "f").await;
        let writes = faulty.write_calls().len();

        let data = pattern(50, 2);
        for offset in [B + 10, B - 5, 2 * B - 10, 2 * B - 50] {
            assert_io(
                handle.write(offset as u64, &data).await,
                io::ErrorKind::InvalidData,
            );
        }
        assert_eq!(files.contents("f").unwrap(), bytes);
        assert_eq!(
            (faulty.write_calls().len(), faulty.truncates()),
            (writes, 0)
        );
        let warnings = logs.warnings();
        assert_eq!(warnings.len(), 4, "{warnings:?}");
        assert!(
            warnings.iter().all(|line| line.contains("block=1")),
            "{warnings:?}"
        );
        assert_eq!(
            header_reads(&faulty),
            1 + 4,
            "one load, then one reload for each write"
        );

        assert_eq!(handle.write(0, &data).await.unwrap(), 50);
        assert_eq!(handle.write(2 * B as u64, &data).await.unwrap(), 50);
        assert_eq!(handle.write(len as u64, &data).await.unwrap(), 50);
    }

    #[tokio::test]
    async fn a_write_that_covers_a_whole_block_that_fails_authentication_replaces_it() {
        let len = 3 * B + 100;
        let plain = pattern(len, 1);
        let mut bytes = stored(&plain);
        bytes[at(1) + 40] ^= 0x80;
        let (_files, _, layer) = faulty_file(&bytes).await;
        let handle = open_file(&layer, "f").await;
        assert_io(handle.read(B as u64, 1).await, io::ErrorKind::InvalidData);

        let data = pattern(B, 2);
        assert_eq!(handle.write(B as u64, &data).await.unwrap(), B as u32);
        let mut model = plain;
        apply(&mut model, B, &data);
        assert_eq!(read_all(&handle).await, model);
    }

    #[tokio::test]
    async fn a_file_replaced_from_outside_is_written_once_the_header_reloads() {
        let logs = Logs::new();
        let old = pattern(2 * B + 10, 1);
        let new = pattern(2 * B + 10, 2);
        let (files, faulty, layer) = faulty_file(&stored(&old)).await;
        let handle = open_file(&layer, "f").await;
        handle.write(5, b"ab").await.unwrap();
        let loaded = header_reads(&faulty);

        let replaced = stored_file_with_id(&key_schedule(), shift(), other_file_id(), &new);
        files.clone().with_file("f", &replaced);
        assert_eq!(handle.write(B as u64 + 5, b"cd").await.unwrap(), 2);

        let mut model = new;
        apply(&mut model, B + 5, b"cd");
        assert_eq!(read_all(&handle).await, model);
        assert_eq!(header_reads(&faulty), loaded + 1);
        assert_eq!(files.contents("f").unwrap()[8..H], other_file_id()[..]);
        assert!(logs.warnings().is_empty());
    }

    #[tokio::test]
    async fn a_replaced_file_that_is_corrupt_too_fails_a_write_after_one_reload() {
        let logs = Logs::new();
        let len = 2 * B + 10;
        let (files, faulty, layer) = faulty_file(&stored(&pattern(len, 1))).await;
        let handle = open_file(&layer, "f").await;
        handle.write(5, b"ab").await.unwrap();
        let loaded = header_reads(&faulty);
        let blocks = block_reads(&faulty).len();
        let writes = faulty.write_calls().len();

        let mut replaced =
            stored_file_with_id(&key_schedule(), shift(), other_file_id(), &pattern(len, 2));
        replaced[at(1) + 40] ^= 0x80;
        files.clone().with_file("f", &replaced);
        assert_io(
            handle.write(B as u64 + 5, b"cd").await,
            io::ErrorKind::InvalidData,
        );
        assert_eq!(header_reads(&faulty), loaded + 1, "one reload");
        assert_eq!(
            block_reads(&faulty).len(),
            blocks + 2,
            "a failure, one retry"
        );
        assert_eq!(faulty.write_calls().len(), writes);
        assert_eq!(files.contents("f").unwrap(), replaced);
        assert_eq!(logs.warnings().len(), 1);
    }

    #[tokio::test]
    async fn a_node_without_a_header_gets_a_new_file_id_for_a_write() {
        let files = MemFsBackend::new();
        let layer = layer_over(files.clone()).await;
        let (handle, action) = open(&layer, "g", OpenIntent::Create).await;
        assert_eq!(action, OpenAction::Created);
        assert_eq!(handle.node().header().await, Some(HeaderKind::Absent));
        handle.write(0, b"abc").await.unwrap();
        assert_eq!(handle.node().header().await, Some(HeaderKind::Present));
        let first = files.contents("g").unwrap()[8..H].to_vec();

        let (again, action) = open(&layer, "g", OpenIntent::Truncate).await;
        assert_eq!(action, OpenAction::Overwritten);
        assert_eq!(files.contents("g"), Some(Vec::new()));
        assert_eq!(again.node().header().await, Some(HeaderKind::Absent));
        again.write(0, b"xyz").await.unwrap();
        assert_ne!(files.contents("g").unwrap()[8..H], first[..]);
        assert_eq!(read_all(&handle).await, b"xyz");
    }

    #[tokio::test]
    async fn a_node_without_a_header_loads_the_one_a_file_got_from_outside() {
        let files = MemFsBackend::new();
        let layer = layer_over(files.clone()).await;
        let (handle, _) = open(&layer, "g", OpenIntent::Create).await;
        assert_eq!(handle.node().header().await, Some(HeaderKind::Absent));

        let plain = pattern(2 * B + 10, 1);
        files.clone().with_file("g", &stored(&plain));
        handle.write(B as u64 + 5, b"ab").await.unwrap();
        let mut model = plain;
        apply(&mut model, B + 5, b"ab");
        assert_eq!(read_all(&handle).await, model);
        assert_eq!(files.contents("g").unwrap()[8..H], file_id()[..]);
    }

    #[tokio::test]
    async fn one_inner_call_of_a_write_moves_whole_blocks_and_at_most_4_mib() {
        for (bits, len) in [(13, 9 * 1024 * 1024 + 17), (20, 7 * 1024 * 1024 + 1)] {
            let shift = BlockShift::new(bits).unwrap();
            let block = shift.stored_block_size();
            let files = MemFsBackend::new();
            let faulty = Faulty::new(files.clone());
            let layer = clear_blocks(faulty.clone(), shift).await;
            let (handle, _) = open(&layer, "f", OpenIntent::Create).await;

            let plain = pattern(len, 1);
            let before = faulty.write_calls().len();
            assert_eq!(handle.write(0, &plain).await.unwrap(), len as u32);
            let end = stored_size(shift, len as u64).unwrap();
            let calls = writes_since(&faulty, before);
            assert!(calls.len() >= 2, "shift {bits}");
            assert_calls(&calls, block, 0, end, &format!("shift {bits}"));

            // The new bytes go from the end of the file, past the old
            // partial block, and the old block's own part follows.
            let more = pattern(9 * 1024 * 1024 + 5, 2);
            let before = faulty.write_calls().len();
            handle.write(len as u64, &more).await.unwrap();
            let new_end = stored_size(shift, (len + more.len()) as u64).unwrap();
            let calls = writes_since(&faulty, before);
            let (below, above) = calls.split_last().unwrap();
            assert!(above.len() >= 3, "shift {bits}");
            assert_calls(above, block, end, new_end, &format!("shift {bits}"));
            let block_start = H as u64 + (len as u64 >> bits) * block;
            assert_eq!(*below, (block_start, (end - block_start) as usize));

            let mut model = plain;
            model.extend_from_slice(&more);
            assert!(read_all(&handle).await == model, "shift {bits}");
        }
    }

    #[tokio::test]
    async fn a_failed_write_to_a_new_file_cuts_it_back_to_empty_and_caches_no_header() {
        for fail in [1, 2] {
            let (files, faulty, handle) = new_file().await;
            faulty.fail_write(fail, SmbError::DiskFull);
            assert_err(
                handle.write(2 * B as u64 + 5, &pattern(10, 1)).await,
                SmbError::DiskFull,
            );
            assert_eq!(files.contents("f"), Some(Vec::new()), "write {fail}");
            assert_eq!(faulty.truncates(), 1);
            assert_eq!(handle.node().header().await, Some(HeaderKind::Absent));
            assert!(handle.read(0, 10).await.unwrap().is_empty());

            let data = pattern(10, 2);
            assert_eq!(handle.write(2 * B as u64 + 5, &data).await.unwrap(), 10);
            let mut model = Vec::new();
            apply(&mut model, 2 * B + 5, &data);
            assert_eq!(read_all(&handle).await, model);
            assert_eq!(handle.node().header().await, Some(HeaderKind::Present));
        }
    }

    #[tokio::test]
    async fn a_rollback_that_fails_too_returns_the_error_of_the_write() {
        let plain = pattern(B, 1);
        let (files, faulty, layer) = faulty_file(&stored(&plain)).await;
        let handle = open_file(&layer, "f").await;
        let data = pattern(50, 2);

        // The write leaves a fragment after the last block, and so does the
        // cut back that fails.
        faulty.tear_write(1, 20, SmbError::DiskFull);
        faulty.fail_truncate(1, SmbError::AccessDenied);
        assert_err(handle.write(B as u64, &data).await, SmbError::DiskFull);
        assert_eq!(faulty.truncates(), 1);
        assert_eq!(files.contents("f").unwrap().len(), at(1) + 20);
        assert_eq!(read_all(&handle).await, plain);

        assert_eq!(handle.write(B as u64, &data).await.unwrap(), 50);
        assert_eq!(faulty.truncates(), 2);
        let mut model = plain;
        apply(&mut model, B, &data);
        assert_eq!(read_all(&handle).await, model);
        assert_eq!(files.contents("f").unwrap().len(), stored_len(model.len()));
    }

    #[tokio::test]
    async fn a_cut_that_fails_before_the_write_stores_no_block() {
        let plain = pattern(B, 1);
        let mut bytes = stored(&plain);
        bytes.extend([7; 7]);
        let (files, faulty, layer) = faulty_file(&bytes).await;
        let handle = open_file(&layer, "f").await;
        let writes = faulty.write_calls().len();

        faulty.fail_truncate(1, SmbError::AccessDenied);
        assert_err(handle.write(10, b"abc").await, SmbError::AccessDenied);
        assert_eq!(faulty.write_calls().len(), writes);
        assert_eq!(files.contents("f").unwrap(), bytes);

        assert_eq!(handle.write(10, b"abc").await.unwrap(), 3);
        let mut model = plain;
        apply(&mut model, 10, b"abc");
        assert_eq!(read_all(&handle).await, model);
    }

    #[tokio::test]
    async fn a_new_header_is_cached_by_the_write_that_stores_it() {
        let (_files, faulty, handle) = new_file().await;
        handle.write(0, &pattern(100, 1)).await.unwrap();
        assert_eq!(handle.node().header().await, Some(HeaderKind::Present));
        assert_eq!(handle.read(5, 10).await.unwrap().len(), 10);
        handle.write(50, b"abc").await.unwrap();
        assert_eq!(header_reads(&faulty), 0, "the header is never read back");
    }

    #[tokio::test]
    async fn a_write_moves_the_request_and_two_blocks_at_most_through_the_inner_backend() {
        for bits in [13, 16] {
            let shift = BlockShift::new(bits).unwrap();
            let b = shift.block_len();
            // Old size, offset and length: a new file and an old one, one
            // block and several, with a pad and without, across the old end
            // and not.
            let cells = [
                (0, 5, 10),
                (0, 5, 3 * b + 5),
                (0, 5 * b, 10),
                (b + 10, 5, 10),
                (3 * b, b - 1, b + 2),
                (b + 10, b + 5, 10),
                (b + 10, b + 5, 3 * b),
                (b + 10, 4 * b + 9, 10),
                (b + 10, 3 * b + 5, 2 * b + 3),
                (2 * b, 5 * b, 10),
            ];
            for (logical, offset, len) in cells {
                let bytes = if logical == 0 {
                    Vec::new()
                } else {
                    stored_file(&key_schedule(), shift, &pattern(logical, 1))
                };
                let (_files, faulty, layer) = faulty_file_in(shift, &bytes).await;
                let handle = open_file(&layer, "f").await;
                let before = faulty.write_calls().len();
                handle.write(offset as u64, &pattern(len, 2)).await.unwrap();
                let cell = format!("shift {bits}, logical {logical}, offset {offset}, len {len}");

                // The data, two blocks of other bytes, a header, and the overhead per block.
                let sent: usize = writes_since(&faulty, before).iter().map(|&(_, n)| n).sum();
                let bound = len + 2 * b + H + OVERHEAD * (len / b + 3);
                assert!(sent <= bound, "{cell}: {sent} bytes sent");
                let read: usize = block_reads(&faulty).iter().map(|&(_, n)| n as usize).sum();
                assert!(read <= 2 * (b + OVERHEAD), "{cell}: {read} bytes read");
            }
        }
    }

    #[test]
    fn a_stored_run_that_crosses_the_old_end_is_two_writes_with_the_part_from_the_end_first() {
        let sealed = |lead, lead_at, run_at| Sealed {
            bytes: vec![0; 100],
            lead,
            lead_at,
            run_at,
            pad_end: (lead > 0).then_some(run_at),
        };
        let view = |steps: Vec<Step>| -> Vec<(u64, Range<usize>, Option<u64>)> {
            steps
                .into_iter()
                .map(|s| (s.at, s.range, s.pad_end))
                .collect()
        };

        // A lead and a run apart: the lead crosses the old end.
        assert_eq!(
            view(sealed(40, 10, 200).steps(30)),
            [
                (30, 20..40, None),
                (10, 0..20, Some(200)),
                (200, 40..100, None)
            ]
        );
        // Next to each other, they are one write.
        assert_eq!(
            view(sealed(40, 10, 50).steps(30)),
            [(30, 20..100, None), (10, 0..20, Some(50))]
        );
        // Wholly above or below the old end: no split.
        assert_eq!(
            view(sealed(40, 10, 200).steps(10)),
            [(10, 0..40, Some(200)), (200, 40..100, None)]
        );
        assert_eq!(
            view(sealed(40, 10, 200).steps(50)),
            [(10, 0..40, Some(200)), (200, 40..100, None)]
        );
        // A run alone that crosses it.
        assert_eq!(
            view(sealed(0, 0, 10).steps(60)),
            [(60, 50..100, None), (10, 0..50, None)]
        );
        assert_eq!(view(sealed(0, 0, 10).steps(110)), [(10, 0..100, None)]);
    }

    #[tokio::test]
    async fn a_file_with_an_unusable_header_refuses_the_write_and_stays_as_it_is() {
        let logs = Logs::new();
        let good = stored(&pattern(B + 10, 1));
        let mut bad_magic = good.clone();
        bad_magic[0] ^= 1;
        let mut bad_version = good.clone();
        bad_version[4] = 9;
        let cases = [
            (bad_magic, io::ErrorKind::InvalidData),
            (bad_version, io::ErrorKind::Unsupported),
            (vec![0x55; 100], io::ErrorKind::InvalidData),
        ];
        for (bytes, kind) in &cases {
            let (files, faulty, layer) = faulty_file(bytes).await;
            let handle = open_file(&layer, "f").await;
            let before = faulty.write_calls().len();
            assert_io(handle.write(3, b"abc").await, *kind);
            assert_eq!(files.contents("f").unwrap(), *bytes);
            assert_eq!(faulty.write_calls().len(), before);
            assert_eq!(handle.node().header().await, Some(HeaderKind::Unknown));
        }
        assert_eq!(logs.warnings().len(), cases.len());
    }

    #[tokio::test]
    async fn every_block_size_reads_back_what_was_written() {
        for bits in [13, 16, 20] {
            let shift = BlockShift::new(bits).unwrap();
            let block = shift.block_len();
            let files = MemFsBackend::new();
            let layer = clear_blocks(files.clone(), shift).await;
            let (handle, _) = open(&layer, "f", OpenIntent::Create).await;
            let mut model = Vec::new();
            for (offset, len) in [(0, 10), (block - 1, 3), (2 * block + 5, 4), (block + 1, 1)] {
                let data = pattern(len, len as u8);
                assert_eq!(
                    handle.write(offset as u64, &data).await.unwrap(),
                    len as u32
                );
                apply(&mut model, offset, &data);
            }
            assert!(read_all(&handle).await == model, "shift {bits}");
            let stored = files.contents("f").unwrap().len() as u64;
            assert_eq!(Some(stored), stored_size(shift, model.len() as u64));
        }
    }

    #[tokio::test]
    async fn a_dropped_write_frees_the_lock_and_drops_the_cached_header() {
        let plain = pattern(2 * B + 10, 1);
        let bytes = stored(&plain);
        let (files, gated, layer) = gated_file(&bytes).await;
        let handle = open_file(&layer, "f").await;
        assert_eq!(handle.read(0, 10).await.unwrap(), plain[..10]);
        assert_eq!(handle.node().header().await, Some(HeaderKind::Present));
        let file = handle.node().file().unwrap();

        let gate = gated.arm(Op::Write);
        drop_at(&gate, handle.write(B as u64 + 5, b"abc")).await;
        assert!(file.try_write().is_ok(), "the lock is free");
        assert_eq!(handle.node().header().await, Some(HeaderKind::Unknown));
        assert_eq!(files.contents("f").unwrap(), bytes);

        assert_eq!(handle.read(0, 10).await.unwrap(), plain[..10]);
        assert_eq!(handle.node().header().await, Some(HeaderKind::Present));
        assert_eq!(handle.write(B as u64 + 5, b"abc").await.unwrap(), 3);
        let mut model = plain;
        apply(&mut model, B + 5, b"abc");
        assert_eq!(read_all(&handle).await, model);
    }

    #[tokio::test]
    async fn a_write_dropped_between_the_two_parts_of_a_pad_leaves_the_old_block_torn() {
        let plain = pattern(B + 100, 1);
        let bytes = stored(&plain);
        let old_end = at(1) + 100 + OVERHEAD;
        let (files, gated, layer) = gated_file(&bytes).await;
        let handle = open_file(&layer, "f").await;
        let file = handle.node().file().unwrap();
        let data = pattern(10, 2);
        let offset = 4 * B as u64 + 3;

        // The part of the pad from the old end on is stored; the part below
        // it parks.
        let above = gated.arm(Op::Write);
        let below = gated.arm(Op::Write);
        above.release();
        drop_at(&below, handle.write(offset, &data)).await;
        assert!(file.try_write().is_ok(), "the lock is free");
        let after = files.contents("f").unwrap();
        assert_eq!(after.len(), at(2));
        assert_eq!(after[..old_end], bytes[..old_end]);

        assert_io(handle.read(B as u64, 1).await, io::ErrorKind::InvalidData);
        assert_eq!(handle.read(0, B as u32).await.unwrap(), plain[..B]);

        let again = open_file(&layer, "f").await;
        assert_eq!(again.write(offset, &data).await.unwrap(), 10);
        assert_eq!(again.read(offset, 10).await.unwrap(), data);
        assert_eq!(again.read(0, B as u32).await.unwrap(), plain[..B]);
    }

    #[tokio::test]
    async fn a_write_to_a_new_file_dropped_while_it_stores_leaves_no_header_cached() {
        let files = MemFsBackend::new();
        let gated = Gated::new(files.clone());
        let layer = layer_over(gated.clone()).await;
        let (handle, _) = open(&layer, "f", OpenIntent::Create).await;
        let file = handle.node().file().unwrap();

        let gate = gated.arm(Op::Write);
        drop_at(&gate, handle.write(3, b"abc")).await;
        assert!(file.try_write().is_ok(), "the lock is free");
        assert_eq!(handle.node().header().await, Some(HeaderKind::Absent));
        assert_eq!(files.contents("f"), Some(Vec::new()));

        assert_eq!(handle.write(3, b"abc").await.unwrap(), 3);
        assert_eq!(read_all(&handle).await, b"\0\0\0abc");
    }
}
