//! A full disk during an edit of a file that ends in a partial block. Each
//! inner write of the edit fails in turn, whole and cut short, and the stored
//! file is read back through a fresh layer over the same store.

use std::io;
use std::ops::Range;

use super::format::{BlockShift, HEADER_LEN, OVERHEAD};
use super::testing::{
    Edit, KEPT, clear_blocks, edited, faulty_file_in, key_schedule, open_file, perform, read_all,
    resized, stored_file, writes_since,
};
use crate::backend::Handle;
use crate::error::SmbError;
use crate::tests::data::pattern;

/// An edit of a file of `whole` blocks and a partial one, which makes the
/// partial block longer. The part of that block from the old end on is
/// stored first, and the part below the old end second.
struct Case {
    name: &'static str,
    whole: usize,
    edit: Edit,
    /// Inner writes the edit makes.
    writes: usize,
    /// Indexes of the writes that cut the file back when they fail.
    above: &'static [usize],
}

impl Case {
    fn write(name: &'static str, whole: usize, offset: usize, len: usize) -> Self {
        Self {
            name,
            whole,
            edit: Edit::Write { offset, len },
            writes: 2,
            above: &[0],
        }
    }

    fn truncate(name: &'static str, whole: usize, len: usize) -> Self {
        Self {
            name,
            whole,
            edit: Edit::Truncate { len },
            writes: 2,
            above: &[0],
        }
    }

    /// The padded last block and the new blocks are not next to each other.
    /// The new blocks are a third write, which starts at or above the end of
    /// the padded block.
    fn apart(self) -> Self {
        Self {
            writes: 3,
            above: &[0, 2],
            ..self
        }
    }
}

/// Writes that start in the partial last block.
fn appends(b: usize, whole: usize) -> Vec<Case> {
    let old = whole * b + KEPT;
    vec![
        Case::write("append inside the last block", whole, old, 50),
        Case::write(
            "append up to the end of the last block",
            whole,
            old,
            b - KEPT,
        ),
        Case::write("append into the next block", whole, old, b + 50),
        Case::write("write over the old end", whole, old - 20, 50),
    ]
}

/// Writes that start after the last block, which is padded first.
fn writes_past_the_last_block(b: usize, whole: usize) -> Vec<Case> {
    let next = (whole + 1) * b;
    vec![
        Case::write("write at the start of the next block", whole, next, 10),
        Case::write("write into the next block", whole, next + 3, 10),
        Case::write("write over two blocks after the last", whole, next + 3, b),
        Case::write("write one block past the next", whole, next + b + 3, 10).apart(),
        Case::write("write over two blocks apart", whole, next + 4 * b + 3, b).apart(),
    ]
}

/// Writes that start in a block before the last and end after the old end.
fn writes_from_below_to_past_the_end(b: usize) -> Vec<Case> {
    vec![
        Case::write("write from block 1 into the last block", 2, b + 5, b + 130),
        Case::write("write from block 1 into the next block", 2, b + 5, 2 * b),
        Case::write("write from block 0 into the next block", 2, 5, 3 * b),
    ]
}

fn extensions(b: usize, whole: usize) -> Vec<Case> {
    let end = (whole + 1) * b;
    vec![
        Case::truncate(
            "extension inside the last block",
            whole,
            end - b + KEPT + 200,
        ),
        Case::truncate("extension to the end of the last block", whole, end),
        Case::truncate("extension one byte past the last block", whole, end + 1),
        Case::truncate(
            "extension three blocks past the last",
            whole,
            end + 3 * b + 7,
        ),
    ]
}

/// The `written` ranges, as offset and length, cover all of `target`.
fn covers(written: &[(u64, usize)], target: &Range<u64>) -> bool {
    let mut sorted = written.to_vec();
    sorted.sort_unstable();
    let mut reach = target.start;
    for (at, len) in sorted {
        if at <= reach {
            reach = reach.max(at + len as u64);
        }
    }
    reach >= target.end
}

/// A case at one block size, with the inner writes of its edit.
struct Run<'a> {
    case: &'a Case,
    shift: BlockShift,
    b: usize,
    plain: Vec<u8>,
    stored: Vec<u8>,
    /// Where the old last block is stored once the edit has made it longer,
    /// when the edit does not start in it.
    pad: Option<Range<u64>>,
    /// Offset and length of each inner write, from a run with no fault.
    calls: Vec<(u64, usize)>,
}

impl<'a> Run<'a> {
    async fn new(bits: u8, case: &'a Case) -> Self {
        let shift = BlockShift::new(bits).unwrap();
        let b = shift.block_len();
        let plain = pattern(case.whole * b + KEPT, 1);
        let stored = stored_file(&key_schedule(), shift, &plain);
        let mut run = Self {
            case,
            shift,
            b,
            plain,
            stored,
            pad: None,
            calls: Vec::new(),
        };
        run.pad = run.pad_range();
        run.calls = run.clean().await;

        let name = run.name();
        let old_end = run.end();
        assert_eq!(run.calls.len(), case.writes, "{name}: inner writes");
        assert_eq!(run.calls[0].0, old_end, "{name}: the first write");
        let (at, len) = run.calls[1];
        assert_eq!(at + len as u64, old_end, "{name}: the second write");
        let above: Vec<usize> = (0..run.calls.len())
            .filter(|&n| run.calls[n].0 >= run.safe_end(n))
            .collect();
        assert_eq!(above, case.above, "{name}: writes at or above the safe end");
        run
    }

    fn name(&self) -> String {
        format!("{}, block size {}", self.case.name, self.b)
    }

    /// Where block `index` starts in the stored file.
    fn at(&self, index: usize) -> u64 {
        (HEADER_LEN + index * (self.b + OVERHEAD)) as u64
    }

    /// Size of the old stored file.
    fn end(&self) -> u64 {
        self.stored.len() as u64
    }

    fn pad_range(&self) -> Option<Range<u64>> {
        let whole = self.case.whole;
        let plain = match self.case.edit {
            Edit::Write { offset, .. } if offset / self.b > whole => self.b,
            Edit::Write { .. } => return None,
            Edit::Truncate { len } => (len - whole * self.b).min(self.b),
        };
        let start = self.at(whole);
        Some(start..start + (plain + OVERHEAD) as u64)
    }

    /// The first block the edit rewrites: the one it starts in, or the old
    /// last block when it starts after it.
    fn first_block(&self) -> usize {
        match self.case.edit {
            Edit::Write { offset, .. } => (offset / self.b).min(self.case.whole),
            Edit::Truncate { .. } => self.case.whole,
        }
    }

    /// The stored size the file is cut back to when write `n` fails: the old
    /// size, until the writes before `n` have stored all of the padded last
    /// block.
    fn safe_end(&self, n: usize) -> u64 {
        match &self.pad {
            Some(pad) if covers(&self.calls[..n], pad) => pad.end,
            _ => self.end(),
        }
    }

    /// What a file cut back to `safe_end` reads as: the old bytes, and zeros
    /// up to the end of the padded last block when that block is whole.
    fn cut_back_to(&self, safe_end: u64) -> Vec<u8> {
        let len = match &self.pad {
            Some(pad) if safe_end == pad.end => {
                self.case.whole * self.b + (pad.end - pad.start) as usize - OVERHEAD
            }
            _ => self.plain.len(),
        };
        resized(&self.plain, len)
    }

    /// The inner writes of the edit with no fault.
    async fn clean(&self) -> Vec<(u64, usize)> {
        let (_files, faulty, layer) = faulty_file_in(self.shift, &self.stored).await;
        let handle = open_file(&layer, "f").await;
        let before = faulty.write_calls().len();
        perform(&handle, self.case.edit).await.unwrap();
        assert!(
            read_all(&handle).await == edited(&self.plain, self.case.edit),
            "{}: the edit",
            self.name()
        );
        writes_since(&faulty, before)
    }

    /// Fails each inner write of the edit, whole and cut short.
    async fn fail_each_write(&self) {
        for (n, &(_, len)) in self.calls.iter().enumerate() {
            let mut prefixes = vec![0, 1, len / 2, len - 1];
            prefixes.sort_unstable();
            prefixes.dedup();
            for applied in prefixes {
                self.fail(n, applied).await;
            }
        }
    }

    /// Fails write `n` of the edit with a full disk after `applied` of its
    /// bytes reach the store, and reads the stored file back.
    async fn fail(&self, n: usize, applied: usize) {
        let name = format!("{}, write {n}, {applied} bytes applied", self.name());
        let (files, faulty, layer) = faulty_file_in(self.shift, &self.stored).await;
        let handle = open_file(&layer, "f").await;
        let before = faulty.write_calls().len();
        if applied == 0 {
            faulty.fail_write(n + 1, SmbError::DiskFull);
        } else {
            faulty.tear_write(n + 1, applied, SmbError::DiskFull);
        }

        let result = perform(&handle, self.case.edit).await;
        assert!(
            matches!(result, Err(SmbError::DiskFull)),
            "{name}: {result:?}"
        );
        assert_eq!(writes_since(&faulty, before), self.calls[..=n], "{name}");

        let stored = files.contents("f").unwrap();
        let fresh = clear_blocks(files.clone(), self.shift).await;
        let reader = open_file(&fresh, "f").await;
        let at = self.calls[n].0;
        let safe_end = self.safe_end(n);
        if at >= safe_end {
            assert_eq!(faulty.truncate_calls(), [safe_end], "{name}: the cut");
            assert_eq!(stored.len() as u64, safe_end, "{name}: stored size");
            assert!(
                read_all(&reader).await == self.cut_back_to(safe_end),
                "{name}: the old bytes"
            );
            perform(&handle, self.case.edit).await.unwrap();
            assert!(
                read_all(&reader).await == edited(&self.plain, self.case.edit),
                "{name}: the edit again"
            );
            return;
        }

        // The write is below the old end: nothing is cut, and the blocks it
        // rewrites can be torn.
        assert_eq!(faulty.truncates(), 0, "{name}: nothing is cut");
        let grown = self.calls[..n]
            .iter()
            .map(|&(at, len)| at + len as u64)
            .chain([self.end(), at + applied as u64])
            .max()
            .unwrap();
        assert_eq!(stored.len() as u64, grown, "{name}: stored size");
        let first = self.first_block();
        assert_eq!(at, self.at(first), "{name}: the write starts at a block");
        assert!(
            stored[..at as usize] == self.stored[..at as usize],
            "{name}: stored bytes before the write"
        );
        if first > 0 {
            let got = reader.read(0, (first * self.b) as u32).await.unwrap();
            assert!(
                got[..] == self.plain[..first * self.b],
                "{name}: the blocks before the write"
            );
        }
        match reader.read((first * self.b) as u64, u32::MAX).await {
            // A torn block can still open when the unapplied bytes happen to
            // equal the new ones.
            Ok(got) => {
                let after = edited(&self.plain, self.case.edit);
                let start = first * self.b;
                assert!(
                    got[..] == after[start..start + got.len()],
                    "{name}: the rewritten blocks"
                );
            }
            Err(SmbError::Io(error)) if error.kind() == io::ErrorKind::InvalidData => {}
            other => panic!("{name}: the rewritten blocks: {other:?}"),
        }
    }
}

#[tokio::test]
async fn a_disk_full_in_an_append_damages_only_the_blocks_it_rewrites() {
    for bits in [13, 16] {
        for whole in [0, 2] {
            for case in appends(1 << bits, whole) {
                Run::new(bits, &case).await.fail_each_write().await;
            }
        }
    }
}

#[tokio::test]
async fn a_disk_full_in_a_write_past_the_last_block_damages_only_the_blocks_it_rewrites() {
    for bits in [13, 16] {
        for whole in [0, 2] {
            for case in writes_past_the_last_block(1 << bits, whole) {
                Run::new(bits, &case).await.fail_each_write().await;
            }
        }
    }
}

#[tokio::test]
async fn a_disk_full_in_a_write_from_below_the_last_block_damages_only_the_blocks_it_rewrites() {
    for bits in [13, 16] {
        for case in writes_from_below_to_past_the_end(1 << bits) {
            Run::new(bits, &case).await.fail_each_write().await;
        }
    }
}

#[tokio::test]
async fn a_disk_full_in_an_extension_damages_only_the_blocks_it_rewrites() {
    for bits in [13, 16] {
        for whole in [0, 2] {
            for case in extensions(1 << bits, whole) {
                Run::new(bits, &case).await.fail_each_write().await;
            }
        }
    }
}
