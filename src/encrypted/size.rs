//! Mapping between logical file sizes and stored sizes.

use super::format::{BlockShift, HEADER_LEN, MAX_STORED_SIZE, OVERHEAD};

const HEADER: u64 = HEADER_LEN as u64;
const BLOCK_OVERHEAD: u64 = OVERHEAD as u64;

/// How a stored size relates to the file it holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum StoredKind {
    /// The size is the one `stored_size` gives for the logical size.
    Normal,
    /// Fewer bytes than a header.
    TornHeader,
    /// A header and nothing else.
    HeaderOnly,
    /// Bytes after the last whole block that are too few to hold a block.
    Fragment,
}

/// The logical size a stored size stands for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct LogicalSize {
    pub(crate) size: u64,
    pub(crate) kind: StoredKind,
}

/// Stored size of a file of `logical` bytes. `None` when it would pass
/// `MAX_STORED_SIZE`.
pub(crate) fn stored_size(shift: BlockShift, logical: u64) -> Option<u64> {
    if logical == 0 {
        return Some(0);
    }
    let blocks = logical >> shift.get();
    let rest = logical & (shift.block_size() - 1);
    let tail = if rest > 0 { rest + BLOCK_OVERHEAD } else { 0 };
    let size = blocks
        .checked_mul(shift.stored_block_size())?
        .checked_add(HEADER + tail)?;
    (size <= MAX_STORED_SIZE).then_some(size)
}

/// Logical size of a stored file of `stored` bytes. Any `stored` is valid;
/// sizes that are not `Normal` are reported with the data they still hold.
pub(crate) fn logical_size(shift: BlockShift, stored: u64) -> LogicalSize {
    let (size, kind) = if stored == 0 {
        (0, StoredKind::Normal)
    } else if stored < HEADER {
        (0, StoredKind::TornHeader)
    } else if stored == HEADER {
        (0, StoredKind::HeaderOnly)
    } else {
        let data = stored - HEADER;
        let block = shift.stored_block_size();
        let whole = (data / block) << shift.get();
        match data % block {
            0 => (whole, StoredKind::Normal),
            rest if rest > BLOCK_OVERHEAD => (whole + rest - BLOCK_OVERHEAD, StoredKind::Normal),
            _ => (whole, StoredKind::Fragment),
        }
    };
    LogicalSize { size, kind }
}

/// Where a run of blocks sits in the stored file and how many bytes it holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct BlockRange {
    /// Offset of the first block in the stored file.
    pub(crate) offset: u64,
    /// Stored bytes of the run, overhead included.
    pub(crate) stored_len: u64,
    /// Plaintext bytes of the run.
    pub(crate) plain_len: u64,
}

/// The blocks `first..=last` of a file of `logical` bytes. `None` when
/// `first` is after `last`, when `last` starts at or past the end of the
/// file, or when an offset does not fit in 64 bits.
pub(crate) fn block_range(
    shift: BlockShift,
    logical: u64,
    first: u64,
    last: u64,
) -> Option<BlockRange> {
    let block = shift.block_size();
    let last_start = last.checked_mul(block)?;
    if first > last || last_start >= logical {
        return None;
    }
    let count = last - first + 1;
    let tail = (logical - last_start).min(block);
    let plain_len = (count - 1) * block + tail;
    let stored_len = plain_len.checked_add(count.checked_mul(BLOCK_OVERHEAD)?)?;
    let offset = first
        .checked_mul(shift.stored_block_size())?
        .checked_add(HEADER)?;
    Some(BlockRange {
        offset,
        stored_len,
        plain_len,
    })
}

/// `stored_size` computed in 128 bits, where nothing overflows.
#[cfg(any(test, fuzzing))]
pub(super) fn expected_stored_size(shift: BlockShift, logical: u64) -> Option<u64> {
    if logical == 0 {
        return Some(0);
    }
    let (block, overhead) = (u128::from(shift.block_size()), u128::from(BLOCK_OVERHEAD));
    let logical = u128::from(logical);
    let tail = match logical % block {
        0 => 0,
        rest => rest + overhead,
    };
    let stored = u128::from(HEADER) + logical / block * (block + overhead) + tail;
    u64::try_from(stored)
        .ok()
        .filter(|&stored| stored <= MAX_STORED_SIZE)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SHIFTS: [u8; 3] = [13, 16, 20];

    fn shift(shift: u8) -> BlockShift {
        BlockShift::new(shift).unwrap()
    }

    fn mapped(s: u8, stored: u64) -> (u64, StoredKind) {
        let info = logical_size(shift(s), stored);
        (info.size, info.kind)
    }

    #[test]
    fn worked_examples() {
        let s = shift(16);
        assert_eq!(stored_size(s, 0), Some(0));
        assert_eq!(stored_size(s, 1), Some(53));
        assert_eq!(stored_size(s, 65536), Some(65588));
        assert_eq!(stored_size(s, 65537), Some(65617));
        assert_eq!(mapped(16, 0), (0, StoredKind::Normal));
        assert_eq!(mapped(16, 24), (0, StoredKind::HeaderOnly));
        assert_eq!(mapped(16, 52), (0, StoredKind::Fragment));
        assert_eq!(mapped(16, 53), (1, StoredKind::Normal));
        assert_eq!(mapped(16, 65588), (65536, StoredKind::Normal));
        assert_eq!(mapped(16, 65617), (65537, StoredKind::Normal));
    }

    #[test]
    fn abnormal_sizes_are_classified() {
        for bits in SHIFTS {
            let block = shift(bits).block_size();
            let full = shift(bits).stored_block_size();
            for stored in 1..24 {
                assert_eq!(mapped(bits, stored), (0, StoredKind::TornHeader));
            }
            assert_eq!(mapped(bits, 24), (0, StoredKind::HeaderOnly));
            for stored in 25..=52 {
                assert_eq!(mapped(bits, stored), (0, StoredKind::Fragment));
            }
            assert_eq!(mapped(bits, 53), (1, StoredKind::Normal));
            assert_eq!(mapped(bits, 24 + full - 1), (block - 1, StoredKind::Normal));
            assert_eq!(mapped(bits, 24 + full), (block, StoredKind::Normal));
            for extra in 1..=28 {
                assert_eq!(
                    mapped(bits, 24 + full + extra),
                    (block, StoredKind::Fragment)
                );
            }
            assert_eq!(
                mapped(bits, 24 + full + 29),
                (block + 1, StoredKind::Normal)
            );
        }
    }

    #[test]
    fn every_small_stored_size_maps_back() {
        for bits in SHIFTS {
            let s = shift(bits);
            for stored in 0..=3 * s.stored_block_size() + 24 {
                let info = logical_size(s, stored);
                let normal = stored_size(s, info.size).unwrap();
                assert!(normal <= stored, "shift {bits}, stored {stored}");
                assert_eq!(
                    info.kind == StoredKind::Normal,
                    normal == stored,
                    "shift {bits}, stored {stored}"
                );
                assert_eq!(
                    logical_size(s, normal),
                    LogicalSize {
                        size: info.size,
                        kind: StoredKind::Normal
                    },
                    "shift {bits}, stored {stored}"
                );
            }
        }
    }

    fn samples(bits: u8) -> Vec<u64> {
        let s = shift(bits);
        let mut out = vec![u64::MAX];
        for base in [s.block_size(), s.stored_block_size(), 1 << 32, 1 << 62] {
            out.extend([base - 1, base, base + 1]);
        }
        out.extend([MAX_STORED_SIZE - 1, MAX_STORED_SIZE, MAX_STORED_SIZE + 1]);
        out
    }

    #[test]
    fn sampled_large_values() {
        for bits in SHIFTS {
            let s = shift(bits);
            for stored in samples(bits) {
                let info = logical_size(s, stored);
                assert!(info.size <= stored);
                match stored_size(s, info.size) {
                    Some(normal) => {
                        assert!(normal <= stored);
                        assert_eq!(logical_size(s, normal).size, info.size);
                    }
                    None => assert!(stored > MAX_STORED_SIZE, "shift {bits}, stored {stored}"),
                }
            }
            for logical in samples(bits) {
                let expected = expected_stored_size(s, logical);
                assert_eq!(
                    stored_size(s, logical),
                    expected,
                    "shift {bits}, logical {logical}"
                );
                if let Some(stored) = expected {
                    let info = logical_size(s, stored);
                    assert_eq!(info.size, logical);
                    assert_eq!(info.kind, StoredKind::Normal);
                }
            }
        }
    }

    #[test]
    fn a_run_of_blocks_sits_at_its_stored_offsets() {
        let s = shift(16);
        let logical = 3 * 65536 + 100;
        let range = |offset, stored_len, plain_len| {
            Some(BlockRange {
                offset,
                stored_len,
                plain_len,
            })
        };
        assert_eq!(block_range(s, logical, 0, 0), range(24, 65564, 65536));
        assert_eq!(
            block_range(s, logical, 1, 2),
            range(24 + 65564, 2 * 65564, 2 * 65536)
        );
        assert_eq!(
            block_range(s, logical, 3, 3),
            range(24 + 3 * 65564, 128, 100)
        );
        assert_eq!(
            block_range(s, logical, 2, 3),
            range(24 + 2 * 65564, 65564 + 128, 65536 + 100)
        );
        let whole = block_range(s, logical, 0, 3).unwrap();
        assert_eq!(whole.offset, 24);
        assert_eq!(
            Some(whole.offset + whole.stored_len),
            stored_size(s, logical)
        );
        assert_eq!(whole.plain_len, logical);
    }

    #[test]
    fn blocks_the_file_does_not_hold_have_no_range() {
        let s = shift(16);
        assert_eq!(block_range(s, 65536, 1, 1), None, "starts at the end");
        assert_eq!(block_range(s, 65537, 1, 0), None, "first after last");
        assert_eq!(block_range(s, 0, 0, 0), None, "empty file");
        assert_eq!(block_range(s, u64::MAX, u64::MAX, u64::MAX), None);
        assert_eq!(block_range(s, u64::MAX, 0, u64::MAX >> 16), None);
        assert!(block_range(s, 65537, 1, 1).is_some());
    }

    #[test]
    fn a_range_of_any_stored_size_ends_inside_the_stored_file() {
        let ends_inside = |s: BlockShift, stored: u64| {
            let logical = logical_size(s, stored).size;
            if logical == 0 {
                return;
            }
            let last = (logical - 1) >> s.get();
            for first in [0, last / 2, last] {
                let range = block_range(s, logical, first, last).unwrap();
                let end = u128::from(range.offset) + u128::from(range.stored_len);
                assert!(end <= u128::from(stored), "shift {s:?}, stored {stored}");
                assert!(range.plain_len <= logical);
            }
        };
        for bits in SHIFTS {
            let s = shift(bits);
            for stored in 0..=3 * s.stored_block_size() + 24 {
                ends_inside(s, stored);
            }
            for stored in samples(bits) {
                ends_inside(s, stored);
            }
        }
    }

    #[test]
    fn sizes_past_the_stored_maximum_are_rejected() {
        for bits in SHIFTS {
            let s = shift(bits);
            assert_eq!(stored_size(s, u64::MAX), None);
            assert_eq!(stored_size(s, 1 << 63), None);
            assert_eq!(stored_size(s, MAX_STORED_SIZE), None);

            let edge = logical_size(s, MAX_STORED_SIZE).size;
            assert!(stored_size(s, edge).is_some(), "shift {bits}");
            assert!(stored_size(s, edge + 1).is_none(), "shift {bits}");
        }
    }
}
