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

#[cfg(test)]
mod tests {
    use super::*;

    const SHIFTS: [u8; 3] = [13, 16, 20];

    fn shift(shift: u8) -> BlockShift {
        BlockShift::new(shift).unwrap()
    }

    /// The stored size computed in u128, which holds it for every u64.
    fn expected_stored_size(shift: u8, logical: u64) -> Option<u64> {
        if logical == 0 {
            return Some(0);
        }
        let block = 1u128 << shift;
        let logical = u128::from(logical);
        let tail = match logical % block {
            0 => 0,
            rest => rest + 28,
        };
        let size = 24 + logical / block * (block + 28) + tail;
        u64::try_from(size).ok().filter(|s| *s <= MAX_STORED_SIZE)
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
                let expected = expected_stored_size(bits, logical);
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
