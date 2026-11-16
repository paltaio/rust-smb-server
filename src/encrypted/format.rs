//! Constants and shared types of the on-disk format.

/// Version of the marker and of the file header.
pub(crate) const FORMAT_VERSION: u8 = 1;

/// Suite byte of AES-256-GCM with a 96-bit random nonce and a 128-bit tag.
pub(crate) const SUITE_AES_256_GCM: u8 = 1;

/// Length of the header at the start of every stored file that holds data.
pub(crate) const HEADER_LEN: usize = 24;
pub(crate) const FILE_ID_LEN: usize = 16;

pub(crate) const NONCE_LEN: usize = 12;
pub(crate) const TAG_LEN: usize = 16;
/// Stored bytes a block adds to its plaintext.
pub(crate) const OVERHEAD: usize = NONCE_LEN + TAG_LEN;

/// Name of the marker object in the root of the inner backend.
pub(crate) const MARKER_NAME: &str = ".smb-encryption";
pub(crate) const MARKER_LEN: usize = 60;
pub(crate) const SHARE_ID_LEN: usize = 16;
/// Shortest long-name threshold of a share that encrypts names.
pub(crate) const MIN_LONG_NAME_THRESHOLD: u8 = 62;

/// Largest stored file size, `2^63 - 1`.
pub(crate) const MAX_STORED_SIZE: u64 = i64::MAX as u64;

pub(crate) fn is_zero(bytes: &[u8]) -> bool {
    bytes.iter().all(|&b| b == 0)
}

/// A block size of `1 << shift` plaintext bytes, with `shift` in 13..=20.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct BlockShift(u8);

impl BlockShift {
    pub(crate) const MIN: u8 = 13;
    pub(crate) const MAX: u8 = 20;
    pub(crate) const DEFAULT: Self = Self(16);

    pub(crate) fn new(shift: u8) -> Option<Self> {
        (Self::MIN..=Self::MAX)
            .contains(&shift)
            .then_some(Self(shift))
    }

    pub(crate) fn get(self) -> u8 {
        self.0
    }

    /// Plaintext bytes of a full block.
    pub(crate) fn block_size(self) -> u64 {
        1 << self.0
    }

    /// Plaintext bytes of a full block, as a buffer length.
    pub(crate) fn block_len(self) -> usize {
        1 << self.0
    }

    /// Stored bytes of a full block.
    pub(crate) fn stored_block_size(self) -> u64 {
        self.block_size() + OVERHEAD as u64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constants_match_the_format() {
        assert_eq!(MARKER_NAME, ".smb-encryption");
        assert_eq!(MAX_STORED_SIZE, 9_223_372_036_854_775_807);
    }

    #[test]
    fn shift_range_is_13_to_20() {
        for shift in 0..=u8::MAX {
            assert_eq!(
                BlockShift::new(shift).map(BlockShift::get),
                (13..=20).contains(&shift).then_some(shift)
            );
        }
        assert_eq!(BlockShift::DEFAULT.get(), 16);
    }
}
