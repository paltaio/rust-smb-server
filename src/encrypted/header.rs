//! The header at the start of every stored file that holds data.

use super::format::{
    BlockShift, FILE_ID_LEN, FORMAT_VERSION, HEADER_LEN, SUITE_AES_256_GCM, is_zero,
};

const MAGIC: &[u8; 4] = b"smbe";

/// A valid file header: its bytes are what the blocks authenticate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Header {
    bytes: [u8; HEADER_LEN],
    shift: BlockShift,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum HeaderError {
    /// The format version or the suite is not one this build reads.
    Unsupported,
    /// Anything else that is not a header of this share.
    Invalid,
}

impl Header {
    /// The header of a file with `file_id`. `None` when `file_id` is all
    /// zero.
    pub(crate) fn new(shift: BlockShift, file_id: [u8; FILE_ID_LEN]) -> Option<Self> {
        if is_zero(&file_id) {
            return None;
        }
        let mut bytes = [0u8; HEADER_LEN];
        bytes[..4].copy_from_slice(MAGIC);
        bytes[4] = FORMAT_VERSION;
        bytes[5] = SUITE_AES_256_GCM;
        bytes[6] = shift.get();
        bytes[8..].copy_from_slice(&file_id);
        Some(Self { bytes, shift })
    }

    /// The header in `bytes`, for a share with block shift `shift`. Checks
    /// in field order: length, magic, version, suite, block shift, reserved
    /// byte, file id.
    pub(crate) fn parse(bytes: &[u8], shift: BlockShift) -> Result<Self, HeaderError> {
        let bytes: &[u8; HEADER_LEN] = bytes.try_into().map_err(|_| HeaderError::Invalid)?;
        if bytes[..4] != MAGIC[..] {
            return Err(HeaderError::Invalid);
        }
        if bytes[4] != FORMAT_VERSION || bytes[5] != SUITE_AES_256_GCM {
            return Err(HeaderError::Unsupported);
        }
        if bytes[6] != shift.get() || bytes[7] != 0 || is_zero(&bytes[8..]) {
            return Err(HeaderError::Invalid);
        }
        Ok(Self {
            bytes: *bytes,
            shift,
        })
    }

    pub(crate) fn as_bytes(&self) -> &[u8; HEADER_LEN] {
        &self.bytes
    }

    pub(crate) fn suite(&self) -> u8 {
        self.bytes[5]
    }

    pub(crate) fn block_shift(&self) -> BlockShift {
        self.shift
    }

    pub(crate) fn file_id(&self) -> [u8; FILE_ID_LEN] {
        let mut id = [0u8; FILE_ID_LEN];
        id.copy_from_slice(&self.bytes[8..]);
        id
    }
}

#[cfg(test)]
mod tests {
    use super::super::testing::{file_id, unhex};
    use super::*;

    const HEADER: &str = "736d626501011000a0a1a2a3a4a5a6a7a8a9aaabacadaeaf";

    fn shift(bits: u8) -> BlockShift {
        BlockShift::new(bits).unwrap()
    }

    fn valid() -> [u8; HEADER_LEN] {
        *Header::new(BlockShift::DEFAULT, file_id())
            .unwrap()
            .as_bytes()
    }

    fn parse(bytes: &[u8]) -> Result<Header, HeaderError> {
        Header::parse(bytes, BlockShift::DEFAULT)
    }

    #[test]
    fn header_vector() {
        assert_eq!(valid().as_slice(), unhex(HEADER));
        let header = parse(&unhex(HEADER)).unwrap();
        assert_eq!(header.as_bytes().as_slice(), unhex(HEADER));
        assert_eq!(header.suite(), SUITE_AES_256_GCM);
        assert_eq!(header.file_id(), file_id());
    }

    #[test]
    fn all_zero_file_id_is_refused() {
        assert!(Header::new(BlockShift::DEFAULT, [0; FILE_ID_LEN]).is_none());
        let mut bytes = valid();
        bytes[8..].fill(0);
        assert_eq!(parse(&bytes), Err(HeaderError::Invalid));
        bytes[23] = 1;
        assert!(parse(&bytes).is_ok());
    }

    #[test]
    fn wrong_length_is_invalid() {
        let good = valid();
        assert_eq!(parse(&good[..23]), Err(HeaderError::Invalid), "short");
        let mut long = good.to_vec();
        long.push(0);
        assert_eq!(parse(&long), Err(HeaderError::Invalid), "long");
    }

    #[test]
    fn invalid_fields() {
        let mut bytes = valid();
        bytes[0] ^= 1;
        assert_eq!(parse(&bytes), Err(HeaderError::Invalid), "magic");
        let mut bytes = valid();
        bytes[7] = 1;
        assert_eq!(parse(&bytes), Err(HeaderError::Invalid), "reserved");
        assert_eq!(
            Header::parse(&valid(), shift(13)),
            Err(HeaderError::Invalid),
            "share uses another shift"
        );
    }

    #[test]
    fn unknown_version_or_suite_is_unsupported() {
        for value in [0, 2, 255] {
            let mut bytes = valid();
            bytes[4] = value;
            assert_eq!(
                parse(&bytes),
                Err(HeaderError::Unsupported),
                "version {value}"
            );
            let mut bytes = valid();
            bytes[5] = value;
            assert_eq!(
                parse(&bytes),
                Err(HeaderError::Unsupported),
                "suite {value}"
            );
        }
    }

    #[test]
    fn check_order_follows_the_fields() {
        let mut bytes = valid();
        bytes[0] ^= 1;
        bytes[4] = 2;
        assert_eq!(
            parse(&bytes),
            Err(HeaderError::Invalid),
            "magic before version"
        );
        let mut bytes = valid();
        bytes[5] = 2;
        bytes[6] = 13;
        bytes[7] = 1;
        bytes[8..].fill(0);
        assert_eq!(
            parse(&bytes),
            Err(HeaderError::Unsupported),
            "suite before shift, reserved and file id"
        );
    }
}
