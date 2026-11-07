//! FSCTL_DUPLICATE_EXTENTS_TO_FILE (MS-FSCC 2.3.7.2, MS-SMB2 3.3.5.15.17).
//! All integers are little-endian.

use super::create::FileId;

/// Size of SMB2_DUPLICATE_EXTENTS_DATA.
const LEN: usize = 40;

/// SMB2_DUPLICATE_EXTENTS_DATA: `byte_count` bytes at `source_offset` of the
/// open `source` go to `target_offset` of the open the request is on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DuplicateExtentsRequest {
    pub source: FileId,
    pub source_offset: u64,
    pub target_offset: u64,
    pub byte_count: u64,
}

impl DuplicateExtentsRequest {
    /// Reads the input of an IOCTL request, `None` when it is shorter than
    /// 40 bytes. Bytes after the structure are ignored.
    pub fn parse(input: &[u8]) -> Option<Self> {
        let raw = input.first_chunk::<LEN>()?;
        let word = |at: usize| u64::from_le_bytes(raw[at..at + 8].try_into().expect("8 bytes"));
        Some(Self {
            source: FileId::new(word(0), word(8)),
            source_offset: word(16),
            target_offset: word(24),
            byte_count: word(32),
        })
    }

    /// The offset after the last byte read from the source, `None` when it
    /// passes `u64::MAX`.
    pub fn source_end(&self) -> Option<u64> {
        self.source_offset.checked_add(self.byte_count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input(persistent: u64, volatile: u64, source: u64, target: u64, count: u64) -> Vec<u8> {
        [persistent, volatile, source, target, count]
            .iter()
            .flat_map(|word| word.to_le_bytes())
            .collect()
    }

    #[test]
    fn forty_bytes_parse_in_wire_order() {
        let request = DuplicateExtentsRequest::parse(&input(1, 2, 3, 4, 5)).unwrap();
        assert_eq!(
            request,
            DuplicateExtentsRequest {
                source: FileId::new(1, 2),
                source_offset: 3,
                target_offset: 4,
                byte_count: 5,
            }
        );
    }

    #[test]
    fn input_shorter_than_forty_bytes_fails() {
        let full = input(1, 2, 3, 4, 5);
        assert!(DuplicateExtentsRequest::parse(&[]).is_none());
        assert!(DuplicateExtentsRequest::parse(&full[..39]).is_none());
        assert!(DuplicateExtentsRequest::parse(&full).is_some());
    }

    #[test]
    fn bytes_after_the_structure_are_ignored() {
        let mut long = input(1, 2, 3, 4, 5);
        long.extend_from_slice(&[0xFF; 24]);
        assert_eq!(
            DuplicateExtentsRequest::parse(&long),
            DuplicateExtentsRequest::parse(&long[..40])
        );
    }

    #[test]
    fn the_source_end_stops_at_u64_max() {
        let at =
            |offset, count| DuplicateExtentsRequest::parse(&input(0, 0, offset, 0, count)).unwrap();
        assert_eq!(at(u64::MAX - 4096, 4096).source_end(), Some(u64::MAX));
        assert_eq!(at(u64::MAX - 4096, 4097).source_end(), None);
    }
}
