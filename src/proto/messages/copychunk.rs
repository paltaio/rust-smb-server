//! Server-side copy: FSCTL_SRV_REQUEST_RESUME_KEY, FSCTL_SRV_COPYCHUNK and
//! FSCTL_SRV_COPYCHUNK_WRITE (MS-SMB2 2.2.31.1, 2.2.32.1, 2.2.32.3). All
//! integers are little-endian.

use super::create::FileId;

/// Size of a resume key.
pub const RESUME_KEY_LEN: usize = 24;

/// Size of the tag that makes a resume key one of this server's.
pub(crate) const RESUME_TAG_LEN: usize = 8;

/// Most chunks one request may carry.
pub const MAX_CHUNKS: u32 = 256;

/// Largest chunk, in bytes.
pub const MAX_CHUNK_LEN: u32 = 1 << 20;

/// Most bytes one request may copy in all its chunks.
pub const MAX_COPY_LEN: u32 = 16 << 20;

/// Size of the SRV_COPYCHUNK_COPY fields before the chunks.
const HEADER_LEN: usize = 32;

/// Size of one SRV_COPYCHUNK.
const CHUNK_LEN: usize = 24;

/// Largest TargetOffset other than all ones.
const MAX_TARGET_OFFSET: u64 = i64::MAX as u64;

/// A resume key naming `file_id`: its volatile and persistent halves, then
/// `tag`.
pub(crate) fn resume_key(file_id: FileId, tag: &[u8; RESUME_TAG_LEN]) -> [u8; RESUME_KEY_LEN] {
    let mut key = [0; RESUME_KEY_LEN];
    key[..8].copy_from_slice(&file_id.volatile.to_le_bytes());
    key[8..16].copy_from_slice(&file_id.persistent.to_le_bytes());
    key[16..].copy_from_slice(tag);
    key
}

/// The FileId `key` names, or `None` when it does not end in `tag`.
pub(crate) fn resume_key_file_id(
    key: &[u8; RESUME_KEY_LEN],
    tag: &[u8; RESUME_TAG_LEN],
) -> Option<FileId> {
    if key[16..] != tag[..] {
        return None;
    }
    let half = |at: usize| u64::from_le_bytes(key[at..at + 8].try_into().expect("8 bytes"));
    Some(FileId::new(half(8), half(0)))
}

/// SRV_REQUEST_RESUME_KEY response: the key, ContextLength 0 and 4 bytes of
/// padding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResumeKeyResponse {
    pub key: [u8; RESUME_KEY_LEN],
}

impl ResumeKeyResponse {
    /// Size of the response.
    pub const LEN: usize = 32;

    pub fn encode(&self) -> Vec<u8> {
        let mut out = vec![0; Self::LEN];
        out[..RESUME_KEY_LEN].copy_from_slice(&self.key);
        out
    }
}

/// SRV_COPYCHUNK (MS-SMB2 2.2.31.1.1). The Reserved field is not read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Chunk {
    pub source_offset: u64,
    pub target_offset: u64,
    pub length: u32,
}

impl Chunk {
    /// The offset after the last byte read from the source, `None` when it
    /// passes `u64::MAX`.
    pub fn source_end(&self) -> Option<u64> {
        self.source_offset.checked_add(u64::from(self.length))
    }

    /// The offset after the last byte written to the target, `None` when it
    /// passes `u64::MAX`.
    pub fn target_end(&self) -> Option<u64> {
        self.target_offset.checked_add(u64::from(self.length))
    }
}

/// SRV_COPYCHUNK_COPY (MS-SMB2 2.2.31.1): the key of the source open and
/// the chunks to copy, within the limits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CopychunkRequest {
    pub source_key: [u8; RESUME_KEY_LEN],
    pub chunks: Vec<Chunk>,
}

/// A request that is cut short or breaks a limit, answered with
/// [`CopychunkResponse::LIMITS`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OverLimits {
    /// The request's SourceKey, when the input holds the fields before the
    /// chunks.
    pub source_key: Option<[u8; RESUME_KEY_LEN]>,
}

impl CopychunkRequest {
    /// Reads the input of an IOCTL request. It breaks a limit when it is
    /// shorter than its ChunkCount needs, has more than [`MAX_CHUNKS`]
    /// chunks, a chunk of no bytes or more than [`MAX_CHUNK_LEN`], more
    /// than [`MAX_COPY_LEN`] bytes in all, or a TargetOffset of 2^63 or
    /// more other than all ones. Bytes after the last chunk are ignored.
    pub fn parse(input: &[u8]) -> Result<Self, OverLimits> {
        let Some(header) = input.first_chunk::<HEADER_LEN>() else {
            return Err(OverLimits { source_key: None });
        };
        let source_key: [u8; RESUME_KEY_LEN] =
            header[..RESUME_KEY_LEN].try_into().expect("24 bytes");
        let over = OverLimits {
            source_key: Some(source_key),
        };
        let count = u32::from_le_bytes(header[24..28].try_into().expect("4 bytes"));
        if count > MAX_CHUNKS {
            return Err(over);
        }
        let count = count as usize;
        let Some(array) = input.get(HEADER_LEN..HEADER_LEN + count * CHUNK_LEN) else {
            return Err(over);
        };
        let mut chunks = Vec::with_capacity(count);
        let mut total = 0u64;
        for raw in array.chunks_exact(CHUNK_LEN) {
            let chunk = Chunk {
                source_offset: u64::from_le_bytes(raw[..8].try_into().expect("8 bytes")),
                target_offset: u64::from_le_bytes(raw[8..16].try_into().expect("8 bytes")),
                length: u32::from_le_bytes(raw[16..20].try_into().expect("4 bytes")),
            };
            let target_ok =
                chunk.target_offset <= MAX_TARGET_OFFSET || chunk.target_offset == u64::MAX;
            if chunk.length == 0 || chunk.length > MAX_CHUNK_LEN || !target_ok {
                return Err(over);
            }
            total += u64::from(chunk.length);
            chunks.push(chunk);
        }
        if total > u64::from(MAX_COPY_LEN) {
            return Err(over);
        }
        Ok(Self { source_key, chunks })
    }
}

/// SRV_COPYCHUNK_RESPONSE (MS-SMB2 2.2.32.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CopychunkResponse {
    pub chunks_written: u32,
    pub chunk_bytes_written: u32,
    pub total_bytes_written: u32,
}

impl CopychunkResponse {
    /// Size of the response.
    pub const LEN: usize = 12;

    /// A response that reports no chunk and no byte.
    pub const ZERO: Self = Self {
        chunks_written: 0,
        chunk_bytes_written: 0,
        total_bytes_written: 0,
    };

    /// The limits, which a request that breaks one gets with
    /// STATUS_INVALID_PARAMETER.
    pub const LIMITS: Self = Self {
        chunks_written: MAX_CHUNKS,
        chunk_bytes_written: MAX_CHUNK_LEN,
        total_bytes_written: MAX_COPY_LEN,
    };

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(Self::LEN);
        out.extend_from_slice(&self.chunks_written.to_le_bytes());
        out.extend_from_slice(&self.chunk_bytes_written.to_le_bytes());
        out.extend_from_slice(&self.total_bytes_written.to_le_bytes());
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: [u8; RESUME_KEY_LEN] = [0x77; RESUME_KEY_LEN];

    fn input(count: u32, chunks: &[(u64, u64, u32)]) -> Vec<u8> {
        let mut input = KEY.to_vec();
        input.extend_from_slice(&count.to_le_bytes());
        input.extend_from_slice(&[0; 4]);
        for &(source, target, length) in chunks {
            input.extend_from_slice(&source.to_le_bytes());
            input.extend_from_slice(&target.to_le_bytes());
            input.extend_from_slice(&length.to_le_bytes());
            input.extend_from_slice(&[0; 4]);
        }
        input
    }

    fn over() -> OverLimits {
        OverLimits {
            source_key: Some(KEY),
        }
    }

    #[test]
    fn a_header_without_chunks_parses() {
        let request = CopychunkRequest::parse(&input(0, &[])).unwrap();
        assert_eq!(request.source_key, KEY);
        assert!(request.chunks.is_empty());
    }

    #[test]
    fn chunks_parse_in_order() {
        let chunks = [(0, 4096, 100), (7, 9, 1), (1 << 40, 1 << 41, 1 << 20)];
        let request = CopychunkRequest::parse(&input(3, &chunks)).unwrap();
        let expected: Vec<Chunk> = chunks
            .iter()
            .map(|&(source_offset, target_offset, length)| Chunk {
                source_offset,
                target_offset,
                length,
            })
            .collect();
        assert_eq!(request.chunks, expected);
    }

    #[test]
    fn the_most_chunks_parse() {
        let chunks = vec![(0, 0, MAX_CHUNK_LEN / 16); 256];
        let request = CopychunkRequest::parse(&input(256, &chunks)).unwrap();
        assert_eq!(request.chunks.len(), 256);
    }

    #[test]
    fn more_chunks_than_the_limit_fail_before_the_array_is_read() {
        assert_eq!(
            CopychunkRequest::parse(&input(257, &vec![(0, 0, 1); 257])),
            Err(over()),
            "the whole array is there"
        );
        assert_eq!(
            CopychunkRequest::parse(&input(u32::MAX, &[(0, 0, 1)])),
            Err(over())
        );
    }

    #[test]
    fn input_shorter_than_the_chunk_count_needs_fails() {
        let full = input(2, &[(0, 0, 10), (10, 10, 10)]);
        assert!(CopychunkRequest::parse(&full).is_ok());
        assert_eq!(
            CopychunkRequest::parse(&full[..full.len() - 1]),
            Err(over())
        );
        assert_eq!(
            CopychunkRequest::parse(&input(2, &[(0, 0, 10)])),
            Err(over())
        );
    }

    #[test]
    fn input_shorter_than_the_header_has_no_key() {
        let none = OverLimits { source_key: None };
        assert_eq!(CopychunkRequest::parse(&[]), Err(none));
        assert_eq!(CopychunkRequest::parse(&input(0, &[])[..31]), Err(none));
    }

    #[test]
    fn bytes_after_the_last_chunk_are_ignored() {
        let mut long = input(1, &[(0, 0, 10)]);
        long.extend_from_slice(&[0xFF; 40]);
        assert_eq!(CopychunkRequest::parse(&long).unwrap().chunks.len(), 1);
    }

    #[test]
    fn reserved_fields_are_ignored() {
        let mut junk = input(1, &[(0, 0, 10)]);
        junk[28..32].copy_from_slice(&[0xAA; 4]);
        junk[32 + 20..32 + 24].copy_from_slice(&[0xBB; 4]);
        assert_eq!(CopychunkRequest::parse(&junk).unwrap().chunks.len(), 1);
    }

    #[test]
    fn chunk_lengths_are_bounded() {
        let limit = MAX_CHUNK_LEN;
        assert!(CopychunkRequest::parse(&input(1, &[(0, 0, limit)])).is_ok());
        assert_eq!(
            CopychunkRequest::parse(&input(1, &[(0, 0, 0)])),
            Err(over())
        );
        assert_eq!(
            CopychunkRequest::parse(&input(1, &[(0, 0, limit + 1)])),
            Err(over())
        );
        assert_eq!(
            CopychunkRequest::parse(&input(2, &[(0, 0, 10), (0, 0, 0)])),
            Err(over()),
            "a later chunk counts too"
        );
    }

    #[test]
    fn the_total_is_bounded() {
        let limit = MAX_CHUNK_LEN;
        let sixteen = vec![(0, 0, limit); 16];
        assert!(CopychunkRequest::parse(&input(16, &sixteen)).is_ok());
        let mut over_by_one = sixteen;
        over_by_one.push((0, 0, 1));
        assert_eq!(
            CopychunkRequest::parse(&input(17, &over_by_one)),
            Err(over())
        );
    }

    #[test]
    fn target_offsets_stop_below_two_to_the_63() {
        let top = i64::MAX as u64;
        assert!(CopychunkRequest::parse(&input(1, &[(0, top, 10)])).is_ok());
        assert_eq!(
            CopychunkRequest::parse(&input(1, &[(0, top + 1, 10)])),
            Err(over())
        );
        assert_eq!(
            CopychunkRequest::parse(&input(1, &[(0, u64::MAX - 1, 10)])),
            Err(over())
        );
        assert!(
            CopychunkRequest::parse(&input(1, &[(0, u64::MAX, 10)])).is_ok(),
            "all ones passes the limits check"
        );
    }

    #[test]
    fn source_offsets_are_not_limited() {
        let request = CopychunkRequest::parse(&input(1, &[(u64::MAX - 3, 0, 10)])).unwrap();
        assert_eq!(request.chunks[0].source_offset, u64::MAX - 3);
    }

    #[test]
    fn chunk_ends_stop_at_u64_max() {
        let at_source_end = Chunk {
            source_offset: u64::MAX - 10,
            target_offset: 4096,
            length: 10,
        };
        assert_eq!(at_source_end.source_end(), Some(u64::MAX));
        assert_eq!(at_source_end.target_end(), Some(4106));
        let past = Chunk {
            length: 11,
            ..at_source_end
        };
        assert_eq!(past.source_end(), None);
        assert_eq!(past.target_end(), Some(4107));

        let at_target_end = Chunk {
            source_offset: 4096,
            target_offset: u64::MAX - 10,
            length: 10,
        };
        assert_eq!(at_target_end.source_end(), Some(4106));
        assert_eq!(at_target_end.target_end(), Some(u64::MAX));
        let past = Chunk {
            length: 11,
            ..at_target_end
        };
        assert_eq!(past.source_end(), Some(4107));
        assert_eq!(past.target_end(), None);
    }

    #[test]
    fn responses_encode_in_wire_order() {
        let response = CopychunkResponse {
            chunks_written: 1,
            chunk_bytes_written: 2,
            total_bytes_written: 3,
        };
        assert_eq!(response.encode(), [1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0]);
    }

    #[test]
    fn a_resume_key_response_is_the_key_and_eight_zero_bytes() {
        let key: [u8; RESUME_KEY_LEN] = std::array::from_fn(|i| i as u8 + 1);
        let out = ResumeKeyResponse { key }.encode();
        assert_eq!(out.len(), 32);
        assert_eq!(out[..24], key);
        assert_eq!(out[24..], [0; 8], "ContextLength 0 and 4 bytes of padding");
    }

    #[test]
    fn a_resume_key_names_its_file_id() {
        let tag = [9, 8, 7, 6, 5, 4, 3, 2];
        let id = FileId::new(0x1122_3344_5566_7788, 0x99AA_BBCC_DDEE_FF00);
        let key = resume_key(id, &tag);
        assert_eq!(key[..8], id.volatile.to_le_bytes());
        assert_eq!(key[8..16], id.persistent.to_le_bytes());
        assert_eq!(key[16..], tag);
        assert_eq!(resume_key_file_id(&key, &tag), Some(id));
    }

    #[test]
    fn a_resume_key_with_another_tag_names_nothing() {
        let id = FileId::new(5, 5);
        let key = resume_key(id, &[1; RESUME_TAG_LEN]);
        assert_eq!(resume_key_file_id(&key, &[2; RESUME_TAG_LEN]), None);
        for at in 16..24 {
            let mut other = key;
            other[at] ^= 1;
            assert_eq!(resume_key_file_id(&other, &[1; RESUME_TAG_LEN]), None);
        }
    }
}
