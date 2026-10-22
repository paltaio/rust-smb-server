//! CHANGE_NOTIFY Request/Response (MS-SMB2 2.2.35 / 2.2.36) and the
//! FILE_NOTIFY_INFORMATION entries a response carries (MS-FSCC 2.7.1).

use binrw::{BinRead, BinWrite, binrw};
use std::io::Cursor;

use super::create::FileId;
use crate::proto::error::ProtoResult;

// CompletionFilter bits (MS-SMB2 2.2.35).
pub const FILE_NOTIFY_CHANGE_FILE_NAME: u32 = 0x0000_0001;
pub const FILE_NOTIFY_CHANGE_DIR_NAME: u32 = 0x0000_0002;
pub const FILE_NOTIFY_CHANGE_ATTRIBUTES: u32 = 0x0000_0004;
pub const FILE_NOTIFY_CHANGE_SIZE: u32 = 0x0000_0008;
pub const FILE_NOTIFY_CHANGE_LAST_WRITE: u32 = 0x0000_0010;
pub const FILE_NOTIFY_CHANGE_LAST_ACCESS: u32 = 0x0000_0020;
pub const FILE_NOTIFY_CHANGE_CREATION: u32 = 0x0000_0040;
pub const FILE_NOTIFY_CHANGE_EA: u32 = 0x0000_0080;
pub const FILE_NOTIFY_CHANGE_SECURITY: u32 = 0x0000_0100;
pub const FILE_NOTIFY_CHANGE_STREAM_NAME: u32 = 0x0000_0200;
pub const FILE_NOTIFY_CHANGE_STREAM_SIZE: u32 = 0x0000_0400;
pub const FILE_NOTIFY_CHANGE_STREAM_WRITE: u32 = 0x0000_0800;
/// Every CompletionFilter bit; a server ignores the others.
pub const FILE_NOTIFY_VALID_MASK: u32 = 0x0000_0FFF;

// Action of a FILE_NOTIFY_INFORMATION entry (MS-FSCC 2.7.1).
pub const FILE_ACTION_ADDED: u32 = 1;
pub const FILE_ACTION_REMOVED: u32 = 2;
pub const FILE_ACTION_MODIFIED: u32 = 3;
pub const FILE_ACTION_RENAMED_OLD_NAME: u32 = 4;
pub const FILE_ACTION_RENAMED_NEW_NAME: u32 = 5;

/// Bytes of a FILE_NOTIFY_INFORMATION entry before its name.
const ENTRY_HEADER_LEN: usize = 12;

#[binrw]
#[brw(little)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChangeNotifyRequest {
    pub structure_size: u16,
    pub flags: u16,
    pub output_buffer_length: u32,
    pub file_id: FileId,
    pub completion_filter: u32,
    pub reserved: u32,
}

impl ChangeNotifyRequest {
    /// Flag: SMB2_WATCH_TREE.
    pub const FLAG_WATCH_TREE: u16 = 0x0001;

    pub fn parse(buf: &[u8]) -> ProtoResult<Self> {
        Ok(Self::read(&mut Cursor::new(buf))?)
    }
    pub fn write_to(&self, out: &mut Vec<u8>) -> ProtoResult<()> {
        let mut c = Cursor::new(Vec::new());
        BinWrite::write(self, &mut c)?;
        out.extend_from_slice(&c.into_inner());
        Ok(())
    }
}

#[binrw]
#[brw(little)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChangeNotifyResponse {
    pub structure_size: u16,
    pub output_buffer_offset: u16,
    pub output_buffer_length: u32,
    #[br(parse_with = super::read_buf, args(output_buffer_length as usize))]
    pub buffer: Vec<u8>,
}

impl ChangeNotifyResponse {
    /// OutputBufferOffset: the buffer follows the fixed part of the body.
    pub const BUFFER_OFFSET: u16 = 0x48;

    /// The response body carrying the entries `buffer`. An empty buffer
    /// still takes the one byte StructureSize 9 counts.
    pub(crate) fn encode(buffer: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(8 + buffer.len().max(1));
        out.extend_from_slice(&9u16.to_le_bytes());
        out.extend_from_slice(&Self::BUFFER_OFFSET.to_le_bytes());
        out.extend_from_slice(&(buffer.len() as u32).to_le_bytes());
        out.extend_from_slice(buffer);
        if buffer.is_empty() {
            out.push(0);
        }
        out
    }

    pub fn parse(buf: &[u8]) -> ProtoResult<Self> {
        Ok(Self::read(&mut Cursor::new(buf))?)
    }
    pub fn write_to(&self, out: &mut Vec<u8>) -> ProtoResult<()> {
        let mut c = Cursor::new(Vec::new());
        BinWrite::write(self, &mut c)?;
        out.extend_from_slice(&c.into_inner());
        Ok(())
    }
}

/// Appends a FILE_NOTIFY_INFORMATION entry for `action` on `name` to
/// `buf`, padded to 4 bytes, and points the NextEntryOffset of the entry
/// at `last` to it; `last` then names the new entry. An entry equal to the
/// one at `last` is not added again.
pub(crate) fn push_entry(buf: &mut Vec<u8>, last: &mut Option<usize>, action: u32, name: &[u16]) {
    let name_len = name.len() * 2;
    if let Some(at) = *last {
        let same_name = buf[at + 8..at + 12] == (name_len as u32).to_le_bytes()
            && buf[at + ENTRY_HEADER_LEN..]
                .chunks_exact(2)
                .zip(name)
                .all(|(unit, &c)| unit == c.to_le_bytes());
        if same_name && buf[at + 4..at + 8] == action.to_le_bytes() {
            return;
        }
        let next = (buf.len() - at) as u32;
        buf[at..at + 4].copy_from_slice(&next.to_le_bytes());
    }
    let start = buf.len();
    buf.extend_from_slice(&0u32.to_le_bytes());
    buf.extend_from_slice(&action.to_le_bytes());
    buf.extend_from_slice(&(name_len as u32).to_le_bytes());
    buf.extend(name.iter().flat_map(|c| c.to_le_bytes()));
    buf.resize(start + (ENTRY_HEADER_LEN + name_len).next_multiple_of(4), 0);
    *last = Some(start);
}

/// Length of the entries in `buf` without the padding after the last one,
/// which starts at `last`: what a response carries.
pub(crate) fn entries_len(buf: &[u8], last: Option<usize>) -> usize {
    match last {
        Some(at) => {
            let name_len = u32::from_le_bytes(buf[at + 8..at + 12].try_into().expect("4 bytes"));
            at + ENTRY_HEADER_LEN + name_len as usize
        }
        None => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_round_trips() {
        let r = ChangeNotifyRequest {
            structure_size: 32,
            flags: ChangeNotifyRequest::FLAG_WATCH_TREE,
            output_buffer_length: 0x1000,
            file_id: FileId::new(1, 2),
            completion_filter: 0xFF,
            reserved: 0,
        };
        let mut buf = Vec::new();
        r.write_to(&mut buf).unwrap();
        assert_eq!(ChangeNotifyRequest::parse(&buf).unwrap(), r);
    }

    #[test]
    fn response_round_trips() {
        let r = ChangeNotifyResponse {
            structure_size: 9,
            output_buffer_offset: 0x48,
            output_buffer_length: 0,
            buffer: vec![],
        };
        let mut buf = Vec::new();
        r.write_to(&mut buf).unwrap();
        assert_eq!(ChangeNotifyResponse::parse(&buf).unwrap(), r);
    }

    fn units(s: &str) -> Vec<u16> {
        s.encode_utf16().collect()
    }

    /// (NextEntryOffset, Action, name) of each entry, checking the layout
    /// rules of MS-FSCC 2.7.1 on the way.
    fn entries(buf: &[u8]) -> Vec<(u32, u32, String)> {
        let mut out = Vec::new();
        let mut at = 0;
        loop {
            let field = |o: usize| u32::from_le_bytes(buf[at + o..at + o + 4].try_into().unwrap());
            let (next, action, len) = (field(0), field(4), field(8) as usize);
            assert_eq!(len % 2, 0);
            let name: Vec<u16> = buf[at + 12..at + 12 + len]
                .chunks_exact(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .collect();
            out.push((next, action, String::from_utf16(&name).unwrap()));
            if next == 0 {
                assert_eq!(at + 12 + len, buf.len(), "the last entry is not padded");
                return out;
            }
            assert_eq!(next % 4, 0);
            assert_eq!(next as usize, (12 + len).next_multiple_of(4));
            at += next as usize;
        }
    }

    #[test]
    fn entries_chain_and_pad_to_four_bytes() {
        let mut buf = Vec::new();
        let mut last = None;
        assert_eq!(entries_len(&buf, last), 0);
        push_entry(&mut buf, &mut last, FILE_ACTION_ADDED, &units("ab"));
        assert_eq!(buf.len(), 16);
        assert_eq!(entries_len(&buf, last), 16);
        push_entry(&mut buf, &mut last, FILE_ACTION_REMOVED, &units("odd"));
        push_entry(&mut buf, &mut last, FILE_ACTION_ADDED, &units("d\\été"));
        assert_eq!(buf.len() % 4, 0);
        let len = entries_len(&buf, last);
        assert_eq!(len, 16 + 20 + 12 + 10);
        assert_eq!(
            entries(&buf[..len]),
            [
                (16, FILE_ACTION_ADDED, "ab".to_string()),
                (20, FILE_ACTION_REMOVED, "odd".to_string()),
                (0, FILE_ACTION_ADDED, "d\\été".to_string()),
            ]
        );
    }

    #[test]
    fn only_adjacent_duplicates_collapse() {
        let mut buf = Vec::new();
        let mut last = None;
        push_entry(&mut buf, &mut last, FILE_ACTION_ADDED, &units("x"));
        push_entry(&mut buf, &mut last, FILE_ACTION_ADDED, &units("x"));
        push_entry(&mut buf, &mut last, FILE_ACTION_REMOVED, &units("x"));
        push_entry(&mut buf, &mut last, FILE_ACTION_ADDED, &units("x"));
        push_entry(&mut buf, &mut last, FILE_ACTION_ADDED, &units("xy"));
        let len = entries_len(&buf, last);
        let found: Vec<_> = entries(&buf[..len])
            .into_iter()
            .map(|(_, action, name)| (action, name))
            .collect();
        assert_eq!(
            found,
            [
                (FILE_ACTION_ADDED, "x".to_string()),
                (FILE_ACTION_REMOVED, "x".to_string()),
                (FILE_ACTION_ADDED, "x".to_string()),
                (FILE_ACTION_ADDED, "xy".to_string()),
            ]
        );
    }

    #[test]
    fn responses_without_entries_keep_one_byte() {
        let empty = ChangeNotifyResponse::encode(&[]);
        assert_eq!(empty, [9, 0, 0x48, 0, 0, 0, 0, 0, 0]);
        let full = ChangeNotifyResponse::encode(&[1, 2, 3]);
        let parsed = ChangeNotifyResponse::parse(&full).unwrap();
        assert_eq!(parsed.output_buffer_length, 3);
        assert_eq!(parsed.buffer, [1, 2, 3]);
    }
}
