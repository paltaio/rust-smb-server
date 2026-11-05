//! QUERY_INFO Request/Response (MS-SMB2 §2.2.37 / §2.2.38).

use binrw::{BinRead, BinWrite, binrw};
use std::io::Cursor;

use super::create::FileId;
use crate::proto::error::ProtoResult;

/// `InfoType` values (MS-SMB2 §2.2.37 InfoType field).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum InfoType {
    File = 0x01,
    FileSystem = 0x02,
    Security = 0x03,
    Quota = 0x04,
}

impl InfoType {
    pub fn from_u8(v: u8) -> Option<Self> {
        Some(match v {
            0x01 => Self::File,
            0x02 => Self::FileSystem,
            0x03 => Self::Security,
            0x04 => Self::Quota,
            _ => return None,
        })
    }
}

/// SMB2_QUERY_INFO_REQUEST (MS-SMB2 §2.2.37).
#[binrw]
#[brw(little)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueryInfoRequest {
    pub structure_size: u16,
    pub info_type: u8,
    pub file_information_class: u8,
    pub output_buffer_length: u32,
    pub input_buffer_offset: u16,
    pub reserved: u16,
    pub input_buffer_length: u32,
    /// `AdditionalInformation`: which fields of the security descriptor to
    /// return when `info_type == Security`, or the starting EA index for a
    /// `FileFullEaInformation` query. Zero for all other queries.
    pub additional_information: u32,
    pub flags: u32,
    pub file_id: FileId,
    /// `input_buffer_length` bytes at `input_buffer_offset`, counted from
    /// the start of the SMB2 header and not before the end of the fixed
    /// fields: the extended attribute names of a `FileFullEaInformation`
    /// query.
    #[br(parse_with = super::read_buf_at, args(
        input_buffer_offset.into(),
        input_buffer_length as usize,
        QUERY_INFO_BUFFER_OFFSET,
    ))]
    #[bw(write_with = super::write_buf_at, args(u64::from(*input_buffer_offset)))]
    pub input_buffer: Vec<u8>,
}

/// Offset of the first byte after the fixed QUERY_INFO request fields,
/// counted from the start of the SMB2 header: 64 + 40.
const QUERY_INFO_BUFFER_OFFSET: u64 = 0x68;

impl QueryInfoRequest {
    /// Flag: SL_RESTART_SCAN.
    pub const FLAG_RESTART_SCAN: u32 = 0x0000_0001;
    /// Flag: SL_RETURN_SINGLE_ENTRY.
    pub const FLAG_RETURN_SINGLE_ENTRY: u32 = 0x0000_0002;
    /// Flag: SL_INDEX_SPECIFIED.
    pub const FLAG_INDEX_SPECIFIED: u32 = 0x0000_0004;

    pub fn info_type_enum(&self) -> Option<InfoType> {
        InfoType::from_u8(self.info_type)
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

/// SMB2_QUERY_INFO_RESPONSE (MS-SMB2 §2.2.38).
#[binrw]
#[brw(little)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueryInfoResponse {
    pub structure_size: u16,
    pub output_buffer_offset: u16,
    pub output_buffer_length: u32,
    #[br(parse_with = super::read_buf, args(output_buffer_length as usize))]
    pub buffer: Vec<u8>,
}

impl QueryInfoResponse {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_round_trips() {
        let r = QueryInfoRequest {
            structure_size: 41,
            info_type: InfoType::File as u8,
            file_information_class: 0x05, // FileStandardInformation
            output_buffer_length: 0x1000,
            input_buffer_offset: 0,
            reserved: 0,
            input_buffer_length: 0,
            additional_information: 0,
            flags: 0,
            file_id: FileId::new(1, 2),
            input_buffer: vec![],
        };
        let mut buf = Vec::new();
        r.write_to(&mut buf).unwrap();
        let decoded = QueryInfoRequest::parse(&buf).unwrap();
        assert_eq!(decoded, r);
        assert_eq!(decoded.info_type_enum(), Some(InfoType::File));
    }

    #[test]
    fn the_input_buffer_is_written_and_read_at_its_offset() {
        let request = QueryInfoRequest {
            structure_size: 41,
            info_type: InfoType::File as u8,
            file_information_class: 0x0F,
            output_buffer_length: 0x1000,
            input_buffer_offset: 0x70,
            reserved: 0,
            input_buffer_length: 4,
            additional_information: 0,
            flags: 0,
            file_id: FileId::new(1, 2),
            input_buffer: vec![1, 2, 3, 4],
        };
        let mut body = Vec::new();
        request.write_to(&mut body).unwrap();
        // 0x70 is 8 bytes past the end of the fixed fields.
        assert_eq!(body[40..], [0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4]);
        assert_eq!(QueryInfoRequest::parse(&body).unwrap(), request);
        // Inside the fixed fields.
        body[8..10].copy_from_slice(&0x60u16.to_le_bytes());
        assert!(QueryInfoRequest::parse(&body).is_err());
    }

    #[test]
    fn response_round_trips() {
        let r = QueryInfoResponse {
            structure_size: 9,
            output_buffer_offset: 0x48,
            output_buffer_length: 4,
            buffer: vec![0xAB, 0xCD, 0xEF, 0x01],
        };
        let mut buf = Vec::new();
        r.write_to(&mut buf).unwrap();
        assert_eq!(QueryInfoResponse::parse(&buf).unwrap(), r);
    }
}
