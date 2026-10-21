//! Durable handle create contexts (MS-SMB2 2.2.13.2.3, 2.2.13.2.4,
//! 2.2.13.2.11, 2.2.13.2.12, 2.2.14.2.3, 2.2.14.2.12).

use crate::proto::error::{ProtoError, ProtoResult};

use super::create::FileId;

/// SMB2_DHANDLE_FLAG_PERSISTENT.
pub const DHANDLE_FLAG_PERSISTENT: u32 = 0x0000_0002;

/// Data of a `DHnQ` request context.
pub const DURABLE_REQUEST_LEN: usize = 16;
/// Data of a `DHnC` context.
pub const DURABLE_RECONNECT_LEN: usize = 16;
/// Data of a `DH2Q` request context.
pub const DURABLE_REQUEST_V2_LEN: usize = 32;
/// Data of a `DH2C` context.
pub const DURABLE_RECONNECT_V2_LEN: usize = 36;

fn u32_at(data: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(data[at..at + 4].try_into().expect("4 bytes"))
}

fn u64_at(data: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(data[at..at + 8].try_into().expect("8 bytes"))
}

fn file_id_at(data: &[u8], at: usize) -> FileId {
    FileId::new(u64_at(data, at), u64_at(data, at + 8))
}

fn check_len(data: &[u8], len: usize, what: &'static str) -> ProtoResult<()> {
    if data.len() == len {
        Ok(())
    } else {
        Err(ProtoError::Malformed(what))
    }
}

/// SMB2_CREATE_DURABLE_HANDLE_REQUEST, the data of a `DHnQ` request
/// context: 16 reserved bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct DurableRequest;

impl DurableRequest {
    pub fn parse(data: &[u8]) -> ProtoResult<Self> {
        check_len(data, DURABLE_REQUEST_LEN, "durable request size")?;
        Ok(Self)
    }
}

/// SMB2_CREATE_DURABLE_HANDLE_RECONNECT, the data of a `DHnC` context.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct DurableReconnect {
    pub file_id: FileId,
}

impl DurableReconnect {
    pub fn parse(data: &[u8]) -> ProtoResult<Self> {
        check_len(data, DURABLE_RECONNECT_LEN, "durable reconnect size")?;
        Ok(Self {
            file_id: file_id_at(data, 0),
        })
    }
}

/// SMB2_CREATE_DURABLE_HANDLE_REQUEST_V2, the data of a `DH2Q` context.
/// The CreateGuid is kept as the 16 bytes on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct DurableRequestV2 {
    pub timeout_ms: u32,
    pub flags: u32,
    pub create_guid: [u8; 16],
}

impl DurableRequestV2 {
    pub fn parse(data: &[u8]) -> ProtoResult<Self> {
        check_len(data, DURABLE_REQUEST_V2_LEN, "durable v2 request size")?;
        Ok(Self {
            timeout_ms: u32_at(data, 0),
            flags: u32_at(data, 4),
            create_guid: data[16..32].try_into().expect("16 bytes"),
        })
    }
}

/// SMB2_CREATE_DURABLE_HANDLE_RECONNECT_V2, the data of a `DH2C` context.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct DurableReconnectV2 {
    pub file_id: FileId,
    pub create_guid: [u8; 16],
    pub flags: u32,
}

impl DurableReconnectV2 {
    pub fn parse(data: &[u8]) -> ProtoResult<Self> {
        check_len(data, DURABLE_RECONNECT_V2_LEN, "durable v2 reconnect size")?;
        Ok(Self {
            file_id: file_id_at(data, 0),
            create_guid: data[16..32].try_into().expect("16 bytes"),
            flags: u32_at(data, 32),
        })
    }
}

/// SMB2_CREATE_DURABLE_HANDLE_RESPONSE: 8 reserved bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct DurableResponse;

impl DurableResponse {
    pub fn encode(&self) -> Vec<u8> {
        vec![0; 8]
    }
}

/// SMB2_CREATE_DURABLE_HANDLE_RESPONSE_V2.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct DurableResponseV2 {
    pub timeout_ms: u32,
    pub flags: u32,
}

impl DurableResponseV2 {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(8);
        out.extend_from_slice(&self.timeout_ms.to_le_bytes());
        out.extend_from_slice(&self.flags.to_le_bytes());
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_context_has_one_size() {
        for len in [0, 15, 16, 17, 31, 32, 33, 35, 36, 37] {
            let data = vec![0; len];
            assert_eq!(DurableRequest::parse(&data).is_ok(), len == 16, "{len}");
            assert_eq!(DurableReconnect::parse(&data).is_ok(), len == 16, "{len}");
            assert_eq!(DurableRequestV2::parse(&data).is_ok(), len == 32, "{len}");
            assert_eq!(DurableReconnectV2::parse(&data).is_ok(), len == 36, "{len}");
        }
    }

    #[test]
    fn fields_sit_at_their_offsets() {
        let data: Vec<u8> = (0..36).collect();
        let id = FileId::new(
            u64::from_le_bytes([0, 1, 2, 3, 4, 5, 6, 7]),
            u64::from_le_bytes([8, 9, 10, 11, 12, 13, 14, 15]),
        );
        let guid: [u8; 16] = (16..32).collect::<Vec<u8>>().try_into().unwrap();

        assert_eq!(DurableReconnect::parse(&data[..16]).unwrap().file_id, id);
        let v2 = DurableRequestV2::parse(&data[..32]).unwrap();
        assert_eq!(v2.timeout_ms, u32::from_le_bytes([0, 1, 2, 3]));
        assert_eq!(v2.flags, u32::from_le_bytes([4, 5, 6, 7]));
        assert_eq!(v2.create_guid, guid);
        let reconnect = DurableReconnectV2::parse(&data).unwrap();
        assert_eq!(reconnect.file_id, id);
        assert_eq!(reconnect.create_guid, guid);
        assert_eq!(reconnect.flags, u32::from_le_bytes([32, 33, 34, 35]));
    }

    #[test]
    fn responses_have_their_fixed_layouts() {
        assert_eq!(DurableResponse.encode(), [0; 8]);
        let v2 = DurableResponseV2 {
            timeout_ms: 120_000,
            flags: DHANDLE_FLAG_PERSISTENT,
        };
        assert_eq!(v2.encode(), [0xC0, 0xD4, 0x01, 0x00, 2, 0, 0, 0]);
    }
}
