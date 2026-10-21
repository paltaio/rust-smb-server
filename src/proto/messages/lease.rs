//! Lease create contexts and lease break messages (MS-SMB2 2.2.13.2.8,
//! 2.2.13.2.10, 2.2.14.2.10, 2.2.14.2.11, 2.2.23.2, 2.2.24.2).

use binrw::{BinRead, BinWrite, binrw};
use std::io::Cursor;

use crate::proto::error::{ProtoError, ProtoResult};

/// SMB2_LEASE_READ_CACHING.
pub const LEASE_READ_CACHING: u32 = 0x01;
/// SMB2_LEASE_HANDLE_CACHING.
pub const LEASE_HANDLE_CACHING: u32 = 0x02;
/// SMB2_LEASE_WRITE_CACHING.
pub const LEASE_WRITE_CACHING: u32 = 0x04;

/// Data of a version 1 lease context.
pub const LEASE_V1_LEN: usize = 32;
/// Data of a version 2 lease context.
pub const LEASE_V2_LEN: usize = 52;

/// SMB2_CREATE_REQUEST_LEASE(_V2) and SMB2_CREATE_RESPONSE_LEASE(_V2), the
/// data of an `RqLs` create context. Request and response share one layout;
/// the version 2 form adds ParentLeaseKey and Epoch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct LeaseContext {
    pub key: [u8; 16],
    pub state: u32,
    pub flags: u32,
    /// Version 2 only.
    pub parent_key: [u8; 16],
    /// Version 2 only.
    pub epoch: u16,
    pub v2: bool,
}

impl LeaseContext {
    /// SMB2_LEASE_FLAG_BREAK_IN_PROGRESS, in responses.
    pub const FLAG_BREAK_IN_PROGRESS: u32 = 0x02;
    /// SMB2_LEASE_FLAG_PARENT_LEASE_KEY_SET, version 2 only.
    pub const FLAG_PARENT_LEASE_KEY_SET: u32 = 0x04;

    /// Parses 32 bytes as version 1 and 52 bytes as version 2. LeaseDuration
    /// and Reserved are ignored.
    pub fn parse(data: &[u8]) -> ProtoResult<Self> {
        let v2 = match data.len() {
            LEASE_V1_LEN => false,
            LEASE_V2_LEN => true,
            _ => return Err(ProtoError::Malformed("lease context size")),
        };
        let u32_at = |at: usize| u32::from_le_bytes(data[at..at + 4].try_into().expect("4 bytes"));
        let mut lease = Self {
            key: data[..16].try_into().expect("16 bytes"),
            state: u32_at(16),
            flags: u32_at(20),
            v2,
            ..Self::default()
        };
        if v2 {
            lease.parent_key = data[32..48].try_into().expect("16 bytes");
            lease.epoch = u16::from_le_bytes([data[48], data[49]]);
        }
        Ok(lease)
    }

    /// The 32- or 52-byte context data.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(LEASE_V2_LEN);
        out.extend_from_slice(&self.key);
        out.extend_from_slice(&self.state.to_le_bytes());
        out.extend_from_slice(&self.flags.to_le_bytes());
        out.extend_from_slice(&0u64.to_le_bytes());
        if self.v2 {
            out.extend_from_slice(&self.parent_key);
            out.extend_from_slice(&self.epoch.to_le_bytes());
            out.extend_from_slice(&0u16.to_le_bytes());
        }
        out
    }
}

/// Lease Break Notification (MS-SMB2 2.2.23.2).
#[binrw]
#[brw(little)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeaseBreakNotification {
    pub structure_size: u16,
    pub new_epoch: u16,
    pub flags: u32,
    pub lease_key: [u8; 16],
    pub current_lease_state: u32,
    pub new_lease_state: u32,
    pub break_reason: u32,
    pub access_mask_hint: u32,
    pub share_mask_hint: u32,
}

impl LeaseBreakNotification {
    /// SMB2_NOTIFY_BREAK_LEASE_FLAG_ACK_REQUIRED.
    pub const FLAG_ACK_REQUIRED: u32 = 0x01;

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

/// Lease Break Acknowledgment (MS-SMB2 2.2.24.2).
#[binrw]
#[brw(little)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeaseBreakAck {
    pub structure_size: u16,
    pub reserved: u16,
    pub flags: u32,
    pub lease_key: [u8; 16],
    pub lease_state: u32,
    pub lease_duration: u64,
}

impl LeaseBreakAck {
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

/// Lease Break Response (MS-SMB2 2.2.25.2): same wire shape as the
/// acknowledgment.
pub type LeaseBreakResponse = LeaseBreakAck;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn contexts_round_trip_in_both_versions() {
        let v1 = LeaseContext {
            key: [7; 16],
            state: LEASE_READ_CACHING | LEASE_HANDLE_CACHING,
            ..LeaseContext::default()
        };
        let data = v1.encode();
        assert_eq!(data.len(), LEASE_V1_LEN);
        assert_eq!(LeaseContext::parse(&data).unwrap(), v1);

        let v2 = LeaseContext {
            key: [1; 16],
            state: LEASE_READ_CACHING,
            flags: LeaseContext::FLAG_PARENT_LEASE_KEY_SET,
            parent_key: [2; 16],
            epoch: 9,
            v2: true,
        };
        let data = v2.encode();
        assert_eq!(data.len(), LEASE_V2_LEN);
        assert_eq!(LeaseContext::parse(&data).unwrap(), v2);
    }

    #[test]
    fn other_sizes_are_malformed() {
        for len in [0, 31, 33, 40, 51, 53] {
            assert!(LeaseContext::parse(&vec![0; len]).is_err(), "{len}");
        }
    }

    #[test]
    fn break_messages_have_their_fixed_sizes() {
        let notification = LeaseBreakNotification {
            structure_size: 44,
            new_epoch: 3,
            flags: 0,
            lease_key: [5; 16],
            current_lease_state: LEASE_READ_CACHING,
            new_lease_state: 0,
            break_reason: 0,
            access_mask_hint: 0,
            share_mask_hint: 0,
        };
        let mut buf = Vec::new();
        notification.write_to(&mut buf).unwrap();
        assert_eq!(buf.len(), 44);
        assert_eq!(LeaseBreakNotification::parse(&buf).unwrap(), notification);

        let ack = LeaseBreakAck {
            structure_size: 36,
            reserved: 0,
            flags: 0,
            lease_key: [5; 16],
            lease_state: 0,
            lease_duration: 0,
        };
        let mut buf = Vec::new();
        ack.write_to(&mut buf).unwrap();
        assert_eq!(buf.len(), 36);
        assert_eq!(LeaseBreakAck::parse(&buf).unwrap(), ack);
    }
}
