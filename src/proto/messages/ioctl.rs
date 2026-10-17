//! IOCTL Request/Response (MS-SMB2 §2.2.31 / §2.2.32).

use binrw::{BinRead, BinWrite, binrw};
use std::io::Cursor;

use super::create::FileId;
use crate::proto::error::ProtoResult;

/// File-system control codes we recognize at the wire layer.
///
/// MS-FSCC lists the full set. Unknown codes round-trip via [`Fsctl::Other`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fsctl {
    /// `FSCTL_VALIDATE_NEGOTIATE_INFO`.
    ValidateNegotiateInfo,
    /// `FSCTL_DFS_GET_REFERRALS`.
    DfsGetReferrals,
    /// `FSCTL_DFS_GET_REFERRALS_EX`.
    DfsGetReferralsEx,
    /// `FSCTL_PIPE_TRANSCEIVE`.
    PipeTransceive,
    /// `FSCTL_PIPE_PEEK`.
    PipePeek,
    /// `FSCTL_PIPE_WAIT`.
    PipeWait,
    /// `FSCTL_LMR_REQUEST_RESILIENCY`.
    LmrRequestResiliency,
    /// `FSCTL_QUERY_NETWORK_INTERFACE_INFO`.
    QueryNetworkInterfaceInfo,
    /// `FSCTL_SRV_ENUMERATE_SNAPSHOTS`.
    SrvEnumerateSnapshots,
    /// Anything else.
    Other(u32),
}

impl Fsctl {
    pub const VALIDATE_NEGOTIATE_INFO: u32 = 0x0014_0204;
    pub const DFS_GET_REFERRALS: u32 = 0x0006_0194;
    pub const DFS_GET_REFERRALS_EX: u32 = 0x0006_01B0;
    pub const PIPE_TRANSCEIVE: u32 = 0x0011_C017;
    pub const PIPE_PEEK: u32 = 0x0011_400C;
    pub const PIPE_WAIT: u32 = 0x0011_0018;
    pub const LMR_REQUEST_RESILIENCY: u32 = 0x0014_01D4;
    pub const QUERY_NETWORK_INTERFACE_INFO: u32 = 0x0014_01FC;
    pub const SRV_ENUMERATE_SNAPSHOTS: u32 = 0x0014_4064;

    pub fn from_u32(code: u32) -> Self {
        match code {
            Self::VALIDATE_NEGOTIATE_INFO => Self::ValidateNegotiateInfo,
            Self::DFS_GET_REFERRALS => Self::DfsGetReferrals,
            Self::DFS_GET_REFERRALS_EX => Self::DfsGetReferralsEx,
            Self::PIPE_TRANSCEIVE => Self::PipeTransceive,
            Self::PIPE_PEEK => Self::PipePeek,
            Self::PIPE_WAIT => Self::PipeWait,
            Self::LMR_REQUEST_RESILIENCY => Self::LmrRequestResiliency,
            Self::QUERY_NETWORK_INTERFACE_INFO => Self::QueryNetworkInterfaceInfo,
            Self::SRV_ENUMERATE_SNAPSHOTS => Self::SrvEnumerateSnapshots,
            other => Self::Other(other),
        }
    }

    pub fn as_u32(self) -> u32 {
        match self {
            Self::ValidateNegotiateInfo => Self::VALIDATE_NEGOTIATE_INFO,
            Self::DfsGetReferrals => Self::DFS_GET_REFERRALS,
            Self::DfsGetReferralsEx => Self::DFS_GET_REFERRALS_EX,
            Self::PipeTransceive => Self::PIPE_TRANSCEIVE,
            Self::PipePeek => Self::PIPE_PEEK,
            Self::PipeWait => Self::PIPE_WAIT,
            Self::LmrRequestResiliency => Self::LMR_REQUEST_RESILIENCY,
            Self::QueryNetworkInterfaceInfo => Self::QUERY_NETWORK_INTERFACE_INFO,
            Self::SrvEnumerateSnapshots => Self::SRV_ENUMERATE_SNAPSHOTS,
            Self::Other(c) => c,
        }
    }
}

/// SMB2_IOCTL_REQUEST (MS-SMB2 §2.2.31).
///
/// `input_offset` and `output_offset` are absolute (from the start of the
/// SMB2 header). `input` is read immediately after the fixed prefix.
#[binrw]
#[brw(little)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IoctlRequest {
    pub structure_size: u16,
    pub reserved: u16,
    pub ctl_code: u32,
    pub file_id: FileId,
    pub input_offset: u32,
    pub input_count: u32,
    pub max_input_response: u32,
    pub output_offset: u32,
    pub output_count: u32,
    pub max_output_response: u32,
    pub flags: u32,
    pub reserved2: u32,
    #[br(parse_with = super::read_buf, args(input_count as usize))]
    pub input: Vec<u8>,
}

impl IoctlRequest {
    /// Flag: SMB2_0_IOCTL_IS_FSCTL.
    pub const FLAG_IS_FSCTL: u32 = 0x0000_0001;

    pub fn fsctl(&self) -> Fsctl {
        Fsctl::from_u32(self.ctl_code)
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

/// SMB2_IOCTL_RESPONSE (MS-SMB2 §2.2.32).
#[binrw]
#[brw(little)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IoctlResponse {
    pub structure_size: u16,
    pub reserved: u16,
    pub ctl_code: u32,
    pub file_id: FileId,
    pub input_offset: u32,
    pub input_count: u32,
    pub output_offset: u32,
    pub output_count: u32,
    pub flags: u32,
    pub reserved2: u32,
    /// Output buffer immediately following the fixed prefix.
    #[br(parse_with = super::read_buf, args(output_count as usize))]
    pub output: Vec<u8>,
}

impl IoctlResponse {
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
    fn fsctl_decode_known() {
        assert_eq!(Fsctl::from_u32(0x0014_0204), Fsctl::ValidateNegotiateInfo);
        assert_eq!(Fsctl::from_u32(0xDEAD_BEEF), Fsctl::Other(0xDEAD_BEEF));
        assert_eq!(Fsctl::ValidateNegotiateInfo.as_u32(), 0x0014_0204);
        assert_eq!(Fsctl::Other(0xDEAD_BEEF).as_u32(), 0xDEAD_BEEF);
    }

    /// Codes from the MS-SMB2 2.2.31 CtlCode table.
    #[test]
    fn fsctl_codes_match_ms_smb2() {
        for (code, fsctl) in [
            (0x0006_0194, Fsctl::DfsGetReferrals),
            (0x0011_0018, Fsctl::PipeWait),
            (0x0011_C017, Fsctl::PipeTransceive),
            (0x0014_4064, Fsctl::SrvEnumerateSnapshots),
            (0x0014_01D4, Fsctl::LmrRequestResiliency),
            (0x0014_01FC, Fsctl::QueryNetworkInterfaceInfo),
            (0x0014_0204, Fsctl::ValidateNegotiateInfo),
            (0x0006_01B0, Fsctl::DfsGetReferralsEx),
        ] {
            assert_eq!(Fsctl::from_u32(code), fsctl, "0x{code:08X}");
            assert_eq!(fsctl.as_u32(), code);
        }
    }

    #[test]
    fn request_round_trips() {
        let r = IoctlRequest {
            structure_size: 57,
            reserved: 0,
            ctl_code: Fsctl::VALIDATE_NEGOTIATE_INFO,
            file_id: FileId::any(),
            input_offset: 0x78,
            input_count: 4,
            max_input_response: 0,
            output_offset: 0,
            output_count: 0,
            max_output_response: 0x1000,
            flags: IoctlRequest::FLAG_IS_FSCTL,
            reserved2: 0,
            input: vec![0xCA, 0xFE, 0xBA, 0xBE],
        };
        let mut buf = Vec::new();
        r.write_to(&mut buf).unwrap();
        let decoded = IoctlRequest::parse(&buf).unwrap();
        assert_eq!(decoded, r);
        assert_eq!(decoded.fsctl(), Fsctl::ValidateNegotiateInfo);
    }

    #[test]
    fn response_round_trips() {
        let r = IoctlResponse {
            structure_size: 49,
            reserved: 0,
            ctl_code: Fsctl::VALIDATE_NEGOTIATE_INFO,
            file_id: FileId::any(),
            input_offset: 0,
            input_count: 0,
            output_offset: 0x70,
            output_count: 4,
            flags: 0,
            reserved2: 0,
            output: vec![1, 2, 3, 4],
        };
        let mut buf = Vec::new();
        r.write_to(&mut buf).unwrap();
        assert_eq!(IoctlResponse::parse(&buf).unwrap(), r);
    }
}
