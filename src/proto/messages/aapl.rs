//! Apple's `AAPL` create context, which macOS clients send to find out
//! whether the server has Apple's SMB2 extensions. The layout is the one
//! Apple's SMB client and Samba use. All integers are little-endian.

use crate::proto::error::{ProtoError, ProtoResult};

/// CommandCode of a server query.
pub const AAPL_SERVER_QUERY: u32 = 1;

/// RequestBitmap and ReplyBitmap: the reply carries the server caps.
pub const AAPL_SERVER_CAPS: u64 = 0x01;
/// RequestBitmap and ReplyBitmap: the reply carries the volume caps.
pub const AAPL_VOLUME_CAPS: u64 = 0x02;
/// RequestBitmap and ReplyBitmap: the reply carries the model string.
pub const AAPL_MODEL_INFO: u64 = 0x04;

/// Client and server caps: directory listings carry Finder data
/// (READ_DIR_ATTR).
pub const AAPL_SUPPORTS_READ_DIR_ATTR: u64 = 0x01;
/// Server caps: the server runs on a Unix system.
pub const AAPL_UNIX_BASED: u64 = 0x04;

/// Volume caps: names on the share are case-sensitive.
pub const AAPL_CASE_SENSITIVE: u64 = 0x02;

/// Data of a server query.
pub const AAPL_QUERY_LEN: usize = 24;

/// A server query: CommandCode, Reserved, RequestBitmap and ClientCaps.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AaplQuery {
    /// What the client asks the reply to carry.
    pub bitmap: u64,
    /// The extensions the client has.
    pub client_caps: u64,
}

impl AaplQuery {
    /// Parses exactly [`AAPL_QUERY_LEN`] bytes whose CommandCode is
    /// [`AAPL_SERVER_QUERY`]. Reserved is ignored.
    pub fn parse(data: &[u8]) -> ProtoResult<Self> {
        let data: &[u8; AAPL_QUERY_LEN] = data
            .try_into()
            .map_err(|_| ProtoError::Malformed("AAPL context size"))?;
        let u64_at = |at: usize| u64::from_le_bytes(data[at..at + 8].try_into().expect("8 bytes"));
        if u32::from_le_bytes(data[..4].try_into().expect("4 bytes")) != AAPL_SERVER_QUERY {
            return Err(ProtoError::Malformed("AAPL command"));
        }
        Ok(Self {
            bitmap: u64_at(8),
            client_caps: u64_at(16),
        })
    }
}

/// The reply to a server query.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AaplReply<'a> {
    /// The parts the reply carries. Bits other than [`AAPL_SERVER_CAPS`],
    /// [`AAPL_VOLUME_CAPS`] and [`AAPL_MODEL_INFO`] are left out.
    pub bitmap: u64,
    pub server_caps: u64,
    pub volume_caps: u64,
    pub model: &'a str,
}

impl AaplReply<'_> {
    /// CommandCode, Reserved and ReplyBitmap, then, for each bit of the
    /// bitmap in bit order: ServerCaps; VolumeCaps; Pad, the length of the
    /// model in bytes and the model in UTF-16LE without a terminator.
    pub fn encode(&self) -> Vec<u8> {
        let bitmap = self.bitmap & (AAPL_SERVER_CAPS | AAPL_VOLUME_CAPS | AAPL_MODEL_INFO);
        let mut out = Vec::with_capacity(40 + 2 * self.model.len());
        out.extend_from_slice(&AAPL_SERVER_QUERY.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&bitmap.to_le_bytes());
        if bitmap & AAPL_SERVER_CAPS != 0 {
            out.extend_from_slice(&self.server_caps.to_le_bytes());
        }
        if bitmap & AAPL_VOLUME_CAPS != 0 {
            out.extend_from_slice(&self.volume_caps.to_le_bytes());
        }
        if bitmap & AAPL_MODEL_INFO != 0 {
            let model = crate::utils::utf16le(self.model);
            out.extend_from_slice(&0u32.to_le_bytes());
            out.extend_from_slice(&(model.len() as u32).to_le_bytes());
            out.extend_from_slice(&model);
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A query asking for all three parts from a client with every
    /// extension bit set, as macOS sends it.
    const QUERY: [u8; 24] = [
        0x01, 0, 0, 0, 0, 0, 0, 0, //
        0x07, 0, 0, 0, 0, 0, 0, 0, //
        0x3F, 0, 0, 0, 0, 0, 0, 0,
    ];

    #[test]
    fn a_server_query_parses() {
        assert_eq!(
            AaplQuery::parse(&QUERY).unwrap(),
            AaplQuery {
                bitmap: 0x07,
                client_caps: 0x3F,
            }
        );
        let mut reserved = QUERY;
        reserved[4] = 0xFF;
        assert!(AaplQuery::parse(&reserved).is_ok());
    }

    #[test]
    fn a_query_of_another_size_or_command_is_malformed() {
        for len in [0, 16, 23, 25, 32] {
            let mut data = QUERY.to_vec();
            data.resize(len, 0);
            assert!(AaplQuery::parse(&data).is_err(), "{len} bytes");
        }
        for command in [0u32, 2, 0x0100_0001] {
            let mut data = QUERY;
            data[..4].copy_from_slice(&command.to_le_bytes());
            assert!(AaplQuery::parse(&data).is_err(), "command {command:#x}");
        }
    }

    #[test]
    fn a_reply_with_every_part_has_them_in_bit_order() {
        let reply = AaplReply {
            bitmap: 0x07,
            server_caps: 0x0D,
            volume_caps: 0,
            model: "MacSamba",
        };
        let expected = [
            "01000000 00000000 0700000000000000",
            "0d00000000000000 0000000000000000",
            "00000000 10000000 4d0061006300530061006d0062006100",
        ]
        .concat()
        .replace(' ', "");
        assert_eq!(hex::encode(reply.encode()), expected);
    }

    #[test]
    fn a_reply_carries_only_the_known_parts_asked_for() {
        let reply = |bitmap| {
            AaplReply {
                bitmap,
                server_caps: 0x04,
                volume_caps: 0x02,
                model: "smb-server",
            }
            .encode()
        };
        let head = |bitmap: u64| {
            let mut out = vec![1, 0, 0, 0, 0, 0, 0, 0];
            out.extend_from_slice(&bitmap.to_le_bytes());
            out
        };
        assert_eq!(reply(0), head(0));
        assert_eq!(reply(0xF8), head(0));
        assert_eq!(
            reply(0x02),
            [head(0x02), 0x02u64.to_le_bytes().to_vec()].concat()
        );
        let model = [
            head(0x05),
            0x04u64.to_le_bytes().to_vec(),
            vec![0, 0, 0, 0, 20, 0, 0, 0],
            crate::utils::utf16le("smb-server"),
        ]
        .concat();
        assert_eq!(reply(0x0D), model);
    }
}
