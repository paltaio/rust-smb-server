//! Checks on received SMB2 messages made before any handler runs.

use std::ops::Range;

use crate::conn::limits::{MAX_SMALL_REQUEST, is_bulk, supports_multi_credit};
use crate::proto::header::{Command, SMB2_HEADER_LEN, Smb2Header};
use crate::proto::messages::Dialect;

/// One request of a received frame.
pub struct Request {
    pub header: Smb2Header,
    /// The request's bytes in the frame, up to the next request.
    pub range: Range<usize>,
}

/// Splits a frame into its requests. Fails when any request has an unusable
/// header or NextCommand, is larger than its command allows, or does not
/// fit the connection state: NEGOTIATE once a dialect is negotiated, any
/// other command before. The connection then closes without a reply and no
/// request of the frame runs (MS-SMB2 3.3.5.2, 3.3.5.2.2, 3.3.5.2.6,
/// 3.3.5.4).
pub fn split(frame: &[u8], dialect: Option<Dialect>) -> Result<Vec<Request>, String> {
    let mut requests = Vec::new();
    let mut offset = 0;
    loop {
        let rest = &frame[offset..];
        if rest.len() < SMB2_HEADER_LEN {
            return Err(format!(
                "request of {} bytes is shorter than its header",
                rest.len()
            ));
        }
        let (header, _) = Smb2Header::parse(rest).map_err(|e| e.to_string())?;
        let next = header.next_command as usize;
        let len = match next {
            0 => rest.len(),
            n if (SMB2_HEADER_LEN..=rest.len()).contains(&n) => n,
            n => return Err(format!("NextCommand {n} with {} bytes left", rest.len())),
        };
        if len > MAX_SMALL_REQUEST && !is_bulk(header.command) && supports_multi_credit(dialect) {
            return Err(format!("{:?} request of {len} bytes", header.command));
        }
        let negotiated = matches!(dialect, Some(d) if d != Dialect::Smb2Wildcard);
        if (header.command == Command::Negotiate) == negotiated {
            return Err(format!("{:?} with dialect {dialect:?}", header.command));
        }
        requests.push(Request {
            header,
            range: offset..offset + len,
        });
        if next == 0 {
            return Ok(requests);
        }
        offset += next;
    }
}

/// Bytes a request sends or may get back in its variable part, whichever
/// is larger: the size its CreditCharge has to cover (MS-SMB2 3.3.5.12,
/// 3.3.5.13, 3.3.5.15, 3.3.5.17 to 3.3.5.21).
pub fn payload_size(command: Command, body: &[u8]) -> u64 {
    let u32_at = |offset: usize| {
        body.get(offset..offset + 4).map_or(0, |b| {
            u64::from(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
        })
    };
    match command {
        // Length.
        Command::Read | Command::Write => u32_at(4),
        // InputCount + OutputCount, MaxInputResponse + MaxOutputResponse.
        Command::Ioctl => (u32_at(28) + u32_at(40)).max(u32_at(32) + u32_at(44)),
        // OutputBufferLength.
        Command::QueryDirectory => u32_at(28),
        Command::ChangeNotify => u32_at(4),
        // OutputBufferLength, InputBufferLength.
        Command::QueryInfo => u32_at(4).max(u32_at(12)),
        // BufferLength.
        Command::SetInfo => u32_at(4),
        _ => 0,
    }
}

/// The StructureSize values a request body of `command` may carry
/// (MS-SMB2 2.2). OPLOCK_BREAK acknowledges an oplock (24) or a lease (36).
fn structure_sizes(command: Command) -> &'static [u16] {
    match command {
        Command::Negotiate => &[36],
        Command::SessionSetup => &[25],
        Command::Logoff | Command::TreeDisconnect | Command::Cancel | Command::Echo => &[4],
        Command::TreeConnect => &[9],
        Command::Create | Command::Ioctl => &[57],
        Command::Close | Command::Flush => &[24],
        Command::Read | Command::Write => &[49],
        Command::Lock => &[48],
        Command::QueryDirectory | Command::SetInfo => &[33],
        Command::ChangeNotify => &[32],
        Command::QueryInfo => &[41],
        Command::OplockBreak => &[24, 36],
    }
}

/// Whether `body` starts with the StructureSize its command defines and
/// holds at least the fixed part of the structure. An odd StructureSize
/// counts one byte of the variable part.
pub fn body_is_well_formed(command: Command, body: &[u8]) -> bool {
    let Some(size) = body.get(..2).map(|b| u16::from_le_bytes([b[0], b[1]])) else {
        return false;
    };
    structure_sizes(command).contains(&size) && body.len() >= usize::from(size & !1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::header::SMB2_FLAGS_RELATED_OPERATIONS;

    const NEGOTIATED: Option<Dialect> = Some(Dialect::Smb210);

    fn request(command: Command, next: u32, body: &[u8]) -> Vec<u8> {
        let hdr = Smb2Header {
            command,
            next_command: next,
            flags: SMB2_FLAGS_RELATED_OPERATIONS,
            ..Default::default()
        };
        let mut out = Vec::new();
        hdr.write(&mut out).expect("header");
        out.extend_from_slice(body);
        out
    }

    #[test]
    fn negotiate_comes_first_and_once() {
        let negotiate = request(Command::Negotiate, 0, &[36, 0]);
        let echo = request(Command::Echo, 0, &[4, 0, 0, 0]);
        for dialect in [None, Some(Dialect::Smb2Wildcard)] {
            assert!(split(&negotiate, dialect).is_ok());
            assert!(split(&echo, dialect).is_err());
        }
        for dialect in [Dialect::Smb202, Dialect::Smb311] {
            assert!(split(&negotiate, Some(dialect)).is_err());
            assert!(split(&echo, Some(dialect)).is_ok());
        }
    }

    #[test]
    fn splits_a_compound_at_next_command() {
        let mut frame = request(Command::Echo, 72, &[4, 0, 0, 0, 0, 0, 0, 0]);
        frame.extend(request(Command::Echo, 0, &[4, 0, 0, 0]));
        let requests = split(&frame, Some(Dialect::Smb210)).expect("split");
        let ranges: Vec<_> = requests.iter().map(|r| r.range.clone()).collect();
        assert_eq!(ranges, [0..72, 72..140]);
    }

    #[test]
    fn rejects_frames_with_any_bad_request() {
        let echo = request(Command::Echo, 0, &[4, 0, 0, 0]);
        assert!(split(&echo, NEGOTIATED).is_ok());
        assert!(split(&echo[..63], NEGOTIATED).is_err());

        let mut unknown = echo.clone();
        unknown[12] = 0x13;
        assert!(split(&unknown, NEGOTIATED).is_err());

        let mut transform = echo.clone();
        transform[0] = 0xFD;
        assert!(split(&transform, NEGOTIATED).is_err());

        for next in [32, 69, 200] {
            let mut frame = request(Command::Echo, next, &[4, 0, 0, 0]);
            frame.extend_from_slice(&echo);
            assert!(split(&frame, NEGOTIATED).is_err(), "NextCommand {next}");
        }

        let mut tail = request(Command::Echo, 72, &[4, 0, 0, 0, 0, 0, 0, 0]);
        tail.extend_from_slice(&echo[..40]);
        assert!(split(&tail, NEGOTIATED).is_err());
    }

    #[test]
    fn small_commands_are_limited_to_68_kib() {
        let mut body = vec![4, 0, 0, 0];
        body.resize(MAX_SMALL_REQUEST - SMB2_HEADER_LEN, 0);
        let fits = request(Command::Echo, 0, &body);
        assert!(split(&fits, Some(Dialect::Smb300)).is_ok());

        body.push(0);
        let over = request(Command::Echo, 0, &body);
        assert!(split(&over, Some(Dialect::Smb300)).is_err());
        let write = request(Command::Write, 0, &body);
        assert!(split(&write, Some(Dialect::Smb300)).is_ok());
    }

    #[test]
    fn payload_size_reads_each_command_s_length_fields() {
        let mut body = vec![0u8; 56];
        body[4..8].copy_from_slice(&0x10_0000u32.to_le_bytes());
        assert_eq!(payload_size(Command::Read, &body), 0x10_0000);
        assert_eq!(payload_size(Command::Write, &body), 0x10_0000);
        assert_eq!(payload_size(Command::QueryInfo, &body), 0x10_0000);
        assert_eq!(payload_size(Command::Echo, &body), 0);

        let mut ioctl = vec![0u8; 56];
        ioctl[28..32].copy_from_slice(&100u32.to_le_bytes());
        ioctl[44..48].copy_from_slice(&70_000u32.to_le_bytes());
        assert_eq!(payload_size(Command::Ioctl, &ioctl), 70_000);
        assert_eq!(payload_size(Command::Ioctl, &ioctl[..10]), 0);
    }

    #[test]
    fn body_structure_size_and_length() {
        assert!(body_is_well_formed(Command::Echo, &[4, 0, 0, 0]));
        assert!(!body_is_well_formed(Command::Echo, &[0, 0, 0, 0]));
        assert!(!body_is_well_formed(Command::Echo, &[4, 0]));
        assert!(!body_is_well_formed(Command::Echo, &[]));

        let mut create = vec![0u8; 56];
        create[0] = 57;
        assert!(body_is_well_formed(Command::Create, &create));
        assert!(!body_is_well_formed(Command::Create, &create[..55]));
        create[0] = 56;
        assert!(!body_is_well_formed(Command::Create, &create));

        let mut lease_ack = vec![0u8; 36];
        lease_ack[0] = 36;
        assert!(body_is_well_formed(Command::OplockBreak, &lease_ack));
    }
}
