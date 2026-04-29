//! Helpers for hand-building SMB2 client requests in integration tests.

use smb_server::wire::header::{Command, HeaderTail, Smb2Header, SMB2_FLAGS_SERVER_TO_REDIR};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

pub const NTLMSSP_SIGNATURE: &[u8] = b"NTLMSSP\0";
pub const OID_SPNEGO: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x02];
pub const OID_NTLMSSP: &[u8] = &[0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a];
const FRAME_HEADER_LEN: usize = 4;

pub const STATUS_SUCCESS: u32 = 0x0000_0000;
pub const STATUS_MORE_PROCESSING_REQUIRED: u32 = 0xC000_0016;

pub fn utf16le(s: &str) -> Vec<u8> {
    s.encode_utf16().flat_map(u16::to_le_bytes).collect()
}

pub fn build_header(
    command: Command,
    message_id: u64,
    session_id: u64,
    tree_id: u32,
) -> Smb2Header {
    Smb2Header {
        credit_charge: 1,
        channel_sequence_status: 0,
        command,
        credit_request_response: 64,
        flags: 0,
        next_command: 0,
        message_id,
        tail: HeaderTail::sync(tree_id),
        session_id,
        signature: [0u8; 16],
    }
}

pub async fn write_frame(s: &mut TcpStream, header: &Smb2Header, body: &[u8]) {
    let mut payload = Vec::new();
    header.write(&mut payload).expect("hdr");
    payload.extend_from_slice(body);
    let mut framed = Vec::new();
    encode_frame(&payload, &mut framed);
    s.write_all(&framed).await.expect("write");
}

pub fn encode_frame(payload: &[u8], out: &mut Vec<u8>) {
    assert!(payload.len() <= 0x00FF_FFFF);
    out.push(0);
    out.push(((payload.len() >> 16) & 0xff) as u8);
    out.push(((payload.len() >> 8) & 0xff) as u8);
    out.push((payload.len() & 0xff) as u8);
    out.extend_from_slice(payload);
}

fn decode_frame_header(hdr: &[u8; FRAME_HEADER_LEN]) -> usize {
    assert_eq!(hdr[0], 0, "unsupported direct TCP frame marker");
    ((hdr[1] as usize) << 16) | ((hdr[2] as usize) << 8) | hdr[3] as usize
}

pub async fn read_frame(s: &mut TcpStream) -> Vec<u8> {
    let mut hdr = [0u8; FRAME_HEADER_LEN];
    s.read_exact(&mut hdr).await.expect("hdr");
    let len = decode_frame_header(&hdr);
    let mut body = vec![0u8; len];
    s.read_exact(&mut body).await.expect("body");
    body
}

pub fn parse_response_header(frame: &[u8]) -> (Smb2Header, &[u8]) {
    let (h, rest) = Smb2Header::parse(frame).expect("parse hdr");
    assert!(
        h.flags & SMB2_FLAGS_SERVER_TO_REDIR != 0,
        "must be a response"
    );
    (h, rest)
}

pub fn build_spnego_init(ntlm: &[u8]) -> Vec<u8> {
    fn write_tlv(tag: u8, content: &[u8], out: &mut Vec<u8>) {
        out.push(tag);
        if content.len() < 0x80 {
            out.push(content.len() as u8);
        } else {
            let mut tmp = Vec::new();
            let mut n = content.len();
            while n > 0 {
                tmp.push((n & 0xff) as u8);
                n >>= 8;
            }
            out.push(0x80 | tmp.len() as u8);
            for b in tmp.into_iter().rev() {
                out.push(b);
            }
        }
        out.extend_from_slice(content);
    }

    let mut mts = Vec::new();
    write_tlv(0x06, OID_NTLMSSP, &mut mts);
    let mut mts_seq = Vec::new();
    write_tlv(0x30, &mts, &mut mts_seq);
    let mut mts_ctx0 = Vec::new();
    write_tlv(0xa0, &mts_seq, &mut mts_ctx0);

    let mut tok_oct = Vec::new();
    write_tlv(0x04, ntlm, &mut tok_oct);
    let mut tok_ctx2 = Vec::new();
    write_tlv(0xa2, &tok_oct, &mut tok_ctx2);

    let mut seq = Vec::new();
    seq.extend_from_slice(&mts_ctx0);
    seq.extend_from_slice(&tok_ctx2);
    let mut neg_token_init = Vec::new();
    write_tlv(0x30, &seq, &mut neg_token_init);

    let mut choice = Vec::new();
    write_tlv(0xa0, &neg_token_init, &mut choice);

    let mut gss_inner = Vec::new();
    write_tlv(0x06, OID_SPNEGO, &mut gss_inner);
    gss_inner.extend_from_slice(&choice);

    let mut blob = Vec::new();
    write_tlv(0x60, &gss_inner, &mut blob);
    blob
}

pub fn build_spnego_resp(ntlm: &[u8]) -> Vec<u8> {
    fn write_tlv(tag: u8, content: &[u8], out: &mut Vec<u8>) {
        out.push(tag);
        if content.len() < 0x80 {
            out.push(content.len() as u8);
        } else {
            let mut tmp = Vec::new();
            let mut n = content.len();
            while n > 0 {
                tmp.push((n & 0xff) as u8);
                n >>= 8;
            }
            out.push(0x80 | tmp.len() as u8);
            for b in tmp.into_iter().rev() {
                out.push(b);
            }
        }
        out.extend_from_slice(content);
    }

    let mut enum_state = Vec::new();
    write_tlv(0x0a, &[1], &mut enum_state);
    let mut state_ctx0 = Vec::new();
    write_tlv(0xa0, &enum_state, &mut state_ctx0);

    let mut mech_oid = Vec::new();
    write_tlv(0x06, OID_NTLMSSP, &mut mech_oid);
    let mut mech_ctx1 = Vec::new();
    write_tlv(0xa1, &mech_oid, &mut mech_ctx1);

    let mut tok_oct = Vec::new();
    write_tlv(0x04, ntlm, &mut tok_oct);
    let mut tok_ctx2 = Vec::new();
    write_tlv(0xa2, &tok_oct, &mut tok_ctx2);

    let mut seq = Vec::new();
    seq.extend_from_slice(&state_ctx0);
    seq.extend_from_slice(&mech_ctx1);
    seq.extend_from_slice(&tok_ctx2);

    let mut seq_outer = Vec::new();
    write_tlv(0x30, &seq, &mut seq_outer);
    let mut out = Vec::new();
    write_tlv(0xa1, &seq_outer, &mut out);
    out
}
