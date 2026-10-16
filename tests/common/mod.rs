//! Helpers for hand-building SMB2 client requests in integration tests.

use std::net::SocketAddr;

use smb_server::SmbServerBuilder;
use smb_server::wire::header::{Command, HeaderTail, SMB2_FLAGS_SERVER_TO_REDIR, Smb2Header};
use smb_server::wire::messages::{
    NegotiateRequest, NegotiateResponse, SessionSetupRequest, SessionSetupResponse,
    TreeConnectRequest, TreeConnectResponse,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::task::JoinHandle;

pub const NTLMSSP_SIGNATURE: &[u8] = b"NTLMSSP\0";
pub const OID_SPNEGO: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x02];
pub const OID_NTLMSSP: &[u8] = &[0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a];
const FRAME_HEADER_LEN: usize = 4;

pub const STATUS_SUCCESS: u32 = 0x0000_0000;
pub const STATUS_MORE_PROCESSING_REQUIRED: u32 = 0xC000_0016;

/// Builds the server on a loopback port, binds it and serves it on a task.
pub async fn start_server(builder: SmbServerBuilder) -> (SocketAddr, JoinHandle<()>) {
    let server = builder
        .listen("127.0.0.1:0".parse().unwrap())
        .build()
        .expect("build");
    let addr = server.bind().await.expect("bind");
    let handle = tokio::spawn(async move {
        let _ = server.serve().await;
    });
    (addr, handle)
}

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

pub fn build_spnego_init(ntlm: &[u8]) -> Vec<u8> {
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

pub async fn negotiate(s: &mut TcpStream) -> NegotiateResponse {
    let neg_req = NegotiateRequest {
        structure_size: 36,
        dialect_count: 2,
        security_mode: 0x0001,
        reserved: 0,
        capabilities: 0,
        client_guid: [0xCD; 16],
        negotiate_context_offset_or_client_start_time: 0,
        dialects: vec![0x0202, 0x0210],
    };
    let mut body = Vec::new();
    neg_req.write_to(&mut body).expect("write negotiate");
    let hdr = build_header(Command::Negotiate, 0, 0, 0);
    write_frame(s, &hdr, &body).await;

    let resp = read_frame(s).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::Negotiate);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let neg_resp = NegotiateResponse::parse(rb).expect("parse neg resp");
    assert!(matches!(neg_resp.dialect_revision, 0x0202 | 0x0210));
    assert_eq!(neg_resp.security_mode, 0x0001);
    neg_resp
}

/// Sends SESSION_SETUP with an SPNEGO-wrapped NTLM NEGOTIATE; returns the
/// response status and SessionId.
pub async fn start_ntlm_session_setup(s: &mut TcpStream, message_id: u64) -> (u32, u64) {
    let (status, session_id, _) = send_ntlm_negotiate(s, message_id).await;
    (status, session_id)
}

/// Sends the NTLM NEGOTIATE round; returns the status, SessionId and the
/// response security buffer.
async fn send_ntlm_negotiate(s: &mut TcpStream, message_id: u64) -> (u32, u64, Vec<u8>) {
    let mut ntlm_negotiate = Vec::new();
    ntlm_negotiate.extend_from_slice(NTLMSSP_SIGNATURE);
    ntlm_negotiate.extend_from_slice(&1u32.to_le_bytes());
    ntlm_negotiate.extend_from_slice(&0x6209_8215u32.to_le_bytes());
    ntlm_negotiate.extend_from_slice(&[0u8; 16]);
    ntlm_negotiate.extend_from_slice(&[0u8; 8]);

    let spnego_init = build_spnego_init(&ntlm_negotiate);
    let ss_req = SessionSetupRequest {
        structure_size: 25,
        flags: 0,
        security_mode: 0x01,
        capabilities: 0,
        channel: 0,
        security_buffer_offset: 88,
        security_buffer_length: spnego_init.len() as u16,
        previous_session_id: 0,
        security_buffer: spnego_init,
    };
    let mut body = Vec::new();
    ss_req.write_to(&mut body).expect("write session setup");
    let hdr = build_header(Command::SessionSetup, message_id, 0, 0);
    write_frame(s, &hdr, &body).await;

    let resp = read_frame(s).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::SessionSetup);
    let mut security_buffer = Vec::new();
    if rh.channel_sequence_status == STATUS_MORE_PROCESSING_REQUIRED {
        assert_ne!(rh.session_id, 0);
        let ss_resp = SessionSetupResponse::parse(rb).expect("parse ss resp");
        assert!(!ss_resp.security_buffer.is_empty());
        security_buffer = ss_resp.security_buffer;
    }
    (rh.channel_sequence_status, rh.session_id, security_buffer)
}

type HmacMd5 = hmac::Hmac<md5::Md5>;

fn hmac_md5(key: &[u8], parts: &[&[u8]]) -> [u8; 16] {
    use hmac::Mac as _;
    let mut mac = HmacMd5::new_from_slice(key).expect("hmac key");
    for part in parts {
        mac.update(part);
    }
    mac.finalize().into_bytes().into()
}

/// NTLMv2 AUTHENTICATE_MESSAGE for `user` and `password`, with an empty
/// domain and no MIC, and the session key it yields.
fn ntlm_authenticate(user: &str, password: &str, server_challenge: &[u8]) -> (Vec<u8>, [u8; 16]) {
    use md4::Digest as _;
    let nt_hash: [u8; 16] = md4::Md4::digest(utf16le(password)).into();
    let response_key = hmac_md5(&nt_hash, &[&utf16le(&user.to_uppercase())]);
    let mut client_blob = vec![1, 1, 0, 0, 0, 0, 0, 0];
    client_blob.extend_from_slice(&[0; 8]); // timestamp
    client_blob.extend_from_slice(&[0xAA; 8]); // client challenge
    client_blob.extend_from_slice(&[0; 8]); // reserved, empty AV pair list
    let proof = hmac_md5(&response_key, &[server_challenge, &client_blob]);
    let session_key = hmac_md5(&response_key, &[&proof]);
    let nt_response = [&proof[..], &client_blob].concat();

    // Lm, Nt, Domain, User, Workstation, EncryptedRandomSessionKey.
    let user = utf16le(user);
    let lm = [0u8; 24];
    let fields: [&[u8]; 6] = [&lm, &nt_response, &[], &user, &[], &[]];
    let header_len = 72u32;
    let mut msg = Vec::new();
    let mut payload = Vec::new();
    msg.extend_from_slice(NTLMSSP_SIGNATURE);
    msg.extend_from_slice(&3u32.to_le_bytes());
    for field in fields {
        let offset = header_len + payload.len() as u32;
        msg.extend_from_slice(&(field.len() as u16).to_le_bytes());
        msg.extend_from_slice(&(field.len() as u16).to_le_bytes());
        msg.extend_from_slice(&offset.to_le_bytes());
        payload.extend_from_slice(field);
    }
    msg.extend_from_slice(&0x0000_0001u32.to_le_bytes()); // NTLMSSP_NEGOTIATE_UNICODE
    msg.extend_from_slice(&[0; 8]); // Version
    msg.extend_from_slice(&payload);
    (msg, session_key)
}

/// NTLMv2 SESSION_SETUP as `user`; returns the final status, the SessionId,
/// the session key and the final response frame.
#[allow(dead_code, reason = "not every test crate signs in a user")]
pub async fn user_session_setup(
    s: &mut TcpStream,
    user: &str,
    password: &str,
) -> (u32, u64, [u8; 16], Vec<u8>) {
    let (status, session_id, challenge) = send_ntlm_negotiate(s, 1).await;
    assert_eq!(status, STATUS_MORE_PROCESSING_REQUIRED);
    let ntlm = challenge
        .windows(NTLMSSP_SIGNATURE.len())
        .position(|w| w == NTLMSSP_SIGNATURE)
        .expect("NTLM CHALLENGE");
    let server_challenge = &challenge[ntlm + 24..ntlm + 32];
    let (auth, session_key) = ntlm_authenticate(user, password, server_challenge);

    let blob = build_spnego_resp(&auth);
    let req = SessionSetupRequest {
        structure_size: 25,
        flags: 0,
        security_mode: 0x01,
        capabilities: 0,
        channel: 0,
        security_buffer_offset: 88,
        security_buffer_length: blob.len() as u16,
        previous_session_id: 0,
        security_buffer: blob,
    };
    let mut body = Vec::new();
    req.write_to(&mut body).expect("write session setup");
    let hdr = build_header(Command::SessionSetup, 2, session_id, 0);
    write_frame(s, &hdr, &body).await;
    let resp = read_frame(s).await;
    let (rh, _) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::SessionSetup);
    (rh.channel_sequence_status, session_id, session_key, resp)
}

/// SMB 2.x signature (HMAC-SHA256) of `msg` with its signature field zeroed.
#[allow(dead_code, reason = "not every test crate signs messages")]
pub fn smb2_signature(msg: &[u8], key: &[u8; 16]) -> [u8; 16] {
    use hmac::Mac as _;
    let mut mac = hmac::Hmac::<sha2::Sha256>::new_from_slice(key).expect("hmac key");
    mac.update(&msg[..48]);
    mac.update(&[0; 16]);
    mac.update(&msg[64..]);
    mac.finalize().into_bytes()[..16]
        .try_into()
        .expect("16 bytes")
}

/// Sends the anonymous NTLM AUTHENTICATE round for `session_id`; returns the
/// response status.
pub async fn finish_anonymous_session_setup(
    s: &mut TcpStream,
    message_id: u64,
    session_id: u64,
) -> u32 {
    let mut ntlm_auth = Vec::new();
    ntlm_auth.extend_from_slice(NTLMSSP_SIGNATURE);
    ntlm_auth.extend_from_slice(&3u32.to_le_bytes());
    let header_len: u32 = 72;
    for _ in 0..6 {
        ntlm_auth.extend_from_slice(&0u16.to_le_bytes());
        ntlm_auth.extend_from_slice(&0u16.to_le_bytes());
        ntlm_auth.extend_from_slice(&header_len.to_le_bytes());
    }
    ntlm_auth.extend_from_slice(&0x0000_0800u32.to_le_bytes());
    ntlm_auth.extend_from_slice(&[0u8; 8]);

    let spnego_resp_blob = build_spnego_resp(&ntlm_auth);
    let ss_req2 = SessionSetupRequest {
        structure_size: 25,
        flags: 0,
        security_mode: 0x01,
        capabilities: 0,
        channel: 0,
        security_buffer_offset: 88,
        security_buffer_length: spnego_resp_blob.len() as u16,
        previous_session_id: 0,
        security_buffer: spnego_resp_blob,
    };
    let mut body = Vec::new();
    ss_req2.write_to(&mut body).expect("write session setup");
    let hdr = build_header(Command::SessionSetup, message_id, session_id, 0);
    write_frame(s, &hdr, &body).await;

    let resp = read_frame(s).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::SessionSetup);
    if rh.channel_sequence_status == STATUS_SUCCESS {
        assert_eq!(rh.session_id, session_id);
        let ss_resp = SessionSetupResponse::parse(rb).expect("parse ss success resp");
        assert_eq!(
            ss_resp.session_flags,
            SessionSetupResponse::FLAG_IS_NULL,
            "anonymous session flags"
        );
    }
    rh.channel_sequence_status
}

pub async fn anonymous_session_setup(s: &mut TcpStream) -> u64 {
    let (status, session_id) = start_ntlm_session_setup(s, 1).await;
    assert_eq!(status, STATUS_MORE_PROCESSING_REQUIRED);
    assert_eq!(
        finish_anonymous_session_setup(s, 2, session_id).await,
        STATUS_SUCCESS
    );
    session_id
}

pub async fn tree_connect(s: &mut TcpStream, path: &str, session_id: u64, message_id: u64) -> u32 {
    let path_u16 = utf16le(path);
    let tc_req = TreeConnectRequest {
        structure_size: 9,
        flags: 0,
        path_offset: 64 + 8,
        path_length: path_u16.len() as u16,
        path: path_u16,
    };
    let mut body = Vec::new();
    tc_req.write_to(&mut body).expect("write tree connect");
    let hdr = build_header(Command::TreeConnect, message_id, session_id, 0);
    write_frame(s, &hdr, &body).await;

    let resp = read_frame(s).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::TreeConnect);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let tree_id = rh.tree_id().expect("tree id");
    assert_ne!(tree_id, 0);
    let tc_resp = TreeConnectResponse::parse(rb).expect("parse tc resp");
    assert_eq!(tc_resp.share_type, TreeConnectResponse::SHARE_TYPE_DISK);
    tree_id
}

/// Name and FileId of each entry in a FileIdBothDirectoryInformation buffer.
#[allow(dead_code, reason = "not every test crate lists directories")]
pub fn decode_file_id_both_directory_info(mut buf: &[u8]) -> Vec<(String, u64)> {
    let mut entries = Vec::new();
    loop {
        assert!(
            buf.len() >= 104,
            "short FileIdBothDirectoryInformation entry"
        );
        let next = u32::from_le_bytes(buf[0..4].try_into().unwrap()) as usize;
        let name_len = u32::from_le_bytes(buf[60..64].try_into().unwrap()) as usize;
        let file_id = u64::from_le_bytes(buf[96..104].try_into().unwrap());
        let name_end = 104 + name_len;
        assert!(buf.len() >= name_end, "short file name");
        let units: Vec<u16> = buf[104..name_end]
            .chunks_exact(2)
            .map(|b| u16::from_le_bytes([b[0], b[1]]))
            .collect();
        entries.push((String::from_utf16(&units).expect("utf16 name"), file_id));
        if next == 0 {
            break entries;
        }
        assert!(buf.len() >= next, "invalid NextEntryOffset");
        buf = &buf[next..];
    }
}
