//! Helpers for hand-building SMB2 client requests in integration tests.

#![allow(dead_code, reason = "each test crate uses part of the helpers")]

pub mod auth;
pub mod client;
pub mod crypto;
pub mod durable;
pub mod lease;
pub mod transport;

use std::io;
use std::net::SocketAddr;

use smb_server::ntstatus::{STATUS_MORE_PROCESSING_REQUIRED, STATUS_SUCCESS};
use smb_server::wire::header::{Command, HeaderTail, SMB2_FLAGS_SERVER_TO_REDIR, Smb2Header};
use smb_server::wire::messages::{
    NegotiateRequest, NegotiateResponse, SessionSetupRequest, SessionSetupResponse,
    TreeConnectRequest, TreeConnectResponse,
};
use smb_server::{ConfigHandle, ShutdownHandle, SmbServerBuilder};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::task::JoinHandle;

use auth::{mech_type_list, ntlm_negotiate, spnego_init, spnego_resp};

pub const NTLMSSP_SIGNATURE: &[u8] = b"NTLMSSP\0";
pub const OID_SPNEGO: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x02];
pub const OID_NTLMSSP: &[u8] = &[0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a];

/// NTLM NEGOTIATE flags of the sessions the helpers open.
pub const NTLM_NEGOTIATE_FLAGS: u32 = 0x6209_8215;

/// Builds the server on a loopback port, binds it and serves it on a task.
pub async fn start_server(builder: SmbServerBuilder) -> (SocketAddr, JoinHandle<()>) {
    let (addr, _, _, task) = spawn_server(builder).await;
    (addr, task)
}

/// Like [`start_server`], and also returns the server's shutdown handle.
pub async fn start_with_shutdown(
    builder: SmbServerBuilder,
) -> (SocketAddr, ShutdownHandle, JoinHandle<()>) {
    let (addr, _, shutdown, task) = spawn_server(builder).await;
    (addr, shutdown, task)
}

async fn spawn_server(
    builder: SmbServerBuilder,
) -> (SocketAddr, ConfigHandle, ShutdownHandle, JoinHandle<()>) {
    let server = builder
        .listen("127.0.0.1:0".parse().unwrap())
        .build()
        .expect("build");
    let config = server.config_handle();
    let shutdown = server.shutdown_handle();
    let addr = server.bind().await.expect("bind");
    let task = tokio::spawn(async move {
        let _ = server.serve().await;
    });
    (addr, config, shutdown, task)
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

/// Header and body as one SMB2 message, without the transport prefix.
pub fn message(hdr: &Smb2Header, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    hdr.write(&mut out).expect("header");
    out.extend_from_slice(body);
    out
}

/// `payload` with its 4-byte Direct TCP prefix.
pub fn framed(payload: &[u8]) -> Vec<u8> {
    assert!(payload.len() <= 0x00FF_FFFF);
    let len = payload.len() as u32;
    let mut out = vec![0, (len >> 16) as u8, (len >> 8) as u8, len as u8];
    out.extend_from_slice(payload);
    out
}

pub async fn write_frame(s: &mut TcpStream, header: &Smb2Header, body: &[u8]) {
    s.write_all(&framed(&message(header, body)))
        .await
        .expect("write");
}

/// Reads one frame, or the error that ended the stream.
pub async fn try_read_frame(s: &mut TcpStream) -> io::Result<Vec<u8>> {
    let mut prefix = [0u8; 4];
    s.read_exact(&mut prefix).await?;
    assert_eq!(prefix[0], 0, "unsupported direct TCP frame marker");
    let len =
        (usize::from(prefix[1]) << 16) | (usize::from(prefix[2]) << 8) | usize::from(prefix[3]);
    let mut payload = vec![0u8; len];
    s.read_exact(&mut payload).await?;
    Ok(payload)
}

pub async fn read_frame(s: &mut TcpStream) -> Vec<u8> {
    try_read_frame(s).await.expect("frame")
}

pub fn parse_response_header(frame: &[u8]) -> (Smb2Header, &[u8]) {
    let (h, rest) = Smb2Header::parse(frame).expect("parse hdr");
    assert!(
        h.flags & SMB2_FLAGS_SERVER_TO_REDIR != 0,
        "must be a response"
    );
    (h, rest)
}

/// ClientGuid of the NEGOTIATE requests the helpers send.
pub const CLIENT_GUID: [u8; 16] = [0xCD; 16];

/// NEGOTIATE request body.
pub fn negotiate_body(dialects: &[u16], security_mode: u16, capabilities: u32) -> Vec<u8> {
    negotiate_body_from(dialects, security_mode, capabilities, CLIENT_GUID)
}

/// NEGOTIATE request body with `client_guid`.
pub fn negotiate_body_from(
    dialects: &[u16],
    security_mode: u16,
    capabilities: u32,
    client_guid: [u8; 16],
) -> Vec<u8> {
    let req = NegotiateRequest {
        structure_size: 36,
        dialect_count: dialects.len() as u16,
        security_mode,
        reserved: 0,
        capabilities,
        client_guid,
        negotiate_context_offset_or_client_start_time: 0,
        dialects: dialects.to_vec(),
    };
    let mut body = Vec::new();
    req.write_to(&mut body).expect("negotiate");
    body
}

/// NEGOTIATE offering `dialects` (2.x or 3.0 to 3.0.2) with MessageId 0.
pub async fn negotiate_dialects(s: &mut TcpStream, dialects: &[u16]) -> NegotiateResponse {
    negotiate_dialects_from(s, dialects, CLIENT_GUID).await
}

/// [`negotiate_dialects`] from the client `client_guid`.
pub async fn negotiate_dialects_from(
    s: &mut TcpStream,
    dialects: &[u16],
    client_guid: [u8; 16],
) -> NegotiateResponse {
    let body = negotiate_body_from(dialects, 0x0001, 0, client_guid);
    let hdr = build_header(Command::Negotiate, 0, 0, 0);
    write_frame(s, &hdr, &body).await;

    let resp = read_frame(s).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::Negotiate);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let neg_resp = NegotiateResponse::parse(rb).expect("parse neg resp");
    assert!(dialects.contains(&neg_resp.dialect_revision));
    neg_resp
}

/// NEGOTIATE offering 2.0.2 and 2.1.
pub async fn negotiate(s: &mut TcpStream) -> NegotiateResponse {
    let neg_resp = negotiate_dialects(s, &[0x0202, 0x0210]).await;
    assert_eq!(neg_resp.security_mode, 0x0001);
    neg_resp
}

/// SESSION_SETUP request body.
pub fn session_setup_body(blob: &[u8], flags: u8, security_mode: u8, previous: u64) -> Vec<u8> {
    let req = SessionSetupRequest {
        structure_size: 25,
        flags,
        security_mode,
        capabilities: 0,
        channel: 0,
        security_buffer_offset: 88,
        security_buffer_length: blob.len() as u16,
        previous_session_id: previous,
        security_buffer: blob.to_vec(),
    };
    let mut body = Vec::new();
    req.write_to(&mut body).expect("session setup");
    body
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
    let ntlm = ntlm_negotiate(NTLM_NEGOTIATE_FLAGS);
    let blob = spnego_init(&mech_type_list(&[OID_NTLMSSP]), Some(&ntlm));
    let body = session_setup_body(&blob, 0, 0x01, 0);
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

/// SMB 2.x signature (HMAC-SHA256) of `msg` with its signature field zeroed.
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

    let body = session_setup_body(&spnego_resp(Some(&ntlm_auth), None), 0, 0x01, 0);
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

/// TREE_CONNECT request body for `path`.
pub fn tree_connect_body(path: &str) -> Vec<u8> {
    let path = utf16le(path);
    let mut body = Vec::new();
    TreeConnectRequest {
        structure_size: 9,
        flags: 0,
        path_offset: 64 + 8,
        path_length: path.len() as u16,
        path,
    }
    .write_to(&mut body)
    .expect("tree connect");
    body
}

pub async fn tree_connect(s: &mut TcpStream, path: &str, session_id: u64, message_id: u64) -> u32 {
    let hdr = build_header(Command::TreeConnect, message_id, session_id, 0);
    write_frame(s, &hdr, &tree_connect_body(path)).await;

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

/// Name, FileId and FileNameLength of each FileIdBothDirectoryInformation
/// entry in `buf`. A name cut short by the buffer is decoded as far as it
/// goes.
pub fn id_both_entries(mut buf: &[u8]) -> Vec<(String, u64, usize)> {
    let mut out = Vec::new();
    while buf.len() >= 104 {
        let next = u32::from_le_bytes(buf[0..4].try_into().unwrap()) as usize;
        let name_len = u32::from_le_bytes(buf[60..64].try_into().unwrap()) as usize;
        let file_id = u64::from_le_bytes(buf[96..104].try_into().unwrap());
        let end = (104 + name_len).min(buf.len());
        let units: Vec<u16> = buf[104..end]
            .chunks_exact(2)
            .map(|b| u16::from_le_bytes([b[0], b[1]]))
            .collect();
        out.push((
            String::from_utf16(&units).expect("utf16"),
            file_id,
            name_len,
        ));
        if next == 0 {
            break;
        }
        buf = &buf[next..];
    }
    out
}
