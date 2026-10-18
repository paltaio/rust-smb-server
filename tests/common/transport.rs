//! Raw-socket helpers for the transport tests.

use std::io;
use std::net::SocketAddr;
use std::time::Duration;

use smb_server::ntstatus::STATUS_MORE_PROCESSING_REQUIRED;
use smb_server::wire::header::{Command, Smb2Header};
use smb_server::wire::messages::{CreateResponse, FileId, ReadRequest};
use smb_server::{LocalFsBackend, Share, SmbServer, SmbServerBuilder};
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use super::auth::ntlm_negotiate;
use super::client::{Create, FILE_GENERIC_READ, FILE_OPEN_IF};
use super::{
    NTLM_NEGOTIATE_FLAGS, anonymous_session_setup, build_header, framed, message, negotiate,
    negotiate_body, parse_response_header, session_setup_body, tree_connect, try_read_frame,
};

/// How long a test waits for a response or a close.
pub const WAIT: Duration = Duration::from_secs(5);

pub const ECHO_BODY: [u8; 4] = [4, 0, 0, 0];

/// A framed ECHO request.
pub fn echo(message_id: u64) -> Vec<u8> {
    framed(&message(
        &build_header(Command::Echo, message_id, 0, 0),
        &ECHO_BODY,
    ))
}

/// A framed SMB2 NEGOTIATE offering 2.0.2 and 2.1, with MessageId 0.
pub fn negotiate_request() -> Vec<u8> {
    let body = negotiate_body(&[0x0202, 0x0210], 0x0001, 0);
    framed(&message(&build_header(Command::Negotiate, 0, 0, 0), &body))
}

/// Builder with a public share `share` on a new directory holding `files`.
pub fn with_share(files: &[(&str, &[u8])]) -> (SmbServerBuilder, TempDir) {
    let td = tempfile::tempdir().expect("tempdir");
    for (name, data) in files {
        std::fs::write(td.path().join(name), data).expect("file");
    }
    let backend = LocalFsBackend::new(td.path()).expect("backend");
    let builder = SmbServer::builder().share(Share::new("share", backend).public());
    (builder, td)
}

/// Connects with TCP_NODELAY set.
pub async fn connect(addr: SocketAddr) -> TcpStream {
    let s = TcpStream::connect(addr).await.expect("connect");
    s.set_nodelay(true).expect("nodelay");
    s
}

/// Connects with an anonymous session; the next free MessageId is 3.
pub async fn anonymous_session(addr: SocketAddr) -> (TcpStream, u64) {
    let mut s = connect(addr).await;
    negotiate(&mut s).await;
    let session_id = anonymous_session_setup(&mut s).await;
    (s, session_id)
}

/// Anonymous session and tree on `share`; the next free MessageId is 4.
pub async fn anonymous_tree(addr: SocketAddr) -> (TcpStream, u64, u32) {
    let (mut s, session_id) = anonymous_session(addr).await;
    let tree_id = tree_connect(&mut s, "\\\\server\\share", session_id, 3).await;
    (s, session_id, tree_id)
}

/// Requests chained into one compound frame, each 8-byte aligned.
pub fn compound(messages: &[Vec<u8>]) -> Vec<u8> {
    let mut out = Vec::new();
    for (index, msg) in messages.iter().enumerate() {
        let mut msg = msg.clone();
        if index + 1 < messages.len() {
            msg.resize(msg.len().next_multiple_of(8), 0);
            let next = msg.len() as u32;
            msg[0x14..0x18].copy_from_slice(&next.to_le_bytes());
        }
        out.extend_from_slice(&msg);
    }
    framed(&out)
}

/// Connects and completes NEGOTIATE (MessageId 0).
pub async fn connect_negotiated(addr: SocketAddr) -> TcpStream {
    let mut s = connect(addr).await;
    s.write_all(&negotiate_request()).await.expect("write");
    let (hdr, _) = read_response(&mut s).await;
    assert_eq!(hdr.command, Command::Negotiate);
    assert_eq!(hdr.channel_sequence_status, 0, "NEGOTIATE status");
    s
}

/// Sends the first leg of a raw NTLM SESSION_SETUP, which leaves a session
/// in progress on the connection, and returns the credits granted.
pub async fn begin_session_setup(s: &mut TcpStream, message_id: u64, credit_request: u16) -> u16 {
    let ntlm = ntlm_negotiate(NTLM_NEGOTIATE_FLAGS);
    let body = session_setup_body(&ntlm, 0, 0x01, 0);
    let mut hdr = build_header(Command::SessionSetup, message_id, 0, 0);
    hdr.credit_request_response = credit_request;
    s.write_all(&framed(&message(&hdr, &body)))
        .await
        .expect("write");
    let (hdr, _) = read_response(s).await;
    assert_eq!(
        hdr.channel_sequence_status, STATUS_MORE_PROCESSING_REQUIRED,
        "SESSION_SETUP status"
    );
    hdr.credit_request_response
}

/// Connects, completes NEGOTIATE (MessageId 0) and starts a SESSION_SETUP
/// (MessageId 1), so the server answers ECHO.
pub async fn connect_in_session_setup(addr: SocketAddr) -> TcpStream {
    let mut s = connect_negotiated(addr).await;
    begin_session_setup(&mut s, 1, 64).await;
    s
}

/// CREATE body opening `name` for reading, creating it if missing.
pub fn create_body(name: &str) -> Vec<u8> {
    Create {
        name,
        access: FILE_GENERIC_READ,
        disposition: FILE_OPEN_IF,
        ..Create::default()
    }
    .body()
}

/// Opens `name` on the tree and returns its FileId.
pub async fn open_file(
    s: &mut TcpStream,
    message_id: u64,
    session_id: u64,
    tree_id: u32,
    name: &str,
) -> FileId {
    let hdr = build_header(Command::Create, message_id, session_id, tree_id);
    s.write_all(&framed(&message(&hdr, &create_body(name))))
        .await
        .expect("write");
    let (hdr, frame) = read_response(s).await;
    assert_eq!(hdr.channel_sequence_status, 0, "CREATE status");
    CreateResponse::parse(&frame[64..])
        .expect("create response")
        .file_id
}

/// READ body for `length` bytes at offset 0.
pub fn read_body(file_id: FileId, length: u32) -> Vec<u8> {
    let req = ReadRequest {
        structure_size: 49,
        padding: 0x50,
        flags: 0,
        length,
        offset: 0,
        file_id,
        minimum_count: 0,
        channel: 0,
        remaining_bytes: 0,
        read_channel_info_offset: 0,
        read_channel_info_length: 0,
        buffer: vec![0],
    };
    let mut body = Vec::new();
    req.write_to(&mut body).expect("read");
    body
}

/// Reads one response and splits off its header.
pub async fn read_response(s: &mut TcpStream) -> (Smb2Header, Vec<u8>) {
    let frame = tokio::time::timeout(WAIT, try_read_frame(s))
        .await
        .expect("response in time")
        .expect("response");
    let (hdr, _) = parse_response_header(&frame);
    (hdr, frame)
}

/// Asserts that the server closes the connection within `within`, without
/// sending anything first.
pub async fn assert_closed(s: &mut TcpStream, within: Duration) {
    let mut buf = [0u8; 64];
    match tokio::time::timeout(within, s.read(&mut buf)).await {
        Err(_) => panic!("connection still open after {within:?}"),
        Ok(Ok(0)) => {}
        Ok(Ok(n)) => panic!("expected a close, got {n} bytes"),
        Ok(Err(e)) => assert!(
            matches!(
                e.kind(),
                io::ErrorKind::ConnectionReset | io::ErrorKind::ConnectionAborted
            ),
            "unexpected error {e}"
        ),
    }
}

/// Asserts that nothing arrives and the connection stays open for `quiet`.
pub async fn assert_open(s: &mut TcpStream, quiet: Duration) {
    let mut buf = [0u8; 1];
    if let Ok(r) = tokio::time::timeout(quiet, s.read(&mut buf)).await {
        panic!("expected an open, quiet connection, got {r:?}");
    }
}
