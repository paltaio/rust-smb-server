//! Raw-socket helpers for the transport tests.
#![allow(dead_code, reason = "each test crate uses a subset of the helpers")]

use std::io;
use std::net::SocketAddr;
use std::time::Duration;

use smb_server::wire::header::{Command, HeaderTail, SMB2_FLAGS_SERVER_TO_REDIR, Smb2Header};
use smb_server::wire::messages::{
    CreateRequest, CreateResponse, FileId, NegotiateRequest, ReadRequest,
};
use smb_server::{ShutdownHandle, SmbServerBuilder};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::task::JoinHandle;

/// How long a test waits for a response or a close.
pub const WAIT: Duration = Duration::from_secs(5);

/// Request header with CreditCharge 1 and CreditRequest 64.
pub fn header(command: Command, message_id: u64, session_id: u64, tree_id: u32) -> Smb2Header {
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

pub const ECHO_BODY: [u8; 4] = [4, 0, 0, 0];

/// A framed ECHO request.
pub fn echo(message_id: u64) -> Vec<u8> {
    framed(&message(
        &header(Command::Echo, message_id, 0, 0),
        &ECHO_BODY,
    ))
}

/// A framed SMB2 NEGOTIATE offering 2.0.2 and 2.1, with MessageId 0.
pub fn negotiate_request() -> Vec<u8> {
    let req = NegotiateRequest {
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
    req.write_to(&mut body).expect("negotiate");
    framed(&message(&header(Command::Negotiate, 0, 0, 0), &body))
}

/// Builds the server on a loopback port and serves it on a task.
pub async fn start(builder: SmbServerBuilder) -> (SocketAddr, JoinHandle<()>) {
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

/// Like [`start`], and also returns the server's shutdown handle.
pub async fn start_with_shutdown(
    builder: SmbServerBuilder,
) -> (SocketAddr, ShutdownHandle, JoinHandle<()>) {
    let server = builder
        .listen("127.0.0.1:0".parse().unwrap())
        .build()
        .expect("build");
    let addr = server.bind().await.expect("bind");
    let shutdown = server.shutdown_handle();
    let handle = tokio::spawn(async move {
        let _ = server.serve().await;
    });
    (addr, shutdown, handle)
}

/// Connects with TCP_NODELAY set.
pub async fn connect(addr: SocketAddr) -> TcpStream {
    let s = TcpStream::connect(addr).await.expect("connect");
    s.set_nodelay(true).expect("nodelay");
    s
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

/// CREATE body opening `name` for reading, creating it if missing.
pub fn create_body(name: &str) -> Vec<u8> {
    let name: Vec<u8> = name.encode_utf16().flat_map(u16::to_le_bytes).collect();
    let req = CreateRequest {
        structure_size: 57,
        security_flags: 0,
        requested_oplock_level: 0,
        impersonation_level: 2,
        smb_create_flags: 0,
        reserved: 0,
        desired_access: 0x0012_0089,
        file_attributes: 0,
        share_access: 0x0000_0007,
        create_disposition: 3,
        create_options: 0,
        name_offset: 0x78,
        name_length: name.len() as u16,
        create_contexts_offset: 0,
        create_contexts_length: 0,
        name,
        create_contexts: vec![],
    };
    let mut body = Vec::new();
    req.write_to(&mut body).expect("create");
    body
}

/// Opens `name` on the tree and returns its FileId.
pub async fn open_file(
    s: &mut TcpStream,
    message_id: u64,
    session_id: u64,
    tree_id: u32,
    name: &str,
) -> FileId {
    let hdr = header(Command::Create, message_id, session_id, tree_id);
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

/// Reads one frame, or the error that ended the stream.
pub async fn try_read_frame(s: &mut TcpStream) -> io::Result<Vec<u8>> {
    let mut prefix = [0u8; 4];
    s.read_exact(&mut prefix).await?;
    let len =
        (usize::from(prefix[1]) << 16) | (usize::from(prefix[2]) << 8) | usize::from(prefix[3]);
    let mut payload = vec![0u8; len];
    s.read_exact(&mut payload).await?;
    Ok(payload)
}

/// Reads one response and splits off its header.
pub async fn read_response(s: &mut TcpStream) -> (Smb2Header, Vec<u8>) {
    let frame = tokio::time::timeout(WAIT, try_read_frame(s))
        .await
        .expect("response in time")
        .expect("response");
    let (hdr, _) = Smb2Header::parse(&frame).expect("response header");
    assert_ne!(
        hdr.flags & SMB2_FLAGS_SERVER_TO_REDIR,
        0,
        "must be a response"
    );
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
