//! Connection limits, timeouts and keepalive.

#[allow(dead_code, reason = "only the session helpers are used here")]
mod common;
#[path = "support_transport.rs"]
mod support;

use std::time::{Duration, Instant};

use smb_server::ntstatus::STATUS_INSUFFICIENT_RESOURCES;
use smb_server::wire::header::Command;
use smb_server::{LocalFsBackend, Share, SmbServer, SmbServerBuilder};
use support::{
    WAIT, assert_closed, assert_open, connect, connect_negotiated, framed, header, message,
    negotiate_request, open_file, read_body, start, try_read_frame,
};
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// Builder with a public share holding `f.txt` of `size` bytes.
fn with_share(size: usize) -> (SmbServerBuilder, TempDir) {
    let td = tempfile::tempdir().expect("tempdir");
    std::fs::write(td.path().join("f.txt"), vec![0x5A; size]).expect("file");
    let backend = LocalFsBackend::new(td.path()).expect("backend");
    let builder = SmbServer::builder().share(Share::new("share", backend).public());
    (builder, td)
}

/// Anonymous session and tree on `share`; the next free MessageId is 4.
async fn anonymous_tree(addr: std::net::SocketAddr) -> (TcpStream, u64, u32) {
    let mut s = connect(addr).await;
    common::negotiate(&mut s).await;
    let session_id = common::anonymous_session_setup(&mut s).await;
    let tree_id = common::tree_connect(&mut s, "\\\\server\\share", session_id, 3).await;
    (s, session_id, tree_id)
}

#[tokio::test]
async fn connections_beyond_the_limit_are_closed() {
    let (addr, handle) = start(SmbServer::builder().max_connections(2)).await;
    let first = connect_negotiated(addr).await;
    let _second = connect_negotiated(addr).await;
    let mut third = connect(addr).await;
    assert_closed(&mut third, WAIT).await;

    // The slot is free again once the server sees the close.
    drop(first);
    let deadline = Instant::now() + WAIT;
    loop {
        let mut s = connect(addr).await;
        let _ = s.write_all(&negotiate_request()).await;
        if let Ok(Ok(_)) =
            tokio::time::timeout(Duration::from_secs(1), try_read_frame(&mut s)).await
        {
            break;
        }
        assert!(Instant::now() < deadline, "connection slot not released");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    handle.abort();
}

#[tokio::test]
async fn connections_without_a_session_close_after_the_handshake_timeout() {
    let builder = SmbServer::builder().handshake_timeout(Duration::from_millis(300));
    let (addr, handle) = start(builder).await;
    let mut silent = connect(addr).await;
    let mut negotiated = connect_negotiated(addr).await;
    assert_closed(&mut silent, WAIT).await;
    assert_closed(&mut negotiated, WAIT).await;
    handle.abort();
}

#[tokio::test]
async fn partial_frames_close_after_the_io_timeout() {
    let builder = SmbServer::builder().io_timeout(Duration::from_millis(300));
    let (addr, handle) = start(builder).await;
    let mut short_prefix = connect_negotiated(addr).await;
    short_prefix.write_all(&[0, 0]).await.expect("write");
    let mut short_payload = connect_negotiated(addr).await;
    let mut frame = vec![0, 0, 0, 100];
    frame.extend_from_slice(&[0xFE; 10]);
    short_payload.write_all(&frame).await.expect("write");
    assert_closed(&mut short_prefix, WAIT).await;
    assert_closed(&mut short_payload, WAIT).await;
    handle.abort();
}

#[tokio::test]
async fn idle_connections_close_unless_a_file_is_open() {
    let (builder, _td) = with_share(16);
    let (addr, handle) = start(builder.idle_timeout(Duration::from_millis(500))).await;
    let (mut idle, _, _) = anonymous_tree(addr).await;
    let (mut busy, session_id, tree_id) = anonymous_tree(addr).await;
    open_file(&mut busy, 4, session_id, tree_id, "f.txt").await;

    assert_closed(&mut idle, WAIT).await;
    assert_open(&mut busy, Duration::from_millis(1500)).await;
    handle.abort();
}

#[tokio::test]
async fn a_peer_that_stops_reading_is_dropped_after_the_io_timeout() {
    const MIB: u32 = 1024 * 1024;
    let (builder, _td) = with_share(MIB as usize);
    let (addr, handle) = start(builder.io_timeout(Duration::from_millis(500))).await;
    let (mut s, session_id, tree_id) = anonymous_tree(addr).await;
    let file_id = open_file(&mut s, 4, session_id, tree_id, "f.txt").await;

    let mut requests = Vec::new();
    for i in 0..64 {
        let mut hdr = header(Command::Read, 5 + 16 * i, session_id, tree_id);
        hdr.credit_charge = 16;
        hdr.credit_request_response = 16;
        requests.extend_from_slice(&framed(&message(&hdr, &read_body(file_id, MIB))));
    }
    s.write_all(&requests).await.expect("write");
    tokio::time::sleep(Duration::from_secs(2)).await;

    // What the server managed to send is still buffered; after that the
    // stream ends instead of stalling.
    let drained = tokio::time::timeout(WAIT, async {
        let mut buf = vec![0u8; 1 << 16];
        let mut total = 0usize;
        loop {
            match s.read(&mut buf).await {
                Ok(0) | Err(_) => return total,
                Ok(n) => total += n,
            }
        }
    })
    .await
    .expect("connection closed");
    assert!(drained < 64 * MIB as usize, "read {drained} bytes");
    handle.abort();
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn accepted_connections_use_tcp_keepalive() {
    let builder = SmbServer::builder().tcp_keepalive(Some(Duration::from_secs(30)));
    let (addr, handle) = start(builder).await;
    let s = connect_negotiated(addr).await;
    let client_port = s.local_addr().expect("local addr").port();

    // /proc/net/tcp: "sl local rem st tx:rx tr:when ...", ports in hex; timer
    // type 2 is the keepalive timer.
    let table = std::fs::read_to_string("/proc/net/tcp").expect("/proc/net/tcp");
    let port = |field: &str| u16::from_str_radix(field.rsplit(':').next().unwrap(), 16).unwrap();
    let server_side = table
        .lines()
        .skip(1)
        .map(|line| line.split_whitespace().collect::<Vec<_>>())
        .find(|f| port(f[1]) == addr.port() && port(f[2]) == client_port)
        .expect("server socket");
    assert!(
        server_side[5].starts_with("02:"),
        "timer {} is not keepalive",
        server_side[5]
    );
    handle.abort();
}

#[tokio::test]
async fn abandoned_authentication_exchanges_expire() {
    let (builder, _td) = with_share(0);
    let (addr, handle) = start(builder.handshake_timeout(Duration::from_millis(500))).await;
    let mut s = connect(addr).await;
    common::negotiate(&mut s).await;
    common::anonymous_session_setup(&mut s).await;

    let mut message_id = 3;
    for _ in 0..16 {
        let (status, _) = common::start_ntlm_session_setup(&mut s, message_id).await;
        assert_eq!(status, common::STATUS_MORE_PROCESSING_REQUIRED);
        message_id += 1;
    }
    let (status, _) = common::start_ntlm_session_setup(&mut s, message_id).await;
    assert_eq!(status, STATUS_INSUFFICIENT_RESOURCES);

    tokio::time::sleep(Duration::from_millis(600)).await;
    let (status, _) = common::start_ntlm_session_setup(&mut s, message_id + 1).await;
    assert_eq!(status, common::STATUS_MORE_PROCESSING_REQUIRED);
    handle.abort();
}
