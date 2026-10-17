//! Request validation in the dispatcher.

#[allow(dead_code, reason = "only the session helpers are used here")]
mod common;
#[path = "support_transport.rs"]
mod support;

use smb_server::ntstatus::STATUS_INVALID_PARAMETER;
use smb_server::wire::header::Command;
use smb_server::{LocalFsBackend, Share, SmbServer, SmbServerBuilder};
use support::{
    ECHO_BODY, WAIT, assert_closed, connect, connect_negotiated, create_body, framed, header,
    message, read_response, start,
};
use tempfile::TempDir;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

fn with_share() -> (SmbServerBuilder, TempDir) {
    let td = tempfile::tempdir().expect("tempdir");
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

/// Requests chained into one compound frame, each 8-byte aligned.
fn compound(messages: &[Vec<u8>]) -> Vec<u8> {
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

#[tokio::test]
async fn malformed_frames_close_the_connection() {
    let (addr, handle) = start(SmbServer::builder()).await;
    let echo = message(&header(Command::Echo, 1, 0, 0), &ECHO_BODY);

    let mut short = echo.clone();
    short.truncate(63);
    let mut unknown_command = echo.clone();
    unknown_command[12] = 0x13;
    let mut bad_magic = echo.clone();
    bad_magic[0] = 0x41;
    let mut transform = echo.clone();
    transform[0] = 0xFD;
    let mut header_size = echo.clone();
    header_size[4] = 63;
    let mut bad_next = echo.clone();
    bad_next[0x14] = 32;
    bad_next.extend_from_slice(&echo);

    for (name, payload) in [
        ("short", short),
        ("unknown command", unknown_command),
        ("bad magic", bad_magic),
        ("transform header", transform),
        ("header StructureSize", header_size),
        ("NextCommand", bad_next),
        ("empty", Vec::new()),
    ] {
        eprintln!("frame: {name}");
        let mut s = connect_negotiated(addr).await;
        s.write_all(&framed(&payload)).await.expect("write");
        assert_closed(&mut s, WAIT).await;
    }
    handle.abort();
}

#[tokio::test]
async fn a_compound_with_a_bad_request_runs_none_of_it() {
    let (builder, td) = with_share();
    let (addr, handle) = start(builder).await;
    let (mut s, session_id, tree_id) = anonymous_tree(addr).await;

    let create = message(
        &header(Command::Create, 4, session_id, tree_id),
        &create_body("orphan.tmp"),
    );
    let mut bad = message(&header(Command::Echo, 5, 0, 0), &ECHO_BODY);
    bad[0] = 0x41;
    s.write_all(&compound(&[create, bad])).await.expect("write");
    assert_closed(&mut s, WAIT).await;
    assert!(!td.path().join("orphan.tmp").exists(), "CREATE ran");
    handle.abort();
}

#[tokio::test]
async fn bodies_must_carry_their_structure_size() {
    let (builder, td) = with_share();
    let (addr, handle) = start(builder).await;
    let (mut s, session_id, tree_id) = anonymous_tree(addr).await;

    let echo = message(&header(Command::Echo, 4, 0, 0), &[0, 0, 0, 0]);
    s.write_all(&framed(&echo)).await.expect("write");
    let (hdr, _) = read_response(&mut s).await;
    assert_eq!(hdr.channel_sequence_status, STATUS_INVALID_PARAMETER);

    let mut body = create_body("made.tmp");
    body[..2].copy_from_slice(&0xFFFFu16.to_le_bytes());
    let create = message(&header(Command::Create, 5, session_id, tree_id), &body);
    s.write_all(&framed(&create)).await.expect("write");
    let (hdr, _) = read_response(&mut s).await;
    assert_eq!(hdr.channel_sequence_status, STATUS_INVALID_PARAMETER);
    assert!(!td.path().join("made.tmp").exists(), "CREATE ran");

    // The connection stays usable.
    let echo = message(&header(Command::Echo, 6, 0, 0), &ECHO_BODY);
    s.write_all(&framed(&echo)).await.expect("write");
    let (hdr, _) = read_response(&mut s).await;
    assert_eq!(hdr.channel_sequence_status, 0);
    handle.abort();
}
