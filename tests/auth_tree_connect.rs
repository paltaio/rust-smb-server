//! TREE_CONNECT path parsing.

#![cfg(feature = "localfs")]

mod common;

use common::auth::*;
use common::{anonymous_session_setup, negotiate, start_server, tree_connect_body, utf16le};
use smb_server::ntstatus::{STATUS_BAD_NETWORK_NAME, STATUS_INVALID_PARAMETER};
use smb_server::wire::header::Command;
use smb_server::{LocalFsBackend, Share, SmbServer};
use tokio::net::TcpStream;

async fn connect() -> (
    TcpStream,
    u64,
    tokio::task::JoinHandle<()>,
    tempfile::TempDir,
) {
    let td = tempfile::tempdir().expect("tempdir");
    let backend = LocalFsBackend::new(td.path()).expect("open root");
    let (addr, handle) =
        start_server(SmbServer::builder().share(Share::new("pub", backend).public())).await;
    let mut s = TcpStream::connect(addr).await.expect("connect");
    negotiate(&mut s).await;
    let sid = anonymous_session_setup(&mut s).await;
    (s, sid, handle, td)
}

/// TREE_CONNECT with `path` placed `pad` bytes after the fixed part.
fn body_with(path: &[u8], pad: usize) -> Vec<u8> {
    let mut body = vec![9, 0, 0, 0];
    body.extend_from_slice(&((64 + 8 + pad) as u16).to_le_bytes());
    body.extend_from_slice(&(path.len() as u16).to_le_bytes());
    body.extend(std::iter::repeat_n(0u8, pad));
    body.extend_from_slice(path);
    body
}

#[tokio::test]
async fn path_must_be_server_and_share() {
    let (mut s, sid, _h, _td) = connect().await;
    let frame = request(
        &mut s,
        Command::TreeConnect,
        3,
        sid,
        0,
        &tree_connect_body(r"\\srv\pub\sub"),
    )
    .await;
    assert_eq!(status(&frame), STATUS_INVALID_PARAMETER);
    let mut odd = utf16le(r"\\srv\pub");
    odd.push(0);
    let frame = request(
        &mut s,
        Command::TreeConnect,
        20,
        sid,
        0,
        &body_with(&odd, 0),
    )
    .await;
    assert_eq!(status(&frame), STATUS_INVALID_PARAMETER, "odd length");

    let frame = request(
        &mut s,
        Command::TreeConnect,
        21,
        sid,
        0,
        &tree_connect_body(r"\\srv\nope"),
    )
    .await;
    assert_eq!(status(&frame), STATUS_BAD_NETWORK_NAME);
    let frame = request(
        &mut s,
        Command::TreeConnect,
        22,
        sid,
        0,
        &tree_connect_body(r"\\srv\PUB"),
    )
    .await;
    assert_eq!(status(&frame), 0);
}

#[tokio::test]
async fn path_is_read_at_path_offset() {
    let (mut s, sid, _h, _td) = connect().await;
    let path = utf16le(r"\\srv\pub");
    let frame = request(
        &mut s,
        Command::TreeConnect,
        3,
        sid,
        0,
        &body_with(&path, 8),
    )
    .await;
    assert_eq!(status(&frame), 0);
}
