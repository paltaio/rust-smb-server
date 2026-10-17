//! Session.SigningRequired: the client's SecurityMode bits and the server's
//! require-signing option.

#![cfg(feature = "localfs")]

#[allow(dead_code, reason = "this crate uses part of the shared helpers")]
mod common;
#[path = "support_auth.rs"]
mod support;

use common::{anonymous_session_setup, start_server};
use smb_server::wire::header::Command;
use smb_server::wire::messages::NegotiateResponse;
use smb_server::{Access, LocalFsBackend, Share, SmbServer, SmbServerBuilder};
use support::*;
use tokio::net::TcpStream;

fn builder(td: &tempfile::TempDir) -> SmbServerBuilder {
    let home = LocalFsBackend::new(td.path()).expect("open root");
    let public = LocalFsBackend::new(td.path()).expect("open root");
    SmbServer::builder()
        .user("alice", "password")
        .share(Share::new("home", home).user("alice", Access::ReadWrite))
        .share(Share::new("pub", public).public())
}

/// SMB 2.1 connection negotiated with `security_mode`.
async fn connect(builder: SmbServerBuilder, security_mode: u16) -> (TcpStream, NegotiateResponse) {
    let (addr, _handle) = start_server(builder).await;
    let mut s = TcpStream::connect(addr).await.expect("connect");
    let body = negotiate_body(&[0x0202, 0x0210], security_mode, 0);
    let frame = request(&mut s, Command::Negotiate, 0, 0, 0, &body).await;
    assert_eq!(status(&frame), 0);
    (s, NegotiateResponse::parse(&frame[64..]).unwrap())
}

async fn tree_connect_status(
    s: &mut TcpStream,
    mid: u64,
    sid: u64,
    share: &str,
    key: Option<&[u8; 16]>,
) -> u32 {
    let hdr = build_header(Command::TreeConnect, mid, sid, 0);
    let body = tree_connect_body(&format!(r"\\srv\{share}"));
    status(&send(s, hdr, &body, key).await)
}

async fn alice(s: &mut TcpStream, security_mode: u8) -> Login {
    let opts = LoginOptions {
        security_mode,
        ..LoginOptions::default()
    };
    let login = login_with(s, 1, 0, "alice", "password", opts).await;
    assert_eq!(login.status, 0);
    login
}

#[tokio::test]
async fn client_signing_required_bit_requires_signed_requests() {
    // SIGNING_REQUIRED in SESSION_SETUP, then in NEGOTIATE.
    for (negotiate_mode, session_mode) in [(0x0001, 0x03), (0x0003, 0x01)] {
        let td = tempfile::tempdir().unwrap();
        let (mut s, _) = connect(builder(&td), negotiate_mode).await;
        let login = alice(&mut s, session_mode).await;
        let sid = login.session_id;
        assert_eq!(
            tree_connect_status(&mut s, 3, sid, "home", None).await,
            STATUS_ACCESS_DENIED,
            "unsigned, modes {negotiate_mode:#x}/{session_mode:#x}"
        );
        assert_eq!(
            tree_connect_status(&mut s, 4, sid, "home", Some(&login.key)).await,
            0
        );
    }
}

#[tokio::test]
async fn signing_is_optional_when_nobody_requires_it() {
    let td = tempfile::tempdir().unwrap();
    let (mut s, neg) = connect(builder(&td), 0x0001).await;
    assert_eq!(neg.security_mode, 0x0001);
    let login = alice(&mut s, 0x01).await;
    assert_eq!(
        tree_connect_status(&mut s, 3, login.session_id, "home", None).await,
        0
    );
}

#[tokio::test]
async fn require_signing_option_requires_signed_requests() {
    let td = tempfile::tempdir().unwrap();
    let (mut s, neg) = connect(builder(&td).require_signing(true), 0x0001).await;
    assert_eq!(neg.security_mode, 0x0003);
    let login = alice(&mut s, 0x01).await;
    let sid = login.session_id;
    assert_eq!(
        tree_connect_status(&mut s, 3, sid, "home", None).await,
        STATUS_ACCESS_DENIED
    );
    assert_eq!(
        tree_connect_status(&mut s, 4, sid, "home", Some(&login.key)).await,
        0
    );
}

#[tokio::test]
async fn anonymous_sessions_stay_unsigned() {
    let td = tempfile::tempdir().unwrap();
    let (mut s, _) = connect(builder(&td).require_signing(true), 0x0003).await;
    let sid = anonymous_session_setup(&mut s).await;
    assert_eq!(tree_connect_status(&mut s, 3, sid, "pub", None).await, 0);
}

#[tokio::test]
async fn smb311_unsigned_tree_connect_is_refused() {
    let td = tempfile::tempdir().unwrap();
    let (addr, _handle) = start_server(builder(&td)).await;
    let mut s = TcpStream::connect(addr).await.expect("connect");
    let body = negotiate_311_body(&[0x0311], &[preauth_context(&[1])]);
    let frame = request(&mut s, Command::Negotiate, 0, 0, 0, &body).await;
    assert_eq!(status(&frame), 0);
    let login = alice(&mut s, 0x01).await;

    let hdr = build_header(Command::TreeConnect, 3, login.session_id, 0);
    let mut msg = Vec::new();
    hdr.write(&mut msg).unwrap();
    msg.extend_from_slice(&tree_connect_body(r"\\srv\home"));
    let mut framed = Vec::new();
    encode_frame(&msg, &mut framed);
    tokio::io::AsyncWriteExt::write_all(&mut s, &framed)
        .await
        .unwrap();
    let reply = read_or_closed(&mut s).await;
    assert!(reply.is_none_or(|f| status(&f) != 0));
}
