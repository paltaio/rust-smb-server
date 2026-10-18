//! SESSION_SETUP on existing sessions, PreviousSessionId and LOGOFF.

#![cfg(feature = "localfs")]

#[allow(dead_code, reason = "this crate uses part of the shared helpers")]
mod common;
#[path = "support_auth.rs"]
mod support;

use std::net::SocketAddr;

use common::{STATUS_MORE_PROCESSING_REQUIRED, negotiate, start_server};
use smb_server::wire::header::Command;
use smb_server::{Access, LocalFsBackend, Share, SmbServer};
use support::*;
use tokio::net::TcpStream;

async fn server() -> (SocketAddr, tokio::task::JoinHandle<()>, tempfile::TempDir) {
    let td = tempfile::tempdir().expect("tempdir");
    let backend = LocalFsBackend::new(td.path()).expect("open root");
    let (addr, handle) = start_server(
        SmbServer::builder()
            .user("alice", "password")
            .user("bob", "hunter2")
            .share(
                Share::new("home", backend)
                    .user("alice", Access::ReadWrite)
                    .user("bob", Access::ReadWrite),
            ),
    )
    .await;
    (addr, handle, td)
}

async fn connect(addr: SocketAddr) -> TcpStream {
    let mut s = TcpStream::connect(addr).await.expect("connect");
    negotiate(&mut s).await;
    s
}

async fn tree_connect(s: &mut TcpStream, mid: u64, sid: u64) -> (u32, u32) {
    let frame = request(
        s,
        Command::TreeConnect,
        mid,
        sid,
        0,
        &tree_connect_body(r"\\srv\home"),
    )
    .await;
    let tid = smb_server::wire::header::Smb2Header::parse(&frame)
        .unwrap()
        .0
        .tree_id()
        .unwrap_or(0);
    (status(&frame), tid)
}

async fn tree_disconnect(s: &mut TcpStream, mid: u64, sid: u64, tid: u32) -> u32 {
    status(&request(s, Command::TreeDisconnect, mid, sid, tid, &[4, 0, 0, 0]).await)
}

#[tokio::test]
async fn unknown_session_id_is_refused() {
    let (addr, _h, _td) = server().await;
    let mut s = connect(addr).await;
    let login = login_with(
        &mut s,
        1,
        0x7777,
        "alice",
        "password",
        LoginOptions::default(),
    )
    .await;
    assert_eq!(login.status, STATUS_USER_SESSION_DELETED);
}

#[tokio::test]
async fn binding_is_not_accepted() {
    let (addr, _h, _td) = server().await;
    let mut s = connect(addr).await;
    let sid = spnego_login(&mut s, 1, 0, "alice", "password")
        .await
        .session_id;
    let opts = LoginOptions {
        flags: 0x01,
        ..LoginOptions::default()
    };
    let login = login_with(&mut s, 3, sid, "alice", "password", opts).await;
    assert_eq!(login.status, STATUS_REQUEST_NOT_ACCEPTED);
}

#[tokio::test]
async fn reauthentication_keeps_the_session_and_its_trees() {
    let (addr, _h, _td) = server().await;
    let mut s = connect(addr).await;
    let sid = spnego_login(&mut s, 1, 0, "alice", "password")
        .await
        .session_id;
    let (st, tid) = tree_connect(&mut s, 3, sid).await;
    assert_eq!(st, 0);

    // First round on the existing session id.
    let negotiate_msg = ntlm_negotiate(CLIENT_FLAGS);
    let body = session_setup_body(&negotiate_msg, 0, 1, 0);
    let frame = request(&mut s, Command::SessionSetup, 4, sid, 0, &body).await;
    assert_eq!(status(&frame), STATUS_MORE_PROCESSING_REQUIRED);
    assert_eq!(response_session_id(&frame), sid);

    let login = login_with(&mut s, 5, sid, "alice", "password", LoginOptions::default()).await;
    assert_eq!(login.status, 0);
    assert_eq!(response_session_id(&login.frame), sid);
    assert_eq!(tree_disconnect(&mut s, 7, sid, tid).await, 0);
}

#[tokio::test]
async fn failed_reauthentication_ends_the_session() {
    let (addr, _h, _td) = server().await;
    let mut s = connect(addr).await;
    let sid = spnego_login(&mut s, 1, 0, "alice", "password")
        .await
        .session_id;
    let (_, tid) = tree_connect(&mut s, 3, sid).await;
    let login = login_with(&mut s, 4, sid, "alice", "wrong", LoginOptions::default()).await;
    assert_eq!(login.status, STATUS_LOGON_FAILURE);
    assert_eq!(
        tree_disconnect(&mut s, 6, sid, tid).await,
        STATUS_USER_SESSION_DELETED
    );
}

#[tokio::test]
async fn reauthentication_as_another_user_is_refused() {
    let (addr, _h, _td) = server().await;
    let mut s = connect(addr).await;
    let sid = spnego_login(&mut s, 1, 0, "alice", "password")
        .await
        .session_id;
    let (_, tid) = tree_connect(&mut s, 3, sid).await;
    let login = login_with(&mut s, 4, sid, "bob", "hunter2", LoginOptions::default()).await;
    assert_eq!(login.status, STATUS_ACCESS_DENIED);
    assert_eq!(tree_disconnect(&mut s, 6, sid, tid).await, 0);
}

#[tokio::test]
async fn session_ids_are_unique_across_connections() {
    let (addr, _h, _td) = server().await;
    let mut a = connect(addr).await;
    let mut b = connect(addr).await;
    let sa = spnego_login(&mut a, 1, 0, "alice", "password").await;
    let sb = spnego_login(&mut b, 1, 0, "alice", "password").await;
    assert_eq!((sa.status, sb.status), (0, 0));
    assert_ne!(sa.session_id, sb.session_id);
}

#[tokio::test]
async fn previous_session_id_ends_the_old_session_of_the_same_user() {
    let (addr, _h, _td) = server().await;
    let mut old = connect(addr).await;
    let old_sid = spnego_login(&mut old, 1, 0, "alice", "password")
        .await
        .session_id;
    let mut bobs = connect(addr).await;
    let bob_sid = spnego_login(&mut bobs, 1, 0, "bob", "hunter2")
        .await
        .session_id;

    let mut new = connect(addr).await;
    for (mid, previous) in [(1, bob_sid), (3, old_sid)] {
        let opts = LoginOptions {
            previous_session_id: previous,
            ..LoginOptions::default()
        };
        let login = login_with(&mut new, mid, 0, "alice", "password", opts).await;
        assert_eq!(login.status, 0);
    }
    // Bob's session belongs to another user and stays.
    assert_eq!(tree_connect(&mut bobs, 3, bob_sid).await.0, 0);
    assert_eq!(
        tree_connect(&mut old, 3, old_sid).await.0,
        STATUS_USER_SESSION_DELETED
    );
}

#[tokio::test]
async fn logoff_of_an_unknown_session_fails() {
    let (addr, _h, _td) = server().await;
    let mut s = connect(addr).await;
    let frame = request(&mut s, Command::Logoff, 1, 0x99, 0, &[4, 0, 0, 0]).await;
    assert_eq!(status(&frame), STATUS_USER_SESSION_DELETED);
    let sid = spnego_login(&mut s, 2, 0, "alice", "password")
        .await
        .session_id;
    let frame = request(&mut s, Command::Logoff, 4, sid, 0, &[4, 0, 0, 0]).await;
    assert_eq!(status(&frame), 0);
}
