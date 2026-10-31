//! Guest logons: the user name `guest` with an empty password, on a server
//! with a public share.

#![cfg(feature = "localfs")]

mod common;

use std::net::SocketAddr;

use common::auth::*;
use common::client::{FILE_WRITE_DATA, local};
use common::{negotiate, parse_response_header, start_server, tree_connect_body};
use smb_server::ntstatus::{STATUS_ACCESS_DENIED, STATUS_LOGON_FAILURE, STATUS_SUCCESS};
use smb_server::wire::header::{Command, SMB2_FLAGS_SIGNED};
use smb_server::wire::messages::{SessionSetupResponse, TreeConnectResponse};
use smb_server::{Access, Share, SmbServer, SmbServerBuilder};
use tempfile::TempDir;
use tokio::net::TcpStream;

/// User alice; public shares `pub` (read-write) and `docs` (read-only),
/// and alice's share `home`.
fn builder(td: &TempDir) -> SmbServerBuilder {
    SmbServer::builder()
        .user("alice", "password")
        .share(Share::new("pub", local(td.path())).public())
        .share(Share::new("docs", local(td.path())).public_read_only())
        .share(Share::new("home", local(td.path())).user("alice", Access::ReadWrite))
}

/// SMB 2.1 connection to a server started from `builder`.
async fn connect(builder: SmbServerBuilder) -> TcpStream {
    let (addr, _handle) = start_server(builder).await;
    connect_to(addr).await
}

async fn connect_to(addr: SocketAddr) -> TcpStream {
    let mut s = TcpStream::connect(addr).await.expect("connect");
    negotiate(&mut s).await;
    s
}

async fn logon(s: &mut TcpStream, user: &str, password: &str, opts: LoginOptions) -> Login {
    login_with(s, 1, 0, user, password, opts).await
}

fn session_flags(frame: &[u8]) -> u16 {
    SessionSetupResponse::parse(&frame[64..])
        .expect("session setup response")
        .session_flags
}

/// Status and MaximalAccess of an unsigned TREE_CONNECT to `share`.
async fn tree_connect(s: &mut TcpStream, mid: u64, sid: u64, share: &str) -> (u32, u32) {
    let body = tree_connect_body(&format!(r"\\srv\{share}"));
    let frame = request(s, Command::TreeConnect, mid, sid, 0, &body).await;
    let access = TreeConnectResponse::parse(&frame[64..]).map_or(0, |r| r.maximal_access);
    (status(&frame), access)
}

#[tokio::test]
async fn guest_with_an_empty_password_gets_the_public_shares() {
    let td = tempfile::tempdir().unwrap();
    let (addr, _handle) = start_server(builder(&td)).await;
    for (user, raw) in [("guest", false), ("GUEST", false), ("Guest", true)] {
        let mut s = connect_to(addr).await;
        let opts = LoginOptions {
            raw,
            ..LoginOptions::default()
        };
        let login = logon(&mut s, user, "", opts).await;
        assert_eq!(login.status, STATUS_SUCCESS, "{user}");
        assert_eq!(
            session_flags(&login.frame),
            SessionSetupResponse::FLAG_IS_GUEST
        );
        let (hdr, _) = parse_response_header(&login.frame);
        assert_eq!(hdr.flags & SMB2_FLAGS_SIGNED, 0, "final response signed");
        assert_eq!(hdr.signature, [0; 16]);

        let sid = login.session_id;
        let (st, access) = tree_connect(&mut s, 3, sid, "pub").await;
        assert_eq!(st, STATUS_SUCCESS);
        assert_ne!(access & FILE_WRITE_DATA, 0, "pub is read-write");
        let (st, access) = tree_connect(&mut s, 4, sid, "docs").await;
        assert_eq!(st, STATUS_SUCCESS);
        assert_eq!(access & FILE_WRITE_DATA, 0, "docs is read-only");
        assert_eq!(tree_connect(&mut s, 5, sid, "IPC$").await.0, STATUS_SUCCESS);
        assert_eq!(
            tree_connect(&mut s, 6, sid, "home").await.0,
            STATUS_ACCESS_DENIED
        );
    }
}

#[tokio::test]
async fn guest_with_a_password_is_refused() {
    let td = tempfile::tempdir().unwrap();
    let mut s = connect(builder(&td)).await;
    let login = logon(&mut s, "guest", "secret", LoginOptions::default()).await;
    assert_eq!(login.status, STATUS_LOGON_FAILURE);
}

#[tokio::test]
async fn other_unknown_names_are_not_guests() {
    let td = tempfile::tempdir().unwrap();
    let (addr, _handle) = start_server(builder(&td)).await;
    for user in ["guests", "nobody"] {
        let mut s = connect_to(addr).await;
        let login = logon(&mut s, user, "", LoginOptions::default()).await;
        assert_eq!(login.status, STATUS_LOGON_FAILURE, "{user}");
    }
}

#[tokio::test]
async fn guest_needs_a_public_share() {
    let td = tempfile::tempdir().unwrap();
    let builder = SmbServer::builder()
        .user("alice", "password")
        .share(Share::new("home", local(td.path())).user("alice", Access::ReadWrite));
    let mut s = connect(builder).await;
    let login = logon(&mut s, "guest", "", LoginOptions::default()).await;
    assert_eq!(login.status, STATUS_LOGON_FAILURE);
}

#[tokio::test]
async fn a_user_named_guest_logs_on_with_its_password() {
    let td = tempfile::tempdir().unwrap();
    let (addr, _handle) = start_server(builder(&td).user("Guest", "hunter2")).await;

    let mut s = connect_to(addr).await;
    let login = logon(&mut s, "guest", "hunter2", LoginOptions::default()).await;
    assert_eq!(login.status, STATUS_SUCCESS);
    assert_eq!(session_flags(&login.frame), 0);
    let (hdr, _) = parse_response_header(&login.frame);
    assert_ne!(hdr.flags & SMB2_FLAGS_SIGNED, 0, "final response signed");

    let mut s = connect_to(addr).await;
    let login = logon(&mut s, "guest", "", LoginOptions::default()).await;
    assert_eq!(login.status, STATUS_LOGON_FAILURE);
}

#[tokio::test]
async fn guest_is_refused_when_the_client_requires_signing() {
    let td = tempfile::tempdir().unwrap();
    let (addr, _handle) = start_server(builder(&td)).await;
    for security_mode in [0x02, 0x03] {
        let mut s = connect_to(addr).await;
        let opts = LoginOptions {
            security_mode,
            ..LoginOptions::default()
        };
        let login = logon(&mut s, "guest", "", opts).await;
        assert_eq!(login.status, STATUS_ACCESS_DENIED, "{security_mode:#x}");
    }
}

#[tokio::test]
async fn reauthentication_between_a_user_and_guest_is_refused() {
    let td = tempfile::tempdir().unwrap();
    let (addr, _handle) = start_server(builder(&td)).await;
    for (first, first_password, then, then_password) in [
        ("alice", "password", "guest", ""),
        ("guest", "", "alice", "password"),
    ] {
        let mut s = connect_to(addr).await;
        let login = logon(&mut s, first, first_password, LoginOptions::default()).await;
        assert_eq!(login.status, STATUS_SUCCESS, "{first}");
        let opts = LoginOptions::default();
        let again = login_with(&mut s, 3, login.session_id, then, then_password, opts).await;
        assert_eq!(again.status, STATUS_ACCESS_DENIED, "{first} as {then}");
    }
}
