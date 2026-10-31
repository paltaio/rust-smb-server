//! Failed-logon throttle.

#![cfg(feature = "localfs")]

mod common;

use std::net::SocketAddr;
use std::time::Duration;

use common::auth::*;
use common::{negotiate, start_server};
use smb_server::ntstatus::{STATUS_ACCOUNT_LOCKED_OUT, STATUS_LOGON_FAILURE};
use smb_server::{Access, LocalFsBackend, Share, SmbServer};
use tokio::net::TcpStream;

async fn logon(addr: SocketAddr, user: &str, password: &str) -> u32 {
    let mut s = TcpStream::connect(addr).await.expect("connect");
    negotiate(&mut s).await;
    spnego_login(&mut s, 1, 0, user, password).await.status
}

#[tokio::test]
async fn repeated_failures_lock_the_user_name_for_a_while() {
    let td = tempfile::tempdir().expect("tempdir");
    let backend = LocalFsBackend::new(td.path()).expect("open root");
    let (addr, _handle) = start_server(
        SmbServer::builder()
            .user("alice", "password")
            .user("bob", "hunter2")
            .share(Share::new("home", backend).user("alice", Access::Read))
            .logon_throttle(3, Duration::from_millis(400)),
    )
    .await;

    for _ in 0..3 {
        assert_eq!(logon(addr, "alice", "wrong").await, STATUS_LOGON_FAILURE);
        assert_eq!(logon(addr, "mallory", "guess").await, STATUS_LOGON_FAILURE);
    }
    // The right password does not get through while the name is locked,
    // and a name that is not configured locks the same way.
    assert_eq!(
        logon(addr, "ALICE", "password").await,
        STATUS_ACCOUNT_LOCKED_OUT
    );
    assert_eq!(
        logon(addr, "mallory", "guess").await,
        STATUS_ACCOUNT_LOCKED_OUT
    );
    assert_eq!(logon(addr, "bob", "hunter2").await, 0);

    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(logon(addr, "alice", "password").await, 0);
}

#[tokio::test]
async fn failures_from_one_address_lock_it_out() {
    let td = tempfile::tempdir().expect("tempdir");
    let backend = LocalFsBackend::new(td.path()).expect("open root");
    let (addr, _handle) = start_server(
        SmbServer::builder()
            .user("alice", "password")
            .share(Share::new("home", backend).user("alice", Access::Read))
            .logon_throttle(2, Duration::from_secs(60)),
    )
    .await;

    // Ten times the per-user limit, one guess per name.
    for i in 0..20 {
        let user = format!("guess{i}");
        assert_eq!(logon(addr, &user, "wrong").await, STATUS_LOGON_FAILURE);
    }
    assert_eq!(
        logon(addr, "alice", "password").await,
        STATUS_ACCOUNT_LOCKED_OUT
    );
}

#[tokio::test]
async fn guest_logons_count_by_address_only_when_they_fail() {
    let td = tempfile::tempdir().expect("tempdir");
    let backend = LocalFsBackend::new(td.path()).expect("open root");
    let (addr, _handle) = start_server(
        SmbServer::builder()
            .user("alice", "password")
            .share(Share::new("pub", backend).public())
            .logon_throttle(2, Duration::from_secs(60)),
    )
    .await;

    // On one connection and on new ones, past the limit.
    let mut s = TcpStream::connect(addr).await.expect("connect");
    negotiate(&mut s).await;
    for i in 0..3 {
        let login = spnego_login(&mut s, 1 + 2 * i, 0, "guest", "").await;
        assert_eq!(login.status, 0);
    }
    for _ in 0..3 {
        assert_eq!(logon(addr, "guest", "").await, 0);
    }
    assert_eq!(logon(addr, "alice", "password").await, 0);

    // The guest password is known to everyone, so the name is not locked.
    for _ in 0..2 {
        assert_eq!(logon(addr, "guest", "wrong").await, STATUS_LOGON_FAILURE);
    }
    assert_eq!(logon(addr, "guest", "").await, 0);

    // The address is, at ten times the per-user limit.
    for _ in 2..20 {
        assert_eq!(logon(addr, "guest", "wrong").await, STATUS_LOGON_FAILURE);
    }
    assert_eq!(logon(addr, "guest", "").await, STATUS_ACCOUNT_LOCKED_OUT);
    assert_eq!(
        logon(addr, "alice", "password").await,
        STATUS_ACCOUNT_LOCKED_OUT
    );
}
