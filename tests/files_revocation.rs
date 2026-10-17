//! Configuration changes reach live connections.

#[path = "support_files.rs"]
mod support;

use std::time::Duration;

use smb_server::{Access, Share, SmbServer, ntstatus};
use support::common::{STATUS_SUCCESS, negotiate, tree_connect, user_session_setup};
use support::*;
use tempfile::tempdir;
use tokio::net::TcpStream;
use tokio::sync::Semaphore;

/// Signs in `user` with `password` on a new connection and connects `share`.
async fn user_client(server: &Server, user: &str, password: &str) -> Client {
    let mut s = TcpStream::connect(server.addr).await.unwrap();
    let _ = negotiate(&mut s).await;
    let (status, session_id, _, _) = user_session_setup(&mut s, user, password).await;
    assert_eq!(status, STATUS_SUCCESS);
    let tree_id = tree_connect(&mut s, "\\\\127.0.0.1\\share", session_id, 3).await;
    Client::from_parts(s, session_id, tree_id)
}

fn user_server(
    backend: impl smb_server::ShareBackend,
    access: Access,
) -> smb_server::SmbServerBuilder {
    SmbServer::builder()
        .user("alice", "password")
        .share(Share::new("share", backend).user("alice", access))
}

#[tokio::test]
async fn create_in_flight_does_not_land_in_a_removed_share() {
    let td = tempdir().unwrap();
    let (backend, counters) = Probe::new(
        td.path(),
        Counters {
            open_gate: Some(Semaphore::new(0)),
            ..Counters::default()
        },
    );
    let server = Server::public(backend).await;
    let mut c = server.client().await;
    let create = tokio::spawn(async move {
        let status = c
            .create(Create {
                name: "late.txt",
                access: RW | DELETE,
                disposition: FILE_CREATE,
                options: FILE_DELETE_ON_CLOSE,
                ..Create::default()
            })
            .await;
        (c, status)
    });
    // Let the CREATE reach the backend.
    tokio::time::sleep(Duration::from_millis(100)).await;

    server.config.remove_share("share").await.unwrap();
    counters.open_gate.as_ref().unwrap().add_permits(1);
    let (_c, status) = create.await.unwrap();
    assert_eq!(status.unwrap_err(), ntstatus::STATUS_NETWORK_NAME_DELETED);
    assert_eq!(Counters::get(&counters.closes), 1);
}

#[tokio::test]
async fn lowering_access_reaches_live_trees() {
    let td = tempdir().unwrap();
    let server = Server::start(user_server(local(td.path()), Access::ReadWrite)).await;
    let mut c = user_client(&server, "alice", "password").await;
    let f = c
        .create(Create {
            name: "w1.txt",
            disposition: FILE_CREATE,
            ..Create::default()
        })
        .await
        .unwrap()
        .file_id;
    c.close(f).await;

    server
        .config
        .grant_share_user("share", "alice", Access::Read)
        .await
        .unwrap();
    let status = c
        .create(Create {
            name: "w2.txt",
            disposition: FILE_CREATE,
            ..Create::default()
        })
        .await
        .unwrap_err();
    assert_eq!(status, ntstatus::STATUS_NETWORK_NAME_DELETED);
    assert!(!td.path().join("w2.txt").exists());

    // Raising access leaves the tree alone.
    let mut c = user_client(&server, "alice", "password").await;
    server
        .config
        .grant_share_user("share", "alice", Access::ReadWrite)
        .await
        .unwrap();
    assert!(c.open("w1.txt", FILE_READ_DATA, SHARE_ALL).await.is_ok());
}

#[tokio::test]
async fn new_password_ends_old_sessions() {
    let td = tempdir().unwrap();
    std::fs::write(td.path().join("f.txt"), b"x").unwrap();
    let server = Server::start(user_server(local(td.path()), Access::ReadWrite)).await;
    let mut c = user_client(&server, "alice", "password").await;

    server.config.add_user("alice", "password").await.unwrap();
    assert!(c.open("f.txt", FILE_READ_DATA, SHARE_ALL).await.is_ok());

    server.config.add_user("alice", "changed").await.unwrap();
    assert_eq!(
        c.open("f.txt", FILE_READ_DATA, SHARE_ALL).await,
        Err(ntstatus::STATUS_USER_SESSION_DELETED)
    );
}

#[tokio::test]
async fn stuck_read_does_not_keep_other_connections_alive() {
    let td = tempdir().unwrap();
    std::fs::write(td.path().join("f.txt"), b"data").unwrap();
    let (backend, counters) = Probe::new(
        td.path(),
        Counters {
            read_gate: Some(Semaphore::new(0)),
            ..Counters::default()
        },
    );
    let server = Server::start(user_server(backend, Access::ReadWrite)).await;
    // Connections are swept in no fixed order. With three stuck and seven
    // idle ones, a sweep that stops at the first stuck connection leaves an
    // idle one working in all but one order out of 120.
    let mut idle = Vec::new();
    for _ in 0..7 {
        idle.push(user_client(&server, "alice", "password").await);
    }
    let mut reads = Vec::new();
    for _ in 0..3 {
        let mut stuck = user_client(&server, "alice", "password").await;
        let f = stuck
            .open("f.txt", FILE_READ_DATA, SHARE_ALL)
            .await
            .unwrap();
        reads.push(tokio::spawn(async move {
            let r = stuck.read(f, 0, 4).await;
            (stuck, r)
        }));
    }
    tokio::time::sleep(Duration::from_millis(50)).await;

    let config = server.config.clone();
    let remove = tokio::spawn(async move { config.remove_user("alice").await });
    tokio::time::sleep(Duration::from_millis(200)).await;
    for c in &mut idle {
        assert_eq!(
            c.open("f.txt", FILE_READ_DATA, SHARE_ALL).await,
            Err(ntstatus::STATUS_USER_SESSION_DELETED),
            "a revoked user's idle connection kept working"
        );
    }

    counters
        .read_gate
        .as_ref()
        .unwrap()
        .add_permits(reads.len());
    for read in reads {
        let (_stuck, r) = read.await.unwrap();
        assert_eq!(r.unwrap(), b"data");
    }
    remove.await.unwrap().unwrap();
    assert!(eventually(|| Counters::get(&counters.closes) == Counters::get(&counters.opens)).await);
}
