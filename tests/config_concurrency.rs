//! Configuration changes running alongside SESSION_SETUP and TREE_CONNECT.

#![cfg(feature = "localfs")]

mod common;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use common::auth::{Login, spnego_login};
use common::{
    build_header, negotiate, parse_response_header, read_frame, tree_connect_body, write_frame,
};
use smb_server::ntstatus::STATUS_SUCCESS;
use smb_server::wire::header::Command;
use smb_server::{Access, ConfigHandle, LocalFsBackend, Share, SmbServer, ntstatus};
use tokio::net::TcpStream;

/// Signs in alice and connects the share until `stop` is set, with a new
/// session on the same connection whenever the session ends. Returns the
/// number of sessions and trees established.
async fn connect_until(addr: SocketAddr, stop: Arc<AtomicBool>) -> (usize, usize) {
    let (mut sessions, mut trees) = (0, 0);
    let mut s = TcpStream::connect(addr).await.expect("connect");
    negotiate(&mut s).await;
    let mut message_id = 1;
    while !stop.load(Ordering::Relaxed) {
        let Login {
            status,
            session_id,
            frame,
            ..
        } = spnego_login(&mut s, message_id, 0, "alice", "password").await;
        message_id = parse_response_header(&frame).0.message_id + 1;
        if status != STATUS_SUCCESS {
            assert_eq!(status, ntstatus::STATUS_LOGON_FAILURE);
            continue;
        }
        sessions += 1;
        let mut ended = false;
        for _ in 0..20 {
            let hdr = build_header(Command::TreeConnect, message_id, session_id, 0);
            message_id += 1;
            write_frame(&mut s, &hdr, &tree_connect_body(r"\\127.0.0.1\share")).await;
            let frame = read_frame(&mut s).await;
            match parse_response_header(&frame).0.channel_sequence_status {
                STATUS_SUCCESS => trees += 1,
                ntstatus::STATUS_ACCESS_DENIED | ntstatus::STATUS_BAD_NETWORK_NAME => {}
                ntstatus::STATUS_USER_SESSION_DELETED => {
                    ended = true;
                    break;
                }
                other => panic!("TREE_CONNECT status {other:#x}"),
            }
        }
        // A session still in place makes room for the next one.
        if !ended {
            let hdr = build_header(Command::Logoff, message_id, session_id, 0);
            message_id += 1;
            write_frame(&mut s, &hdr, &[4, 0, 0, 0]).await;
            read_frame(&mut s).await;
        }
    }
    (sessions, trees)
}

/// Lowers and restores alice's access to the share until `end`; each
/// lowering ends her trees on it. Steps that race with the share or user
/// being replaced may fail.
async fn sweep_trees(config: &ConfigHandle, end: Instant) {
    while Instant::now() < end {
        let _ = config
            .grant_share_user("share", "alice", Access::Read)
            .await;
        let _ = config
            .grant_share_user("share", "alice", Access::ReadWrite)
            .await;
        let _ = config.revoke_share_user("share", "alice").await;
        let _ = config
            .grant_share_user("share", "alice", Access::ReadWrite)
            .await;
        tokio::task::yield_now().await;
    }
}

/// Changes alice's password, replaces the share and replaces alice until
/// `end`, ending her sessions and trees each time.
async fn sweep_sessions(config: &ConfigHandle, root: PathBuf, end: Instant) {
    while Instant::now() < end {
        config.add_user("alice", "changed").await.unwrap();
        config.add_user("alice", "password").await.unwrap();
        config.remove_share("share").await.unwrap();
        let backend = LocalFsBackend::new(&root).unwrap();
        config
            .add_share(Share::new("share", backend).user("alice", Access::ReadWrite))
            .await
            .unwrap();
        config.remove_user("alice").await.unwrap();
        config.add_user("alice", "password").await.unwrap();
        config
            .grant_share_user("share", "alice", Access::ReadWrite)
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn revocation_runs_alongside_logons_and_tree_connects() {
    let td = tempfile::tempdir().unwrap();
    let server = SmbServer::builder()
        .listen("127.0.0.1:0".parse().unwrap())
        .user("alice", "password")
        .share(
            Share::new("share", LocalFsBackend::new(td.path()).unwrap())
                .user("alice", Access::ReadWrite),
        )
        .logon_throttle(0, Duration::from_secs(1))
        .build()
        .unwrap();
    let config = server.config_handle();
    let addr = server.bind().await.unwrap();
    let serve = tokio::spawn(async move {
        let _ = server.serve().await;
    });

    let stop = Arc::new(AtomicBool::new(false));
    let clients: Vec<_> = (0..16)
        .map(|_| tokio::spawn(connect_until(addr, Arc::clone(&stop))))
        .collect();
    let run = async {
        let end = Instant::now() + Duration::from_secs(3);
        tokio::join!(
            sweep_trees(&config, end),
            sweep_sessions(&config, td.path().to_path_buf(), end)
        );
        stop.store(true, Ordering::Relaxed);
        let (mut sessions, mut trees) = (0, 0);
        for client in clients {
            let (s, t) = client.await.unwrap();
            sessions += s;
            trees += t;
        }
        (sessions, trees)
    };
    let (sessions, trees) = tokio::time::timeout(Duration::from_secs(60), run)
        .await
        .expect("configuration changes and logons finish");
    assert!(
        sessions > 0 && trees > 0,
        "{sessions} sessions, {trees} trees"
    );

    // New trees follow the configuration the changes left behind.
    config.revoke_share_user("share", "alice").await.unwrap();
    let mut s = TcpStream::connect(addr).await.unwrap();
    negotiate(&mut s).await;
    let Login {
        status, session_id, ..
    } = spnego_login(&mut s, 1, 0, "alice", "password").await;
    assert_eq!(status, STATUS_SUCCESS);
    let hdr = build_header(Command::TreeConnect, 3, session_id, 0);
    write_frame(&mut s, &hdr, &tree_connect_body(r"\\127.0.0.1\share")).await;
    let frame = read_frame(&mut s).await;
    assert_eq!(
        parse_response_header(&frame).0.channel_sequence_status,
        ntstatus::STATUS_ACCESS_DENIED
    );
    serve.abort();
}
