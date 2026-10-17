//! Graceful shutdown.

#[path = "support_transport.rs"]
mod support;

use std::time::Duration;

use smb_server::SmbServer;
use smb_server::wire::header::Command;
use support::{
    WAIT, assert_closed, connect_in_session_setup, connect_negotiated, echo, read_response,
    start_with_shutdown,
};
use tokio::io::AsyncWriteExt;

#[tokio::test]
async fn shutdown_before_serve_stops_the_server() {
    let server = SmbServer::builder()
        .listen("127.0.0.1:0".parse().unwrap())
        .build()
        .expect("build");
    server.bind().await.expect("bind");
    server.shutdown_handle().shutdown();
    let serve = tokio::spawn(server.serve());
    tokio::time::timeout(Duration::from_secs(2), serve)
        .await
        .expect("serve returns")
        .expect("join")
        .expect("serve");
}

#[tokio::test]
async fn serve_returns_after_idle_connections_close() {
    let (addr, shutdown, serve) = start_with_shutdown(SmbServer::builder()).await;
    let mut first = connect_negotiated(addr).await;
    let mut second = connect_negotiated(addr).await;

    shutdown.shutdown();
    tokio::time::timeout(Duration::from_secs(2), serve)
        .await
        .expect("serve returns")
        .expect("join");
    assert_closed(&mut first, Duration::from_millis(100)).await;
    assert_closed(&mut second, Duration::from_millis(100)).await;
}

#[tokio::test]
async fn a_request_arriving_during_shutdown_is_answered() {
    let (addr, shutdown, serve) = start_with_shutdown(SmbServer::builder()).await;
    let mut s = connect_in_session_setup(addr).await;

    let request = echo(2);
    s.write_all(&request[..10]).await.expect("write");
    tokio::time::sleep(Duration::from_millis(100)).await;
    shutdown.shutdown();
    tokio::time::sleep(Duration::from_millis(100)).await;
    s.write_all(&request[10..]).await.expect("write");

    let (hdr, _) = read_response(&mut s).await;
    assert_eq!(hdr.command, Command::Echo);
    assert_closed(&mut s, WAIT).await;
    tokio::time::timeout(WAIT, serve)
        .await
        .expect("serve returns")
        .expect("join");
}
