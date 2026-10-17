//! MessageId window, credit grants and CreditCharge.

#[allow(dead_code, reason = "only the session helpers are used here")]
mod common;
#[path = "support_transport.rs"]
mod support;

use smb_server::ntstatus::STATUS_INVALID_PARAMETER;
use smb_server::wire::header::Command;
use smb_server::{LocalFsBackend, Share, SmbServer};
use support::{
    ECHO_BODY, WAIT, assert_closed, connect, connect_negotiated, framed, header, message,
    open_file, read_body, read_response, start,
};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

/// Sends an ECHO and returns the credits granted in its response.
async fn echo(s: &mut TcpStream, message_id: u64, credit_request: u16) -> u16 {
    let mut hdr = header(Command::Echo, message_id, 0, 0);
    hdr.credit_request_response = credit_request;
    s.write_all(&framed(&message(&hdr, &ECHO_BODY)))
        .await
        .expect("write");
    let (hdr, _) = read_response(s).await;
    assert_eq!(hdr.channel_sequence_status, 0, "ECHO {message_id}");
    hdr.credit_request_response
}

#[tokio::test]
async fn message_ids_are_accepted_once_in_any_order() {
    let (addr, handle) = start(SmbServer::builder()).await;
    let mut s = connect_negotiated(addr).await;
    for message_id in [3, 1, 2] {
        echo(&mut s, message_id, 1).await;
    }
    let replay = message(&header(Command::Echo, 2, 0, 0), &ECHO_BODY);
    s.write_all(&framed(&replay)).await.expect("write");
    assert_closed(&mut s, WAIT).await;
    handle.abort();
}

#[tokio::test]
async fn message_ids_outside_the_window_close_the_connection() {
    let (addr, handle) = start(SmbServer::builder()).await;
    for message_id in [0, 1000, u64::MAX] {
        let mut s = connect_negotiated(addr).await;
        let request = message(&header(Command::Echo, message_id, 0, 0), &ECHO_BODY);
        s.write_all(&framed(&request)).await.expect("write");
        assert_closed(&mut s, WAIT).await;
    }
    handle.abort();
}

#[tokio::test]
async fn grants_stay_between_one_and_the_server_maximum() {
    let (addr, handle) = start(SmbServer::builder()).await;
    let mut s = connect(addr).await;
    let mut hdr = header(Command::Negotiate, 0, 0, 0);
    hdr.credit_request_response = 0;
    let mut negotiate = support::negotiate_request();
    negotiate[4..68].copy_from_slice(&message(&hdr, &[])[..64]);
    s.write_all(&negotiate).await.expect("write");
    let (hdr, _) = read_response(&mut s).await;
    assert_eq!(hdr.credit_request_response, 1, "NEGOTIATE grant");

    // Holding no other credit, a request for none still gets one.
    assert_eq!(echo(&mut s, 1, 0).await, 1);
    let granted = echo(&mut s, 2, u16::MAX).await;
    assert!((1..=512).contains(&granted), "granted {granted}");
    handle.abort();
}

#[tokio::test]
async fn credit_charge_must_cover_the_payload() {
    const MIB: u32 = 1024 * 1024;
    let td = tempfile::tempdir().expect("tempdir");
    std::fs::write(td.path().join("f.txt"), vec![0x5A; MIB as usize]).expect("file");
    let backend = LocalFsBackend::new(td.path()).expect("backend");
    let builder = SmbServer::builder().share(Share::new("share", backend).public());
    let (addr, handle) = start(builder).await;

    let mut s = connect(addr).await;
    common::negotiate(&mut s).await;
    let session_id = common::anonymous_session_setup(&mut s).await;
    let tree_id = common::tree_connect(&mut s, "\\\\server\\share", session_id, 3).await;
    let file_id = open_file(&mut s, 4, session_id, tree_id, "f.txt").await;

    let mut message_id = 5;
    for (charge, status) in [
        (0, STATUS_INVALID_PARAMETER),
        (1, STATUS_INVALID_PARAMETER),
        (15, STATUS_INVALID_PARAMETER),
        (16, 0),
    ] {
        let mut hdr = header(Command::Read, message_id, session_id, tree_id);
        hdr.credit_charge = charge;
        message_id += u64::from(charge.max(1));
        s.write_all(&framed(&message(&hdr, &read_body(file_id, MIB))))
            .await
            .expect("write");
        let (hdr, _) = read_response(&mut s).await;
        assert_eq!(hdr.channel_sequence_status, status, "CreditCharge {charge}");
    }

    // A charge of 0 still covers up to 64 KiB.
    let mut hdr = header(Command::Read, message_id, session_id, tree_id);
    hdr.credit_charge = 0;
    s.write_all(&framed(&message(&hdr, &read_body(file_id, 65536))))
        .await
        .expect("write");
    let (hdr, _) = read_response(&mut s).await;
    assert_eq!(hdr.channel_sequence_status, 0);
    handle.abort();
}
