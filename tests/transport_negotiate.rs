//! NEGOTIATE ordering and the SMB1 bootstrap.

#[allow(dead_code, reason = "only the session helpers are used here")]
mod common;
#[path = "support_transport.rs"]
mod support;

use smb_server::ntstatus::STATUS_INVALID_PARAMETER;
use smb_server::wire::header::{Command, SMB2_FLAGS_SIGNED};
use smb_server::wire::messages::{NegotiateRequest, NegotiateResponse};
use smb_server::{LocalFsBackend, Share, SmbServer};
use support::{
    ECHO_BODY, WAIT, assert_closed, connect, connect_negotiated, framed, header, message,
    negotiate_request, read_response, start,
};
use tokio::io::AsyncWriteExt;

/// A framed SMB1 NEGOTIATE offering `dialects`.
fn smb1_negotiate(dialects: &[&str]) -> Vec<u8> {
    let mut blob = Vec::new();
    for d in dialects {
        blob.push(0x02);
        blob.extend_from_slice(d.as_bytes());
        blob.push(0);
    }
    let mut msg = vec![0xFF, b'S', b'M', b'B', 0x72];
    msg.resize(32, 0);
    msg.push(0);
    msg.extend_from_slice(&(blob.len() as u16).to_le_bytes());
    msg.extend_from_slice(&blob);
    framed(&msg)
}

/// A framed SMB2 NEGOTIATE offering 2.0.2 and 2.1 with `message_id`.
fn negotiate_with_id(message_id: u64) -> Vec<u8> {
    let req = NegotiateRequest {
        structure_size: 36,
        dialect_count: 2,
        security_mode: 1,
        reserved: 0,
        capabilities: 0,
        client_guid: [0xCD; 16],
        negotiate_context_offset_or_client_start_time: 0,
        dialects: vec![0x0202, 0x0210],
    };
    let mut body = Vec::new();
    req.write_to(&mut body).expect("negotiate");
    framed(&message(
        &header(Command::Negotiate, message_id, 0, 0),
        &body,
    ))
}

#[tokio::test]
async fn a_second_negotiate_closes_the_connection() {
    let (addr, handle) = start(SmbServer::builder()).await;
    let mut s = connect_negotiated(addr).await;
    s.write_all(&negotiate_with_id(1)).await.expect("write");
    assert_closed(&mut s, WAIT).await;

    let mut s = connect_negotiated(addr).await;
    s.write_all(&smb1_negotiate(&["SMB 2.???"]))
        .await
        .expect("write");
    assert_closed(&mut s, WAIT).await;
    handle.abort();
}

#[tokio::test]
async fn requests_before_negotiate_close_the_connection() {
    let (addr, handle) = start(SmbServer::builder()).await;
    let mut s = connect(addr).await;
    let echo = message(&header(Command::Echo, 0, 0, 0), &ECHO_BODY);
    s.write_all(&framed(&echo)).await.expect("write");
    assert_closed(&mut s, WAIT).await;

    // After the SMB1 bootstrap only an SMB2 NEGOTIATE is accepted.
    let mut s = connect(addr).await;
    s.write_all(&smb1_negotiate(&["SMB 2.???"]))
        .await
        .expect("write");
    read_response(&mut s).await;
    let echo = message(&header(Command::Echo, 1, 0, 0), &ECHO_BODY);
    s.write_all(&framed(&echo)).await.expect("write");
    assert_closed(&mut s, WAIT).await;
    handle.abort();
}

#[tokio::test]
async fn smb1_wildcard_negotiate_grants_a_credit_and_leads_to_smb2_negotiate() {
    let (addr, handle) = start(SmbServer::builder()).await;
    let mut s = connect(addr).await;
    s.write_all(&smb1_negotiate(&["NT LM 0.12", "SMB 2.002", "SMB 2.???"]))
        .await
        .expect("write");
    let (hdr, frame) = read_response(&mut s).await;
    assert_eq!(hdr.command, Command::Negotiate);
    assert!(hdr.credit_request_response >= 1, "no credit granted");
    let resp = NegotiateResponse::parse(&frame[64..]).expect("negotiate response");
    assert_eq!(resp.dialect_revision, 0x02FF);

    s.write_all(&negotiate_with_id(1)).await.expect("write");
    let (hdr, frame) = read_response(&mut s).await;
    assert_eq!(hdr.channel_sequence_status, 0);
    let resp = NegotiateResponse::parse(&frame[64..]).expect("negotiate response");
    assert_eq!(resp.dialect_revision, 0x0210);
    handle.abort();
}

#[tokio::test]
async fn smb1_negotiate_for_2_0_2_alone_allows_logon() {
    let td = tempfile::tempdir().expect("tempdir");
    let backend = LocalFsBackend::new(td.path()).expect("backend");
    let (addr, handle) =
        start(SmbServer::builder().share(Share::new("share", backend).public())).await;
    let mut s = connect(addr).await;
    s.write_all(&smb1_negotiate(&["NT LM 0.12", "SMB 2.002"]))
        .await
        .expect("write");
    let (hdr, frame) = read_response(&mut s).await;
    assert!(hdr.credit_request_response >= 1, "no credit granted");
    let resp = NegotiateResponse::parse(&frame[64..]).expect("negotiate response");
    assert_eq!(resp.dialect_revision, 0x0202);

    let session_id = common::anonymous_session_setup(&mut s).await;
    assert_ne!(session_id, 0);
    handle.abort();
}

#[tokio::test]
async fn a_signed_negotiate_fails() {
    let (addr, handle) = start(SmbServer::builder()).await;
    let mut s = connect(addr).await;
    let mut frame = negotiate_request();
    frame[4 + 0x10] |= SMB2_FLAGS_SIGNED as u8;
    s.write_all(&frame).await.expect("write");
    let (hdr, _) = read_response(&mut s).await;
    assert_eq!(hdr.channel_sequence_status, STATUS_INVALID_PARAMETER);
    handle.abort();
}
