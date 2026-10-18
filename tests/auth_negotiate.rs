//! NEGOTIATE request checks and response fields.

#![cfg(feature = "localfs")]

mod common;

use common::auth::*;
use common::{negotiate_body, start_server};
use smb_server::ntstatus::{
    STATUS_INVALID_PARAMETER, STATUS_NOT_SUPPORTED, STATUS_SMB_NO_PREAUTH_INTEGRITY_HASH_OVERLAP,
};
use smb_server::wire::header::Command;
use smb_server::wire::messages::NegotiateResponse;
use smb_server::{LocalFsBackend, Share, SmbServer};
use tokio::net::TcpStream;

const SHA512: u16 = 0x0001;
const AES_CMAC: u16 = 0x0001;
const AES_GMAC: u16 = 0x0002;

async fn connect() -> (TcpStream, tokio::task::JoinHandle<()>, tempfile::TempDir) {
    let td = tempfile::tempdir().expect("tempdir");
    let backend = LocalFsBackend::new(td.path()).expect("open root");
    let (addr, handle) =
        start_server(SmbServer::builder().share(Share::new("pub", backend).public())).await;
    let s = TcpStream::connect(addr).await.expect("connect");
    (s, handle, td)
}

async fn negotiate_frame(body: &[u8]) -> Vec<u8> {
    let (mut s, handle, _td) = connect().await;
    let frame = request(&mut s, Command::Negotiate, 0, 0, 0, body).await;
    handle.abort();
    frame
}

fn parse(frame: &[u8]) -> NegotiateResponse {
    NegotiateResponse::parse(&frame[64..]).expect("negotiate response")
}

#[tokio::test]
async fn dialect_count_zero_is_an_invalid_parameter() {
    let frame = negotiate_frame(&negotiate_body(&[], 1, 0)).await;
    assert_eq!(status(&frame), STATUS_INVALID_PARAMETER);
    let frame = negotiate_frame(&negotiate_body(&[0x0101], 1, 0)).await;
    assert_eq!(status(&frame), STATUS_NOT_SUPPORTED, "no common dialect");
}

#[tokio::test]
async fn large_mtu_is_offered_only_with_multi_credit_dialects() {
    let frame = negotiate_frame(&negotiate_body(&[0x0202], 1, 0)).await;
    assert_eq!(status(&frame), 0);
    assert_eq!(parse(&frame).capabilities, 0);
    let frame = negotiate_frame(&negotiate_body(&[0x0202, 0x0210], 1, 0)).await;
    assert_eq!(parse(&frame).capabilities, 0x0000_0004);
}

#[tokio::test]
async fn server_start_time_is_zero() {
    let frame = negotiate_frame(&negotiate_body(&[0x0210, 0x0300], 1, 0)).await;
    assert_eq!(parse(&frame).server_start_time, 0);
}

#[tokio::test]
async fn smb311_contexts_are_checked() {
    let preauth = preauth_context(&[SHA512]);
    let signing = id_list_context(CTX_SIGNING, &[AES_CMAC]);
    for (contexts, expected) in [
        (vec![], STATUS_INVALID_PARAMETER),
        (
            vec![preauth.clone(), preauth.clone()],
            STATUS_INVALID_PARAMETER,
        ),
        (
            vec![preauth_context(&[0x0002])],
            STATUS_SMB_NO_PREAUTH_INTEGRITY_HASH_OVERLAP,
        ),
        (vec![(CTX_PREAUTH, vec![1, 0])], STATUS_INVALID_PARAMETER),
        (
            vec![preauth.clone(), signing.clone(), signing.clone()],
            STATUS_INVALID_PARAMETER,
        ),
        (
            vec![
                preauth.clone(),
                id_list_context(CTX_ENCRYPTION, &[1]),
                id_list_context(CTX_ENCRYPTION, &[2]),
            ],
            STATUS_INVALID_PARAMETER,
        ),
        (
            vec![preauth.clone(), id_list_context(CTX_SIGNING, &[])],
            STATUS_INVALID_PARAMETER,
        ),
    ] {
        let frame = negotiate_frame(&negotiate_311_body(&[0x0311], &contexts)).await;
        assert_eq!(status(&frame), expected, "contexts {contexts:?}");
    }
}

#[tokio::test]
async fn signing_context_is_answered_only_when_sent() {
    let preauth = preauth_context(&[0x0002, SHA512]);
    let frame = negotiate_frame(&negotiate_311_body(
        &[0x0311],
        std::slice::from_ref(&preauth),
    ))
    .await;
    assert_eq!(status(&frame), 0);
    assert_eq!(parse(&frame).dialect_revision, 0x0311);
    let contexts = response_contexts(&frame);
    assert_eq!(contexts.len(), 1);
    assert_eq!(contexts[0].0, CTX_PREAUTH);

    let signing = id_list_context(CTX_SIGNING, &[AES_GMAC, AES_CMAC]);
    let frame = negotiate_frame(&negotiate_311_body(&[0x0311], &[preauth, signing])).await;
    assert_eq!(status(&frame), 0);
    let contexts = response_contexts(&frame);
    assert_eq!(contexts.len(), 2);
    assert_eq!(contexts[1], id_list_context(CTX_SIGNING, &[AES_CMAC]));
}
