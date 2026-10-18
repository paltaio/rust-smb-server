//! SPNEGO mechListMIC and mechanism selection in SESSION_SETUP.

#![cfg(feature = "localfs")]

#[allow(dead_code, reason = "this crate uses part of the shared helpers")]
mod common;
#[path = "support_auth.rs"]
mod support;

use common::{STATUS_MORE_PROCESSING_REQUIRED, negotiate, start_server};
use smb_server::wire::header::Command;
use smb_server::{Access, LocalFsBackend, Share, SmbServer};
use support::*;
use tokio::net::TcpStream;

const ACCEPT_COMPLETED: u8 = 0;
const ACCEPT_INCOMPLETE: u8 = 1;
const REQUEST_MIC: u8 = 3;

async fn server() -> (TcpStream, tokio::task::JoinHandle<()>, tempfile::TempDir) {
    let td = tempfile::tempdir().expect("tempdir");
    let backend = LocalFsBackend::new(td.path()).expect("open root");
    let (addr, handle) = start_server(
        SmbServer::builder()
            .user("alice", "password")
            .share(Share::new("home", backend).user("alice", Access::ReadWrite)),
    )
    .await;
    let mut s = TcpStream::connect(addr).await.expect("connect");
    negotiate(&mut s).await;
    (s, handle, td)
}

#[tokio::test]
async fn final_reply_carries_the_server_mech_list_mic() {
    let (mut s, handle, _td) = server().await;
    let login = spnego_login(&mut s, 1, 0, "alice", "password").await;
    assert_eq!(login.status, 0);
    assert_eq!(
        login.frame[48..64],
        smb2_signature(&login.frame, &login.key)
    );

    let resp = parse_neg_resp(&session_setup_token(&login.frame));
    assert_eq!(resp.state, Some(ACCEPT_COMPLETED));
    let mech_list = mech_type_list(&[OID_NTLMSSP]);
    let expected = ntlm_mac(&login.key, false, &mech_list);
    assert_eq!(resp.mic.as_deref(), Some(&expected[..]));
    handle.abort();
}

#[tokio::test]
async fn wrong_client_mech_list_mic_fails_the_logon() {
    let (mut s, handle, _td) = server().await;
    let negotiate_msg = ntlm_negotiate(CLIENT_FLAGS);
    let mech_list = mech_type_list(&[OID_NTLMSSP]);
    let body = session_setup_body(&spnego_init(&mech_list, Some(&negotiate_msg)), 0, 1, 0);
    let frame = request(&mut s, Command::SessionSetup, 1, 0, 0, &body).await;
    assert_eq!(status(&frame), STATUS_MORE_PROCESSING_REQUIRED);
    let sid = response_session_id(&frame);
    let challenge = parse_neg_resp(&session_setup_token(&frame)).token.unwrap();
    let (auth, key) = ntlm_authenticate(
        "alice",
        "password",
        &negotiate_msg,
        &challenge,
        AuthOptions::default(),
    );
    // A MIC over a different mechanism list.
    let mic = ntlm_mac(&key, true, &mech_type_list(&[OID_KRB5, OID_NTLMSSP]));
    let body = session_setup_body(&spnego_resp(Some(&auth), Some(&mic)), 0, 1, 0);
    let frame = request(&mut s, Command::SessionSetup, 2, sid, 0, &body).await;
    assert_eq!(status(&frame), STATUS_LOGON_FAILURE);
    handle.abort();
}

/// NTLM listed after Kerberos: the server selects NTLM, asks for the MIC
/// exchange and ignores the Kerberos token.
#[tokio::test]
async fn ntlm_after_kerberos_gets_a_counter_proposal() {
    for send_client_mic in [true, false] {
        let (mut s, handle, _td) = server().await;
        let mech_list = mech_type_list(&[OID_KRB5, OID_NTLMSSP]);
        let body = session_setup_body(&spnego_init(&mech_list, Some(b"krb5 ap-req")), 0, 1, 0);
        let frame = request(&mut s, Command::SessionSetup, 1, 0, 0, &body).await;
        assert_eq!(status(&frame), STATUS_MORE_PROCESSING_REQUIRED);
        let sid = response_session_id(&frame);
        let resp = parse_neg_resp(&session_setup_token(&frame));
        assert_eq!(resp.state, Some(REQUEST_MIC));
        assert_eq!(resp.mech.as_deref(), Some(OID_NTLMSSP));
        assert!(resp.token.is_none());

        let negotiate_msg = ntlm_negotiate(CLIENT_FLAGS);
        let body = session_setup_body(&spnego_resp(Some(&negotiate_msg), None), 0, 1, 0);
        let frame = request(&mut s, Command::SessionSetup, 2, sid, 0, &body).await;
        assert_eq!(status(&frame), STATUS_MORE_PROCESSING_REQUIRED);
        assert_eq!(response_session_id(&frame), sid);
        let resp = parse_neg_resp(&session_setup_token(&frame));
        assert_eq!(resp.state, Some(ACCEPT_INCOMPLETE));
        let challenge = resp.token.expect("challenge");

        let (auth, key) = ntlm_authenticate(
            "alice",
            "password",
            &negotiate_msg,
            &challenge,
            AuthOptions::default(),
        );
        let mic = ntlm_mac(&key, true, &mech_list);
        let mic = send_client_mic.then_some(&mic[..]);
        let body = session_setup_body(&spnego_resp(Some(&auth), mic), 0, 1, 0);
        let frame = request(&mut s, Command::SessionSetup, 3, sid, 0, &body).await;
        if send_client_mic {
            assert_eq!(status(&frame), 0);
            let resp = parse_neg_resp(&session_setup_token(&frame));
            let expected = ntlm_mac(&key, false, &mech_list);
            assert_eq!(resp.mic.as_deref(), Some(&expected[..]));
        } else {
            assert_eq!(status(&frame), STATUS_LOGON_FAILURE, "MIC is required");
        }
        handle.abort();
    }
}

#[tokio::test]
async fn negtokeninit_without_a_mech_token_selects_ntlm() {
    let (mut s, handle, _td) = server().await;
    let mech_list = mech_type_list(&[OID_NTLMSSP]);
    let body = session_setup_body(&spnego_init(&mech_list, None), 0, 1, 0);
    let frame = request(&mut s, Command::SessionSetup, 1, 0, 0, &body).await;
    assert_eq!(status(&frame), STATUS_MORE_PROCESSING_REQUIRED);
    let sid = response_session_id(&frame);
    let resp = parse_neg_resp(&session_setup_token(&frame));
    assert_eq!(resp.state, Some(ACCEPT_INCOMPLETE));
    assert_eq!(resp.mech.as_deref(), Some(OID_NTLMSSP));
    assert!(resp.token.is_none());

    let negotiate_msg = ntlm_negotiate(CLIENT_FLAGS);
    let body = session_setup_body(&spnego_resp(Some(&negotiate_msg), None), 0, 1, 0);
    let frame = request(&mut s, Command::SessionSetup, 2, sid, 0, &body).await;
    assert_eq!(status(&frame), STATUS_MORE_PROCESSING_REQUIRED);
    let challenge = parse_neg_resp(&session_setup_token(&frame)).token.unwrap();
    let (auth, key) = ntlm_authenticate(
        "alice",
        "password",
        &negotiate_msg,
        &challenge,
        AuthOptions {
            mic: false,
            ..AuthOptions::default()
        },
    );
    let body = session_setup_body(&spnego_resp(Some(&auth), None), 0, 1, 0);
    let frame = request(&mut s, Command::SessionSetup, 3, sid, 0, &body).await;
    assert_eq!(status(&frame), 0);
    assert_eq!(frame[48..64], smb2_signature(&frame, &key));
    // No MIC was offered or asked for, so none is sent.
    assert!(parse_neg_resp(&session_setup_token(&frame)).mic.is_none());
    handle.abort();
}

/// MsvAvFlags announces a MIC; the client strips the MIC field.
#[tokio::test]
async fn stripped_ntlm_mic_fails_the_logon() {
    let (mut s, handle, _td) = server().await;
    let negotiate_msg = ntlm_negotiate(CLIENT_FLAGS);
    let mech_list = mech_type_list(&[OID_NTLMSSP]);
    let body = session_setup_body(&spnego_init(&mech_list, Some(&negotiate_msg)), 0, 1, 0);
    let frame = request(&mut s, Command::SessionSetup, 1, 0, 0, &body).await;
    let sid = response_session_id(&frame);
    let challenge = parse_neg_resp(&session_setup_token(&frame)).token.unwrap();
    let (auth, _) = ntlm_authenticate(
        "alice",
        "password",
        &negotiate_msg,
        &challenge,
        AuthOptions::default(),
    );
    // Drop the 16 MIC bytes and move every payload offset back.
    let mut stripped = auth[..72].to_vec();
    stripped.extend_from_slice(&auth[88..]);
    for field in 0..6 {
        let at = 12 + field * 8 + 4;
        let off = u32::from_le_bytes(stripped[at..at + 4].try_into().unwrap()) - 16;
        stripped[at..at + 4].copy_from_slice(&off.to_le_bytes());
    }
    let body = session_setup_body(&spnego_resp(Some(&stripped), None), 0, 1, 0);
    let frame = request(&mut s, Command::SessionSetup, 2, sid, 0, &body).await;
    assert_eq!(status(&frame), STATUS_LOGON_FAILURE);
    handle.abort();
}
