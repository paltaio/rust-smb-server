//! SMB 3.x encryption: cipher negotiation, encrypted sessions and shares,
//! clients that cannot encrypt, and encrypted messages that close the
//! connection.

#![cfg(feature = "localfs")]

mod common;

use std::net::SocketAddr;

use common::auth::*;
use common::client::{Create, FILE_OVERWRITE_IF, local, write_request};
use common::crypto::*;
use common::transport::{ECHO_BODY, compound, read_body};
use common::{
    anonymous_session_setup, build_header, framed, message, negotiate_body, read_frame,
    start_server, tree_connect_body,
};
use smb_server::ntstatus::{STATUS_ACCESS_DENIED, STATUS_SUCCESS};
use smb_server::wire::header::{Command, HeaderTail, SMB2_FLAGS_RELATED_OPERATIONS, Smb2Header};
use smb_server::wire::messages::{
    CloseRequest, FileId, NegotiateResponse, ReadResponse, SessionSetupResponse,
    TreeConnectResponse, WriteResponse,
};
use smb_server::{Share, SmbServer, SmbServerBuilder};
use tempfile::TempDir;
use tokio::io::AsyncWriteExt as _;
use tokio::net::TcpStream;

const USER: &str = "alice";
const PASSWORD: &str = "password";
const SHAREFLAG_ENCRYPT_DATA: u32 = 0x0000_8000;
const RELATED_FILE_ID: FileId = FileId::new(u64::MAX, u64::MAX);

/// Public shares `plain` and `secret` on `td`; `secret` is encrypted.
fn builder(td: &TempDir) -> SmbServerBuilder {
    SmbServer::builder()
        .user(USER, PASSWORD)
        .share(Share::new("plain", local(td.path())).public())
        .share(
            Share::new("secret", local(td.path()))
                .public()
                .encrypt_data(),
        )
}

async fn serve(builder: SmbServerBuilder) -> SocketAddr {
    start_server(builder).await.0
}

fn path(share: &str) -> String {
    format!(r"\\srv\{share}")
}

/// Connects and sends NEGOTIATE with `body`; returns the stream and the
/// successful response frame.
async fn negotiate_with(addr: SocketAddr, body: &[u8]) -> (TcpStream, Vec<u8>) {
    let mut s = TcpStream::connect(addr).await.expect("connect");
    let frame = request(&mut s, Command::Negotiate, 0, 0, 0, body).await;
    assert_eq!(status(&frame), STATUS_SUCCESS, "NEGOTIATE");
    (s, frame)
}

/// SMB 2.1 connection logged in as alice.
async fn smb21_login(addr: SocketAddr) -> (TcpStream, Login) {
    let (mut s, _) = negotiate_with(addr, &negotiate_body(&[0x0202, 0x0210], 0x0001, 0)).await;
    let login = spnego_login(&mut s, 1, 0, USER, PASSWORD).await;
    (s, login)
}

/// 3.1.1 session with AES-128-GCM and a tree on `plain`.
async fn session(addr: SocketAddr) -> EncryptedSession {
    let mut sess = EncryptedSession::smb311(addr, &[Cipher::Aes128Gcm], USER, PASSWORD).await;
    assert_eq!(
        status(&sess.tree_connect(&path("plain")).await),
        STATUS_SUCCESS
    );
    sess
}

fn session_flags(frame: &[u8]) -> u16 {
    SessionSetupResponse::parse(&frame[64..])
        .expect("session setup response")
        .session_flags
}

fn share_flags(frame: &[u8]) -> u32 {
    TreeConnectResponse::parse(&frame[64..])
        .expect("tree connect response")
        .share_flags
}

fn create_body(name: &str) -> Vec<u8> {
    Create {
        name,
        disposition: FILE_OVERWRITE_IF,
        ..Create::default()
    }
    .body()
}

fn close_body(file_id: FileId) -> Vec<u8> {
    let mut body = Vec::new();
    CloseRequest {
        structure_size: 24,
        flags: 0,
        reserved: 0,
        file_id,
    }
    .write_to(&mut body)
    .expect("close");
    body
}

/// Creates `name`, writes to it, reads it back and closes it, all encrypted.
async fn round_trip(sess: &mut EncryptedSession, name: &str) {
    let resp = sess
        .send_encrypted(Command::Create, &create_body(name))
        .await;
    let file_id = created_file_id(&resp);

    let data = format!("contents of {name}").into_bytes();
    let mut body = Vec::new();
    write_request(file_id, 0, &data)
        .write_to(&mut body)
        .expect("write");
    let resp = sess.send_encrypted(Command::Write, &body).await;
    assert_eq!(status(&resp), STATUS_SUCCESS, "WRITE");
    let count = WriteResponse::parse(&resp[64..])
        .expect("write response")
        .count;
    assert_eq!(count as usize, data.len());

    let resp = sess
        .send_encrypted(Command::Read, &read_body(file_id, 4096))
        .await;
    assert_eq!(status(&resp), STATUS_SUCCESS, "READ");
    assert_eq!(ReadResponse::parse(&resp[64..]).expect("read").data, data);

    let resp = sess
        .send_encrypted(Command::Close, &close_body(file_id))
        .await;
    assert_eq!(status(&resp), STATUS_SUCCESS, "CLOSE");
}

/// Sends `msg` signed with the SMB 3.x signing `key`; returns the response.
async fn send_signed(s: &mut TcpStream, mut msg: Vec<u8>, key: &[u8; 16]) -> Vec<u8> {
    cmac_sign(&mut msg, key);
    s.write_all(&framed(&msg)).await.expect("write");
    read_frame(s).await
}

/// Writes `payload` and asserts the server closes the connection without
/// replying.
async fn assert_dropped(sess: &mut EncryptedSession, payload: &[u8]) {
    sess.stream
        .write_all(&framed(payload))
        .await
        .expect("write");
    assert!(
        read_or_closed(&mut sess.stream).await.is_none(),
        "server replied"
    );
}

fn echo(sess: &mut EncryptedSession) -> Vec<u8> {
    let hdr = sess.header(Command::Echo);
    message(&hdr, &ECHO_BODY)
}

/// A related request: SessionId, TreeId and FileId come from the one before.
fn related(sess: &mut EncryptedSession, command: Command, body: &[u8]) -> Vec<u8> {
    let mut hdr = sess.header(command);
    hdr.flags |= SMB2_FLAGS_RELATED_OPERATIONS;
    hdr.session_id = u64::MAX;
    hdr.tail = HeaderTail::sync(u32::MAX);
    message(&hdr, body)
}

// --- Cipher negotiation -------------------------------------------------------

#[tokio::test]
async fn each_cipher_carries_an_encrypted_file_round_trip() {
    let td = tempfile::tempdir().unwrap();
    let addr = serve(builder(&td)).await;
    for cipher in Cipher::ALL {
        let mut sess = EncryptedSession::smb311(addr, &[cipher], USER, PASSWORD).await;
        assert_eq!(sess.cipher, cipher);
        let resp = sess.tree_connect(&path("plain")).await;
        assert_eq!(status(&resp), STATUS_SUCCESS, "{cipher:?}");
        round_trip(&mut sess, &format!("{cipher:?}.txt")).await;
    }
}

#[tokio::test]
async fn server_takes_the_first_offered_cipher_it_implements() {
    let td = tempfile::tempdir().unwrap();
    let addr = serve(builder(&td)).await;
    let cases: [(&[u16], Cipher); 3] = [
        (&[4, 1], Cipher::Aes256Gcm),
        (&[1, 4], Cipher::Aes128Ccm),
        (&[0x0009, 3, 2], Cipher::Aes256Ccm),
    ];
    for (ids, expected) in cases {
        let (_, frame) = negotiate_with(addr, &negotiate_311_cipher_ids_body(ids)).await;
        assert_eq!(negotiated_cipher(&frame), Some(expected), "{ids:?}");
    }
}

#[tokio::test]
async fn no_common_cipher_answers_cipher_zero_and_drops_encrypted_requests() {
    let td = tempfile::tempdir().unwrap();
    let addr = serve(builder(&td)).await;
    let mut s = TcpStream::connect(addr).await.expect("connect");
    let mut hash = [0u8; 64];
    let body = negotiate_311_cipher_ids_body(&[9, 0xFFFF]);
    let frame = hashed_negotiate(&mut s, &body, &mut hash).await;
    assert_eq!(status(&frame), STATUS_SUCCESS, "NEGOTIATE");
    let (_, data) = response_contexts(&frame)
        .into_iter()
        .find(|(t, _)| *t == CTX_ENCRYPTION)
        .expect("ENCRYPTION context");
    // CipherCount 1, Cipher 0.
    assert_eq!(data, [1, 0, 0, 0]);

    // Keys the session would have, had a cipher been agreed.
    let login = hashed_login(&mut s, 1, USER, PASSWORD, &mut hash).await;
    assert_eq!(login.status, STATUS_SUCCESS);
    let keys = keys_311(&login.key, Cipher::Aes128Gcm, &hash);
    let hdr = build_header(Command::Echo, 3, login.session_id, 0);
    let sealed = encrypt(
        Cipher::Aes128Gcm,
        &keys.encryption,
        login.session_id,
        &[1],
        &message(&hdr, &ECHO_BODY),
    );
    s.write_all(&framed(&sealed)).await.expect("write");
    assert!(read_or_closed(&mut s).await.is_none(), "server replied");
}

#[tokio::test]
async fn smb30_and_302_encrypt_when_the_client_has_the_capability() {
    let td = tempfile::tempdir().unwrap();
    let addr = serve(builder(&td)).await;
    for dialect in [0x0300, 0x0302] {
        let mut sess = EncryptedSession::smb30(addr, dialect, USER, PASSWORD).await;
        let neg = NegotiateResponse::parse(&sess.negotiate_frame[64..]).unwrap();
        assert_eq!(neg.dialect_revision, dialect);
        assert_ne!(neg.capabilities & CAP_ENCRYPTION, 0, "{dialect:#x}");
        let resp = sess.tree_connect(&path("plain")).await;
        assert_eq!(status(&resp), STATUS_SUCCESS, "{dialect:#x}");
        round_trip(&mut sess, &format!("{dialect:x}.txt")).await;
    }
}

#[tokio::test]
async fn smb30_without_the_capability_gets_no_encryption_capability() {
    let td = tempfile::tempdir().unwrap();
    let addr = serve(builder(&td)).await;
    for dialect in [0x0300, 0x0302] {
        let (_, frame) = negotiate_with(addr, &negotiate_body(&[dialect], 0x0001, 0)).await;
        let neg = NegotiateResponse::parse(&frame[64..]).unwrap();
        assert_eq!(neg.capabilities & CAP_ENCRYPTION, 0, "{dialect:#x}");
    }
}

// --- Encrypted sessions -------------------------------------------------------

#[tokio::test]
async fn encrypt_data_flags_the_session_and_denies_plain_requests() {
    let td = tempfile::tempdir().unwrap();
    let addr = serve(builder(&td).encrypt_data(true)).await;
    let mut sess = EncryptedSession::smb311(addr, &[Cipher::Aes128Gcm], USER, PASSWORD).await;
    assert_ne!(
        sess.session_flags() & SessionSetupResponse::FLAG_ENCRYPT_DATA,
        0
    );

    let frame = sess
        .send_plain(Command::TreeConnect, &tree_connect_body(&path("plain")))
        .await;
    let resp = sess.open(&frame).expect("encrypted TREE_CONNECT response");
    assert_eq!(status(&resp), STATUS_ACCESS_DENIED);

    assert_eq!(
        status(&sess.tree_connect(&path("plain")).await),
        STATUS_SUCCESS
    );
    let frame = sess
        .send_plain(Command::Create, &create_body("f.txt"))
        .await;
    let resp = sess.open(&frame).expect("encrypted CREATE response");
    assert_eq!(status(&resp), STATUS_ACCESS_DENIED);
}

#[tokio::test]
async fn encrypt_data_refuses_logons_that_cannot_encrypt() {
    let td = tempfile::tempdir().unwrap();
    let addr = serve(builder(&td).encrypt_data(true)).await;

    let (_, login) = smb21_login(addr).await;
    assert_eq!(login.status, STATUS_ACCESS_DENIED, "SMB 2.1");

    let body = negotiate_311_body(&[0x0311], &[preauth_context(&[PREAUTH_SHA512])]);
    let (mut s, _) = negotiate_with(addr, &body).await;
    let login = spnego_login(&mut s, 1, 0, USER, PASSWORD).await;
    assert_eq!(login.status, STATUS_ACCESS_DENIED, "3.1.1 without a cipher");
}

#[tokio::test]
async fn encrypt_data_serves_smb21_in_the_clear_without_reject_unencrypted_access() {
    let td = tempfile::tempdir().unwrap();
    let addr = serve(
        builder(&td)
            .encrypt_data(true)
            .reject_unencrypted_access(false),
    )
    .await;
    let (mut s, login) = smb21_login(addr).await;
    assert_eq!(login.status, STATUS_SUCCESS);
    assert_eq!(
        session_flags(&login.frame) & SessionSetupResponse::FLAG_ENCRYPT_DATA,
        0
    );
    let sid = login.session_id;
    let tc = request(
        &mut s,
        Command::TreeConnect,
        3,
        sid,
        0,
        &tree_connect_body(&path("plain")),
    )
    .await;
    assert_eq!(status(&tc), STATUS_SUCCESS);
    let tid = Smb2Header::parse(&tc).unwrap().0.tree_id().unwrap();
    let resp = request(&mut s, Command::Create, 4, sid, tid, &create_body("f.txt")).await;
    assert_eq!(status(&resp), STATUS_SUCCESS);
}

#[tokio::test]
async fn encrypt_data_serves_311_without_a_cipher_in_the_clear_without_reject_unencrypted_access() {
    let td = tempfile::tempdir().unwrap();
    let addr = serve(
        builder(&td)
            .encrypt_data(true)
            .reject_unencrypted_access(false),
    )
    .await;
    let mut s = TcpStream::connect(addr).await.expect("connect");
    let mut hash = [0u8; 64];
    let body = negotiate_311_body(&[0x0311], &[preauth_context(&[PREAUTH_SHA512])]);
    let frame = hashed_negotiate(&mut s, &body, &mut hash).await;
    assert_eq!(status(&frame), STATUS_SUCCESS);
    let login = hashed_login(&mut s, 1, USER, PASSWORD, &mut hash).await;
    assert_eq!(login.status, STATUS_SUCCESS);
    assert_eq!(
        session_flags(&login.frame) & SessionSetupResponse::FLAG_ENCRYPT_DATA,
        0
    );
    let sid = login.session_id;

    // A 3.1.1 TREE_CONNECT is signed.
    let key: [u8; 16] = kdf(&login.key, b"SMBSigningKey\0", &hash, 16)
        .try_into()
        .unwrap();
    let tc = message(
        &build_header(Command::TreeConnect, 3, sid, 0),
        &tree_connect_body(&path("plain")),
    );
    let tc = send_signed(&mut s, tc, &key).await;
    assert!(!is_transform(&tc));
    assert_eq!(status(&tc), STATUS_SUCCESS);
    let tid = Smb2Header::parse(&tc).unwrap().0.tree_id().unwrap();
    let resp = request(&mut s, Command::Create, 4, sid, tid, &create_body("f.txt")).await;
    assert_eq!(status(&resp), STATUS_SUCCESS);
}

// --- Encrypted shares ---------------------------------------------------------

#[tokio::test]
async fn encrypted_share_flags_its_tree_and_denies_plain_requests() {
    let td = tempfile::tempdir().unwrap();
    let addr = serve(builder(&td)).await;
    let mut sess = EncryptedSession::smb311(addr, &[Cipher::Aes128Gcm], USER, PASSWORD).await;
    assert_eq!(
        sess.session_flags() & SessionSetupResponse::FLAG_ENCRYPT_DATA,
        0
    );

    let resp = sess.tree_connect(&path("secret")).await;
    assert_eq!(status(&resp), STATUS_SUCCESS);
    assert_ne!(share_flags(&resp) & SHAREFLAG_ENCRYPT_DATA, 0);
    let secret = sess.tree_id;
    let resp = sess.tree_connect(&path("plain")).await;
    assert_eq!(status(&resp), STATUS_SUCCESS);
    assert_eq!(share_flags(&resp) & SHAREFLAG_ENCRYPT_DATA, 0);

    let frame = sess
        .send_plain(Command::Create, &create_body("p.txt"))
        .await;
    assert!(!is_transform(&frame));
    assert_eq!(status(&frame), STATUS_SUCCESS);

    sess.tree_id = secret;
    let frame = sess
        .send_plain(Command::Create, &create_body("s.txt"))
        .await;
    let resp = sess.open(&frame).expect("encrypted CREATE response");
    assert_eq!(status(&resp), STATUS_ACCESS_DENIED);
}

#[tokio::test]
async fn encrypted_share_refuses_sessions_that_cannot_encrypt() {
    let td = tempfile::tempdir().unwrap();
    let addr = serve(builder(&td)).await;
    let tc = tree_connect_body(&path("secret"));

    // Anonymous, on a connection that negotiated a cipher.
    let body = negotiate_311_encryption_body(&[Cipher::Aes128Gcm]);
    let (mut s, _) = negotiate_with(addr, &body).await;
    let sid = anonymous_session_setup(&mut s).await;
    let resp = request(&mut s, Command::TreeConnect, 3, sid, 0, &tc).await;
    assert_eq!(status(&resp), STATUS_ACCESS_DENIED, "anonymous");

    let (mut s, login) = smb21_login(addr).await;
    assert_eq!(login.status, STATUS_SUCCESS);
    let resp = request(&mut s, Command::TreeConnect, 3, login.session_id, 0, &tc).await;
    assert_eq!(status(&resp), STATUS_ACCESS_DENIED, "SMB 2.1");
}

#[tokio::test]
async fn encrypted_share_serves_smb21_in_the_clear_without_reject_unencrypted_access() {
    let td = tempfile::tempdir().unwrap();
    let addr = serve(builder(&td).reject_unencrypted_access(false)).await;
    let (mut s, login) = smb21_login(addr).await;
    assert_eq!(login.status, STATUS_SUCCESS);
    let sid = login.session_id;
    let tc = request(
        &mut s,
        Command::TreeConnect,
        3,
        sid,
        0,
        &tree_connect_body(&path("secret")),
    )
    .await;
    assert_eq!(status(&tc), STATUS_SUCCESS);
    assert_eq!(share_flags(&tc) & SHAREFLAG_ENCRYPT_DATA, 0);
    let tid = Smb2Header::parse(&tc).unwrap().0.tree_id().unwrap();
    let resp = request(&mut s, Command::Create, 4, sid, tid, &create_body("f.txt")).await;
    assert!(!is_transform(&resp));
    assert_eq!(status(&resp), STATUS_SUCCESS);
}

// --- Messages that close the connection -----------------------------------------

#[tokio::test]
async fn tampered_ciphertext_or_tag_closes_the_connection() {
    let td = tempfile::tempdir().unwrap();
    let addr = serve(builder(&td)).await;
    // First ciphertext byte, then first tag byte.
    for at in [TRANSFORM_HEADER_LEN, 4] {
        let mut sess = session(addr).await;
        let msg = echo(&mut sess);
        let mut sealed = sess.seal(&msg);
        sealed[at] ^= 0x01;
        assert_dropped(&mut sess, &sealed).await;
    }
}

#[tokio::test]
async fn unknown_transform_session_closes_the_connection() {
    let td = tempfile::tempdir().unwrap();
    let addr = serve(builder(&td)).await;
    let mut sess = session(addr).await;
    let unknown = sess.session_id + 1;
    let mut hdr = sess.header(Command::Echo);
    hdr.session_id = unknown;
    let sealed = encrypt(
        sess.cipher,
        &sess.keys.encryption,
        unknown,
        &[0x77],
        &message(&hdr, &ECHO_BODY),
    );
    assert_dropped(&mut sess, &sealed).await;
}

#[tokio::test]
async fn transform_and_header_session_mismatch_closes_the_connection() {
    let td = tempfile::tempdir().unwrap();
    let addr = serve(builder(&td)).await;
    let mut sess = session(addr).await;
    let mut hdr = sess.header(Command::Echo);
    hdr.session_id += 1;
    let sealed = sess.seal(&message(&hdr, &ECHO_BODY));
    assert_dropped(&mut sess, &sealed).await;
}

#[tokio::test]
async fn related_first_request_closes_the_connection() {
    let td = tempfile::tempdir().unwrap();
    let addr = serve(builder(&td)).await;
    let mut sess = session(addr).await;
    let mut hdr = sess.header(Command::Echo);
    hdr.flags |= SMB2_FLAGS_RELATED_OPERATIONS;
    let sealed = sess.seal(&message(&hdr, &ECHO_BODY));
    assert_dropped(&mut sess, &sealed).await;
}

#[tokio::test]
async fn transform_flags_other_than_encrypted_close_the_connection() {
    let td = tempfile::tempdir().unwrap();
    let addr = serve(builder(&td)).await;
    for flags in [0x0000, 0x0003] {
        let mut sess = session(addr).await;
        let msg = echo(&mut sess);
        let sealed = encrypt_with_flags(
            sess.cipher,
            &sess.keys.encryption,
            sess.session_id,
            &[0x55],
            flags,
            &msg,
        );
        assert_dropped(&mut sess, &sealed).await;
    }
}

#[tokio::test]
async fn header_only_or_truncated_message_closes_the_connection() {
    let td = tempfile::tempdir().unwrap();
    let addr = serve(builder(&td)).await;

    // A header with an empty, correctly sealed message.
    let mut sess = session(addr).await;
    let sealed = sess.seal(&[]);
    assert_eq!(sealed.len(), TRANSFORM_HEADER_LEN);
    assert_dropped(&mut sess, &sealed).await;

    // A header cut short.
    let mut sess = session(addr).await;
    let msg = echo(&mut sess);
    let sealed = sess.seal(&msg);
    assert_dropped(&mut sess, &sealed[..40]).await;
}

// --- Compounds and nonces -------------------------------------------------------

#[tokio::test]
async fn encrypted_compound_gets_one_encrypted_chained_reply() {
    let td = tempfile::tempdir().unwrap();
    std::fs::write(td.path().join("c.txt"), b"compound data").unwrap();
    let addr = serve(builder(&td)).await;
    let mut sess = session(addr).await;

    let hdr = sess.header(Command::Create);
    let create = Create {
        name: "c.txt",
        ..Create::default()
    }
    .body();
    let requests = [
        message(&hdr, &create),
        related(&mut sess, Command::Read, &read_body(RELATED_FILE_ID, 4096)),
        related(&mut sess, Command::Close, &close_body(RELATED_FILE_ID)),
    ];
    // Without the transport prefix.
    let chain = &compound(&requests)[4..];
    let sealed = sess.seal(chain);
    let frame = sess.exchange(&sealed).await;
    let plain = sess.open(&frame).expect("one encrypted reply");

    let mut seen = Vec::new();
    let mut at = 0;
    loop {
        let (hdr, _) = Smb2Header::parse(&plain[at..]).expect("response header");
        seen.push((hdr.command, hdr.channel_sequence_status));
        if hdr.command == Command::Read {
            let data = ReadResponse::parse(&plain[at + 64..]).expect("read").data;
            assert_eq!(data, b"compound data");
        }
        let next = hdr.next_command as usize;
        if next == 0 {
            break;
        }
        assert_eq!(next % 8, 0, "NextCommand alignment");
        at += next;
    }
    assert_eq!(
        seen,
        [
            (Command::Create, STATUS_SUCCESS),
            (Command::Read, STATUS_SUCCESS),
            (Command::Close, STATUS_SUCCESS),
        ]
    );
}

#[tokio::test]
async fn consecutive_responses_use_different_nonces() {
    let td = tempfile::tempdir().unwrap();
    let addr = serve(builder(&td)).await;
    let mut sess = session(addr).await;
    let mut nonces = vec![sess.last_frame[20..36].to_vec()];
    for _ in 0..3 {
        let resp = sess.send_encrypted(Command::Echo, &ECHO_BODY).await;
        assert_eq!(status(&resp), STATUS_SUCCESS);
        nonces.push(sess.last_frame[20..36].to_vec());
    }
    for pair in nonces.windows(2) {
        assert_ne!(pair[0], pair[1]);
    }
}
