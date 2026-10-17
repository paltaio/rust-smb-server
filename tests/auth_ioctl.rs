//! IOCTL checks and FSCTL_VALIDATE_NEGOTIATE_INFO.

#![cfg(feature = "localfs")]

#[allow(dead_code, reason = "this crate uses part of the shared helpers")]
mod common;
#[path = "support_auth.rs"]
mod support;

use common::{anonymous_session_setup, start_server, tree_connect};
use smb_server::wire::header::Command;
use smb_server::wire::messages::{FileId, Fsctl, IoctlRequest, IoctlResponse, NegotiateResponse};
use smb_server::{LocalFsBackend, Share, SmbServer};
use support::*;
use tokio::net::TcpStream;

const FSCTL_SRV_ENUMERATE_SNAPSHOTS: u32 = 0x0014_4064;
const FSCTL_GET_COMPRESSION: u32 = 0x0009_003C;
const IS_FSCTL: u32 = IoctlRequest::FLAG_IS_FSCTL;
const CLIENT_GUID: [u8; 16] = [0xCD; 16];
const DIALECTS: [u16; 3] = [0x0210, 0x0300, 0x0302];

struct Conn {
    s: TcpStream,
    sid: u64,
    tid: u32,
    neg: NegotiateResponse,
    _handle: tokio::task::JoinHandle<()>,
    _td: tempfile::TempDir,
}

/// SMB 3.0.2 connection with an anonymous session on share `pub`.
async fn connect() -> Conn {
    let td = tempfile::tempdir().expect("tempdir");
    std::fs::write(td.path().join("f.txt"), b"x").unwrap();
    let backend = LocalFsBackend::new(td.path()).expect("open root");
    let (addr, handle) =
        start_server(SmbServer::builder().share(Share::new("pub", backend).public())).await;
    let mut s = TcpStream::connect(addr).await.expect("connect");
    let frame = request(
        &mut s,
        Command::Negotiate,
        0,
        0,
        0,
        &negotiate_body(&DIALECTS, 0x0001, 0x44),
    )
    .await;
    assert_eq!(status(&frame), 0);
    let neg = NegotiateResponse::parse(&frame[64..]).unwrap();
    assert_eq!(neg.dialect_revision, 0x0302);
    let sid = anonymous_session_setup(&mut s).await;
    let tid = tree_connect(&mut s, r"\\srv\pub", sid, 3).await;
    Conn {
        s,
        sid,
        tid,
        neg,
        _handle: handle,
        _td: td,
    }
}

impl Conn {
    async fn ioctl(&mut self, mid: u64, body: &[u8]) -> Vec<u8> {
        request(&mut self.s, Command::Ioctl, mid, self.sid, self.tid, body).await
    }

    /// Sends a VALIDATE_NEGOTIATE_INFO and returns the reply, or `None` when
    /// the server closes the connection instead.
    async fn validate(&mut self, input: &[u8], max_output: u32) -> Option<Vec<u8>> {
        let body = ioctl_body(
            Fsctl::VALIDATE_NEGOTIATE_INFO,
            FileId::any(),
            input,
            max_output,
            IS_FSCTL,
        );
        let hdr = common::build_header(Command::Ioctl, 10, self.sid, self.tid);
        let mut msg = Vec::new();
        hdr.write(&mut msg).unwrap();
        msg.extend_from_slice(&body);
        let mut framed = Vec::new();
        common::encode_frame(&msg, &mut framed);
        tokio::io::AsyncWriteExt::write_all(&mut self.s, &framed)
            .await
            .unwrap();
        read_or_closed(&mut self.s).await
    }
}

fn good_input() -> Vec<u8> {
    validate_negotiate_input(0x44, CLIENT_GUID, 0x0001, &DIALECTS)
}

#[tokio::test]
async fn validate_negotiate_info_answers_a_matching_request() {
    let mut c = connect().await;
    let frame = c.validate(&good_input(), 24).await.expect("reply");
    assert_eq!(status(&frame), 0);
    let resp = IoctlResponse::parse(&frame[64..]).unwrap();
    assert_eq!(resp.file_id, FileId::any());
    let mut expected = c.neg.capabilities.to_le_bytes().to_vec();
    expected.extend_from_slice(&c.neg.server_guid);
    expected.extend_from_slice(&c.neg.security_mode.to_le_bytes());
    expected.extend_from_slice(&0x0302u16.to_le_bytes());
    assert_eq!(resp.output, expected);
}

#[tokio::test]
async fn validate_negotiate_info_mismatch_is_refused() {
    let other_guid = [0xEE; 16];
    for (input, max_output) in [
        (
            validate_negotiate_input(0x7F, CLIENT_GUID, 0x0001, &DIALECTS),
            24,
        ),
        (
            validate_negotiate_input(0x44, other_guid, 0x0001, &DIALECTS),
            24,
        ),
        (
            validate_negotiate_input(0x44, CLIENT_GUID, 0x0003, &DIALECTS),
            24,
        ),
        (
            validate_negotiate_input(0x44, CLIENT_GUID, 0x0001, &[0x0210, 0x0300]),
            24,
        ),
        (good_input(), 8),
    ] {
        let mut c = connect().await;
        let reply = c.validate(&input, max_output).await;
        assert!(
            reply.is_none_or(|f| status(&f) != 0),
            "validated {input:02x?} / {max_output}"
        );
    }
}

#[tokio::test]
async fn validate_negotiate_info_is_refused_on_smb311() {
    let td = tempfile::tempdir().expect("tempdir");
    let backend = LocalFsBackend::new(td.path()).expect("open root");
    let (addr, _handle) =
        start_server(SmbServer::builder().share(Share::new("pub", backend).public())).await;
    let mut s = TcpStream::connect(addr).await.expect("connect");
    let body = negotiate_311_body(&[0x0311], &[preauth_context(&[1])]);
    let frame = request(&mut s, Command::Negotiate, 0, 0, 0, &body).await;
    assert_eq!(status(&frame), 0);
    let sid = anonymous_session_setup(&mut s).await;
    let tid = tree_connect(&mut s, r"\\srv\pub", sid, 3).await;
    let input = validate_negotiate_input(0, CLIENT_GUID, 1, &[0x0311]);
    let body = ioctl_body(
        Fsctl::VALIDATE_NEGOTIATE_INFO,
        FileId::any(),
        &input,
        24,
        IS_FSCTL,
    );
    let hdr = common::build_header(Command::Ioctl, 4, sid, tid);
    let mut msg = Vec::new();
    hdr.write(&mut msg).unwrap();
    msg.extend_from_slice(&body);
    let mut framed = Vec::new();
    common::encode_frame(&msg, &mut framed);
    tokio::io::AsyncWriteExt::write_all(&mut s, &framed)
        .await
        .unwrap();
    let reply = read_or_closed(&mut s).await;
    assert!(reply.is_none_or(|f| status(&f) != 0));
}

#[tokio::test]
async fn ioctl_checks_session_tree_flags_and_file_id() {
    let mut c = connect().await;
    let body = ioctl_body(
        Fsctl::VALIDATE_NEGOTIATE_INFO,
        FileId::any(),
        &good_input(),
        24,
        IS_FSCTL,
    );
    let frame = request(&mut c.s, Command::Ioctl, 20, 0, c.tid, &body).await;
    assert_eq!(status(&frame), STATUS_USER_SESSION_DELETED);
    let frame = request(&mut c.s, Command::Ioctl, 21, c.sid, 99, &body).await;
    assert_eq!(status(&frame), STATUS_NETWORK_NAME_DELETED);

    let body = ioctl_body(
        Fsctl::VALIDATE_NEGOTIATE_INFO,
        FileId::any(),
        &good_input(),
        24,
        0,
    );
    assert_eq!(status(&c.ioctl(22, &body).await), STATUS_NOT_SUPPORTED);

    let some_file = FileId::new(5, 5);
    let body = ioctl_body(
        Fsctl::VALIDATE_NEGOTIATE_INFO,
        some_file,
        &good_input(),
        24,
        IS_FSCTL,
    );
    assert_eq!(status(&c.ioctl(23, &body).await), STATUS_INVALID_PARAMETER);

    let body = ioctl_body(FSCTL_GET_COMPRESSION, some_file, &[], 8, IS_FSCTL);
    assert_eq!(status(&c.ioctl(24, &body).await), STATUS_FILE_CLOSED);

    // InputOffset not a multiple of 8.
    let mut body = ioctl_body(
        Fsctl::VALIDATE_NEGOTIATE_INFO,
        FileId::any(),
        &good_input(),
        24,
        IS_FSCTL,
    );
    body[24..28].copy_from_slice(&0x7Au32.to_le_bytes());
    assert_eq!(status(&c.ioctl(25, &body).await), STATUS_INVALID_PARAMETER);
}

#[tokio::test]
async fn enumerate_snapshots_returns_an_empty_array() {
    let mut c = connect().await;
    let file_id = open_file(&mut c, "f.txt").await;
    let body = ioctl_body(FSCTL_SRV_ENUMERATE_SNAPSHOTS, file_id, &[], 16, IS_FSCTL);
    let frame = c.ioctl(31, &body).await;
    assert_eq!(status(&frame), 0);
    let resp = IoctlResponse::parse(&frame[64..]).unwrap();
    assert_eq!(resp.file_id, file_id);
    assert_eq!(resp.output, [0u8; 12]);

    let body = ioctl_body(FSCTL_SRV_ENUMERATE_SNAPSHOTS, file_id, &[], 8, IS_FSCTL);
    assert_eq!(status(&c.ioctl(32, &body).await), STATUS_INVALID_PARAMETER);
}

async fn open_file(c: &mut Conn, name: &str) -> FileId {
    let body = create_body(name, 0x0012_0089, 0);
    created_file_id(&request(&mut c.s, Command::Create, 30, c.sid, c.tid, &body).await)
}
