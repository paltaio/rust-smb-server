//! NEGOTIATE, SESSION_SETUP and signing over TCP loopback.

mod common;

use common::{
    STATUS_MORE_PROCESSING_REQUIRED, STATUS_SUCCESS, anonymous_session_setup, build_header,
    encode_frame, finish_anonymous_session_setup, negotiate, parse_response_header, read_frame,
    smb2_signature, start_ntlm_session_setup, start_server, tree_connect, user_session_setup,
    utf16le, write_frame,
};

use smb_server::wire::header::{Command, SMB2_FLAGS_SIGNED};
use smb_server::wire::messages::{FileId, Fsctl, IoctlRequest, IoctlResponse, TreeConnectRequest};
use smb_server::{Access, LocalFsBackend, Share, SmbServer, ntstatus};
use tempfile::tempdir;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

#[tokio::test]
async fn validate_negotiate_info_matches_negotiate() {
    let td = tempdir().expect("tempdir");
    let backend = LocalFsBackend::new(td.path()).expect("open root");
    let (addr, handle) = start_server(
        SmbServer::builder()
            .share(Share::new("downloads", backend).public())
            .netbios_name("TESTSERVER"),
    )
    .await;

    let mut s = TcpStream::connect(addr).await.expect("connect");

    let neg_resp = negotiate(&mut s).await;
    let session_id = anonymous_session_setup(&mut s).await;
    let tree_id = tree_connect(&mut s, "\\\\TESTSERVER\\downloads", session_id, 3).await;

    // ---- FSCTL_VALIDATE_NEGOTIATE_INFO mirrors NEGOTIATE ----------------
    let ioctl_req = IoctlRequest {
        structure_size: 57,
        reserved: 0,
        ctl_code: Fsctl::VALIDATE_NEGOTIATE_INFO,
        file_id: FileId::any(),
        input_offset: 0,
        input_count: 0,
        max_input_response: 0,
        output_offset: 0,
        output_count: 0,
        max_output_response: 24,
        flags: IoctlRequest::FLAG_IS_FSCTL,
        reserved2: 0,
        input: vec![],
    };
    let mut body = Vec::new();
    ioctl_req.write_to(&mut body).expect("write");
    let hdr = build_header(Command::Ioctl, 4, session_id, tree_id);
    write_frame(&mut s, &hdr, &body).await;

    let resp = read_frame(&mut s).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::Ioctl);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let ioctl_resp = IoctlResponse::parse(rb).expect("parse ioctl resp");
    let mut expected = neg_resp.capabilities.to_le_bytes().to_vec();
    expected.extend_from_slice(&neg_resp.server_guid);
    expected.extend_from_slice(&neg_resp.security_mode.to_le_bytes());
    expected.extend_from_slice(&neg_resp.dialect_revision.to_le_bytes());
    assert_eq!(ioctl_resp.output, expected);

    drop(s);
    // The server keeps accepting; abort the spawned task so the test
    // process exits cleanly.
    handle.abort();
}

#[tokio::test]
async fn pending_ntlm_exchanges_are_capped_per_connection() {
    const MAX_PENDING: usize = 16;

    let td = tempdir().expect("tempdir");
    let backend = LocalFsBackend::new(td.path()).expect("open root");
    let (addr, handle) =
        start_server(SmbServer::builder().share(Share::new("share", backend).public())).await;

    let mut s = TcpStream::connect(addr).await.expect("connect");
    let _ = negotiate(&mut s).await;
    let mut mid = 1;
    let mut next_mid = || {
        mid += 1;
        mid
    };

    let mut pending = Vec::new();
    for _ in 0..MAX_PENDING {
        let (status, sid) = start_ntlm_session_setup(&mut s, next_mid()).await;
        assert_eq!(status, STATUS_MORE_PROCESSING_REQUIRED);
        pending.push(sid);
    }
    let (status, _) = start_ntlm_session_setup(&mut s, next_mid()).await;
    assert_eq!(status, ntstatus::STATUS_INSUFFICIENT_RESOURCES);

    // Interleaved exchanges each complete, and completing one frees a slot.
    for sid in pending.iter().rev().take(3) {
        assert_eq!(
            finish_anonymous_session_setup(&mut s, next_mid(), *sid).await,
            STATUS_SUCCESS
        );
    }
    let (status, sid) = start_ntlm_session_setup(&mut s, next_mid()).await;
    assert_eq!(status, STATUS_MORE_PROCESSING_REQUIRED);
    assert_eq!(
        finish_anonymous_session_setup(&mut s, next_mid(), sid).await,
        STATUS_SUCCESS
    );

    drop(s);
    handle.abort();
}

#[tokio::test]
async fn smb2_sessions_sign_with_the_session_key() {
    let td = tempdir().expect("tempdir");
    let backend = LocalFsBackend::new(td.path()).expect("open root");
    let (addr, handle) = start_server(
        SmbServer::builder()
            .user("alice", "password")
            .share(Share::new("home", backend).user("alice", Access::ReadWrite)),
    )
    .await;
    let mut s = TcpStream::connect(addr).await.expect("connect");
    assert_eq!(negotiate(&mut s).await.dialect_revision, 0x0210);

    let (status, session_id, key, resp) = user_session_setup(&mut s, "alice", "password").await;
    assert_eq!(status, STATUS_SUCCESS);
    assert_ne!(read_u32(&resp, 0x10) & SMB2_FLAGS_SIGNED, 0);
    assert_eq!(resp[48..64], smb2_signature(&resp, &key));

    // A TREE_CONNECT signed with the session key is accepted.
    let path = utf16le("\\\\127.0.0.1\\home");
    let mut body = Vec::new();
    TreeConnectRequest {
        structure_size: 9,
        flags: 0,
        path_offset: 64 + 8,
        path_length: path.len() as u16,
        path,
    }
    .write_to(&mut body)
    .expect("write tree connect");
    let mut hdr = build_header(Command::TreeConnect, 3, session_id, 0);
    hdr.flags |= SMB2_FLAGS_SIGNED;
    let mut msg = Vec::new();
    hdr.write(&mut msg).expect("header");
    msg.extend_from_slice(&body);
    let signature = smb2_signature(&msg, &key);
    msg[48..64].copy_from_slice(&signature);
    let mut framed = Vec::new();
    encode_frame(&msg, &mut framed);
    s.write_all(&framed).await.expect("write");
    let resp = read_frame(&mut s).await;
    let (rh, _) = parse_response_header(&resp);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    assert_eq!(resp[48..64], smb2_signature(&resp, &key));

    drop(s);
    handle.abort();
}

#[tokio::test]
async fn user_names_match_configured_users_ignoring_case() {
    let td = tempdir().expect("tempdir");
    let backend = LocalFsBackend::new(td.path()).expect("open root");
    let (addr, handle) = start_server(
        SmbServer::builder()
            .user("guest", "")
            .share(Share::new("g", backend).user("guest", Access::Read)),
    )
    .await;

    for (user, expected) in [
        ("guest", STATUS_SUCCESS),
        ("GUEST", STATUS_SUCCESS),
        ("nobody", ntstatus::STATUS_LOGON_FAILURE),
    ] {
        let mut s = TcpStream::connect(addr).await.expect("connect");
        negotiate(&mut s).await;
        let (status, session_id, _, _) = user_session_setup(&mut s, user, "").await;
        assert_eq!(status, expected, "user {user}");
        if status == STATUS_SUCCESS {
            tree_connect(&mut s, "\\\\127.0.0.1\\g", session_id, 3).await;
        }
    }

    handle.abort();
}

fn read_u32(buf: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(buf[offset..offset + 4].try_into().unwrap())
}
