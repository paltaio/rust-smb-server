//! Cross-stack integration test: drive a real `SmbServer` backed by
//! `smb_fs::LocalFsBackend` over a TCP loopback through the full
//! NEGOTIATE → SESSION_SETUP (anonymous) → TREE_CONNECT → CREATE → READ →
//! CLOSE → TREE_DISCONNECT → LOGOFF flow.
//!
//! Hand-crafts the request bytes since the workspace does not depend on an SMB
//! client crate.

mod common;

use common::{
    build_header, build_spnego_init, parse_response_header, read_frame, utf16le, write_frame,
    STATUS_MORE_PROCESSING_REQUIRED, STATUS_SUCCESS,
};
use smb_fs::LocalFsBackend;
use smb_proto::auth::ntlm::NTLMSSP_SIGNATURE;
use smb_proto::auth::spnego::{decode_resp_token, encode_resp_token, NegState, OID_NTLMSSP};
use smb_proto::header::Command;
use smb_proto::messages::{
    CloseRequest, CloseResponse, CreateRequest, CreateResponse, LogoffRequest, LogoffResponse,
    NegotiateRequest, NegotiateResponse, QueryDirectoryRequest, QueryDirectoryResponse,
    ReadRequest, ReadResponse, SessionSetupRequest, SessionSetupResponse, TreeConnectRequest,
    TreeConnectResponse, TreeDisconnectRequest, TreeDisconnectResponse,
};
use smb_server::{Share, SmbServer};
use tempfile::tempdir;
use tokio::net::TcpStream;

#[tokio::test]
async fn end_to_end_anon_read_localfs() {
    // 1. Pre-populate a temp dir: one file with known contents + one empty subdir.
    let td = tempdir().expect("tempdir");
    std::fs::write(td.path().join("hello.txt"), b"hi").expect("write hello.txt");
    std::fs::create_dir(td.path().join("sub")).expect("mkdir sub");

    // 2. Stand up an `SmbServer` with a single anonymous share over LocalFsBackend.
    let backend = LocalFsBackend::new(td.path()).expect("open root");
    let server = SmbServer::builder()
        .listen("127.0.0.1:0".parse().unwrap())
        .share(Share::new("share", backend).public())
        .netbios_name("TESTSERVER")
        .build()
        .expect("build");

    server.bind().await.expect("bind");
    let addr = server.local_addr().await.expect("addr");
    let handle = tokio::spawn(async move { server.serve().await });
    tokio::task::yield_now().await;

    let mut s = TcpStream::connect(addr).await.expect("connect");

    // ---- NEGOTIATE -------------------------------------------------------
    let neg_req = NegotiateRequest {
        structure_size: 36,
        dialect_count: 2,
        security_mode: 0x0001,
        reserved: 0,
        capabilities: 0,
        client_guid: [0xCD; 16],
        negotiate_context_offset_or_client_start_time: 0,
        dialects: vec![0x0202, 0x0210],
    };
    let mut body = Vec::new();
    neg_req.write_to(&mut body).expect("write");
    let hdr = build_header(Command::Negotiate, 0, 0, 0);
    write_frame(&mut s, &hdr, &body).await;
    let resp = read_frame(&mut s).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::Negotiate);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let _ = NegotiateResponse::parse(rb).expect("parse neg resp");

    // ---- SESSION_SETUP round 1 (NTLM NEGOTIATE wrapped in SPNEGO init) ----
    let mut ntlm_negotiate = Vec::new();
    ntlm_negotiate.extend_from_slice(NTLMSSP_SIGNATURE);
    ntlm_negotiate.extend_from_slice(&1u32.to_le_bytes());
    let flags: u32 = 0x6209_8215;
    ntlm_negotiate.extend_from_slice(&flags.to_le_bytes());
    ntlm_negotiate.extend_from_slice(&[0u8; 16]);
    ntlm_negotiate.extend_from_slice(&[0u8; 8]);
    let spnego_init = build_spnego_init(&ntlm_negotiate);
    let ss_req = SessionSetupRequest {
        structure_size: 25,
        flags: 0,
        security_mode: 0x01,
        capabilities: 0,
        channel: 0,
        security_buffer_offset: 88,
        security_buffer_length: spnego_init.len() as u16,
        previous_session_id: 0,
        security_buffer: spnego_init,
    };
    let mut body = Vec::new();
    ss_req.write_to(&mut body).expect("write");
    let hdr = build_header(Command::SessionSetup, 1, 0, 0);
    write_frame(&mut s, &hdr, &body).await;
    let resp = read_frame(&mut s).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::SessionSetup);
    assert_eq!(rh.channel_sequence_status, STATUS_MORE_PROCESSING_REQUIRED);
    let session_id = rh.session_id;
    assert_ne!(session_id, 0);
    let ss_resp = SessionSetupResponse::parse(rb).expect("parse ss resp");
    let _ = decode_resp_token(&ss_resp.security_buffer).expect("decode spnego resp");

    // ---- SESSION_SETUP round 2 (anonymous NTLM AUTHENTICATE) -------------
    let mut ntlm_auth = Vec::new();
    ntlm_auth.extend_from_slice(NTLMSSP_SIGNATURE);
    ntlm_auth.extend_from_slice(&3u32.to_le_bytes());
    let header_len: u32 = 72;
    for _ in 0..6 {
        ntlm_auth.extend_from_slice(&0u16.to_le_bytes());
        ntlm_auth.extend_from_slice(&0u16.to_le_bytes());
        ntlm_auth.extend_from_slice(&header_len.to_le_bytes());
    }
    ntlm_auth.extend_from_slice(&0x0000_0800u32.to_le_bytes()); // anonymous flag
    ntlm_auth.extend_from_slice(&[0u8; 8]);
    let spnego_resp_blob = encode_resp_token(
        NegState::AcceptIncomplete,
        Some(OID_NTLMSSP),
        Some(&ntlm_auth),
        None,
    );
    let ss_req2 = SessionSetupRequest {
        structure_size: 25,
        flags: 0,
        security_mode: 0x01,
        capabilities: 0,
        channel: 0,
        security_buffer_offset: 88,
        security_buffer_length: spnego_resp_blob.len() as u16,
        previous_session_id: 0,
        security_buffer: spnego_resp_blob,
    };
    let mut body = Vec::new();
    ss_req2.write_to(&mut body).expect("write");
    let hdr = build_header(Command::SessionSetup, 2, session_id, 0);
    write_frame(&mut s, &hdr, &body).await;
    let resp = read_frame(&mut s).await;
    let (rh, _rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::SessionSetup);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    assert_eq!(rh.session_id, session_id);

    // ---- TREE_CONNECT to \\TESTSERVER\share ------------------------------
    let path_u16 = utf16le("\\\\127.0.0.1\\share");
    let tc_req = TreeConnectRequest {
        structure_size: 9,
        flags: 0,
        path_offset: 64 + 8,
        path_length: path_u16.len() as u16,
        path: path_u16,
    };
    let mut body = Vec::new();
    tc_req.write_to(&mut body).expect("write");
    let hdr = build_header(Command::TreeConnect, 3, session_id, 0);
    write_frame(&mut s, &hdr, &body).await;
    let resp = read_frame(&mut s).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::TreeConnect);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let tree_id = rh.tree_id().expect("tree id");
    assert_ne!(tree_id, 0);
    let tc_resp = TreeConnectResponse::parse(rb).expect("parse tc resp");
    assert_eq!(tc_resp.share_type, TreeConnectResponse::SHARE_TYPE_DISK);

    // ---- CREATE share root without FILE_DIRECTORY_FILE -------------------
    // Windows Explorer opens directories this way before issuing
    // FileIdBothDirectoryInformation queries.
    let cr_root_req = CreateRequest {
        structure_size: 57,
        security_flags: 0,
        requested_oplock_level: 0,
        impersonation_level: 2,
        smb_create_flags: 0,
        reserved: 0,
        desired_access: 0x0012_0089, // FILE_GENERIC_READ
        file_attributes: 0,
        share_access: 0x0000_0007,
        create_disposition: 1, // FILE_OPEN
        create_options: 0,
        name_offset: 0x78,
        name_length: 0,
        create_contexts_offset: 0,
        create_contexts_length: 0,
        name: vec![],
        create_contexts: vec![],
    };
    let mut body = Vec::new();
    cr_root_req.write_to(&mut body).expect("write");
    let hdr = build_header(Command::Create, 4, session_id, tree_id);
    write_frame(&mut s, &hdr, &body).await;
    let resp = read_frame(&mut s).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::Create);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let cr_root_resp = CreateResponse::parse(rb).expect("parse root create resp");
    let root_dir_id = cr_root_resp.file_id;
    assert_ne!(
        cr_root_resp.file_attributes & 0x10,
        0,
        "root is a directory"
    );

    // ---- QUERY_DIRECTORY FileIdBothDirectoryInformation ------------------
    let pat = utf16le("*");
    let qd_req = QueryDirectoryRequest {
        structure_size: 33,
        file_information_class: 0x25, // FileIdBothDirectoryInformation
        flags: QueryDirectoryRequest::FLAG_RESTART_SCANS,
        file_index: 0,
        file_id: root_dir_id,
        file_name_offset: 64 + 32,
        file_name_length: pat.len() as u16,
        output_buffer_length: 4096,
        file_name: pat,
    };
    let mut body = Vec::new();
    qd_req.write_to(&mut body).expect("write");
    let hdr = build_header(Command::QueryDirectory, 5, session_id, tree_id);
    write_frame(&mut s, &hdr, &body).await;
    let resp = read_frame(&mut s).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::QueryDirectory);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let qd_resp = QueryDirectoryResponse::parse(rb).expect("parse query directory resp");
    assert!(qd_resp.output_buffer_length >= 104);
    let names = decode_file_id_both_names(&qd_resp.buffer);
    assert!(names.iter().any(|n| n == "hello.txt"), "names={names:?}");
    assert!(names.iter().any(|n| n == "sub"), "names={names:?}");

    // ---- CLOSE root dir --------------------------------------------------
    let cl_root_req = CloseRequest {
        structure_size: 24,
        flags: 0,
        reserved: 0,
        file_id: root_dir_id,
    };
    let mut body = Vec::new();
    cl_root_req.write_to(&mut body).expect("write");
    let hdr = build_header(Command::Close, 6, session_id, tree_id);
    write_frame(&mut s, &hdr, &body).await;
    let resp = read_frame(&mut s).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::Close);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let _ = CloseResponse::parse(rb).expect("parse root close resp");

    // ---- CREATE hello.txt (read-only intent) -----------------------------
    let name_u16 = utf16le("hello.txt");
    let cr_req = CreateRequest {
        structure_size: 57,
        security_flags: 0,
        requested_oplock_level: 0,
        impersonation_level: 2,
        smb_create_flags: 0,
        reserved: 0,
        desired_access: 0x0012_0089, // FILE_GENERIC_READ
        file_attributes: 0,
        share_access: 0x0000_0007, // FILE_SHARE_READ|WRITE|DELETE
        create_disposition: 1,     // FILE_OPEN
        create_options: 0,
        name_offset: 0x78,
        name_length: name_u16.len() as u16,
        create_contexts_offset: 0,
        create_contexts_length: 0,
        name: name_u16,
        create_contexts: vec![],
    };
    let mut body = Vec::new();
    cr_req.write_to(&mut body).expect("write");
    let hdr = build_header(Command::Create, 7, session_id, tree_id);
    write_frame(&mut s, &hdr, &body).await;
    let resp = read_frame(&mut s).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::Create);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let cr_resp = CreateResponse::parse(rb).expect("parse create resp");
    let file_id = cr_resp.file_id;
    assert_eq!(
        cr_resp.end_of_file, 2,
        "hello.txt was pre-populated as b\"hi\""
    );

    // ---- READ ------------------------------------------------------------
    let rd_req = ReadRequest {
        structure_size: 49,
        padding: ReadResponse::STANDARD_DATA_OFFSET,
        flags: 0,
        length: 64,
        offset: 0,
        file_id,
        minimum_count: 0,
        channel: 0,
        remaining_bytes: 0,
        read_channel_info_offset: 0,
        read_channel_info_length: 0,
        buffer: vec![0],
    };
    let mut body = Vec::new();
    rd_req.write_to(&mut body).expect("write");
    let hdr = build_header(Command::Read, 8, session_id, tree_id);
    write_frame(&mut s, &hdr, &body).await;
    let resp = read_frame(&mut s).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::Read);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let rd_resp = ReadResponse::parse(rb).expect("parse read resp");
    assert_eq!(rd_resp.data, b"hi");

    // ---- CLOSE -----------------------------------------------------------
    let cl_req = CloseRequest {
        structure_size: 24,
        flags: 0,
        reserved: 0,
        file_id,
    };
    let mut body = Vec::new();
    cl_req.write_to(&mut body).expect("write");
    let hdr = build_header(Command::Close, 9, session_id, tree_id);
    write_frame(&mut s, &hdr, &body).await;
    let resp = read_frame(&mut s).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::Close);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let _ = CloseResponse::parse(rb).expect("parse close resp");

    // ---- TREE_DISCONNECT -------------------------------------------------
    let td_req = TreeDisconnectRequest::default();
    let mut body = Vec::new();
    td_req.write_to(&mut body).expect("write");
    let hdr = build_header(Command::TreeDisconnect, 10, session_id, tree_id);
    write_frame(&mut s, &hdr, &body).await;
    let resp = read_frame(&mut s).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::TreeDisconnect);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let _ = TreeDisconnectResponse::parse(rb).expect("parse td resp");

    // ---- LOGOFF ----------------------------------------------------------
    let lo_req = LogoffRequest::default();
    let mut body = Vec::new();
    lo_req.write_to(&mut body).expect("write");
    let hdr = build_header(Command::Logoff, 11, session_id, 0);
    write_frame(&mut s, &hdr, &body).await;
    let resp = read_frame(&mut s).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::Logoff);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let _ = LogoffResponse::parse(rb).expect("parse logoff resp");

    drop(s);
    handle.abort();
}

fn decode_file_id_both_names(mut buf: &[u8]) -> Vec<String> {
    let mut names = Vec::new();
    loop {
        assert!(
            buf.len() >= 104,
            "short FileIdBothDirectoryInformation entry"
        );
        let next = u32::from_le_bytes(buf[0..4].try_into().unwrap()) as usize;
        let name_len = u32::from_le_bytes(buf[60..64].try_into().unwrap()) as usize;
        let name_start = 104;
        let name_end = name_start + name_len;
        assert!(buf.len() >= name_end, "short file name");
        let units: Vec<u16> = buf[name_start..name_end]
            .chunks_exact(2)
            .map(|b| u16::from_le_bytes([b[0], b[1]]))
            .collect();
        names.push(String::from_utf16(&units).expect("utf16 name"));
        if next == 0 {
            break;
        }
        assert!(buf.len() >= next, "invalid NextEntryOffset");
        buf = &buf[next..];
    }
    names
}
