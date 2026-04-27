//! Integration test: drive a real `SmbServer` over a TCP loopback through a
//! NEGOTIATE → SESSION_SETUP (anonymous) → TREE_CONNECT → CREATE → READ flow.
//!
//! We hand-craft the request bytes since we don't depend on a Rust SMB client
//! crate.

mod common;
#[path = "common/memfs.rs"]
mod memfs;

use common::{
    build_header, build_spnego_init, parse_response_header, read_frame, utf16le, write_frame,
    STATUS_MORE_PROCESSING_REQUIRED, STATUS_SUCCESS,
};
use memfs::MemFsBackend;

use smb_proto::auth::ntlm::NTLMSSP_SIGNATURE;
use smb_proto::auth::spnego::{decode_resp_token, encode_resp_token, NegState, OID_NTLMSSP};
use smb_proto::header::Command;
use smb_proto::messages::{
    CreateRequest, CreateResponse, FileId, Fsctl, IoctlRequest, IoctlResponse, NegotiateRequest,
    NegotiateResponse, ReadRequest, ReadResponse, SessionSetupRequest, SessionSetupResponse,
    TreeConnectRequest, TreeConnectResponse,
};
use smb_server::{Share, SmbServer};
use tokio::net::TcpStream;

#[tokio::test]
async fn end_to_end_anon_read() {
    // 1. Build a server with one public share and one in-memory file.
    let backend = MemFsBackend::new().with_file("hello.txt", b"hello world\n");
    let server = SmbServer::builder()
        .listen("127.0.0.1:0".parse().unwrap())
        .share(Share::new("downloads", backend).public())
        .netbios_name("TESTSERVER")
        .build()
        .expect("build");

    server.bind().await.expect("bind");
    let addr = server.local_addr().await.expect("addr");

    // Spawn the server.
    let handle = tokio::spawn(async move { server.serve().await });

    // Tiny grace period.
    tokio::task::yield_now().await;

    let mut s = TcpStream::connect(addr).await.expect("connect");

    // ---- NEGOTIATE -------------------------------------------------------
    let neg_req = NegotiateRequest {
        structure_size: 36,
        dialect_count: 2,
        security_mode: 0x0001, // signing enabled
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
    let neg_resp = NegotiateResponse::parse(rb).expect("parse neg resp");
    assert!(matches!(neg_resp.dialect_revision, 0x0202 | 0x0210));
    assert_eq!(neg_resp.security_mode, 0x0001);

    // ---- SESSION_SETUP (round 1: anon NTLM NEGOTIATE blob in SPNEGO init) -
    let mut ntlm_negotiate = Vec::new();
    ntlm_negotiate.extend_from_slice(NTLMSSP_SIGNATURE);
    ntlm_negotiate.extend_from_slice(&1u32.to_le_bytes()); // MessageType
    let flags: u32 = 0x6209_8215; // typical client-side NTLM negotiate flags
    ntlm_negotiate.extend_from_slice(&flags.to_le_bytes());
    // Domain + workstation: empty fields (8 bytes each).
    ntlm_negotiate.extend_from_slice(&[0u8; 16]);
    // Version (8 bytes).
    ntlm_negotiate.extend_from_slice(&[0u8; 8]);
    // Wrap in SPNEGO init.
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
    let _spnego_resp = decode_resp_token(&ss_resp.security_buffer).expect("decode spnego resp");

    // ---- SESSION_SETUP (round 2: anonymous NTLM AUTHENTICATE) ------------
    let mut ntlm_auth = Vec::new();
    ntlm_auth.extend_from_slice(NTLMSSP_SIGNATURE);
    ntlm_auth.extend_from_slice(&3u32.to_le_bytes()); // MessageType
                                                      // 6 empty fields (Lm, Nt, Domain, User, Workstation, Key) — len=0, off=72.
    let header_len: u32 = 72;
    for _ in 0..6 {
        ntlm_auth.extend_from_slice(&0u16.to_le_bytes());
        ntlm_auth.extend_from_slice(&0u16.to_le_bytes());
        ntlm_auth.extend_from_slice(&header_len.to_le_bytes());
    }
    // NegotiateFlags (anonymous bit set).
    ntlm_auth.extend_from_slice(&0x0000_0800u32.to_le_bytes());
    // Version.
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
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::SessionSetup);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    assert_eq!(rh.session_id, session_id);
    let ss_resp = SessionSetupResponse::parse(rb).expect("parse ss success resp");
    assert_eq!(
        ss_resp.session_flags & SessionSetupResponse::FLAG_IS_GUEST,
        SessionSetupResponse::FLAG_IS_GUEST
    );
    assert_eq!(
        ss_resp.session_flags & SessionSetupResponse::FLAG_IS_NULL,
        0
    );

    // ---- TREE_CONNECT to \\server\downloads ------------------------------
    let path_u16 = utf16le("\\\\TESTSERVER\\downloads");
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
    assert_eq!(ioctl_resp.output.len(), 24);
    let validate_security_mode = u16::from_le_bytes([ioctl_resp.output[20], ioctl_resp.output[21]]);
    assert_eq!(validate_security_mode, neg_resp.security_mode);

    // ---- CREATE hello.txt ------------------------------------------------
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
    let hdr = build_header(Command::Create, 5, session_id, tree_id);
    write_frame(&mut s, &hdr, &body).await;

    let resp = read_frame(&mut s).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::Create);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let cr_resp = CreateResponse::parse(rb).expect("parse create resp");
    let file_id = cr_resp.file_id;
    assert_eq!(cr_resp.end_of_file, 12); // "hello world\n"

    // ---- READ ------------------------------------------------------------
    let rd_req = ReadRequest {
        structure_size: 49,
        padding: ReadResponse::STANDARD_DATA_OFFSET,
        flags: 0,
        length: 32,
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
    let hdr = build_header(Command::Read, 6, session_id, tree_id);
    write_frame(&mut s, &hdr, &body).await;

    let resp = read_frame(&mut s).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.command, Command::Read);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let rd_resp = ReadResponse::parse(rb).expect("parse read resp");
    assert_eq!(rd_resp.data, b"hello world\n");

    drop(s);
    // The server keeps accepting; abort the spawned task so the test
    // process exits cleanly.
    handle.abort();
}
