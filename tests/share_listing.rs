//! Named pipes on IPC$ and the DCE/RPC binds and calls they carry.

mod common;

use common::auth::{ioctl_body, validate_negotiate_input};
use common::client::{
    Client, Create, FILE_STANDARD_INFORMATION, LOCK_EXCLUSIVE, MAXIMUM_ALLOWED, Server,
    write_request,
};
use common::durable::{SMB21, SMB302, contexts, dhnc, lease_v2};
use common::rpc::*;
use common::{CLIENT_GUID, utf16le};
use smb_server::ntstatus::*;
use smb_server::wire::header::Command;
use smb_server::wire::messages::{
    ChangeNotifyRequest, CloseRequest, CreateResponse, FileId, Fsctl, IoctlRequest,
    QueryInfoResponse, ReadRequest, ReadResponse, WriteRequest,
};
use smb_server::{Share, SmbServer, SmbServerBuilder};
use tempfile::TempDir;

const DELETE: u32 = 0x0001_0000;
const FILE_PIPE_INFORMATION: u8 = 23;

/// A server with a public share, so anonymous sessions are allowed, and
/// the user alice.
fn builder() -> (SmbServerBuilder, TempDir) {
    let td = tempfile::tempdir().expect("tempdir");
    let builder = SmbServer::builder()
        .user("alice", "password")
        .share(Share::new("public", common::client::local(td.path())).public());
    (builder, td)
}

async fn server() -> (Server, TempDir) {
    let (builder, td) = builder();
    (Server::start(builder).await, td)
}

/// An anonymous client on IPC$ at SMB 2.1.
async fn ipc(server: &Server) -> Client {
    ipc_client(server.addr, SMB21, None).await
}

#[tokio::test]
async fn only_srvsvc_opens() {
    let (server, _td) = server().await;
    let mut c = ipc(&server).await;
    for name in [
        "lsarpc",
        "mdssvc",
        "MsFteWds",
        "wkssvc",
        "\\srvsvc",
        "\\pipe\\srvsvc",
        "",
    ] {
        assert_eq!(
            c.open_pipe(name).await.err(),
            Some(STATUS_OBJECT_NAME_NOT_FOUND),
            "{name}"
        );
    }
    for name in ["srvsvc", "SRVSVC", "SrvSvc"] {
        c.open_pipe(name).await.expect(name);
    }
}

#[tokio::test]
async fn a_pipe_open_reports_what_windows_reports() {
    let (server, _td) = server().await;
    let mut c = ipc(&server).await;
    let leased = Create {
        oplock: 0xFF,
        contexts: contexts(&[lease_v2([0xA1; 16], 0x7)]),
        ..pipe_create("srvsvc")
    };
    let resp: CreateResponse = c.create(leased).await.expect("open");
    assert_eq!(resp.oplock_level, 0);
    assert_eq!(resp.create_action, 1, "FILE_OPENED");
    assert_eq!(
        (
            resp.creation_time,
            resp.last_access_time,
            resp.last_write_time,
            resp.change_time
        ),
        (0, 0, 0, 0)
    );
    assert_eq!((resp.allocation_size, resp.end_of_file), (4096, 0));
    assert_eq!(resp.file_attributes, 0x80);
    assert_eq!(resp.create_contexts_length, 0);
    assert_eq!(resp.create_contexts_offset, 0);

    let batch = Create {
        oplock: 9,
        ..pipe_create("srvsvc")
    };
    assert_eq!(c.create(batch).await.expect("open").oplock_level, 0);
}

#[tokio::test]
async fn pipe_opens_check_access_impersonation_and_reconnects() {
    let (server, _td) = server().await;
    let mut c = ipc(&server).await;
    let with_access = |access| Create {
        access,
        ..pipe_create("srvsvc")
    };
    for access in [DELETE, 0x0004_0000, 0x1000_0000, 0x2000_0000] {
        assert_eq!(
            c.create(with_access(access)).await.err(),
            Some(STATUS_ACCESS_DENIED),
            "{access:#x}"
        );
    }
    for access in [0, MAXIMUM_ALLOWED, 0x8000_0000 | 0x4000_0000, 0x0002_019F] {
        c.create(with_access(access)).await.expect("allowed");
    }

    // DesiredAccess 0: the open can only be closed.
    let file_id = c.create(with_access(0)).await.expect("open").file_id;
    assert_eq!(
        c.pipe_write(file_id, &srvsvc_bind(1)).await,
        STATUS_ACCESS_DENIED
    );
    assert_eq!(c.pipe_read(file_id, 100).await.0, STATUS_ACCESS_DENIED);
    assert_eq!(
        c.transceive(file_id, &[], 100).await.0,
        STATUS_ACCESS_DENIED
    );
    c.close(file_id).await;

    let mut body = pipe_create("srvsvc").body();
    body[4..8].copy_from_slice(&3u32.to_le_bytes());
    assert_eq!(
        c.send(Command::Create, &body).await.0,
        STATUS_BAD_IMPERSONATION_LEVEL
    );

    let reconnect = Create {
        contexts: contexts(&[dhnc(FileId::new(1, 1))]),
        ..pipe_create("srvsvc")
    };
    assert_eq!(
        c.create(reconnect).await.err(),
        Some(STATUS_OBJECT_NAME_NOT_FOUND)
    );
    let broken = Create {
        contexts: vec![0xFF; 8],
        ..pipe_create("srvsvc")
    };
    assert_eq!(c.create(broken).await.err(), Some(STATUS_INVALID_PARAMETER));
}

#[tokio::test]
async fn pipe_opens_count_against_the_open_limit() {
    let (builder, _td) = builder();
    let server = Server::start(builder.max_opens_per_connection(2)).await;
    let mut c = ipc(&server).await;
    let first = c.open_pipe("srvsvc").await.expect("first").file_id;
    c.open_pipe("srvsvc").await.expect("second");
    assert_eq!(
        c.open_pipe("srvsvc").await.err(),
        Some(STATUS_INSUFFICIENT_RESOURCES)
    );
    c.close(first).await;
    c.open_pipe("srvsvc").await.expect("after a close");
}

#[tokio::test]
async fn a_connection_holds_at_most_16_pipes() {
    let (server, _td) = server().await;
    let mut c = ipc(&server).await;
    let mut pipes = Vec::new();
    for _ in 0..16 {
        pipes.push(
            c.open_pipe("srvsvc")
                .await
                .expect("under the limit")
                .file_id,
        );
    }
    assert_eq!(
        c.open_pipe("srvsvc").await.err(),
        Some(STATUS_INSUFFICIENT_RESOURCES)
    );
    // The limit is per connection.
    let mut other = ipc(&server).await;
    other.open_pipe("srvsvc").await.expect("another connection");
    c.close(pipes[3]).await;
    c.open_pipe("srvsvc").await.expect("after a close");
}

#[tokio::test]
async fn pipe_wait_finds_srvsvc_only() {
    let (server, _td) = server().await;
    let mut c = ipc(&server).await;
    let wait = |name: &str, len: Option<u32>| {
        let name = utf16le(name);
        let mut input = 0i64.to_le_bytes().to_vec();
        input.extend_from_slice(&len.unwrap_or(name.len() as u32).to_le_bytes());
        input.extend_from_slice(&[0, 0]);
        input.extend_from_slice(&name);
        ioctl_body(
            Fsctl::PIPE_WAIT,
            FileId::any(),
            &input,
            0,
            IoctlRequest::FLAG_IS_FSCTL,
        )
    };
    let (status, body) = c.send(Command::Ioctl, &wait("srvsvc", None)).await;
    assert_eq!(status, STATUS_SUCCESS);
    let resp = smb_server::wire::messages::IoctlResponse::parse(&body).expect("ioctl");
    assert_eq!(resp.file_id, FileId::any());
    assert_eq!(resp.output_count, 0);
    for (name, len) in [
        ("lsarpc", None),
        ("srvsvc", Some(100)),
        ("srvsvc", Some(11)),
    ] {
        assert_eq!(
            c.send(Command::Ioctl, &wait(name, len)).await.0,
            STATUS_OBJECT_NAME_NOT_FOUND,
            "{name} {len:?}"
        );
    }
}

#[tokio::test]
async fn a_bind_is_answered_and_every_call_faults() {
    let (server, _td) = server().await;
    let mut c = ipc(&server).await;
    let (file_id, ack) = c.bound_pipe().await;
    assert_eq!(call_id(&ack), 1);
    assert_eq!(pfc_flags(&ack), FIRST | LAST);
    assert_eq!(ack_results(&ack), [(0, 0), (2, 2), (3, 2)]);
    assert_eq!(&ack[16..20], [0xB8, 0x10, 0xB8, 0x10], "4280 both ways");
    assert_eq!(&ack[24..39], b"\x0d\x00\\PIPE\\srvsvc\0");

    let (status, fault) = c
        .transceive(
            file_id,
            &request_pdu(2, FIRST | LAST, 0, 15, &[0; 40]),
            4280,
        )
        .await;
    assert_eq!(status, STATUS_SUCCESS);
    assert_eq!(fault_status(&fault), NCA_OP_RNG_ERROR);
    assert_eq!((call_id(&fault), pfc_flags(&fault)), (2, 0x23));
}

#[tokio::test]
async fn faults_leave_the_pipe_working() {
    let (server, _td) = server().await;
    let mut c = ipc_client(server.addr, SMB21, Some("alice")).await;
    let (file_id, _) = c.bound_pipe().await;
    let cases = [
        (request_pdu(2, FIRST | LAST, 0, 99, &[]), NCA_OP_RNG_ERROR),
        (request_pdu(3, FIRST | LAST, 5, 15, &[]), NCA_UNK_IF),
        (request_pdu(4, FIRST | LAST, 0, 15, &[]), NCA_OP_RNG_ERROR),
    ];
    for (request, expected) in cases {
        let (status, fault) = c.transceive(file_id, &request, 4280).await;
        assert_eq!(status, STATUS_SUCCESS);
        assert_eq!(fault_status(&fault), expected);
        assert_eq!(call_id(&fault), call_id(&request));
    }
}

#[tokio::test]
async fn a_request_in_fragments_is_answered_once_whole() {
    let (server, _td) = server().await;
    let mut c = ipc(&server).await;
    let (file_id, _) = c.bound_pipe().await;
    assert_eq!(
        c.pipe_write(file_id, &request_pdu(7, FIRST, 0, 15, &[1; 100]))
            .await,
        STATUS_SUCCESS
    );
    assert_eq!(
        c.pipe_write(file_id, &request_pdu(7, 0, 0, 15, &[2; 100]))
            .await,
        STATUS_SUCCESS
    );
    let (status, fault) = c
        .transceive(file_id, &request_pdu(7, LAST, 0, 15, &[3; 100]), 4280)
        .await;
    assert_eq!(status, STATUS_SUCCESS);
    assert_eq!(
        (fault_status(&fault), call_id(&fault)),
        (NCA_OP_RNG_ERROR, 7)
    );

    // A transceive that completes no request waits for the reply.
    let mid = c
        .send_no_wait(
            Command::Ioctl,
            &transceive_body(file_id, &request_pdu(8, FIRST, 0, 15, &[1; 8]), 4280),
        )
        .await;
    c.recv_interim(mid).await;
    assert_eq!(
        c.pipe_write(file_id, &request_pdu(8, LAST, 0, 15, &[2; 8]))
            .await,
        STATUS_SUCCESS
    );
    let (status, body) = c.recv(mid, Command::Ioctl).await;
    assert_eq!(status, STATUS_SUCCESS);
    let fault = ioctl_output(status, &body);
    assert_eq!(
        (fault_status(&fault), call_id(&fault)),
        (NCA_OP_RNG_ERROR, 8)
    );
}

#[tokio::test]
async fn pdus_are_cut_from_the_bytes_written() {
    let (server, _td) = server().await;
    let mut c = ipc(&server).await;
    let file_id = c.open_pipe("srvsvc").await.expect("open").file_id;
    let bind = srvsvc_bind(1);
    assert_eq!(c.pipe_write(file_id, &bind[..10]).await, STATUS_SUCCESS);
    assert_eq!(c.pipe_write(file_id, &bind[10..]).await, STATUS_SUCCESS);
    let (status, ack) = c.pipe_read(file_id, 4280).await;
    assert_eq!(status, STATUS_SUCCESS);
    assert_pdu(&ack, PTYPE_BIND_ACK);

    let file_id = c.open_pipe("srvsvc").await.expect("open").file_id;
    let mut both = srvsvc_bind(1);
    both.extend(request_pdu(2, FIRST | LAST, 0, 15, &[]));
    assert_eq!(c.pipe_write(file_id, &both).await, STATUS_SUCCESS);
    let (_, ack) = c.pipe_read(file_id, 4280).await;
    assert_pdu(&ack, PTYPE_BIND_ACK);
    let (status, fault) = c.pipe_read(file_id, 4280).await;
    assert_eq!(status, STATUS_SUCCESS);
    assert_eq!(fault_status(&fault), NCA_OP_RNG_ERROR);
}

#[tokio::test]
async fn short_reads_get_the_rest_of_a_message_next() {
    let (server, _td) = server().await;
    let mut c = ipc(&server).await;
    let file_id = c.open_pipe("srvsvc").await.expect("open").file_id;
    assert_eq!(c.pipe_write(file_id, &srvsvc_bind(1)).await, STATUS_SUCCESS);
    let (status, head) = c.pipe_read(file_id, 10).await;
    assert_eq!((status, head.len()), (STATUS_BUFFER_OVERFLOW, 10));
    // A READ of 0 bytes succeeds and takes nothing.
    assert_eq!(c.pipe_read(file_id, 0).await, (STATUS_SUCCESS, Vec::new()));
    let (status, rest) = c.pipe_read_at(file_id, 12345, 4280).await;
    assert_eq!(status, STATUS_SUCCESS);
    let ack = [head, rest].concat();
    assert_pdu(&ack, PTYPE_BIND_ACK);

    let (status, head) = c
        .transceive(file_id, &request_pdu(2, FIRST | LAST, 0, 15, &[]), 10)
        .await;
    assert_eq!((status, head.len()), (STATUS_BUFFER_OVERFLOW, 10));
    let (status, rest) = c.pipe_read(file_id, 4280).await;
    assert_eq!(status, STATUS_SUCCESS);
    assert_eq!(fault_status(&[head, rest].concat()), NCA_OP_RNG_ERROR);

    let (status, out) = c
        .transceive(file_id, &request_pdu(3, FIRST | LAST, 0, 15, &[]), 0)
        .await;
    assert_eq!((status, out.len()), (STATUS_BUFFER_OVERFLOW, 0));
    assert_eq!(c.pipe_read(file_id, 4280).await.1.len(), 32);
}

#[tokio::test]
async fn transceive_with_a_reply_unread_is_busy() {
    let (server, _td) = server().await;
    let mut c = ipc(&server).await;
    let file_id = c.open_pipe("srvsvc").await.expect("open").file_id;
    assert_eq!(c.pipe_write(file_id, &srvsvc_bind(1)).await, STATUS_SUCCESS);
    let request = request_pdu(2, FIRST | LAST, 0, 15, &[]);
    assert_eq!(
        c.transceive(file_id, &request, 4280).await.0,
        STATUS_PIPE_BUSY
    );
    c.pipe_read(file_id, 4280).await;
    assert_eq!(
        c.transceive(file_id, &request, 4280).await.0,
        STATUS_SUCCESS
    );
}

#[tokio::test]
async fn a_request_before_the_bind_ends_the_association() {
    let (server, _td) = server().await;
    let mut c = ipc(&server).await;
    let file_id = c.open_pipe("srvsvc").await.expect("open").file_id;
    let request = request_pdu(4, FIRST | LAST, 0, 15, &[]);
    assert_eq!(c.pipe_write(file_id, &request).await, STATUS_SUCCESS);
    let (status, nak) = c.pipe_read(file_id, 4280).await;
    assert_eq!(status, STATUS_SUCCESS);
    assert_eq!(nak_reason(&nak), 4);
    assert_eq!(call_id(&nak), 4);
    assert_eq!(nak.len(), 24);
    assert_eq!(
        c.pipe_write(file_id, &srvsvc_bind(5)).await,
        STATUS_PIPE_DISCONNECTED
    );
    assert_eq!(c.pipe_read(file_id, 4280).await.0, STATUS_PIPE_DISCONNECTED);
    assert_eq!(
        c.transceive(file_id, &[], 4280).await.0,
        STATUS_PIPE_DISCONNECTED
    );
    c.close(file_id).await;
}

#[tokio::test]
async fn an_authenticated_bind_is_refused() {
    let (server, _td) = server().await;
    let mut c = ipc(&server).await;
    let file_id = c.open_pipe("srvsvc").await.expect("open").file_id;
    // RPC_C_AUTHN_WINNT with an NTLMSSP NEGOTIATE, padded to 32 bytes.
    let mut token = b"NTLMSSP\0".to_vec();
    token.extend_from_slice(&1u32.to_le_bytes());
    token.extend_from_slice(&0xE208_8297u32.to_le_bytes());
    token.resize(32, 0);
    let bind = with_auth(srvsvc_bind(3), 10, &token);
    assert_eq!(c.pipe_write(file_id, &bind).await, STATUS_SUCCESS);
    let (_, nak) = c.pipe_read(file_id, 4280).await;
    assert_eq!(nak_reason(&nak), 8);
    assert_eq!(c.pipe_read(file_id, 4280).await.0, STATUS_PIPE_DISCONNECTED);

    // A Kerberos token makes a bind larger than a request may be.
    let file_id = c.open_pipe("srvsvc").await.expect("open").file_id;
    let bind = with_auth(srvsvc_bind(4), 16, &[0x60; 12000]);
    assert!(bind.len() > 4280);
    for part in bind.chunks(4096) {
        assert_eq!(c.pipe_write(file_id, part).await, STATUS_SUCCESS);
    }
    let (_, nak) = c.pipe_read(file_id, 4280).await;
    assert_eq!(nak_reason(&nak), 8);
}

#[tokio::test]
async fn other_commands_on_a_pipe_get_a_pipes_answers() {
    let (server, _td) = server().await;
    let mut c = ipc_client(server.addr, SMB302, None).await;
    let (file_id, _) = c.bound_pipe().await;

    let (status, body) = c
        .query_info_raw(file_id, 1, FILE_STANDARD_INFORMATION, 24)
        .await;
    assert_eq!(status, STATUS_SUCCESS);
    let info = QueryInfoResponse::parse(&body).expect("query info").buffer;
    let mut expected = 4096u64.to_le_bytes().to_vec();
    expected.extend_from_slice(&[0; 8]);
    expected.extend_from_slice(&1u32.to_le_bytes());
    expected.extend_from_slice(&[1, 0, 0, 0]);
    assert_eq!(info, expected);
    assert_eq!(
        c.query_info_raw(file_id, 1, FILE_STANDARD_INFORMATION, 23)
            .await
            .0,
        STATUS_INFO_LENGTH_MISMATCH
    );
    for (info_type, class) in [(1, FILE_PIPE_INFORMATION), (1, 24), (2, 1), (3, 0)] {
        assert_eq!(
            c.query_info_raw(file_id, info_type, class, 1024).await.0,
            STATUS_NOT_SUPPORTED,
            "{info_type} {class}"
        );
    }
    assert_eq!(
        c.set_info_raw(file_id, 1, FILE_PIPE_INFORMATION, vec![0; 8])
            .await,
        STATUS_NOT_SUPPORTED
    );
    assert_eq!(c.flush(file_id).await, STATUS_SUCCESS);
    assert_eq!(
        c.lock(file_id, &[(0, 1, LOCK_EXCLUSIVE)]).await,
        STATUS_NOT_SUPPORTED
    );
    assert_eq!(
        c.query_directory(file_id, 0x25, 0, "*", 1024).await.0,
        STATUS_INVALID_PARAMETER
    );
    let mut notify = Vec::new();
    ChangeNotifyRequest {
        structure_size: 32,
        flags: 0,
        output_buffer_length: 1024,
        file_id,
        completion_filter: 0x17,
        reserved: 0,
    }
    .write_to(&mut notify)
    .expect("notify");
    assert_eq!(
        c.send(Command::ChangeNotify, &notify).await.0,
        STATUS_INVALID_PARAMETER
    );

    // Writes through or unbuffered, and unbuffered reads, are refused.
    for flags in [
        WriteRequest::FLAG_WRITE_THROUGH,
        WriteRequest::FLAG_WRITE_UNBUFFERED,
    ] {
        let req = WriteRequest {
            flags,
            ..write_request(file_id, 0, &request_pdu(2, FIRST | LAST, 0, 15, &[]))
        };
        assert_eq!(c.write_raw(req).await, Err(STATUS_INVALID_PARAMETER));
    }
    let mut read = Vec::new();
    ReadRequest {
        structure_size: 49,
        padding: ReadResponse::STANDARD_DATA_OFFSET,
        flags: ReadRequest::FLAG_READ_UNBUFFERED,
        length: 100,
        offset: 0,
        file_id,
        minimum_count: 0,
        channel: 0,
        remaining_bytes: 0,
        read_channel_info_offset: 0,
        read_channel_info_length: 0,
        buffer: vec![0],
    }
    .write_to(&mut read)
    .expect("read");
    assert_eq!(
        c.send(Command::Read, &read).await.0,
        STATUS_INVALID_PARAMETER
    );

    let (status, resp) = c
        .close_with(file_id, CloseRequest::FLAG_POSTQUERY_ATTRIB)
        .await;
    assert_eq!(status, STATUS_SUCCESS);
    let resp = resp.expect("close response");
    assert_eq!(resp.flags, 0);
    assert_eq!(
        (resp.allocation_size, resp.end_of_file, resp.file_attributes),
        (0, 0, 0)
    );
}

#[tokio::test]
async fn write_through_is_refused_from_smb_2_1_on() {
    let (server, _td) = server().await;
    let mut c = ipc(&server).await;
    let (file_id, _) = c.bound_pipe().await;
    let request = request_pdu(2, FIRST | LAST, 0, 15, &[]);
    let through = WriteRequest {
        flags: WriteRequest::FLAG_WRITE_THROUGH,
        ..write_request(file_id, 0, &request)
    };
    assert_eq!(c.write_raw(through).await, Err(STATUS_INVALID_PARAMETER));
    // WRITE_UNBUFFERED is not defined before 3.0.2 and is ignored.
    let unbuffered = WriteRequest {
        flags: WriteRequest::FLAG_WRITE_UNBUFFERED,
        ..write_request(file_id, 0, &request)
    };
    assert_eq!(c.write_raw(unbuffered).await, Ok(request.len() as u32));
}

#[tokio::test]
async fn create_write_and_read_in_one_compound() {
    let (server, _td) = server().await;
    let mut c = ipc(&server).await;
    let related = FileId::any();
    let mut write = Vec::new();
    write_request(related, 0, &srvsvc_bind(1))
        .write_to(&mut write)
        .expect("write");
    let mut read = Vec::new();
    ReadRequest {
        structure_size: 49,
        padding: ReadResponse::STANDARD_DATA_OFFSET,
        flags: 0,
        length: 4280,
        offset: 0,
        file_id: related,
        minimum_count: 0,
        channel: 0,
        remaining_bytes: 0,
        read_channel_info_offset: 0,
        read_channel_info_length: 0,
        buffer: vec![0],
    }
    .write_to(&mut read)
    .expect("read");
    let replies = c
        .send_compound(&[
            (Command::Create, pipe_create("srvsvc").body(), false),
            (Command::Write, write, true),
            (Command::Read, read, true),
        ])
        .await;
    let statuses: Vec<u32> = replies.iter().map(|(status, _)| *status).collect();
    assert_eq!(statuses, [STATUS_SUCCESS; 3]);
    let ack = ReadResponse::parse(&replies[2].1).expect("read").data;
    assert_pdu(&ack, PTYPE_BIND_ACK);
}

#[tokio::test]
async fn a_read_waiting_on_a_pipe_ends_with_its_close() {
    let (server, _td) = server().await;
    let mut c = ipc(&server).await;
    let (file_id, _) = c.bound_pipe().await;
    let mut read = Vec::new();
    ReadRequest {
        structure_size: 49,
        padding: ReadResponse::STANDARD_DATA_OFFSET,
        flags: 0,
        length: 4280,
        offset: 0,
        file_id,
        minimum_count: 0,
        channel: 0,
        remaining_bytes: 0,
        read_channel_info_offset: 0,
        read_channel_info_length: 0,
        buffer: vec![0],
    }
    .write_to(&mut read)
    .expect("read");
    let mid = c.send_no_wait(Command::Read, &read).await;
    c.recv_interim(mid).await;
    c.close(file_id).await;
    assert_eq!(c.recv(mid, Command::Read).await.0, STATUS_PIPE_BROKEN);
}

#[tokio::test]
async fn ioctls_without_a_file_on_ipc_keep_their_answers() {
    let (server, _td) = server().await;
    let mut c = ipc_client(server.addr, SMB302, None).await;
    let input = validate_negotiate_input(0, CLIENT_GUID, 0x0001, &[SMB302]);
    let body = ioctl_body(
        Fsctl::VALIDATE_NEGOTIATE_INFO,
        FileId::any(),
        &input,
        24,
        IoctlRequest::FLAG_IS_FSCTL,
    );
    let (status, body) = c.send(Command::Ioctl, &body).await;
    assert_eq!(status, STATUS_SUCCESS);
    let resp = smb_server::wire::messages::IoctlResponse::parse(&body).expect("ioctl");
    assert_eq!(resp.output_count, 24);

    let mut referral = 3u16.to_le_bytes().to_vec();
    referral.extend_from_slice(&utf16le("\\127.0.0.1\\public\0"));
    let body = ioctl_body(
        Fsctl::DFS_GET_REFERRALS,
        FileId::any(),
        &referral,
        4096,
        IoctlRequest::FLAG_IS_FSCTL,
    );
    assert_eq!(
        c.send(Command::Ioctl, &body).await.0,
        STATUS_FS_DRIVER_REQUIRED
    );

    // On a pipe, an FSCTL that names no file still needs FileId -1.
    let (file_id, _) = c.bound_pipe().await;
    let body = ioctl_body(
        Fsctl::VALIDATE_NEGOTIATE_INFO,
        file_id,
        &input,
        24,
        IoctlRequest::FLAG_IS_FSCTL,
    );
    assert_eq!(
        c.send(Command::Ioctl, &body).await.0,
        STATUS_INVALID_PARAMETER
    );
    let body = ioctl_body(0x0011_400C, file_id, &[], 64, IoctlRequest::FLAG_IS_FSCTL);
    assert_eq!(c.send(Command::Ioctl, &body).await.0, STATUS_NOT_SUPPORTED);
}

#[tokio::test]
async fn unknown_file_ids_on_ipc_are_closed() {
    let (server, _td) = server().await;
    let mut c = ipc(&server).await;
    let gone = FileId::new(77, 77);
    assert_eq!(
        c.pipe_write(gone, &srvsvc_bind(1)).await,
        STATUS_FILE_CLOSED
    );
    assert_eq!(c.pipe_read(gone, 10).await.0, STATUS_FILE_CLOSED);
    assert_eq!(c.transceive(gone, &[], 10).await.0, STATUS_FILE_CLOSED);
    assert_eq!(c.close_with(gone, 0).await.0, STATUS_FILE_CLOSED);
}
