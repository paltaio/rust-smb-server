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
use smb_server::{Access, Share, ShareMode, SmbServer, SmbServerBuilder};
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
async fn a_bind_is_answered_and_unknown_operations_fault() {
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
            &request_pdu(2, FIRST | LAST, 0, OPNUM_SHARE_ENUM_STICKY, &[0; 40]),
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
    let file_id = c.srvsvc().await;
    let enum_stub = enum_request(1, u32::MAX, Some(0));
    let cases = [
        (
            request_pdu(2, FIRST | LAST, 0, 99, &[]),
            NCA_OP_RNG_ERROR,
            0x23,
        ),
        (
            request_pdu(3, FIRST | LAST, 5, 15, &enum_stub),
            NCA_UNK_IF,
            0x23,
        ),
        (
            request_pdu(4, FIRST | LAST, 0, 15, &enum_stub[..enum_stub.len() - 2]),
            BAD_STUB_DATA,
            0x03,
        ),
        (
            request_pdu(5, FIRST | LAST, 0, 16, &[0; 4]),
            BAD_STUB_DATA,
            0x03,
        ),
    ];
    for (request, expected, flags) in cases {
        let (status, fault) = c.transceive(file_id, &request, 4280).await;
        assert_eq!(status, STATUS_SUCCESS);
        assert_eq!(fault_status(&fault), expected);
        assert_eq!(pfc_flags(&fault), flags);
        assert_eq!(call_id(&fault), call_id(&request));
        assert!(
            !c.list_shares(file_id, 1).await.entries.is_empty(),
            "still works"
        );
    }
}

#[tokio::test]
async fn a_request_in_fragments_is_answered_once_whole() {
    let (server, _td) = server().await;
    let mut c = ipc(&server).await;
    let file_id = c.srvsvc().await;
    let stub = enum_request(1, u32::MAX, Some(0));
    let (a, rest) = stub.split_at(16);
    let (b, last) = rest.split_at(12);
    assert_eq!(
        c.pipe_write(file_id, &request_pdu(7, FIRST, 0, 15, a))
            .await,
        STATUS_SUCCESS
    );
    assert_eq!(
        c.pipe_write(file_id, &request_pdu(7, 0, 0, 15, b)).await,
        STATUS_SUCCESS
    );
    let (status, response) = c
        .transceive(file_id, &request_pdu(7, LAST, 0, 15, last), 4280)
        .await;
    assert_eq!(status, STATUS_SUCCESS);
    assert_pdu(&response, PTYPE_RESPONSE);
    assert_eq!(call_id(&response), 7);
    assert_eq!(decode_enum(&response[24..]).names(), ["public", "IPC$"]);

    // A transceive that completes no request waits for the reply.
    let mid = c
        .send_no_wait(
            Command::Ioctl,
            &transceive_body(file_id, &request_pdu(8, FIRST, 0, 15, a), 4280),
        )
        .await;
    c.recv_interim(mid).await;
    let mut tail = b.to_vec();
    tail.extend_from_slice(last);
    assert_eq!(
        c.pipe_write(file_id, &request_pdu(8, LAST, 0, 15, &tail))
            .await,
        STATUS_SUCCESS
    );
    let (status, body) = c.recv(mid, Command::Ioctl).await;
    assert_eq!(status, STATUS_SUCCESS);
    let response = ioctl_output(status, &body);
    assert_eq!(call_id(&response), 8);
    assert_eq!(decode_enum(&response[24..]).names(), ["public", "IPC$"]);
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
    both.extend(request_pdu(
        2,
        FIRST | LAST,
        0,
        OPNUM_SHARE_ENUM_STICKY,
        &[],
    ));
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
        .transceive(
            file_id,
            &request_pdu(2, FIRST | LAST, 0, OPNUM_SHARE_ENUM_STICKY, &[]),
            10,
        )
        .await;
    assert_eq!((status, head.len()), (STATUS_BUFFER_OVERFLOW, 10));
    let (status, rest) = c.pipe_read(file_id, 4280).await;
    assert_eq!(status, STATUS_SUCCESS);
    assert_eq!(fault_status(&[head, rest].concat()), NCA_OP_RNG_ERROR);

    let (status, out) = c
        .transceive(
            file_id,
            &request_pdu(3, FIRST | LAST, 0, OPNUM_SHARE_ENUM_STICKY, &[]),
            0,
        )
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
    let request = request_pdu(2, FIRST | LAST, 0, OPNUM_SHARE_ENUM_STICKY, &[]);
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
    let request = request_pdu(4, FIRST | LAST, 0, OPNUM_SHARE_ENUM_STICKY, &[]);
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
            ..write_request(
                file_id,
                0,
                &request_pdu(2, FIRST | LAST, 0, OPNUM_SHARE_ENUM_STICKY, &[]),
            )
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
    let request = request_pdu(2, FIRST | LAST, 0, OPNUM_SHARE_ENUM_STICKY, &[]);
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

/// Users alice and bob, and shares, in this order: `public` (public),
/// `home` and `secret$` (alice), `archive` (alice, unlisted), `docs`
/// (public, with a remark).
fn listing_builder() -> (SmbServerBuilder, TempDir) {
    let td = tempfile::tempdir().expect("tempdir");
    let local = || common::client::local(td.path());
    let builder = SmbServer::builder()
        .netbios_name("LISTSRV")
        .user("alice", "password")
        .user("bob", "password")
        .share(Share::new("public", local()).public())
        .share(Share::new("home", local()).user("alice", Access::ReadWrite))
        .share(Share::new("secret$", local()).user("alice", Access::Read))
        .share(
            Share::new("archive", local())
                .user("alice", Access::Read)
                .listed(false),
        )
        .share(
            Share::new("docs", local())
                .public_read_only()
                .remark("Docs"),
        );
    (builder, td)
}

async fn listing_server() -> (Server, TempDir) {
    let (builder, td) = listing_builder();
    (Server::start(builder).await, td)
}

fn entry(name: &str, kind: u32, remark: &str) -> Entry {
    Entry {
        name: name.to_string(),
        kind: Some(kind),
        remark: Some(remark.to_string()),
        flags: None,
    }
}

#[tokio::test]
async fn anonymous_sessions_see_the_public_shares_and_ipc() {
    let (server, _td) = listing_server().await;
    let mut c = ipc(&server).await;
    let file_id = c.srvsvc().await;
    let reply = c.list_shares(file_id, 1).await;
    assert_eq!(reply.status, 0);
    assert_eq!(
        reply.entries,
        [
            entry("public", STYPE_DISKTREE, ""),
            entry("docs", STYPE_DISKTREE, "Docs"),
            entry("IPC$", STYPE_IPC_SPECIAL, "Remote IPC"),
        ]
    );
    assert_eq!((reply.total, reply.resume), (3, Some(0)));

    let level_0 = c.list_shares(file_id, 0).await;
    assert_eq!(level_0.names(), ["public", "docs", "IPC$"]);
    assert!(level_0.entries.iter().all(|e| e.kind.is_none()));
    let level_501 = c.list_shares(file_id, 501).await;
    assert_eq!(level_501.names(), ["public", "docs", "IPC$"]);
    assert!(level_501.entries.iter().all(|e| e.flags == Some(0)));
    assert_eq!(level_501.entries[1].remark.as_deref(), Some("Docs"));
}

#[tokio::test]
async fn users_see_the_shares_they_may_connect_to() {
    let (server, _td) = listing_server().await;
    let mut alice = ipc_client(server.addr, SMB21, Some("alice")).await;
    let file_id = alice.srvsvc().await;
    let reply = alice.list_shares(file_id, 1).await;
    assert_eq!(reply.names(), ["public", "home", "secret$", "docs", "IPC$"]);
    // A name ending in `$` is an ordinary disk share.
    assert_eq!(reply.entries[2].kind, Some(STYPE_DISKTREE));

    let mut bob = ipc_client(server.addr, SMB21, Some("bob")).await;
    let file_id = bob.srvsvc().await;
    assert_eq!(
        bob.list_shares(file_id, 1).await.names(),
        ["public", "docs", "IPC$"]
    );
}

#[tokio::test]
async fn share_get_info_finds_only_the_shares_listed_to_the_caller() {
    let (server, _td) = listing_server().await;
    let mut alice = ipc_client(server.addr, SMB21, Some("alice")).await;
    let a = alice.srvsvc().await;
    let mut bob = ipc_client(server.addr, SMB21, Some("bob")).await;
    let b = bob.srvsvc().await;
    let get = async |c: &mut Client, file_id, name: &str, level| {
        let stub = c
            .call(
                file_id,
                9,
                OPNUM_SHARE_GET_INFO,
                &get_info_request(name, level),
            )
            .await
            .expect("NetrShareGetInfo");
        decode_get_info(&stub)
    };

    assert_eq!(
        get(&mut alice, a, "HOME", 1).await,
        (1, Some(entry("home", STYPE_DISKTREE, "")), 0)
    );
    assert_eq!(
        get(&mut bob, b, "home", 1).await,
        (1, None, NERR_NET_NAME_NOT_FOUND)
    );
    assert_eq!(
        get(&mut alice, a, "archive", 1).await,
        (1, Some(entry("archive", STYPE_DISKTREE, "")), 0),
        "an unlisted share is found by those who may connect to it"
    );
    assert_eq!(
        get(&mut bob, b, "archive", 1).await,
        (1, None, NERR_NET_NAME_NOT_FOUND)
    );
    assert_eq!(
        get(&mut bob, b, "ipc$", 501).await,
        (
            501,
            Some(Entry {
                flags: Some(0),
                ..entry("IPC$", STYPE_IPC_SPECIAL, "Remote IPC")
            }),
            0
        )
    );
    let (_, info, status) = get(&mut bob, b, "docs", 0).await;
    assert_eq!(
        (info.map(|e| e.name), status),
        (Some("docs".to_string()), 0)
    );
    let (_, info, status) = get(&mut bob, b, "docs", 1005).await;
    assert_eq!((info.and_then(|e| e.flags), status), (Some(0), 0));
    assert_eq!(
        get(&mut bob, b, "", 1).await,
        (1, None, ERROR_INVALID_PARAMETER)
    );
    for level in [2, 502, 503] {
        assert_eq!(
            get(&mut alice, a, "home", level).await,
            (level, None, ERROR_ACCESS_DENIED)
        );
    }
    assert_eq!(get(&mut alice, a, "home", 7).await.2, ERROR_INVALID_LEVEL);
}

#[tokio::test]
async fn server_get_info_reports_the_netbios_name() {
    let (server, _td) = listing_server().await;
    let mut c = ipc(&server).await;
    let file_id = c.srvsvc().await;
    let get = async |c: &mut Client, level| {
        let stub = c
            .call(
                file_id,
                3,
                OPNUM_SERVER_GET_INFO,
                &server_info_request(level),
            )
            .await
            .expect("NetrServerGetInfo");
        decode_server_info(&stub)
    };
    let info = |details| ServerInfo {
        platform_id: 500,
        name: "LISTSRV".to_string(),
        details,
    };
    assert_eq!(get(&mut c, 100).await, (100, Some(info(None)), 0));
    assert_eq!(
        get(&mut c, 101).await,
        (101, Some(info(Some((10, 0, 0x9003, String::new())))), 0)
    );
    assert_eq!(get(&mut c, 102).await, (102, None, ERROR_ACCESS_DENIED));
}

#[tokio::test]
async fn share_enum_refuses_the_levels_it_does_not_serve() {
    let (server, _td) = listing_server().await;
    let mut c = ipc(&server).await;
    let file_id = c.srvsvc().await;
    for (level, status) in [(2, 5), (502, 5), (503, 5), (9, ERROR_INVALID_LEVEL)] {
        let stub = c
            .call(
                file_id,
                4,
                OPNUM_SHARE_ENUM,
                &enum_request(level, u32::MAX, Some(0)),
            )
            .await;
        let reply = decode_enum(&stub.expect("NetrShareEnum"));
        assert_eq!((reply.level, reply.status), (level, status));
        assert!(reply.entries.is_empty());
        assert_eq!(reply.total, 0);
    }
}

#[tokio::test]
async fn the_list_follows_the_configuration_on_a_bound_pipe() {
    let (builder, td) = listing_builder();
    let server = Server::start(builder).await;
    let mut alice = ipc_client(server.addr, SMB21, Some("alice")).await;
    let a = alice.srvsvc().await;
    let mut bob = ipc_client(server.addr, SMB21, Some("bob")).await;
    let b = bob.srvsvc().await;
    let local = || common::client::local(td.path());

    server
        .config
        .add_share(Share::new("music", local()).public().remark("Música"))
        .await
        .unwrap();
    let reply = bob.list_shares(b, 1).await;
    assert_eq!(reply.names(), ["public", "docs", "music", "IPC$"]);
    assert_eq!(reply.entries[2].remark.as_deref(), Some("Música"));

    // A share removed and added again goes last.
    server.config.remove_share("public").await.unwrap();
    assert_eq!(
        bob.list_shares(b, 1).await.names(),
        ["docs", "music", "IPC$"]
    );
    server
        .config
        .add_share(Share::new("public", local()).public())
        .await
        .unwrap();
    assert_eq!(
        bob.list_shares(b, 1).await.names(),
        ["docs", "music", "public", "IPC$"]
    );

    server
        .config
        .revoke_share_user("home", "alice")
        .await
        .unwrap();
    assert_eq!(
        alice.list_shares(a, 1).await.names(),
        ["secret$", "docs", "music", "public", "IPC$"]
    );
    server
        .config
        .set_share_mode("home", ShareMode::Public)
        .await
        .unwrap();
    assert_eq!(
        bob.list_shares(b, 1).await.names(),
        ["home", "docs", "music", "public", "IPC$"]
    );

    // The user's sessions end with the user, and their pipes with them.
    server.config.remove_user("alice").await.unwrap();
    let request = request_pdu(9, FIRST | LAST, 0, 15, &enum_request(1, u32::MAX, None));
    assert_eq!(
        alice.pipe_write(a, &request).await,
        STATUS_USER_SESSION_DELETED
    );
}

#[tokio::test]
async fn turned_off_share_listing_opens_no_pipe() {
    let (builder, _td) = listing_builder();
    let server = Server::start(builder.share_listing(false)).await;
    let mut c = ipc(&server).await;
    assert_eq!(
        c.open_pipe("srvsvc").await.err(),
        Some(STATUS_OBJECT_NAME_NOT_FOUND)
    );
    let mut input = 0i64.to_le_bytes().to_vec();
    input.extend_from_slice(&12u32.to_le_bytes());
    input.extend_from_slice(&[0, 0]);
    input.extend_from_slice(&utf16le("srvsvc"));
    let wait = ioctl_body(
        Fsctl::PIPE_WAIT,
        FileId::any(),
        &input,
        0,
        IoctlRequest::FLAG_IS_FSCTL,
    );
    assert_eq!(
        c.send(Command::Ioctl, &wait).await.0,
        STATUS_OBJECT_NAME_NOT_FOUND
    );
}

#[tokio::test]
async fn a_long_list_comes_in_fragments_of_the_negotiated_size() {
    let remark = "r".repeat(40);
    let mut builder = SmbServer::builder();
    for i in 0..400 {
        builder = builder.share(
            Share::new(format!("share{i:03}"), Unopened)
                .public()
                .remark(remark.clone()),
        );
    }
    let server = Server::start(builder).await;
    let mut c = ipc(&server).await;
    let file_id = c.open_pipe("srvsvc").await.expect("open").file_id;
    let bind = bind_pdu(1, 2048, &[(0, SRVSVC, NDR)]);
    assert_eq!(c.pipe_write(file_id, &bind).await, STATUS_SUCCESS);
    let (_, ack) = c.pipe_read(file_id, 4280).await;
    assert_eq!(&ack[16..20], [0, 8, 0, 8], "2048 both ways");

    let request = request_pdu(2, FIRST | LAST, 0, 15, &enum_request(1, u32::MAX, Some(0)));
    let (status, head) = c.transceive(file_id, &request, 1024).await;
    assert_eq!((status, head.len()), (STATUS_BUFFER_OVERFLOW, 1024));
    let (status, rest) = c.pipe_read(file_id, 4096).await;
    assert_eq!(status, STATUS_SUCCESS);
    let mut fragments = vec![[head, rest].concat()];
    loop {
        let (status, head) = c.pipe_read(file_id, 100).await;
        if status == STATUS_SUCCESS {
            fragments.push(head);
            break;
        }
        assert_eq!((status, head.len()), (STATUS_BUFFER_OVERFLOW, 100));
        let (status, rest) = c.pipe_read(file_id, 4096).await;
        assert_eq!(status, STATUS_SUCCESS);
        let fragment = [head, rest].concat();
        let last = pfc_flags(&fragment) & LAST != 0;
        fragments.push(fragment);
        if last {
            break;
        }
    }

    let total: usize = fragments.iter().map(|f| f.len() - 24).sum();
    let mut left = total;
    let mut stub = Vec::new();
    for (i, fragment) in fragments.iter().enumerate() {
        assert_pdu(fragment, PTYPE_RESPONSE);
        assert!(fragment.len() <= 2048);
        let flags = pfc_flags(fragment);
        assert_eq!(flags & FIRST != 0, i == 0);
        assert_eq!(flags & LAST != 0, i == fragments.len() - 1);
        let alloc_hint = u32::from_le_bytes(fragment[16..20].try_into().unwrap());
        assert_eq!(alloc_hint as usize, left);
        left -= fragment.len() - 24;
        stub.extend_from_slice(&fragment[24..]);
    }
    assert!(fragments.len() > 10);
    let reply = decode_enum(&stub);
    assert_eq!(reply.entries.len(), 401);
    assert_eq!(reply.entries[399].remark.as_deref(), Some(remark.as_str()));
    assert_eq!(reply.names()[400], "IPC$");
}

#[tokio::test]
async fn pages_put_together_make_the_whole_list() {
    let (server, _td) = listing_server().await;
    let mut c = ipc_client(server.addr, SMB21, Some("alice")).await;
    let file_id = c.srvsvc().await;
    let whole = c.list_shares(file_id, 1).await;
    let mut names = Vec::new();
    let mut resume = 0;
    let mut pages = 0;
    loop {
        let stub = c
            .call(
                file_id,
                10 + pages,
                OPNUM_SHARE_ENUM,
                &enum_request(1, 200, Some(resume)),
            )
            .await
            .expect("a page");
        let page = decode_enum(&stub);
        pages += 1;
        assert_eq!(page.total as usize, whole.entries.len() - names.len());
        names.extend(page.entries.iter().map(|e| e.name.clone()));
        if page.status == 0 {
            assert_eq!(page.resume, Some(0));
            break;
        }
        assert_eq!(page.status, ERROR_MORE_DATA);
        resume = page.resume.expect("a resume handle");
        assert_eq!(resume as usize, names.len());
    }
    assert!(pages > 1);
    assert_eq!(names, whole.names());
}

#[tokio::test]
async fn every_dialect_lists_the_shares() {
    let (server, _td) = listing_server().await;
    for dialect in [0x0202, 0x0210, 0x0300, 0x0302] {
        let mut c = ipc_client(server.addr, dialect, None).await;
        let file_id = c.srvsvc().await;
        assert_eq!(
            c.list_shares(file_id, 1).await.names(),
            ["public", "docs", "IPC$"],
            "{dialect:#x}"
        );
    }
}

/// Opens srvsvc, binds it and lists the shares at level 1 on a session
/// whose requests `send` sends, one at a time, returning each response.
async fn list_through(mut send: impl AsyncFnMut(Command, &[u8]) -> Vec<u8>) -> Vec<String> {
    let reply = send(Command::Create, &pipe_create("srvsvc").body()).await;
    assert_eq!(common::auth::status(&reply), 0, "CREATE");
    let file_id = CreateResponse::parse(&reply[64..]).expect("create").file_id;
    let mut write = Vec::new();
    write_request(file_id, 0, &srvsvc_bind(1))
        .write_to(&mut write)
        .unwrap();
    assert_eq!(common::auth::status(&send(Command::Write, &write).await), 0);
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
    .unwrap();
    let reply = send(Command::Read, &read).await;
    assert_pdu(
        &ReadResponse::parse(&reply[64..]).unwrap().data,
        PTYPE_BIND_ACK,
    );

    let request = request_pdu(2, FIRST | LAST, 0, 15, &enum_request(1, u32::MAX, None));
    let reply = send(Command::Ioctl, &transceive_body(file_id, &request, 4280)).await;
    assert_eq!(common::auth::status(&reply), 0, "IOCTL");
    let response = smb_server::wire::messages::IoctlResponse::parse(&reply[64..])
        .unwrap()
        .output;
    decode_enum(&response[24..])
        .entries
        .into_iter()
        .map(|e| e.name)
        .collect()
}

#[tokio::test]
async fn an_encrypted_session_lists_the_shares() {
    use common::crypto::{Cipher, EncryptedSession};

    let (builder, _td) = listing_builder();
    let server = Server::start(builder.encrypt_data(true)).await;
    let mut s =
        EncryptedSession::smb311(server.addr, &[Cipher::Aes128Gcm], "alice", "password").await;
    let reply = s.tree_connect("\\\\127.0.0.1\\IPC$").await;
    assert_eq!(common::auth::status(&reply), 0);
    let names = list_through(async |command, body| s.send_encrypted(command, body).await).await;
    assert_eq!(names, ["public", "home", "secret$", "docs", "IPC$"]);
}

#[tokio::test]
async fn shares_whose_traffic_is_encrypted_are_listed_to_sessions_that_can_encrypt() {
    use common::crypto::EncryptedSession;

    let td = tempfile::tempdir().expect("tempdir");
    let local = || common::client::local(td.path());
    let builder = SmbServer::builder()
        .user("alice", "password")
        .share(Share::new("open", local()).public())
        .share(
            Share::new("sealed", local())
                .user("alice", Access::Read)
                .encrypt_data(),
        );
    let server = Server::start(builder).await;

    for user in [None, Some("alice")] {
        let mut c = ipc_client(server.addr, SMB21, user).await;
        let file_id = c.srvsvc().await;
        assert_eq!(
            c.list_shares(file_id, 1).await.names(),
            ["open", "IPC$"],
            "{user:?}"
        );
        let stub = c
            .call(
                file_id,
                3,
                OPNUM_SHARE_GET_INFO,
                &get_info_request("sealed", 1),
            )
            .await
            .expect("NetrShareGetInfo");
        assert_eq!(
            decode_get_info(&stub).2,
            NERR_NET_NAME_NOT_FOUND,
            "{user:?}"
        );
    }

    let mut s = EncryptedSession::smb30(server.addr, SMB302, "alice", "password").await;
    let reply = s.tree_connect("\\\\127.0.0.1\\IPC$").await;
    assert_eq!(common::auth::status(&reply), 0);
    let names = list_through(async |command, body| s.send_encrypted(command, body).await).await;
    assert_eq!(names, ["open", "sealed", "IPC$"]);
}

#[tokio::test]
async fn a_signed_smb311_session_lists_the_shares() {
    use common::auth::{negotiate_311_body, preauth_context};
    use common::crypto::{
        Cipher, PREAUTH_SHA512, cmac_sign, hashed_login, hashed_negotiate, keys_311,
    };
    use smb_server::wire::header::SMB2_FLAGS_SIGNED;
    use tokio::io::AsyncWriteExt;

    let (builder, _td) = listing_builder();
    let server = Server::start(builder).await;
    let mut s = tokio::net::TcpStream::connect(server.addr)
        .await
        .expect("connect");
    let mut hash = [0u8; 64];
    let body = negotiate_311_body(&[0x0311], &[preauth_context(&[PREAUTH_SHA512])]);
    let negotiate = hashed_negotiate(&mut s, &body, &mut hash).await;
    assert_eq!(common::auth::status(&negotiate), 0);
    let login = hashed_login(&mut s, 1, "alice", "password", &mut hash).await;
    assert_eq!(login.status, 0);
    // The signing key does not depend on the cipher, and none was agreed.
    let key = keys_311(&login.key, Cipher::Aes128Gcm, &hash).signing;

    let mut mid = 3;
    let mut tree_id = 0;
    let mut send = async |command: Command, body: &[u8]| {
        let hdr = common::build_header(command, mid, login.session_id, tree_id);
        mid += 1;
        let mut msg = common::message(&hdr, body);
        cmac_sign(&mut msg, &key);
        s.write_all(&common::framed(&msg)).await.expect("write");
        let reply = common::read_frame(&mut s).await;
        let (rh, _) = common::parse_response_header(&reply);
        assert_ne!(rh.flags & SMB2_FLAGS_SIGNED, 0, "{command:?} reply signed");
        if command == Command::TreeConnect {
            tree_id = rh.tree_id().expect("tree id");
        }
        reply
    };
    let reply = send(
        Command::TreeConnect,
        &common::tree_connect_body("\\\\127.0.0.1\\IPC$"),
    )
    .await;
    assert_eq!(common::auth::status(&reply), 0);
    let names = list_through(send).await;
    assert_eq!(names, ["public", "home", "secret$", "docs", "IPC$"]);
}

/// A backend that holds no file and opens nothing, for shares that are
/// only listed.
struct Unopened;

#[async_trait::async_trait]
impl smb_server::ShareBackend for Unopened {
    async fn open(
        &self,
        _path: &smb_server::SmbPath,
        _opts: smb_server::OpenOptions,
    ) -> smb_server::SmbResult<(Box<dyn smb_server::Handle>, smb_server::OpenAction)> {
        Err(smb_server::SmbError::NotSupported)
    }

    async fn unlink(&self, _path: &smb_server::SmbPath) -> smb_server::SmbResult<()> {
        Err(smb_server::SmbError::NotSupported)
    }

    async fn rename(
        &self,
        _from: &smb_server::SmbPath,
        _to: &smb_server::SmbPath,
        _replace_if_exists: bool,
    ) -> smb_server::SmbResult<()> {
        Err(smb_server::SmbError::NotSupported)
    }

    fn capabilities(&self) -> smb_server::BackendCapabilities {
        smb_server::BackendCapabilities::default()
    }
}
