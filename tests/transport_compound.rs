//! Related compounded requests.

mod common;

use common::transport::{
    ECHO_BODY, anonymous_session, compound, create_body, read_response, with_share,
};
use common::{build_header, message, start_server, tree_connect_body};
use smb_server::ntstatus::{
    STATUS_INVALID_HANDLE, STATUS_INVALID_PARAMETER, STATUS_OBJECT_NAME_NOT_FOUND,
};
use smb_server::wire::header::{Command, SMB2_FLAGS_RELATED_OPERATIONS, Smb2Header};
use smb_server::wire::messages::{CloseRequest, FileId, QueryInfoRequest};
use tempfile::TempDir;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

const RELATED_FILE_ID: FileId = FileId::new(u64::MAX, u64::MAX);

/// Server with a public share holding `f.txt`, and an anonymous session
/// on it; the next free MessageId is 3.
async fn session() -> (TcpStream, u64, TempDir, tokio::task::JoinHandle<()>) {
    let (builder, td) = with_share(&[("f.txt", b"data")]);
    let (addr, handle) = start_server(builder).await;
    let (s, session_id) = anonymous_session(addr).await;
    (s, session_id, td, handle)
}

fn related(command: Command, message_id: u64, body: &[u8]) -> Vec<u8> {
    let mut hdr = build_header(command, message_id, u64::MAX, u32::MAX);
    hdr.flags |= SMB2_FLAGS_RELATED_OPERATIONS;
    message(&hdr, body)
}

fn query_info_body() -> Vec<u8> {
    let mut body = Vec::new();
    QueryInfoRequest {
        structure_size: 41,
        info_type: 1,
        file_information_class: 5,
        output_buffer_length: 4096,
        input_buffer_offset: 0,
        reserved: 0,
        input_buffer_length: 0,
        additional_information: 0,
        flags: 0,
        file_id: RELATED_FILE_ID,
        input_buffer: vec![],
    }
    .write_to(&mut body)
    .expect("query info");
    body
}

fn close_body() -> Vec<u8> {
    let mut body = Vec::new();
    CloseRequest {
        structure_size: 24,
        flags: 0,
        reserved: 0,
        file_id: RELATED_FILE_ID,
    }
    .write_to(&mut body)
    .expect("close");
    body
}

/// Header of each response in a compound response.
async fn responses(s: &mut TcpStream) -> Vec<Smb2Header> {
    let (_, frame) = read_response(s).await;
    let mut out = Vec::new();
    let mut rest = &frame[..];
    loop {
        let (hdr, _) = Smb2Header::parse(rest).expect("response header");
        let next = hdr.next_command as usize;
        out.push(hdr);
        if next == 0 {
            return out;
        }
        rest = &rest[next..];
    }
}

fn statuses(headers: &[Smb2Header]) -> Vec<u32> {
    headers.iter().map(|h| h.channel_sequence_status).collect()
}

#[tokio::test]
async fn a_failed_create_fails_the_requests_that_use_its_file() {
    let (mut s, session_id, _td, handle) = session().await;
    let tree_id = common::tree_connect(&mut s, "\\\\server\\share", session_id, 3).await;

    let mut create = create_body("missing.txt");
    // FILE_OPEN
    create[36..40].copy_from_slice(&1u32.to_le_bytes());
    let first = message(
        &build_header(Command::Create, 4, session_id, tree_id),
        &create,
    );
    s.write_all(&compound(&[
        first,
        related(Command::QueryInfo, 5, &query_info_body()),
        related(Command::Close, 6, &close_body()),
    ]))
    .await
    .expect("write");
    assert_eq!(
        statuses(&responses(&mut s).await),
        [STATUS_OBJECT_NAME_NOT_FOUND; 3]
    );
    handle.abort();
}

#[tokio::test]
async fn a_related_request_uses_the_tree_a_tree_connect_created() {
    let (mut s, session_id, _td, handle) = session().await;

    let tree_connect = tree_connect_body("\\\\server\\share");
    let first = message(
        &build_header(Command::TreeConnect, 3, session_id, 0),
        &tree_connect,
    );
    s.write_all(&compound(&[
        first,
        related(Command::Create, 4, &create_body("f.txt")),
        related(Command::Close, 5, &close_body()),
    ]))
    .await
    .expect("write");
    let headers = responses(&mut s).await;
    assert_eq!(statuses(&headers), [0, 0, 0]);
    let tree_id = headers[0].tree_id().expect("tree id");
    assert_ne!(tree_id, 0);
    assert_eq!(headers[1].tree_id(), Some(tree_id));
    handle.abort();
}

#[tokio::test]
async fn a_chain_that_starts_related_fails() {
    let (mut s, _, _td, handle) = session().await;
    s.write_all(&compound(&[
        related(Command::Echo, 3, &ECHO_BODY),
        related(Command::Echo, 4, &ECHO_BODY),
    ]))
    .await
    .expect("write");
    assert_eq!(
        statuses(&responses(&mut s).await),
        [STATUS_INVALID_PARAMETER; 2]
    );
    handle.abort();
}

#[tokio::test]
async fn a_related_request_needs_a_file_from_the_one_before() {
    let (mut s, session_id, _td, handle) = session().await;
    let tree_id = common::tree_connect(&mut s, "\\\\server\\share", session_id, 3).await;
    let first = message(
        &build_header(Command::Echo, 4, session_id, tree_id),
        &ECHO_BODY,
    );
    s.write_all(&compound(&[
        first,
        related(Command::QueryInfo, 5, &query_info_body()),
        related(Command::Close, 6, &close_body()),
    ]))
    .await
    .expect("write");
    assert_eq!(
        statuses(&responses(&mut s).await),
        [0, STATUS_INVALID_HANDLE, STATUS_INVALID_HANDLE]
    );
    handle.abort();
}
