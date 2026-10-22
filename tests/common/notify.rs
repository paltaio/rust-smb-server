//! CHANGE_NOTIFY requests and the FILE_NOTIFY_INFORMATION entries of their
//! responses.

use std::time::Duration;

use smb_server::wire::header::Command;
use smb_server::wire::messages::{ChangeNotifyRequest, ChangeNotifyResponse, FileId};

use super::client::{Client, interim};

pub use smb_server::wire::messages::change_notify::{
    FILE_ACTION_ADDED, FILE_ACTION_MODIFIED, FILE_ACTION_REMOVED, FILE_ACTION_RENAMED_NEW_NAME,
    FILE_ACTION_RENAMED_OLD_NAME, FILE_NOTIFY_CHANGE_DIR_NAME, FILE_NOTIFY_CHANGE_FILE_NAME,
};

/// How long a test waits for an answer before it fails.
pub const NOTIFY_WAIT: Duration = Duration::from_secs(5);

/// `fut`, failing the test when it takes longer than [`NOTIFY_WAIT`].
pub async fn within<T>(fut: impl Future<Output = T>) -> T {
    tokio::time::timeout(NOTIFY_WAIT, fut)
        .await
        .expect("no answer in time")
}

/// FILE_NAME | DIR_NAME.
pub const NAMES: u32 = FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_DIR_NAME;

/// A CHANGE_NOTIFY body for `file_id` with OutputBufferLength `len`,
/// CompletionFilter `filter` and SMB2_WATCH_TREE when `tree`.
pub fn notify_body(file_id: FileId, len: u32, filter: u32, tree: bool) -> Vec<u8> {
    let mut body = Vec::new();
    ChangeNotifyRequest {
        structure_size: 32,
        flags: if tree {
            ChangeNotifyRequest::FLAG_WATCH_TREE
        } else {
            0
        },
        output_buffer_length: len,
        file_id,
        completion_filter: filter,
        reserved: 0,
    }
    .write_to(&mut body)
    .expect("write");
    body
}

/// (action, name) of each entry in the response body `body` to a request
/// with OutputBufferLength `len`. Checks what MS-FSCC 2.7.1 and the client
/// checks of MS-SMB2 3.2.5.16 require: the buffer fits `len`, entries are
/// 4-byte aligned, the last has NextEntryOffset 0, and names start with
/// no separator and hold no `"`.
pub fn notify_entries(body: &[u8], len: u32) -> Vec<(u32, String)> {
    let resp = ChangeNotifyResponse::parse(body).expect("CHANGE_NOTIFY body");
    assert_eq!(resp.structure_size, 9);
    let buf = resp.buffer;
    if buf.is_empty() {
        return Vec::new();
    }
    assert_eq!(resp.output_buffer_offset, 0x48);
    assert!(buf.len() <= len as usize, "buffer larger than asked for");
    let mut out = Vec::new();
    let mut at = 0;
    loop {
        let field = |o: usize| u32::from_le_bytes(buf[at + o..at + o + 4].try_into().unwrap());
        let (next, action, name_len) = (field(0) as usize, field(4), field(8) as usize);
        let units: Vec<u16> = buf[at + 12..at + 12 + name_len]
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        let name = String::from_utf16(&units).expect("UTF-16 name");
        assert!(
            !name.starts_with(['\\', '/']) && !name.contains('"'),
            "{name}"
        );
        out.push((action, name));
        if next == 0 {
            assert_eq!(at + 12 + name_len, buf.len(), "bytes after the last entry");
            return out;
        }
        assert_eq!(next % 4, 0);
        assert!(next >= 12 + name_len);
        at += next;
    }
}

/// Sends a CHANGE_NOTIFY that has to wait; returns its MessageId once its
/// interim response arrived.
pub async fn arm(client: &mut Client, dir: FileId, len: u32, filter: u32, tree: bool) -> u64 {
    let mid = client
        .send_no_wait(Command::ChangeNotify, &notify_body(dir, len, filter, tree))
        .await;
    within(client.recv_interim(mid)).await;
    mid
}

/// Sends a CHANGE_NOTIFY on `dir` and returns the status and body of its
/// final response.
pub async fn ask(
    client: &mut Client,
    dir: FileId,
    len: u32,
    filter: u32,
    tree: bool,
) -> (u32, Vec<u8>) {
    let body = notify_body(dir, len, filter, tree);
    within(client.send(Command::ChangeNotify, &body)).await
}

/// The status and entries of the final response to the CHANGE_NOTIFY
/// `mid`, sent with OutputBufferLength `len`.
pub async fn wait_notify(client: &mut Client, mid: u64, len: u32) -> (u32, Vec<(u32, String)>) {
    let (status, body) = within(client.recv(mid, Command::ChangeNotify)).await;
    (status, notify_entries(&body, len))
}

pub fn added(name: &str) -> (u32, String) {
    (FILE_ACTION_ADDED, name.to_string())
}

pub fn removed(name: &str) -> (u32, String) {
    (FILE_ACTION_REMOVED, name.to_string())
}

pub fn old_name(name: &str) -> (u32, String) {
    (FILE_ACTION_RENAMED_OLD_NAME, name.to_string())
}

pub fn new_name(name: &str) -> (u32, String) {
    (FILE_ACTION_RENAMED_NEW_NAME, name.to_string())
}

pub fn modified(name: &str) -> (u32, String) {
    (FILE_ACTION_MODIFIED, name.to_string())
}

/// Arms a watch on `dir` and cancels the request, so later changes are
/// buffered with no request waiting.
pub async fn arm_idle(client: &mut Client, dir: FileId, filter: u32, tree: bool) {
    let body = notify_body(dir, 4096, filter, tree);
    let mid = client.send_no_wait(Command::ChangeNotify, &body).await;
    let async_id = within(client.recv_interim(mid)).await;
    client.cancel(mid, Some(async_id)).await;
    let (status, _) = within(client.recv(mid, Command::ChangeNotify)).await;
    assert_eq!(status, smb_server::ntstatus::STATUS_CANCELLED);
}

/// What a request on the armed watch `dir` gets at once, with `tree`, or
/// `None` when it would wait; such a request is cancelled.
pub async fn now(client: &mut Client, dir: FileId, tree: bool) -> Option<Vec<(u32, String)>> {
    let body = notify_body(dir, 4096, 0, tree);
    let mid = client.send_no_wait(Command::ChangeNotify, &body).await;
    let frame = within(client.next_frame()).await;
    match interim(&frame) {
        Some((_, async_id)) => {
            client.cancel(mid, Some(async_id)).await;
            let (status, _) = within(client.recv(mid, Command::ChangeNotify)).await;
            assert_eq!(status, smb_server::ntstatus::STATUS_CANCELLED);
            None
        }
        None => Some(notify_entries(&frame[64..], 4096)),
    }
}
