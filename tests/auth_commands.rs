//! Session, tree and FileId checks of ECHO, OPLOCK_BREAK and CHANGE_NOTIFY.

#![cfg(feature = "localfs")]

mod common;

use common::auth::*;
use common::client::{Create, FILE_DIRECTORY_FILE, FILE_READ_ATTRIBUTES};
use common::{anonymous_session_setup, negotiate, start_server, tree_connect};
use smb_server::ntstatus::{
    STATUS_ACCESS_DENIED, STATUS_FILE_CLOSED, STATUS_INVALID_DEVICE_STATE,
    STATUS_INVALID_PARAMETER, STATUS_NETWORK_NAME_DELETED, STATUS_NOT_SUPPORTED,
    STATUS_USER_SESSION_DELETED,
};
use smb_server::wire::header::Command;
use smb_server::wire::messages::FileId;
use smb_server::{LocalFsBackend, Share, SmbServer};
use tokio::net::TcpStream;

struct Conn {
    s: TcpStream,
    sid: u64,
    tid: u32,
    mid: u64,
    _handle: tokio::task::JoinHandle<()>,
    _td: tempfile::TempDir,
}

async fn connect() -> Conn {
    let td = tempfile::tempdir().expect("tempdir");
    std::fs::write(td.path().join("f.txt"), b"x").unwrap();
    std::fs::create_dir(td.path().join("d")).unwrap();
    let backend = LocalFsBackend::new(td.path()).expect("open root");
    let (addr, handle) =
        start_server(SmbServer::builder().share(Share::new("pub", backend).public())).await;
    let mut s = TcpStream::connect(addr).await.expect("connect");
    negotiate(&mut s).await;
    let sid = anonymous_session_setup(&mut s).await;
    let tid = tree_connect(&mut s, r"\\srv\pub", sid, 3).await;
    Conn {
        s,
        sid,
        tid,
        mid: 10,
        _handle: handle,
        _td: td,
    }
}

impl Conn {
    async fn send(&mut self, command: Command, sid: u64, tid: u32, body: &[u8]) -> u32 {
        self.mid += 1;
        status(&request(&mut self.s, command, self.mid, sid, tid, body).await)
    }

    async fn open(&mut self, name: &str, access: u32, options: u32) -> FileId {
        self.mid += 1;
        let body = Create {
            name,
            access,
            options,
            ..Create::default()
        }
        .body();
        let frame = request(
            &mut self.s,
            Command::Create,
            self.mid,
            self.sid,
            self.tid,
            &body,
        )
        .await;
        created_file_id(&frame)
    }
}

fn echo_body() -> Vec<u8> {
    vec![4, 0, 0, 0]
}

fn oplock_ack(file_id: FileId) -> Vec<u8> {
    let mut body = vec![24, 0, 0, 0, 0, 0, 0, 0];
    body.extend_from_slice(&file_id.persistent.to_le_bytes());
    body.extend_from_slice(&file_id.volatile.to_le_bytes());
    body
}

fn change_notify(file_id: FileId) -> Vec<u8> {
    let mut body = vec![32, 0, 0, 0];
    body.extend_from_slice(&1024u32.to_le_bytes());
    body.extend_from_slice(&file_id.persistent.to_le_bytes());
    body.extend_from_slice(&file_id.volatile.to_le_bytes());
    body.extend_from_slice(&0x17u32.to_le_bytes());
    body.extend_from_slice(&0u32.to_le_bytes());
    body
}

#[tokio::test]
async fn echo_checks_a_nonzero_session_id() {
    let mut c = connect().await;
    assert_eq!(c.send(Command::Echo, 0, 0, &echo_body()).await, 0);
    let sid = c.sid;
    assert_eq!(c.send(Command::Echo, sid, 0, &echo_body()).await, 0);
    assert_eq!(
        c.send(Command::Echo, 0x1234, 0, &echo_body()).await,
        STATUS_USER_SESSION_DELETED
    );
}

#[tokio::test]
async fn echo_without_a_session_is_refused() {
    let td = tempfile::tempdir().expect("tempdir");
    let backend = LocalFsBackend::new(td.path()).expect("open root");
    let (addr, _handle) =
        start_server(SmbServer::builder().share(Share::new("pub", backend).public())).await;
    let mut s = TcpStream::connect(addr).await.expect("connect");
    negotiate(&mut s).await;
    let hdr = common::build_header(Command::Echo, 1, 0, 0);
    common::write_frame(&mut s, &hdr, &echo_body()).await;
    let reply = read_or_closed(&mut s).await;
    assert!(reply.is_none_or(|f| status(&f) != 0));
}

#[tokio::test]
async fn oplock_break_ack_needs_a_breaking_open() {
    let mut c = connect().await;
    let (sid, tid) = (c.sid, c.tid);
    let ack = oplock_ack(FileId::any());
    assert_eq!(
        c.send(Command::OplockBreak, 0, tid, &ack).await,
        STATUS_USER_SESSION_DELETED
    );
    assert_eq!(
        c.send(Command::OplockBreak, sid, 77, &ack).await,
        STATUS_NETWORK_NAME_DELETED
    );
    assert_eq!(
        c.send(Command::OplockBreak, sid, tid, &ack).await,
        STATUS_FILE_CLOSED
    );
    let file = c.open("f.txt", 0x0012_0089, 0).await;
    assert_eq!(
        c.send(Command::OplockBreak, sid, tid, &oplock_ack(file))
            .await,
        STATUS_INVALID_DEVICE_STATE
    );
}

#[tokio::test]
async fn change_notify_checks_come_before_not_supported() {
    let mut c = connect().await;
    let (sid, tid) = (c.sid, c.tid);
    let any = change_notify(FileId::any());
    assert_eq!(
        c.send(Command::ChangeNotify, 0, tid, &any).await,
        STATUS_USER_SESSION_DELETED
    );
    assert_eq!(
        c.send(Command::ChangeNotify, sid, tid, &any).await,
        STATUS_FILE_CLOSED
    );
    let file = c.open("f.txt", 0x0012_0089, 0).await;
    assert_eq!(
        c.send(Command::ChangeNotify, sid, tid, &change_notify(file))
            .await,
        STATUS_INVALID_PARAMETER
    );
    let dir = c.open("d", FILE_READ_ATTRIBUTES, FILE_DIRECTORY_FILE).await;
    assert_eq!(
        c.send(Command::ChangeNotify, sid, tid, &change_notify(dir))
            .await,
        STATUS_ACCESS_DENIED
    );
    let dir = c.open("d", 0x0012_0089, FILE_DIRECTORY_FILE).await;
    assert_eq!(
        c.send(Command::ChangeNotify, sid, tid, &change_notify(dir))
            .await,
        STATUS_NOT_SUPPORTED
    );
}
