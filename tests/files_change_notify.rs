//! CHANGE_NOTIFY over the wire: what a client hears about files created
//! and deleted through other connections, buffering and overflow, signed
//! and encrypted answers, and how waiting requests end.

#![cfg(feature = "localfs")]

mod common;

use std::net::SocketAddr;

use common::auth::{
    LoginOptions, created_file_id, login_with, request, send, spnego_login, status,
};
use common::client::*;
use common::crypto::{Cipher, EncryptedSession, is_transform};
use common::notify::*;
use common::{build_header, negotiate, read_frame, smb2_signature, tree_connect_body, write_frame};
use smb_server::ntstatus::{
    STATUS_INVALID_PARAMETER, STATUS_LOGON_FAILURE, STATUS_NOTIFY_CLEANUP, STATUS_NOTIFY_ENUM_DIR,
    STATUS_PENDING, STATUS_SUCCESS,
};
use smb_server::wire::header::{Command, SMB2_FLAGS_SIGNED, Smb2Header};
use smb_server::wire::messages::FileId;
use smb_server::{Share, SmbServer, SmbServerBuilder};
use tokio::net::TcpStream;

const USER: &str = "alice";
const PASSWORD: &str = "password";

/// `builder` with alice and the public share `share`, whose root holds the
/// directory `d`.
async fn start(builder: SmbServerBuilder) -> (Server, tempfile::TempDir) {
    let td = tempfile::tempdir().expect("tempdir");
    std::fs::create_dir(td.path().join("d")).unwrap();
    let share = Share::new("share", local(td.path())).public();
    let server = Server::start(builder.user(USER, PASSWORD).share(share)).await;
    (server, td)
}

async fn server() -> (Server, tempfile::TempDir) {
    start(SmbServer::builder()).await
}

async fn create_file(c: &mut Client, name: &str) {
    let created = c
        .create(Create {
            name,
            disposition: FILE_CREATE,
            ..Create::default()
        })
        .await
        .expect("create");
    c.close(created.file_id).await;
}

async fn make_dir(c: &mut Client, name: &str) {
    let created = c
        .create(dir_create(name, FILE_CREATE))
        .await
        .expect("mkdir");
    c.close(created.file_id).await;
}

fn dir_create(name: &str, disposition: u32) -> Create<'_> {
    Create {
        name,
        access: FILE_GENERIC_READ,
        disposition,
        options: FILE_DIRECTORY_FILE,
        ..Create::default()
    }
}

/// Deletes `name` through an open with FILE_DELETE_ON_CLOSE and `options`.
async fn delete(c: &mut Client, name: &str, options: u32) {
    let file_id = c
        .open_with_options(name, DELETE, options | FILE_DELETE_ON_CLOSE)
        .await
        .expect("open for deletion");
    c.close(file_id).await;
}

#[tokio::test]
async fn created_and_deleted_entries_are_reported_to_another_client() {
    let (srv, _td) = server().await;
    let mut watcher = srv.client().await;
    let mut maker = srv.client().await;
    let dir = watcher.open_dir("d").await;

    let mid = arm(&mut watcher, dir, 4096, NAMES, false).await;
    create_file(&mut maker, "d\\x.txt").await;
    assert_eq!(
        wait_notify(&mut watcher, mid, 4096).await,
        (STATUS_SUCCESS, vec![added("x.txt")])
    );
    let mid = arm(&mut watcher, dir, 4096, NAMES, false).await;
    make_dir(&mut maker, "d\\sub").await;
    assert_eq!(
        wait_notify(&mut watcher, mid, 4096).await,
        (STATUS_SUCCESS, vec![added("sub")])
    );
    let mid = arm(&mut watcher, dir, 4096, NAMES, false).await;
    delete(&mut maker, "d\\x.txt", 0).await;
    assert_eq!(
        wait_notify(&mut watcher, mid, 4096).await,
        (STATUS_SUCCESS, vec![removed("x.txt")])
    );
    let mid = arm(&mut watcher, dir, 4096, NAMES, false).await;
    delete(&mut maker, "d\\sub", FILE_DIRECTORY_FILE).await;
    assert_eq!(
        wait_notify(&mut watcher, mid, 4096).await,
        (STATUS_SUCCESS, vec![removed("sub")])
    );
}

#[tokio::test]
async fn a_tree_watch_names_nested_changes_and_a_plain_watch_sees_only_its_entries() {
    let (srv, _td) = server().await;
    let mut watcher = srv.client().await;
    let mut maker = srv.client().await;
    let tree = watcher.open_dir("d").await;
    let plain = watcher.open_dir("d").await;
    let tree_mid = arm(&mut watcher, tree, 4096, NAMES, true).await;
    let plain_mid = arm(&mut watcher, plain, 4096, NAMES, false).await;
    make_dir(&mut maker, "d\\sub").await;
    for mid in [tree_mid, plain_mid] {
        assert_eq!(
            wait_notify(&mut watcher, mid, 4096).await,
            (STATUS_SUCCESS, vec![added("sub")])
        );
    }

    make_dir(&mut maker, "d\\sub\\deep").await;
    create_file(&mut maker, "d\\sub\\deep\\x").await;
    create_file(&mut maker, "d\\y").await;
    let (st, body) = ask(&mut watcher, tree, 4096, NAMES, true).await;
    assert_eq!(st, STATUS_SUCCESS);
    assert_eq!(
        notify_entries(&body, 4096),
        [added("sub\\deep"), added("sub\\deep\\x"), added("y")]
    );
    let (st, body) = ask(&mut watcher, plain, 4096, NAMES, false).await;
    assert_eq!(st, STATUS_SUCCESS);
    assert_eq!(notify_entries(&body, 4096), [added("y")]);
}

#[tokio::test]
async fn too_many_changes_between_requests_answer_enum_dir() {
    let (srv, _td) = server().await;
    let mut watcher = srv.client().await;
    let mut maker = srv.client().await;
    let dir = watcher.open_dir("d").await;
    let mid = arm(&mut watcher, dir, 1000, NAMES, true).await;
    create_file(&mut maker, "d\\first").await;
    assert_eq!(
        wait_notify(&mut watcher, mid, 1000).await,
        (STATUS_SUCCESS, vec![added("first")])
    );

    for i in 0..200 {
        create_file(&mut maker, &format!("d\\file{i:03}")).await;
    }
    let (st, body) = ask(&mut watcher, dir, 1000, NAMES, true).await;
    assert_eq!(st, STATUS_NOTIFY_ENUM_DIR);
    assert_eq!(body, [9, 0, 0x48, 0, 0, 0, 0, 0, 0]);

    let mid = arm(&mut watcher, dir, 1000, NAMES, true).await;
    create_file(&mut maker, "d\\last").await;
    assert_eq!(
        wait_notify(&mut watcher, mid, 1000).await,
        (STATUS_SUCCESS, vec![added("last")])
    );
}

/// Sends a CHANGE_NOTIFY on `dir` for OutputBufferLength `len` with
/// CreditCharge `charge`; returns its MessageId.
async fn send_charged(c: &mut Client, dir: FileId, len: u32, charge: u16) -> u64 {
    let mid = c.take_mid();
    for _ in 1..charge {
        c.take_mid();
    }
    let mut hdr = build_header(Command::ChangeNotify, mid, c.session_id, c.tree_id);
    hdr.credit_charge = charge;
    write_frame(&mut c.s, &hdr, &notify_body(dir, len, NAMES, false)).await;
    mid
}

#[tokio::test]
async fn output_buffer_lengths_from_zero_up_to_the_transact_size() {
    const MAX: u32 = 128 * 1024;
    let (srv, _td) = start(SmbServer::builder().max_read_size(MAX)).await;
    let mut watcher = srv.client().await;
    let mut maker = srv.client().await;

    // A watch whose first request has no room hears only that something
    // changed.
    let empty = watcher.open_dir("d").await;
    let mid = arm(&mut watcher, empty, 0, NAMES, false).await;
    create_file(&mut maker, "d\\a").await;
    assert_eq!(
        wait_notify(&mut watcher, mid, 0).await,
        (STATUS_NOTIFY_ENUM_DIR, vec![])
    );

    let dir = watcher.open_dir("d").await;
    let mid = send_charged(&mut watcher, dir, MAX + 1, 3).await;
    assert_eq!(
        within(watcher.recv(mid, Command::ChangeNotify)).await.0,
        STATUS_INVALID_PARAMETER
    );
    let mid = send_charged(&mut watcher, dir, MAX, 2).await;
    within(watcher.recv_interim(mid)).await;
    create_file(&mut maker, "d\\b").await;
    assert_eq!(
        wait_notify(&mut watcher, mid, MAX).await,
        (STATUS_SUCCESS, vec![added("b")])
    );
}

#[tokio::test]
async fn tree_disconnect_ends_a_waiting_request_with_cleanup() {
    let (srv, _td) = server().await;
    let mut watcher = srv.client().await;
    let dir = watcher.open_dir("d").await;
    let mid = arm(&mut watcher, dir, 4096, NAMES, false).await;
    // The two responses may come in either order.
    let disconnect = watcher
        .send_no_wait(Command::TreeDisconnect, &[4, 0, 0, 0])
        .await;
    assert_eq!(
        within(watcher.recv(disconnect, Command::TreeDisconnect))
            .await
            .0,
        STATUS_SUCCESS
    );
    let (st, body) = within(watcher.recv(mid, Command::ChangeNotify)).await;
    assert_eq!(st, STATUS_NOTIFY_CLEANUP);
    assert_eq!(body, [9, 0, 0x48, 0, 0, 0, 0, 0, 0]);
}

#[tokio::test]
async fn a_final_response_is_signed_like_its_request() {
    let (srv, _td) = server().await;
    let mut s = TcpStream::connect(srv.addr).await.expect("connect");
    negotiate(&mut s).await;
    let login = spnego_login(&mut s, 1, 0, USER, PASSWORD).await;
    assert_eq!(login.status, STATUS_SUCCESS);
    let (sid, key) = (login.session_id, login.key);
    let frame = send(
        &mut s,
        build_header(Command::TreeConnect, 3, sid, 0),
        &tree_connect_body(r"\\srv\share"),
        Some(&key),
    )
    .await;
    let tid = Smb2Header::parse(&frame).unwrap().0.tree_id().unwrap();
    let frame = send(
        &mut s,
        build_header(Command::Create, 4, sid, tid),
        &dir_create("d", FILE_OPEN).body(),
        Some(&key),
    )
    .await;
    let dir = created_file_id(&frame);
    let interim = send(
        &mut s,
        build_header(Command::ChangeNotify, 5, sid, tid),
        &notify_body(dir, 4096, NAMES, false),
        Some(&key),
    )
    .await;
    assert_eq!(status(&interim), STATUS_PENDING);

    let mut maker = srv.client().await;
    create_file(&mut maker, "d\\x").await;
    let last = within(read_frame(&mut s)).await;
    let (hdr, body) = Smb2Header::parse(&last).unwrap();
    assert_eq!((hdr.message_id, status(&last)), (5, STATUS_SUCCESS));
    assert_ne!(hdr.flags & SMB2_FLAGS_SIGNED, 0);
    assert_eq!(last[48..64], smb2_signature(&last, &key));
    assert_eq!(notify_entries(body, 4096), [added("x")]);
}

#[tokio::test]
async fn a_final_response_is_encrypted_like_its_request() {
    let (srv, _td) = server().await;
    let mut sess = EncryptedSession::smb311(srv.addr, &[Cipher::Aes128Gcm], USER, PASSWORD).await;
    assert_eq!(
        status(&sess.tree_connect(r"\\srv\share").await),
        STATUS_SUCCESS
    );
    let resp = sess
        .send_encrypted(Command::Create, &dir_create("d", FILE_OPEN).body())
        .await;
    let dir = created_file_id(&resp);
    let interim = sess
        .send_encrypted(Command::ChangeNotify, &notify_body(dir, 4096, NAMES, false))
        .await;
    assert_eq!(status(&interim), STATUS_PENDING);

    let mut maker = srv.client().await;
    create_file(&mut maker, "d\\x").await;
    let frame = within(read_frame(&mut sess.stream)).await;
    assert!(is_transform(&frame), "the final response is encrypted");
    let last = sess.open(&frame).expect("the final response decrypts");
    assert_eq!(status(&last), STATUS_SUCCESS);
    assert_eq!(notify_entries(&last[64..], 4096), [added("x")]);
}

/// A connection where alice waits on a CHANGE_NOTIFY on `d`, sent as
/// MessageId 5; returns it and alice's SessionId.
async fn alice_waiting(addr: SocketAddr) -> (TcpStream, u64) {
    let mut s = TcpStream::connect(addr).await.expect("connect");
    negotiate(&mut s).await;
    let sid = spnego_login(&mut s, 1, 0, USER, PASSWORD).await.session_id;
    let frame = request(
        &mut s,
        Command::TreeConnect,
        3,
        sid,
        0,
        &tree_connect_body(r"\\srv\share"),
    )
    .await;
    let tid = Smb2Header::parse(&frame).unwrap().0.tree_id().unwrap();
    let body = dir_create("d", FILE_OPEN).body();
    let dir = created_file_id(&request(&mut s, Command::Create, 4, sid, tid, &body).await);
    let body = notify_body(dir, 4096, NAMES, false);
    let interim = request(&mut s, Command::ChangeNotify, 5, sid, tid, &body).await;
    assert_eq!(status(&interim), STATUS_PENDING);
    (s, sid)
}

#[tokio::test]
async fn a_logon_naming_the_session_as_previous_ends_its_requests_with_cleanup() {
    let (srv, _td) = server().await;
    let (mut old, sid) = alice_waiting(srv.addr).await;
    let mut new = TcpStream::connect(srv.addr).await.expect("connect");
    negotiate(&mut new).await;
    let opts = LoginOptions {
        previous_session_id: sid,
        ..LoginOptions::default()
    };
    let login = login_with(&mut new, 1, 0, USER, PASSWORD, opts).await;
    assert_eq!(login.status, STATUS_SUCCESS);
    let last = within(read_frame(&mut old)).await;
    let hdr = Smb2Header::parse(&last).unwrap().0;
    assert_eq!((hdr.command, hdr.message_id), (Command::ChangeNotify, 5));
    assert_eq!(status(&last), STATUS_NOTIFY_CLEANUP);
}

#[tokio::test]
async fn a_failed_reauthentication_ends_the_sessions_requests_with_cleanup() {
    let (srv, _td) = server().await;
    let (mut s, sid) = alice_waiting(srv.addr).await;
    // The CHANGE_NOTIFY may be answered before the SESSION_SETUP.
    let login = within(login_with(
        &mut s,
        6,
        sid,
        USER,
        "wrong",
        LoginOptions::default(),
    ))
    .await;
    let frames = [login.frame, within(read_frame(&mut s)).await];
    let status_of = |command| {
        let frame = frames
            .iter()
            .find(|f| Smb2Header::parse(f).unwrap().0.command == command)
            .expect("a response");
        status(frame)
    };
    assert_eq!(status_of(Command::SessionSetup), STATUS_LOGON_FAILURE);
    assert_eq!(status_of(Command::ChangeNotify), STATUS_NOTIFY_CLEANUP);
}

#[tokio::test]
async fn overwriting_or_superseding_a_file_reports_nothing() {
    let (srv, _td) = server().await;
    let mut watcher = srv.client().await;
    let mut maker = srv.client().await;
    let dir = watcher.open_dir("d").await;
    create_file(&mut maker, "d\\f").await;
    let mid = arm(&mut watcher, dir, 4096, NAMES, false).await;
    for disposition in [FILE_OVERWRITE_IF, FILE_SUPERSEDE] {
        let created = maker
            .create(Create {
                name: "d\\f",
                access: RW | DELETE,
                disposition,
                ..Create::default()
            })
            .await
            .expect("overwrite");
        maker.close(created.file_id).await;
    }
    create_file(&mut maker, "d\\z").await;
    assert_eq!(
        wait_notify(&mut watcher, mid, 4096).await,
        (STATUS_SUCCESS, vec![added("z")])
    );
}

#[tokio::test]
async fn deleting_a_directory_with_entries_reports_nothing() {
    let (srv, td) = server().await;
    let mut watcher = srv.client().await;
    let mut maker = srv.client().await;
    let dir = watcher.open_dir("d").await;
    make_dir(&mut maker, "d\\sub").await;
    create_file(&mut maker, "d\\sub\\f").await;
    let mid = arm(&mut watcher, dir, 4096, NAMES, false).await;
    delete(&mut maker, "d\\sub", FILE_DIRECTORY_FILE).await;
    assert!(td.path().join("d/sub/f").exists());
    create_file(&mut maker, "d\\z").await;
    assert_eq!(
        wait_notify(&mut watcher, mid, 4096).await,
        (STATUS_SUCCESS, vec![added("z")])
    );
}

#[tokio::test]
async fn a_removal_reaches_only_watches_for_its_kind_of_entry() {
    let (srv, _td) = server().await;
    let mut watcher = srv.client().await;
    let mut maker = srv.client().await;
    let dirs = watcher.open_dir("d").await;
    let files = watcher.open_dir("d").await;
    make_dir(&mut maker, "d\\sub").await;
    create_file(&mut maker, "d\\f").await;
    let dirs_mid = arm(&mut watcher, dirs, 4096, FILE_NOTIFY_CHANGE_DIR_NAME, false).await;
    let files_mid = arm(
        &mut watcher,
        files,
        4096,
        FILE_NOTIFY_CHANGE_FILE_NAME,
        false,
    )
    .await;

    delete(&mut maker, "d\\sub", FILE_DIRECTORY_FILE).await;
    assert_eq!(
        wait_notify(&mut watcher, dirs_mid, 4096).await,
        (STATUS_SUCCESS, vec![removed("sub")])
    );
    delete(&mut maker, "d\\f", 0).await;
    assert_eq!(
        wait_notify(&mut watcher, files_mid, 4096).await,
        (STATUS_SUCCESS, vec![removed("f")])
    );
    // The file's removal was not buffered for the directory watch.
    let body = notify_body(dirs, 4096, FILE_NOTIFY_CHANGE_DIR_NAME, false);
    let mid = watcher.send_no_wait(Command::ChangeNotify, &body).await;
    let frame = within(watcher.next_frame()).await;
    assert_eq!(interim(&frame).map(|(m, _)| m), Some(mid));
}

#[tokio::test]
async fn a_request_without_watch_tree_on_a_tree_watch_gets_no_nested_names() {
    let (srv, _td) = server().await;
    let mut watcher = srv.client().await;
    let mut maker = srv.client().await;
    let dir = watcher.open_dir("d").await;
    let mid = arm(&mut watcher, dir, 4096, NAMES, true).await;
    make_dir(&mut maker, "d\\sub").await;
    assert_eq!(
        wait_notify(&mut watcher, mid, 4096).await,
        (STATUS_SUCCESS, vec![added("sub")])
    );

    create_file(&mut maker, "d\\sub\\x").await;
    let (st, body) = ask(&mut watcher, dir, 4096, NAMES, false).await;
    assert_eq!(st, STATUS_NOTIFY_ENUM_DIR);
    assert_eq!(body, [9, 0, 0x48, 0, 0, 0, 0, 0, 0]);
    create_file(&mut maker, "d\\y").await;
    let (st, body) = ask(&mut watcher, dir, 4096, NAMES, false).await;
    assert_eq!(st, STATUS_SUCCESS);
    assert_eq!(notify_entries(&body, 4096), [added("y")]);
}
