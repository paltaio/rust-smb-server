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
#[cfg(unix)]
use smb_server::ntstatus::STATUS_DELETE_PENDING;
use smb_server::ntstatus::{
    STATUS_ACCESS_DENIED, STATUS_INVALID_PARAMETER, STATUS_LOGON_FAILURE, STATUS_NOTIFY_CLEANUP,
    STATUS_NOTIFY_ENUM_DIR, STATUS_PENDING, STATUS_SUCCESS,
};
use smb_server::wire::header::{Command, SMB2_FLAGS_SIGNED, Smb2Header};
use smb_server::wire::messages::FileId;
use smb_server::{Share, SmbServer, SmbServerBuilder};
use tokio::net::TcpStream;

const USER: &str = "alice";
const LAST_WRITE: u32 = 0x10;
const ATTRIBUTES: u32 = 0x4;
/// The filter macOS clients use.
const MACOS: u32 = 0xD47;
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
    assert_eq!(body, [9, 0, 0x48, 0, 0, 0, 0, 0]);

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
    assert_eq!(body, [9, 0, 0x48, 0, 0, 0, 0, 0]);
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
async fn an_overwrite_or_supersede_reports_new_contents() {
    let (srv, _td) = server().await;
    let mut watcher = srv.client().await;
    let mut maker = srv.client().await;
    let dir = watcher.open_dir("d").await;
    let names = watcher.open_dir("d").await;
    create_file(&mut maker, "d\\f").await;
    arm_idle(&mut watcher, names, NAMES, false).await;
    for disposition in [FILE_OVERWRITE_IF, FILE_SUPERSEDE] {
        let mid = arm(&mut watcher, dir, 4096, LAST_WRITE, false).await;
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
        assert_eq!(
            wait_notify(&mut watcher, mid, 4096).await,
            (STATUS_SUCCESS, vec![modified("f")])
        );
    }
    assert_eq!(now(&mut watcher, names, false).await, None);
}

#[tokio::test]
async fn attributes_set_through_basic_info_are_reported_under_attributes() {
    let (srv, _td) = server().await;
    let mut watcher = srv.client().await;
    let mut maker = srv.client().await;
    create_file(&mut maker, "d\\f").await;
    let mut watches = Vec::new();
    for filter in [ATTRIBUTES, MACOS, LAST_WRITE] {
        let dir = watcher.open_dir("d").await;
        arm_idle(&mut watcher, dir, filter, false).await;
        watches.push(dir);
    }
    let file = maker
        .open(
            "d\\f",
            FILE_WRITE_ATTRIBUTES | FILE_READ_ATTRIBUTES,
            SHARE_ALL,
        )
        .await
        .unwrap();
    let mut basic = vec![0u8; 40];
    basic[32..36].copy_from_slice(&FILE_ATTRIBUTE_READONLY.to_le_bytes());
    assert_eq!(maker.set_info(file, FILE_BASIC_INFORMATION, basic).await, 0);
    maker.close(file).await;
    let found = [
        now(&mut watcher, watches[0], false).await,
        now(&mut watcher, watches[1], false).await,
        now(&mut watcher, watches[2], false).await,
    ];
    assert_eq!(
        found,
        [Some(vec![modified("f")]), Some(vec![modified("f")]), None]
    );
}

#[tokio::test]
async fn a_rename_into_a_subdirectory_modifies_it_for_write_time_watchers() {
    let (srv, _td) = server().await;
    let mut watcher = srv.client().await;
    let mut maker = srv.client().await;
    make_dir(&mut maker, "o").await;
    make_dir(&mut maker, "d\\sub").await;
    create_file(&mut maker, "d\\b.txt").await;
    create_file(&mut maker, "d\\sub\\f2").await;
    let plain = watcher.open_dir("d").await;
    let tree = watcher.open_dir("d").await;
    let macos = watcher.open_dir("d").await;
    arm_idle(&mut watcher, plain, 0x17, false).await;
    arm_idle(&mut watcher, tree, 0x17, true).await;
    arm_idle(&mut watcher, macos, MACOS, false).await;
    let seen = async |watcher: &mut Client| {
        [
            now(watcher, plain, false).await,
            now(watcher, tree, true).await,
            now(watcher, macos, false).await,
        ]
    };

    // A rename inside the subdirectory.
    rename(&mut maker, "d\\sub\\f2", "d\\sub\\f3", false, 0).await;
    assert_eq!(
        seen(&mut watcher).await,
        [
            Some(vec![modified("sub")]),
            Some(vec![
                old_name("sub\\f2"),
                new_name("sub\\f3"),
                modified("sub")
            ]),
            None,
        ]
    );
    // A move into it.
    rename(&mut maker, "d\\b.txt", "d\\sub\\b.txt", false, 0).await;
    assert_eq!(
        seen(&mut watcher).await,
        [
            Some(vec![removed("b.txt"), modified("sub")]),
            Some(vec![removed("b.txt"), added("sub\\b.txt"), modified("sub")]),
            Some(vec![removed("b.txt")]),
        ]
    );
    // Creating, writing and deleting a file in it, and moving one out of
    // it, leave it as it was.
    let file = maker
        .create(Create {
            name: "d\\sub\\c.txt",
            disposition: FILE_CREATE,
            ..Create::default()
        })
        .await
        .unwrap()
        .file_id;
    assert_eq!(maker.write(file, 0, b"data").await, Ok(4));
    maker.close(file).await;
    delete(&mut maker, "d\\sub\\c.txt", 0).await;
    rename(&mut maker, "d\\sub\\b.txt", "o\\b.txt", false, 0).await;
    assert_eq!(
        seen(&mut watcher).await,
        [
            None,
            Some(vec![
                added("sub\\c.txt"),
                modified("sub\\c.txt"),
                removed("sub\\c.txt"),
                removed("sub\\b.txt")
            ]),
            None,
        ]
    );
}

#[tokio::test]
async fn the_close_response_comes_before_the_cleanup_of_its_requests() {
    let (srv, _td) = server().await;
    let mut watcher = srv.client().await;
    let dir = watcher.open_dir("d").await;
    let mid = arm(&mut watcher, dir, 4096, NAMES, false).await;
    let mut body = Vec::new();
    smb_server::wire::messages::CloseRequest {
        structure_size: 24,
        flags: 0,
        reserved: 0,
        file_id: dir,
    }
    .write_to(&mut body)
    .unwrap();
    let close = watcher.send_no_wait(Command::Close, &body).await;
    let first = within(watcher.next_frame()).await;
    let second = within(watcher.next_frame()).await;
    let (first, _) = Smb2Header::parse(&first).unwrap();
    let (second, rest) = Smb2Header::parse(&second).unwrap();
    assert_eq!((first.command, first.message_id), (Command::Close, close));
    assert_eq!(
        (second.command, second.message_id),
        (Command::ChangeNotify, mid)
    );
    assert_eq!(second.channel_sequence_status, STATUS_NOTIFY_CLEANUP);
    assert_eq!(rest, [9, 0, 0x48, 0, 0, 0, 0, 0]);
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
    assert_eq!(body, [9, 0, 0x48, 0, 0, 0, 0, 0]);
    create_file(&mut maker, "d\\y").await;
    let (st, body) = ask(&mut watcher, dir, 4096, NAMES, false).await;
    assert_eq!(st, STATUS_SUCCESS);
    assert_eq!(notify_entries(&body, 4096), [added("y")]);
}

fn rename_info(to: &str, replace: bool) -> Vec<u8> {
    let name = common::utf16le(to);
    let mut buffer = vec![u8::from(replace)];
    buffer.extend_from_slice(&[0; 15]);
    buffer.extend_from_slice(&(name.len() as u32).to_le_bytes());
    buffer.extend_from_slice(&name);
    buffer
}

/// Renames `name`, opened with `options`, to `to`.
async fn rename(c: &mut Client, name: &str, to: &str, replace: bool, options: u32) {
    let status = rename_status(c, name, to, replace, options).await;
    assert_eq!(status, STATUS_SUCCESS, "rename {name} to {to}");
}

/// [`rename`], returning the status of the SET_INFO.
async fn rename_status(c: &mut Client, name: &str, to: &str, replace: bool, options: u32) -> u32 {
    let file_id = c
        .open_with_options(name, DELETE | FILE_READ_ATTRIBUTES, options)
        .await
        .expect("open for renaming");
    let status = c
        .set_info(file_id, FILE_RENAME_INFORMATION, rename_info(to, replace))
        .await;
    c.close(file_id).await;
    status
}

#[tokio::test]
async fn a_rename_within_a_directory_reports_both_names_in_one_answer() {
    let (srv, _td) = server().await;
    let mut watcher = srv.client().await;
    let mut maker = srv.client().await;
    let dir = watcher.open_dir("d").await;
    create_file(&mut maker, "d\\a").await;
    let mid = arm(&mut watcher, dir, 4096, NAMES, false).await;
    rename(&mut maker, "d\\a", "d\\b", false, 0).await;
    assert_eq!(
        wait_notify(&mut watcher, mid, 4096).await,
        (STATUS_SUCCESS, vec![old_name("a"), new_name("b")])
    );
}

#[tokio::test]
async fn a_move_reports_a_removal_and_an_addition() {
    let (srv, _td) = server().await;
    let mut watcher = srv.client().await;
    let mut maker = srv.client().await;
    make_dir(&mut maker, "d\\one").await;
    make_dir(&mut maker, "d\\two").await;
    create_file(&mut maker, "d\\one\\f").await;
    let one = watcher.open_dir("d\\one").await;
    let two = watcher.open_dir("d\\two").await;
    let tree = watcher.open_dir("d").await;
    let one_mid = arm(&mut watcher, one, 4096, NAMES, false).await;
    let two_mid = arm(&mut watcher, two, 4096, NAMES, false).await;
    let tree_mid = arm(&mut watcher, tree, 4096, NAMES, true).await;

    rename(&mut maker, "d\\one\\f", "d\\two\\f", false, 0).await;
    assert_eq!(
        wait_notify(&mut watcher, one_mid, 4096).await,
        (STATUS_SUCCESS, vec![removed("f")])
    );
    assert_eq!(
        wait_notify(&mut watcher, two_mid, 4096).await,
        (STATUS_SUCCESS, vec![added("f")])
    );
    assert_eq!(
        wait_notify(&mut watcher, tree_mid, 4096).await,
        (STATUS_SUCCESS, vec![removed("one\\f"), added("two\\f")])
    );

    // A request without WATCH_TREE gets no nested names.
    rename(&mut maker, "d\\two\\f", "d\\one\\f", false, 0).await;
    let (st, _) = ask(&mut watcher, tree, 4096, NAMES, false).await;
    assert_eq!(st, STATUS_NOTIFY_ENUM_DIR);
}

#[tokio::test]
async fn a_rename_over_a_file_reports_the_target_removed_then_the_rename() {
    let (srv, _td) = server().await;
    let mut watcher = srv.client().await;
    let mut maker = srv.client().await;
    make_dir(&mut maker, "o").await;
    create_file(&mut maker, "d\\a").await;
    create_file(&mut maker, "d\\t").await;
    create_file(&mut maker, "d\\u").await;
    create_file(&mut maker, "o\\u").await;
    let dir = watcher.open_dir("d").await;
    let other = watcher.open_dir("o").await;
    let mid = arm(&mut watcher, dir, 4096, NAMES, false).await;
    rename(&mut maker, "d\\a", "d\\t", true, 0).await;
    assert_eq!(
        wait_notify(&mut watcher, mid, 4096).await,
        (
            STATUS_SUCCESS,
            vec![removed("t"), old_name("a"), new_name("t")]
        )
    );

    // A move over a file in another directory.
    let mid = arm(&mut watcher, dir, 4096, NAMES, false).await;
    let other_mid = arm(&mut watcher, other, 4096, NAMES, false).await;
    rename(&mut maker, "o\\u", "d\\u", true, 0).await;
    assert_eq!(
        wait_notify(&mut watcher, mid, 4096).await,
        (STATUS_SUCCESS, vec![removed("u"), added("u")])
    );
    assert_eq!(
        wait_notify(&mut watcher, other_mid, 4096).await,
        (STATUS_SUCCESS, vec![removed("u")])
    );
}

#[tokio::test]
async fn a_renamed_watched_directory_keeps_its_buffer_and_its_watch() {
    let (srv, _td) = server().await;
    let mut watcher = srv.client().await;
    let mut maker = srv.client().await;
    make_dir(&mut maker, "d\\sub").await;
    let sub = watcher.open_dir("d\\sub").await;
    let mid = arm(&mut watcher, sub, 4096, NAMES, false).await;
    create_file(&mut maker, "d\\sub\\a").await;
    assert_eq!(
        wait_notify(&mut watcher, mid, 4096).await,
        (STATUS_SUCCESS, vec![added("a")])
    );
    create_file(&mut maker, "d\\sub\\b").await;
    rename(&mut maker, "d\\sub", "d\\moved", false, FILE_DIRECTORY_FILE).await;
    create_file(&mut maker, "d\\moved\\c").await;
    let (st, body) = ask(&mut watcher, sub, 4096, NAMES, false).await;
    assert_eq!(st, STATUS_SUCCESS);
    assert_eq!(notify_entries(&body, 4096), [added("b"), added("c")]);
}

#[tokio::test]
async fn renaming_an_ancestor_of_an_open_directory_is_refused() {
    let (srv, _td) = server().await;
    let mut watcher = srv.client().await;
    let mut maker = srv.client().await;
    make_dir(&mut maker, "d\\p").await;
    make_dir(&mut maker, "d\\p\\q").await;
    let deep = watcher.open_dir("d\\p\\q").await;
    let mid = arm(&mut watcher, deep, 4096, NAMES, true).await;
    for (from, to) in [("d\\p", "d\\r"), ("d", "z")] {
        let status = rename_status(&mut maker, from, to, false, FILE_DIRECTORY_FILE).await;
        assert_eq!(status, STATUS_ACCESS_DENIED, "rename {from}");
    }
    create_file(&mut maker, "d\\p\\q\\after").await;
    assert_eq!(
        wait_notify(&mut watcher, mid, 4096).await,
        (STATUS_SUCCESS, vec![added("after")])
    );
}

#[tokio::test]
async fn a_rename_reaches_watches_by_the_kind_of_entry() {
    let (srv, _td) = server().await;
    let mut watcher = srv.client().await;
    let mut maker = srv.client().await;
    make_dir(&mut maker, "d\\sub").await;
    create_file(&mut maker, "d\\f").await;
    let dirs = watcher.open_dir("d").await;
    let files = watcher.open_dir("d").await;
    let dirs_mid = arm(&mut watcher, dirs, 4096, FILE_NOTIFY_CHANGE_DIR_NAME, false).await;
    let files_mid = arm(
        &mut watcher,
        files,
        4096,
        FILE_NOTIFY_CHANGE_FILE_NAME,
        false,
    )
    .await;

    rename(&mut maker, "d\\sub", "d\\sub2", false, FILE_DIRECTORY_FILE).await;
    assert_eq!(
        wait_notify(&mut watcher, dirs_mid, 4096).await,
        (STATUS_SUCCESS, vec![old_name("sub"), new_name("sub2")])
    );
    rename(&mut maker, "d\\f", "d\\g", false, 0).await;
    assert_eq!(
        wait_notify(&mut watcher, files_mid, 4096).await,
        (STATUS_SUCCESS, vec![old_name("f"), new_name("g")])
    );
    // The file's rename was not buffered for the directory watch.
    let body = notify_body(dirs, 4096, FILE_NOTIFY_CHANGE_DIR_NAME, false);
    let mid = watcher.send_no_wait(Command::ChangeNotify, &body).await;
    let frame = within(watcher.next_frame()).await;
    assert_eq!(interim(&frame).map(|(m, _)| m), Some(mid));
}

#[cfg(unix)]
#[tokio::test]
async fn a_mark_ends_watches_armed_through_a_symlink_to_the_directory() {
    let (srv, td) = server().await;
    std::fs::create_dir(td.path().join("d").join("w")).unwrap();
    std::os::unix::fs::symlink("w", td.path().join("d").join("link")).unwrap();
    let mut watcher = srv.client().await;
    let mut marker = srv.client().await;
    let link = watcher.open_dir("d\\link").await;
    let mid = arm(&mut watcher, link, 4096, NAMES, false).await;
    let mark = marker
        .open_with_options("d\\w", DELETE | FILE_READ_ATTRIBUTES, FILE_DIRECTORY_FILE)
        .await
        .unwrap();
    assert_eq!(marker.set_delete(mark, true).await, STATUS_SUCCESS);
    assert_eq!(
        wait_notify(&mut watcher, mid, 4096).await,
        (STATUS_DELETE_PENDING, vec![])
    );
}

/// Kernel watches on the inode of `dir` held by this process.
#[cfg(target_os = "linux")]
fn kernel_watches_on(dir: &std::path::Path) -> usize {
    use std::os::unix::fs::MetadataExt;
    let ino = format!(" ino:{:x} ", std::fs::metadata(dir).unwrap().ino());
    let mut count = 0;
    for entry in std::fs::read_dir("/proc/self/fd").unwrap().flatten() {
        let is_inotify = std::fs::read_link(entry.path())
            .is_ok_and(|target| target.as_os_str() == "anon_inode:inotify");
        if !is_inotify {
            continue;
        }
        let info = std::fs::read_to_string(
            std::path::Path::new("/proc/self/fdinfo").join(entry.file_name()),
        )
        .unwrap_or_default();
        count += info
            .lines()
            .filter(|line| line.starts_with("inotify wd:") && line.contains(&ino))
            .count();
    }
    count
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn changes_made_on_disk_are_reported() {
    let (srv, td) = server().await;
    let d = td.path().join("d");
    std::fs::create_dir(td.path().join("o")).unwrap();
    std::fs::write(d.join("w"), b"old").unwrap();
    let mut watcher = srv.client().await;
    let names = watcher.open_dir("d").await;
    let contents = watcher.open_dir("d").await;
    let attributes = watcher.open_dir("d").await;

    let mid = arm(&mut watcher, names, 4096, NAMES, false).await;
    drop(std::fs::File::create(d.join("x")).unwrap());
    assert_eq!(
        wait_notify(&mut watcher, mid, 4096).await,
        (STATUS_SUCCESS, vec![added("x")])
    );
    let mid = arm(&mut watcher, names, 4096, NAMES, false).await;
    std::fs::rename(d.join("x"), d.join("y")).unwrap();
    assert_eq!(
        wait_notify(&mut watcher, mid, 4096).await,
        (STATUS_SUCCESS, vec![old_name("x"), new_name("y")])
    );
    let mid = arm(&mut watcher, names, 4096, NAMES, false).await;
    std::fs::remove_file(d.join("y")).unwrap();
    assert_eq!(
        wait_notify(&mut watcher, mid, 4096).await,
        (STATUS_SUCCESS, vec![removed("y")])
    );
    let mid = arm(&mut watcher, names, 4096, NAMES, false).await;
    std::fs::rename(d.join("w"), td.path().join("o").join("w")).unwrap();
    assert_eq!(
        wait_notify(&mut watcher, mid, 4096).await,
        (STATUS_SUCCESS, vec![removed("w")])
    );
    std::fs::rename(td.path().join("o").join("w"), d.join("w")).unwrap();
    let mid = arm(&mut watcher, names, 4096, NAMES, false).await;
    assert_eq!(
        wait_notify(&mut watcher, mid, 4096).await,
        (STATUS_SUCCESS, vec![added("w")])
    );

    // Contents under the content filter, attributes under ATTRIBUTES.
    let mid = arm(&mut watcher, contents, 4096, LAST_WRITE, false).await;
    std::fs::write(d.join("w"), b"new").unwrap();
    assert_eq!(
        wait_notify(&mut watcher, mid, 4096).await,
        (STATUS_SUCCESS, vec![modified("w")])
    );
    let mid = arm(&mut watcher, attributes, 4096, ATTRIBUTES, false).await;
    let mut permissions = std::fs::metadata(d.join("w")).unwrap().permissions();
    permissions.set_readonly(true);
    std::fs::set_permissions(d.join("w"), permissions).unwrap();
    let (status, entries) = wait_notify(&mut watcher, mid, 4096).await;
    assert_eq!(status, STATUS_SUCCESS);
    assert_eq!(entries[0], modified("w"));
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn a_change_made_through_the_server_is_reported_once() {
    let (srv, td) = server().await;
    let mut watcher = srv.client().await;
    let mut maker = srv.client().await;
    let dir = watcher.open_dir("d").await;
    arm_idle(&mut watcher, dir, 0x17, false).await;
    let file = maker
        .create(Create {
            name: "d\\x",
            disposition: FILE_CREATE,
            ..Create::default()
        })
        .await
        .unwrap()
        .file_id;
    assert_eq!(maker.write(file, 0, b"data").await, Ok(4));
    maker.close(file).await;
    rename(&mut maker, "d\\x", "d\\y", false, 0).await;
    make_dir(&mut maker, "d\\sub").await;
    delete(&mut maker, "d\\y", 0).await;
    assert_eq!(
        now(&mut watcher, dir, false).await,
        Some(vec![
            added("x"),
            modified("x"),
            old_name("x"),
            new_name("y"),
            added("sub"),
            removed("y")
        ])
    );
    // What the kernel saw of the same changes adds nothing: a change made
    // on disk afterwards, which the kernel reports after them, is the next
    // thing heard.
    std::fs::create_dir(td.path().join("d").join("z")).unwrap();
    let mid = arm(&mut watcher, dir, 4096, NAMES, false).await;
    assert_eq!(
        wait_notify(&mut watcher, mid, 4096).await,
        (STATUS_SUCCESS, vec![added("z")])
    );
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn the_kernel_watch_goes_with_the_last_watch_of_its_directory() {
    let (srv, td) = server().await;
    let d = td.path().join("d");
    let mut watcher = srv.client().await;
    let first = watcher.open_dir("d").await;
    let second = watcher.open_dir("d").await;
    assert_eq!(kernel_watches_on(&d), 0);
    arm_idle(&mut watcher, first, NAMES, false).await;
    arm_idle(&mut watcher, second, NAMES, false).await;
    assert_eq!(kernel_watches_on(&d), 1, "one kernel watch per directory");
    watcher.close(first).await;
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    assert_eq!(kernel_watches_on(&d), 1);
    assert_eq!(kernel_watches_on(td.path()), 1, "and one on its parent");
    watcher.close(second).await;
    assert!(eventually(|| kernel_watches_on(&d) == 0).await);
    assert!(eventually(|| kernel_watches_on(td.path()) == 0).await);
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn a_watched_directory_moved_on_disk_asks_for_a_listing() {
    let (srv, td) = server().await;
    let mut watcher = srv.client().await;
    let mut maker = srv.client().await;
    make_dir(&mut maker, "d\\sub").await;
    let sub = watcher.open_dir("d\\sub").await;
    arm_idle(&mut watcher, sub, NAMES, false).await;
    rename(&mut maker, "d\\sub", "d\\moved", false, FILE_DIRECTORY_FILE).await;
    // The kernel reports the rename before this, so hearing only this
    // shows the rename asked for no listing.
    let d = td.path().join("d");
    std::fs::create_dir(d.join("moved").join("x")).unwrap();
    let mid = arm(&mut watcher, sub, 4096, NAMES, false).await;
    assert_eq!(
        wait_notify(&mut watcher, mid, 4096).await,
        (STATUS_SUCCESS, vec![added("x")])
    );
    std::fs::rename(d.join("moved"), d.join("away")).unwrap();
    let mid = arm(&mut watcher, sub, 4096, NAMES, false).await;
    assert_eq!(
        wait_notify(&mut watcher, mid, 4096).await,
        (STATUS_NOTIFY_ENUM_DIR, vec![])
    );
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn a_directory_deleted_on_disk_ends_its_watches() {
    let (srv, td) = server().await;
    let sub = td.path().join("d").join("sub");
    std::fs::create_dir(&sub).unwrap();
    let mut watcher = srv.client().await;
    let dir = watcher.open_dir("d\\sub").await;
    let mid = arm(&mut watcher, dir, 4096, NAMES, false).await;
    std::fs::remove_dir(&sub).unwrap();
    let deleted = (STATUS_DELETE_PENDING, vec![]);
    assert_eq!(wait_notify(&mut watcher, mid, 4096).await, deleted);
    let (status, _) = ask(&mut watcher, dir, 4096, NAMES, false).await;
    assert_eq!(status, deleted.0, "and so does the next request");
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn a_directory_deleted_on_disk_before_its_first_request_ends_it() {
    let (srv, td) = server().await;
    let sub = td.path().join("d").join("sub");
    std::fs::create_dir(&sub).unwrap();
    let mut watcher = srv.client().await;
    let dir = watcher.open_dir("d\\sub").await;
    std::fs::remove_dir(&sub).unwrap();
    let (status, _) = ask(&mut watcher, dir, 4096, NAMES, false).await;
    assert_eq!(status, STATUS_DELETE_PENDING);
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn a_directory_replaced_on_disk_by_a_rename_ends_its_watches() {
    let (srv, td) = server().await;
    let d = td.path().join("d");
    std::fs::create_dir(d.join("sub")).unwrap();
    std::fs::create_dir(td.path().join("other")).unwrap();
    let mut watcher = srv.client().await;
    let dir = watcher.open_dir("d\\sub").await;
    let mid = arm(&mut watcher, dir, 4096, NAMES, false).await;
    std::fs::rename(td.path().join("other"), d.join("sub")).unwrap();
    assert_eq!(
        wait_notify(&mut watcher, mid, 4096).await,
        (STATUS_DELETE_PENDING, vec![])
    );
}

/// `LocalFsBackend` that waits `delay` after each change it makes, before
/// the server can report it.
#[cfg(target_os = "linux")]
struct Slow {
    inner: smb_server::LocalFsBackend,
    delay: std::time::Duration,
}

#[cfg(target_os = "linux")]
#[async_trait::async_trait]
impl smb_server::ShareBackend for Slow {
    async fn open(
        &self,
        path: &smb_server::SmbPath,
        opts: smb_server::OpenOptions,
    ) -> smb_server::SmbResult<(Box<dyn smb_server::Handle>, smb_server::OpenAction)> {
        let opened = self.inner.open(path, opts).await;
        if matches!(&opened, Ok((_, action)) if *action != smb_server::OpenAction::Opened) {
            tokio::time::sleep(self.delay).await;
        }
        opened
    }

    async fn unlink(&self, path: &smb_server::SmbPath) -> smb_server::SmbResult<()> {
        let unlinked = self.inner.unlink(path).await;
        tokio::time::sleep(self.delay).await;
        unlinked
    }

    async fn rename(
        &self,
        from: &smb_server::SmbPath,
        to: &smb_server::SmbPath,
        replace_if_exists: bool,
    ) -> smb_server::SmbResult<()> {
        let renamed = self.inner.rename(from, to, replace_if_exists).await;
        tokio::time::sleep(self.delay).await;
        renamed
    }

    fn capabilities(&self) -> smb_server::BackendCapabilities {
        self.inner.capabilities()
    }
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn a_change_the_server_reports_late_is_still_reported_once() {
    let td = tempfile::tempdir().unwrap();
    std::fs::create_dir(td.path().join("d")).unwrap();
    // Longer than the backend's reports wait, so they are compared before
    // the server reports.
    let slow = Slow {
        inner: local(td.path()),
        delay: std::time::Duration::from_millis(600),
    };
    let share = Share::new("share", slow).public();
    let srv = Server::start(SmbServer::builder().user(USER, PASSWORD).share(share)).await;
    let mut watcher = srv.client().await;
    let mut maker = srv.client().await;
    let dir = watcher.open_dir("d").await;
    arm_idle(&mut watcher, dir, NAMES, false).await;
    make_dir(&mut maker, "d\\x").await;
    rename(&mut maker, "d\\x", "d\\y", false, FILE_DIRECTORY_FILE).await;
    delete(&mut maker, "d\\y", FILE_DIRECTORY_FILE).await;
    assert_eq!(
        now(&mut watcher, dir, false).await,
        Some(vec![added("x"), old_name("x"), new_name("y"), removed("y")])
    );
    std::fs::create_dir(td.path().join("d").join("z")).unwrap();
    let mid = arm(&mut watcher, dir, 4096, NAMES, false).await;
    assert_eq!(
        wait_notify(&mut watcher, mid, 4096).await,
        (STATUS_SUCCESS, vec![added("z")])
    );
}

/// `LocalFsBackend` on which a CREATE that must create loses the race to
/// another program, which creates the directory first.
#[cfg(target_os = "linux")]
struct Racing {
    inner: smb_server::LocalFsBackend,
    root: std::path::PathBuf,
}

#[cfg(target_os = "linux")]
#[async_trait::async_trait]
impl smb_server::ShareBackend for Racing {
    async fn open(
        &self,
        path: &smb_server::SmbPath,
        opts: smb_server::OpenOptions,
    ) -> smb_server::SmbResult<(Box<dyn smb_server::Handle>, smb_server::OpenAction)> {
        if opts.intent != smb_server::OpenIntent::Create {
            return self.inner.open(path, opts).await;
        }
        let on_disk: std::path::PathBuf = path.components().iter().collect();
        std::fs::create_dir(self.root.join(on_disk)).unwrap();
        // Longer than the backend's reports wait.
        tokio::time::sleep(std::time::Duration::from_millis(600)).await;
        Err(smb_server::SmbError::Exists)
    }

    async fn unlink(&self, path: &smb_server::SmbPath) -> smb_server::SmbResult<()> {
        self.inner.unlink(path).await
    }

    async fn rename(
        &self,
        from: &smb_server::SmbPath,
        to: &smb_server::SmbPath,
        replace_if_exists: bool,
    ) -> smb_server::SmbResult<()> {
        self.inner.rename(from, to, replace_if_exists).await
    }

    fn capabilities(&self) -> smb_server::BackendCapabilities {
        self.inner.capabilities()
    }
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn a_create_that_loses_to_a_change_on_disk_reports_that_change() {
    let td = tempfile::tempdir().unwrap();
    std::fs::create_dir(td.path().join("d")).unwrap();
    let racing = Racing {
        inner: local(td.path()),
        root: td.path().to_path_buf(),
    };
    let share = Share::new("share", racing).public();
    let srv = Server::start(SmbServer::builder().user(USER, PASSWORD).share(share)).await;
    let mut watcher = srv.client().await;
    let mut maker = srv.client().await;
    let dir = watcher.open_dir("d").await;
    arm_idle(&mut watcher, dir, NAMES, false).await;
    let refused = maker.create(dir_create("d\\x", FILE_CREATE)).await;
    assert!(refused.is_err(), "the CREATE fails");
    assert_eq!(now(&mut watcher, dir, false).await, Some(vec![added("x")]));
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn a_change_on_disk_is_heard_before_a_later_one_through_the_server() {
    let (srv, td) = server().await;
    let mut watcher = srv.client().await;
    let mut maker = srv.client().await;
    let dir = watcher.open_dir("d").await;
    arm_idle(&mut watcher, dir, NAMES, false).await;
    std::fs::create_dir(td.path().join("d").join("a")).unwrap();
    // The kernel's report is read, and waiting, when the server deletes.
    tokio::time::sleep(std::time::Duration::from_millis(150)).await;
    delete(&mut maker, "d\\a", FILE_DIRECTORY_FILE).await;
    assert_eq!(
        now(&mut watcher, dir, false).await,
        Some(vec![added("a"), removed("a")])
    );
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn a_tree_watch_hears_a_directory_made_on_disk_before_a_file_made_in_it() {
    let (srv, td) = server().await;
    let mut watcher = srv.client().await;
    let mut maker = srv.client().await;
    let dir = watcher.open_dir("d").await;
    arm_idle(&mut watcher, dir, NAMES, true).await;
    std::fs::create_dir(td.path().join("d").join("b")).unwrap();
    // The kernel's report is read, and waiting, when the server creates.
    tokio::time::sleep(std::time::Duration::from_millis(150)).await;
    create_file(&mut maker, "d\\b\\c").await;
    assert_eq!(
        now(&mut watcher, dir, true).await,
        Some(vec![added("b"), added("b\\c")])
    );
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn a_removal_on_disk_right_after_a_save_through_the_server_is_reported() {
    let (srv, td) = server().await;
    let mut watcher = srv.client().await;
    let mut editor = srv.client().await;
    create_file(&mut editor, "d\\f").await;
    let dir = watcher.open_dir("d").await;
    arm_idle(&mut watcher, dir, NAMES, false).await;
    // Save by writing a new file and renaming it over the old one.
    let temp = editor
        .create(Create {
            name: "d\\f.tmp",
            access: RW | DELETE,
            disposition: FILE_CREATE,
            ..Create::default()
        })
        .await
        .unwrap()
        .file_id;
    assert_eq!(editor.write(temp, 0, b"new").await, Ok(3));
    let to = rename_info("d\\f", true);
    assert_eq!(
        editor.set_info(temp, FILE_RENAME_INFORMATION, to).await,
        STATUS_SUCCESS
    );
    editor.close(temp).await;
    assert_eq!(
        now(&mut watcher, dir, false).await,
        Some(vec![
            added("f.tmp"),
            removed("f"),
            old_name("f.tmp"),
            new_name("f")
        ])
    );
    std::fs::remove_file(td.path().join("d").join("f")).unwrap();
    let mid = arm(&mut watcher, dir, 4096, NAMES, false).await;
    assert_eq!(
        wait_notify(&mut watcher, mid, 4096).await,
        (STATUS_SUCCESS, vec![removed("f")])
    );
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn a_write_on_disk_to_a_file_open_only_to_read_is_reported() {
    let (srv, td) = server().await;
    let file = td.path().join("d").join("r");
    std::fs::write(&file, b"old").unwrap();
    let mut watcher = srv.client().await;
    let mut reader = srv.client().await;
    let read = reader
        .open_with_options("d\\r", FILE_GENERIC_READ, 0)
        .await
        .unwrap();
    let dir = watcher.open_dir("d").await;
    let mid = arm(&mut watcher, dir, 4096, LAST_WRITE, false).await;
    std::fs::write(&file, b"new").unwrap();
    assert_eq!(
        wait_notify(&mut watcher, mid, 4096).await,
        (STATUS_SUCCESS, vec![modified("r")])
    );
    reader.close(read).await;
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn changes_on_disk_are_not_reported_when_host_watching_is_off() {
    let td = tempfile::tempdir().unwrap();
    let d = td.path().join("d");
    std::fs::create_dir(&d).unwrap();
    let share = Share::new("share", local(td.path()).watch_host_changes(false)).public();
    let srv = Server::start(SmbServer::builder().user(USER, PASSWORD).share(share)).await;
    let mut watcher = srv.client().await;
    let mut maker = srv.client().await;
    let dir = watcher.open_dir("d").await;
    let mid = arm(&mut watcher, dir, 4096, NAMES, false).await;
    std::fs::write(d.join("outside"), b"x").unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    assert_eq!(kernel_watches_on(&d), 0);
    create_file(&mut maker, "d\\inside").await;
    assert_eq!(
        wait_notify(&mut watcher, mid, 4096).await,
        (STATUS_SUCCESS, vec![added("inside")])
    );
}
