//! Durable opens: which opens get one, and how a kept open ends once its
//! session is gone.

mod common;

use std::sync::Arc;
use std::time::Duration;

use common::auth::{LoginOptions, login_with};
use common::client::*;
use common::durable::*;
use common::lease::{OPLOCK_LEVEL_LEASE, RWH, lease_reply};
use common::{start_with_shutdown, utf16le};
use smb_server::wire::messages::{CreateContext, CreateResponse, FileId};
use smb_server::{Access, Share, ShareBackend, SmbServer, SmbServerBuilder, ntstatus};
use tempfile::{TempDir, tempdir};

const R: u32 = 0x1;
const RH: u32 = 0x3;
const KEY_A: [u8; 16] = [0xA5; 16];
const KEY_B: [u8; 16] = [0xB5; 16];
const GUID_A: [u8; 16] = [0xA1; 16];
const GUID_B: [u8; 16] = [0xB1; 16];

/// Backend handles open now.
fn handles(counters: &Counters) -> usize {
    Counters::get(&counters.opens) - Counters::get(&counters.closes)
}

/// alice and bob, both with read-write access to `share` on `backend`.
fn users(backend: impl ShareBackend) -> SmbServerBuilder {
    SmbServer::builder()
        .user("alice", "password")
        .user("bob", "password")
        .share(
            Share::new("share", backend)
                .user("alice", Access::ReadWrite)
                .user("bob", Access::ReadWrite),
        )
}

/// A CREATE of `name` with `contexts`, asking for a lease when one of them
/// is a lease context.
fn create_with<'a>(name: &'a str, list: &[CreateContext]) -> Create<'a> {
    let leased = list.iter().any(|c| c.name == CreateContext::NAME_RQLS);
    Create {
        name,
        oplock: if leased { OPLOCK_LEVEL_LEASE } else { 0 },
        disposition: FILE_OPEN_IF,
        contexts: contexts(list),
        ..Create::default()
    }
}

/// Opens `name` asking for a durable handle and the lease `state` under
/// `key`, sharing `share`; the open must be durable.
async fn open_durable(
    c: &mut Client,
    name: &str,
    key: [u8; 16],
    state: u32,
    share: u32,
) -> CreateResponse {
    let resp = c
        .create(Create {
            share,
            ..create_with(name, &[lease_v1(key, state), dhnq()])
        })
        .await
        .expect("create");
    assert_eq!(durable_reply(&resp), Some(vec![0; 8]), "durable granted");
    resp
}

#[tokio::test]
async fn a_durable_handle_needs_a_lease_that_caches_handles() {
    let td = tempdir().unwrap();
    std::fs::create_dir(td.path().join("dir")).unwrap();
    let server = Server::start(
        SmbServer::builder()
            .user("alice", "password")
            .share(Share::new("share", local(td.path())).user("alice", Access::ReadWrite))
            .share(
                Share::new("nolease", local(td.path()))
                    .user("alice", Access::ReadWrite)
                    .leases(false),
            )
            .share(
                Share::new("nodurable", local(td.path()))
                    .user("alice", Access::ReadWrite)
                    .durable_handles(false),
            )
            .share(Share::new("public", local(td.path())).public()),
    )
    .await;

    for dialect in [SMB21, SMB302] {
        let mut c = user_client(
            server.addr,
            SignIn {
                dialect,
                ..SignIn::default()
            },
        )
        .await;
        let resp = open_durable(&mut c, "f.txt", KEY_A, RWH, SHARE_ALL).await;
        assert_eq!(resp.oplock_level, OPLOCK_LEVEL_LEASE);
        assert_eq!(lease_reply(&resp).expect("lease").state, RWH);
        assert_ne!(resp.file_id.persistent, resp.file_id.volatile);
        c.close(resp.file_id).await;

        let lease = |state| lease_v1(KEY_A, state);
        let batch = Create {
            oplock: 0x09,
            ..create_with("f.txt", &[dhnq()])
        };
        let directory = Create {
            access: FILE_GENERIC_READ,
            options: FILE_DIRECTORY_FILE,
            ..create_with("dir", &[lease(RH), dhnq()])
        };
        let v2_only = create_with("f.txt", &[lease(RWH), dh2q(0, 0, [7; 16])]);
        for (what, create) in [
            (
                "read caching only",
                create_with("f.txt", &[lease(R), dhnq()]),
            ),
            ("no lease", create_with("f.txt", &[dhnq()])),
            ("batch oplock", batch),
            ("directory", directory),
            ("version 2 request", v2_only),
        ] {
            let resp = c.create(create).await.expect(what);
            assert_eq!(durable_reply(&resp), None, "{what} at {dialect:#x}");
            c.close(resp.file_id).await;
        }

        let both = create_with("f.txt", &[lease(RWH), dhnq(), dh2q(0, 0, [7; 16])]);
        match dialect {
            SMB21 => {
                let resp = c.create(both).await.expect("version 2 context ignored");
                assert_eq!(durable_reply(&resp), Some(vec![0; 8]));
                c.close(resp.file_id).await;
            }
            _ => assert_eq!(
                c.create(both).await.err(),
                Some(ntstatus::STATUS_INVALID_PARAMETER)
            ),
        }
        let mut short = dhnq();
        short.data.pop();
        assert_eq!(
            c.create(create_with("f.txt", &[lease(RWH), short]))
                .await
                .err(),
            Some(ntstatus::STATUS_INVALID_PARAMETER)
        );
    }

    let mut v2 = user_client(
        server.addr,
        SignIn {
            dialect: SMB302,
            ..SignIn::default()
        },
    )
    .await;
    let resp = v2
        .create(create_with("f.txt", &[lease_v2(KEY_A, RWH), dhnq()]))
        .await
        .unwrap();
    assert_eq!(
        durable_reply(&resp),
        Some(vec![0; 8]),
        "with a version 2 lease"
    );
    v2.close(resp.file_id).await;

    for (share, dialect) in [("nolease", SMB21), ("nodurable", SMB21), ("share", SMB202)] {
        let mut c = user_client(
            server.addr,
            SignIn {
                dialect,
                share,
                ..SignIn::default()
            },
        )
        .await;
        let resp = c
            .create(create_with("f.txt", &[lease_v1(KEY_A, RWH), dhnq()]))
            .await
            .unwrap();
        assert_eq!(durable_reply(&resp), None, "{share} at {dialect:#x}");
        c.close(resp.file_id).await;
    }
    let mut anonymous = Client::connect_with(server.addr, Some(SMB21), GUID_A, "public").await;
    let resp = anonymous
        .create(create_with("f.txt", &[lease_v1(KEY_A, RWH), dhnq()]))
        .await
        .unwrap();
    assert_eq!(lease_reply(&resp).expect("lease").state, RWH);
    assert_eq!(durable_reply(&resp), None, "anonymous");
}

/// A server whose share holds f.txt, and alice's durable open of it, kept
/// after a LOGOFF.
struct Kept {
    server: Server,
    counters: Arc<Counters>,
    file_id: FileId,
    _td: TempDir,
}

/// [`Kept`] with the lease `state`, sharing `share`. With `lock`, the open
/// takes an exclusive lock on bytes 0 to 9 first.
async fn kept(state: u32, share: u32, lock: bool) -> Kept {
    let td = tempdir().unwrap();
    std::fs::write(td.path().join("f.txt"), b"0123456789").unwrap();
    let (backend, counters) = Probe::new(td.path(), Counters::default());
    let server = Server::start(users(backend)).await;
    let mut a = user_client(server.addr, SignIn::default()).await;
    let file_id = open_durable(&mut a, "f.txt", KEY_A, state, share)
        .await
        .file_id;
    if lock {
        assert_eq!(
            a.lock(file_id, &[(0, 10, LOCK_EXCLUSIVE | LOCK_FAIL_IMMEDIATELY)])
                .await,
            0
        );
    }
    assert_eq!(a.logoff().await, 0);
    assert_eq!(handles(&counters), 1, "kept after LOGOFF");
    Kept {
        server,
        counters,
        file_id,
        _td: td,
    }
}

impl Kept {
    /// bob, from another client.
    async fn bob(&self) -> Client {
        user_client(
            self.server.addr,
            SignIn {
                client_guid: GUID_B,
                user: "bob",
                ..SignIn::default()
            },
        )
        .await
    }
}

#[tokio::test]
async fn logoff_keeps_a_durable_open_and_tree_disconnect_closes_it() {
    let k = kept(RH, SHARE_ALL, false).await;
    let mut a = user_client(k.server.addr, SignIn::default()).await;
    let resp = open_durable(&mut a, "g.txt", KEY_B, RH, SHARE_ALL).await;
    assert_eq!(handles(&k.counters), 2);
    assert_ne!(resp.file_id.persistent, resp.file_id.volatile);
    assert_eq!(a.tree_disconnect().await, 0);
    assert_eq!(handles(&k.counters), 1, "closed with its tree");
}

#[tokio::test]
async fn a_dropped_connection_keeps_a_durable_open() {
    for reset_it in [false, true] {
        let td = tempdir().unwrap();
        let (backend, counters) = Probe::new(td.path(), Counters::default());
        // One connection at a time: the next one gets in only once the
        // dropped one is torn down.
        let server = Server::start(users(backend).max_connections(1)).await;
        let mut a = user_client(server.addr, SignIn::default()).await;
        let f = open_durable(&mut a, "f.txt", KEY_A, RWH, SHARE_ALL)
            .await
            .file_id;
        assert_eq!(a.write(f, 0, b"0123456789").await, Ok(10));
        assert_eq!(
            a.lock(f, &[(0, 10, LOCK_EXCLUSIVE | LOCK_FAIL_IMMEDIATELY)])
                .await,
            0
        );
        if reset_it {
            reset(a);
        } else {
            drop(a);
        }

        let mut b = user_client(
            server.addr,
            SignIn {
                client_guid: GUID_B,
                user: "bob",
                ..SignIn::default()
            },
        )
        .await;
        assert_eq!(handles(&counters), 1, "kept, reset {reset_it}");
        // An open that needs write caching gone closes the kept open, and
        // its lock with it.
        let g = b.open("f.txt", RW, SHARE_ALL).await.unwrap();
        assert_eq!(handles(&counters), 1, "only bob's open is left");
        assert_eq!(b.read(g, 0, 10).await.unwrap(), b"0123456789");
        assert_eq!(
            b.lock(g, &[(0, 10, LOCK_EXCLUSIVE | LOCK_FAIL_IMMEDIATELY)])
                .await,
            0
        );
    }
}

#[tokio::test]
async fn attribute_only_and_compatible_opens_leave_a_kept_open() {
    let k = kept(RH, SHARE_ALL, false).await;
    let mut b = k.bob().await;
    b.open("f.txt", FILE_READ_ATTRIBUTES, 0).await.unwrap();
    for asked in [RH, RWH] {
        let resp = b
            .create(create_with("f.txt", &[lease_v1(KEY_B, asked)]))
            .await
            .unwrap();
        assert_eq!(lease_reply(&resp).expect("lease").state, RH, "{asked}");
    }
    // An open breaks write caching only, which an RH lease does not hold.
    b.open("f.txt", RW, SHARE_ALL).await.unwrap();
    assert_eq!(handles(&k.counters), 5, "the kept open and bob's four");
}

#[tokio::test]
async fn an_open_that_needs_write_caching_gone_closes_a_kept_open() {
    let k = kept(RWH, SHARE_ALL, false).await;
    let mut b = k.bob().await;
    b.open("f.txt", FILE_READ_DATA, SHARE_ALL).await.unwrap();
    assert_eq!(handles(&k.counters), 1);
}

#[tokio::test]
async fn a_sharing_violation_closes_a_kept_open() {
    let k = kept(RH, 0, false).await;
    let mut b = k.bob().await;
    b.open("f.txt", FILE_READ_DATA, SHARE_ALL).await.unwrap();
    assert_eq!(handles(&k.counters), 1);
}

#[tokio::test]
async fn a_write_closes_a_kept_open() {
    let k = kept(RH, SHARE_ALL, false).await;
    let mut b = k.bob().await;
    let g = b.open("f.txt", RW, SHARE_ALL).await.unwrap();
    assert_eq!(handles(&k.counters), 2);
    assert_eq!(b.write(g, 0, b"x").await, Ok(1));
    assert!(eventually(|| handles(&k.counters) == 1).await);
}

#[tokio::test]
async fn a_rename_closes_a_kept_open() {
    let k = kept(RH, SHARE_ALL, false).await;
    let mut b = k.bob().await;
    let g = b
        .open("f.txt", DELETE | FILE_READ_ATTRIBUTES, SHARE_ALL)
        .await
        .unwrap();
    let name = utf16le("g.txt");
    let mut info = vec![0u8; 16];
    info.extend_from_slice(&(name.len() as u32).to_le_bytes());
    info.extend_from_slice(&name);
    assert_eq!(b.set_info(g, FILE_RENAME_INFORMATION, info).await, 0);
    assert!(eventually(|| handles(&k.counters) == 1).await);
}

#[tokio::test]
async fn an_open_beside_a_kept_lock_closes_it_and_the_range_is_free() {
    let k = kept(RWH, SHARE_ALL, true).await;
    let mut b = k.bob().await;
    let g = b.open("f.txt", RW, SHARE_ALL).await.unwrap();
    assert_eq!(handles(&k.counters), 1);
    assert_eq!(b.write(g, 0, b"x").await, Ok(1));
    assert_eq!(
        b.lock(g, &[(0, 10, LOCK_EXCLUSIVE | LOCK_FAIL_IMMEDIATELY)])
            .await,
        0
    );
}

#[tokio::test]
async fn configuration_changes_close_kept_opens() {
    let td = tempdir().unwrap();
    let mut builder = SmbServer::builder()
        .user("alice", "password")
        .user("bob", "password");
    let mut counters = Vec::new();
    for name in ["s1", "s2", "s3", "s4"] {
        let dir = td.path().join(name);
        std::fs::create_dir(&dir).unwrap();
        let (backend, c) = Probe::new(&dir, Counters::default());
        counters.push(c);
        builder = builder.share(
            Share::new(name, backend)
                .user("alice", Access::ReadWrite)
                .user("bob", Access::ReadWrite),
        );
    }
    let server = Server::start(builder).await;
    // One client, so each open needs its own lease key.
    let keep = async |share: &str, user: &str, key: u8| {
        let mut c = user_client(
            server.addr,
            SignIn {
                share,
                user,
                ..SignIn::default()
            },
        )
        .await;
        open_durable(&mut c, "f.txt", [key; 16], RH, SHARE_ALL).await;
        assert_eq!(c.logoff().await, 0);
    };
    for (key, share) in (1..).zip(["s1", "s2", "s3", "s4"]) {
        keep(share, "alice", key).await;
    }
    for (key, share) in (11..).zip(["s2", "s4"]) {
        keep(share, "bob", key).await;
    }
    let open = |n: usize| handles(&counters[n]);
    assert_eq!((open(0), open(1), open(2), open(3)), (1, 2, 1, 2));

    server.config.remove_share("s1").await.unwrap();
    assert_eq!(open(0), 0, "remove_share");
    server
        .config
        .revoke_share_user("s2", "alice")
        .await
        .unwrap();
    assert_eq!(open(1), 1, "revoke_share_user keeps bob's");
    server
        .config
        .grant_share_user("s3", "alice", Access::Read)
        .await
        .unwrap();
    assert_eq!(open(2), 0, "grant_share_user lowering access");
    server.config.add_user("alice", "changed").await.unwrap();
    assert_eq!(open(3), 1, "new password keeps bob's");
    server.config.remove_user("bob").await.unwrap();
    assert_eq!((open(1), open(3)), (0, 0), "remove_user");
}

#[tokio::test]
async fn a_kept_open_closes_when_its_time_runs_out() {
    let td = tempdir().unwrap();
    let server =
        Server::start(users(local(td.path())).durable_handle_timeout(Duration::from_secs(1))).await;
    let mut a = user_client(server.addr, SignIn::default()).await;
    let resp = a
        .create(Create {
            access: RW | DELETE,
            disposition: FILE_CREATE,
            options: FILE_DELETE_ON_CLOSE,
            ..create_with("tmp.txt", &[lease_v1(KEY_A, RWH), dhnq()])
        })
        .await
        .unwrap();
    assert!(durable_reply(&resp).is_some());
    assert_eq!(a.logoff().await, 0);
    let path = td.path().join("tmp.txt");
    // LOGOFF would have deleted a file it closed.
    assert!(path.exists(), "kept after LOGOFF");
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert!(eventually(|| !path.exists()).await, "closed as CLOSE would");
}

#[tokio::test]
async fn shutdown_closes_kept_and_attached_durable_opens() {
    let td = tempdir().unwrap();
    let (backend, counters) = Probe::new(td.path(), Counters::default());
    let (addr, shutdown, task) = start_with_shutdown(users(backend)).await;
    let mut kept = user_client(addr, SignIn::default()).await;
    open_durable(&mut kept, "f.txt", KEY_A, RH, SHARE_ALL).await;
    assert_eq!(kept.logoff().await, 0);
    let mut attached = user_client(addr, SignIn::default()).await;
    open_durable(&mut attached, "g.txt", KEY_B, RH, SHARE_ALL).await;
    assert_eq!(handles(&counters), 2);

    shutdown.shutdown();
    task.await.unwrap();
    assert_eq!(handles(&counters), 0);
}

#[tokio::test]
async fn a_previous_session_of_the_same_user_keeps_its_durable_opens() {
    let td = tempdir().unwrap();
    let (backend, counters) = Probe::new(td.path(), Counters::default());
    let server = Server::start(users(backend)).await;
    let mut a = user_client(server.addr, SignIn::default()).await;
    let f = open_durable(&mut a, "f.txt", KEY_A, RWH, SHARE_ALL)
        .await
        .file_id;

    // Another user naming the session changes nothing.
    let _bob = user_client(
        server.addr,
        SignIn {
            user: "bob",
            previous: a.session_id,
            ..SignIn::default()
        },
    )
    .await;
    assert_eq!(a.write(f, 0, b"x").await, Ok(1));

    let mut again = user_client(
        server.addr,
        SignIn {
            previous: a.session_id,
            ..SignIn::default()
        },
    )
    .await;
    assert_eq!(
        a.read(f, 0, 1).await,
        Err(ntstatus::STATUS_USER_SESSION_DELETED)
    );
    assert_eq!(handles(&counters), 1, "kept");
    again
        .open("f.txt", FILE_READ_DATA, SHARE_ALL)
        .await
        .unwrap();
    assert_eq!(handles(&counters), 1, "closed for the new open");
}

#[tokio::test]
async fn a_reconnect_fails_and_closes_only_its_owners_kept_open() {
    let k = kept(RWH, SHARE_ALL, true).await;
    let reconnect = |file_id: FileId, list: &[CreateContext]| {
        let mut all = list.to_vec();
        all.push(dhnc(file_id));
        Create {
            disposition: FILE_OPEN,
            ..create_with("f.txt", &all)
        }
    };
    let client = async |user: &str, client_guid: [u8; 16], dialect: u16| {
        user_client(
            k.server.addr,
            SignIn {
                dialect,
                client_guid,
                user,
                ..SignIn::default()
            },
        )
        .await
    };
    let id = k.file_id;
    let not_found = Some(ntstatus::STATUS_OBJECT_NAME_NOT_FOUND);

    let mut bob = client("bob", GUID_A, SMB21).await;
    let status = bob
        .create(reconnect(id, &[lease_v1(KEY_A, RWH)]))
        .await
        .err();
    assert_eq!(status, Some(ntstatus::STATUS_ACCESS_DENIED));
    let mut elsewhere = client("alice", GUID_B, SMB21).await;
    let status = elsewhere
        .create(reconnect(id, &[lease_v1(KEY_A, RWH)]))
        .await
        .err();
    assert_eq!(status, not_found, "another client");
    let mut a = client("alice", GUID_A, SMB302).await;
    for (what, list) in [
        ("another lease key", vec![lease_v1(KEY_B, RWH)]),
        ("no lease", vec![]),
    ] {
        assert_eq!(
            a.create(reconnect(id, &list)).await.err(),
            not_found,
            "{what}"
        );
    }
    let unknown = FileId::new(id.persistent ^ 1, 1);
    let status = a.create(reconnect(unknown, &[lease_v1(KEY_A, RWH)])).await;
    assert_eq!(status.err(), not_found, "another open");
    let v2 = Create {
        disposition: FILE_OPEN,
        ..create_with("f.txt", &[lease_v2(KEY_A, RWH), dh2c(id, [7; 16], 0)])
    };
    assert_eq!(a.create(v2).await.err(), not_found, "version 2");
    let mixed = Create {
        disposition: FILE_OPEN,
        ..create_with(
            "f.txt",
            &[lease_v2(KEY_A, RWH), dhnc(id), dh2q(0, 0, [7; 16])],
        )
    };
    assert_eq!(
        a.create(mixed).await.err(),
        Some(ntstatus::STATUS_INVALID_PARAMETER)
    );
    assert_eq!(handles(&k.counters), 1, "still kept");

    let status = a.create(reconnect(id, &[lease_v2(KEY_A, RWH)])).await;
    assert_eq!(status.err(), not_found);
    assert_eq!(handles(&k.counters), 0, "closed by its owner's reconnect");
    // The client opens the file again and takes its lock back.
    let resp = a
        .create(create_with("f.txt", &[lease_v2(KEY_A, RWH), dhnq()]))
        .await
        .unwrap();
    assert_eq!(lease_reply(&resp).expect("lease").state, RWH);
    assert_eq!(
        a.lock(
            resp.file_id,
            &[(0, 10, LOCK_EXCLUSIVE | LOCK_FAIL_IMMEDIATELY)]
        )
        .await,
        0
    );

    // An open still in its session cannot be reconnected.
    let mut other = client("alice", GUID_A, SMB302).await;
    let status = other
        .create(reconnect(resp.file_id, &[lease_v2(KEY_A, RWH)]))
        .await;
    assert_eq!(status.err(), not_found, "still attached");
    assert_eq!(a.read(resp.file_id, 0, 10).await.unwrap(), b"0123456789");
}

#[tokio::test]
async fn a_failed_reauthentication_keeps_durable_opens() {
    let td = tempdir().unwrap();
    let (backend, counters) = Probe::new(td.path(), Counters::default());
    let server = Server::start(users(backend)).await;
    let mut a = user_client(server.addr, SignIn::default()).await;
    let f = open_durable(&mut a, "f.txt", KEY_A, RWH, SHARE_ALL)
        .await
        .file_id;

    let mid = a.take_mid();
    a.take_mid();
    let session_id = a.session_id;
    let login = login_with(
        &mut a.s,
        mid,
        session_id,
        "alice",
        "wrong",
        LoginOptions::default(),
    )
    .await;
    assert_eq!(login.status, ntstatus::STATUS_LOGON_FAILURE);
    assert_eq!(
        a.read(f, 0, 1).await,
        Err(ntstatus::STATUS_USER_SESSION_DELETED)
    );
    assert_eq!(handles(&counters), 1, "kept");
    let mut b = user_client(
        server.addr,
        SignIn {
            client_guid: GUID_B,
            user: "bob",
            ..SignIn::default()
        },
    )
    .await;
    b.open("f.txt", FILE_READ_DATA, SHARE_ALL).await.unwrap();
    assert_eq!(handles(&counters), 1, "closed for bob's open");
}
