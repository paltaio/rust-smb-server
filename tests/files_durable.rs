//! Durable opens: which opens get one, and how a kept open ends once its
//! session is gone.

mod common;

use std::sync::Arc;
use std::time::Duration;

use common::auth::{self, LoginOptions, login_with};
use common::client::*;
use common::crypto::{EncryptedSession, is_transform};
use common::durable::*;
use common::lease::{OPLOCK_LEVEL_LEASE, RWH, lease_reply};
use common::{start_with_shutdown, utf16le};
use smb_server::wire::header::Command;
use smb_server::wire::messages::{
    CreateContext, CreateResponse, FileId, ReadRequest, ReadResponse,
};
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

const CREATE_GUID: [u8; 16] = [0xC5; 16];

/// SMB2_DHANDLE_FLAG_PERSISTENT.
const PERSISTENT: u32 = 0x2;

/// A DH2C for `file_id` with `create_guid` on `name`, with `lease` as its
/// lease context.
fn reconnect_v2(
    name: &str,
    file_id: FileId,
    create_guid: [u8; 16],
    lease: CreateContext,
) -> Create<'_> {
    Create {
        disposition: FILE_OPEN,
        ..create_with(name, &[lease, dh2c(file_id, create_guid, 0)])
    }
}

/// The Timeout and Flags of a DH2Q response context.
fn granted_v2(resp: &CreateResponse) -> Option<(u32, u32)> {
    let data = CreateContext::parse_chain(&resp.create_contexts)
        .unwrap()
        .into_iter()
        .find(|c| c.name == CreateContext::NAME_DH2Q)?
        .data;
    assert_eq!(data.len(), 8);
    Some((u32_at(&data, 0), u32_at(&data, 4)))
}

/// alice at SMB 3.0.2.
fn v3() -> SignIn<'static> {
    SignIn {
        dialect: SMB302,
        ..SignIn::default()
    }
}

/// A DHnC for `file_id` on `name`, with `lease` as its lease context.
fn reconnect(name: &str, file_id: FileId, lease: CreateContext) -> Create<'_> {
    Create {
        disposition: FILE_OPEN,
        ..create_with(name, &[lease, dhnc(file_id)])
    }
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
        for (what, create) in [
            (
                "read caching only",
                create_with("f.txt", &[lease(R), dhnq()]),
            ),
            ("no lease", create_with("f.txt", &[dhnq()])),
            ("batch oplock", batch),
            ("directory", directory),
        ] {
            let resp = c.create(create).await.expect(what);
            assert_eq!(durable_reply(&resp), None, "{what} at {dialect:#x}");
            c.close(resp.file_id).await;
        }

        // SMB 2.1 has no version 2 contexts; SMB 3.x grants one.
        let v2_only = create_with("f.txt", &[lease(RWH), dh2q(0, 0, [7; 16])]);
        let resp = c.create(v2_only).await.expect("version 2 request");
        let expected = (dialect == SMB302).then(|| [120_000u32.to_le_bytes(), [0; 4]].concat());
        assert_eq!(
            durable_reply(&resp),
            expected,
            "version 2 request at {dialect:#x}"
        );
        c.close(resp.file_id).await;

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
    let other = Share::new("other", local(td.path()))
        .user("alice", Access::ReadWrite)
        .user("bob", Access::ReadWrite);
    let server = Server::start(users(backend).share(other)).await;
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
    /// A client signed in as `who` says, which asks for the kept open back
    /// with `lease` as its lease context.
    async fn reclaim(
        &self,
        who: SignIn<'_>,
        lease: CreateContext,
    ) -> (Client, Result<CreateResponse, u32>) {
        let mut c = user_client(self.server.addr, who).await;
        let resp = c.create(reconnect("f.txt", self.file_id, lease)).await;
        (c, resp)
    }

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
async fn a_dropped_connection_s_open_comes_back_with_its_data_lease_and_lock() {
    for reset_it in [false, true] {
        let td = tempdir().unwrap();
        let (backend, counters) = Probe::new(td.path(), Counters::default());
        let server = Server::start(users(backend)).await;
        let mut a = user_client(server.addr, SignIn::default()).await;
        let f = open_durable(&mut a, "f.txt", KEY_A, RWH, SHARE_ALL)
            .await
            .file_id;
        let data: Vec<u8> = (0..64 * 1024).map(|n| (n % 251) as u8).collect();
        assert_eq!(a.write(f, 0, &data).await, Ok(data.len() as u32));
        assert_eq!(
            a.lock(f, &[(0, 10, LOCK_EXCLUSIVE | LOCK_FAIL_IMMEDIATELY)])
                .await,
            0
        );
        // An open that is not durable, closed once the old connection is
        // closing; the durable one may or may not be kept by then.
        let plain = Create {
            name: "plain.txt",
            disposition: FILE_OPEN_IF,
            ..Create::default()
        };
        a.create(plain).await.expect("plain open");
        if reset_it {
            reset(a);
        } else {
            drop(a);
        }
        assert!(eventually(|| Counters::get(&counters.closes) == 1).await);

        // The reconnect waits for the open to be kept if it is not yet.
        let mut a = user_client(server.addr, SignIn::default()).await;
        let resp = a
            .create(reconnect("f.txt", f, lease_v1(KEY_A, RWH)))
            .await
            .expect("reconnected");
        assert_eq!(resp.file_id.persistent, f.persistent);
        assert_ne!(resp.file_id.volatile, f.volatile);
        assert_eq!(resp.create_action, 1, "FILE_OPENED");
        assert_eq!(resp.oplock_level, OPLOCK_LEVEL_LEASE);
        assert_eq!(lease_reply(&resp).expect("lease").state, RWH);
        assert_eq!(durable_reply(&resp), None);
        assert_eq!(Counters::get(&counters.opens), 2, "the same backend handle");
        let f = resp.file_id;
        assert_eq!(a.read(f, 0, data.len() as u32).await.unwrap(), data);

        // The lease still caches writes: bob's open waits for the break,
        // which goes to the new connection.
        let mut b = user_client(
            server.addr,
            SignIn {
                client_guid: GUID_B,
                user: "bob",
                ..SignIn::default()
            },
        )
        .await;
        let mid = b
            .send_no_wait(
                Command::Create,
                &Create {
                    name: "f.txt",
                    ..Create::default()
                }
                .body(),
            )
            .await;
        let n = a.next_break(Duration::from_secs(5)).await.expect("break");
        assert_eq!((n.current_lease_state, n.new_lease_state), (RWH, RH));
        assert_eq!(a.ack(KEY_A, RH).await, 0);
        let (status, body) = b.recv(mid, Command::Create).await;
        assert_eq!(status, 0, "reset {reset_it}");
        let g = CreateResponse::parse(&body).unwrap().file_id;
        // And the lock still holds.
        assert_eq!(
            b.lock(g, &[(0, 10, LOCK_EXCLUSIVE | LOCK_FAIL_IMMEDIATELY)])
                .await,
            ntstatus::STATUS_LOCK_NOT_GRANTED
        );
        assert_eq!(
            b.read(g, 0, 10).await,
            Err(ntstatus::STATUS_FILE_LOCK_CONFLICT)
        );
        assert_eq!(a.lock(f, &[(0, 10, LOCK_UNLOCK)]).await, 0);
        assert_eq!(b.read(g, 0, 10).await.unwrap(), &data[..10]);
    }
}

#[tokio::test]
async fn a_session_named_as_previous_hands_its_durable_opens_over() {
    let td = tempdir().unwrap();
    let server = Server::start(users(local(td.path()))).await;
    let mut a = user_client(server.addr, SignIn::default()).await;
    let f = open_durable(&mut a, "f.txt", KEY_A, RWH, SHARE_ALL)
        .await
        .file_id;
    assert_eq!(a.write(f, 0, b"kept").await, Ok(4));
    // The old connection stays up, as when the client lost it but the
    // server did not notice.
    let mut again = user_client(
        server.addr,
        SignIn {
            previous: a.session_id,
            ..SignIn::default()
        },
    )
    .await;
    let resp = again
        .create(reconnect("f.txt", f, lease_v1(KEY_A, RWH)))
        .await
        .expect("reconnected");
    assert_eq!(again.read(resp.file_id, 0, 4).await.unwrap(), b"kept");
    assert_eq!(
        a.read(f, 0, 4).await,
        Err(ntstatus::STATUS_USER_SESSION_DELETED)
    );
}

#[tokio::test]
async fn only_the_owner_on_the_same_client_lease_name_and_share_gets_it_back() {
    let k = kept(RWH, SHARE_ALL, true).await;
    let alice = SignIn::default();
    let lease = || lease_v1(KEY_A, RWH);
    let not_found = Some(ntstatus::STATUS_OBJECT_NAME_NOT_FOUND);

    let bob = SignIn {
        user: "bob",
        ..alice
    };
    let (_, refused) = k.reclaim(bob, lease()).await;
    assert_eq!(refused.err(), Some(ntstatus::STATUS_ACCESS_DENIED));
    let other_client = SignIn {
        client_guid: GUID_B,
        ..alice
    };
    let (_, refused) = k.reclaim(other_client, lease()).await;
    assert_eq!(refused.err(), not_found, "another client");
    let (_, refused) = k.reclaim(alice, lease_v1(KEY_B, RWH)).await;
    assert_eq!(refused.err(), not_found, "another lease key");
    let other_share = SignIn {
        share: "other",
        ..alice
    };
    let (_, refused) = k.reclaim(other_share, lease()).await;
    assert_eq!(refused.err(), not_found, "another share");
    let v3 = SignIn {
        dialect: SMB302,
        ..alice
    };
    let (mut c, refused) = k.reclaim(v3, lease_v2(KEY_A, RWH)).await;
    assert_eq!(refused.err(), not_found, "another lease version");
    let unknown = FileId::new(k.file_id.persistent ^ 1, 1);
    let refused = c
        .create(reconnect("f.txt", unknown, lease_v1(KEY_A, RWH)))
        .await;
    assert_eq!(refused.err(), not_found, "another open");
    let no_lease = Create {
        disposition: FILE_OPEN,
        ..create_with("f.txt", &[dhnc(k.file_id)])
    };
    assert_eq!(c.create(no_lease).await.err(), not_found, "no lease");
    let v2 = Create {
        disposition: FILE_OPEN,
        ..create_with(
            "f.txt",
            &[lease_v2(KEY_A, RWH), dh2c(k.file_id, [7; 16], 0)],
        )
    };
    assert_eq!(c.create(v2).await.err(), not_found, "version 2 reconnect");
    let mixed = Create {
        disposition: FILE_OPEN,
        ..create_with(
            "f.txt",
            &[lease_v1(KEY_A, RWH), dhnc(k.file_id), dh2q(0, 0, [7; 16])],
        )
    };
    assert_eq!(
        c.create(mixed).await.err(),
        Some(ntstatus::STATUS_INVALID_PARAMETER)
    );
    let renamed = c.create(reconnect("g.txt", k.file_id, lease())).await;
    assert_eq!(renamed.err(), Some(ntstatus::STATUS_INVALID_PARAMETER));
    let (mut b, _) = k.reclaim(bob, lease()).await;
    let renamed = b.create(reconnect("g.txt", k.file_id, lease())).await;
    assert_eq!(
        renamed.err(),
        Some(ntstatus::STATUS_INVALID_PARAMETER),
        "the name before the owner"
    );
    assert_eq!(handles(&k.counters), 1, "refusals leave the open kept");

    let (mut a, resp) = k.reclaim(alice, lease()).await;
    let resp = resp.expect("reconnected");
    assert_eq!(a.read(resp.file_id, 0, 10).await.unwrap(), b"0123456789");
    // Taken once: a second reconnect finds it in a session.
    let (_, again) = k.reclaim(alice, lease()).await;
    assert_eq!(again.err(), not_found, "second reconnect");
    assert_eq!(a.read(resp.file_id, 0, 10).await.unwrap(), b"0123456789");
}

#[tokio::test]
async fn an_open_gone_from_its_kept_state_cannot_be_reconnected() {
    // A break that needed what the lease caches closed it.
    let k = kept(RWH, SHARE_ALL, false).await;
    k.bob()
        .await
        .open("f.txt", FILE_READ_DATA, SHARE_ALL)
        .await
        .unwrap();
    let (_, refused) = k.reclaim(SignIn::default(), lease_v1(KEY_A, RWH)).await;
    assert_eq!(refused.err(), Some(ntstatus::STATUS_OBJECT_NAME_NOT_FOUND));

    // The user lost write access to the share while away, or all access.
    let k = kept(RWH, SHARE_ALL, false).await;
    k.server
        .config
        .grant_share_user("share", "alice", Access::Read)
        .await
        .unwrap();
    assert_eq!(handles(&k.counters), 0);
    let (_, refused) = k.reclaim(SignIn::default(), lease_v1(KEY_A, RWH)).await;
    assert_eq!(refused.err(), Some(ntstatus::STATUS_OBJECT_NAME_NOT_FOUND));
    let k = kept(RWH, SHARE_ALL, false).await;
    k.server
        .config
        .revoke_share_user("share", "alice")
        .await
        .unwrap();
    k.server
        .config
        .grant_share_user("share", "alice", Access::ReadWrite)
        .await
        .unwrap();
    let (_, refused) = k.reclaim(SignIn::default(), lease_v1(KEY_A, RWH)).await;
    assert_eq!(refused.err(), Some(ntstatus::STATUS_OBJECT_NAME_NOT_FOUND));

    // TREE_DISCONNECT closed it.
    let k = kept(RWH, SHARE_ALL, false).await;
    let (mut a, resp) = k.reclaim(SignIn::default(), lease_v1(KEY_A, RWH)).await;
    resp.expect("reconnected");
    assert_eq!(a.tree_disconnect().await, 0);
    assert_eq!(handles(&k.counters), 0);
    let (_, refused) = k.reclaim(SignIn::default(), lease_v1(KEY_A, RWH)).await;
    assert_eq!(refused.err(), Some(ntstatus::STATUS_OBJECT_NAME_NOT_FOUND));
}

#[tokio::test]
async fn a_reconnect_after_the_open_expired_finds_nothing() {
    let td = tempdir().unwrap();
    let (backend, counters) = Probe::new(td.path(), Counters::default());
    let server = Server::start(users(backend).durable_handle_timeout(Duration::from_secs(1))).await;
    let mut a = user_client(server.addr, SignIn::default()).await;
    let f = open_durable(&mut a, "f.txt", KEY_A, RWH, SHARE_ALL)
        .await
        .file_id;
    assert_eq!(a.logoff().await, 0);
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert!(eventually(|| handles(&counters) == 0).await);
    let mut a = user_client(server.addr, SignIn::default()).await;
    let refused = a.create(reconnect("f.txt", f, lease_v1(KEY_A, RWH))).await;
    assert_eq!(refused.err(), Some(ntstatus::STATUS_OBJECT_NAME_NOT_FOUND));
}

#[tokio::test]
async fn a_logged_off_open_comes_back_on_the_same_connection_and_closes_as_usual() {
    let td = tempdir().unwrap();
    let (backend, counters) = Probe::new(td.path(), Counters::default());
    let server = Server::start(users(backend)).await;
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
    // A new session on the same connection.
    let mid = a.take_mid();
    a.take_mid();
    let login = login_with(
        &mut a.s,
        mid,
        0,
        "alice",
        "password",
        LoginOptions::default(),
    )
    .await;
    assert_eq!(login.status, 0);
    let tree_mid = a.take_mid();
    a.session_id = login.session_id;
    a.tree_id =
        common::tree_connect(&mut a.s, "\\\\127.0.0.1\\share", a.session_id, tree_mid).await;
    let back = a
        .create(reconnect("tmp.txt", resp.file_id, lease_v1(KEY_A, RWH)))
        .await
        .expect("reconnected");
    a.close(back.file_id).await;
    assert!(!td.path().join("tmp.txt").exists(), "delete-on-close ran");
    assert_eq!(handles(&counters), 0);
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

#[tokio::test]
async fn a_reconnect_in_a_compound_serves_related_requests() {
    let k = kept(RWH, SHARE_ALL, false).await;
    let mut a = user_client(k.server.addr, SignIn::default()).await;
    let read = ReadRequest {
        structure_size: 49,
        padding: ReadResponse::STANDARD_DATA_OFFSET,
        flags: 0,
        length: 10,
        offset: 0,
        file_id: FileId::any(),
        minimum_count: 0,
        channel: 0,
        remaining_bytes: 0,
        read_channel_info_offset: 0,
        read_channel_info_length: 0,
        buffer: vec![0],
    };
    let mut read_body = Vec::new();
    read.write_to(&mut read_body).unwrap();
    let create = reconnect("f.txt", k.file_id, lease_v1(KEY_A, RWH)).body();
    let replies = a
        .send_compound(&[
            (Command::Create, create, false),
            (Command::Read, read_body, true),
        ])
        .await;
    assert_eq!(replies[0].0, 0, "reconnect");
    assert_eq!(replies[1].0, 0, "related read");
    let data = ReadResponse::parse(&replies[1].1).unwrap().data;
    assert_eq!(data, b"0123456789");
}

#[tokio::test]
async fn an_encrypted_session_reconnects_and_gets_encrypted_answers() {
    let td = tempdir().unwrap();
    let (backend, counters) = Probe::new(td.path(), Counters::default());
    let server = Server::start(users(backend).encrypt_data(true)).await;
    let path = "\\\\127.0.0.1\\share";
    let mut a = EncryptedSession::smb30(server.addr, SMB302, "alice", "password").await;
    assert_eq!(auth::status(&a.tree_connect(path).await), 0);
    let open = create_with("f.txt", &[lease_v1(KEY_A, RWH), dhnq()]);
    let reply = a.send_encrypted(Command::Create, &open.body()).await;
    assert_eq!(auth::status(&reply), 0);
    let held = CreateResponse::parse(&reply[64..]).unwrap();
    assert!(durable_reply(&held).is_some());
    // An open that is not durable, closed once the connection is closing.
    let plain = Create {
        name: "plain.txt",
        disposition: FILE_OPEN_IF,
        ..Create::default()
    };
    assert_eq!(
        auth::status(&a.send_encrypted(Command::Create, &plain.body()).await),
        0
    );
    drop(a);
    assert!(eventually(|| Counters::get(&counters.closes) == 1).await);

    let mut b = EncryptedSession::smb30(server.addr, SMB302, "alice", "password").await;
    assert_eq!(auth::status(&b.tree_connect(path).await), 0);
    let body = reconnect("f.txt", held.file_id, lease_v1(KEY_A, RWH)).body();
    let hdr = b.header(Command::Create);
    let sealed = b.seal(&common::message(&hdr, &body));
    let mut frame = b.exchange(&sealed).await;
    loop {
        assert!(is_transform(&frame), "answers are encrypted");
        let reply = b.open(&frame).expect("decrypts");
        if auth::status(&reply) != ntstatus::STATUS_PENDING {
            assert_eq!(auth::status(&reply), 0);
            let resp = CreateResponse::parse(&reply[64..]).unwrap();
            assert_eq!(resp.file_id.persistent, held.file_id.persistent);
            break;
        }
        frame = common::read_frame(&mut b.stream).await;
    }
    assert_eq!(Counters::get(&counters.opens), 2, "the kept handle");
}

#[tokio::test]
async fn a_version_2_durable_handle_negotiates_its_timeout() {
    let td = tempdir().unwrap();
    let server = Server::start(users(local(td.path()))).await;
    let mut c = user_client(server.addr, v3()).await;
    let lease = || lease_v2(KEY_A, RWH);
    for (asked, flags, granted) in [
        (0, 0, 120_000),
        (10_000, 0, 10_000),
        (600_000, 0, 300_000),
        (0, PERSISTENT, 120_000),
    ] {
        let resp = c
            .create(create_with(
                "f.txt",
                &[lease(), dh2q(asked, flags, CREATE_GUID)],
            ))
            .await
            .unwrap();
        assert_eq!(
            granted_v2(&resp),
            Some((granted, 0)),
            "asked {asked}, flags {flags}"
        );
        assert_ne!(resp.file_id.persistent, resp.file_id.volatile);
        c.close(resp.file_id).await;
    }
    // Without a lease that caches handles the open is not durable, and the
    // response carries no durable context.
    for (what, list) in [
        (
            "read caching only",
            vec![lease_v2(KEY_A, R), dh2q(0, 0, CREATE_GUID)],
        ),
        ("no lease", vec![dh2q(0, 0, CREATE_GUID)]),
    ] {
        let resp = c.create(create_with("f.txt", &list)).await.expect(what);
        assert_eq!(durable_reply(&resp), None, "{what}");
        c.close(resp.file_id).await;
    }
    for (what, list) in [
        ("with DHnQ", vec![lease(), dh2q(0, 0, CREATE_GUID), dhnq()]),
        (
            "with DH2C",
            vec![
                lease(),
                dh2q(0, 0, CREATE_GUID),
                dh2c(FileId::new(1, 1), CREATE_GUID, 0),
            ],
        ),
        (
            "with DHnC",
            vec![lease(), dh2q(0, 0, CREATE_GUID), dhnc(FileId::new(1, 1))],
        ),
        (
            "DH2C with DHnQ",
            vec![lease(), dh2c(FileId::new(1, 1), CREATE_GUID, 0), dhnq()],
        ),
    ] {
        let status = c.create(create_with("f.txt", &list)).await.err();
        assert_eq!(status, Some(ntstatus::STATUS_INVALID_PARAMETER), "{what}");
    }
    // SMB 2.1 has no version 2 contexts: the request is a plain open.
    let mut old = user_client(server.addr, SignIn::default()).await;
    let resp = old
        .create(create_with(
            "f.txt",
            &[lease_v1(KEY_B, RWH), dh2q(0, 0, CREATE_GUID)],
        ))
        .await
        .unwrap();
    assert_eq!(durable_reply(&resp), None);
}

/// [`Kept`] for a version 2 open with a version 2 lease, made at SMB 3.0.2.
async fn kept_v2(lock: bool) -> Kept {
    let td = tempdir().unwrap();
    std::fs::write(td.path().join("f.txt"), b"0123456789").unwrap();
    let (backend, counters) = Probe::new(td.path(), Counters::default());
    let other = Share::new("other", local(td.path()))
        .user("alice", Access::ReadWrite)
        .user("bob", Access::ReadWrite);
    let server = Server::start(users(backend).share(other)).await;
    let mut a = user_client(server.addr, v3()).await;
    let resp = a
        .create(create_with(
            "f.txt",
            &[lease_v2(KEY_A, RWH), dh2q(0, PERSISTENT, CREATE_GUID)],
        ))
        .await
        .unwrap();
    assert_eq!(granted_v2(&resp), Some((120_000, 0)));
    if lock {
        assert_eq!(
            a.lock(
                resp.file_id,
                &[(0, 10, LOCK_EXCLUSIVE | LOCK_FAIL_IMMEDIATELY)]
            )
            .await,
            0
        );
    }
    assert_eq!(a.logoff().await, 0);
    assert_eq!(handles(&counters), 1, "kept after LOGOFF");
    Kept {
        server,
        counters,
        file_id: resp.file_id,
        _td: td,
    }
}

#[tokio::test]
async fn a_dropped_version_2_open_comes_back_by_dh2c_with_its_lease_and_lock() {
    for reset_it in [false, true] {
        let td = tempdir().unwrap();
        let (backend, counters) = Probe::new(td.path(), Counters::default());
        let server = Server::start(users(backend)).await;
        let mut a = user_client(server.addr, v3()).await;
        let resp = a
            .create(create_with(
                "f.txt",
                &[lease_v2(KEY_A, RWH), dh2q(0, 0, CREATE_GUID)],
            ))
            .await
            .unwrap();
        let f = resp.file_id;
        let held_epoch = lease_reply(&resp).expect("lease").epoch;
        assert_eq!(a.write(f, 0, b"0123456789").await, Ok(10));
        assert_eq!(
            a.lock(f, &[(0, 10, LOCK_EXCLUSIVE | LOCK_FAIL_IMMEDIATELY)])
                .await,
            0
        );
        let plain = Create {
            name: "plain.txt",
            disposition: FILE_OPEN_IF,
            ..Create::default()
        };
        a.create(plain).await.expect("plain open");
        if reset_it {
            reset(a);
        } else {
            drop(a);
        }
        assert!(eventually(|| Counters::get(&counters.closes) == 1).await);

        let mut a = user_client(server.addr, v3()).await;
        let resp = a
            .create(reconnect_v2("f.txt", f, CREATE_GUID, lease_v2(KEY_A, RWH)))
            .await
            .expect("reconnected");
        assert_eq!(resp.file_id.persistent, f.persistent);
        assert_eq!(durable_reply(&resp), None);
        let lease = lease_reply(&resp).expect("lease");
        assert_eq!((lease.state, lease.epoch), (RWH, held_epoch));
        let f = resp.file_id;
        assert_eq!(a.read(f, 0, 10).await.unwrap(), b"0123456789");

        let mut b = user_client(
            server.addr,
            SignIn {
                client_guid: GUID_B,
                user: "bob",
                ..v3()
            },
        )
        .await;
        let mid = b
            .send_no_wait(
                Command::Create,
                &Create {
                    name: "f.txt",
                    ..Create::default()
                }
                .body(),
            )
            .await;
        let n = a.next_break(Duration::from_secs(5)).await.expect("break");
        assert_eq!(n.lease_key, KEY_A);
        assert_eq!((n.current_lease_state, n.new_lease_state), (RWH, RH));
        assert_eq!(a.ack(KEY_A, RH).await, 0);
        let (status, body) = b.recv(mid, Command::Create).await;
        assert_eq!(status, 0, "reset {reset_it}");
        let g = CreateResponse::parse(&body).unwrap().file_id;
        assert_eq!(
            b.lock(g, &[(0, 10, LOCK_EXCLUSIVE | LOCK_FAIL_IMMEDIATELY)])
                .await,
            ntstatus::STATUS_LOCK_NOT_GRANTED
        );
    }
}

#[tokio::test]
async fn a_dh2c_names_the_create_guid_owner_share_and_file() {
    let k = kept_v2(true).await;
    let lease = || lease_v2(KEY_A, RWH);
    let not_found = Some(ntstatus::STATUS_OBJECT_NAME_NOT_FOUND);
    let mut c = user_client(k.server.addr, v3()).await;
    let wrong_guid = reconnect_v2("f.txt", k.file_id, [9; 16], lease());
    assert_eq!(
        c.create(wrong_guid).await.err(),
        not_found,
        "another CreateGuid"
    );
    let renamed = reconnect_v2("g.txt", k.file_id, CREATE_GUID, lease());
    assert_eq!(c.create(renamed).await.err(), not_found, "another name");
    let v1_lease = reconnect_v2("f.txt", k.file_id, CREATE_GUID, lease_v1(KEY_A, RWH));
    assert_eq!(
        c.create(v1_lease).await.err(),
        not_found,
        "another lease version"
    );
    let mut bob = user_client(
        k.server.addr,
        SignIn {
            user: "bob",
            ..v3()
        },
    )
    .await;
    let theirs = reconnect_v2("f.txt", k.file_id, CREATE_GUID, lease());
    assert_eq!(
        bob.create(theirs).await.err(),
        Some(ntstatus::STATUS_ACCESS_DENIED)
    );
    let mut elsewhere = user_client(
        k.server.addr,
        SignIn {
            share: "other",
            ..v3()
        },
    )
    .await;
    let there = reconnect_v2("f.txt", k.file_id, CREATE_GUID, lease());
    assert_eq!(
        elsewhere.create(there).await.err(),
        not_found,
        "another share"
    );
    let mut other_client = user_client(
        k.server.addr,
        SignIn {
            client_guid: GUID_B,
            ..v3()
        },
    )
    .await;
    let theirs = reconnect_v2("f.txt", k.file_id, CREATE_GUID, lease());
    assert_eq!(
        other_client.create(theirs).await.err(),
        not_found,
        "another client"
    );
    let other_key = reconnect_v2("f.txt", k.file_id, CREATE_GUID, lease_v2(KEY_B, RWH));
    assert_eq!(
        c.create(other_key).await.err(),
        not_found,
        "another lease key"
    );
    let no_lease = Create {
        disposition: FILE_OPEN,
        ..create_with("f.txt", &[dh2c(k.file_id, CREATE_GUID, 0)])
    };
    assert_eq!(c.create(no_lease).await.err(), not_found, "no lease");
    assert_eq!(handles(&k.counters), 1, "refusals leave the open kept");

    // The PERSISTENT flag is ignored.
    let persistent = Create {
        disposition: FILE_OPEN,
        ..create_with(
            "f.txt",
            &[lease(), dh2c(k.file_id, CREATE_GUID, PERSISTENT)],
        )
    };
    let resp = c.create(persistent).await.expect("reconnected");
    assert_eq!(c.read(resp.file_id, 0, 10).await.unwrap(), b"0123456789");
}

#[tokio::test]
async fn a_dhnc_takes_a_version_2_open_back_but_a_dh2c_finds_no_version_1_open() {
    let k = kept_v2(false).await;
    let mut c = user_client(k.server.addr, v3()).await;
    let resp = c
        .create(reconnect("f.txt", k.file_id, lease_v2(KEY_A, RWH)))
        .await
        .expect("a version 1 reconnect checks no CreateGuid");
    assert_eq!(resp.file_id.persistent, k.file_id.persistent);

    let k = kept(RWH, SHARE_ALL, false).await;
    let mut c = user_client(k.server.addr, v3()).await;
    let status = c
        .create(reconnect_v2(
            "f.txt",
            k.file_id,
            CREATE_GUID,
            lease_v1(KEY_A, RWH),
        ))
        .await;
    assert_eq!(status.err(), Some(ntstatus::STATUS_OBJECT_NAME_NOT_FOUND));
    assert_eq!(handles(&k.counters), 1);
    let resp = c
        .create(reconnect("f.txt", k.file_id, lease_v1(KEY_A, RWH)))
        .await
        .expect("the version 1 open is still kept");
    assert_eq!(resp.file_id.persistent, k.file_id.persistent);
}

#[tokio::test]
async fn a_session_named_as_previous_hands_its_version_2_opens_over() {
    let td = tempdir().unwrap();
    let server = Server::start(users(local(td.path()))).await;
    let mut a = user_client(server.addr, v3()).await;
    let resp = a
        .create(create_with(
            "f.txt",
            &[lease_v2(KEY_A, RWH), dh2q(0, 0, CREATE_GUID)],
        ))
        .await
        .unwrap();
    assert_eq!(a.write(resp.file_id, 0, b"kept").await, Ok(4));
    let mut again = user_client(
        server.addr,
        SignIn {
            previous: a.session_id,
            ..v3()
        },
    )
    .await;
    let back = again
        .create(reconnect_v2(
            "f.txt",
            resp.file_id,
            CREATE_GUID,
            lease_v2(KEY_A, RWH),
        ))
        .await
        .expect("reconnected");
    assert_eq!(again.read(back.file_id, 0, 4).await.unwrap(), b"kept");
}

#[tokio::test]
async fn an_encrypted_311_session_reconnects_a_version_2_open() {
    let td = tempdir().unwrap();
    let (backend, counters) = Probe::new(td.path(), Counters::default());
    let server = Server::start(users(backend).encrypt_data(true)).await;
    let path = "\\\\127.0.0.1\\share";
    let gcm = [common::crypto::Cipher::Aes128Gcm];
    let mut a = EncryptedSession::smb311(server.addr, &gcm, "alice", "password").await;
    assert_eq!(auth::status(&a.tree_connect(path).await), 0);
    let open = create_with("f.txt", &[lease_v2(KEY_A, RWH), dh2q(0, 0, CREATE_GUID)]);
    let reply = a.send_encrypted(Command::Create, &open.body()).await;
    assert_eq!(auth::status(&reply), 0);
    let held = CreateResponse::parse(&reply[64..]).unwrap();
    assert_eq!(granted_v2(&held), Some((120_000, 0)));
    // An open that is not durable, closed once the connection is closing.
    let plain = Create {
        name: "plain.txt",
        disposition: FILE_OPEN_IF,
        ..Create::default()
    };
    assert_eq!(
        auth::status(&a.send_encrypted(Command::Create, &plain.body()).await),
        0
    );
    drop(a);
    assert!(eventually(|| Counters::get(&counters.closes) == 1).await);

    let mut b = EncryptedSession::smb311(server.addr, &gcm, "alice", "password").await;
    assert_eq!(auth::status(&b.tree_connect(path).await), 0);
    let body = reconnect_v2("f.txt", held.file_id, CREATE_GUID, lease_v2(KEY_A, RWH)).body();
    let hdr = b.header(Command::Create);
    let sealed = b.seal(&common::message(&hdr, &body));
    let mut frame = b.exchange(&sealed).await;
    let reply = loop {
        assert!(is_transform(&frame), "answers are encrypted");
        let reply = b.open(&frame).expect("decrypts");
        if auth::status(&reply) != ntstatus::STATUS_PENDING {
            break reply;
        }
        frame = common::read_frame(&mut b.stream).await;
    };
    assert_eq!(auth::status(&reply), 0);
    let resp = CreateResponse::parse(&reply[64..]).unwrap();
    assert_eq!(resp.file_id.persistent, held.file_id.persistent);
    assert_eq!(Counters::get(&counters.opens), 2, "the kept handle");
}
