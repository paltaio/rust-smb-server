//! Requests answered asynchronously while a lease break completes, driven
//! through the dispatcher with time paused where the acknowledgment timer
//! matters.

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::RwLock;

use crate::ShareBackend;
use crate::conn::state::{Connection, Session, TreeConnect};
use crate::conn::writer::{ResponseReceiver, response_queue};
use crate::dispatch::{Outgoing, dispatch_frame, read_u32};
use crate::files::LEASE_BREAK_TIMEOUT;
use crate::ntstatus;
use crate::proto::auth::ntlm::Identity;
use crate::proto::crypto::{SigningAlgo, sign, verify};
use crate::proto::header::{
    Command, HeaderTail, SMB2_FLAGS_ASYNC_COMMAND, SMB2_FLAGS_SIGNED, SMB2_HEADER_LEN, Smb2Header,
};
use crate::proto::messages::{
    CloseRequest, CreateContext, CreateRequest, CreateResponse, Dialect, FileId, LeaseBreakAck,
    LeaseBreakNotification, LeaseContext, WriteRequest,
};
use crate::server::ServerState;
use crate::tests::memfs::MemFsBackend;
use crate::{Access, Share, SmbServer};

const KEY: [u8; 16] = [0x5A; 16];
const LEASE_KEY: [u8; 16] = [0xA1; 16];
const READ_WRITE: u32 = 0x3;
const DELETE: u32 = 0x0001_0000;
const READ_ATTRIBUTES: u32 = 0x80;
const SHARE_READ_WRITE: u32 = 0x3;
const RH: u32 = 0x3;

/// One connection with session 1 on tree 1 of `home`, and the queue its
/// unsolicited messages and late responses go to.
struct Peer {
    conn: Arc<Connection>,
    rx: ResponseReceiver,
    next_mid: u64,
    signed: bool,
}

impl Peer {
    async fn new(state: &Arc<ServerState>, signed: bool) -> Self {
        let conn = Arc::new(Connection::new(state.config.server_guid, 1 << 20, 1 << 20));
        *conn.dialect.write().await = Some(Dialect::Smb300);
        *conn.signing_algo.write().await = SigningAlgo::AesCmac;
        {
            let mut credits = conn.credits.lock().expect("credits");
            assert!(credits.consume(0, 1));
            credits.grant(64, false);
        }
        let identity = if signed {
            Identity::User {
                user: "alice".to_string(),
                domain: String::new(),
            }
        } else {
            Identity::Anonymous
        };
        let session = Session::new(identity, [0; 16], KEY, false, None);
        let share = state.find_share("home").await.expect("share");
        let tree = TreeConnect::new(1, share, Access::ReadWrite);
        session
            .trees
            .write()
            .await
            .insert(1, Arc::new(RwLock::new(tree)));
        conn.sessions
            .write()
            .await
            .insert(1, Arc::new(RwLock::new(session)));
        let (tx, rx) = response_queue();
        conn.outbound.attach(tx);
        Self {
            conn,
            rx,
            next_mid: 1,
            signed,
        }
    }

    /// A request on session 1 and tree 1 with the next MessageId.
    fn message(&mut self, command: Command, body: &[u8]) -> (u64, Vec<u8>) {
        let mid = self.next_mid;
        self.next_mid += 1;
        (mid, self.message_with(command, mid, 1, body))
    }

    fn message_with(&self, command: Command, mid: u64, session_id: u64, body: &[u8]) -> Vec<u8> {
        let hdr = Smb2Header {
            credit_charge: 1,
            command,
            credit_request_response: 1,
            flags: if self.signed { SMB2_FLAGS_SIGNED } else { 0 },
            message_id: mid,
            tail: HeaderTail::sync(1),
            session_id,
            ..Smb2Header::default()
        };
        let mut msg = Vec::new();
        hdr.write(&mut msg).expect("header");
        msg.extend_from_slice(body);
        if self.signed {
            sign(&mut msg, &KEY, SigningAlgo::AesCmac).expect("sign");
        }
        msg
    }

    /// Dispatches `frame` as the reader would: the frame it answers with is
    /// returned, and a continuation runs on the connection's task set.
    async fn dispatch(&self, state: &Arc<ServerState>, frame: &[u8]) -> Option<Vec<u8>> {
        let Outgoing {
            bytes,
            after_send,
            continuation,
        } = dispatch_frame(state, &self.conn, frame).await?;
        drop(after_send);
        if let Some(continuation) = continuation {
            self.conn
                .pending
                .spawn(continuation.run(Arc::clone(state), Arc::clone(&self.conn)));
        }
        Some(bytes)
    }

    /// Sends one request; returns its MessageId and the frame answering it.
    async fn request(
        &mut self,
        state: &Arc<ServerState>,
        command: Command,
        body: &[u8],
    ) -> (u64, Vec<u8>) {
        let (mid, msg) = self.message(command, body);
        let reply = self.dispatch(state, &msg).await.expect("a response");
        (mid, reply)
    }

    /// The next message queued for the connection outside the reader.
    async fn next(&mut self) -> Vec<u8> {
        self.rx.recv().await.expect("a queued message")
    }
}

fn create_body(access: u32, share: u32, lease: bool) -> Vec<u8> {
    create_body_with(access, share, lease.then_some(RH))
}

/// A CREATE of f.txt asking for the lease state `lease` under
/// `LEASE_KEY`.
fn create_body_with(access: u32, share: u32, lease: Option<u32>) -> Vec<u8> {
    let name = crate::utils::utf16le("f.txt");
    let mut contexts = Vec::new();
    if let Some(state) = lease {
        let data = LeaseContext {
            key: LEASE_KEY,
            state,
            ..LeaseContext::default()
        }
        .encode();
        CreateContext::encode_chain(
            &[CreateContext {
                name: CreateContext::NAME_RQLS.to_vec(),
                data,
            }],
            &mut contexts,
        )
        .expect("contexts");
    }
    let name_padded = {
        let mut n = name.clone();
        n.resize(n.len().next_multiple_of(8), 0);
        n
    };
    let mut body = Vec::new();
    CreateRequest {
        structure_size: 57,
        security_flags: 0,
        requested_oplock_level: if lease.is_some() { 0xFF } else { 0 },
        impersonation_level: 2,
        smb_create_flags: 0,
        reserved: 0,
        desired_access: access,
        file_attributes: 0,
        share_access: share,
        create_disposition: 1,
        create_options: 0,
        name_offset: 0x78,
        name_length: name.len() as u16,
        create_contexts_offset: if lease.is_some() {
            0x78 + name_padded.len() as u32
        } else {
            0
        },
        create_contexts_length: contexts.len() as u32,
        name: name_padded,
        create_contexts: contexts,
    }
    .write_to(&mut body)
    .expect("create");
    body
}

fn close_body(file_id: FileId) -> Vec<u8> {
    let mut body = Vec::new();
    CloseRequest {
        structure_size: 24,
        flags: 0,
        reserved: 0,
        file_id,
    }
    .write_to(&mut body)
    .expect("close");
    body
}

fn ack_body(state: u32) -> Vec<u8> {
    let mut body = Vec::new();
    LeaseBreakAck {
        structure_size: 36,
        reserved: 0,
        flags: 0,
        lease_key: LEASE_KEY,
        lease_state: state,
        lease_duration: 0,
    }
    .write_to(&mut body)
    .expect("ack");
    body
}

fn status(frame: &[u8]) -> u32 {
    read_u32(frame, 0x08)
}

fn header(frame: &[u8]) -> Smb2Header {
    Smb2Header::parse(frame).expect("header").0
}

async fn server() -> Arc<ServerState> {
    serve(MemFsBackend::new().with_file("f.txt", b"data")).await
}

/// A server with the public share `home` on `backend`.
async fn serve(backend: impl crate::ShareBackend) -> Arc<ServerState> {
    let server = SmbServer::builder()
        .listen("127.0.0.1:0".parse().unwrap())
        .share(Share::new("home", backend).public())
        .build()
        .expect("build");
    server.state()
}

/// A server whose `home` share holds f.txt, and a view of its files.
async fn server_with_files() -> (Arc<ServerState>, MemFsBackend) {
    let backend = MemFsBackend::new().with_file("f.txt", b"data");
    (serve(backend.clone()).await, backend)
}

/// Whether an open on `home` has f.txt as its name.
async fn f_is_open(state: &Arc<ServerState>) -> bool {
    let share = state.find_share("home").await.expect("share");
    share.files.path_is_open(&"f.txt".parse().unwrap(), false)
}

/// A holder with RH on f.txt that shares read and write only, and a waiter
/// whose CREATE for DELETE went asynchronous. Returns the holder's FileId
/// and the AsyncId of the waiting CREATE.
async fn waiting_create(
    state: &Arc<ServerState>,
    waiter_signed: bool,
) -> (Peer, FileId, Peer, u64) {
    let mut holder = Peer::new(state, false).await;
    let (_, reply) = holder
        .request(
            state,
            Command::Create,
            &create_body(READ_WRITE, SHARE_READ_WRITE, true),
        )
        .await;
    assert_eq!(status(&reply), 0);
    let held = CreateResponse::parse(&reply[SMB2_HEADER_LEN..]).expect("create response");
    let mut waiter = Peer::new(state, waiter_signed).await;
    let (_, interim) = waiter
        .request(
            state,
            Command::Create,
            &create_body(DELETE | READ_ATTRIBUTES, 0x7, false),
        )
        .await;
    assert_eq!(status(&interim), ntstatus::STATUS_PENDING);
    let async_id = header(&interim).async_id().expect("an AsyncId");
    (holder, held.file_id, waiter, async_id)
}

#[tokio::test]
async fn interim_and_final_responses_follow_the_async_rules() {
    let state = server().await;
    let (mut holder, held, mut waiter, async_id) = waiting_create(&state, true).await;

    let notice = holder.rx.try_recv().expect("break sent");
    let n = LeaseBreakNotification::parse(&notice[SMB2_HEADER_LEN..]).expect("break");
    assert_eq!(n.flags, LeaseBreakNotification::FLAG_ACK_REQUIRED);
    assert_eq!((n.current_lease_state, n.new_lease_state), (RH, 0x1));

    let (_, closed) = holder
        .request(&state, Command::Close, &close_body(held))
        .await;
    assert_eq!(status(&closed), 0);
    let last = waiter.next().await;
    let hdr = header(&last);
    assert_eq!(hdr.command, Command::Create);
    assert_eq!(status(&last), 0);
    assert_ne!(hdr.flags & SMB2_FLAGS_ASYNC_COMMAND, 0);
    assert_eq!(hdr.async_id(), Some(async_id));
    assert_eq!(hdr.credit_request_response, 0);
    assert_ne!(hdr.flags & SMB2_FLAGS_SIGNED, 0);
    assert!(verify(&last, &KEY, SigningAlgo::AesCmac).is_ok());
    assert_eq!(waiter.conn.pending.len(), 0);
}

#[tokio::test]
async fn an_interim_response_grants_credits_and_is_never_signed() {
    let state = server().await;
    let mut holder = Peer::new(&state, false).await;
    holder
        .request(
            &state,
            Command::Create,
            &create_body(READ_WRITE, SHARE_READ_WRITE, true),
        )
        .await;
    let mut waiter = Peer::new(&state, true).await;
    let (mid, interim) = waiter
        .request(
            &state,
            Command::Create,
            &create_body(DELETE | READ_ATTRIBUTES, 0x7, false),
        )
        .await;
    let hdr = header(&interim);
    assert_eq!(hdr.channel_sequence_status, ntstatus::STATUS_PENDING);
    assert_ne!(hdr.flags & SMB2_FLAGS_ASYNC_COMMAND, 0);
    assert_eq!(hdr.flags & SMB2_FLAGS_SIGNED, 0);
    assert!(hdr.async_id().is_some_and(|id| id != 0));
    assert_eq!(hdr.message_id, mid);
    assert_ne!(hdr.credit_request_response, 0);
    // An ERROR body with no data.
    assert_eq!(interim.len(), SMB2_HEADER_LEN + 9);
}

#[tokio::test]
async fn a_compound_frame_ends_with_the_interim_response() {
    let state = server().await;
    let mut holder = Peer::new(&state, false).await;
    holder
        .request(
            &state,
            Command::Create,
            &create_body(READ_WRITE, SHARE_READ_WRITE, true),
        )
        .await;
    let mut waiter = Peer::new(&state, false).await;
    let (_, mut echo) = waiter.message(Command::Echo, &[4, 0, 0, 0]);
    let (create_mid, create) = waiter.message(
        Command::Create,
        &create_body(DELETE | READ_ATTRIBUTES, 0x7, false),
    );
    echo.resize(echo.len().next_multiple_of(8), 0);
    let next = echo.len() as u32;
    echo[0x14..0x18].copy_from_slice(&next.to_le_bytes());
    echo.extend_from_slice(&create);
    let frame = waiter.dispatch(&state, &echo).await.expect("a response");
    let first = header(&frame);
    assert_eq!(first.command, Command::Echo);
    assert_eq!(first.channel_sequence_status, 0);
    let second = &frame[first.next_command as usize..];
    let hdr = header(second);
    assert_eq!(hdr.command, Command::Create);
    assert_eq!(hdr.channel_sequence_status, ntstatus::STATUS_PENDING);
    assert_eq!(hdr.message_id, create_mid);
    assert!(hdr.async_id().is_some_and(|id| id != 0));
    assert_eq!(hdr.next_command, 0);
}

#[tokio::test(start_paused = true)]
async fn an_unacknowledged_break_times_out_and_the_wait_ends() {
    let state = server().await;
    let started = tokio::time::Instant::now();
    let (mut holder, _held, mut waiter, async_id) = waiting_create(&state, false).await;
    assert!(holder.rx.try_recv().is_some(), "break sent");

    // The holder keeps its handle and never acknowledges.
    let last = waiter.next().await;
    assert!(started.elapsed() >= LEASE_BREAK_TIMEOUT);
    assert!(started.elapsed() < LEASE_BREAK_TIMEOUT + Duration::from_secs(5));
    assert_eq!(header(&last).async_id(), Some(async_id));
    assert_eq!(status(&last), ntstatus::STATUS_SHARING_VIOLATION);
    assert!(
        holder.rx.try_recv().is_none(),
        "nothing more for the holder"
    );

    // The lease dropped to NONE: nothing is left to acknowledge.
    let (_, reply) = holder
        .request(&state, Command::OplockBreak, &ack_body(0x1))
        .await;
    assert_eq!(status(&reply), ntstatus::STATUS_UNSUCCESSFUL);
}

#[tokio::test(start_paused = true)]
async fn an_acknowledgment_stops_the_timer() {
    let state = server().await;
    let (mut holder, _held, mut waiter, _mid) = waiting_create(&state, false).await;
    assert!(holder.rx.try_recv().is_some(), "break sent");
    let (_, reply) = holder
        .request(&state, Command::OplockBreak, &ack_body(0x1))
        .await;
    assert_eq!(status(&reply), 0);
    assert_eq!(
        LeaseBreakAck::parse(&reply[SMB2_HEADER_LEN..])
            .expect("ack response")
            .lease_state,
        0x1
    );
    // The holder kept its handle, so the waiting CREATE fails at once.
    assert_eq!(
        status(&waiter.next().await),
        ntstatus::STATUS_SHARING_VIOLATION
    );
    tokio::time::sleep(LEASE_BREAK_TIMEOUT * 2).await;
    assert!(holder.rx.try_recv().is_none());
    // Still R after the timeout would have passed: a write breaks it from R.
    let (_, reply) = waiter
        .request(
            &state,
            Command::Create,
            &create_body(READ_WRITE, 0x7, false),
        )
        .await;
    assert_eq!(status(&reply), 0);
    let opened = CreateResponse::parse(&reply[SMB2_HEADER_LEN..]).expect("create response");
    let mut write = Vec::new();
    WriteRequest {
        structure_size: 49,
        data_offset: WriteRequest::STANDARD_DATA_OFFSET,
        length: 1,
        offset: 0,
        file_id: opened.file_id,
        channel: 0,
        remaining_bytes: 0,
        write_channel_info_offset: 0,
        write_channel_info_length: 0,
        flags: 0,
        data: vec![b'x'],
    }
    .write_to(&mut write)
    .expect("write");
    let (_, reply) = waiter.request(&state, Command::Write, &write).await;
    assert_eq!(status(&reply), 0);
    let notice = holder.rx.try_recv().expect("break from R");
    let n = LeaseBreakNotification::parse(&notice[SMB2_HEADER_LEN..]).expect("break");
    assert_eq!(
        (n.flags, n.current_lease_state, n.new_lease_state),
        (0, 0x1, 0)
    );
}

#[tokio::test]
async fn a_break_no_connection_takes_drops_the_lease_and_ends_the_wait() {
    let state = server().await;
    let mut holder = Peer::new(&state, false).await;
    holder
        .request(
            &state,
            Command::Create,
            &create_body(READ_WRITE, SHARE_READ_WRITE, true),
        )
        .await;
    holder.conn.outbound.close();
    let mut waiter = Peer::new(&state, false).await;
    let (_, reply) = waiter
        .request(
            &state,
            Command::Create,
            &create_body(DELETE | READ_ATTRIBUTES, 0x7, false),
        )
        .await;
    // Either the CREATE noticed the failed delivery before it went
    // asynchronous, or its final response follows.
    let last = if status(&reply) == ntstatus::STATUS_PENDING {
        waiter.next().await
    } else {
        reply
    };
    assert_eq!(status(&last), ntstatus::STATUS_SHARING_VIOLATION);
    let (_, reply) = holder
        .request(&state, Command::OplockBreak, &ack_body(0x1))
        .await;
    assert_eq!(status(&reply), ntstatus::STATUS_UNSUCCESSFUL);
}

#[tokio::test]
async fn cancel_from_another_session_is_ignored() {
    let state = server().await;
    let (_holder, _held, mut waiter, async_id) = waiting_create(&state, false).await;
    // The waiting CREATE was the waiter's first request.
    let mid = 1;
    let cancel = waiter.message_with(Command::Cancel, mid, 2, &[4, 0, 0, 0]);
    assert!(waiter.dispatch(&state, &cancel).await.is_none());
    tokio::task::yield_now().await;
    assert!(waiter.rx.try_recv().is_none());
    assert_eq!(waiter.conn.pending.len(), 1);

    let cancel = waiter.message_with(Command::Cancel, mid, 1, &[4, 0, 0, 0]);
    assert!(waiter.dispatch(&state, &cancel).await.is_none());
    let last = waiter.next().await;
    assert_eq!(status(&last), ntstatus::STATUS_CANCELLED);
    assert_eq!(header(&last).async_id(), Some(async_id));
}

#[tokio::test]
async fn logoff_ends_a_waiting_create_with_its_session() {
    let state = server().await;
    let (_holder, _held, mut waiter, async_id) = waiting_create(&state, true).await;
    let (_, reply) = waiter.request(&state, Command::Logoff, &[4, 0, 0, 0]).await;
    assert_eq!(status(&reply), 0);
    let last = waiter.next().await;
    assert_eq!(header(&last).async_id(), Some(async_id));
    assert_eq!(status(&last), ntstatus::STATUS_USER_SESSION_DELETED);
    // Signed with the key of the session it came on.
    assert!(verify(&last, &KEY, SigningAlgo::AesCmac).is_ok());
}

#[tokio::test]
async fn tree_disconnect_ends_a_waiting_create_with_its_tree() {
    let state = server().await;
    let (_holder, _held, mut waiter, async_id) = waiting_create(&state, false).await;
    let (_, reply) = waiter
        .request(&state, Command::TreeDisconnect, &[4, 0, 0, 0])
        .await;
    assert_eq!(status(&reply), 0);
    let last = waiter.next().await;
    assert_eq!(header(&last).async_id(), Some(async_id));
    assert_eq!(status(&last), ntstatus::STATUS_NETWORK_NAME_DELETED);
}

#[tokio::test]
async fn connection_teardown_cancels_waiting_requests() {
    let state = server().await;
    let (_holder, _held, mut waiter, async_id) = waiting_create(&state, false).await;
    assert_eq!(waiter.conn.pending.len(), 1);
    waiter.conn.pending.shutdown(Duration::from_secs(1)).await;
    let last = waiter.next().await;
    assert_eq!(header(&last).async_id(), Some(async_id));
    assert_eq!(status(&last), ntstatus::STATUS_CANCELLED);
    assert_eq!(waiter.conn.pending.len(), 0);
}

/// `messages` chained into one compound frame.
fn compound(messages: &[Vec<u8>]) -> Vec<u8> {
    let mut frame = Vec::new();
    for (index, msg) in messages.iter().enumerate() {
        let mut msg = msg.clone();
        if index + 1 < messages.len() {
            msg.resize(msg.len().next_multiple_of(8), 0);
            let next = msg.len() as u32;
            msg[0x14..0x18].copy_from_slice(&next.to_le_bytes());
        }
        frame.extend_from_slice(&msg);
    }
    frame
}

fn write_body(file_id: FileId, data: Vec<u8>) -> Vec<u8> {
    let mut body = Vec::new();
    WriteRequest {
        structure_size: 49,
        data_offset: WriteRequest::STANDARD_DATA_OFFSET,
        length: data.len() as u32,
        offset: 0,
        file_id,
        channel: 0,
        remaining_bytes: 0,
        write_channel_info_offset: 0,
        write_channel_info_length: 0,
        flags: 0,
        data,
    }
    .write_to(&mut body)
    .expect("write");
    body
}

/// A holder with RH on f.txt that shares read and write only.
async fn holder(state: &Arc<ServerState>) -> Peer {
    let mut holder = Peer::new(state, false).await;
    let (_, reply) = holder
        .request(
            state,
            Command::Create,
            &create_body(READ_WRITE, SHARE_READ_WRITE, true),
        )
        .await;
    assert_eq!(status(&reply), 0);
    holder
}

#[tokio::test]
async fn a_waiting_request_holds_only_itself_and_what_follows_it() {
    let state = server().await;
    let _holder = holder(&state).await;
    const BIG: usize = 256 * 1024;

    let mut waiter = Peer::new(&state, false).await;
    let (_, write) = waiter.message(Command::Write, &write_body(FileId::new(9, 9), vec![0; BIG]));
    let (_, create) = waiter.message(
        Command::Create,
        &create_body(DELETE | READ_ATTRIBUTES, 0x7, false),
    );
    let create_len = create.len();
    waiter
        .dispatch(&state, &compound(&[write, create]))
        .await
        .expect("a response");
    assert_eq!(waiter.conn.pending.held_bytes(), create_len);

    let mut waiter = Peer::new(&state, false).await;
    let (_, create) = waiter.message(
        Command::Create,
        &create_body(DELETE | READ_ATTRIBUTES, 0x7, false),
    );
    let (_, write) = waiter.message(Command::Write, &write_body(FileId::new(9, 9), vec![0; BIG]));
    let frame = compound(&[create, write]);
    waiter.dispatch(&state, &frame).await.expect("a response");
    assert_eq!(waiter.conn.pending.held_bytes(), frame.len());
}

#[tokio::test]
async fn a_further_break_follows_the_acknowledgment_response() {
    let state = server().await;
    let (mut holder, _held, _waiter, _) = waiting_create(&state, false).await;
    assert!(holder.rx.try_recv().is_some(), "break to R sent");

    // A write during the break needs no read caching.
    let mut writer = Peer::new(&state, false).await;
    let (_, reply) = writer
        .request(
            &state,
            Command::Create,
            &create_body(READ_WRITE, 0x7, false),
        )
        .await;
    let opened = CreateResponse::parse(&reply[SMB2_HEADER_LEN..]).expect("create response");
    let (_, reply) = writer
        .request(
            &state,
            Command::Write,
            &write_body(opened.file_id, vec![b'x']),
        )
        .await;
    assert_eq!(status(&reply), 0);
    assert!(holder.rx.try_recv().is_none());

    let (_, ack) = holder.message(Command::OplockBreak, &ack_body(0x1));
    let out = dispatch_frame(&state, &holder.conn, &ack)
        .await
        .expect("a response");
    assert_eq!(status(&out.bytes), 0);
    assert!(
        holder.rx.try_recv().is_none(),
        "nothing goes out before the response is queued"
    );
    drop(out.after_send);
    let notice = holder.rx.try_recv().expect("break on to NONE");
    let n = LeaseBreakNotification::parse(&notice[SMB2_HEADER_LEN..]).expect("break");
    assert_eq!(
        (n.flags, n.current_lease_state, n.new_lease_state),
        (0, 0x1, 0)
    );
}

#[tokio::test]
async fn a_create_past_the_waiting_limit_is_refused() {
    let state = server().await;
    let _holder = holder(&state).await;
    let mut waiter = Peer::new(&state, false).await;
    let body = create_body(DELETE | READ_ATTRIBUTES, 0x7, false);
    for _ in 0..crate::conn::pending::MAX_PENDING_REQUESTS {
        let (_, reply) = waiter.request(&state, Command::Create, &body).await;
        assert_eq!(status(&reply), ntstatus::STATUS_PENDING);
    }
    let (_, reply) = waiter.request(&state, Command::Create, &body).await;
    assert_eq!(status(&reply), ntstatus::STATUS_INSUFFICIENT_RESOURCES);
    assert_eq!(
        waiter.conn.pending.len(),
        crate::conn::pending::MAX_PENDING_REQUESTS
    );
}

/// A holder with RWH on f.txt, sharing everything, and a waiter whose open
/// for reading and writing waits for write caching to be given up.
async fn waiting_for_write_caching(state: &Arc<ServerState>) -> (Peer, Peer) {
    let mut holder = Peer::new(state, false).await;
    let (_, reply) = holder
        .request(
            state,
            Command::Create,
            &create_body_with(READ_WRITE, 0x7, Some(0x7)),
        )
        .await;
    assert_eq!(status(&reply), 0);
    let mut waiter = Peer::new(state, false).await;
    let (_, interim) = waiter
        .request(state, Command::Create, &create_body(READ_WRITE, 0x7, false))
        .await;
    assert_eq!(status(&interim), ntstatus::STATUS_PENDING);
    let notice = holder.rx.try_recv().expect("write break");
    let n = LeaseBreakNotification::parse(&notice[SMB2_HEADER_LEN..]).expect("break");
    assert_eq!((n.current_lease_state, n.new_lease_state), (0x7, RH));
    (holder, waiter)
}

#[tokio::test(start_paused = true)]
async fn a_waiting_open_goes_ahead_once_an_unacknowledged_write_break_times_out() {
    let state = server().await;
    let started = tokio::time::Instant::now();
    let (mut holder, mut waiter) = waiting_for_write_caching(&state).await;
    let last = waiter.next().await;
    assert_eq!(status(&last), 0);
    assert!(started.elapsed() >= LEASE_BREAK_TIMEOUT);
    // The lease dropped to NONE: nothing is left to acknowledge.
    let (_, reply) = holder
        .request(&state, Command::OplockBreak, &ack_body(RH))
        .await;
    assert_eq!(status(&reply), ntstatus::STATUS_UNSUCCESSFUL);
}

#[tokio::test]
async fn a_cancelled_open_waiting_in_the_table_leaves_it() {
    let state = server().await;
    let (holder, mut waiter) = waiting_for_write_caching(&state).await;
    let share = state.find_share("home").await.expect("share");
    let cancel = waiter.message_with(Command::Cancel, 1, 1, &[4, 0, 0, 0]);
    assert!(waiter.dispatch(&state, &cancel).await.is_none());
    assert_eq!(status(&waiter.next().await), ntstatus::STATUS_CANCELLED);
    // Only the holder's open is left on the file.
    holder.conn.close_all().await;
    assert!(!share.files.path_is_open(&"f.txt".parse().unwrap(), false));
}

#[tokio::test]
async fn teardown_ends_an_open_waiting_in_the_table() {
    let (state, files) = server_with_files().await;
    let (holder, mut waiter) = waiting_for_write_caching(&state).await;
    assert_eq!(files.open_handles(), 2);
    waiter.conn.pending.shutdown(Duration::from_secs(1)).await;
    assert_eq!(status(&waiter.next().await), ntstatus::STATUS_CANCELLED);
    assert_eq!(
        files.open_handles(),
        1,
        "the waiting open's handle is closed"
    );
    holder.conn.close_all().await;
    assert!(!f_is_open(&state).await, "and its table entry is gone");
}

#[tokio::test]
async fn logoff_and_tree_disconnect_end_an_open_waiting_in_the_table() {
    for command in [Command::Logoff, Command::TreeDisconnect] {
        let (state, files) = server_with_files().await;
        let (_holder, mut waiter) = waiting_for_write_caching(&state).await;
        let (_, reply) = waiter.request(&state, command, &[4, 0, 0, 0]).await;
        assert_eq!(status(&reply), 0);
        let expected = match command {
            Command::Logoff => ntstatus::STATUS_USER_SESSION_DELETED,
            _ => ntstatus::STATUS_NETWORK_NAME_DELETED,
        };
        assert_eq!(status(&waiter.next().await), expected, "{command:?}");
        assert_eq!(files.open_handles(), 1, "{command:?}");
    }
}

#[tokio::test]
async fn a_holder_that_closes_instead_of_acknowledging_lets_the_open_go_ahead() {
    let (state, files) = server_with_files().await;
    let (holder, mut waiter) = waiting_for_write_caching(&state).await;
    holder.conn.close_all().await;
    assert_eq!(status(&waiter.next().await), 0);
    assert_eq!(files.open_handles(), 1);
}

#[tokio::test(start_paused = true)]
async fn a_wait_whose_timer_is_lost_gives_up_and_closes_what_it_opened() {
    let (state, files) = server_with_files().await;
    let (_holder, mut waiter) = waiting_for_write_caching(&state).await;
    let share = state.find_share("home").await.expect("share");
    // Let the timer start, then lose it.
    tokio::task::yield_now().await;
    share.files.stop_timers();
    let started = tokio::time::Instant::now();
    let last = waiter.next().await;
    assert_eq!(status(&last), ntstatus::STATUS_SHARING_VIOLATION);
    assert!(started.elapsed() > LEASE_BREAK_TIMEOUT);
    assert!(started.elapsed() <= crate::files::MAX_BREAK_WAIT);
    assert_eq!(files.open_handles(), 1);
}

/// Memory backend whose next `misses` plain opens report the file missing,
/// as if it appeared just after.
struct LateFile {
    inner: MemFsBackend,
    misses: Arc<std::sync::atomic::AtomicUsize>,
}

#[async_trait::async_trait]
impl crate::ShareBackend for LateFile {
    async fn open(
        &self,
        path: &crate::SmbPath,
        opts: crate::OpenOptions,
    ) -> crate::SmbResult<(Box<dyn crate::Handle>, crate::OpenAction)> {
        let miss = opts.intent == crate::OpenIntent::Open
            && self
                .misses
                .fetch_update(
                    std::sync::atomic::Ordering::AcqRel,
                    std::sync::atomic::Ordering::Acquire,
                    |n| n.checked_sub(1),
                )
                .is_ok();
        if miss {
            return Err(crate::SmbError::NotFound);
        }
        self.inner.open(path, opts).await
    }

    async fn unlink(&self, path: &crate::SmbPath) -> crate::SmbResult<()> {
        self.inner.unlink(path).await
    }

    async fn rename(
        &self,
        from: &crate::SmbPath,
        to: &crate::SmbPath,
        replace: bool,
    ) -> crate::SmbResult<()> {
        self.inner.rename(from, to, replace).await
    }

    fn capabilities(&self) -> crate::BackendCapabilities {
        self.inner.capabilities()
    }
}

#[tokio::test]
async fn an_overwrite_that_finds_no_file_and_then_one_still_waits_before_truncating() {
    let files = MemFsBackend::new().with_file("f.txt", b"data");
    let misses = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let state = serve(LateFile {
        inner: files.clone(),
        misses: Arc::clone(&misses),
    })
    .await;
    let mut holder = Peer::new(&state, false).await;
    let (_, reply) = holder
        .request(
            &state,
            Command::Create,
            &create_body_with(READ_WRITE, 0x7, Some(0x7)),
        )
        .await;
    assert_eq!(status(&reply), 0);

    misses.store(1, std::sync::atomic::Ordering::Release);
    let mut waiter = Peer::new(&state, false).await;
    let mut body = create_body(READ_WRITE, 0x7, false);
    // CreateDisposition FILE_OVERWRITE_IF.
    body[36..40].copy_from_slice(&5u32.to_le_bytes());
    let (_, interim) = waiter.request(&state, Command::Create, &body).await;
    assert_eq!(status(&interim), ntstatus::STATUS_PENDING);
    let size = async || {
        let path: crate::SmbPath = "f.txt".parse().unwrap();
        let (handle, _) = files
            .open(&path, crate::OpenOptions::default())
            .await
            .unwrap();
        let size = handle.stat().await.unwrap().end_of_file;
        handle.close().await.unwrap();
        size
    };
    assert_eq!(
        size().await,
        4,
        "nothing truncated while the holder caches writes"
    );

    let (_, reply) = holder
        .request(&state, Command::OplockBreak, &ack_body(0))
        .await;
    assert_eq!(status(&reply), 0);
    assert_eq!(status(&waiter.next().await), 0);
    assert_eq!(size().await, 0);
}
