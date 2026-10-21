//! A connection driven through the dispatcher without a socket, for tests
//! that need the server's state at hand.

use std::sync::Arc;

use tokio::sync::RwLock;
use uuid::Uuid;

use crate::Access;
use crate::conn::state::{Connection, Session, TreeConnect};
use crate::conn::writer::{ResponseReceiver, response_queue};
use crate::dispatch::{Outgoing, dispatch_frame, read_u32};
use crate::proto::auth::ntlm::Identity;
use crate::proto::crypto::{SigningAlgo, sign};
use crate::proto::header::{Command, HeaderTail, SMB2_FLAGS_SIGNED, Smb2Header};
use crate::proto::messages::Dialect;
use crate::server::{ServerState, ShareBindings};

/// Signing key of the signed sessions.
pub(crate) const KEY: [u8; 16] = [0x5A; 16];

/// One connection with session 1 on tree 1, of `home` unless made with
/// [`Peer::on_ipc`], and the queue its unsolicited messages and late
/// responses go to.
pub(crate) struct Peer {
    pub(crate) conn: Arc<Connection>,
    pub(crate) rx: ResponseReceiver,
    next_mid: u64,
    signed: bool,
}

impl Peer {
    /// A peer whose session is alice's and signed when `signed`, otherwise
    /// anonymous, from a client without a ClientGuid.
    pub(crate) async fn new(state: &Arc<ServerState>, signed: bool) -> Self {
        Self::from_client(state, signed, Uuid::nil()).await
    }

    /// [`Peer::new`] from the client `client`.
    pub(crate) async fn from_client(state: &Arc<ServerState>, signed: bool, client: Uuid) -> Self {
        let share = state.find_share("home").await.expect("share");
        Self::on_share(state, signed, client, share, Access::ReadWrite).await
    }

    /// [`Peer::new`] with tree 1 on IPC$.
    pub(crate) async fn on_ipc(state: &Arc<ServerState>, signed: bool) -> Self {
        let ipc = ShareBindings::ipc();
        Self::on_share(state, signed, Uuid::nil(), ipc, Access::Read).await
    }

    async fn on_share(
        state: &Arc<ServerState>,
        signed: bool,
        client: Uuid,
        share: Arc<ShareBindings>,
        access: Access,
    ) -> Self {
        let conn = Arc::new(Connection::new(state.config.server_guid, 1 << 20, 1 << 20));
        *conn.dialect.write().await = Some(Dialect::Smb300);
        *conn.signing_algo.write().await = SigningAlgo::AesCmac;
        *conn.client_guid.write().await = client;
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
        let tree = TreeConnect::new(1, share, access);
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
    pub(crate) fn message(&mut self, command: Command, body: &[u8]) -> (u64, Vec<u8>) {
        let mid = self.next_mid;
        self.next_mid += 1;
        (mid, self.message_with(command, mid, 1, body))
    }

    pub(crate) fn message_with(
        &self,
        command: Command,
        mid: u64,
        session_id: u64,
        body: &[u8],
    ) -> Vec<u8> {
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
    pub(crate) async fn dispatch(&self, state: &Arc<ServerState>, frame: &[u8]) -> Option<Vec<u8>> {
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
    pub(crate) async fn request(
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
    pub(crate) async fn next(&mut self) -> Vec<u8> {
        self.rx.recv().await.expect("a queued message")
    }

    /// Ends the connection as the server does when the client goes away:
    /// nothing more goes out, and its durable opens that qualify are kept.
    pub(crate) async fn drop_connection(&self, state: &Arc<ServerState>) {
        self.conn.mark_closing();
        self.conn
            .pending
            .shutdown(std::time::Duration::from_secs(1))
            .await;
        self.conn.outbound.close();
        self.conn.close_all(Some(&state.durable)).await;
    }
}

pub(crate) fn status(frame: &[u8]) -> u32 {
    read_u32(frame, 0x08)
}

pub(crate) fn header(frame: &[u8]) -> Smb2Header {
    Smb2Header::parse(frame).expect("header").0
}
