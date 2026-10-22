//! Connection / session / tree / open state held during a single TCP
//! connection's lifetime.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use crate::proto::auth::ntlm::{Identity, NtlmServer};
use crate::proto::crypto::{Cipher, PreauthIntegrity, SessionCipher, SigningAlgo};
use crate::proto::messages::{Dialect, FileId};
use tokio::sync::RwLock;
use uuid::Uuid;

use crate::backend::{FileTimes, Handle};
use crate::builder::Access;
use crate::conn::outbound::Outbound;
use crate::conn::pending::{PendingOps, Stop};
use crate::files::{
    Closing, DurableReg, DurableTable, FileRef, NotifyBudget, OpenSlot, WatchReg, close_opens,
    end_opens, finish_close,
};
use crate::path::SmbPath;
use crate::rpc::pipe::{Pipe, PipeBudget};
use crate::server::ShareBindings;

/// In-flight NTLM acceptor + a `is_raw_ntlmssp` flag (true = raw, false =
/// SPNEGO-wrapped). The handler hands the second-round response back in the
/// same form the client opened with.
pub type PendingAuth = Arc<Mutex<(NtlmServer, bool)>>;

/// Most NTLM exchanges one connection may have waiting for their final
/// SESSION_SETUP round.
pub const MAX_PENDING_AUTHS: usize = 16;

// ---------------------------------------------------------------------------
// Connection
// ---------------------------------------------------------------------------

/// One connection's negotiated state and its session/tree/open tables.
pub struct Connection {
    pub server_guid: Uuid,
    pub client_guid: tokio::sync::RwLock<Uuid>,
    pub dialect: tokio::sync::RwLock<Option<Dialect>>,
    pub signing_algo: tokio::sync::RwLock<SigningAlgo>,
    /// Connection.CipherId: the cipher SMB 3.x sessions encrypt with, `None`
    /// when the client cannot encrypt.
    pub cipher: tokio::sync::RwLock<Option<Cipher>>,
    /// Connection.PreauthIntegrityHashValue after NEGOTIATE. SMB 3.1.1
    /// SESSION_SETUP exchanges fork this into `session_preauth`.
    pub preauth: Mutex<PreauthIntegrity>,
    /// Max READ/WRITE sizes advertised in the NEGOTIATE response.
    pub max_read_size: tokio::sync::RwLock<u32>,
    pub max_write_size: tokio::sync::RwLock<u32>,

    /// Sessions keyed by SessionId.
    pub sessions: RwLock<HashMap<u64, Arc<RwLock<Session>>>>,

    /// In-flight NTLM acceptors keyed by SessionId. They live outside
    /// `Session` because a `Session` is created only when the final
    /// SESSION_SETUP round succeeds; until then the acceptor lives here. The
    /// `bool` records whether the client sent raw NTLMSSP (true) or
    /// SPNEGO-wrapped (false) so the second-round response matches form.
    pub pending_auths: RwLock<HashMap<u64, PendingAuth>>,

    /// In-flight SMB 3.1.1 preauth state keyed by SessionId during
    /// multi-leg SESSION_SETUP.
    pub session_preauth: RwLock<HashMap<u64, PreauthIntegrity>>,

    /// Set when the connection must close without sending a reply.
    disconnect: AtomicBool,

    /// Set once the connection takes no more requests and is closing.
    closing: AtomicBool,

    /// Connection.CommandSequenceWindow: the MessageIds the client may use.
    pub credits: Mutex<crate::conn::credits::CreditWindow>,

    /// When each SESSION_SETUP exchange in `pending_auths` started.
    pub pending_auth_started: Mutex<HashMap<u64, std::time::Instant>>,

    /// The client's NEGOTIATE request, kept for FSCTL_VALIDATE_NEGOTIATE_INFO
    /// and the session signing rules.
    pub client_negotiate: Mutex<Option<crate::handlers::negotiate::ClientNegotiate>>,
    /// Failed logons on this connection.
    pub logon_failures: AtomicU32,

    /// Opens held on this connection, across its sessions and trees.
    pub open_count: Arc<std::sync::atomic::AtomicUsize>,

    /// The client's address, set when the connection is accepted.
    pub peer_addr: Option<std::net::SocketAddr>,

    /// Where lease breaks for this connection's opens are sent.
    pub(crate) outbound: Arc<Outbound>,

    /// Requests answered asynchronously that are still running.
    pub(crate) pending: PendingOps,

    /// The named pipes open on this connection and the bytes they hold.
    pub(crate) pipe_budget: Arc<PipeBudget>,

    /// The change notification watches of this connection's opens and the
    /// bytes they buffer.
    pub(crate) notify_budget: Arc<NotifyBudget>,
}

impl Connection {
    pub fn new(server_guid: Uuid, max_read_size: u32, max_write_size: u32) -> Self {
        Self {
            server_guid,
            client_guid: tokio::sync::RwLock::new(Uuid::nil()),
            dialect: tokio::sync::RwLock::new(None),
            signing_algo: tokio::sync::RwLock::new(SigningAlgo::HmacSha256),
            cipher: tokio::sync::RwLock::new(None),
            preauth: Mutex::new(PreauthIntegrity::new()),
            max_read_size: tokio::sync::RwLock::new(max_read_size),
            max_write_size: tokio::sync::RwLock::new(max_write_size),
            sessions: RwLock::new(HashMap::new()),
            pending_auths: RwLock::new(HashMap::new()),
            session_preauth: RwLock::new(HashMap::new()),
            disconnect: AtomicBool::new(false),
            closing: AtomicBool::new(false),
            credits: Mutex::new(crate::conn::credits::CreditWindow::new()),
            pending_auth_started: Mutex::new(HashMap::new()),
            client_negotiate: Mutex::new(None),
            logon_failures: AtomicU32::new(0),
            open_count: Arc::default(),
            peer_addr: None,
            outbound: Arc::default(),
            pending: PendingOps::default(),
            pipe_budget: Arc::default(),
            notify_budget: Arc::default(),
        }
    }

    /// Close the connection after the current request, without a reply.
    pub fn request_disconnect(&self) {
        self.disconnect.store(true, Ordering::Release);
    }

    /// True once a handler has asked to close the connection.
    pub fn disconnect_requested(&self) -> bool {
        self.disconnect.load(Ordering::Acquire)
    }

    /// Marks the connection as closing: it reads no more requests, and its
    /// sessions are about to end.
    pub(crate) fn mark_closing(&self) {
        self.closing.store(true, Ordering::Release);
    }

    /// True once the connection is closing.
    pub(crate) fn is_closing(&self) -> bool {
        self.closing.load(Ordering::Acquire)
    }

    /// Removes the session `session_id` and ends its opens; with `keep`,
    /// the durable opens that qualify stay in that table. Returns false
    /// when the connection has no such session.
    pub async fn close_session(&self, session_id: u64, keep: Option<&Arc<DurableTable>>) -> bool {
        let keep = keep.map(|table| (table, table.sweeps()));
        let removed = self.sessions.write().await.remove(&session_id);
        let Some(sess_arc) = removed else {
            return false;
        };
        self.pending
            .stop_where(Stop::Retry, |op| op.session_id == session_id);
        end_opens(detach_session(&sess_arc).await, keep).await;
        true
    }

    pub async fn close_tree(&self, session_id: u64, tree_id: u32) -> bool {
        let sess_arc = {
            let sessions = self.sessions.read().await;
            sessions.get(&session_id).cloned()
        };
        let Some(sess_arc) = sess_arc else {
            return false;
        };
        let removed = {
            let sess = sess_arc.read().await;
            let mut trees = sess.trees.write().await;
            trees.remove(&tree_id)
        };
        let Some(tree_arc) = removed else {
            return false;
        };
        self.pending.stop_where(Stop::Retry, |op| {
            op.session_id == session_id && op.tree_id == tree_id
        });
        close_opens(detach_tree(&tree_arc).await).await;
        true
    }

    /// Removes every session of `user` and returns their opens, which the
    /// caller closes with [`close_opens`].
    pub async fn detach_sessions_for_user(&self, user: &str) -> Vec<Arc<RwLock<Open>>> {
        let removed = {
            let mut sessions = self.sessions.write().await;
            let mut ids = Vec::new();
            for (session_id, sess_arc) in sessions.iter() {
                let sess = sess_arc.read().await;
                if matches!(&sess.identity, Identity::User { user: session_user, .. } if session_user == user)
                {
                    ids.push(*session_id);
                }
            }
            self.pending
                .stop_where(Stop::Retry, |op| ids.contains(&op.session_id));
            ids.into_iter()
                .filter_map(|id| sessions.remove(&id))
                .collect::<Vec<_>>()
        };
        let mut opens = Vec::new();
        for sess_arc in removed {
            opens.extend(detach_session(&sess_arc).await);
        }
        opens
    }

    /// Removes every tree connected to `share` and returns their opens,
    /// which the caller closes with [`close_opens`].
    pub async fn detach_trees_for_share(
        &self,
        share: &Arc<ShareBindings>,
    ) -> Vec<Arc<RwLock<Open>>> {
        self.detach_matching_trees(|_, tree| Arc::ptr_eq(&tree.share, share))
            .await
    }

    /// Removes every tree `user` has connected to `share` and returns their
    /// opens, which the caller closes with [`close_opens`].
    pub async fn detach_trees_for_user_share(
        &self,
        user: &str,
        share: &Arc<ShareBindings>,
    ) -> Vec<Arc<RwLock<Open>>> {
        self.detach_matching_trees(|sess, tree| {
            matches!(&sess.identity, Identity::User { user: session_user, .. } if session_user == user)
                && Arc::ptr_eq(&tree.share, share)
        })
        .await
    }

    async fn detach_matching_trees(
        &self,
        matches_tree: impl Fn(&Session, &TreeConnect) -> bool,
    ) -> Vec<Arc<RwLock<Open>>> {
        let sessions: Vec<_> = {
            let sessions = self.sessions.read().await;
            sessions
                .iter()
                .map(|(id, s)| (*id, Arc::clone(s)))
                .collect()
        };

        let mut opens = Vec::new();
        for (session_id, sess_arc) in sessions {
            let removed = {
                let sess = sess_arc.read().await;
                let mut trees = sess.trees.write().await;
                let mut ids = Vec::new();
                for (tree_id, tree_arc) in trees.iter() {
                    let tree = tree_arc.read().await;
                    if matches_tree(&sess, &tree) {
                        ids.push(*tree_id);
                    }
                }
                self.pending.stop_where(Stop::Retry, |op| {
                    op.session_id == session_id && ids.contains(&op.tree_id)
                });
                ids.into_iter()
                    .filter_map(|id| trees.remove(&id))
                    .collect::<Vec<_>>()
            };
            for tree_arc in removed {
                opens.extend(detach_tree(&tree_arc).await);
            }
        }
        opens
    }

    /// Closes every session and tree of the connection and ends their
    /// opens; with `keep`, the durable opens that qualify stay in that
    /// table. Runs when the connection ends.
    pub async fn close_all(&self, keep: Option<&Arc<DurableTable>>) {
        let keep = keep.map(|table| (table, table.sweeps()));
        let sessions: Vec<_> = self.sessions.write().await.drain().collect();
        let mut opens = Vec::new();
        for (_, sess_arc) in sessions {
            opens.extend(detach_session(&sess_arc).await);
        }
        end_opens(opens, keep).await;
    }
}

/// Removes every tree of a session that is no longer reachable and returns
/// their opens.
async fn detach_session(sess_arc: &Arc<RwLock<Session>>) -> Vec<Arc<RwLock<Open>>> {
    let trees: Vec<_> = {
        let sess = sess_arc.read().await;
        let mut trees = sess.trees.write().await;
        trees.drain().collect()
    };
    let mut opens = Vec::new();
    for (_, tree_arc) in trees {
        opens.extend(detach_tree(&tree_arc).await);
    }
    opens
}

/// Marks a tree that is no longer reachable as closed, so no CREATE adds to
/// it, drops its pipes and takes its opens. Waits for no request.
async fn detach_tree(tree_arc: &Arc<RwLock<TreeConnect>>) -> Vec<Arc<RwLock<Open>>> {
    let mut tree = tree_arc.write().await;
    tree.closed = true;
    tree.pipes
        .get_mut()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .clear();
    let opens: Vec<_> = tree.opens.write().await.drain().map(|(_, o)| o).collect();
    opens
}

// ---------------------------------------------------------------------------
// Session
// ---------------------------------------------------------------------------

pub struct Session {
    pub identity: Identity,
    pub session_base_key: [u8; 16],
    pub signing_key: [u8; 16],
    /// Whether signing is required for this session's traffic.
    pub signing_required: bool,
    /// Session.EncryptData: every message of the session is encrypted.
    pub encrypt_data: bool,
    /// Encryption and decryption keys, set once the session is established
    /// on a connection with a cipher. Anonymous sessions have none.
    pub cipher: Option<Arc<SessionCipher>>,
    pub trees: RwLock<HashMap<u32, Arc<RwLock<TreeConnect>>>>,
    /// 3.1.1: snapshot taken at SESSION_SETUP completion (after the request
    /// hash but before the response is hashed). Used as KDF context.
    pub preauth_snapshot: Option<[u8; 64]>,

    next_tree_id: AtomicU32,
}

impl Session {
    pub fn new(
        identity: Identity,
        session_base_key: [u8; 16],
        signing_key: [u8; 16],
        signing_required: bool,
        preauth_snapshot: Option<[u8; 64]>,
    ) -> Self {
        Self {
            identity,
            session_base_key,
            signing_key,
            signing_required,
            encrypt_data: false,
            cipher: None,
            trees: RwLock::new(HashMap::new()),
            preauth_snapshot,
            next_tree_id: AtomicU32::new(1),
        }
    }

    pub fn alloc_tree_id(&self) -> u32 {
        self.next_tree_id.fetch_add(1, Ordering::Relaxed)
    }

    pub fn is_anonymous(&self) -> bool {
        matches!(self.identity, Identity::Anonymous)
    }
}

// ---------------------------------------------------------------------------
// TreeConnect
// ---------------------------------------------------------------------------

pub struct TreeConnect {
    pub id: u32,
    pub share: Arc<ShareBindings>,
    pub granted_access: Access,
    pub opens: RwLock<HashMap<FileId, Arc<RwLock<Open>>>>,
    /// Named pipe opens, on an IPC$ tree. They hold no backend handle and
    /// no place in a file table.
    pub(crate) pipes: Mutex<HashMap<FileId, Arc<Pipe>>>,
    /// Set once the tree is disconnected or revoked. Opens are no longer
    /// added to it.
    pub closed: bool,
}

/// Source of FileIds. One counter for the process keeps every FileId unique
/// within its session, and -1 is never reached.
static NEXT_FILE_ID: AtomicU64 = AtomicU64::new(1);

impl TreeConnect {
    pub fn new(id: u32, share: Arc<ShareBindings>, granted_access: Access) -> Self {
        Self {
            id,
            share,
            granted_access,
            opens: RwLock::new(HashMap::new()),
            pipes: Mutex::default(),
            closed: false,
        }
    }

    pub fn alloc_file_id(&self) -> FileId {
        let v = self.alloc_volatile();
        FileId::new(v, v)
    }

    /// A volatile FileId part no other open of the process has.
    pub fn alloc_volatile(&self) -> u64 {
        NEXT_FILE_ID.fetch_add(1, Ordering::Relaxed)
    }
}

// ---------------------------------------------------------------------------
// Open / DirCursor
// ---------------------------------------------------------------------------

pub struct Open {
    pub file_id: FileId,
    pub handle: Option<Box<dyn Handle>>,
    /// Open.GrantedAccess: access mask bits, generic rights already mapped.
    pub granted_access: u32,
    pub is_directory: bool,
    /// FILE_DELETE_ON_CLOSE was set on CREATE (MS-FSA Open.Mode): the file
    /// becomes delete-pending when this open closes.
    pub delete_on_close: bool,
    pub search_state: Option<DirCursor>,
    /// Access and write times that FileBasicInformation fixed for this open
    /// (MS-FSA 2.1.5.15.2). Writes and truncation through the open, and its
    /// CLOSE, restore them.
    pub fixed_times: FileTimes,
    /// CreateOptions of the CREATE request.
    pub create_options: u32,
    /// The open's entry in its share's table of open files, which holds its
    /// current name. `None` once the open is closed.
    pub(crate) file: Option<FileRef>,
    /// Counts the open against its connection's limit.
    pub(crate) slot: Option<OpenSlot>,
    /// Set on a durable open (Open.IsDurable).
    pub(crate) durable: Option<DurableReg>,
    /// The change notification watch the first CHANGE_NOTIFY on the open
    /// armed.
    pub(crate) watch: Option<WatchReg>,
    /// A WRITE through the open changed the file; its close reports that.
    pub(crate) wrote: AtomicBool,
    /// The CREATE that made the open created or overwrote the file.
    pub(crate) created: bool,
    /// FileDispositionInformation through the open marked its directory
    /// for deletion (MS-FSA Open.ChangeNotifyDirectoryMarkedDeleted). It
    /// stays set when the mark is cleared.
    pub(crate) marked_deleted: AtomicBool,
}

impl Open {
    /// The open's current name on the share, `None` once the open is closed.
    pub fn path(&self) -> Option<SmbPath> {
        self.file.as_ref().map(FileRef::path)
    }

    /// Whether the file is delete-pending (MS-FSA Link.IsDeleted), as
    /// FileStandardInformation reports it.
    pub fn delete_pending(&self) -> bool {
        self.file.as_ref().is_some_and(FileRef::delete_pending)
    }
}

impl Drop for Open {
    /// An open dropped without a CLOSE closes on the current runtime as a
    /// CLOSE would, delete-on-close included. Without a runtime the handle
    /// and the table entry are dropped and the file stays.
    fn drop(&mut self) {
        let Some(handle) = self.handle.take() else {
            return;
        };
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            return;
        };
        let closing = Closing::announce(self, false);
        let file = self.file.take();
        runtime.spawn(finish_close(
            handle,
            file,
            self.delete_on_close,
            self.is_directory,
            closing,
        ));
    }
}

/// Iterator state for a directory listing across multiple QUERY_DIRECTORY
/// calls. We snapshot the entries once and consume them in order; subsequent
/// calls advance `next` until exhaustion.
pub struct DirCursor {
    pub entries: Vec<crate::backend::DirEntry>,
    pub next: usize,
    /// Pattern used for the current listing. RESTART_SCANS and REOPEN re-list
    /// with the request's pattern.
    pub pattern: Option<String>,
}
