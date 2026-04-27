//! Connection / session / tree / open state held during a single TCP
//! connection's lifetime.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;

use smb_proto::auth::ntlm::{Identity, NtlmServer};
use smb_proto::crypto::{PreauthIntegrity, SigningAlgo};
use smb_proto::messages::{Dialect, FileId};
use tokio::sync::RwLock;
use uuid::Uuid;

use crate::backend::Handle;
use crate::builder::Access;
use crate::path::SmbPath;
use crate::server::ShareBindings;

/// In-flight NTLM acceptor + a `is_raw_ntlmssp` flag (true = raw, false =
/// SPNEGO-wrapped). The handler hands the second-round response back in the
/// same form the client opened with.
pub type PendingAuth = Arc<tokio::sync::Mutex<(NtlmServer, bool)>>;

// ---------------------------------------------------------------------------
// Connection
// ---------------------------------------------------------------------------

/// One connection's negotiated state and its session/tree/open tables.
pub struct Connection {
    pub server_guid: Uuid,
    pub client_guid: tokio::sync::RwLock<Uuid>,
    pub dialect: tokio::sync::RwLock<Option<Dialect>>,
    pub signing_algo: tokio::sync::RwLock<SigningAlgo>,
    pub preauth: tokio::sync::Mutex<PreauthIntegrity>,
    /// Held only until SESSION_SETUP completes for the very first session.
    /// Subsequent sessions snapshot per-session preauth at the appropriate
    /// instant.
    pub negotiate_done: tokio::sync::RwLock<bool>,
    /// Granted at NEGOTIATE: large MTU support flag etc.
    pub max_read_size: tokio::sync::RwLock<u32>,
    pub max_write_size: tokio::sync::RwLock<u32>,

    /// Sessions keyed by SessionId.
    pub sessions: RwLock<HashMap<u64, Arc<RwLock<Session>>>>,

    /// In-flight NTLM acceptors keyed by SessionId. We keep them out of
    /// `Session` because a session is created only after a successful first
    /// SESSION_SETUP round — between rounds the entry lives here. The
    /// `bool` records whether the client sent raw NTLMSSP (true) or
    /// SPNEGO-wrapped (false) so the second-round response matches form.
    pub pending_auths: RwLock<HashMap<u64, PendingAuth>>,

    /// Per-session preauth snapshots taken at SESSION_SETUP request arrival —
    /// SMB 3.1.1 only.
    pub session_preauth: RwLock<HashMap<u64, PreauthIntegrity>>,

    /// Monotonic SessionId allocator.
    next_session_id: AtomicU64,
}

impl Connection {
    pub fn new(server_guid: Uuid, max_read_size: u32, max_write_size: u32) -> Self {
        Self {
            server_guid,
            client_guid: tokio::sync::RwLock::new(Uuid::nil()),
            dialect: tokio::sync::RwLock::new(None),
            signing_algo: tokio::sync::RwLock::new(SigningAlgo::HmacSha256),
            preauth: tokio::sync::Mutex::new(PreauthIntegrity::new()),
            negotiate_done: tokio::sync::RwLock::new(false),
            max_read_size: tokio::sync::RwLock::new(max_read_size),
            max_write_size: tokio::sync::RwLock::new(max_write_size),
            sessions: RwLock::new(HashMap::new()),
            pending_auths: RwLock::new(HashMap::new()),
            session_preauth: RwLock::new(HashMap::new()),
            next_session_id: AtomicU64::new(1),
        }
    }

    pub fn alloc_session_id(&self) -> u64 {
        self.next_session_id.fetch_add(1, Ordering::Relaxed)
    }
}

// ---------------------------------------------------------------------------
// Session
// ---------------------------------------------------------------------------

pub struct Session {
    pub id: u64,
    pub identity: Identity,
    pub session_base_key: [u8; 16],
    pub signing_key: [u8; 16],
    /// Whether signing is required for this session's traffic.
    pub signing_required: bool,
    pub trees: RwLock<HashMap<u32, Arc<RwLock<TreeConnect>>>>,
    /// 3.1.1: snapshot taken at SESSION_SETUP completion (after the request
    /// hash but before the response is hashed). Used as KDF context.
    pub preauth_snapshot: Option<[u8; 64]>,

    next_tree_id: AtomicU32,
}

impl Session {
    pub fn new(
        id: u64,
        identity: Identity,
        session_base_key: [u8; 16],
        signing_key: [u8; 16],
        signing_required: bool,
        preauth_snapshot: Option<[u8; 64]>,
    ) -> Self {
        Self {
            id,
            identity,
            session_base_key,
            signing_key,
            signing_required,
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
    next_volatile: AtomicU64,
}

impl TreeConnect {
    pub fn new(id: u32, share: Arc<ShareBindings>, granted_access: Access) -> Self {
        Self {
            id,
            share,
            granted_access,
            opens: RwLock::new(HashMap::new()),
            next_volatile: AtomicU64::new(1),
        }
    }

    pub fn alloc_file_id(&self) -> FileId {
        let v = self.next_volatile.fetch_add(1, Ordering::Relaxed);
        FileId::new(v, v)
    }
}

// ---------------------------------------------------------------------------
// Open / DirCursor
// ---------------------------------------------------------------------------

pub struct Open {
    pub file_id: FileId,
    pub handle: Option<Box<dyn Handle>>,
    pub granted_access: Access,
    pub last_path: SmbPath,
    pub is_directory: bool,
    pub delete_on_close: bool,
    pub search_state: Option<DirCursor>,
}

impl Open {
    pub fn new(
        file_id: FileId,
        handle: Box<dyn Handle>,
        granted_access: Access,
        last_path: SmbPath,
        is_directory: bool,
        delete_on_close: bool,
    ) -> Self {
        Self {
            file_id,
            handle: Some(handle),
            granted_access,
            last_path,
            is_directory,
            delete_on_close,
            search_state: None,
        }
    }
}

/// Iterator state for a directory listing across multiple QUERY_DIRECTORY
/// calls. We snapshot the entries once and consume them in order; subsequent
/// calls advance `next` until exhaustion.
pub struct DirCursor {
    pub entries: Vec<crate::backend::DirEntry>,
    pub next: usize,
    /// The pattern fixed on the first scan; `RESTART_SCANS` resets `next`.
    pub pattern: Option<String>,
}
