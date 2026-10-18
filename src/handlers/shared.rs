//! Internal helpers shared across handlers: tree/open lookup, etc.

use std::sync::Arc;

use crate::proto::header::Smb2Header;
use crate::proto::messages::{Dialect, FileId};
use tokio::sync::RwLock;
use tracing::warn;

use crate::conn::state::{Connection, Open, Session, TreeConnect};
use crate::ntstatus;

/// Look up the session and tree referenced by `hdr`, returning the tree
/// inside the session. Returns the appropriate NTSTATUS on miss.
pub async fn lookup_session_tree(
    conn: &Arc<Connection>,
    hdr: &Smb2Header,
) -> Result<Arc<RwLock<TreeConnect>>, u32> {
    let tid = hdr.tree_id().ok_or(ntstatus::STATUS_INVALID_PARAMETER)?;
    let sess_arc = lookup_session(conn, hdr.session_id).await?;
    let sess = sess_arc.read().await;
    let trees = sess.trees.read().await;
    trees
        .get(&tid)
        .cloned()
        .ok_or(ntstatus::STATUS_NETWORK_NAME_DELETED)
}

pub async fn lookup_session(conn: &Arc<Connection>, sid: u64) -> Result<Arc<RwLock<Session>>, u32> {
    if sid == 0 {
        return Err(ntstatus::STATUS_USER_SESSION_DELETED);
    }
    let sessions = conn.sessions.read().await;
    sessions
        .get(&sid)
        .cloned()
        .ok_or(ntstatus::STATUS_USER_SESSION_DELETED)
}

pub async fn lookup_open(
    tree: &Arc<RwLock<TreeConnect>>,
    file_id: FileId,
) -> Option<Arc<RwLock<Open>>> {
    let tree = tree.read().await;
    let opens = tree.opens.read().await;
    opens.get(&file_id).cloned()
}

/// True if a READ or WRITE on `dialect` may carry `channel`. Every
/// connection is TCP, so on SMB 3.x an RDMA channel is never valid; on
/// earlier dialects the field is reserved and ignored.
pub fn channel_is_valid(dialect: Option<Dialect>, channel: u32) -> bool {
    channel == 0
        || !matches!(
            dialect,
            Some(Dialect::Smb300 | Dialect::Smb302 | Dialect::Smb311)
        )
}

/// Puts back the times `open` keeps fixed, after a change made through it.
pub async fn restore_fixed_times(open: &Open) {
    let fixed = open.fixed_times;
    if fixed.last_access_time.is_none() && fixed.last_write_time.is_none() {
        return;
    }
    if let Some(handle) = open.handle.as_ref()
        && let Err(e) = handle.set_times(fixed).await
    {
        warn!(error = %e, path = %open.path().unwrap_or_default(), "restoring fixed times failed");
    }
}
