//! Internal helpers shared across handlers: tree/open lookup, etc.

use std::sync::Arc;

use crate::proto::header::Smb2Header;
use crate::proto::messages::FileId;
use tokio::sync::RwLock;
use tracing::warn;

use crate::conn::state::{Connection, Open, Session, TreeConnect};
use crate::ntstatus;
use crate::path::{SmbPath, rebase};
use crate::server::{ServerState, ShareBindings};

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

/// Puts back the times `open` keeps fixed, after a change made through it.
pub async fn restore_fixed_times(open: &Open) {
    let fixed = open.fixed_times;
    if fixed.last_access_time.is_none() && fixed.last_write_time.is_none() {
        return;
    }
    if let Some(handle) = open.handle.as_ref()
        && let Err(e) = handle.set_times(fixed).await
    {
        warn!(error = %e, path = %open.last_path, "restoring fixed times failed");
    }
}

/// Every open on `share`, on any connection.
async fn share_opens(server: &ServerState, share: &Arc<ShareBindings>) -> Vec<Arc<RwLock<Open>>> {
    let mut out = Vec::new();
    for conn in server.active_connections.live().await {
        let sessions: Vec<_> = conn.sessions.read().await.values().cloned().collect();
        for sess_arc in sessions {
            let trees: Vec<_> = {
                let sess = sess_arc.read().await;
                let trees = sess.trees.read().await;
                trees.values().cloned().collect()
            };
            for tree_arc in trees {
                let tree = tree_arc.read().await;
                if Arc::ptr_eq(&tree.share, share) {
                    out.extend(tree.opens.read().await.values().cloned());
                }
            }
        }
    }
    out
}

/// Moves every open on `share` whose path is `from`, or lies below it, to
/// the matching path under `to`.
pub async fn rename_open_paths(
    server: &ServerState,
    share: &Arc<ShareBindings>,
    from: &SmbPath,
    to: &SmbPath,
) {
    let case_sensitive = share.backend.capabilities().case_sensitive;
    for open_arc in share_opens(server, share).await {
        let mut open = open_arc.write().await;
        if let Some(path) = rebase(&open.last_path, from, to, case_sensitive) {
            open.last_path = path;
        }
    }
}
