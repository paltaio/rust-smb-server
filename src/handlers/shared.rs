//! Internal helpers shared across handlers: tree/open lookup, etc.

use std::sync::Arc;

use crate::proto::header::Smb2Header;
use crate::proto::messages::FileId;
use tokio::sync::RwLock;

use crate::conn::state::{Connection, Open, Session, TreeConnect};
use crate::ntstatus;
use crate::path::{SmbPath, same_path};
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

/// True if an open on `share`, on any connection, currently has `path` as
/// its path. Opens made through another name for the same file, such as a
/// hard link, are not seen.
pub async fn path_is_open(
    server: &ServerState,
    share: &Arc<ShareBindings>,
    path: &SmbPath,
) -> bool {
    let case_sensitive = share.backend.capabilities().case_sensitive;
    for conn in server.active_connections.live().await {
        let sessions: Vec<_> = conn.sessions.read().await.values().cloned().collect();
        for sess_arc in sessions {
            let trees: Vec<_> = {
                let sess = sess_arc.read().await;
                let trees = sess.trees.read().await;
                trees.values().cloned().collect()
            };
            for tree_arc in trees {
                let opens: Vec<_> = {
                    let tree = tree_arc.read().await;
                    if !Arc::ptr_eq(&tree.share, share) {
                        continue;
                    }
                    let opens = tree.opens.read().await;
                    opens.values().cloned().collect()
                };
                for open_arc in opens {
                    if same_path(&open_arc.read().await.last_path, path, case_sensitive) {
                        return true;
                    }
                }
            }
        }
    }
    false
}
