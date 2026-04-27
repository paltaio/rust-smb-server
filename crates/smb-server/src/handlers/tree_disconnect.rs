//! TREE_DISCONNECT handler.

use std::sync::Arc;

use smb_proto::header::Smb2Header;
use smb_proto::messages::TreeDisconnectResponse;

use crate::conn::state::Connection;
use crate::dispatch::HandlerResponse;
use crate::ntstatus;
use crate::server::ServerState;

pub async fn handle(
    _server: &Arc<ServerState>,
    conn: &Arc<Connection>,
    hdr: &Smb2Header,
    _body: &[u8],
) -> HandlerResponse {
    let tid = match hdr.tree_id() {
        Some(t) => t,
        None => return HandlerResponse::err(ntstatus::STATUS_INVALID_PARAMETER),
    };

    let sessions = conn.sessions.read().await;
    let sess_arc = match sessions.get(&hdr.session_id) {
        Some(s) => s.clone(),
        None => return HandlerResponse::err(ntstatus::STATUS_USER_SESSION_DELETED),
    };
    drop(sessions);

    let removed = {
        let sess = sess_arc.read().await;
        let mut trees = sess.trees.write().await;
        trees.remove(&tid)
    };
    if let Some(tree_arc) = removed {
        let tree = tree_arc.write().await;
        let opens: Vec<_> = tree.opens.write().await.drain().collect();
        for (_fid, open_arc) in opens {
            let mut open = open_arc.write().await;
            if let Some(handle) = open.handle.take() {
                let _ = handle.close().await;
            }
        }
    } else {
        return HandlerResponse::err(ntstatus::STATUS_NETWORK_NAME_DELETED);
    }
    let mut buf = Vec::new();
    TreeDisconnectResponse::default()
        .write_to(&mut buf)
        .expect("encode");
    HandlerResponse::ok(buf)
}
