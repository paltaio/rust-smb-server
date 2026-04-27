//! LOGOFF handler.

use std::sync::Arc;

use smb_proto::header::Smb2Header;
use smb_proto::messages::LogoffResponse;

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
    if hdr.session_id == 0 {
        return HandlerResponse::err(ntstatus::STATUS_USER_SESSION_DELETED);
    }
    // Drop session and all its trees/opens — backend handles drop the file
    // handles via the Open's Drop / Box. We close handles best-effort here.
    let removed = {
        let mut sessions = conn.sessions.write().await;
        sessions.remove(&hdr.session_id)
    };
    if let Some(sess_arc) = removed {
        let sess = sess_arc.write().await;
        let trees: Vec<_> = sess.trees.write().await.drain().collect();
        for (_tid, tree_arc) in trees {
            let tree = tree_arc.write().await;
            let opens: Vec<_> = tree.opens.write().await.drain().collect();
            for (_fid, open_arc) in opens {
                let mut open = open_arc.write().await;
                if let Some(handle) = open.handle.take() {
                    let _ = handle.close().await;
                }
            }
        }
    }
    let mut buf = Vec::new();
    LogoffResponse::default()
        .write_to(&mut buf)
        .expect("encode");
    HandlerResponse::ok(buf)
}
