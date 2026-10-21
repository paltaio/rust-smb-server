//! LOGOFF handler.

use std::sync::Arc;

use crate::proto::header::Smb2Header;
use crate::proto::messages::LogoffResponse;

use crate::conn::state::Connection;
use crate::dispatch::HandlerResponse;
use crate::ntstatus;
use crate::server::ServerState;

pub async fn handle(
    server: &Arc<ServerState>,
    conn: &Arc<Connection>,
    hdr: &Smb2Header,
    _body: &[u8],
) -> HandlerResponse {
    if hdr.session_id == 0 {
        return HandlerResponse::err(ntstatus::STATUS_USER_SESSION_DELETED);
    }
    // MS-SMB2 3.3.5.6: the session must exist; one still logging on counts.
    // Its durable opens are kept for the client.
    let closed = conn
        .close_session(hdr.session_id, Some(&server.durable))
        .await
        || conn
            .pending_auths
            .write()
            .await
            .remove(&hdr.session_id)
            .is_some();
    if !closed {
        return HandlerResponse::err(ntstatus::STATUS_USER_SESSION_DELETED);
    }
    let mut buf = Vec::new();
    LogoffResponse::default()
        .write_to(&mut buf)
        .expect("encode");
    HandlerResponse::ok(buf)
}
