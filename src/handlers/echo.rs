//! ECHO handler (MS-SMB2 3.3.5.17).

use std::sync::Arc;

use crate::proto::header::{SMB2_FLAGS_SIGNED, Smb2Header};
use crate::proto::messages::EchoResponse;

use crate::conn::state::Connection;
use crate::dispatch::HandlerResponse;
use crate::handlers::shared::lookup_session;
use crate::ntstatus;
use crate::server::ServerState;

pub async fn handle(
    _server: &Arc<ServerState>,
    conn: &Arc<Connection>,
    hdr: &Smb2Header,
    _body: &[u8],
) -> HandlerResponse {
    // A connection with no session, established or in progress, has no
    // business sending ECHO.
    let no_sessions =
        conn.sessions.read().await.is_empty() && conn.pending_auths.read().await.is_empty();
    if no_sessions {
        conn.request_disconnect();
        return HandlerResponse::err(ntstatus::STATUS_INVALID_PARAMETER);
    }
    if (hdr.flags & SMB2_FLAGS_SIGNED != 0 || hdr.session_id != 0)
        && let Err(status) = lookup_session(conn, hdr.session_id).await
    {
        return HandlerResponse::err(status);
    }
    let mut buf = Vec::new();
    EchoResponse::default().write_to(&mut buf).expect("encode");
    HandlerResponse::ok(buf)
}
