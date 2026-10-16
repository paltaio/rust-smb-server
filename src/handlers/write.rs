//! WRITE handler.

use std::sync::Arc;

use crate::proto::header::Smb2Header;
use crate::proto::messages::{WriteRequest, WriteResponse};

use crate::access_mask::{FILE_APPEND_DATA, FILE_WRITE_DATA};
use crate::conn::state::Connection;
use crate::dispatch::HandlerResponse;
use crate::handlers::shared::{lookup_open, lookup_session_tree, restore_fixed_times};
use crate::ntstatus;
use crate::server::ServerState;

pub async fn handle(
    _server: &Arc<ServerState>,
    conn: &Arc<Connection>,
    hdr: &Smb2Header,
    body: &[u8],
) -> HandlerResponse {
    let req = match WriteRequest::parse(body) {
        Ok(r) => r,
        Err(_) => return HandlerResponse::err(ntstatus::STATUS_INVALID_PARAMETER),
    };
    let max_write = *conn.max_write_size.read().await;
    if req.length > max_write {
        return HandlerResponse::err(ntstatus::STATUS_INVALID_PARAMETER);
    }
    let tree_arc = match lookup_session_tree(conn, hdr).await {
        Ok(t) => t,
        Err(s) => return HandlerResponse::err(s),
    };
    let open_arc = match lookup_open(&tree_arc, req.file_id).await {
        Some(o) => o,
        None => return HandlerResponse::err(ntstatus::STATUS_FILE_CLOSED),
    };
    let result = {
        let open = open_arc.read().await;
        // FILE_WRITE_DATA or FILE_APPEND_DATA allows a write at any offset
        // (MS-SMB2 3.3.5.13).
        if open.granted_access & (FILE_WRITE_DATA | FILE_APPEND_DATA) == 0 {
            return HandlerResponse::err(ntstatus::STATUS_ACCESS_DENIED);
        }
        let result = match open.handle.as_ref() {
            Some(h) => h.write_owned(req.offset, req.data).await,
            None => return HandlerResponse::err(ntstatus::STATUS_FILE_CLOSED),
        };
        if result.is_ok() {
            restore_fixed_times(&open).await;
        }
        result
    };
    let count = match result {
        Ok(n) => n,
        Err(e) => return HandlerResponse::err(e.to_nt_status()),
    };
    let mut buf = Vec::new();
    WriteResponse::new(count)
        .write_to(&mut buf)
        .expect("encode");
    HandlerResponse::ok(buf)
}
