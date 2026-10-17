//! CHANGE_NOTIFY handler. Change notifications are not supported; a valid
//! request gets STATUS_NOT_SUPPORTED after the checks of MS-SMB2 3.3.5.19.

use std::sync::Arc;

use crate::proto::header::Smb2Header;
use crate::proto::messages::ChangeNotifyRequest;

use crate::access_mask::FILE_READ_DATA;
use crate::conn::state::Connection;
use crate::dispatch::HandlerResponse;
use crate::handlers::shared::{lookup_open, lookup_session_tree};
use crate::ntstatus;
use crate::server::ServerState;

/// FILE_LIST_DIRECTORY shares its bit with FILE_READ_DATA.
const FILE_LIST_DIRECTORY: u32 = FILE_READ_DATA;

pub async fn handle(
    _server: &Arc<ServerState>,
    conn: &Arc<Connection>,
    hdr: &Smb2Header,
    body: &[u8],
) -> HandlerResponse {
    let tree = match lookup_session_tree(conn, hdr).await {
        Ok(t) => t,
        Err(status) => return HandlerResponse::err(status),
    };
    let Ok(req) = ChangeNotifyRequest::parse(body) else {
        return HandlerResponse::err(ntstatus::STATUS_INVALID_PARAMETER);
    };
    let Some(open) = lookup_open(&tree, req.file_id).await else {
        return HandlerResponse::err(ntstatus::STATUS_FILE_CLOSED);
    };
    if req.output_buffer_length > *conn.max_read_size.read().await {
        return HandlerResponse::err(ntstatus::STATUS_INVALID_PARAMETER);
    }
    let open = open.read().await;
    if !open.is_directory {
        return HandlerResponse::err(ntstatus::STATUS_INVALID_PARAMETER);
    }
    if open.granted_access & FILE_LIST_DIRECTORY == 0 {
        return HandlerResponse::err(ntstatus::STATUS_ACCESS_DENIED);
    }
    HandlerResponse::err(ntstatus::STATUS_NOT_SUPPORTED)
}
