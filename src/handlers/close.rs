//! CLOSE handler.

use std::sync::Arc;

use crate::proto::header::Smb2Header;
use crate::proto::messages::{CloseRequest, CloseResponse};

use crate::conn::state::Connection;
use crate::dispatch::HandlerResponse;
use crate::files::close_open;
use crate::handlers::shared::lookup_session_tree;
use crate::ntstatus;
use crate::server::ServerState;

const FLAG_POSTQUERY_ATTRIB: u16 = 0x0001;

pub async fn handle(
    _server: &Arc<ServerState>,
    conn: &Arc<Connection>,
    hdr: &Smb2Header,
    body: &[u8],
) -> HandlerResponse {
    let req = match CloseRequest::parse(body) {
        Ok(r) => r,
        Err(_) => return HandlerResponse::err(ntstatus::STATUS_INVALID_PARAMETER),
    };
    let tree_arc = match lookup_session_tree(conn, hdr).await {
        Ok(t) => t,
        Err(s) => return HandlerResponse::err(s),
    };
    let removed = {
        let tree = tree_arc.write().await;
        let mut opens = tree.opens.write().await;
        opens.remove(&req.file_id)
    };
    let open_arc = match removed {
        Some(o) => o,
        None => return HandlerResponse::err(ntstatus::STATUS_FILE_CLOSED),
    };

    let want_attrs = req.flags & FLAG_POSTQUERY_ATTRIB != 0;
    let info = close_open(&open_arc, want_attrs).await;

    // MS-SMB2 3.3.5.10: without the attributes, Flags and every attribute
    // field are 0.
    let resp = match info {
        Some(info) => CloseResponse {
            structure_size: 60,
            flags: FLAG_POSTQUERY_ATTRIB,
            reserved: 0,
            creation_time: info.creation_time,
            last_access_time: info.last_access_time,
            last_write_time: info.last_write_time,
            change_time: info.change_time,
            allocation_size: info.allocation_size,
            end_of_file: info.end_of_file,
            file_attributes: info.attributes(),
        },
        None => CloseResponse::new(),
    };
    let mut buf = Vec::new();
    resp.write_to(&mut buf).expect("encode");
    HandlerResponse::ok(buf)
}
