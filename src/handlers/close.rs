//! CLOSE handler.

use std::sync::Arc;

use crate::proto::header::Smb2Header;
use crate::proto::messages::{CloseRequest, CloseResponse};
use tracing::{debug, warn};

use crate::conn::state::Connection;
use crate::dispatch::HandlerResponse;
use crate::error::SmbError;
use crate::handlers::shared::{lookup_session_tree, restore_fixed_times};
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

    // Pull state out, close the handle, then optionally unlink.
    let mut open = open_arc.write().await;
    restore_fixed_times(&open).await;
    let handle = open.handle.take();
    let is_directory = open.is_directory;
    let path = open.last_path.clone();
    let delete_on_close = open.delete_on_close;
    let want_attrs = req.flags & FLAG_POSTQUERY_ATTRIB != 0;
    drop(open);

    // Stat before closing if needed.
    let info_before_close = if want_attrs {
        if let Some(h) = handle.as_ref() {
            h.stat().await.ok()
        } else {
            None
        }
    } else {
        None
    };
    if let Some(h) = handle {
        let _ = h.close().await;
    }
    if delete_on_close {
        let tree = tree_arc.read().await;
        let backend = tree.share.backend.clone();
        drop(tree);
        // A failed delete-on-close does not fail the CLOSE (MS-SMB2
        // 3.3.4.17). A non-empty directory stays (MS-FSA 2.1.5.5).
        match backend.unlink(&path).await {
            Ok(()) => {}
            Err(SmbError::NotEmpty) if is_directory => {
                debug!(path = %path, "delete-on-close skipped a non-empty directory");
            }
            Err(e) => warn!(error = %e, path = %path, "delete-on-close failed"),
        }
    }

    let resp = CloseResponse {
        structure_size: 60,
        flags: req.flags & FLAG_POSTQUERY_ATTRIB,
        reserved: 0,
        creation_time: info_before_close
            .as_ref()
            .map(|i| i.creation_time)
            .unwrap_or(0),
        last_access_time: info_before_close
            .as_ref()
            .map(|i| i.last_access_time)
            .unwrap_or(0),
        last_write_time: info_before_close
            .as_ref()
            .map(|i| i.last_write_time)
            .unwrap_or(0),
        change_time: info_before_close
            .as_ref()
            .map(|i| i.change_time)
            .unwrap_or(0),
        allocation_size: info_before_close
            .as_ref()
            .map(|i| i.allocation_size)
            .unwrap_or(0),
        end_of_file: info_before_close
            .as_ref()
            .map(|i| i.end_of_file)
            .unwrap_or(0),
        file_attributes: info_before_close
            .as_ref()
            .map(|i| i.attributes())
            .unwrap_or(0),
    };
    let mut buf = Vec::new();
    resp.write_to(&mut buf).expect("encode");
    HandlerResponse::ok(buf)
}
