//! WRITE handler.

use std::sync::Arc;

use crate::proto::header::Smb2Header;
use crate::proto::messages::{Dialect, WriteRequest, WriteResponse};

use crate::access_mask::{FILE_APPEND_DATA, FILE_WRITE_DATA};
use crate::conn::state::Connection;
use crate::dispatch::HandlerResponse;
use crate::handlers::create::{FILE_NO_INTERMEDIATE_BUFFERING, WRITE_THROUGH_OPTIONS};
use crate::handlers::shared::{lookup_open, lookup_session_tree, restore_fixed_times};
use crate::ntstatus;
use crate::server::ServerState;

/// Largest DataOffset of a WRITE that carries its data inline (MS-SMB2
/// 3.3.5.13).
const MAX_DATA_OFFSET: u16 = 0x100;

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
    let dialect = *conn.dialect.read().await;
    // Every connection is TCP, so an RDMA channel is never valid.
    if is_smb3(dialect) && req.channel != 0 {
        return HandlerResponse::err(ntstatus::STATUS_INVALID_PARAMETER);
    }
    if req.data_offset > MAX_DATA_OFFSET {
        return HandlerResponse::err(ntstatus::STATUS_INVALID_PARAMETER);
    }

    let open = open_arc.read().await;
    let Some(handle) = open.handle.as_ref() else {
        return HandlerResponse::err(ntstatus::STATUS_FILE_CLOSED);
    };

    // MS-SMB2 3.3.5.13: a per-request write-through needs an unbuffered
    // write. UNBUFFERED is defined from 3.0.2 on.
    let unbuffered_dialect = matches!(dialect, Some(Dialect::Smb302 | Dialect::Smb311));
    let write_through_flag = req.flags & WriteRequest::FLAG_WRITE_THROUGH != 0;
    let unbuffered_flag =
        unbuffered_dialect && req.flags & WriteRequest::FLAG_WRITE_UNBUFFERED != 0;
    let unbuffered_open = open.create_options & FILE_NO_INTERMEDIATE_BUFFERING != 0;
    let checks_write_through = !matches!(dialect, None | Some(Dialect::Smb202));
    if checks_write_through && write_through_flag && !unbuffered_flag && !unbuffered_open {
        return HandlerResponse::err(ntstatus::STATUS_INVALID_PARAMETER);
    }
    let write_through = (checks_write_through && write_through_flag)
        || unbuffered_flag
        || open.create_options & WRITE_THROUGH_OPTIONS != 0;

    // MS-SMB2 3.3.5.13: overwriting bytes needs FILE_WRITE_DATA and growing
    // the file needs FILE_APPEND_DATA.
    let can_write = open.granted_access & FILE_WRITE_DATA != 0;
    let can_append = open.granted_access & FILE_APPEND_DATA != 0;
    if !can_write && !can_append {
        return HandlerResponse::err(ntstatus::STATUS_ACCESS_DENIED);
    }
    let length = u64::from(req.length);
    if req.length > 0 && !(can_write && can_append) {
        let size = match handle.stat().await {
            Ok(info) => info.end_of_file,
            Err(e) => return HandlerResponse::err(e.to_nt_status()),
        };
        let overwrites = req.offset < size;
        let grows = req.offset.saturating_add(length) > size;
        if (overwrites && !can_write) || (grows && !can_append) {
            return HandlerResponse::err(ntstatus::STATUS_ACCESS_DENIED);
        }
    }

    if req.length == 0 {
        let mut buf = Vec::new();
        WriteResponse::new(0).write_to(&mut buf).expect("encode");
        return HandlerResponse::ok(buf);
    }
    if let Some(file) = open.file.as_ref()
        && let Err(status) = file.check_io(req.offset, length, true)
    {
        return HandlerResponse::err(status);
    }

    let mut result = handle.write_owned(req.offset, req.data).await;
    if result.is_ok() && write_through {
        result = handle.flush().await.and(result);
    }
    if result.is_ok() {
        restore_fixed_times(&open).await;
    }
    drop(open);
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

/// True for the SMB 3.x dialects.
pub(crate) fn is_smb3(dialect: Option<Dialect>) -> bool {
    matches!(
        dialect,
        Some(Dialect::Smb300 | Dialect::Smb302 | Dialect::Smb311)
    )
}
