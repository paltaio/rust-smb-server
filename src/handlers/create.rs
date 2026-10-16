//! CREATE handler: open or create a file/directory and allocate a FileId.

use std::sync::Arc;

use crate::proto::header::Smb2Header;
use crate::proto::messages::{CreateRequest, CreateResponse};
use tracing::{debug, warn};

use crate::access_mask::{
    DELETE, FILE_APPEND_DATA, FILE_READ_ATTRIBUTES, FILE_READ_DATA, FILE_WRITE_ATTRIBUTES,
    FILE_WRITE_DATA, GENERIC_ALL, GENERIC_READ, GENERIC_WRITE, MAXIMUM_ALLOWED, granted_access,
    maximal_access,
};
use crate::backend::{OpenIntent, OpenOptions};
use crate::conn::state::{Connection, Open};
use crate::dispatch::HandlerResponse;
use crate::handlers::shared::lookup_session_tree;
use crate::ntstatus;
use crate::path::SmbPath;
use crate::server::ServerState;
use crate::utils::utf16le_to_units;

// CreateOptions
const FILE_DIRECTORY_FILE: u32 = 0x0000_0001;
const FILE_NON_DIRECTORY_FILE: u32 = 0x0000_0040;
const FILE_DELETE_ON_CLOSE: u32 = 0x0000_1000;

// CreateDisposition
const FILE_SUPERSEDE: u32 = 0x0000_0000;
const FILE_OPEN: u32 = 0x0000_0001;
const FILE_CREATE: u32 = 0x0000_0002;
const FILE_OPEN_IF: u32 = 0x0000_0003;
const FILE_OVERWRITE: u32 = 0x0000_0004;
const FILE_OVERWRITE_IF: u32 = 0x0000_0005;

// CreateAction in response (MS-SMB2 §2.2.14)
const FILE_OPENED: u32 = 0x0000_0001;
const FILE_CREATED: u32 = 0x0000_0002;

pub async fn handle(
    _server: &Arc<ServerState>,
    conn: &Arc<Connection>,
    hdr: &Smb2Header,
    body: &[u8],
) -> HandlerResponse {
    let req = match CreateRequest::parse(body) {
        Ok(r) => r,
        Err(_) => return HandlerResponse::err(ntstatus::STATUS_INVALID_PARAMETER),
    };

    let tree_arc = match lookup_session_tree(conn, hdr).await {
        Ok(t) => t,
        Err(s) => return HandlerResponse::err(s),
    };
    let tree = tree_arc.read().await;
    let granted = tree.granted_access;
    let backend = tree.share.backend.clone();
    drop(tree);

    // Decode path.
    let units = match utf16le_to_units(&req.name) {
        Some(u) => u,
        None => return HandlerResponse::err(ntstatus::STATUS_OBJECT_NAME_INVALID),
    };
    let path = match SmbPath::from_utf16(&units) {
        Ok(p) => p,
        Err(_) => return HandlerResponse::err(ntstatus::STATUS_OBJECT_NAME_INVALID),
    };

    // Translate disposition.
    let intent = match req.create_disposition {
        FILE_SUPERSEDE | FILE_OVERWRITE_IF => OpenIntent::OverwriteOrCreate,
        FILE_OPEN => OpenIntent::Open,
        FILE_CREATE => OpenIntent::Create,
        FILE_OPEN_IF => OpenIntent::OpenOrCreate,
        FILE_OVERWRITE => OpenIntent::Truncate,
        _ => return HandlerResponse::err(ntstatus::STATUS_INVALID_PARAMETER),
    };

    // Translate desired access into read/write hints.
    let want_read = req.desired_access
        & (FILE_READ_DATA | FILE_READ_ATTRIBUTES | GENERIC_READ | GENERIC_ALL | MAXIMUM_ALLOWED)
        != 0;
    let want_write = req.desired_access
        & (FILE_WRITE_DATA
            | FILE_APPEND_DATA
            | FILE_WRITE_ATTRIBUTES
            | DELETE
            | GENERIC_WRITE
            | GENERIC_ALL
            | MAXIMUM_ALLOWED)
        != 0;

    // Reject writes on a read-only tree.
    if want_write && !granted.allows_write() {
        warn!(path = %path, "write open on read-only tree");
        return HandlerResponse::err(ntstatus::STATUS_ACCESS_DENIED);
    }
    // Disposition that creates: requires write permission.
    if !granted.allows_write()
        && matches!(
            intent,
            OpenIntent::Create
                | OpenIntent::OpenOrCreate
                | OpenIntent::OverwriteOrCreate
                | OpenIntent::Truncate
        )
    {
        return HandlerResponse::err(ntstatus::STATUS_ACCESS_DENIED);
    }

    let directory = req.create_options & FILE_DIRECTORY_FILE != 0;
    let non_directory = req.create_options & FILE_NON_DIRECTORY_FILE != 0;
    if directory && non_directory {
        return HandlerResponse::err(ntstatus::STATUS_INVALID_PARAMETER);
    }
    let maximal = maximal_access(granted);
    let open_access = granted_access(req.desired_access, maximal);
    let delete_on_close = req.create_options & FILE_DELETE_ON_CLOSE != 0;
    if delete_on_close {
        // MS-SMB2 3.3.5.9: the tree must allow DELETE.
        if maximal & DELETE == 0 {
            warn!(path = %path, "delete-on-close open on read-only tree");
            return HandlerResponse::err(ntstatus::STATUS_ACCESS_DENIED);
        }
        // MS-FSA 2.1.5.1: the open itself must request DELETE.
        if open_access & DELETE == 0 {
            return HandlerResponse::err(ntstatus::STATUS_INVALID_PARAMETER);
        }
    }

    let opts = OpenOptions {
        read: want_read || !want_write,
        write: want_write,
        intent,
        directory,
        non_directory,
        delete_on_close,
    };

    let handle = match backend.open(&path, opts).await {
        Ok(h) => h,
        Err(e) => {
            debug!(error = %e, path = %path, "backend open failed");
            return HandlerResponse::err(e.to_nt_status());
        }
    };

    // Stat for the response.
    let info = match handle.stat().await {
        Ok(i) => i,
        Err(e) => {
            let _ = handle.close().await;
            return HandlerResponse::err(e.to_nt_status());
        }
    };

    // Allocate FileId, register Open.
    let tree = tree_arc.write().await;
    let file_id = tree.alloc_file_id();
    let open = Open::new(
        file_id,
        handle,
        open_access,
        path,
        info.is_directory,
        delete_on_close,
    );
    let open_arc = Arc::new(tokio::sync::RwLock::new(open));
    tree.opens.write().await.insert(file_id, open_arc);
    drop(tree);

    let create_action = match intent {
        OpenIntent::Create => FILE_CREATED,
        OpenIntent::OpenOrCreate | OpenIntent::OverwriteOrCreate => FILE_OPENED,
        OpenIntent::Open | OpenIntent::Truncate => FILE_OPENED,
    };
    let resp = CreateResponse {
        structure_size: 89,
        oplock_level: 0,
        flags: 0,
        create_action,
        creation_time: info.creation_time,
        last_access_time: info.last_access_time,
        last_write_time: info.last_write_time,
        change_time: info.change_time,
        allocation_size: info.allocation_size,
        end_of_file: info.end_of_file,
        file_attributes: info.attributes(),
        reserved2: 0,
        file_id,
        create_contexts_offset: 0,
        create_contexts_length: 0,
        create_contexts: vec![],
    };
    let mut buf = Vec::new();
    resp.write_to(&mut buf).expect("encode");
    HandlerResponse::ok(buf)
}
