//! QUERY_DIRECTORY handler (MS-SMB2 3.3.5.18, MS-FSA 2.1.5.6.3).

use std::sync::Arc;

use crate::proto::header::Smb2Header;
use crate::proto::messages::{FileInfoClass, QueryDirectoryRequest, QueryDirectoryResponse};

use crate::access_mask::FILE_LIST_DIRECTORY;
use crate::backend::{DirEntry, FileInfo, OpenIntent, OpenOptions, ShareBackend};
use crate::conn::state::{Connection, DirCursor, Open};
use crate::dispatch::HandlerResponse;
use crate::handlers::shared::{lookup_open, lookup_session_tree};
use crate::info_class::{align8, dir_entry_name_offset, encode_dir_entry};
use crate::ntstatus;
use crate::path::is_valid_pattern;
use crate::server::ServerState;
use crate::utils::utf16le_to_units;
use crate::wildcard::Pattern;

/// Classes MS-SMB2 3.3.5.18 lists that this server does not encode:
/// FileIdExtdDirectoryInformation, FileId64ExtdDirectoryInformation,
/// FileId64ExtdBothDirectoryInformation, FileIdAllExtdDirectoryInformation
/// and FileIdAllExtdBothDirectoryInformation.
const UNSUPPORTED_CLASSES: [u8; 5] = [0x3C, 0x4E, 0x4F, 0x50, 0x51];

pub async fn handle(
    _server: &Arc<ServerState>,
    conn: &Arc<Connection>,
    hdr: &Smb2Header,
    body: &[u8],
) -> HandlerResponse {
    let req = match QueryDirectoryRequest::parse(body) {
        Ok(r) => r,
        Err(_) => return HandlerResponse::err(ntstatus::STATUS_INVALID_PARAMETER),
    };

    let tree_arc = match lookup_session_tree(conn, hdr).await {
        Ok(t) => t,
        Err(s) => return HandlerResponse::err(s),
    };
    let open_arc = match lookup_open(&tree_arc, req.file_id).await {
        Some(o) => o,
        None => return HandlerResponse::err(ntstatus::STATUS_FILE_CLOSED),
    };
    let backend = Arc::clone(&tree_arc.read().await.share.backend);

    let mut open = open_arc.write().await;
    if !open.is_directory {
        return HandlerResponse::err(ntstatus::STATUS_INVALID_PARAMETER);
    }
    // NEGOTIATE advertises MaxTransactSize equal to MaxReadSize.
    if req.output_buffer_length > *conn.max_read_size.read().await {
        return HandlerResponse::err(ntstatus::STATUS_INVALID_PARAMETER);
    }
    if open.granted_access & FILE_LIST_DIRECTORY == 0 {
        return HandlerResponse::err(ntstatus::STATUS_ACCESS_DENIED);
    }
    let class = req.file_information_class;
    if FileInfoClass::from_u8(class).is_none() {
        let status = if UNSUPPORTED_CLASSES.contains(&class) {
            ntstatus::STATUS_NOT_SUPPORTED
        } else {
            ntstatus::STATUS_INVALID_INFO_CLASS
        };
        return HandlerResponse::err(status);
    }
    let name_offset = dir_entry_name_offset(class).expect("supported class");
    let cap = req.output_buffer_length as usize;
    if cap < name_offset {
        return HandlerResponse::err(ntstatus::STATUS_INFO_LENGTH_MISMATCH);
    }

    let Some(units) = utf16le_to_units(&req.file_name) else {
        return HandlerResponse::err(ntstatus::STATUS_INVALID_PARAMETER);
    };
    let Ok(requested) = String::from_utf16(&units) else {
        return HandlerResponse::err(ntstatus::STATUS_OBJECT_NAME_INVALID);
    };

    let reopen = req.flags & QueryDirectoryRequest::FLAG_REOPEN != 0;
    let restart = reopen || req.flags & QueryDirectoryRequest::FLAG_RESTART_SCANS != 0;
    let single_entry = req.flags & QueryDirectoryRequest::FLAG_RETURN_SINGLE_ENTRY != 0;
    // FileIndex and SMB2_INDEX_SPECIFIED are ignored, as MS-SMB2 3.3.5.18
    // allows.
    let first_query = open.search_state.is_none() || reopen;

    // MS-FSA 2.1.5.6.3: the first query sets the pattern ("*" when empty); a
    // restart replaces it only with a non-empty one.
    if first_query || (restart && !requested.is_empty()) {
        if !requested.is_empty() && !is_valid_pattern(&requested) {
            return HandlerResponse::err(ntstatus::STATUS_OBJECT_NAME_INVALID);
        }
        let pattern = (!requested.is_empty() && requested != "*").then_some(requested);
        if let Err(status) = start_scan(&mut open, backend.as_ref(), pattern).await {
            return HandlerResponse::err(status);
        }
    } else if restart {
        let pattern = open.search_state.as_mut().and_then(|c| c.pattern.take());
        if let Err(status) = start_scan(&mut open, backend.as_ref(), pattern).await {
            return HandlerResponse::err(status);
        }
    }

    let cursor = open.search_state.as_mut().expect("scan started");
    let mut buf: Vec<u8> = Vec::new();
    let mut last_entry: Option<usize> = None;
    let mut status = ntstatus::STATUS_SUCCESS;
    while cursor.next < cursor.entries.len() {
        if single_entry && last_entry.is_some() {
            break;
        }
        let mut bytes = encode_dir_entry(class, &cursor.entries[cursor.next]);
        let start = align8(buf.len());
        if last_entry.is_some() && start + bytes.len() > cap {
            break;
        }
        if bytes.len() > cap {
            // Only the first entry gets here: return as much of its name as
            // fits. The entry is returned again by the next query.
            let name_room = (cap - name_offset) & !1;
            bytes.truncate(name_offset + name_room);
            status = ntstatus::STATUS_BUFFER_OVERFLOW;
        }
        buf.resize(start, 0);
        if let Some(prev) = last_entry {
            let delta = (start - prev) as u32;
            buf[prev..prev + 4].copy_from_slice(&delta.to_le_bytes());
        }
        last_entry = Some(start);
        buf.extend_from_slice(&bytes);
        if status != ntstatus::STATUS_SUCCESS {
            break;
        }
        cursor.next += 1;
    }
    if cursor.next >= cursor.entries.len() {
        // Exhausted: later queries return STATUS_NO_MORE_FILES.
        cursor.entries = Vec::new();
        cursor.next = 0;
    }
    if buf.is_empty() {
        return HandlerResponse::err(if first_query {
            ntstatus::STATUS_NO_SUCH_FILE
        } else {
            ntstatus::STATUS_NO_MORE_FILES
        });
    }

    let resp = QueryDirectoryResponse {
        structure_size: 9,
        output_buffer_offset: 64 + 8,
        output_buffer_length: buf.len() as u32,
        buffer: buf,
    };
    let mut out = Vec::new();
    resp.write_to(&mut out).expect("encode");
    let mut response = HandlerResponse::ok(out);
    response.status = status;
    response
}

/// Lists the directory of `open` from the start with `pattern` (`None`
/// matches every name) and stores the listing as its search state. On the
/// first query and every restart the listing starts with "." and "..",
/// when the pattern matches them and the directory is not the share root.
async fn start_scan(
    open: &mut Open,
    backend: &dyn ShareBackend,
    pattern: Option<String>,
) -> Result<(), u32> {
    let handle = open.handle.as_ref().ok_or(ntstatus::STATUS_FILE_CLOSED)?;
    let listed = handle
        .list_dir(pattern.as_deref())
        .await
        .map_err(|e| e.to_nt_status())?;

    let mut entries = Vec::with_capacity(listed.len() + 2);
    if !open.last_path.is_root() {
        let matcher = pattern.as_deref().map(|p| Pattern::new(p, true));
        let matches = |name: &str| matcher.as_ref().is_none_or(|m| m.matches(name));
        if matches(".") || matches("..") {
            let mut this = handle.stat().await.map_err(|e| e.to_nt_status())?;
            this.name = ".".to_string();
            let mut parent = parent_info(backend, open).await.unwrap_or_else(|| {
                let mut info = this.clone();
                info.file_index = 0;
                info
            });
            parent.name = "..".to_string();
            if matches(".") {
                entries.push(DirEntry { info: this });
            }
            if matches("..") {
                entries.push(DirEntry { info: parent });
            }
        }
    }
    entries.extend(
        listed
            .into_iter()
            .filter(|e| e.info.name != "." && e.info.name != ".."),
    );

    open.search_state = Some(DirCursor {
        entries,
        next: 0,
        pattern,
    });
    Ok(())
}

/// File info of the parent directory of `open`, or `None` if it cannot be
/// opened.
async fn parent_info(backend: &dyn ShareBackend, open: &Open) -> Option<FileInfo> {
    let parent = open.last_path.parent()?;
    let opts = OpenOptions {
        read: true,
        write: false,
        write_attributes: false,
        intent: OpenIntent::Open,
        directory: true,
        non_directory: false,
        delete_on_close: false,
    };
    let (handle, _) = backend.open(&parent, opts).await.ok()?;
    let info = handle.stat().await.ok();
    let _ = handle.close().await;
    info
}
