//! SET_INFO handler.

use std::sync::Arc;

use crate::proto::header::Smb2Header;
use crate::proto::messages::{InfoType, SetInfoRequest, SetInfoResponse};

use crate::access_mask::{DELETE, FILE_WRITE_ATTRIBUTES, FILE_WRITE_DATA};
use crate::backend::{
    FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_TEMPORARY, FileTimes, VALID_SET_ATTRIBUTES,
};
use crate::conn::state::{Connection, Open};
use crate::dispatch::HandlerResponse;
use crate::handlers::shared::{
    lookup_open, lookup_session_tree, path_is_open, rename_open_paths, restore_fixed_times,
};
use crate::info_class as ic;
use crate::ntstatus;
use crate::path::{SmbPath, same_path};
use crate::server::ServerState;
use crate::utils::utf16le_to_units;

/// File information classes SET_INFO applies.
enum Class {
    Basic,
    EndOfFile,
    Disposition,
    Rename,
    Allocation,
}

pub async fn handle(
    server: &Arc<ServerState>,
    conn: &Arc<Connection>,
    hdr: &Smb2Header,
    body: &[u8],
) -> HandlerResponse {
    let req = match SetInfoRequest::parse(body) {
        Ok(r) => r,
        Err(_) => return HandlerResponse::err(ntstatus::STATUS_INVALID_PARAMETER),
    };
    let info_type = match InfoType::from_u8(req.info_type) {
        Some(t) => t,
        None => return HandlerResponse::err(ntstatus::STATUS_INVALID_INFO_CLASS),
    };
    if !matches!(info_type, InfoType::File) {
        return HandlerResponse::err(ntstatus::STATUS_NOT_SUPPORTED);
    }

    let tree_arc = match lookup_session_tree(conn, hdr).await {
        Ok(t) => t,
        Err(s) => return HandlerResponse::err(s),
    };
    let open_arc = match lookup_open(&tree_arc, req.file_id).await {
        Some(o) => o,
        None => return HandlerResponse::err(ntstatus::STATUS_FILE_CLOSED),
    };

    // MS-SMB2 3.3.5.21.1: access each class needs from Open.GrantedAccess.
    let (class, required) = match req.file_information_class {
        ic::FILE_BASIC_INFORMATION => (Class::Basic, FILE_WRITE_ATTRIBUTES),
        ic::FILE_DISPOSITION_INFORMATION => (Class::Disposition, DELETE),
        ic::FILE_RENAME_INFORMATION => (Class::Rename, DELETE),
        ic::FILE_END_OF_FILE_INFORMATION => (Class::EndOfFile, FILE_WRITE_DATA),
        ic::FILE_ALLOCATION_INFORMATION => (Class::Allocation, FILE_WRITE_DATA),
        _ => return HandlerResponse::err(ntstatus::STATUS_NOT_SUPPORTED),
    };
    if open_arc.read().await.granted_access & required != required {
        return HandlerResponse::err(ntstatus::STATUS_ACCESS_DENIED);
    }
    let buffer = req.buffer;
    let share = tree_arc.read().await.share.clone();

    let result = match class {
        Class::Basic => {
            if buffer.len() < 36 {
                return HandlerResponse::err(ntstatus::STATUS_INFO_LENGTH_MISMATCH);
            }
            let time = |at: usize| i64::from_le_bytes(buffer[at..at + 8].try_into().unwrap());
            let times = [time(0), time(8), time(16), time(24)];
            let attributes = u32::from_le_bytes(buffer[32..36].try_into().unwrap());
            let mut open = open_arc.write().await;
            set_basic_info(&mut open, times, attributes).await
        }
        Class::EndOfFile => {
            if buffer.len() < 8 {
                return HandlerResponse::err(ntstatus::STATUS_INFO_LENGTH_MISMATCH);
            }
            let new_len = u64::from_le_bytes(buffer[0..8].try_into().unwrap());
            let open = open_arc.read().await;
            truncate(&open, new_len, false).await
        }
        Class::Allocation => {
            if buffer.len() < 8 {
                return HandlerResponse::err(ntstatus::STATUS_INFO_LENGTH_MISMATCH);
            }
            let size = u64::from_le_bytes(buffer[0..8].try_into().unwrap());
            let open = open_arc.read().await;
            truncate(&open, size, true).await
        }
        Class::Disposition => {
            if buffer.is_empty() {
                return HandlerResponse::err(ntstatus::STATUS_INFO_LENGTH_MISMATCH);
            }
            let mut open = open_arc.write().await;
            set_disposition(&mut open, buffer[0] != 0).await
        }
        Class::Rename => {
            // FILE_RENAME_INFORMATION layout (MS-FSCC §2.4.37):
            //   ReplaceIfExists (1) | Reserved (7) | RootDirectory (8) | FileNameLength (4) | FileName...
            if buffer.len() < 20 {
                return HandlerResponse::err(ntstatus::STATUS_INFO_LENGTH_MISMATCH);
            }
            let name_len = u32::from_le_bytes(buffer[16..20].try_into().unwrap()) as usize;
            if buffer.len() < 20 + name_len {
                return HandlerResponse::err(ntstatus::STATUS_INFO_LENGTH_MISMATCH);
            }
            let name_bytes = &buffer[20..20 + name_len];
            let units = match utf16le_to_units(name_bytes) {
                Some(u) => u,
                None => return HandlerResponse::err(ntstatus::STATUS_OBJECT_NAME_INVALID),
            };
            let new_path = match SmbPath::from_utf16(&units) {
                Ok(p) => p,
                Err(_) => return HandlerResponse::err(ntstatus::STATUS_OBJECT_NAME_INVALID),
            };
            let replace_if_exists = buffer[0] != 0;
            let from = open_arc.read().await.last_path.clone();
            // MS-FSA 2.1.5.15.12: an open target is not replaced. A target
            // that names the source itself is the same file and skips this.
            let case_sensitive = share.backend.capabilities().case_sensitive;
            if replace_if_exists
                && !same_path(&from, &new_path, case_sensitive)
                && path_is_open(server, &share, &new_path).await
            {
                return HandlerResponse::err(ntstatus::STATUS_ACCESS_DENIED);
            }
            match share
                .backend
                .rename(&from, &new_path, replace_if_exists)
                .await
            {
                Ok(()) => {
                    rename_open_paths(server, &share, &from, &new_path).await;
                    Ok(())
                }
                Err(e) => Err(e.to_nt_status()),
            }
        }
    };

    if let Err(status) = result {
        return HandlerResponse::err(status);
    }
    let mut buf = Vec::new();
    SetInfoResponse::default()
        .write_to(&mut buf)
        .expect("encode");
    HandlerResponse::ok(buf)
}

/// FileBasicInformation (MS-FSA 2.1.5.15.2, MS-FSCC 2.4.7). A time of 0
/// or -1 leaves it alone. For the access and write times, -1 also keeps the
/// time fixed against later changes made through this open, -2 lets those
/// changes update it again, and a time set through the open stays fixed. A
/// time or attribute set that equals the current one is not passed to the
/// backend.
async fn set_basic_info(open: &mut Open, times: [i64; 4], attributes: u32) -> Result<(), u32> {
    if times.iter().any(|&t| t < -2)
        || (attributes & FILE_ATTRIBUTE_DIRECTORY != 0 && !open.is_directory)
        || (attributes & FILE_ATTRIBUTE_TEMPORARY != 0 && open.is_directory)
    {
        return Err(ntstatus::STATUS_INVALID_PARAMETER);
    }
    let handle = open.handle.as_ref().ok_or(ntstatus::STATUS_FILE_CLOSED)?;
    let current = handle.stat().await.map_err(|e| e.to_nt_status())?;

    let wanted_attributes = attributes & VALID_SET_ATTRIBUTES;
    if attributes != 0 && wanted_attributes != current.attributes() & VALID_SET_ATTRIBUTES {
        handle
            .set_attributes(wanted_attributes)
            .await
            .map_err(|e| e.to_nt_status())?;
    }

    let [creation, access, write, change] = times;
    let new_time = |t: i64, now: u64| u64::try_from(t).ok().filter(|&t| t != 0 && t != now);
    let wanted_times = FileTimes {
        creation_time: new_time(creation, current.creation_time),
        last_access_time: new_time(access, current.last_access_time),
        last_write_time: new_time(write, current.last_write_time),
        change_time: new_time(change, current.change_time),
    };
    if wanted_times != FileTimes::default() {
        handle
            .set_times(wanted_times)
            .await
            .map_err(|e| e.to_nt_status())?;
    }

    let fixed = |t: i64, now: u64, before: Option<u64>| match t {
        0 => before,
        -2 => None,
        -1 => Some(now),
        t => Some(t as u64),
    };
    let before = open.fixed_times;
    open.fixed_times.last_access_time =
        fixed(access, current.last_access_time, before.last_access_time);
    open.fixed_times.last_write_time =
        fixed(write, current.last_write_time, before.last_write_time);
    Ok(())
}

/// FileEndOfFileInformation, or FileAllocationInformation when
/// `allocation` is set (MS-FSA 2.1.5.15.1, 2.1.5.15.4). An allocation size
/// below the end of file truncates the file to it; a larger one leaves the
/// file as it is, and no space is reserved.
async fn truncate(open: &Open, size: u64, allocation: bool) -> Result<(), u32> {
    if open.is_directory {
        return Err(ntstatus::STATUS_INVALID_PARAMETER);
    }
    let handle = open.handle.as_ref().ok_or(ntstatus::STATUS_FILE_CLOSED)?;
    if allocation {
        let info = handle.stat().await.map_err(|e| e.to_nt_status())?;
        if size >= info.end_of_file {
            return Ok(());
        }
    }
    handle.truncate(size).await.map_err(|e| e.to_nt_status())?;
    restore_fixed_times(open).await;
    Ok(())
}

/// FileDispositionInformation (MS-FSA 2.1.5.15.3).
async fn set_disposition(open: &mut Open, delete: bool) -> Result<(), u32> {
    if delete {
        let handle = open.handle.as_ref().ok_or(ntstatus::STATUS_FILE_CLOSED)?;
        let info = handle.stat().await.map_err(|e| e.to_nt_status())?;
        if info.read_only {
            return Err(ntstatus::STATUS_CANNOT_DELETE);
        }
        if open.is_directory {
            let entries = handle.list_dir(None).await.map_err(|e| e.to_nt_status())?;
            if !entries.is_empty() {
                return Err(ntstatus::STATUS_DIRECTORY_NOT_EMPTY);
            }
        }
    }
    open.delete_on_close = delete;
    Ok(())
}
