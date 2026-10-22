//! SET_INFO handler.

use std::sync::Arc;
use std::sync::atomic::Ordering;

use crate::proto::header::Smb2Header;
use crate::proto::messages::{InfoType, SetInfoRequest, SetInfoResponse};

use crate::access_mask::{DELETE, FILE_WRITE_ATTRIBUTES, FILE_WRITE_DATA};
use crate::backend::{
    FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_TEMPORARY, FileInfo, FileTimes, OpenOptions,
    ShareBackend, VALID_SET_ATTRIBUTES,
};
use crate::conn::pending::{Stop, stopped};
use crate::conn::state::{Connection, Open};
use crate::dispatch::HandlerResponse;
use crate::files::{BreakWait, CONTENT_CHANGED, Change, MAX_BREAK_WAIT, Trigger};
use crate::handlers::shared::{lookup_open, lookup_session_tree, restore_fixed_times};
use crate::handlers::{Outcome, Pending};
use crate::info_class as ic;
use crate::ntstatus;
use crate::path::{SmbPath, same_path};
use crate::proto::messages::FileId;
use crate::proto::messages::change_notify::{
    FILE_ACTION_ADDED, FILE_ACTION_MODIFIED, FILE_ACTION_REMOVED, FILE_ACTION_RENAMED_NEW_NAME,
    FILE_ACTION_RENAMED_OLD_NAME, FILE_NOTIFY_CHANGE_ATTRIBUTES, FILE_NOTIFY_CHANGE_CREATION,
    FILE_NOTIFY_CHANGE_DIR_NAME, FILE_NOTIFY_CHANGE_FILE_NAME, FILE_NOTIFY_CHANGE_LAST_ACCESS,
    FILE_NOTIFY_CHANGE_LAST_WRITE,
};
use crate::server::{ServerState, ShareBindings};
use crate::utils::utf16le_to_units;
use tokio::sync::RwLock;
use tracing::warn;

/// Classes MS-FSCC 2.4 lists as settable: Basic, Rename, Link, Disposition,
/// Position, FullEa, Mode, Allocation, EndOfFile, Pipe, Quota,
/// ValidDataLength, ShortName, DispositionEx and RenameEx.
const SETTABLE_CLASSES: [u8; 15] = [4, 10, 11, 13, 14, 15, 16, 19, 20, 23, 32, 39, 40, 64, 65];

/// File information classes SET_INFO applies.
enum Class {
    Basic,
    EndOfFile,
    Disposition,
    Rename,
    Allocation,
}

pub async fn handle(
    _server: &Arc<ServerState>,
    conn: &Arc<Connection>,
    hdr: &Smb2Header,
    body: &[u8],
    retained: usize,
) -> Outcome {
    match set(conn, hdr, body).await {
        Ok(response) => Outcome::Done(response),
        Err((wait, rename)) => wait_for_rename(conn, hdr, wait, rename, retained),
    }
}

/// Applies the SET_INFO request, or returns the rename that has to wait for
/// a lease break first.
async fn set(
    conn: &Arc<Connection>,
    hdr: &Smb2Header,
    body: &[u8],
) -> Result<HandlerResponse, (BreakWait, Rename)> {
    let req = match SetInfoRequest::parse(body) {
        Ok(r) => r,
        Err(_) => return Ok(HandlerResponse::err(ntstatus::STATUS_INVALID_PARAMETER)),
    };
    let tree_arc = match lookup_session_tree(conn, hdr).await {
        Ok(t) => t,
        Err(s) => return Ok(HandlerResponse::err(s)),
    };
    let open_arc = match lookup_open(&tree_arc, req.file_id).await {
        Some(o) => o,
        None => return Ok(HandlerResponse::err(ntstatus::STATUS_FILE_CLOSED)),
    };
    let share = Arc::clone(&tree_arc.read().await.share);
    if req.buffer_length == 0 {
        return Ok(HandlerResponse::err(ntstatus::STATUS_INVALID_PARAMETER));
    }
    let info_type = match InfoType::from_u8(req.info_type) {
        Some(t) => t,
        None => return Ok(HandlerResponse::err(ntstatus::STATUS_INVALID_INFO_CLASS)),
    };
    if !matches!(info_type, InfoType::File) {
        return Ok(HandlerResponse::err(ntstatus::STATUS_NOT_SUPPORTED));
    }

    // MS-SMB2 3.3.5.21.1: access each class needs from Open.GrantedAccess.
    // Other classes MS-FSCC 2.4 marks settable are not supported; the rest
    // cannot be set.
    let (class, required) = match req.file_information_class {
        ic::FILE_BASIC_INFORMATION => (Class::Basic, FILE_WRITE_ATTRIBUTES),
        ic::FILE_DISPOSITION_INFORMATION => (Class::Disposition, DELETE),
        ic::FILE_RENAME_INFORMATION => (Class::Rename, DELETE),
        ic::FILE_END_OF_FILE_INFORMATION => (Class::EndOfFile, FILE_WRITE_DATA),
        ic::FILE_ALLOCATION_INFORMATION => (Class::Allocation, FILE_WRITE_DATA),
        class if SETTABLE_CLASSES.contains(&class) => {
            return Ok(HandlerResponse::err(ntstatus::STATUS_NOT_SUPPORTED));
        }
        _ => return Ok(HandlerResponse::err(ntstatus::STATUS_INVALID_INFO_CLASS)),
    };
    if open_arc.read().await.granted_access & required != required {
        return Ok(HandlerResponse::err(ntstatus::STATUS_ACCESS_DENIED));
    }
    let buffer = req.buffer;
    let result = match class {
        Class::Basic => {
            if buffer.len() < 36 {
                return Ok(HandlerResponse::err(ntstatus::STATUS_INFO_LENGTH_MISMATCH));
            }
            let time = |at: usize| i64::from_le_bytes(buffer[at..at + 8].try_into().unwrap());
            let times = [time(0), time(8), time(16), time(24)];
            let attributes = u32::from_le_bytes(buffer[32..36].try_into().unwrap());
            let changed = set_basic_info(&mut *open_arc.write().await, times, attributes).await;
            match changed {
                Ok(filter) => {
                    report_modified(&share, &open_arc, filter).await;
                    Ok(())
                }
                Err(status) => Err(status),
            }
        }
        Class::EndOfFile => {
            if buffer.len() < 8 {
                return Ok(HandlerResponse::err(ntstatus::STATUS_INFO_LENGTH_MISMATCH));
            }
            let new_len = u64::from_le_bytes(buffer[0..8].try_into().unwrap());
            let heard = !share.watches.is_empty();
            let resized = truncate(&*open_arc.read().await, new_len, false, heard).await;
            match resized {
                Ok(resized) => {
                    report_resized(&share, &open_arc, resized).await;
                    Ok(())
                }
                Err(status) => Err(status),
            }
        }
        Class::Allocation => {
            if buffer.len() < 8 {
                return Ok(HandlerResponse::err(ntstatus::STATUS_INFO_LENGTH_MISMATCH));
            }
            let size = u64::from_le_bytes(buffer[0..8].try_into().unwrap());
            let heard = !share.watches.is_empty();
            let resized = truncate(&*open_arc.read().await, size, true, heard).await;
            match resized {
                Ok(resized) => {
                    report_resized(&share, &open_arc, resized).await;
                    Ok(())
                }
                Err(status) => Err(status),
            }
        }
        Class::Disposition => {
            if buffer.is_empty() {
                return Ok(HandlerResponse::err(ntstatus::STATUS_INFO_LENGTH_MISMATCH));
            }
            let delete = buffer[0] != 0;
            // A directory is marked and its watches ended under one name,
            // with no rename in between.
            let is_directory = open_arc.read().await.is_directory;
            let names = if delete && is_directory {
                Some(share.files.names_lock().await)
            } else {
                None
            };
            let open = open_arc.read().await;
            let result = set_disposition(&open, delete).await;
            if result.is_ok() && names.is_some() {
                end_watches_of_deleted(&share, &open);
            }
            result
        }
        Class::Rename => {
            // FILE_RENAME_INFORMATION layout (MS-FSCC §2.4.37):
            //   ReplaceIfExists (1) | Reserved (7) | RootDirectory (8) | FileNameLength (4) | FileName...
            if buffer.len() < 20 {
                return Ok(HandlerResponse::err(ntstatus::STATUS_INFO_LENGTH_MISMATCH));
            }
            if buffer[8..16] != [0; 8] {
                return Ok(HandlerResponse::err(ntstatus::STATUS_INVALID_PARAMETER));
            }
            let name_len = u32::from_le_bytes(
                buffer[16..20]
                    .try_into()
                    .expect("the length check above covers these bytes"),
            );
            let Some(name_bytes) = usize::try_from(name_len)
                .ok()
                .and_then(|len| buffer.get(20..)?.get(..len))
            else {
                return Ok(HandlerResponse::err(ntstatus::STATUS_INFO_LENGTH_MISMATCH));
            };
            let units = match utf16le_to_units(name_bytes) {
                Some(u) => u,
                None => return Ok(HandlerResponse::err(ntstatus::STATUS_OBJECT_NAME_INVALID)),
            };
            let new_path = match SmbPath::from_utf16(&units) {
                Ok(p) => p,
                Err(_) => return Ok(HandlerResponse::err(ntstatus::STATUS_OBJECT_NAME_INVALID)),
            };
            let rename = Rename {
                file_id: req.file_id,
                to: new_path,
                replace: buffer[0] != 0,
            };
            match rename_attempt(conn, hdr, &rename, Stage::Start).await {
                Renamed::Done(result) => result,
                Renamed::Wait(wait) => return Err((wait, rename)),
            }
        }
    };

    if let Err(status) = result {
        return Ok(HandlerResponse::err(status));
    }
    Ok(set_info_ok())
}

/// Reports a change through `open_arc` that matches the filter bits
/// `filter`, if any, as MODIFIED, when the share has watches. The open's
/// name is read under the share's names lock, taken with the open
/// unlocked, so it is current.
async fn report_modified(share: &ShareBindings, open_arc: &RwLock<Open>, filter: u32) {
    if filter == 0 || share.watches.is_empty() {
        return;
    }
    let _names = share.files.names_lock().await;
    let path = open_arc.read().await.path();
    if let Some(path) = path {
        share.watches.report(&[Change {
            path: &path,
            action: FILE_ACTION_MODIFIED,
            filter,
            seen: true,
        }]);
    }
}

/// Reports a size change through `open_arc` when `resized`, once; Windows
/// reports a truncation twice.
async fn report_resized(share: &ShareBindings, open_arc: &RwLock<Open>, resized: bool) {
    if resized {
        report_modified(share, open_arc, CONTENT_CHANGED).await;
    }
}

/// A FileRenameInformation request.
struct Rename {
    file_id: FileId,
    to: SmbPath,
    replace: bool,
}

/// Where a rename stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Stage {
    Start,
    /// The handle caching of an open target was broken. A target still
    /// open waits while that break is in progress and fails the rename
    /// once it is over.
    AfterHandleBreak,
}

/// How a rename attempt ended.
enum Renamed {
    Done(Result<(), u32>),
    Wait(BreakWait),
}

/// Answers a rename asynchronously while the clients caching handles to
/// its target give them up. Closing the renamed open ends the wait.
fn wait_for_rename(
    conn: &Arc<Connection>,
    hdr: &Smb2Header,
    wait: BreakWait,
    rename: Rename,
    retained: usize,
) -> Outcome {
    let Some((op, mut stop)) = conn.pending.reserve(hdr, Some(rename.file_id), retained) else {
        warn!("too many waiting requests on the connection");
        return Outcome::Done(HandlerResponse::err(
            ntstatus::STATUS_INSUFFICIENT_RESOURCES,
        ));
    };
    let (conn, hdr) = (Arc::clone(conn), *hdr);
    // The wait ends when the break completes, which its acknowledgment
    // timer bounds. A wait that runs out with nothing changed on the
    // target, or one that outlasts [`MAX_BREAK_WAIT`], fails the rename.
    let work = async move {
        let give_up = tokio::time::Instant::now() + MAX_BREAK_WAIT;
        let mut wait = wait;
        loop {
            let changed = tokio::select! {
                biased;
                why = stopped(&mut stop) => {
                    if why == Stop::Cancelled {
                        return HandlerResponse::err(ntstatus::STATUS_CANCELLED);
                    }
                    true
                }
                changed = wait.changed() => changed,
                () = tokio::time::sleep_until(give_up) => false,
            };
            match rename_attempt(&conn, &hdr, &rename, Stage::AfterHandleBreak).await {
                Renamed::Done(Ok(())) => return set_info_ok(),
                Renamed::Done(Err(status)) => return HandlerResponse::err(status),
                Renamed::Wait(_) if !changed => {
                    return HandlerResponse::err(ntstatus::STATUS_ACCESS_DENIED);
                }
                Renamed::Wait(next) => wait = next,
            }
        }
    };
    Outcome::Pending(Pending {
        op,
        work: Box::pin(work),
    })
}

fn set_info_ok() -> HandlerResponse {
    let mut buf = Vec::new();
    SetInfoResponse::default()
        .write_to(&mut buf)
        .expect("encode");
    HandlerResponse::ok(buf)
}

/// FileRenameInformation (MS-FSA 2.1.5.15.12). A directory with a file or
/// directory open below it is not renamed, and neither is an open target
/// replaced; when they are open only because clients cache their handles,
/// the first attempt breaks that caching and waits. The leases on the
/// renamed file give up handle caching.
async fn rename_attempt(
    conn: &Arc<Connection>,
    hdr: &Smb2Header,
    rename: &Rename,
    stage: Stage,
) -> Renamed {
    let tree_arc = match lookup_session_tree(conn, hdr).await {
        Ok(t) => t,
        Err(s) => return Renamed::Done(Err(s)),
    };
    let Some(open_arc) = lookup_open(&tree_arc, rename.file_id).await else {
        return Renamed::Done(Err(ntstatus::STATUS_FILE_CLOSED));
    };
    let share = tree_arc.read().await.share.clone();
    let case_sensitive = share.backend.capabilities().case_sensitive;
    let to = &rename.to;
    // An entry already at the new name, the renamed one itself when only
    // the case changes, is reported by its name as stored. It is looked up
    // only when someone watches it, and before the rename lock, so CREATEs
    // and deletes on the share do not wait for it; one that changes
    // meanwhile is reported as it was.
    let may_exist = |from: &SmbPath| {
        (rename.replace || same_path(from, to, case_sensitive))
            && !same_name(from, to, case_sensitive)
    };
    let named = open_arc.read().await.path();
    let replaced = match named {
        Some(from) if may_exist(&from) && share.watches.watching(to) => {
            stored_entry(share.backend.as_ref(), to, case_sensitive).await
        }
        _ => None,
    };
    let _renames = share.files.rename_lock().await;
    let open = open_arc.read().await;
    let Some(file) = open.file.as_ref() else {
        return Renamed::Done(Err(ntstatus::STATUS_FILE_CLOSED));
    };
    let from = file.path();
    let is_directory = open.is_directory;
    if from.is_root() {
        return Renamed::Done(Err(ntstatus::STATUS_ACCESS_DENIED));
    }
    if is_directory && share.files.open_below(&from, case_sensitive) {
        let start = stage == Stage::Start;
        if let Some(wait) = share
            .files
            .break_handles_below(&from, case_sensitive, start)
        {
            return Renamed::Wait(wait);
        }
        return Renamed::Done(Err(ntstatus::STATUS_ACCESS_DENIED));
    }
    // A target that names the source itself is the same file and skips
    // this.
    let replaces = rename.replace && !same_path(&from, to, case_sensitive);
    if replaces && share.files.path_is_open(to, case_sensitive) {
        let start = stage == Stage::Start;
        if let Some(wait) = share
            .files
            .break_handles_at(to, case_sensitive, file.lease_id(), start)
        {
            return Renamed::Wait(wait);
        }
        return Renamed::Done(Err(ntstatus::STATUS_ACCESS_DENIED));
    }
    file.break_leases(Trigger::Handle);
    let replaced = replaced.filter(|_| may_exist(&from));
    // Renaming one link of a file over another removes the source link.
    let links = replaced
        .as_ref()
        .is_some_and(|entry| file.has_index(entry.file_index))
        && !same_path(&from, to, case_sensitive);
    drop(open);
    let changes = rename_changes(&from, to, is_directory, replaced, links, case_sensitive);
    let changes: Vec<Change<'_>> = changes
        .iter()
        .map(|(path, action, filter, seen)| Change {
            path,
            action: *action,
            filter: *filter,
            seen: *seen,
        })
        .collect();
    let expected = share
        .watches
        .expect(&changes, is_directory.then_some(&from));
    let result = match share.backend.rename(&from, to, rename.replace).await {
        Ok(()) => {
            share.files.rename_paths(&from, to, case_sensitive);
            if is_directory {
                share.watches.rename(&from, to);
            }
            expected.report(&share.watches, &changes);
            Ok(())
        }
        Err(e) => Err(e.to_nt_status()),
    };
    Renamed::Done(result)
}

/// An entry as its directory lists it: its name as stored, and whether it
/// is a directory.
#[derive(Debug, Clone, PartialEq, Eq)]
struct StoredEntry {
    name: String,
    is_directory: bool,
    /// The backend's file id, `0` if it has none.
    file_index: u64,
}

/// The entry `path` names: on a case-sensitive backend, found by opening
/// it, so it is stored as `path` spells it; otherwise looked up in a
/// listing of its directory.
async fn stored_entry(
    backend: &dyn ShareBackend,
    path: &SmbPath,
    case_sensitive: bool,
) -> Option<StoredEntry> {
    let name = path.file_name()?;
    if case_sensitive {
        let (handle, _) = backend.open(path, OpenOptions::default()).await.ok()?;
        let info = handle.stat().await;
        let _ = handle.close().await;
        let info = info.ok()?;
        return Some(StoredEntry {
            name: name.to_string(),
            is_directory: info.is_directory,
            file_index: info.file_index,
        });
    }
    let opts = OpenOptions {
        directory: true,
        ..OpenOptions::default()
    };
    let (handle, _) = backend.open(&path.parent()?, opts).await.ok()?;
    let entries = handle.list_dir(Some(name)).await;
    let _ = handle.close().await;
    entries
        .ok()?
        .into_iter()
        .find(|e| e.info.name.to_lowercase() == name.to_lowercase())
        .map(|e| StoredEntry {
            name: e.info.name,
            is_directory: e.info.is_directory,
            file_index: e.info.file_index,
        })
}

/// True if renaming `from` to `to` keeps the directory and spells the name
/// exactly as before.
fn same_name(from: &SmbPath, to: &SmbPath, case_sensitive: bool) -> bool {
    let parent = |path: &SmbPath| path.parent().unwrap_or_default();
    same_path(&parent(from), &parent(to), case_sensitive) && from.file_name() == to.file_name()
}

/// The changes renaming `from` to `to` reports, as (path, action, filter,
/// seen) in order (MS-FSA 2.1.5.15.12). An entry already at the new name, which
/// the rename replaced, or the renamed entry itself when only the case of
/// its name changes, is REMOVED first under its name as stored (`stored`).
/// This follows Windows; MS-FSA instead reports a replaced target spelled
/// as stored as MODIFIED. Then a rename within one directory is
/// RENAMED_OLD_NAME and RENAMED_NEW_NAME, one into another directory
/// REMOVED and ADDED, and the directory the entry lands in is MODIFIED
/// under LAST_WRITE. A rename to the same name, or to the stored name of
/// the renamed entry, reports nothing. `seen` tells which of these a
/// backend that reports changes sees itself: not the removal of the
/// replaced entry, and when `links` names two links of one file, which the
/// backend renames by removing the source, not the new name either.
fn rename_changes(
    from: &SmbPath,
    to: &SmbPath,
    is_directory: bool,
    stored: Option<StoredEntry>,
    links: bool,
    case_sensitive: bool,
) -> Vec<(SmbPath, u32, u32, bool)> {
    if same_name(from, to, case_sensitive) {
        return Vec::new();
    }
    // Renaming an entry to its own name as stored changes nothing, however
    // the open spelled it.
    if same_path(from, to, case_sensitive)
        && stored
            .as_ref()
            .is_some_and(|entry| to.file_name() == Some(entry.name.as_str()))
    {
        return Vec::new();
    }
    let kind = |directory| {
        if directory {
            FILE_NOTIFY_CHANGE_DIR_NAME
        } else {
            FILE_NOTIFY_CHANGE_FILE_NAME
        }
    };
    let parent = |path: &SmbPath| path.parent().unwrap_or_default();
    let mut changes = Vec::with_capacity(3);
    if let Some(entry) = stored
        && let Ok(path) = parent(to).join(&entry.name)
    {
        changes.push((path, FILE_ACTION_REMOVED, kind(entry.is_directory), false));
    }
    let (old, new) = if same_path(&parent(from), &parent(to), case_sensitive) {
        (FILE_ACTION_RENAMED_OLD_NAME, FILE_ACTION_RENAMED_NEW_NAME)
    } else {
        (FILE_ACTION_REMOVED, FILE_ACTION_ADDED)
    };
    let filter = kind(is_directory);
    changes.push((from.clone(), old, filter, true));
    changes.push((to.clone(), new, filter, !links));
    // The directory the entry lands in has a new write time, which Windows
    // reports as a change of that directory.
    let into = parent(to);
    if !into.is_root() {
        changes.push((
            into,
            FILE_ACTION_MODIFIED,
            FILE_NOTIFY_CHANGE_LAST_WRITE,
            true,
        ));
    }
    changes
}

/// FileBasicInformation (MS-FSA 2.1.5.15.2, MS-FSCC 2.4.7). A time of 0
/// or -1 leaves it alone. For the access and write times, -1 also keeps the
/// time fixed against later changes made through this open, -2 lets those
/// changes update it again, and a time set through the open stays fixed. A
/// time or attribute set that equals the current one is not passed to the
/// backend. Returns the FILE_NOTIFY_CHANGE_* bits of what changed, as a stat
/// before and after shows it: the attributes and each time but the change
/// time (MS-FSA 2.1.5.15.2).
async fn set_basic_info(open: &mut Open, times: [i64; 4], attributes: u32) -> Result<u32, u32> {
    if times.iter().any(|&t| t < -2)
        || (attributes & FILE_ATTRIBUTE_DIRECTORY != 0 && !open.is_directory)
        || (attributes & FILE_ATTRIBUTE_TEMPORARY != 0 && open.is_directory)
    {
        return Err(ntstatus::STATUS_INVALID_PARAMETER);
    }
    let handle = open.handle.as_ref().ok_or(ntstatus::STATUS_FILE_CLOSED)?;
    let current = handle.stat().await.map_err(|e| e.to_nt_status())?;

    let mut passed = false;
    let wanted_attributes = attributes & VALID_SET_ATTRIBUTES;
    if attributes != 0 && wanted_attributes != current.attributes() & VALID_SET_ATTRIBUTES {
        handle
            .set_attributes(wanted_attributes)
            .await
            .map_err(|e| e.to_nt_status())?;
        passed = true;
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
        passed = true;
    }
    // What the backend keeps decides what changed: one that drops a value,
    // or does not store an attribute, reports nothing for it.
    let changed = if passed {
        handle
            .stat()
            .await
            .map_or(0, |after| changed_fields(&current, &after))
    } else {
        0
    };

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
    Ok(changed)
}

/// The FILE_NOTIFY_CHANGE_* bits of the fields FileBasicInformation sets
/// that differ between `before` and `after`.
fn changed_fields(before: &FileInfo, after: &FileInfo) -> u32 {
    [
        (
            before.attributes() & VALID_SET_ATTRIBUTES != after.attributes() & VALID_SET_ATTRIBUTES,
            FILE_NOTIFY_CHANGE_ATTRIBUTES,
        ),
        (
            before.creation_time != after.creation_time,
            FILE_NOTIFY_CHANGE_CREATION,
        ),
        (
            before.last_access_time != after.last_access_time,
            FILE_NOTIFY_CHANGE_LAST_ACCESS,
        ),
        (
            before.last_write_time != after.last_write_time,
            FILE_NOTIFY_CHANGE_LAST_WRITE,
        ),
    ]
    .into_iter()
    .filter(|(differs, _)| *differs)
    .fold(0, |bits, (_, bit)| bits | bit)
}

/// FileEndOfFileInformation, or FileAllocationInformation when
/// `allocation` is set (MS-FSA 2.1.5.15.1, 2.1.5.15.4). An allocation size
/// below the end of file truncates the file to it; a larger one leaves the
/// file as it is, and no space is reserved. With `measure`, returns whether
/// the size changed, from a stat before and after.
async fn truncate(open: &Open, size: u64, allocation: bool, measure: bool) -> Result<bool, u32> {
    if open.is_directory {
        return Err(ntstatus::STATUS_INVALID_PARAMETER);
    }
    let handle = open.handle.as_ref().ok_or(ntstatus::STATUS_FILE_CLOSED)?;
    // MS-FSA 2.1.5.15.1, 2.1.5.15.5: the leases on the file, all but the
    // one this open holds, break even when the size stays. They break again
    // once the size has changed, so a lease granted meanwhile does not keep
    // the old contents cached.
    let break_leases = || {
        if let Some(file) = open.file.as_ref() {
            file.break_leases(Trigger::Write);
        }
    };
    break_leases();
    let before = if allocation || measure {
        let info = handle.stat().await.map_err(|e| e.to_nt_status())?;
        if allocation && size >= info.end_of_file {
            return Ok(false);
        }
        info.end_of_file
    } else {
        0
    };
    let result = handle.truncate(size).await;
    break_leases();
    result.map_err(|e| e.to_nt_status())?;
    restore_fixed_times(open).await;
    if !measure {
        return Ok(false);
    }
    Ok(handle
        .stat()
        .await
        .map_or(true, |after| after.end_of_file != before))
}

/// FileDispositionInformation (MS-FSA 2.1.5.15.3). The flag belongs to the
/// file, so clearing it through any open keeps the file.
async fn set_disposition(open: &Open, delete: bool) -> Result<(), u32> {
    if delete {
        let handle = open.handle.as_ref().ok_or(ntstatus::STATUS_FILE_CLOSED)?;
        let info = handle.stat().await.map_err(|e| e.to_nt_status())?;
        if info.read_only {
            return Err(ntstatus::STATUS_CANNOT_DELETE);
        }
        if open.is_directory && !handle.dir_is_empty().await.map_err(|e| e.to_nt_status())? {
            return Err(ntstatus::STATUS_DIRECTORY_NOT_EMPTY);
        }
    }
    let file = open.file.as_ref().ok_or(ntstatus::STATUS_FILE_CLOSED)?;
    file.set_delete_pending(delete);
    if delete && open.is_directory {
        open.marked_deleted.store(true, Ordering::Release);
    }
    Ok(())
}

/// Ends every watch of the directory `open` just marked for deletion,
/// whichever open armed it and under whichever of the directory's names,
/// with STATUS_DELETE_PENDING (MS-FSA 2.1.5.15.3). The caller holds the
/// share's names lock.
fn end_watches_of_deleted(share: &ShareBindings, open: &Open) {
    if let Some(file) = &open.file {
        for path in file.open_paths() {
            share.watches.end_at(&path, ntstatus::STATUS_DELETE_PENDING);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use async_trait::async_trait;
    use tokio::sync::{Notify, RwLock, Semaphore};

    use super::*;
    use crate::backend::{
        BackendCapabilities, Handle, OpenAction, OpenIntent, OpenOptions, ShareBackend,
    };
    use crate::builder::Access;
    use crate::conn::state::{Session, TreeConnect};
    use crate::error::SmbResult;
    use crate::files::{FileRef, Sharing};
    use crate::proto::auth::ntlm::Identity;
    use crate::proto::header::{Command, HeaderTail};
    use crate::proto::messages::FileId;
    use crate::tests::memfs::MemFsBackend;
    use crate::{Share, SmbServer};

    /// Memory backend that counts renames and, once the first has run in
    /// the backend, tells `waiting` and waits for a permit from `go` before
    /// returning it.
    struct HoldRename {
        inner: MemFsBackend,
        renames: Arc<AtomicUsize>,
        waiting: Arc<Notify>,
        go: Arc<Semaphore>,
    }

    #[async_trait]
    impl ShareBackend for HoldRename {
        async fn open(
            &self,
            path: &SmbPath,
            opts: OpenOptions,
        ) -> SmbResult<(Box<dyn Handle>, OpenAction)> {
            self.inner.open(path, opts).await
        }

        async fn unlink(&self, path: &SmbPath) -> SmbResult<()> {
            self.inner.unlink(path).await
        }

        async fn rename(&self, from: &SmbPath, to: &SmbPath, replace: bool) -> SmbResult<()> {
            let result = self.inner.rename(from, to, replace).await;
            if self.renames.fetch_add(1, Ordering::SeqCst) == 0 {
                self.waiting.notify_one();
                self.go.acquire().await.expect("gate").forget();
            }
            result
        }

        fn capabilities(&self) -> BackendCapabilities {
            self.inner.capabilities()
        }
    }

    fn rename_body(file_id: FileId, to: &str) -> Vec<u8> {
        let name: Vec<u8> = to.encode_utf16().flat_map(u16::to_le_bytes).collect();
        let mut buffer = vec![1];
        buffer.resize(16, 0);
        buffer.extend_from_slice(&(name.len() as u32).to_le_bytes());
        buffer.extend_from_slice(&name);
        let req = SetInfoRequest {
            structure_size: 33,
            info_type: 1,
            file_information_class: ic::FILE_RENAME_INFORMATION,
            buffer_length: buffer.len() as u32,
            buffer_offset: 0x60,
            reserved: 0,
            additional_information: 0,
            file_id,
            buffer,
        };
        let mut body = Vec::new();
        req.write_to(&mut body)
            .expect("encoding into a Vec cannot fail");
        body
    }

    #[tokio::test]
    async fn renames_on_a_share_run_one_at_a_time() {
        let renames = Arc::new(AtomicUsize::new(0));
        let waiting = Arc::new(Notify::new());
        let go = Arc::new(Semaphore::new(0));
        let backend = HoldRename {
            inner: MemFsBackend::new()
                .with_file("d\\f", b"x")
                .with_file("h", b"y"),
            renames: Arc::clone(&renames),
            waiting: Arc::clone(&waiting),
            go: Arc::clone(&go),
        };
        let server = SmbServer::builder()
            .listen("127.0.0.1:0".parse().unwrap())
            .share(Share::new("s", backend).public())
            .build()
            .unwrap();
        let state = server.state();
        let share = state.find_share("s").await.unwrap();
        let conn = Arc::new(Connection::new(
            state.config.server_guid,
            state.config.max_read_size,
            state.config.max_write_size,
        ));
        let session = Session::new(Identity::Anonymous, [0; 16], [0; 16], false, None);
        let tree = TreeConnect::new(1, Arc::clone(&share), Access::ReadWrite);
        let mut file_ids = Vec::new();
        for (path, directory) in [("d\\f", false), ("h", false)] {
            let path: SmbPath = path.parse().unwrap();
            let opts = OpenOptions {
                directory,
                intent: OpenIntent::OpenOrCreate,
                ..OpenOptions::default()
            };
            let (handle, _) = share.backend.open(&path, opts).await.unwrap();
            let info = handle.stat().await.unwrap();
            let sharing = Sharing {
                access: DELETE,
                share: 7,
            };
            let file = FileRef::register(&share, &info, &path, sharing.into())
                .unwrap()
                .0;
            let file_id = tree.alloc_file_id();
            let open = Open {
                file_id,
                handle: Some(handle),
                granted_access: DELETE,
                is_directory: directory,
                delete_on_close: false,
                search_state: None,
                fixed_times: FileTimes::default(),
                create_options: 0,
                file: Some(file),
                slot: None,
                durable: None,
                watch: None,
                wrote: Default::default(),
                created: false,
                marked_deleted: Default::default(),
            };
            tree.opens
                .write()
                .await
                .insert(file_id, Arc::new(RwLock::new(open)));
            file_ids.push(file_id);
        }
        session
            .trees
            .write()
            .await
            .insert(1, Arc::new(RwLock::new(tree)));
        conn.sessions
            .write()
            .await
            .insert(1, Arc::new(RwLock::new(session)));

        let hdr = Smb2Header {
            command: Command::SetInfo,
            tail: HeaderTail::sync(1),
            session_id: 1,
            ..Smb2Header::default()
        };
        let rename = |file_id, to: &str| {
            let state = Arc::clone(&state);
            let conn = Arc::clone(&conn);
            let body = rename_body(file_id, to);
            tokio::spawn(async move {
                match handle(&state, &conn, &hdr, &body, 0).await {
                    Outcome::Done(response) => response.status,
                    Outcome::Pending(_) => panic!("the rename waits"),
                }
            })
        };
        let file = rename(file_ids[0], "d\\g");
        waiting.notified().await;
        let other = rename(file_ids[1], "i");
        for _ in 0..10 {
            tokio::task::yield_now().await;
        }
        assert_eq!(
            renames.load(Ordering::SeqCst),
            1,
            "a rename ran during another"
        );

        go.add_permits(1);
        assert_eq!(file.await.unwrap(), ntstatus::STATUS_SUCCESS);
        assert_eq!(other.await.unwrap(), ntstatus::STATUS_SUCCESS);
        assert_eq!(renames.load(Ordering::SeqCst), 2);
        assert!(share.files.path_is_open(&"d\\g".parse().unwrap(), false));
        assert!(share.files.path_is_open(&"i".parse().unwrap(), false));
    }

    fn p(s: &str) -> SmbPath {
        s.parse().unwrap()
    }

    /// (action, path) of each change renaming `from` to `to` reports.
    fn changes(
        from: &str,
        to: &str,
        is_directory: bool,
        replaced: Option<(&str, bool)>,
    ) -> Vec<(u32, String, u32)> {
        let replaced = replaced.map(|(name, is_directory)| StoredEntry {
            name: name.to_string(),
            is_directory,
            file_index: 0,
        });
        rename_changes(&p(from), &p(to), is_directory, replaced, false, false)
            .into_iter()
            .map(|(path, action, filter, _)| (action, path.display_backslash(), filter))
            .collect()
    }

    #[test]
    fn a_backend_sees_neither_a_replaced_entry_go_nor_a_link_renamed_over_another() {
        let stored = || {
            Some(StoredEntry {
                name: "b".to_string(),
                is_directory: false,
                file_index: 7,
            })
        };
        let seen = |links| {
            rename_changes(&p("a"), &p("b"), false, stored(), links, false)
                .into_iter()
                .map(|(path, action, _, seen)| (action, path.display_backslash(), seen))
                .collect::<Vec<_>>()
        };
        let s = |x: &str| x.to_string();
        assert_eq!(
            seen(false),
            [
                (FILE_ACTION_REMOVED, s("b"), false),
                (FILE_ACTION_RENAMED_OLD_NAME, s("a"), true),
                (FILE_ACTION_RENAMED_NEW_NAME, s("b"), true),
            ]
        );
        assert_eq!(
            seen(true),
            [
                (FILE_ACTION_REMOVED, s("b"), false),
                (FILE_ACTION_RENAMED_OLD_NAME, s("a"), true),
                (FILE_ACTION_RENAMED_NEW_NAME, s("b"), false),
            ]
        );
    }

    const FILE: u32 = FILE_NOTIFY_CHANGE_FILE_NAME;
    const DIR: u32 = FILE_NOTIFY_CHANGE_DIR_NAME;
    const LAST_WRITE: u32 = FILE_NOTIFY_CHANGE_LAST_WRITE;

    #[test]
    fn renames_report_by_directory_and_kind() {
        let s = |x: &str| x.to_string();
        assert_eq!(
            changes("d\\a", "D\\b", false, None),
            [
                (FILE_ACTION_RENAMED_OLD_NAME, s("d\\a"), FILE),
                (FILE_ACTION_RENAMED_NEW_NAME, s("D\\b"), FILE),
                (FILE_ACTION_MODIFIED, s("D"), LAST_WRITE),
            ]
        );
        assert_eq!(
            changes("d\\a", "e\\a", true, None),
            [
                (FILE_ACTION_REMOVED, s("d\\a"), DIR),
                (FILE_ACTION_ADDED, s("e\\a"), DIR),
                (FILE_ACTION_MODIFIED, s("e"), LAST_WRITE),
            ]
        );
        // A change of case only is a rename within the directory.
        assert_eq!(
            changes("d\\a", "d\\A", false, None),
            [
                (FILE_ACTION_RENAMED_OLD_NAME, s("d\\a"), FILE),
                (FILE_ACTION_RENAMED_NEW_NAME, s("d\\A"), FILE),
                (FILE_ACTION_MODIFIED, s("d"), LAST_WRITE),
            ]
        );
        // The same name in the same directory, however the directory is
        // spelled, reports nothing.
        assert!(changes("d\\a", "d\\a", false, None).is_empty());
        assert!(changes("d\\a", "D\\a", false, None).is_empty());
    }

    #[test]
    fn a_rename_into_the_share_root_modifies_no_directory() {
        let s = |x: &str| x.to_string();
        assert_eq!(
            changes("d\\a", "a", false, None),
            [
                (FILE_ACTION_REMOVED, s("d\\a"), FILE),
                (FILE_ACTION_ADDED, s("a"), FILE),
            ]
        );
    }

    #[test]
    fn an_entry_at_the_new_name_is_removed_first_under_its_stored_name() {
        let s = |x: &str| x.to_string();
        let stored = Some(("t", false));
        assert_eq!(
            changes("d\\a", "d\\t", false, stored),
            [
                (FILE_ACTION_REMOVED, s("d\\t"), FILE),
                (FILE_ACTION_RENAMED_OLD_NAME, s("d\\a"), FILE),
                (FILE_ACTION_RENAMED_NEW_NAME, s("d\\t"), FILE),
                (FILE_ACTION_MODIFIED, s("d"), LAST_WRITE),
            ]
        );
        assert_eq!(
            changes("d\\a", "d\\T", false, stored),
            [
                (FILE_ACTION_REMOVED, s("d\\t"), FILE),
                (FILE_ACTION_RENAMED_OLD_NAME, s("d\\a"), FILE),
                (FILE_ACTION_RENAMED_NEW_NAME, s("d\\T"), FILE),
                (FILE_ACTION_MODIFIED, s("d"), LAST_WRITE),
            ]
        );
        assert_eq!(
            changes("d\\a", "e\\t", true, stored),
            [
                (FILE_ACTION_REMOVED, s("e\\t"), FILE),
                (FILE_ACTION_REMOVED, s("d\\a"), DIR),
                (FILE_ACTION_ADDED, s("e\\t"), DIR),
                (FILE_ACTION_MODIFIED, s("e"), LAST_WRITE),
            ]
        );
        // An open spelled differently from the stored name renamed to it.
        assert!(changes("d\\X", "d\\x", false, Some(("x", false))).is_empty());
        // A change of case finds the renamed file itself.
        assert_eq!(
            changes("d\\x", "d\\X", false, Some(("x", false))),
            [
                (FILE_ACTION_REMOVED, s("d\\x"), FILE),
                (FILE_ACTION_RENAMED_OLD_NAME, s("d\\x"), FILE),
                (FILE_ACTION_RENAMED_NEW_NAME, s("d\\X"), FILE),
                (FILE_ACTION_MODIFIED, s("d"), LAST_WRITE),
            ]
        );
    }
}
