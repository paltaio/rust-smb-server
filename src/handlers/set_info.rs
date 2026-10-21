//! SET_INFO handler.

use std::sync::Arc;

use crate::proto::header::Smb2Header;
use crate::proto::messages::{InfoType, SetInfoRequest, SetInfoResponse};

use crate::access_mask::{DELETE, FILE_WRITE_ATTRIBUTES, FILE_WRITE_DATA};
use crate::backend::{
    FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_TEMPORARY, FileTimes, VALID_SET_ATTRIBUTES,
};
use crate::conn::pending::{Stop, stopped};
use crate::conn::state::{Connection, Open};
use crate::dispatch::HandlerResponse;
use crate::files::{BreakWait, MAX_BREAK_WAIT, Trigger};
use crate::handlers::shared::{lookup_open, lookup_session_tree, restore_fixed_times};
use crate::handlers::{Outcome, Pending};
use crate::info_class as ic;
use crate::ntstatus;
use crate::path::{SmbPath, same_path};
use crate::proto::messages::FileId;
use crate::server::ServerState;
use crate::utils::utf16le_to_units;
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
            let mut open = open_arc.write().await;
            set_basic_info(&mut open, times, attributes).await
        }
        Class::EndOfFile => {
            if buffer.len() < 8 {
                return Ok(HandlerResponse::err(ntstatus::STATUS_INFO_LENGTH_MISMATCH));
            }
            let new_len = u64::from_le_bytes(buffer[0..8].try_into().unwrap());
            let open = open_arc.read().await;
            truncate(&open, new_len, false).await
        }
        Class::Allocation => {
            if buffer.len() < 8 {
                return Ok(HandlerResponse::err(ntstatus::STATUS_INFO_LENGTH_MISMATCH));
            }
            let size = u64::from_le_bytes(buffer[0..8].try_into().unwrap());
            let open = open_arc.read().await;
            truncate(&open, size, true).await
        }
        Class::Disposition => {
            if buffer.is_empty() {
                return Ok(HandlerResponse::err(ntstatus::STATUS_INFO_LENGTH_MISMATCH));
            }
            let open = open_arc.read().await;
            set_disposition(&open, buffer[0] != 0).await
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

/// FileRenameInformation (MS-FSA 2.1.5.15.12). An open target is not
/// replaced; when it is open only because clients cache their handles, the
/// first attempt breaks that caching and waits. The leases on the renamed
/// file give up handle caching, as do those on files open below a renamed
/// directory.
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
    let _renames = share.files.rename_lock().await;
    let open = open_arc.read().await;
    let Some(file) = open.file.as_ref() else {
        return Renamed::Done(Err(ntstatus::STATUS_FILE_CLOSED));
    };
    let from = file.path();
    let to = &rename.to;
    // A target that names the source itself is the same file and skips
    // this.
    if rename.replace
        && !same_path(&from, to, case_sensitive)
        && share.files.path_is_open(to, case_sensitive)
    {
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
    if open.is_directory {
        share.files.break_handles_below(&from, case_sensitive);
    }
    drop(open);
    let result = match share.backend.rename(&from, to, rename.replace).await {
        Ok(()) => {
            share.files.rename_paths(&from, to, case_sensitive);
            Ok(())
        }
        Err(e) => Err(e.to_nt_status()),
    };
    Renamed::Done(result)
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
    if allocation {
        let info = handle.stat().await.map_err(|e| e.to_nt_status())?;
        if size >= info.end_of_file {
            return Ok(());
        }
    }
    let result = handle.truncate(size).await;
    break_leases();
    result.map_err(|e| e.to_nt_status())?;
    restore_fixed_times(open).await;
    Ok(())
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
    Ok(())
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
            inner: MemFsBackend::new().with_file("d\\f", b"x"),
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
        for (path, directory) in [("d\\f", false), ("d", true)] {
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
        let parent = rename(file_ids[1], "e");
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
        assert_eq!(parent.await.unwrap(), ntstatus::STATUS_SUCCESS);
        assert!(share.files.path_is_open(&"e\\g".parse().unwrap(), false));
    }
}
