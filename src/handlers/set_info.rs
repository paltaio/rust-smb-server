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
use crate::handlers::shared::{lookup_open, lookup_session_tree, restore_fixed_times};
use crate::info_class as ic;
use crate::ntstatus;
use crate::path::{SmbPath, same_path};
use crate::server::ServerState;
use crate::utils::utf16le_to_units;

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
) -> HandlerResponse {
    let req = match SetInfoRequest::parse(body) {
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
    if req.buffer_length == 0 {
        return HandlerResponse::err(ntstatus::STATUS_INVALID_PARAMETER);
    }
    let info_type = match InfoType::from_u8(req.info_type) {
        Some(t) => t,
        None => return HandlerResponse::err(ntstatus::STATUS_INVALID_INFO_CLASS),
    };
    if !matches!(info_type, InfoType::File) {
        return HandlerResponse::err(ntstatus::STATUS_NOT_SUPPORTED);
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
            return HandlerResponse::err(ntstatus::STATUS_NOT_SUPPORTED);
        }
        _ => return HandlerResponse::err(ntstatus::STATUS_INVALID_INFO_CLASS),
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
            let open = open_arc.read().await;
            set_disposition(&open, buffer[0] != 0).await
        }
        Class::Rename => {
            // FILE_RENAME_INFORMATION layout (MS-FSCC §2.4.37):
            //   ReplaceIfExists (1) | Reserved (7) | RootDirectory (8) | FileNameLength (4) | FileName...
            if buffer.len() < 20 {
                return HandlerResponse::err(ntstatus::STATUS_INFO_LENGTH_MISMATCH);
            }
            if buffer[8..16] != [0; 8] {
                return HandlerResponse::err(ntstatus::STATUS_INVALID_PARAMETER);
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
                return HandlerResponse::err(ntstatus::STATUS_INFO_LENGTH_MISMATCH);
            };
            let units = match utf16le_to_units(name_bytes) {
                Some(u) => u,
                None => return HandlerResponse::err(ntstatus::STATUS_OBJECT_NAME_INVALID),
            };
            let new_path = match SmbPath::from_utf16(&units) {
                Ok(p) => p,
                Err(_) => return HandlerResponse::err(ntstatus::STATUS_OBJECT_NAME_INVALID),
            };
            let replace_if_exists = buffer[0] != 0;
            let case_sensitive = share.backend.capabilities().case_sensitive;
            let _renames = share.files.rename_lock().await;
            let Some(from) = open_arc.read().await.path() else {
                return HandlerResponse::err(ntstatus::STATUS_FILE_CLOSED);
            };
            // MS-FSA 2.1.5.15.12: an open target is not replaced. A target
            // that names the source itself is the same file and skips this.
            if replace_if_exists
                && !same_path(&from, &new_path, case_sensitive)
                && share.files.path_is_open(&new_path, case_sensitive)
            {
                return HandlerResponse::err(ntstatus::STATUS_ACCESS_DENIED);
            }
            match share
                .backend
                .rename(&from, &new_path, replace_if_exists)
                .await
            {
                Ok(()) => {
                    share.files.rename_paths(&from, &new_path, case_sensitive);
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
            let file = FileRef::register(&share, &info, &path, sharing).unwrap();
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
            tokio::spawn(async move { handle(&state, &conn, &hdr, &body).await })
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
        assert_eq!(file.await.unwrap().status, ntstatus::STATUS_SUCCESS);
        assert_eq!(parent.await.unwrap().status, ntstatus::STATUS_SUCCESS);
        assert!(share.files.path_is_open(&"e\\g".parse().unwrap(), false));
    }
}
