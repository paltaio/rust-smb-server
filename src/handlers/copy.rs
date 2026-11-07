//! FSCTL_SRV_REQUEST_RESUME_KEY (MS-SMB2 3.3.5.15.5) and the server-side
//! copy requests FSCTL_SRV_COPYCHUNK and FSCTL_SRV_COPYCHUNK_WRITE (MS-SMB2
//! 3.3.5.15.6). A copy reads the open a resume key names and writes the
//! open the request is on, chunk by chunk, before it answers.

use std::sync::Arc;
use std::sync::atomic::Ordering;

use tokio::sync::{RwLock, RwLockReadGuard};

use crate::access_mask::{FILE_APPEND_DATA, FILE_READ_DATA, FILE_WRITE_DATA};
use crate::backend::{Handle, ShareBackend};
use crate::conn::state::{Connection, Open};
use crate::dispatch::HandlerResponse;
use crate::error::SmbError;
use crate::files::{FileRef, Trigger};
use crate::handlers::create::WRITE_THROUGH_OPTIONS;
use crate::handlers::ioctl::response;
use crate::handlers::shared::{lookup_session, restore_fixed_times};
use crate::ntstatus;
use crate::proto::messages::copychunk::{
    Chunk, CopychunkRequest, CopychunkResponse, RESUME_KEY_LEN, ResumeKeyResponse, resume_key,
    resume_key_file_id,
};
use crate::proto::messages::{FileId, Fsctl, IoctlRequest};
use crate::server::{ServerState, ShareBindings};
use crate::stream::stream_error;

/// How a copy request ended short of its last chunk: the status, and the
/// bytes of the chunk it stopped in that were written.
#[derive(Debug, Clone, Copy)]
struct Failure {
    status: u32,
    partial: u32,
}

impl Failure {
    /// A failure after `written` bytes of its chunk.
    fn after(status: u32, written: u64) -> Self {
        Self {
            status,
            // A chunk has at most 1 MiB.
            partial: written as u32,
        }
    }
}

/// The status of a copy request on a share that does not serve copies.
/// After STATUS_NOT_SUPPORTED on a named stream macOS keeps an extended
/// attribute in a `._` file instead.
fn refusal(on_stream: bool) -> u32 {
    if on_stream {
        ntstatus::STATUS_INVALID_DEVICE_REQUEST
    } else {
        ntstatus::STATUS_NOT_SUPPORTED
    }
}

/// An IOCTL response with `status` that carries a SRV_COPYCHUNK_RESPONSE.
fn copy_response(
    req: &IoctlRequest,
    file_id: FileId,
    status: u32,
    counts: CopychunkResponse,
) -> HandlerResponse {
    let mut answer = response(req.ctl_code, file_id, counts.encode());
    answer.status = status;
    answer
}

/// Read guards on the source and the target open of a copy. Taken in
/// address order: two copies in opposite directions would otherwise deadlock
/// behind a queued writer. One guard when both are the same open.
struct Guards<'a> {
    source: RwLockReadGuard<'a, Open>,
    /// `None` when the target is the source.
    target: Option<RwLockReadGuard<'a, Open>>,
}

impl<'a> Guards<'a> {
    async fn take(source: &'a Arc<RwLock<Open>>, target: &'a Arc<RwLock<Open>>) -> Self {
        if Arc::ptr_eq(source, target) {
            return Self {
                source: source.read().await,
                target: None,
            };
        }
        let (source, target) = if Arc::as_ptr(source) < Arc::as_ptr(target) {
            let source = source.read().await;
            let target = target.read().await;
            (source, target)
        } else {
            let target = target.read().await;
            let source = source.read().await;
            (source, target)
        };
        Self {
            source,
            target: Some(target),
        }
    }

    fn source(&self) -> &Open {
        &self.source
    }

    fn target(&self) -> &Open {
        self.target.as_deref().unwrap_or(&self.source)
    }
}

/// Answers a request of one of the three FSCTLs on `target`, an open of
/// the file share `share`.
pub(super) async fn handle(
    server: &Arc<ServerState>,
    conn: &Arc<Connection>,
    session_id: u64,
    share: &Arc<ShareBindings>,
    target: &Arc<RwLock<Open>>,
    req: &IoctlRequest,
    input: &[u8],
) -> HandlerResponse {
    let open = target.read().await;
    let (file_id, on_stream) = (open.file_id, open.on_stream);
    if !share.server_side_copy {
        return HandlerResponse::err(refusal(on_stream));
    }
    if req.fsctl() == Fsctl::SrvRequestResumeKey {
        return request_resume_key(server, req, &open);
    }
    drop(open);

    let parsed = CopychunkRequest::parse(input);
    let key = match &parsed {
        Ok(request) => Some(request.source_key),
        Err(over) => over.source_key,
    };
    let mut source = None;
    if let Some(key) = key {
        let Some(found) = find_source(server, conn, session_id, &key).await else {
            return HandlerResponse::err(ntstatus::STATUS_OBJECT_NAME_NOT_FOUND);
        };
        source = Some(found);
    }
    if let Some((source_share, _)) = &source
        && !source_share.server_side_copy
    {
        return HandlerResponse::err(refusal(on_stream));
    }
    if req.max_output_response < CopychunkResponse::LEN as u32 {
        return HandlerResponse::err(ntstatus::STATUS_INVALID_PARAMETER);
    }
    let (Ok(request), Some((_, source))) = (parsed, source) else {
        return copy_response(
            req,
            file_id,
            ntstatus::STATUS_INVALID_PARAMETER,
            CopychunkResponse::LIMITS,
        );
    };
    if request.chunks.is_empty() {
        return copy_response(
            req,
            file_id,
            ntstatus::STATUS_SUCCESS,
            CopychunkResponse::ZERO,
        );
    }

    let guards = Guards::take(&source, target).await;
    copy(share, &guards, req, &request.chunks).await
}

/// MS-SMB2 3.3.5.15.5: the key names the open it is asked on, and holds the
/// server's tag.
fn request_resume_key(server: &ServerState, req: &IoctlRequest, open: &Open) -> HandlerResponse {
    if req.max_output_response < ResumeKeyResponse::LEN as u32 {
        return HandlerResponse::err(ntstatus::STATUS_INVALID_PARAMETER);
    }
    if open.handle.is_none() {
        return HandlerResponse::err(ntstatus::STATUS_FILE_CLOSED);
    }
    let key = resume_key(open.file_id, &server.resume_tag);
    response(
        req.ctl_code,
        open.file_id,
        ResumeKeyResponse { key }.encode(),
    )
}

/// The open `key` names among the opens of the session `session_id`, on
/// any of its trees, and the share it is on. A key made for another
/// server, another session, or an open that is closed names nothing.
async fn find_source(
    server: &ServerState,
    conn: &Arc<Connection>,
    session_id: u64,
    key: &[u8; RESUME_KEY_LEN],
) -> Option<(Arc<ShareBindings>, Arc<RwLock<Open>>)> {
    let file_id = resume_key_file_id(key, &server.resume_tag)?;
    let session = lookup_session(conn, session_id).await.ok()?;
    let trees: Vec<_> = session
        .read()
        .await
        .trees
        .read()
        .await
        .values()
        .cloned()
        .collect();
    for tree in trees {
        let tree = tree.read().await;
        if let Some(open) = tree.opens.read().await.get(&file_id) {
            return Some((Arc::clone(&tree.share), Arc::clone(open)));
        }
    }
    None
}

/// Copies `chunks` from the source to the target in order and answers with
/// how far it got (MS-SMB2 3.3.5.15.6).
async fn copy(
    share: &ShareBindings,
    guards: &Guards<'_>,
    req: &IoctlRequest,
    chunks: &[Chunk],
) -> HandlerResponse {
    let (source, target) = (guards.source(), guards.target());
    if source.is_directory
        || target.is_directory
        || source.granted_access & FILE_READ_DATA == 0
        || target.granted_access & (FILE_WRITE_DATA | FILE_APPEND_DATA) == 0
        || (req.fsctl() == Fsctl::SrvCopychunk && target.granted_access & FILE_READ_DATA == 0)
    {
        return HandlerResponse::err(ntstatus::STATUS_ACCESS_DENIED);
    }
    let (Some(source_handle), Some(source_file)) = (source.handle.as_deref(), source.file.as_ref())
    else {
        return HandlerResponse::err(ntstatus::STATUS_OBJECT_NAME_NOT_FOUND);
    };
    let (Some(target_handle), Some(target_file)) = (target.handle.as_deref(), target.file.as_ref())
    else {
        return HandlerResponse::err(ntstatus::STATUS_FILE_CLOSED);
    };
    let ends = Ends {
        source: source_handle,
        source_file,
        target: target_handle,
        target_file,
        backend: share.backend.as_ref(),
        on_stream: target.on_stream,
    };

    if chunks.iter().any(|chunk| ends.check_locks(chunk).is_err()) {
        return copy_response(
            req,
            target.file_id,
            ntstatus::STATUS_FILE_LOCK_CONFLICT,
            CopychunkResponse::ZERO,
        );
    }
    target_file.break_leases(Trigger::Write);

    let mut copied = 0u32;
    let mut bytes = 0u32;
    let mut failure = None;
    for chunk in chunks {
        match ends.copy_chunk(chunk).await {
            Ok(()) => {
                copied += 1;
                bytes += chunk.length;
            }
            Err(f) => {
                failure = Some(f);
                break;
            }
        }
    }
    let partial = failure.map_or(0, |f| f.partial);
    let written = bytes + partial;
    if written > 0 {
        target.wrote.store(true, Ordering::Release);
    }
    // Breaks a lease granted while the copy ran.
    target_file.break_leases(Trigger::Write);
    let mut status = failure.map_or(ntstatus::STATUS_SUCCESS, |f| f.status);
    if status == ntstatus::STATUS_SUCCESS
        && target.create_options & WRITE_THROUGH_OPTIONS != 0
        && let Err(e) = target_handle.flush().await
    {
        status = ends.status_of(e);
    }
    if written > 0 {
        restore_fixed_times(target).await;
    }
    copy_response(
        req,
        target.file_id,
        status,
        CopychunkResponse {
            chunks_written: copied,
            chunk_bytes_written: partial,
            total_bytes_written: written,
        },
    )
}

/// The two sides of a copy.
struct Ends<'a> {
    source: &'a dyn Handle,
    source_file: &'a FileRef,
    target: &'a dyn Handle,
    target_file: &'a FileRef,
    /// The backend of the share the target is on.
    backend: &'a dyn ShareBackend,
    /// The target is a named stream.
    on_stream: bool,
}

impl Ends<'_> {
    /// The status for a backend error. A request on a named stream never
    /// answers STATUS_NOT_SUPPORTED, and no copy answers
    /// STATUS_INVALID_PARAMETER with a body, which a client reads as the
    /// limits.
    fn status_of(&self, error: SmbError) -> u32 {
        let error = if self.on_stream {
            stream_error(error)
        } else {
            error
        };
        match error.to_nt_status() {
            ntstatus::STATUS_INVALID_PARAMETER => ntstatus::STATUS_INVALID_DEVICE_REQUEST,
            status => status,
        }
    }

    /// A failure after `written` bytes of its chunk, caused by `error`.
    fn failure(&self, error: SmbError, written: u64) -> Failure {
        Failure::after(self.status_of(error), written)
    }

    /// Fails with STATUS_FILE_LOCK_CONFLICT when a byte-range lock of
    /// another open stops the read of the chunk's source range or the write
    /// of its target range. The opens' own locks never do (MS-FSA 2.1.4.10).
    fn check_locks(&self, chunk: &Chunk) -> Result<(), u32> {
        let length = u64::from(chunk.length);
        self.source_file
            .check_io(chunk.source_offset, length, false)?;
        self.target_file.check_io(chunk.target_offset, length, true)
    }

    /// Copies one chunk. The source range has to lie inside the source;
    /// STATUS_INVALID_VIEW_SIZE otherwise, with nothing written.
    async fn copy_chunk(&self, chunk: &Chunk) -> Result<(), Failure> {
        let size = self
            .source
            .stat()
            .await
            .map_err(|e| self.failure(e, 0))?
            .end_of_file;
        let Some(source_end) = chunk.source_end().filter(|&end| end <= size) else {
            return Err(Failure::after(ntstatus::STATUS_INVALID_VIEW_SIZE, 0));
        };
        let Some(target_end) = chunk.target_end() else {
            return Err(Failure::after(ntstatus::STATUS_INVALID_DEVICE_REQUEST, 0));
        };
        // A lock can be taken while earlier chunks copy.
        self.check_locks(chunk)
            .map_err(|status| Failure::after(status, 0))?;

        let length = u64::from(chunk.length);
        let overlaps = self.source_file.same_data_as(self.target_file)
            && chunk.source_offset < target_end
            && chunk.target_offset < source_end;
        let mut done = 0;
        if !overlaps {
            match self
                .backend
                .copy_range(
                    self.source,
                    chunk.source_offset,
                    self.target,
                    chunk.target_offset,
                    length,
                )
                .await
            {
                Ok(n) => done = n.min(length),
                Err(SmbError::NotSupported | SmbError::NotSameDevice) => {}
                Err(e) => return Err(self.failure(e, 0)),
            }
        }
        if done < length {
            self.read_write(chunk, done).await?;
        }
        Ok(())
    }

    /// Copies the chunk from byte `done` on, reading all of it before
    /// writing any of it.
    async fn read_write(&self, chunk: &Chunk, done: u64) -> Result<(), Failure> {
        let data = self.read_rest(chunk, done).await?;
        let mut written = 0;
        while written < data.len() {
            let copied = done + written as u64;
            // The ends of both ranges were checked not to pass u64::MAX.
            let n = self
                .target
                .write(chunk.target_offset + copied, &data[written..])
                .await
                .map_err(|e| self.failure(e, copied))?;
            if n == 0 {
                return Err(Failure::after(ntstatus::STATUS_UNEXPECTED_IO_ERROR, copied));
            }
            written += n as usize;
        }
        Ok(())
    }

    /// Reads the bytes of the chunk from byte `done` on, all of them.
    async fn read_rest(&self, chunk: &Chunk, done: u64) -> Result<Vec<u8>, Failure> {
        let source_at = chunk.source_offset + done;
        let length = (u64::from(chunk.length) - done) as usize;
        let mut data = Vec::with_capacity(length);
        while data.len() < length {
            let want = (length - data.len()) as u32;
            let part = self
                .source
                .read(source_at + data.len() as u64, want)
                .await
                .map_err(|e| self.failure(e, done))?;
            if part.is_empty() {
                return Err(Failure::after(ntstatus::STATUS_INVALID_VIEW_SIZE, done));
            }
            data.extend_from_slice(&part[..part.len().min(want as usize)]);
        }
        Ok(data)
    }
}
