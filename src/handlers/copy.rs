//! FSCTL_SRV_REQUEST_RESUME_KEY (MS-SMB2 3.3.5.15.5) and the server-side
//! copy requests FSCTL_SRV_COPYCHUNK and FSCTL_SRV_COPYCHUNK_WRITE (MS-SMB2
//! 3.3.5.15.6). A copy reads the open a resume key names and writes the
//! open the request is on, chunk by chunk, before it answers.
//!
//! A request without chunks from a connection offered Apple's whole-file
//! copy copies the file and its named streams, and answers when it is done.
//!
//! FSCTL_DUPLICATE_EXTENTS_TO_FILE shares the storage of a range of one file
//! with another instead of copying it.

use std::sync::Arc;
use std::sync::atomic::Ordering;

use tokio::sync::{RwLock, RwLockReadGuard};

use crate::access_mask::{FILE_APPEND_DATA, FILE_READ_DATA, FILE_WRITE_DATA};
use crate::backend::{Handle, ShareBackend};
use crate::conn::state::{Connection, Open, TreeConnect};
use crate::dispatch::HandlerResponse;
use crate::error::SmbError;
use crate::files::{FileRef, Trigger};
use crate::handlers::Outcome;
use crate::handlers::create::WRITE_THROUGH_OPTIONS;
use crate::handlers::ioctl::response;
use crate::handlers::shared::{lookup_session, restore_fixed_times};
use crate::ntstatus;
use crate::proto::header::Smb2Header;
use crate::proto::messages::copychunk::{
    Chunk, CopychunkRequest, CopychunkResponse, RESUME_KEY_LEN, ResumeKeyResponse, resume_key,
    resume_key_file_id,
};
use crate::proto::messages::{FileId, Fsctl, IoctlRequest};
use crate::server::{ServerState, ShareBindings};

mod duplicate;
mod whole_file;

pub(super) use duplicate::{duplicate_extents, set_sparse};

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

/// The answer to a copy request on a share that does not serve copies. A
/// request on a named stream (`on_stream`) gets
/// STATUS_INVALID_DEVICE_REQUEST, because after STATUS_NOT_SUPPORTED macOS
/// keeps an extended attribute in a `._` file instead. A whole-file copy
/// request (`whole_file`) on a file gets STATUS_ACCESS_DENIED.
fn refused(whole_file: bool, on_stream: bool) -> Outcome {
    let status = match (whole_file, on_stream) {
        (_, true) => ntstatus::STATUS_INVALID_DEVICE_REQUEST,
        (true, false) => ntstatus::STATUS_ACCESS_DENIED,
        (false, false) => ntstatus::STATUS_NOT_SUPPORTED,
    };
    Outcome::Done(HandlerResponse::err(status))
}

/// The status a copy request answers for a step that failed with `status`.
/// A request on a named stream (`on_stream`) never answers
/// STATUS_NOT_SUPPORTED, and no copy answers STATUS_INVALID_PARAMETER with a
/// body, which a client reads as the limits.
fn reply_status(status: u32, on_stream: bool) -> u32 {
    match status {
        ntstatus::STATUS_INVALID_PARAMETER => ntstatus::STATUS_INVALID_DEVICE_REQUEST,
        ntstatus::STATUS_NOT_SUPPORTED if on_stream => ntstatus::STATUS_ACCESS_DENIED,
        status => status,
    }
}

/// An IOCTL response with `status` that carries a SRV_COPYCHUNK_RESPONSE.
fn copy_response(
    ctl_code: u32,
    file_id: FileId,
    status: u32,
    counts: CopychunkResponse,
) -> HandlerResponse {
    let mut answer = response(ctl_code, file_id, counts.encode());
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

    /// The two sides of a copy from the source to the target, which is on
    /// `share`. Fails with the status a request on a closed open gets when
    /// one of them has no handle.
    fn ends<'s>(&'s self, share: &'s ShareBindings) -> Result<Ends<'s>, u32> {
        let (source, target) = (self.source(), self.target());
        let (Some(source_handle), Some(source_file)) =
            (source.handle.as_deref(), source.file.as_ref())
        else {
            return Err(ntstatus::STATUS_OBJECT_NAME_NOT_FOUND);
        };
        let (Some(target_handle), Some(target_file)) =
            (target.handle.as_deref(), target.file.as_ref())
        else {
            return Err(ntstatus::STATUS_FILE_CLOSED);
        };
        Ok(Ends {
            source: source_handle,
            source_file,
            target: target_handle,
            target_file,
            backend: share.backend.as_ref(),
            on_stream: target.on_stream,
        })
    }
}

/// An IOCTL request for one of the copy or duplicate-extents FSCTLs, as the
/// IOCTL handler read it.
pub(super) struct Call<'a> {
    pub hdr: &'a Smb2Header,
    pub req: &'a IoctlRequest,
    pub input: &'a [u8],
    /// Bytes of the request frame a request that goes asynchronous keeps
    /// until it completes.
    pub retained: usize,
}

/// An open of a copy, with the share and the tree it is on.
struct Side {
    tree_id: u32,
    share: Arc<ShareBindings>,
    open: Arc<RwLock<Open>>,
}

/// Answers FSCTL_SRV_REQUEST_RESUME_KEY, FSCTL_SRV_COPYCHUNK or
/// FSCTL_SRV_COPYCHUNK_WRITE on `target`, an open of a file share on `tree`.
pub(super) async fn handle(
    server: &Arc<ServerState>,
    conn: &Arc<Connection>,
    call: &Call<'_>,
    tree: &Arc<RwLock<TreeConnect>>,
    target: &Arc<RwLock<Open>>,
) -> Outcome {
    let Call {
        hdr, req, input, ..
    } = *call;
    let (tree_id, share) = {
        let tree = tree.read().await;
        (tree.id, Arc::clone(&tree.share))
    };
    let open = target.read().await;
    let (file_id, on_stream) = (open.file_id, open.on_stream);
    if req.fsctl() == Fsctl::SrvRequestResumeKey {
        if !share.server_side_copy {
            return refused(false, on_stream);
        }
        return Outcome::Done(request_resume_key(server, req, &open));
    }
    drop(open);

    let parsed = CopychunkRequest::parse(input);
    let whole_file = conn.aapl_copyfile.load(Ordering::Acquire)
        && parsed
            .as_ref()
            .is_ok_and(|request| request.chunks.is_empty());
    if !share.server_side_copy {
        return refused(whole_file, on_stream);
    }
    let key = match &parsed {
        Ok(request) => Some(request.source_key),
        Err(over) => over.source_key,
    };
    let source = match key {
        Some(key) => match find_source(server, conn, hdr.session_id, &key).await {
            Some(found) => Some(found),
            None => {
                return Outcome::Done(HandlerResponse::err(ntstatus::STATUS_OBJECT_NAME_NOT_FOUND));
            }
        },
        None => None,
    };
    if let Some(source) = &source
        && !source.share.server_side_copy
    {
        return refused(whole_file, on_stream);
    }
    if req.max_output_response < CopychunkResponse::LEN as u32 {
        return Outcome::Done(HandlerResponse::err(ntstatus::STATUS_INVALID_PARAMETER));
    }
    let (Ok(request), Some(source)) = (parsed, source) else {
        return Outcome::Done(copy_response(
            req.ctl_code,
            file_id,
            ntstatus::STATUS_INVALID_PARAMETER,
            CopychunkResponse::LIMITS,
        ));
    };
    if request.chunks.is_empty() {
        if whole_file {
            let target = Side {
                tree_id,
                share,
                open: Arc::clone(target),
            };
            return whole_file::start(server, conn, call, request.source_key, source, target).await;
        }
        return Outcome::Done(copy_response(
            req.ctl_code,
            file_id,
            ntstatus::STATUS_SUCCESS,
            CopychunkResponse::ZERO,
        ));
    }

    let guards = Guards::take(&source.open, target).await;
    Outcome::Done(copy(&share, &guards, req, &request.chunks).await)
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
/// any of its trees, with its share. A key made for another server,
/// another session, or an open that is closed names nothing.
async fn find_source(
    server: &ServerState,
    conn: &Arc<Connection>,
    session_id: u64,
    key: &[u8; RESUME_KEY_LEN],
) -> Option<Side> {
    let file_id = resume_key_file_id(key, &server.resume_tag)?;
    find_open(conn, session_id, file_id).await
}

/// The open `file_id` among the opens of the session `session_id`, on any
/// of its trees, with its share.
async fn find_open(conn: &Arc<Connection>, session_id: u64, file_id: FileId) -> Option<Side> {
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
            return Some(Side {
                tree_id: tree.id,
                share: Arc::clone(&tree.share),
                open: Arc::clone(open),
            });
        }
    }
    None
}

/// Whether `source` and `target` may take part in the copy FSCTL `code`:
/// files, the source open for reading and the target for writing, and for
/// FSCTL_SRV_COPYCHUNK the target also open for reading.
fn permitted(code: Fsctl, source: &Open, target: &Open) -> bool {
    !(source.is_directory
        || target.is_directory
        || source.granted_access & FILE_READ_DATA == 0
        || target.granted_access & (FILE_WRITE_DATA | FILE_APPEND_DATA) == 0
        || (code == Fsctl::SrvCopychunk && target.granted_access & FILE_READ_DATA == 0))
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
    if !permitted(req.fsctl(), source, target) {
        return HandlerResponse::err(ntstatus::STATUS_ACCESS_DENIED);
    }
    let ends = match guards.ends(share) {
        Ok(ends) => ends,
        Err(status) => return HandlerResponse::err(status),
    };

    if chunks.iter().any(|chunk| ends.check_locks(chunk).is_err()) {
        return copy_response(
            req.ctl_code,
            target.file_id,
            ntstatus::STATUS_FILE_LOCK_CONFLICT,
            CopychunkResponse::ZERO,
        );
    }

    let run = ends.copy_chunks(target, chunks).await;
    let mut status = run.failure.map_or(ntstatus::STATUS_SUCCESS, |f| f.status);
    if status == ntstatus::STATUS_SUCCESS
        && let Err(e) = ends.flush_write_through(target).await
    {
        status = ends.status_of(e);
    }
    if run.written() > 0 {
        restore_fixed_times(target).await;
    }
    copy_response(
        req.ctl_code,
        target.file_id,
        status,
        CopychunkResponse {
            chunks_written: run.chunks,
            chunk_bytes_written: run.partial(),
            total_bytes_written: run.written(),
        },
    )
}

/// How far a run of chunks got.
struct Run {
    /// Chunks copied whole.
    chunks: u32,
    /// Bytes of those chunks.
    bytes: u32,
    /// How it ended short of its last chunk.
    failure: Option<Failure>,
}

impl Run {
    /// Bytes of the chunk it stopped in that were written.
    fn partial(&self) -> u32 {
        self.failure.map_or(0, |f| f.partial)
    }

    /// Bytes written, including those written of the chunk it stopped in.
    fn written(&self) -> u32 {
        self.bytes + self.partial()
    }
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
    /// The status for a backend error, as [`reply_status`] gives it.
    fn status_of(&self, error: SmbError) -> u32 {
        reply_status(error.to_nt_status(), self.on_stream)
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

    /// Runs `change`, which writes the target, between two breaks of the
    /// leases on it. The second break catches a lease granted while `change`
    /// ran.
    async fn breaking_leases<T>(&self, change: impl Future<Output = T>) -> T {
        self.target_file.break_leases(Trigger::Write);
        let result = change.await;
        self.target_file.break_leases(Trigger::Write);
        result
    }

    /// Flushes the target when its open `target` asked for write-through.
    async fn flush_write_through(&self, target: &Open) -> Result<(), SmbError> {
        if target.create_options & WRITE_THROUGH_OPTIONS == 0 {
            return Ok(());
        }
        self.target.flush().await
    }

    /// Copies `chunks` in order up to the first that fails. The leases on
    /// the target break before the first chunk and again after the last,
    /// and the open `target` is marked written once any byte is written.
    async fn copy_chunks(&self, target: &Open, chunks: &[Chunk]) -> Run {
        let run = self
            .breaking_leases(async {
                let mut run = Run {
                    chunks: 0,
                    bytes: 0,
                    failure: None,
                };
                for chunk in chunks {
                    match self.copy_chunk(chunk).await {
                        Ok(()) => {
                            run.chunks += 1;
                            run.bytes += chunk.length;
                        }
                        Err(failure) => {
                            run.failure = Some(failure);
                            break;
                        }
                    }
                }
                run
            })
            .await;
        if run.written() > 0 {
            target.wrote.store(true, Ordering::Release);
        }
        run
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
