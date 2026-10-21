//! Commands on IPC$, whose opens are named pipes. CREATE opens a pipe
//! (MS-SMB2 3.3.5.9); WRITE, READ and FSCTL_PIPE_TRANSCEIVE move DCE/RPC
//! PDUs through it (MS-SMB2 3.3.5.12, 3.3.5.13, 3.3.5.15.3); the other
//! commands that name a pipe get the answers a pipe gives.

use std::collections::HashMap;
use std::sync::atomic::Ordering;
use std::sync::{Arc, MutexGuard, PoisonError};

use tokio::sync::RwLock;
use tracing::{debug, warn};

use crate::access_mask::{FILE_APPEND_DATA, FILE_READ_DATA, FILE_WRITE_DATA, granted_access};
use crate::conn::pending::{Stop, stopped};
use crate::conn::state::{Connection, TreeConnect};
use crate::dispatch::HandlerResponse;
use crate::files::OpenSlot;
use crate::handlers::create::FILE_OPENED;
use crate::handlers::shared::{channel_is_valid, lookup_session_tree};
use crate::handlers::{Outcome, Pending, ioctl, query_info};
use crate::info_class::FILE_STANDARD_INFORMATION;
use crate::ntstatus;
use crate::proto::header::{Command, Smb2Header};
use crate::proto::messages::{
    ChangeNotifyRequest, CloseRequest, CloseResponse, CreateContext, CreateRequest, CreateResponse,
    Dialect, FileId, FlushRequest, FlushResponse, Fsctl, InfoType, IoctlRequest, LockRequest,
    QueryDirectoryRequest, QueryInfoRequest, QueryInfoResponse, ReadRequest, ReadResponse,
    SetInfoRequest, WriteRequest, WriteResponse,
};
use crate::rpc::SRVSVC_PIPE;
use crate::rpc::pipe::{MAX_PIPES_PER_CONNECTION, Pipe, Read};
use crate::server::ServerState;
use crate::utils::utf16le_to_units;

/// The access a pipe open may hold: FILE_GENERIC_READ | FILE_GENERIC_WRITE.
const PIPE_ACCESS: u32 = 0x0012_019F;

/// ImpersonationLevel Delegate.
const IMPERSONATION_DELEGATE: u32 = 3;

/// AllocationSize a pipe reports.
const PIPE_ALLOCATION_SIZE: u64 = 4096;

const FILE_ATTRIBUTE_NORMAL: u32 = 0x0000_0080;

/// Largest DataOffset of a WRITE that carries its data inline (MS-SMB2
/// 3.3.5.13).
const MAX_DATA_OFFSET: u16 = 0x100;

/// Locks the pipe table of a tree.
pub(crate) fn pipes(tree: &TreeConnect) -> MutexGuard<'_, HashMap<FileId, Arc<Pipe>>> {
    tree.pipes.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Handles the request when it targets IPC$: a CREATE, a command naming
/// one of the tree's pipes, or FSCTL_PIPE_WAIT. Returns `None` for every
/// other request, which the command's own handler then answers: one whose
/// session or tree is not found, whose FileId names no pipe, or, except
/// for a CREATE, whose body does not parse.
pub(crate) async fn route(
    server: &Arc<ServerState>,
    conn: &Arc<Connection>,
    hdr: &Smb2Header,
    body: &[u8],
    retained: usize,
) -> Option<Outcome> {
    if !matches!(
        hdr.command,
        Command::Create
            | Command::Read
            | Command::Write
            | Command::Ioctl
            | Command::QueryInfo
            | Command::SetInfo
            | Command::Close
            | Command::Flush
            | Command::Lock
            | Command::QueryDirectory
            | Command::ChangeNotify
    ) {
        return None;
    }
    let tree = lookup_session_tree(conn, hdr).await.ok()?;
    if !tree.read().await.share.is_ipc {
        return None;
    }
    let response = match hdr.command {
        Command::Create => create(server, conn, &tree, body).await,
        Command::Read => {
            let req = ReadRequest::parse(body).ok()?;
            let pipe = find(&tree, req.file_id).await?;
            return Some(read(conn, hdr, pipe, &req, retained).await);
        }
        Command::Write => {
            let req = WriteRequest::parse(body).ok()?;
            write(conn, find(&tree, req.file_id).await?, &req).await
        }
        Command::Ioctl => {
            let req = IoctlRequest::parse(body).ok()?;
            if ioctl::takes_no_file(req.fsctl()) {
                if req.fsctl() != Fsctl::PipeWait || req.file_id != FileId::any() {
                    return None;
                }
                pipe_wait(conn, &req, body).await
            } else {
                let pipe = find(&tree, req.file_id).await?;
                return Some(fsctl(conn, hdr, pipe, &req, body, retained).await);
            }
        }
        Command::QueryInfo => {
            let req = QueryInfoRequest::parse(body).ok()?;
            find(&tree, req.file_id).await?;
            query_pipe_info(conn, &req).await
        }
        Command::SetInfo => {
            let req = SetInfoRequest::parse(body).ok()?;
            find(&tree, req.file_id).await?;
            HandlerResponse::err(ntstatus::STATUS_NOT_SUPPORTED)
        }
        Command::Close => {
            let req = CloseRequest::parse(body).ok()?;
            close(conn, &tree, req.file_id).await?
        }
        Command::Flush => {
            let req = FlushRequest::parse(body).ok()?;
            let file_id = FileId::new(req.file_id_persistent, req.file_id_volatile);
            find(&tree, file_id).await?;
            // Every WRITE is consumed before it completes, so nothing is
            // left to wait for (MS-SMB2 3.3.5.11).
            let mut buf = Vec::new();
            FlushResponse::default().write_to(&mut buf).expect("encode");
            HandlerResponse::ok(buf)
        }
        Command::Lock => {
            let req = LockRequest::parse(body).ok()?;
            find(&tree, req.file_id).await?;
            HandlerResponse::err(ntstatus::STATUS_NOT_SUPPORTED)
        }
        // A pipe is not a directory (MS-SMB2 3.3.5.18, 3.3.5.19).
        Command::QueryDirectory => {
            let req = QueryDirectoryRequest::parse(body).ok()?;
            find(&tree, req.file_id).await?;
            HandlerResponse::err(ntstatus::STATUS_INVALID_PARAMETER)
        }
        Command::ChangeNotify => {
            let req = ChangeNotifyRequest::parse(body).ok()?;
            find(&tree, req.file_id).await?;
            HandlerResponse::err(ntstatus::STATUS_INVALID_PARAMETER)
        }
        _ => return None,
    };
    Some(Outcome::Done(response))
}

async fn find(tree: &Arc<RwLock<TreeConnect>>, file_id: FileId) -> Option<Arc<Pipe>> {
    pipes(&*tree.read().await).get(&file_id).cloned()
}

/// MS-SMB2 3.3.5.9 for a pipe. Every open is a new instance of the pipe;
/// only `srvsvc`, compared ignoring ASCII case, exists. FileAttributes,
/// ShareAccess and CreateDisposition are ignored, and so is every create
/// context but a durable handle reconnect, which names no pipe. The
/// response grants no oplock and carries no context.
async fn create(
    server: &Arc<ServerState>,
    conn: &Arc<Connection>,
    tree: &Arc<RwLock<TreeConnect>>,
    body: &[u8],
) -> HandlerResponse {
    let Ok(req) = CreateRequest::parse(body) else {
        return HandlerResponse::err(ntstatus::STATUS_INVALID_PARAMETER);
    };
    if req.impersonation_level == IMPERSONATION_DELEGATE {
        return HandlerResponse::err(ntstatus::STATUS_BAD_IMPERSONATION_LEVEL);
    }
    let Ok(contexts) = CreateContext::parse_chain(&req.create_contexts) else {
        return HandlerResponse::err(ntstatus::STATUS_INVALID_PARAMETER);
    };
    if contexts
        .iter()
        .any(|c| c.name == CreateContext::NAME_DHNC || c.name == CreateContext::NAME_DH2C)
    {
        return HandlerResponse::err(ntstatus::STATUS_OBJECT_NAME_NOT_FOUND);
    }
    let Some(units) = utf16le_to_units(&req.name) else {
        return HandlerResponse::err(ntstatus::STATUS_INVALID_PARAMETER);
    };
    let name = String::from_utf16_lossy(&units);
    if !name.eq_ignore_ascii_case(SRVSVC_PIPE) {
        debug!(name = %name, "no such pipe");
        return HandlerResponse::err(ntstatus::STATUS_OBJECT_NAME_NOT_FOUND);
    }
    let Some(access) = granted_access(req.desired_access, PIPE_ACCESS) else {
        debug!(desired = req.desired_access, "pipe access refused");
        return HandlerResponse::err(ntstatus::STATUS_ACCESS_DENIED);
    };
    let limit = server.max_opens_per_connection.load(Ordering::Relaxed);
    let Some(slot) = OpenSlot::acquire(&conn.open_count, limit) else {
        warn!(limit, "open limit reached");
        return HandlerResponse::err(ntstatus::STATUS_INSUFFICIENT_RESOURCES);
    };
    let tree = tree.write().await;
    if tree.closed {
        return HandlerResponse::err(ntstatus::STATUS_NETWORK_NAME_DELETED);
    }
    let file_id = tree.alloc_file_id();
    let Some(pipe) = Pipe::new(file_id, access, slot, &conn.pipe_budget) else {
        warn!(limit = MAX_PIPES_PER_CONNECTION, "pipe limit reached");
        return HandlerResponse::err(ntstatus::STATUS_INSUFFICIENT_RESOURCES);
    };
    pipes(&tree).insert(file_id, Arc::new(pipe));
    drop(tree);
    debug!(name = %name, ?file_id, "pipe opened");

    let resp = CreateResponse {
        structure_size: 89,
        oplock_level: 0,
        flags: 0,
        create_action: FILE_OPENED,
        creation_time: 0,
        last_access_time: 0,
        last_write_time: 0,
        change_time: 0,
        allocation_size: PIPE_ALLOCATION_SIZE,
        end_of_file: 0,
        file_attributes: FILE_ATTRIBUTE_NORMAL,
        reserved2: 0,
        file_id,
        create_contexts_offset: 0,
        create_contexts_length: 0,
        create_contexts: Vec::new(),
    };
    let mut buf = Vec::new();
    resp.write_to(&mut buf).expect("encode");
    HandlerResponse::ok(buf)
}

/// MS-SMB2 3.3.5.12 for a pipe. Offset and MinimumCount are ignored. A
/// READ on an empty pipe waits for a reply.
async fn read(
    conn: &Arc<Connection>,
    hdr: &Smb2Header,
    pipe: Arc<Pipe>,
    req: &ReadRequest,
    retained: usize,
) -> Outcome {
    let fail = |status| Outcome::Done(HandlerResponse::err(status));
    if pipe.granted_access & FILE_READ_DATA == 0 {
        return fail(ntstatus::STATUS_ACCESS_DENIED);
    }
    if req.length > *conn.max_read_size.read().await {
        return fail(ntstatus::STATUS_INVALID_PARAMETER);
    }
    let dialect = *conn.dialect.read().await;
    if matches!(dialect, Some(Dialect::Smb302 | Dialect::Smb311))
        && req.flags & ReadRequest::FLAG_READ_UNBUFFERED != 0
    {
        return fail(ntstatus::STATUS_INVALID_PARAMETER);
    }
    if !channel_is_valid(dialect, req.channel) {
        return fail(ntstatus::STATUS_INVALID_PARAMETER);
    }
    // A READ of 0 bytes succeeds once a message is there.
    let zero = req.length == 0;
    let answer = move |bytes: Vec<u8>, more: bool| read_response(bytes, more && !zero);
    let len = req.length as usize;
    match pipe.read(len).await {
        Read::Data { bytes, more } => Outcome::Done(answer(bytes, more)),
        Read::Disconnected => fail(ntstatus::STATUS_PIPE_DISCONNECTED),
        Read::Empty => wait(conn, hdr, pipe, len, retained, answer),
    }
}

/// A READ response with `bytes`, and STATUS_BUFFER_OVERFLOW when the
/// message has `more` (MS-SMB2 3.3.4.4).
fn read_response(bytes: Vec<u8>, more: bool) -> HandlerResponse {
    let resp = ReadResponse {
        structure_size: 17,
        data_offset: ReadResponse::STANDARD_DATA_OFFSET,
        reserved: 0,
        data_length: bytes.len() as u32,
        data_remaining: 0,
        flags: 0,
        data: bytes,
    };
    let mut buf = Vec::new();
    resp.write_to(&mut buf).expect("encode");
    overflowing(HandlerResponse::ok(buf), more)
}

fn overflowing(mut response: HandlerResponse, more: bool) -> HandlerResponse {
    if more {
        response.status = ntstatus::STATUS_BUFFER_OVERFLOW;
    }
    response
}

/// Answers once the pipe has a reply for this request, after the requests
/// that waited before it: `answer` gets up to `len` bytes of it and
/// whether the message has more. Until then the request waits
/// asynchronously. CANCEL ends it with STATUS_CANCELLED, a CLOSE of the
/// pipe with STATUS_PIPE_BROKEN, and the end of its tree or session with
/// the status a new request would get.
fn wait(
    conn: &Arc<Connection>,
    hdr: &Smb2Header,
    pipe: Arc<Pipe>,
    len: usize,
    retained: usize,
    answer: impl FnOnce(Vec<u8>, bool) -> HandlerResponse + Send + 'static,
) -> Outcome {
    let Some((op, mut stop)) = conn.pending.reserve(hdr, Some(pipe.file_id), retained) else {
        warn!("too many waiting requests on the connection");
        return Outcome::Done(HandlerResponse::err(
            ntstatus::STATUS_INSUFFICIENT_RESOURCES,
        ));
    };
    let (conn, hdr) = (Arc::clone(conn), *hdr);
    let work = async move {
        // A stop sent before the request was registered is missed; the
        // pipe, tree or session it was about is gone by now.
        if let Err(status) = still_open(&conn, &hdr, pipe.file_id).await {
            return HandlerResponse::err(status);
        }
        let read = pipe.read_waiting(len);
        tokio::pin!(read);
        loop {
            tokio::select! {
                biased;
                why = stopped(&mut stop) => {
                    if why == Stop::Cancelled {
                        return HandlerResponse::err(ntstatus::STATUS_CANCELLED);
                    }
                    if let Err(status) = still_open(&conn, &hdr, pipe.file_id).await {
                        return HandlerResponse::err(status);
                    }
                }
                read = &mut read => {
                    return match read {
                        Read::Data { bytes, more } => answer(bytes, more),
                        _ => HandlerResponse::err(ntstatus::STATUS_PIPE_DISCONNECTED),
                    };
                }
            }
        }
    };
    Outcome::Pending(Pending {
        op,
        work: Box::pin(work),
    })
}

/// Whether the pipe `file_id` is still open on the session and tree of
/// `hdr`: STATUS_PIPE_BROKEN once it is closed, or the status a new
/// request on the session or tree would fail with.
async fn still_open(conn: &Arc<Connection>, hdr: &Smb2Header, file_id: FileId) -> Result<(), u32> {
    let tree = lookup_session_tree(conn, hdr).await?;
    if find(&tree, file_id).await.is_none() {
        return Err(ntstatus::STATUS_PIPE_BROKEN);
    }
    Ok(())
}

/// MS-SMB2 3.3.5.13 for a pipe. Offset is ignored; every byte is taken.
async fn write(conn: &Arc<Connection>, pipe: Arc<Pipe>, req: &WriteRequest) -> HandlerResponse {
    if pipe.granted_access & (FILE_WRITE_DATA | FILE_APPEND_DATA) == 0 {
        return HandlerResponse::err(ntstatus::STATUS_ACCESS_DENIED);
    }
    if req.length > *conn.max_write_size.read().await {
        return HandlerResponse::err(ntstatus::STATUS_INVALID_PARAMETER);
    }
    let dialect = *conn.dialect.read().await;
    if !channel_is_valid(dialect, req.channel) || req.data_offset > MAX_DATA_OFFSET {
        return HandlerResponse::err(ntstatus::STATUS_INVALID_PARAMETER);
    }
    // WRITE_THROUGH is defined from 2.1 on, WRITE_UNBUFFERED from 3.0.2 on;
    // neither applies to a pipe.
    let write_through = !matches!(dialect, None | Some(Dialect::Smb202))
        && req.flags & WriteRequest::FLAG_WRITE_THROUGH != 0;
    let unbuffered = matches!(dialect, Some(Dialect::Smb302 | Dialect::Smb311))
        && req.flags & WriteRequest::FLAG_WRITE_UNBUFFERED != 0;
    if write_through || unbuffered {
        return HandlerResponse::err(ntstatus::STATUS_INVALID_PARAMETER);
    }
    if let Err(status) = pipe.write(&req.data).await {
        return HandlerResponse::err(status);
    }
    let mut buf = Vec::new();
    WriteResponse::new(req.length)
        .write_to(&mut buf)
        .expect("encode");
    HandlerResponse::ok(buf)
}

/// MS-SMB2 3.3.5.15 for an FSCTL on a pipe: FSCTL_PIPE_TRANSCEIVE writes
/// the input and answers with up to MaxOutputResponse bytes of the first
/// reply, waiting for one when the write produced none. Other FSCTLs get
/// STATUS_NOT_SUPPORTED.
async fn fsctl(
    conn: &Arc<Connection>,
    hdr: &Smb2Header,
    pipe: Arc<Pipe>,
    req: &IoctlRequest,
    body: &[u8],
    retained: usize,
) -> Outcome {
    let fail = |status| Outcome::Done(HandlerResponse::err(status));
    let input = match checked_input(conn, req, body).await {
        Ok(input) => input,
        Err(status) => return fail(status),
    };
    if req.fsctl() != Fsctl::PipeTransceive {
        return fail(ntstatus::STATUS_NOT_SUPPORTED);
    }
    let rights = FILE_READ_DATA | FILE_WRITE_DATA;
    if pipe.granted_access & rights != rights {
        return fail(ntstatus::STATUS_ACCESS_DENIED);
    }
    let file_id = pipe.file_id;
    let answer = move |bytes: Vec<u8>, more: bool| {
        overflowing(
            ioctl::response(Fsctl::PIPE_TRANSCEIVE, file_id, bytes),
            more,
        )
    };
    let len = req.max_output_response as usize;
    match pipe.transceive(input, len).await {
        Ok(Read::Data { bytes, more }) => Outcome::Done(answer(bytes, more)),
        Ok(Read::Empty) => wait(conn, hdr, pipe, len, retained, answer),
        Ok(Read::Disconnected) => fail(ntstatus::STATUS_PIPE_DISCONNECTED),
        Err(status) => fail(status),
    }
}

/// MS-SMB2 3.3.5.15.10. Pipe instances are not limited, so a pipe that
/// exists is available at once.
async fn pipe_wait(conn: &Arc<Connection>, req: &IoctlRequest, body: &[u8]) -> HandlerResponse {
    let input = match checked_input(conn, req, body).await {
        Ok(input) => input,
        Err(status) => return HandlerResponse::err(status),
    };
    if !wait_names_srvsvc(input) {
        return HandlerResponse::err(ntstatus::STATUS_OBJECT_NAME_NOT_FOUND);
    }
    ioctl::response(Fsctl::PIPE_WAIT, FileId::any(), Vec::new())
}

/// Whether an FSCTL_PIPE_WAIT_REQUEST (MS-FSCC 2.3.49) is well formed and
/// names the srvsvc pipe.
fn wait_names_srvsvc(input: &[u8]) -> bool {
    let Some(len) = input.get(8..12) else {
        return false;
    };
    let len = u32::from_le_bytes(len.try_into().expect("4 bytes")) as usize;
    let Some(units) = input
        .get(14..)
        .and_then(|name| name.get(..len))
        .and_then(utf16le_to_units)
    else {
        return false;
    };
    String::from_utf16_lossy(&units).eq_ignore_ascii_case(SRVSVC_PIPE)
}

/// The checks MS-SMB2 3.3.5.15 makes on every IOCTL; returns its input.
async fn checked_input<'a>(
    conn: &Arc<Connection>,
    req: &IoctlRequest,
    body: &'a [u8],
) -> Result<&'a [u8], u32> {
    if req.flags != IoctlRequest::FLAG_IS_FSCTL {
        return Err(ntstatus::STATUS_NOT_SUPPORTED);
    }
    let max_transact = *conn.max_read_size.read().await;
    if req.input_count > max_transact
        || req.max_input_response > max_transact
        || req.max_output_response > max_transact
    {
        return Err(ntstatus::STATUS_INVALID_PARAMETER);
    }
    ioctl::input_buffer(req, body).ok_or(ntstatus::STATUS_INVALID_PARAMETER)
}

/// QUERY_INFO on a pipe answers FileStandardInformation only.
async fn query_pipe_info(conn: &Arc<Connection>, req: &QueryInfoRequest) -> HandlerResponse {
    if req.output_buffer_length > *conn.max_read_size.read().await {
        return HandlerResponse::err(ntstatus::STATUS_INVALID_PARAMETER);
    }
    if !matches!(req.info_type_enum(), Some(InfoType::File))
        || req.file_information_class != FILE_STANDARD_INFORMATION
    {
        return HandlerResponse::err(ntstatus::STATUS_NOT_SUPPORTED);
    }
    if req.output_buffer_length < 24 {
        let smb311 = *conn.dialect.read().await == Some(Dialect::Smb311);
        return query_info::info_length_mismatch(smb311);
    }
    // AllocationSize, EndOfFile, NumberOfLinks, DeletePending, Directory.
    let mut info = Vec::with_capacity(24);
    info.extend_from_slice(&PIPE_ALLOCATION_SIZE.to_le_bytes());
    info.extend_from_slice(&0u64.to_le_bytes());
    info.extend_from_slice(&1u32.to_le_bytes());
    info.extend_from_slice(&[1, 0, 0, 0]);
    let resp = QueryInfoResponse {
        structure_size: 9,
        output_buffer_offset: 64 + 8,
        output_buffer_length: info.len() as u32,
        buffer: info,
    };
    let mut buf = Vec::new();
    resp.write_to(&mut buf).expect("encode");
    HandlerResponse::ok(buf)
}

/// MS-SMB2 3.3.5.10 for a pipe: its attributes cannot be fetched, so Flags
/// and every attribute are 0. Requests waiting on it end. `None` when the
/// tree has no such pipe.
async fn close(
    conn: &Arc<Connection>,
    tree: &Arc<RwLock<TreeConnect>>,
    file_id: FileId,
) -> Option<HandlerResponse> {
    pipes(&*tree.read().await).remove(&file_id)?;
    conn.pending
        .stop_where(Stop::Retry, |op| op.file_id == Some(file_id));
    let mut buf = Vec::new();
    CloseResponse::new().write_to(&mut buf).expect("encode");
    Some(HandlerResponse::ok(buf))
}
