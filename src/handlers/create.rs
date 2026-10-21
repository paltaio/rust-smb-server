//! CREATE handler: open or create a file/directory and allocate a FileId.

use std::sync::Arc;
use std::sync::atomic::Ordering;

use crate::proto::header::Smb2Header;
use crate::proto::messages::{
    CreateContext, CreateRequest, CreateResponse, Dialect, LeaseContext, OplockLevel,
};
use tracing::{debug, warn};
use uuid::Uuid;

use crate::access_mask::{
    DELETE, FILE_APPEND_DATA, FILE_READ_DATA, FILE_WRITE_ATTRIBUTES, FILE_WRITE_DATA,
    granted_access, maximal_access,
};
use crate::backend::{
    FILE_ATTRIBUTE_READONLY, FileInfo, FileTimes, Handle, OpenAction, OpenIntent, OpenOptions,
    VALID_SET_ATTRIBUTES,
};
use crate::conn::pending::{Stop, stopped};
use crate::conn::state::{Connection, Open};
use crate::dispatch::HandlerResponse;
use crate::error::SmbError;
use crate::files::{
    BreakWait, FileRef, Granted, LeaseId, LeaseRequest, LeaseState, LeaseVersion, OpenRequest,
    OpenSlot, Refused, Sharing, Trigger,
};
use crate::handlers::shared::lookup_session_tree;
use crate::handlers::{Outcome, Pending};
use crate::info_class::VOLUME_SERIAL_NUMBER;
use crate::ntstatus;
use crate::path::SmbPath;
use crate::server::{ServerState, ShareBindings};
use crate::utils::utf16le_to_units;

// CreateOptions
const FILE_DIRECTORY_FILE: u32 = 0x0000_0001;
const FILE_WRITE_THROUGH: u32 = 0x0000_0002;
pub(crate) const FILE_NO_INTERMEDIATE_BUFFERING: u32 = 0x0000_0008;
const FILE_SYNCHRONOUS_IO_ALERT: u32 = 0x0000_0010;
const FILE_SYNCHRONOUS_IO_NONALERT: u32 = 0x0000_0020;
const FILE_NON_DIRECTORY_FILE: u32 = 0x0000_0040;
const FILE_COMPLETE_IF_OPLOCKED: u32 = 0x0000_0100;
const FILE_OPEN_REMOTE_INSTANCE: u32 = 0x0000_0400;
const FILE_DELETE_ON_CLOSE: u32 = 0x0000_1000;
const FILE_OPEN_BY_FILE_ID: u32 = 0x0000_2000;
const FILE_OPEN_FOR_BACKUP_INTENT: u32 = 0x0000_4000;
const FILE_NO_COMPRESSION: u32 = 0x0000_8000;
const FILE_OPEN_REQUIRING_OPLOCK: u32 = 0x0001_0000;
const FILE_DISALLOW_EXCLUSIVE: u32 = 0x0002_0000;
const FILE_RESERVE_OPFILTER: u32 = 0x0010_0000;
const FILE_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
const FILE_OPEN_FOR_FREE_SPACE_QUERY: u32 = 0x0080_0000;

/// CreateOptions allowed with FILE_DIRECTORY_FILE (MS-SMB2 2.2.13), and the
/// flags the server ignores.
const DIRECTORY_OPTIONS: u32 = FILE_DIRECTORY_FILE
    | FILE_WRITE_THROUGH
    | FILE_OPEN_FOR_BACKUP_INTENT
    | FILE_DELETE_ON_CLOSE
    | FILE_OPEN_REPARSE_POINT
    | FILE_NO_COMPRESSION
    | FILE_SYNCHRONOUS_IO_ALERT
    | FILE_SYNCHRONOUS_IO_NONALERT
    | FILE_COMPLETE_IF_OPLOCKED
    | FILE_OPEN_REMOTE_INSTANCE
    | FILE_OPEN_REQUIRING_OPLOCK
    | FILE_DISALLOW_EXCLUSIVE
    | FILE_OPEN_FOR_FREE_SPACE_QUERY;

/// CreateOptions under which every write through the open reaches storage
/// before it completes.
pub(crate) const WRITE_THROUGH_OPTIONS: u32 = FILE_WRITE_THROUGH | FILE_NO_INTERMEDIATE_BUFFERING;

// CreateDisposition
const FILE_SUPERSEDE: u32 = 0x0000_0000;
const FILE_OPEN: u32 = 0x0000_0001;
const FILE_CREATE: u32 = 0x0000_0002;
const FILE_OPEN_IF: u32 = 0x0000_0003;
const FILE_OVERWRITE: u32 = 0x0000_0004;
const FILE_OVERWRITE_IF: u32 = 0x0000_0005;

// CreateAction in response (MS-SMB2 2.2.14)
const FILE_SUPERSEDED: u32 = 0x0000_0000;
const FILE_OPENED: u32 = 0x0000_0001;
const FILE_CREATED: u32 = 0x0000_0002;
const FILE_OVERWRITTEN: u32 = 0x0000_0003;

/// Offset of the response create contexts from the start of the SMB2
/// header: 64 + 88.
const RESPONSE_CONTEXTS_OFFSET: u32 = 0x98;

/// Caching the server grants in a lease.
const GRANTABLE_LEASE: LeaseState = LeaseState::RH;

/// Create contexts of a request that the response answers (MS-SMB2
/// 3.3.5.9.5, 3.3.5.9.9) or that fail it. Other contexts are ignored.
struct ContextQueries {
    /// QUERY_MAXIMAL_ACCESS, with its timestamp if it has one.
    maximal_access: Option<Option<u64>>,
    query_on_disk_id: bool,
    /// An EA buffer, which needs extended attributes (MS-SMB2 3.3.5.9.1).
    ea_buffer: bool,
    /// A timewarp token, which needs snapshots (MS-SMB2 3.3.5.9.4).
    timewarp: bool,
    /// Data of a lease request.
    lease: Option<Vec<u8>>,
}

impl ContextQueries {
    /// `None` if a context is malformed.
    fn parse(chain: &[u8]) -> Option<Self> {
        let contexts = CreateContext::parse_chain(chain).ok()?;
        let find = |name: &[u8; 4]| contexts.iter().find(|c| c.name == name);
        // The data is empty or one FILETIME (MS-SMB2 2.2.13.2.5).
        let maximal_access = match find(CreateContext::NAME_MXAC) {
            None => None,
            Some(c) if c.data.is_empty() => Some(None),
            Some(c) => Some(Some(u64::from_le_bytes(c.data.as_slice().try_into().ok()?))),
        };
        // Skipped when the request reconnects a durable open.
        let query_on_disk_id = find(CreateContext::NAME_QFID).is_some()
            && find(CreateContext::NAME_DHNC).is_none()
            && find(CreateContext::NAME_DH2C).is_none();
        Some(Self {
            maximal_access,
            query_on_disk_id,
            ea_buffer: find(CreateContext::NAME_EXTA).is_some(),
            timewarp: find(CreateContext::NAME_TWRP).is_some(),
            lease: find(CreateContext::NAME_RQLS).map(|c| c.data.clone()),
        })
    }

    /// Response contexts for an open of a file with `info` on a tree whose
    /// MaximalAccess is `maximal`, on the volume with serial number
    /// `volume_serial`.
    fn answer(&self, info: &FileInfo, maximal: u32, volume_serial: u32) -> Vec<CreateContext> {
        let mut out = Vec::new();
        if let Some(timestamp) = self.maximal_access {
            let (status, access) = if timestamp == Some(info.change_time) {
                (ntstatus::STATUS_NONE_MAPPED, 0)
            } else {
                (ntstatus::STATUS_SUCCESS, maximal)
            };
            let mut data = status.to_le_bytes().to_vec();
            data.extend_from_slice(&access.to_le_bytes());
            out.push(CreateContext {
                name: CreateContext::NAME_MXAC.to_vec(),
                data,
            });
        }
        if self.query_on_disk_id {
            // DiskFileId, VolumeId, 16 reserved bytes.
            let mut data = vec![0; 32];
            data[..8].copy_from_slice(&info.file_index.to_le_bytes());
            data[8..16].copy_from_slice(&u64::from(volume_serial).to_le_bytes());
            out.push(CreateContext {
                name: CreateContext::NAME_QFID.to_vec(),
                data,
            });
        }
        out
    }
}

/// The lease a CREATE asks for (MS-SMB2 3.3.5.9, 3.3.5.9.8, 3.3.5.9.11),
/// on a connection from `client` at `dialect`. Leases need SMB 2.1 or
/// later, and the version 2 context SMB 3.x. A request with an all-zero
/// key gets no lease. A context of the wrong size fails the CREATE with
/// STATUS_INVALID_PARAMETER.
fn lease_request(
    data: Option<&[u8]>,
    dialect: Option<Dialect>,
    client: Uuid,
) -> Result<Option<LeaseRequest>, u32> {
    let (Some(data), Some(dialect)) = (data, dialect) else {
        return Ok(None);
    };
    if matches!(dialect, Dialect::Smb202 | Dialect::Smb2Wildcard) {
        return Ok(None);
    }
    let ctx = LeaseContext::parse(data).map_err(|_| ntstatus::STATUS_INVALID_PARAMETER)?;
    if (ctx.v2 && dialect == Dialect::Smb210) || ctx.key == [0; 16] {
        return Ok(None);
    }
    let (version, parent) = if ctx.v2 {
        let parent =
            (ctx.flags & LeaseContext::FLAG_PARENT_LEASE_KEY_SET != 0).then_some(ctx.parent_key);
        (LeaseVersion::V2, parent)
    } else {
        (LeaseVersion::V1, None)
    };
    Ok(Some(LeaseRequest {
        id: LeaseId {
            client,
            key: ctx.key,
        },
        state: LeaseState::requested(ctx.state),
        version,
        epoch: ctx.epoch,
        parent,
    }))
}

/// The response lease context for `granted`, in the lease's version
/// (MS-SMB2 2.2.14.2.10, 2.2.14.2.11).
fn lease_response(granted: &Granted) -> CreateContext {
    let v2 = granted.version == LeaseVersion::V2;
    let mut flags = 0;
    if granted.breaking {
        flags |= LeaseContext::FLAG_BREAK_IN_PROGRESS;
    }
    if v2 && granted.parent.is_some() {
        flags |= LeaseContext::FLAG_PARENT_LEASE_KEY_SET;
    }
    let ctx = LeaseContext {
        key: granted.id.key,
        state: granted.state.bits(),
        flags,
        parent_key: granted.parent.unwrap_or_default(),
        epoch: if v2 { granted.epoch } else { 0 },
        v2,
    };
    CreateContext {
        name: CreateContext::NAME_RQLS.to_vec(),
        data: ctx.encode(),
    }
}

/// Most attempts an asynchronous CREATE makes; each follows a change on the
/// file while a lease break is in progress.
const MAX_WAIT_ATTEMPTS: u32 = 64;

/// A validated CREATE request: what each attempt to open needs.
struct CreateArgs {
    path: SmbPath,
    intent: OpenIntent,
    options: u32,
    create_disposition: u32,
    open_access: u32,
    maximal: u32,
    delete_on_close: bool,
    /// Attributes for a file this CREATE makes or overwrites.
    new_attributes: u32,
    opts: OpenOptions,
    sharing: Sharing,
    queries: ContextQueries,
    lease: Option<LeaseRequest>,
}

impl CreateArgs {
    /// Checks the request against the tree it targets (MS-SMB2 3.3.5.9).
    async fn parse(conn: &Arc<Connection>, hdr: &Smb2Header, body: &[u8]) -> Result<Self, u32> {
        let req = CreateRequest::parse(body).map_err(|_| ntstatus::STATUS_INVALID_PARAMETER)?;
        let tree_arc = lookup_session_tree(conn, hdr).await?;
        let tree = tree_arc.read().await;
        let tree_access = tree.granted_access;
        let share = Arc::clone(&tree.share);
        drop(tree);

        // Decode path.
        let units = utf16le_to_units(&req.name).ok_or(ntstatus::STATUS_INVALID_PARAMETER)?;
        let path = SmbPath::from_utf16(&units).map_err(|_| ntstatus::STATUS_OBJECT_NAME_INVALID)?;

        // Translate disposition.
        let intent = match req.create_disposition {
            FILE_SUPERSEDE | FILE_OVERWRITE_IF => OpenIntent::OverwriteOrCreate,
            FILE_OPEN => OpenIntent::Open,
            FILE_CREATE => OpenIntent::Create,
            FILE_OPEN_IF => OpenIntent::OpenOrCreate,
            FILE_OVERWRITE => OpenIntent::Truncate,
            _ => return Err(ntstatus::STATUS_INVALID_PARAMETER),
        };

        let options = req.create_options;
        if options & (FILE_OPEN_BY_FILE_ID | FILE_RESERVE_OPFILTER) != 0 {
            return Err(ntstatus::STATUS_NOT_SUPPORTED);
        }
        let directory = options & FILE_DIRECTORY_FILE != 0;
        let non_directory = options & FILE_NON_DIRECTORY_FILE != 0;
        if directory
            && (options & !DIRECTORY_OPTIONS != 0
                || !matches!(
                    intent,
                    OpenIntent::Create | OpenIntent::OpenOrCreate | OpenIntent::Open
                ))
        {
            return Err(ntstatus::STATUS_INVALID_PARAMETER);
        }

        let queries = ContextQueries::parse(&req.create_contexts)
            .ok_or(ntstatus::STATUS_INVALID_PARAMETER)?;
        if queries.timewarp {
            // There are no snapshots, so none matches the token.
            return Err(ntstatus::STATUS_OBJECT_NAME_NOT_FOUND);
        }
        if queries.ea_buffer {
            return Err(ntstatus::STATUS_EAS_NOT_SUPPORTED);
        }
        // Directories get no lease, and neither do shares that turn leases off.
        let lease = if req.requested_oplock_level == OplockLevel::Lease as u8 && share.leases {
            let dialect = *conn.dialect.read().await;
            let client = *conn.client_guid.read().await;
            lease_request(queries.lease.as_deref(), dialect, client)?.filter(|_| !directory)
        } else {
            None
        };

        let maximal = maximal_access(tree_access);
        let delete_on_close = options & FILE_DELETE_ON_CLOSE != 0;
        // MS-SMB2 3.3.5.9: the tree must allow DELETE.
        if delete_on_close && maximal & DELETE == 0 {
            warn!(path = %path, "delete-on-close open on read-only tree");
            return Err(ntstatus::STATUS_ACCESS_DENIED);
        }
        if req.desired_access == 0 {
            return Err(ntstatus::STATUS_ACCESS_DENIED);
        }
        let Some(mut open_access) = granted_access(req.desired_access, maximal) else {
            warn!(path = %path, "requested access exceeds tree access");
            return Err(ntstatus::STATUS_ACCESS_DENIED);
        };
        if options & FILE_NO_INTERMEDIATE_BUFFERING != 0 {
            open_access &= !FILE_APPEND_DATA;
        }
        // Disposition that creates: requires write permission.
        if !tree_access.allows_write()
            && matches!(
                intent,
                OpenIntent::Create
                    | OpenIntent::OpenOrCreate
                    | OpenIntent::OverwriteOrCreate
                    | OpenIntent::Truncate
            )
        {
            return Err(ntstatus::STATUS_ACCESS_DENIED);
        }

        let new_attributes = req.file_attributes & VALID_SET_ATTRIBUTES;
        if delete_on_close {
            // MS-FSA 2.1.5.1: the open itself must request DELETE.
            if open_access & DELETE == 0 {
                return Err(ntstatus::STATUS_INVALID_PARAMETER);
            }
            // MS-FSA 2.1.5.1: a file created read-only cannot be deleted.
            if intent != OpenIntent::Open && new_attributes & FILE_ATTRIBUTE_READONLY != 0 {
                return Err(ntstatus::STATUS_CANNOT_DELETE);
            }
        }

        let write = open_access & (FILE_WRITE_DATA | FILE_APPEND_DATA) != 0;
        let opts = OpenOptions {
            read: open_access & FILE_READ_DATA != 0 || !write,
            write,
            write_attributes: open_access & FILE_WRITE_ATTRIBUTES != 0,
            intent,
            directory,
            non_directory,
            delete_on_close,
        };
        Ok(Self {
            path,
            intent,
            options,
            create_disposition: req.create_disposition,
            open_access,
            maximal,
            delete_on_close,
            new_attributes,
            opts,
            sharing: Sharing {
                access: open_access,
                share: req.share_access,
            },
            queries,
            lease,
        })
    }
}

/// Where an attempt to open stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Stage {
    Start,
    /// A sharing violation broke handle caching. Another violation waits
    /// while that break is in progress and fails the CREATE once it is
    /// over (MS-FSA 2.1.5.1.2).
    AfterHandleBreak,
}

/// How an attempt ended.
enum Step {
    Done(HandlerResponse),
    /// A lease break has to complete first; nothing stays open meanwhile.
    Wait(BreakWait),
}

pub async fn handle(
    server: &Arc<ServerState>,
    conn: &Arc<Connection>,
    hdr: &Smb2Header,
    body: &[u8],
    retained: usize,
) -> Outcome {
    let args = match CreateArgs::parse(conn, hdr, body).await {
        Ok(args) => args,
        Err(status) => return Outcome::Done(HandlerResponse::err(status)),
    };
    let wait = match attempt(server, conn, hdr, &args, Stage::Start).await {
        Step::Done(response) => return Outcome::Done(response),
        Step::Wait(wait) => wait,
    };
    // MS-SMB2 3.3.4.2: past its limits the connection gets no more
    // asynchronous requests.
    let Some((op, mut stop)) = conn.pending.reserve(hdr, None, retained) else {
        warn!("too many waiting requests on the connection");
        return Outcome::Done(HandlerResponse::err(
            ntstatus::STATUS_INSUFFICIENT_RESOURCES,
        ));
    };
    let (server, conn, hdr) = (Arc::clone(server), Arc::clone(conn), *hdr);
    // The wait ends when the break completes, at the latest when its
    // acknowledgment times out. A wait that runs out with nothing changed
    // fails the CREATE as a sharing violation.
    let work = async move {
        let mut wait = wait;
        for _ in 0..MAX_WAIT_ATTEMPTS {
            let changed = tokio::select! {
                biased;
                why = stopped(&mut stop) => {
                    if why == Stop::Cancelled {
                        return HandlerResponse::err(ntstatus::STATUS_CANCELLED);
                    }
                    true
                }
                changed = wait.changed() => changed,
            };
            match attempt(&server, &conn, &hdr, &args, Stage::AfterHandleBreak).await {
                Step::Done(response) => return response,
                Step::Wait(_) if !changed => break,
                Step::Wait(next) => wait = next,
            }
        }
        HandlerResponse::err(ntstatus::STATUS_SHARING_VIOLATION)
    };
    Outcome::Pending(Pending {
        op,
        work: Box::pin(work),
    })
}

/// One try at opening the file. Runs the session and tree checks again, so
/// a CREATE that waited fails once its session or tree is gone.
async fn attempt(
    server: &Arc<ServerState>,
    conn: &Arc<Connection>,
    hdr: &Smb2Header,
    args: &CreateArgs,
    stage: Stage,
) -> Step {
    let fail = |status| Step::Done(HandlerResponse::err(status));
    let tree_arc = match lookup_session_tree(conn, hdr).await {
        Ok(t) => t,
        Err(s) => return fail(s),
    };
    let share = Arc::clone(&tree_arc.read().await.share);
    let backend = Arc::clone(&share.backend);
    let path = &args.path;

    let limit = server.max_opens_per_connection.load(Ordering::Relaxed);
    let Some(slot) = OpenSlot::acquire(&conn.open_count, limit) else {
        warn!(limit, "open limit reached");
        return fail(ntstatus::STATUS_INSUFFICIENT_RESOURCES);
    };

    let open_request = |overwrite| OpenRequest {
        sharing: args.sharing,
        owner: Arc::downgrade(&conn.outbound),
        lease: args.lease.map(|l| l.id),
        overwrite,
        break_handles: stage == Stage::Start,
    };
    let refused = |refused: Refused| match refused.wait {
        Some(wait) => Step::Wait(wait),
        None => fail(refused.status),
    };
    let lease_ref = match &args.lease {
        Some(l) => match server.leases.acquire(l.id, &share, path) {
            Ok(lease_ref) => Some(lease_ref),
            Err(status) => return fail(status),
        },
        None => None,
    };

    // An open that truncates checks the file and takes its place in the
    // table first, so a refused open leaves the file as it was and no other
    // open slips in while the backend truncates.
    let reserved = if matches!(
        args.intent,
        OpenIntent::Truncate | OpenIntent::OverwriteOrCreate
    ) {
        match reserve_existing(&share, path, args.opts, open_request(true)).await {
            Ok(reserved) => reserved,
            Err(r) => return refused(r),
        }
    } else {
        None
    };

    let (handle, action) = match backend.open(path, args.opts).await {
        Ok(opened) => opened,
        Err(e) => {
            debug!(error = %e, path = %path, "backend open failed");
            let case_sensitive = backend.capabilities().case_sensitive;
            if matches!(e, SmbError::Exists) && share.files.delete_pending_at(path, case_sensitive)
            {
                return fail(ntstatus::STATUS_DELETE_PENDING);
            }
            return fail(e.to_nt_status());
        }
    };

    // Stat for the response.
    let mut info = match handle.stat().await {
        Ok(i) => i,
        Err(e) => {
            let _ = handle.close().await;
            return fail(e.to_nt_status());
        }
    };
    // MS-FSA 2.1.5.1.2.1: a read-only file cannot be opened for deletion.
    if args.delete_on_close && info.read_only {
        let _ = handle.close().await;
        return fail(ntstatus::STATUS_CANNOT_DELETE);
    }
    let mut file = match reserved {
        Some(file) if file.is_for(&info, path) => file,
        // The file was replaced between the two opens, or did not exist.
        reserved => {
            drop(reserved);
            let overwrite = action == OpenAction::Overwritten;
            match FileRef::register(&share, &info, path, open_request(overwrite)) {
                Ok(f) => f,
                Err(r) => {
                    let _ = handle.close().await;
                    return refused(r);
                }
            }
        }
    };
    let mut granted = None;
    let mut after_send = None;
    if let (Some(lease), Some(lease_ref)) = (args.lease, lease_ref)
        && !info.is_directory
    {
        match server
            .leases
            .grant(lease_ref, &mut file, &lease, GRANTABLE_LEASE)
        {
            Ok((lease, guard)) => {
                granted = Some(lease);
                after_send = Some(guard);
            }
            Err(status) => {
                drop(file);
                let _ = handle.close().await;
                return fail(status);
            }
        }
    }
    // An overwrite that took the file's place in the table before the
    // backend truncated it broke the leases then; one granted since breaks
    // now, so it does not keep the old contents cached.
    if action == OpenAction::Overwritten {
        file.break_leases(Trigger::Open { overwrite: true });
    }

    if action != OpenAction::Opened
        && args.new_attributes != 0
        && args.new_attributes != info.attributes() & VALID_SET_ATTRIBUTES
    {
        apply_attributes(handle.as_ref(), args.new_attributes, path).await;
        if let Ok(updated) = handle.stat().await {
            info = updated;
        }
    }

    // The on-disk id carries the serial number FileFsVolumeInformation
    // reports.
    let volume_serial = if args.queries.query_on_disk_id {
        backend
            .volume_info()
            .await
            .map_or(VOLUME_SERIAL_NUMBER, |v| v.serial_number)
    } else {
        VOLUME_SERIAL_NUMBER
    };

    // Allocate FileId, register Open. A tree disconnected or revoked while
    // the backend worked takes no new opens.
    let mut tree = tree_arc.write().await;
    if tree.closed {
        drop(tree);
        // The open leaves the table, ending a lease it alone held, before
        // the guard could send a break held back for that lease.
        drop(file);
        drop(after_send);
        let _ = handle.close().await;
        return fail(ntstatus::STATUS_NETWORK_NAME_DELETED);
    }
    let file_id = tree.alloc_file_id();
    let open = Open {
        file_id,
        handle: Some(handle),
        granted_access: args.open_access,
        is_directory: info.is_directory,
        delete_on_close: args.delete_on_close,
        search_state: None,
        fixed_times: FileTimes::default(),
        create_options: args.options,
        file: Some(file),
        slot: Some(slot),
    };
    let open_arc = Arc::new(tokio::sync::RwLock::new(open));
    tree.opens.get_mut().insert(file_id, open_arc);
    drop(tree);

    let create_action = match action {
        OpenAction::Opened => FILE_OPENED,
        OpenAction::Created => FILE_CREATED,
        OpenAction::Overwritten if args.create_disposition == FILE_SUPERSEDE => FILE_SUPERSEDED,
        OpenAction::Overwritten => FILE_OVERWRITTEN,
    };
    let mut answers = args.queries.answer(&info, args.maximal, volume_serial);
    if let Some(granted) = &granted {
        answers.push(lease_response(granted));
    }
    let mut contexts = Vec::new();
    CreateContext::encode_chain(&answers, &mut contexts).expect("encoding into a Vec cannot fail");
    let resp = CreateResponse {
        structure_size: 89,
        oplock_level: if granted.is_some() {
            OplockLevel::Lease as u8
        } else {
            OplockLevel::None as u8
        },
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
        create_contexts_offset: if contexts.is_empty() {
            0
        } else {
            RESPONSE_CONTEXTS_OFFSET
        },
        create_contexts_length: contexts.len() as u32,
        create_contexts: contexts,
    };
    let mut buf = Vec::new();
    resp.write_to(&mut buf).expect("encode");
    let mut response = HandlerResponse::ok(buf);
    if let Some(guard) = after_send {
        response.after_send.push(Box::new(guard));
    }
    Step::Done(response)
}

/// Before a CREATE that truncates the file at `path`, checks the existing
/// file against the opens already on it and against delete-on-close, and
/// enters the new open in the share's table so the file keeps this sharing
/// mode while the backend truncates it. A file that is missing or cannot be
/// opened for reading passes without an entry; the real open reports those.
async fn reserve_existing(
    share: &Arc<ShareBindings>,
    path: &SmbPath,
    opts: OpenOptions,
    req: OpenRequest,
) -> Result<Option<FileRef>, Refused> {
    let probe = OpenOptions {
        read: true,
        write: false,
        write_attributes: false,
        intent: OpenIntent::Open,
        delete_on_close: false,
        ..opts
    };
    let Ok((handle, _)) = share.backend.open(path, probe).await else {
        return Ok(None);
    };
    let result = match handle.stat().await {
        Ok(info) if opts.delete_on_close && info.read_only => {
            Err(ntstatus::STATUS_CANNOT_DELETE.into())
        }
        Ok(info) => FileRef::register(share, &info, path, req).map(Some),
        Err(_) => Ok(None),
    };
    let _ = handle.close().await;
    result
}

/// Gives a file this CREATE made or overwrote the requested attributes. A
/// backend that cannot store all of them gets READONLY alone, when asked
/// for; the CREATE succeeds either way.
async fn apply_attributes(handle: &dyn Handle, attributes: u32, path: &SmbPath) {
    let mut result = handle.set_attributes(attributes).await;
    if matches!(result, Err(SmbError::NotSupported))
        && attributes & FILE_ATTRIBUTE_READONLY != 0
        && attributes != FILE_ATTRIBUTE_READONLY
    {
        result = handle.set_attributes(FILE_ATTRIBUTE_READONLY).await;
    }
    if let Err(e) = result {
        debug!(error = %e, path = %path, attributes, "create attributes not applied");
    }
}

#[cfg(test)]
mod tests {
    use async_trait::async_trait;
    use tokio::sync::{Notify, RwLock, Semaphore};

    use super::*;
    use crate::backend::{BackendCapabilities, ShareBackend};
    use crate::builder::Access;
    use crate::conn::state::{Session, TreeConnect};
    use crate::error::SmbResult;
    use crate::proto::auth::ntlm::Identity;
    use crate::proto::header::{Command, HeaderTail};
    use crate::tests::memfs::MemFsBackend;
    use crate::{Share, SmbServer};

    /// Memory backend whose truncating opens tell `waiting` they have
    /// arrived and then wait for a permit from `go`.
    struct HoldTruncate {
        inner: MemFsBackend,
        waiting: Arc<Notify>,
        go: Arc<Semaphore>,
    }

    #[async_trait]
    impl ShareBackend for HoldTruncate {
        async fn open(
            &self,
            path: &SmbPath,
            opts: OpenOptions,
        ) -> SmbResult<(Box<dyn Handle>, OpenAction)> {
            if opts.intent == OpenIntent::Truncate {
                self.waiting.notify_one();
                self.go.acquire().await.expect("gate").forget();
            }
            self.inner.open(path, opts).await
        }

        async fn unlink(&self, path: &SmbPath) -> SmbResult<()> {
            self.inner.unlink(path).await
        }

        async fn rename(&self, from: &SmbPath, to: &SmbPath, replace: bool) -> SmbResult<()> {
            self.inner.rename(from, to, replace).await
        }

        fn capabilities(&self) -> BackendCapabilities {
            self.inner.capabilities()
        }
    }

    fn create_body(name: &str, disposition: u32) -> Vec<u8> {
        let name: Vec<u8> = name.encode_utf16().flat_map(u16::to_le_bytes).collect();
        let req = CreateRequest {
            structure_size: 57,
            security_flags: 0,
            requested_oplock_level: 0,
            impersonation_level: 2,
            smb_create_flags: 0,
            reserved: 0,
            desired_access: FILE_READ_DATA | FILE_WRITE_DATA,
            file_attributes: 0,
            share_access: 7,
            create_disposition: disposition,
            create_options: 0,
            name_offset: 0x78,
            name_length: name.len() as u16,
            create_contexts_offset: 0,
            create_contexts_length: 0,
            name,
            create_contexts: Vec::new(),
        };
        let mut body = Vec::new();
        req.write_to(&mut body)
            .expect("encoding into a Vec cannot fail");
        body
    }

    #[tokio::test]
    async fn a_truncating_create_holds_the_file_while_the_backend_truncates() {
        let waiting = Arc::new(Notify::new());
        let go = Arc::new(Semaphore::new(0));
        let backend = HoldTruncate {
            inner: MemFsBackend::new().with_file("f.txt", b"precious"),
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
            command: Command::Create,
            tail: HeaderTail::sync(1),
            session_id: 1,
            ..Smb2Header::default()
        };
        let body = create_body("f.txt", FILE_OVERWRITE);
        let truncating = tokio::spawn({
            let state = Arc::clone(&state);
            let conn = Arc::clone(&conn);
            async move {
                match handle(&state, &conn, &hdr, &body, 0).await {
                    Outcome::Done(response) => response.status,
                    Outcome::Pending(_) => panic!("the CREATE waits"),
                }
            }
        });
        waiting.notified().await;

        // Another connection's exclusive open arrives while the backend
        // truncates.
        let path: SmbPath = "f.txt".parse().unwrap();
        let (probe, _) = share
            .backend
            .open(&path, OpenOptions::default())
            .await
            .unwrap();
        let info = probe.stat().await.unwrap();
        let exclusive = FileRef::register(
            &share,
            &info,
            &path,
            Sharing {
                access: FILE_READ_DATA,
                share: 0,
            }
            .into(),
        );
        assert_eq!(
            exclusive.err().map(|r| r.status),
            Some(ntstatus::STATUS_SHARING_VIOLATION)
        );

        go.add_permits(1);
        assert_eq!(truncating.await.unwrap(), ntstatus::STATUS_SUCCESS);
        assert_eq!(probe.stat().await.unwrap().end_of_file, 0);
    }
}
