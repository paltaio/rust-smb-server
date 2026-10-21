//! CREATE handler: open or create a file/directory and allocate a FileId.

use std::sync::Arc;
use std::sync::atomic::Ordering;

use crate::proto::header::Smb2Header;
use crate::proto::messages::{
    CreateContext, CreateRequest, CreateResponse, Dialect, DurableReconnect, DurableReconnectV2,
    DurableRequest, DurableRequestV2, DurableResponse, FileId, LeaseContext, OplockLevel,
};
use tokio::time::Instant;
use tracing::{debug, warn};
use uuid::Uuid;

use crate::access_mask::{
    DELETE, FILE_APPEND_DATA, FILE_READ_DATA, FILE_WRITE_ATTRIBUTES, FILE_WRITE_DATA,
    granted_access, maximal_access,
};
use crate::backend::{
    FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_READONLY, FileInfo, FileTimes, Handle, OpenAction,
    OpenIntent, OpenOptions, VALID_SET_ATTRIBUTES,
};
use crate::conn::pending::{Stop, stopped};
use crate::conn::state::{Connection, Open};
use crate::dispatch::HandlerResponse;
use crate::error::SmbError;
use crate::files::{
    BreakWait, Claim, FileRef, Granted, LeaseId, LeaseRef, LeaseRequest, LeaseState, LeaseVersion,
    MAX_BREAK_WAIT, OpenRequest, OpenSlot, Refused, Sharing, Trigger, close_open,
};
use crate::handlers::shared::{lookup_session, lookup_session_tree};
use crate::handlers::{Outcome, Pending};
use crate::info_class::VOLUME_SERIAL_NUMBER;
use crate::ntstatus;
use crate::path::SmbPath;
use crate::proto::auth::ntlm::Identity;
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
const GRANTABLE_LEASE: LeaseState = LeaseState::RWH;

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
    durable: DurableAsk,
}

/// The durable handle a CREATE asks for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DurableAsk {
    None,
    /// DHnQ (MS-SMB2 3.3.5.9.6).
    V1,
    /// DH2Q, on SMB 3.x (MS-SMB2 3.3.5.9.10).
    V2,
    /// DHnC: reconnect the open named (MS-SMB2 3.3.5.9.7).
    Reconnect(DurableReconnect),
    /// DH2C, on SMB 3.x (MS-SMB2 3.3.5.9.12).
    ReconnectV2(DurableReconnectV2),
}

/// Reads the durable handle contexts of a CREATE on `dialect`. The version
/// 2 contexts count on SMB 3.x only (MS-SMB2 2.2.13.2.11, 2.2.13.2.12). A
/// reconnect ignores a DHnQ next to it (MS-SMB2 3.3.5.9.7); any other two
/// of them together, or one of the wrong size, fail the CREATE with
/// STATUS_INVALID_PARAMETER (MS-SMB2 3.3.5.9.6, 3.3.5.9.7, 3.3.5.9.10).
pub(crate) fn durable_ask(
    contexts: &[CreateContext],
    dialect: Option<Dialect>,
) -> Result<DurableAsk, u32> {
    let v3 = matches!(
        dialect,
        Some(Dialect::Smb300 | Dialect::Smb302 | Dialect::Smb311)
    );
    let find = |name: &[u8; 4], counts: bool| {
        contexts
            .iter()
            .find(|c| counts && c.name == name)
            .map(|c| c.data.as_slice())
    };
    let invalid = |_| ntstatus::STATUS_INVALID_PARAMETER;
    let dhnq = find(CreateContext::NAME_DHNQ, true)
        .map(DurableRequest::parse)
        .transpose()
        .map_err(invalid)?;
    let dhnc = find(CreateContext::NAME_DHNC, true)
        .map(DurableReconnect::parse)
        .transpose()
        .map_err(invalid)?;
    let dh2q = find(CreateContext::NAME_DH2Q, v3)
        .map(DurableRequestV2::parse)
        .transpose()
        .map_err(invalid)?;
    let dh2c = find(CreateContext::NAME_DH2C, v3)
        .map(DurableReconnectV2::parse)
        .transpose()
        .map_err(invalid)?;
    Ok(match (dhnq, dhnc, dh2q, dh2c) {
        (None, None, None, None) => DurableAsk::None,
        (Some(_), None, None, None) => DurableAsk::V1,
        (_, Some(reconnect), None, None) => DurableAsk::Reconnect(reconnect),
        (None, None, Some(_), None) => DurableAsk::V2,
        (None, None, None, Some(reconnect)) => DurableAsk::ReconnectV2(reconnect),
        _ => return Err(ntstatus::STATUS_INVALID_PARAMETER),
    })
}

impl ContextQueries {
    /// `None` if a context is malformed or the durable handle contexts do
    /// not go together.
    fn parse(chain: &[u8], dialect: Option<Dialect>) -> Option<Self> {
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
            durable: durable_ask(&contexts, dialect).ok()?,
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
/// key gets no lease. A version 2 request whose `file_attributes` name a
/// directory asks for no write caching. A context of the wrong size fails
/// the CREATE with STATUS_INVALID_PARAMETER.
fn lease_request(
    data: Option<&[u8]>,
    dialect: Option<Dialect>,
    client: Uuid,
    file_attributes: u32,
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
    let mut state = LeaseState::requested(ctx.state);
    let (version, parent) = if ctx.v2 {
        let parent =
            (ctx.flags & LeaseContext::FLAG_PARENT_LEASE_KEY_SET != 0).then_some(ctx.parent_key);
        if file_attributes & FILE_ATTRIBUTE_DIRECTORY != 0 {
            state = state.without(LeaseState::W);
        }
        (LeaseVersion::V2, parent)
    } else {
        (LeaseVersion::V1, None)
    };
    Ok(Some(LeaseRequest {
        id: LeaseId {
            client,
            key: ctx.key,
        },
        state,
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
    /// The configured name of the session's user; `None` for anonymous.
    owner: Option<String>,
}

/// What a CREATE asks for.
enum Request {
    Open(CreateArgs),
    Reconnect(Reconnect),
}

/// A request to reconnect a durable open.
struct Reconnect {
    /// The FileId the request names.
    file_id: FileId,
    /// DH2C rather than DHnC.
    v2: bool,
    share: Arc<ShareBindings>,
    owner: Option<String>,
    client: Uuid,
    lease: Option<LeaseId>,
}

impl CreateArgs {
    /// Checks the request against the tree it targets (MS-SMB2 3.3.5.9).
    async fn parse(conn: &Arc<Connection>, hdr: &Smb2Header, body: &[u8]) -> Result<Request, u32> {
        let req = CreateRequest::parse(body).map_err(|_| ntstatus::STATUS_INVALID_PARAMETER)?;
        let tree_arc = lookup_session_tree(conn, hdr).await?;
        let tree = tree_arc.read().await;
        let tree_access = tree.granted_access;
        let share = Arc::clone(&tree.share);
        drop(tree);
        let owner = match &lookup_session(conn, hdr.session_id)
            .await?
            .read()
            .await
            .identity
        {
            Identity::User { user, .. } => Some(user.clone()),
            Identity::Anonymous => None,
        };
        let dialect = *conn.dialect.read().await;
        let client = *conn.client_guid.read().await;

        let queries = ContextQueries::parse(&req.create_contexts, dialect)
            .ok_or(ntstatus::STATUS_INVALID_PARAMETER)?;
        // A reconnect skips the checks of the name and of the open itself
        // (MS-SMB2 3.3.5.9.7, 3.3.5.9.12).
        let reconnect = match queries.durable {
            DurableAsk::Reconnect(r) => Some((r.file_id, false)),
            DurableAsk::ReconnectV2(r) => Some((r.file_id, true)),
            _ => None,
        };
        if let Some((file_id, v2)) = reconnect {
            let lease = lease_request(queries.lease.as_deref(), dialect, client, 0)?;
            return Ok(Request::Reconnect(Reconnect {
                file_id,
                v2,
                share,
                owner,
                client,
                lease: lease.map(|l| l.id),
            }));
        }

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

        if queries.timewarp {
            // There are no snapshots, so none matches the token.
            return Err(ntstatus::STATUS_OBJECT_NAME_NOT_FOUND);
        }
        if queries.ea_buffer {
            return Err(ntstatus::STATUS_EAS_NOT_SUPPORTED);
        }
        // Directories get no lease, and neither do shares that turn leases off.
        let lease = if req.requested_oplock_level == OplockLevel::Lease as u8 && share.leases {
            lease_request(
                queries.lease.as_deref(),
                dialect,
                client,
                req.file_attributes,
            )?
            .filter(|_| !directory)
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
        Ok(Request::Open(Self {
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
            owner,
        }))
    }
}

/// Where an attempt to open stands.
enum Stage {
    Start,
    /// A sharing violation broke handle caching. Another violation waits
    /// while that break is in progress and fails the CREATE once it is
    /// over (MS-FSA 2.1.5.1.2).
    AfterHandleBreak,
    /// The open is in the file table, waiting for other clients to give up
    /// write caching (MS-FSA 2.1.4.12, OPEN). Staying in the table keeps
    /// its sharing mode in force and keeps those clients from regaining
    /// write caching meanwhile.
    Reserved(Box<Reserved>),
}

/// What a CREATE waiting in the file table holds.
struct Reserved {
    file: FileRef,
    slot: OpenSlot,
    lease_ref: Option<LeaseRef>,
    /// The backend open, when it already ran. An open that truncates runs
    /// it after the wait, so data the clients write back first is not lost
    /// to the truncation.
    opened: Option<(HeldHandle, OpenAction)>,
}

/// A backend handle a waiting CREATE keeps. One dropped without
/// [`HeldHandle::take`], when the CREATE's task is cancelled or aborted, is
/// closed on the current runtime.
struct HeldHandle(Option<Box<dyn Handle>>);

impl HeldHandle {
    fn take(mut self) -> Box<dyn Handle> {
        self.0.take().expect("a held handle is taken once")
    }
}

impl Drop for HeldHandle {
    fn drop(&mut self) {
        if let Some(handle) = self.0.take()
            && let Ok(runtime) = tokio::runtime::Handle::try_current()
        {
            runtime.spawn(async move {
                let _ = handle.close().await;
            });
        }
    }
}

impl Stage {
    fn break_handles(&self) -> bool {
        matches!(self, Stage::Start)
    }

    /// Gives up what a waiting CREATE holds, closing its backend handle.
    async fn release(self) {
        if let Stage::Reserved(reserved) = self {
            let Reserved { file, opened, .. } = *reserved;
            if let Some((handle, _)) = opened {
                let _ = handle.take().close().await;
            }
            drop(file);
        }
    }
}

/// How an attempt ended.
enum Step {
    Done(HandlerResponse),
    /// A lease break has to complete first.
    Wait(BreakWait, Stage),
}

pub async fn handle(
    server: &Arc<ServerState>,
    conn: &Arc<Connection>,
    hdr: &Smb2Header,
    body: &[u8],
    retained: usize,
) -> Outcome {
    let args = match CreateArgs::parse(conn, hdr, body).await {
        Ok(Request::Open(args)) => args,
        Ok(Request::Reconnect(r)) => {
            return Outcome::Done(HandlerResponse::err(refuse_reconnect(server, r).await));
        }
        Err(status) => return Outcome::Done(HandlerResponse::err(status)),
    };
    let (wait, stage) = match attempt(server, conn, hdr, &args, Stage::Start).await {
        Step::Done(response) => return Outcome::Done(response),
        Step::Wait(wait, stage) => (wait, stage),
    };
    // MS-SMB2 3.3.4.2: past its limits the connection gets no more
    // asynchronous requests.
    let Some((op, mut stop)) = conn.pending.reserve(hdr, None, retained) else {
        warn!("too many waiting requests on the connection");
        stage.release().await;
        return Outcome::Done(HandlerResponse::err(
            ntstatus::STATUS_INSUFFICIENT_RESOURCES,
        ));
    };
    let (server, conn, hdr) = (Arc::clone(server), Arc::clone(conn), *hdr);
    // The wait ends when the breaks complete, which their acknowledgment
    // timers bound. A wait that runs out with nothing changed on the file,
    // or one that outlasts [`MAX_BREAK_WAIT`], fails the CREATE as a sharing
    // violation.
    let work = async move {
        let give_up = Instant::now() + MAX_BREAK_WAIT;
        let mut wait = wait;
        let mut stage = stage;
        loop {
            let changed = tokio::select! {
                biased;
                why = stopped(&mut stop) => {
                    if why == Stop::Cancelled {
                        stage.release().await;
                        return HandlerResponse::err(ntstatus::STATUS_CANCELLED);
                    }
                    true
                }
                changed = wait.changed() => changed,
                () = tokio::time::sleep_until(give_up) => false,
            };
            match attempt(&server, &conn, &hdr, &args, stage).await {
                Step::Done(response) => return response,
                Step::Wait(_, left) if !changed => {
                    left.release().await;
                    return HandlerResponse::err(ntstatus::STATUS_SHARING_VIOLATION);
                }
                Step::Wait(next, left) => {
                    wait = next;
                    stage = left;
                }
            }
        }
    };
    Outcome::Pending(Pending {
        op,
        work: Box::pin(work),
    })
}

/// MS-SMB2 3.3.5.9.7 and 3.3.5.9.12 on a server that hands no durable open
/// back: every reconnect fails. A DHnC from the owner of a kept open, with
/// its client and lease key, closes that open first, as
/// `DurableTable::give_up` describes. No durable open on this server has a
/// CreateGuid, so a DH2C names none (MS-SMB2 3.3.5.9.12).
async fn refuse_reconnect(server: &ServerState, r: Reconnect) -> u32 {
    let id = r.file_id.persistent;
    if r.v2 {
        debug!(id, "durable reconnect refused");
        return ntstatus::STATUS_OBJECT_NAME_NOT_FOUND;
    }
    let claim = Claim {
        share: &r.share,
        user: r.owner.as_deref(),
        client: r.client,
        lease: r.lease,
    };
    match server.durable.give_up(id, &claim) {
        Ok(open) => {
            close_open(&open, false).await;
            ntstatus::STATUS_OBJECT_NAME_NOT_FOUND
        }
        Err(status) => {
            debug!(id, status, "durable reconnect refused");
            status
        }
    }
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
        Err(s) => {
            stage.release().await;
            return fail(s);
        }
    };
    let share = Arc::clone(&tree_arc.read().await.share);
    let backend = Arc::clone(&share.backend);
    let path = &args.path;

    let open_request = |overwrite, break_handles| OpenRequest {
        sharing: args.sharing,
        owner: Arc::downgrade(&conn.outbound),
        lease: args.lease.map(|l| l.id),
        overwrite,
        break_handles,
    };
    let break_handles = stage.break_handles();
    let refused = |refused: Refused, stage: Stage| match refused.wait {
        Some(wait) => Step::Wait(wait, stage),
        None => fail(refused.status),
    };

    let open_failed = |e: SmbError| {
        debug!(error = %e, path = %path, "backend open failed");
        let case_sensitive = backend.capabilities().case_sensitive;
        if matches!(e, SmbError::Exists) && share.files.delete_pending_at(path, case_sensitive) {
            return fail(ntstatus::STATUS_DELETE_PENDING);
        }
        fail(e.to_nt_status())
    };

    let (slot, lease_ref, reserved, opened, registered) = match stage {
        Stage::Reserved(reserved) => {
            match reserved.file.end_wait() {
                // Write caching other clients still hold keeps it waiting.
                Ok(Some(wait)) => return Step::Wait(wait, Stage::Reserved(reserved)),
                Ok(None) => {}
                Err(status) => {
                    Stage::Reserved(reserved).release().await;
                    return fail(status);
                }
            }
            let Reserved {
                file,
                slot,
                lease_ref,
                opened,
            } = *reserved;
            let opened = opened.map(|(handle, action)| (handle.take(), action));
            let registered = opened.is_some();
            (slot, lease_ref, Some(file), opened, registered)
        }
        Stage::Start | Stage::AfterHandleBreak => {
            let limit = server.max_opens_per_connection.load(Ordering::Relaxed);
            let Some(slot) = OpenSlot::acquire(&conn.open_count, limit) else {
                warn!(limit, "open limit reached");
                return fail(ntstatus::STATUS_INSUFFICIENT_RESOURCES);
            };
            let lease_ref = match &args.lease {
                Some(l) => match server.leases.acquire(l.id, &share, path) {
                    Ok(lease_ref) => Some(lease_ref),
                    Err(status) => return fail(status),
                },
                None => None,
            };
            let truncating = matches!(
                args.intent,
                OpenIntent::Truncate | OpenIntent::OverwriteOrCreate
            );
            // An open that truncates checks the file and takes its place
            // in the table first, so a refused open leaves the file as it
            // was, no other open slips in while the backend truncates, and
            // clients caching writes write back before it does. A file
            // that is missing is created instead; one that appears
            // meanwhile is checked again.
            let mut tries = 0;
            let (reserved, opened) = loop {
                if !truncating {
                    break (None, None);
                }
                let request = open_request(true, break_handles);
                match reserve_existing(&share, path, args.opts, request).await {
                    Ok(Probe::Reserved(file, Some(wait))) => {
                        let reserved = Reserved {
                            file,
                            slot,
                            lease_ref,
                            opened: None,
                        };
                        return Step::Wait(wait, Stage::Reserved(Box::new(reserved)));
                    }
                    Ok(Probe::Reserved(file, None)) => break (Some(file), None),
                    Ok(Probe::Missing(e)) if args.intent == OpenIntent::Truncate => {
                        return open_failed(e);
                    }
                    Ok(Probe::Missing(_)) => {
                        let create = OpenOptions {
                            intent: OpenIntent::Create,
                            ..args.opts
                        };
                        match backend.open(path, create).await {
                            Ok(opened) => break (None, Some(opened)),
                            Err(SmbError::Exists) if tries < 2 => tries += 1,
                            Err(e) => return open_failed(e),
                        }
                    }
                    Err(r) => return refused(r, Stage::AfterHandleBreak),
                }
            };
            (slot, lease_ref, reserved, opened, false)
        }
    };

    // The open this attempt made, or the one a waiting CREATE kept.
    let (handle, action) = match opened {
        Some(opened) => opened,
        None => match backend.open(path, args.opts).await {
            Ok(opened) => opened,
            Err(e) => return open_failed(e),
        },
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
        Some(file) if registered || file.is_for(&info, path) => file,
        // The file was replaced between the two opens, or did not exist.
        reserved => {
            drop(reserved);
            let overwrite = action == OpenAction::Overwritten;
            match FileRef::register(&share, &info, path, open_request(overwrite, break_handles)) {
                Ok((file, None)) => file,
                Ok((file, Some(wait))) => {
                    let reserved = Reserved {
                        file,
                        slot,
                        lease_ref,
                        opened: Some((HeldHandle(Some(handle)), action)),
                    };
                    return Step::Wait(wait, Stage::Reserved(Box::new(reserved)));
                }
                Err(r) => {
                    let _ = handle.close().await;
                    return refused(r, Stage::AfterHandleBreak);
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
    // MS-SMB2 3.3.5.9.6: an open asking for a durable handle gets one when
    // its lease caches handles. Anonymous sessions get none, since they all
    // count as one user, and neither does a client without a ClientGuid.
    let durable = match (&granted, &args.owner) {
        (Some(lease), Some(owner))
            if args.queries.durable == DurableAsk::V1
                && lease.state.contains(LeaseState::H)
                && share.durable_handles
                && !lease.id.client.is_nil() =>
        {
            server.durable.register(owner, &share, lease.id)
        }
        _ => None,
    };
    if let Some(reg) = &durable {
        file.mark_durable(&server.durable, reg.id());
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
    let file_id = match &durable {
        Some(reg) => FileId::new(reg.id(), tree.alloc_volatile()),
        None => tree.alloc_file_id(),
    };
    let durable_granted = durable.is_some();
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
        durable,
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
    if durable_granted {
        debug!(
            id = file_id.persistent,
            timeout = ?server.durable.timeout,
            "durable open granted"
        );
        answers.push(CreateContext {
            name: CreateContext::NAME_DHNQ.to_vec(),
            data: DurableResponse.encode(),
        });
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

fn is_missing(e: &SmbError) -> bool {
    matches!(e, SmbError::NotFound | SmbError::PathNotFound)
}

/// What the check before a truncating CREATE found.
enum Probe {
    /// No file at the path; the error the open reported.
    Missing(SmbError),
    /// The open is in the table, with a wait when clients caching writes
    /// have to write back first.
    Reserved(FileRef, Option<BreakWait>),
}

/// Before a CREATE that truncates the file at `path`, opens the existing
/// file without truncating it, checks it against delete-on-close and the
/// opens already on it, and enters the new open in the share's table. That
/// open asks for reading, and for the access the CREATE was granted when
/// reading is refused. Only a missing file passes without an entry; any
/// other failure fails the CREATE, as the truncating open would.
async fn reserve_existing(
    share: &Arc<ShareBindings>,
    path: &SmbPath,
    opts: OpenOptions,
    req: OpenRequest,
) -> Result<Probe, Refused> {
    let probe = OpenOptions {
        intent: OpenIntent::Open,
        delete_on_close: false,
        ..opts
    };
    let read_only = OpenOptions {
        read: true,
        write: false,
        write_attributes: false,
        ..probe
    };
    let mut opened = share.backend.open(path, read_only).await;
    if matches!(opened, Err(ref e) if !is_missing(e)) && probe.write {
        opened = share.backend.open(path, probe).await;
    }
    let handle = match opened {
        Ok((handle, _)) => handle,
        Err(e) if is_missing(&e) => return Ok(Probe::Missing(e)),
        Err(e) => return Err(e.to_nt_status().into()),
    };
    let result = match handle.stat().await {
        Ok(info) if opts.delete_on_close && info.read_only => {
            Err(ntstatus::STATUS_CANNOT_DELETE.into())
        }
        Ok(info) => FileRef::register(share, &info, path, req)
            .map(|(file, wait)| Probe::Reserved(file, wait)),
        Err(e) => Err(e.to_nt_status().into()),
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

    #[test]
    fn a_version_2_request_for_a_directory_asks_for_no_write_caching() {
        let context = |v2| {
            LeaseContext {
                key: [1; 16],
                state: 0x7,
                v2,
                ..LeaseContext::default()
            }
            .encode()
        };
        let state = |v2, attributes| {
            lease_request(
                Some(&context(v2)),
                Some(Dialect::Smb311),
                Uuid::nil(),
                attributes,
            )
            .unwrap()
            .unwrap()
            .state
        };
        assert_eq!(state(true, FILE_ATTRIBUTE_DIRECTORY), LeaseState::RH);
        assert_eq!(state(true, 0), LeaseState::RWH);
        assert_eq!(state(false, FILE_ATTRIBUTE_DIRECTORY), LeaseState::RWH);
    }

    fn ctx(name: &[u8; 4], len: usize) -> CreateContext {
        CreateContext {
            name: name.to_vec(),
            data: vec![0; len],
        }
    }

    #[test]
    fn durable_contexts_are_read_by_dialect_and_combination() {
        use DurableAsk as A;
        let q = || ctx(CreateContext::NAME_DHNQ, 16);
        let c = || ctx(CreateContext::NAME_DHNC, 16);
        let q2 = || ctx(CreateContext::NAME_DH2Q, 32);
        let c2 = || ctx(CreateContext::NAME_DH2C, 36);
        let invalid = Err(ntstatus::STATUS_INVALID_PARAMETER);
        let reconnect = Ok(A::Reconnect(DurableReconnect::default()));
        let reconnect_v2 = Ok(A::ReconnectV2(DurableReconnectV2::default()));
        for dialect in [
            Dialect::Smb202,
            Dialect::Smb210,
            Dialect::Smb300,
            Dialect::Smb302,
            Dialect::Smb311,
        ] {
            let v3 = !matches!(dialect, Dialect::Smb202 | Dialect::Smb210);
            let ask = |list: Vec<CreateContext>| durable_ask(&list, Some(dialect));
            assert_eq!(ask(vec![]), Ok(A::None));
            assert_eq!(ask(vec![q()]), Ok(A::V1));
            assert_eq!(ask(vec![c()]), reconnect);
            assert_eq!(ask(vec![c(), q()]), reconnect, "{dialect:?}");
            assert_eq!(ask(vec![ctx(CreateContext::NAME_DHNQ, 15)]), invalid);
            assert_eq!(ask(vec![ctx(CreateContext::NAME_DHNC, 17)]), invalid);
            if v3 {
                assert_eq!(ask(vec![q2()]), Ok(A::V2));
                assert_eq!(ask(vec![c2()]), reconnect_v2);
                for pair in [
                    vec![c(), q2()],
                    vec![c(), c2()],
                    vec![c2(), q()],
                    vec![c2(), q2()],
                    vec![q2(), q()],
                    vec![ctx(CreateContext::NAME_DH2Q, 31)],
                    vec![ctx(CreateContext::NAME_DH2C, 35)],
                ] {
                    assert_eq!(ask(pair), invalid, "{dialect:?}");
                }
            } else {
                // The version 2 contexts do not exist before SMB 3.x.
                assert_eq!(ask(vec![q2()]), Ok(A::None));
                assert_eq!(ask(vec![c2(), q()]), Ok(A::V1));
                assert_eq!(ask(vec![c(), ctx(CreateContext::NAME_DH2Q, 31)]), reconnect);
            }
        }
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
