//! CREATE handler: open or create a file/directory and allocate a FileId.

use std::collections::HashSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use crate::proto::header::{SMB2_FLAGS_REPLAY_OPERATION, Smb2Header};
use crate::proto::messages::change_notify::{
    FILE_ACTION_ADDED, FILE_ACTION_ADDED_STREAM, FILE_ACTION_MODIFIED, FILE_ACTION_MODIFIED_STREAM,
    FILE_ACTION_REMOVED_STREAM, FILE_NOTIFY_CHANGE_ATTRIBUTES, FILE_NOTIFY_CHANGE_DIR_NAME,
    FILE_NOTIFY_CHANGE_EA, FILE_NOTIFY_CHANGE_FILE_NAME, FILE_NOTIFY_CHANGE_STREAM_NAME,
};
use crate::proto::messages::{
    AaplQuery, CreateContext, CreateRequest, CreateResponse, Dialect, DurableReconnect,
    DurableReconnectV2, DurableRequest, DurableRequestV2, DurableResponse, DurableResponseV2,
    FileId, LeaseContext, OplockLevel,
};
use tokio::time::Instant;
use tracing::{debug, warn};
use uuid::Uuid;

use crate::access_mask::{
    DELETE, FILE_APPEND_DATA, FILE_EXECUTE, FILE_READ_DATA, FILE_WRITE_ATTRIBUTES, FILE_WRITE_DATA,
    granted_access, maximal_access,
};
use crate::backend::{
    FILE_ATTRIBUTE_ARCHIVE, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_HIDDEN,
    FILE_ATTRIBUTE_NOT_CONTENT_INDEXED, FILE_ATTRIBUTE_READONLY, FILE_ATTRIBUTE_SYSTEM, FileInfo,
    FileTimes, Handle, OpenAction, OpenIntent, OpenOptions, VALID_SET_ATTRIBUTES,
};
use crate::conn::pending::{Stop, stopped};
use crate::conn::state::{Connection, Open};
use crate::dispatch::HandlerResponse;
use crate::ea::{self, Ea};
use crate::error::SmbError;
use crate::files::{
    BreakWait, CONTENT_CHANGED, Change, Closing, Durability, FileRef, Granted, LeaseId, LeaseRef,
    LeaseRequest, LeaseState, LeaseVersion, MAX_BREAK_WAIT, OpenRequest, OpenSlot, Refused,
    STREAM_BASE_CHANGED, STREAM_CHANGED, Sharing, Trigger, finish_close, v2_timeout,
};
use crate::handlers::aapl;
use crate::handlers::reconnect::{self, Reconnect};
use crate::handlers::shared::{lookup_session, lookup_session_tree};
use crate::handlers::{Outcome, Pending};
use crate::info_class::VOLUME_SERIAL_NUMBER;
use crate::ntstatus;
use crate::path::SmbPath;
use crate::proto::auth::ntlm::Identity;
use crate::server::{ServerState, ShareBindings};
use crate::stream::{
    StreamHandle, StreamName, StreamPart, data_stream_info, parse_create_name, stream_error,
    unsupported,
};
use crate::utils::utf16le_to_units;

// CreateOptions
const FILE_DIRECTORY_FILE: u32 = 0x0000_0001;
const FILE_WRITE_THROUGH: u32 = 0x0000_0002;
pub(crate) const FILE_NO_INTERMEDIATE_BUFFERING: u32 = 0x0000_0008;
const FILE_SYNCHRONOUS_IO_ALERT: u32 = 0x0000_0010;
const FILE_SYNCHRONOUS_IO_NONALERT: u32 = 0x0000_0020;
const FILE_NON_DIRECTORY_FILE: u32 = 0x0000_0040;
const FILE_COMPLETE_IF_OPLOCKED: u32 = 0x0000_0100;
const FILE_NO_EA_KNOWLEDGE: u32 = 0x0000_0200;
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
pub(super) const FILE_OPENED: u32 = 0x0000_0001;
const FILE_CREATED: u32 = 0x0000_0002;
const FILE_OVERWRITTEN: u32 = 0x0000_0003;

/// Offset of the response create contexts from the start of the SMB2
/// header: 64 + 88.
const RESPONSE_CONTEXTS_OFFSET: u32 = 0x98;

/// Access that makes a version 2 durable open one a replayed CREATE may
/// name (MS-SMB2 3.3.5.9.10, Open.IsReplayEligible).
const REPLAYABLE_ACCESS: u32 =
    FILE_READ_DATA | FILE_EXECUTE | FILE_WRITE_DATA | FILE_APPEND_DATA | DELETE;

/// Caching the server grants in a lease.
const GRANTABLE_LEASE: LeaseState = LeaseState::RWH;

/// Create contexts of a request that the response answers (MS-SMB2
/// 3.3.5.9.5, 3.3.5.9.9) or that fail it. Other contexts are ignored.
pub(super) struct ContextQueries {
    /// QUERY_MAXIMAL_ACCESS, with its timestamp if it has one.
    maximal_access: Option<Option<u64>>,
    query_on_disk_id: bool,
    /// Data of an EA buffer (MS-SMB2 3.3.5.9.1).
    ea_buffer: Option<Vec<u8>>,
    /// A timewarp token, which needs snapshots (MS-SMB2 3.3.5.9.4).
    timewarp: bool,
    /// Data of a lease request.
    lease: Option<Vec<u8>>,
    durable: DurableAsk,
    /// Data of Apple's `AAPL` context.
    aapl: Option<Vec<u8>>,
}

/// The durable handle a CREATE asks for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DurableAsk {
    None,
    /// DHnQ (MS-SMB2 3.3.5.9.6).
    V1,
    /// DH2Q, on SMB 3.x (MS-SMB2 3.3.5.9.10).
    V2(DurableRequestV2),
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
        (None, None, Some(request), None) => DurableAsk::V2(request),
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
            ea_buffer: find(CreateContext::NAME_EXTA).map(|c| c.data.clone()),
            timewarp: find(CreateContext::NAME_TWRP).is_some(),
            lease: find(CreateContext::NAME_RQLS).map(|c| c.data.clone()),
            durable: durable_ask(&contexts, dialect).ok()?,
            aapl: find(CreateContext::NAME_AAPL).map(|c| c.data.clone()),
        })
    }

    /// Response contexts for an open of a file with `info` on a tree whose
    /// MaximalAccess is `maximal`, on the volume with serial number
    /// `volume_serial`.
    pub(super) fn answer(
        &self,
        info: &FileInfo,
        maximal: u32,
        volume_serial: u32,
    ) -> Vec<CreateContext> {
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
pub(super) fn lease_response(granted: &Granted) -> CreateContext {
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
    /// The named stream to open.
    stream: Option<StreamName>,
    intent: OpenIntent,
    options: u32,
    create_disposition: u32,
    open_access: u32,
    maximal: u32,
    delete_on_close: bool,
    /// Attributes for a file this CREATE makes or overwrites.
    new_attributes: u32,
    /// Extended attributes for a file this CREATE makes, overwrites or
    /// supersedes, or the status that refuses them there.
    eas: Result<Vec<Ea>, u32>,
    /// The CREATE opens a named stream and carries an `ExtA` context,
    /// which needs the stream's file to exist.
    stream_exta: bool,
    /// FILE_NO_EA_KNOWLEDGE on a share with extended attributes, on an
    /// open of a file's default stream or of a directory.
    no_ea_knowledge: bool,
    opts: OpenOptions,
    sharing: Sharing,
    queries: ContextQueries,
    lease: Option<LeaseRequest>,
    /// The `AAPL` server query to answer.
    aapl: Option<AaplQuery>,
    /// The configured name of the session's user; `None` for anonymous.
    owner: Option<String>,
}

/// What a CREATE asks for.
enum Request {
    Open(CreateArgs),
    Reconnect(Reconnect),
}

impl CreateArgs {
    /// Checks the request against the tree it targets (MS-SMB2 3.3.5.9).
    async fn parse(
        server: &ServerState,
        conn: &Arc<Connection>,
        hdr: &Smb2Header,
        body: &[u8],
    ) -> Result<Request, u32> {
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
            DurableAsk::Reconnect(r) => Some((r.file_id, None)),
            DurableAsk::ReconnectV2(r) => Some((r.file_id, Some(r.create_guid))),
            _ => None,
        };
        if let Some((file_id, create_guid)) = reconnect {
            let lease = lease_request(queries.lease.as_deref(), dialect, client, 0)?;
            let name = utf16le_to_units(&req.name)
                .and_then(|u| parse_create_name(&u).ok())
                .and_then(|(path, stream)| match stream {
                    StreamPart::Named(name) => Some((path, Some(name))),
                    StreamPart::NamedDirectory(_) => None,
                    _ => Some((path, None)),
                });
            return Ok(Request::Reconnect(Reconnect {
                file_id,
                create_guid,
                name,
                owner,
                client,
                lease,
                queries,
            }));
        }

        // Decode path.
        let units = utf16le_to_units(&req.name).ok_or(ntstatus::STATUS_INVALID_PARAMETER)?;
        let (path, stream) =
            parse_create_name(&units).map_err(|_| ntstatus::STATUS_OBJECT_NAME_INVALID)?;
        if let StreamPart::Named(name) | StreamPart::NamedDirectory(name) = &stream
            && !share.named_streams
        {
            debug!(path = %path, stream = ?name.as_str(), "share without named streams");
            // A volume with neither refuses the extended attributes first.
            if queries
                .ea_buffer
                .as_ref()
                .is_some_and(|data| !data.is_empty())
                && !share.extended_attributes
            {
                return Err(ntstatus::STATUS_EAS_NOT_SUPPORTED);
            }
            return Err(ntstatus::STATUS_OBJECT_NAME_INVALID);
        }

        // Translate disposition.
        let mut intent = match req.create_disposition {
            FILE_SUPERSEDE | FILE_OVERWRITE_IF => OpenIntent::OverwriteOrCreate,
            FILE_OPEN => OpenIntent::Open,
            FILE_CREATE => OpenIntent::Create,
            FILE_OPEN_IF => OpenIntent::OpenOrCreate,
            FILE_OVERWRITE => OpenIntent::Truncate,
            _ => return Err(ntstatus::STATUS_INVALID_PARAMETER),
        };

        let options = req.create_options;
        if options & (FILE_OPEN_BY_FILE_ID | FILE_RESERVE_OPFILTER) != 0 {
            let on_stream = matches!(stream, StreamPart::Named(_) | StreamPart::NamedDirectory(_));
            return Err(unsupported(on_stream));
        }
        let mut directory = options & FILE_DIRECTORY_FILE != 0;
        let mut non_directory = options & FILE_NON_DIRECTORY_FILE != 0;
        if directory
            && (options & !DIRECTORY_OPTIONS != 0
                || !matches!(
                    intent,
                    OpenIntent::Create | OpenIntent::OpenOrCreate | OpenIntent::Open
                ))
        {
            return Err(ntstatus::STATUS_INVALID_PARAMETER);
        }
        // MS-FSA 2.1.5.1 phase 7, after the option checks of phase 1, which
        // look at FILE_DIRECTORY_FILE only: `::$DATA` opens the data of a
        // file, `::$INDEX_ALLOCATION` a directory, and a named stream the
        // stream of a file or directory. The backend never gets both
        // `directory` and `non_directory`.
        match &stream {
            StreamPart::Data if directory => return Err(ntstatus::STATUS_NOT_A_DIRECTORY),
            StreamPart::Data => non_directory = true,
            StreamPart::Directory => {
                directory = true;
                non_directory = false;
            }
            StreamPart::NamedDirectory(_) => return Err(ntstatus::STATUS_INVALID_PARAMETER),
            StreamPart::Named(_) if directory => return Err(ntstatus::STATUS_NOT_A_DIRECTORY),
            StreamPart::Named(_) | StreamPart::None => {}
        }
        let named = match &stream {
            StreamPart::Named(name) => Some(name.clone()),
            _ => None,
        };

        if queries.timewarp {
            // There are no snapshots, so none matches the token.
            return Err(ntstatus::STATUS_OBJECT_NAME_NOT_FOUND);
        }
        let no_ea_knowledge =
            options & FILE_NO_EA_KNOWLEDGE != 0 && share.extended_attributes && named.is_none();
        let aapl = match (&queries.aapl, &server.config.apple_model) {
            (Some(data), Some(_)) => {
                Some(AaplQuery::parse(data).map_err(|_| ntstatus::STATUS_INVALID_PARAMETER)?)
            }
            _ => None,
        };
        // Shares that turn leases off grant none. A named stream, of a file
        // or a directory, gets its own lease; a directory gets none, but
        // its request still fails on a key held elsewhere.
        let lease = if req.requested_oplock_level == OplockLevel::Lease as u8 && share.leases {
            lease_request(
                queries.lease.as_deref(),
                dialect,
                client,
                req.file_attributes,
            )?
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

        let (eas, stream_exta) = match &queries.ea_buffer {
            Some(data) => create_eas(&share, data, named.is_some(), options)?,
            None => (Ok(Vec::new()), false),
        };

        if stream == StreamPart::Directory
            && matches!(intent, OpenIntent::OverwriteOrCreate | OpenIntent::Truncate)
        {
            intent = overwritten_directory(&share, &path, intent).await?;
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
            stream: named,
            intent,
            options,
            create_disposition: req.create_disposition,
            open_access,
            maximal,
            delete_on_close,
            new_attributes,
            eas,
            stream_exta,
            no_ea_knowledge,
            opts,
            sharing: Sharing {
                access: open_access,
                share: req.share_access,
            },
            queries,
            lease,
            aapl,
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
    /// The open made the file, which has yet to get the extended
    /// attributes of the CREATE; a CREATE that gives up removes it again.
    made_without_eas: bool,
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

    /// Gives up what a waiting CREATE holds, closing its backend handle. A
    /// file it made that still lacks the CREATE's extended attributes goes
    /// again, as on delete-on-close.
    async fn release(self) {
        if let Stage::Reserved(reserved) = self {
            let Reserved {
                file,
                opened,
                made_without_eas,
                ..
            } = *reserved;
            match opened {
                Some((handle, _)) if made_without_eas => {
                    let is_directory = file.is_directory();
                    finish_close(
                        Some(handle.take()),
                        Some(file),
                        true,
                        is_directory,
                        Closing::ReadOnly,
                        false,
                    )
                    .await;
                }
                Some((handle, _)) => {
                    let _ = handle.take().close().await;
                    drop(file);
                }
                None => drop(file),
            }
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
    let args = match CreateArgs::parse(server, conn, hdr, body).await {
        Ok(Request::Open(args)) => args,
        Ok(Request::Reconnect(r)) => {
            return reconnect::handle(server, conn, hdr, r, retained).await;
        }
        Err(status) => return Outcome::Done(HandlerResponse::err(status)),
    };
    // MS-SMB2 3.3.5.9.10: a version 2 request that repeats the CreateGuid of
    // a live durable open of the same client fails unless it is marked as a
    // replay. A request marked as one is not answered from that open; it
    // opens the file anew.
    if let DurableAsk::V2(request) = args.queries.durable
        && hdr.flags & SMB2_FLAGS_REPLAY_OPERATION == 0
    {
        let client = *conn.client_guid.read().await;
        if server
            .durable
            .create_guid_in_use(client, request.create_guid)
        {
            return Outcome::Done(HandlerResponse::err(ntstatus::STATUS_DUPLICATE_OBJECTID));
        }
    }
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
    // No rename runs from the first backend call until the open is in the
    // file table under `path`, so the open, and the change it reports,
    // carry the name the file had.
    let names = share.files.names_lock().await;
    if args.stream_exta
        && matches!(stage, Stage::Start)
        && let Err(status) = refuse_stream_exta(&share, path, args.create_disposition).await
    {
        return fail(status);
    }

    let stream = args.stream.as_ref();
    let open_request = |overwrite, break_handles| OpenRequest {
        sharing: args.sharing,
        stream: args.stream.clone(),
        owner: Arc::downgrade(&conn.outbound),
        lease: args.lease.map(|l| l.id),
        overwrite,
        supersede: args.create_disposition == FILE_SUPERSEDE && stream.is_none(),
        break_handles,
    };
    let break_handles = stage.break_handles();
    let refused = |refused: Refused, stage: Stage| match refused.wait {
        Some(wait) => Step::Wait(wait, stage),
        None => fail(refused.status),
    };

    let open_failed = |e: Failed| {
        debug!(error = ?e, path = %path, "backend open failed");
        let case_sensitive = backend.capabilities().case_sensitive;
        if matches!(e, Failed::Backend(SmbError::Exists))
            && share.files.delete_pending_at(path, case_sensitive)
        {
            return fail(ntstatus::STATUS_DELETE_PENDING);
        }
        fail(e.status())
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
                ..
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
                Some(l) => match server.leases.acquire(l.id, &share, path, stream) {
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
                let checks = Checks {
                    delete_on_close: args.opts.delete_on_close,
                    no_ea_knowledge: args.no_ea_knowledge,
                    attributes: stream.is_none().then_some(args.new_attributes),
                };
                match reserve_existing(&share, path, stream, args.opts, checks, request).await {
                    Ok(Probe::Reserved(file, Some(wait))) => {
                        let reserved = Reserved {
                            file,
                            slot,
                            lease_ref,
                            opened: None,
                            made_without_eas: false,
                        };
                        return Step::Wait(wait, Stage::Reserved(Box::new(reserved)));
                    }
                    Ok(Probe::Reserved(file, None)) => break (Some(file), None),
                    Ok(Probe::Missing(e)) if args.intent == OpenIntent::Truncate => {
                        return open_failed(e);
                    }
                    Ok(Probe::Missing(_)) => {
                        if stream.is_none()
                            && let Err(status) = &args.eas
                        {
                            return fail(*status);
                        }
                        let create = OpenOptions {
                            intent: OpenIntent::Create,
                            ..args.opts
                        };
                        match open_reported(&share, path, stream, create, false).await {
                            Ok(opened) => break (None, Some(opened)),
                            Err(Failed::Backend(SmbError::Exists)) if tries < 2 => tries += 1,
                            Err(e) => return open_failed(e),
                        }
                    }
                    Err(r) => return refused(r, Stage::AfterHandleBreak),
                }
            };
            (slot, lease_ref, reserved, opened, false)
        }
    };

    // An overwrite or supersede replaces the file's extended attributes
    // before it truncates the file, so a set that fails leaves the file
    // as it was.
    // A directory, which the truncating open refuses, keeps them.
    let mut replaced = None;
    if let (Some(file), None) = (&reserved, &opened)
        && stream.is_none()
        && share.extended_attributes
        && !file.is_directory()
    {
        match replace_eas_of(&share, path, file, args).await {
            Ok(old) => replaced = old,
            Err(status) => return fail(status),
        }
    }
    // A CREATE that would make a file with extended attributes it refuses
    // fails, unless the file is there and the CREATE opens it.
    if let (None, None, Err(status)) = (&reserved, &opened, &args.eas)
        && stream.is_none()
        && matches!(args.intent, OpenIntent::Create | OpenIntent::OpenOrCreate)
        && !exists(&share, path, args.opts).await
    {
        return fail(*status);
    }

    // The open this attempt made, or the one a waiting CREATE kept.
    let (handle, action) = match opened {
        Some(opened) => opened,
        None => match open_reported(&share, path, stream, args.opts, replaced.is_some()).await {
            Ok(opened) => opened,
            Err(e) => {
                // The file stays as it was, its extended attributes too.
                if let (Some(old), Some(file)) = (&replaced, &reserved)
                    && let Err(status) = restore_eas(&share, path, file, &args.eas, old).await
                {
                    return fail(status);
                }
                return open_failed(e);
            }
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
    if action == OpenAction::Opened
        && args.no_ea_knowledge
        && let Err(status) = refuse_needed_eas(handle.as_ref()).await
    {
        let _ = handle.close().await;
        return fail(status);
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
                        made_without_eas: action == OpenAction::Created
                            && stream.is_none()
                            && args.eas.as_ref().is_ok_and(|eas| !eas.is_empty()),
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
    // The streams are marked before another CREATE can open one, and the
    // ones made after the overwrite are left alone.
    let unopened = if action == OpenAction::Overwritten && stream.is_none() && share.named_streams {
        mark_streams(&file, handle.as_ref()).await
    } else {
        Vec::new()
    };
    drop(names);
    file.remove_streams(unopened).await;
    // A new file whose extended attributes cannot be set goes again, as a
    // delete-on-close open of it would, once no other open is on it.
    let new_eas = match &args.eas {
        Ok(eas) if action == OpenAction::Created && stream.is_none() => Ok(eas.as_slice()),
        Err(status) if action == OpenAction::Created && stream.is_none() => Err(*status),
        _ => Ok(&[][..]),
    };
    let made_with_eas = new_eas.is_ok_and(|eas| !eas.is_empty());
    let set = match new_eas {
        Ok(eas) if !eas.is_empty() => {
            let _setting = file.lock_eas().await;
            handle.set_eas(eas).await.map_err(|e| e.to_nt_status())
        }
        Ok(_) => Ok(()),
        Err(status) => Err(status),
    };
    if let Err(status) = set {
        debug!(status, path = %path, "extended attributes of a new file not set");
        let is_directory = info.is_directory;
        finish_close(
            Some(handle),
            Some(file),
            true,
            is_directory,
            Closing::ReadOnly,
            false,
        )
        .await;
        return fail(status);
    }
    let mut granted = None;
    let mut after_send = None;
    if let (Some(lease), Some(lease_ref)) = (args.lease, lease_ref)
        && (stream.is_some() || !info.is_directory)
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
    // MS-SMB2 3.3.5.9.6, 3.3.5.9.10: an open asking for a durable handle
    // gets one when its lease caches handles; any other open gets none and
    // no durable context in the response. Anonymous sessions get none,
    // since they all count as one user, and neither does a client without a
    // ClientGuid. The PERSISTENT flag of a version 2 request is ignored:
    // no share is continuously available.
    let durability = match args.queries.durable {
        DurableAsk::V1 => Some(Durability {
            create_guid: None,
            timeout: server.durable.timeout,
            replay_eligible: false,
        }),
        DurableAsk::V2(request) => Some(Durability {
            create_guid: Some(request.create_guid),
            timeout: v2_timeout(request.timeout_ms, server.durable.timeout),
            replay_eligible: args.open_access & REPLAYABLE_ACCESS != 0,
        }),
        _ => None,
    };
    let durable = match (&granted, &args.owner, durability) {
        (Some(lease), Some(owner), Some(durability))
            if lease.state.contains(LeaseState::H)
                && share.durable_handles
                && !lease.id.client.is_nil() =>
        {
            let lease = (lease.id, lease.version);
            server
                .durable
                .register(owner, &share, lease, durability, conn)
                .map(|reg| (reg, durability))
        }
        _ => None,
    };
    if let Some((reg, _)) = &durable {
        file.mark_durable(&server.durable, reg.id());
    }
    // An overwrite that took the file's place in the table before the
    // backend truncated it broke the leases then; one granted since breaks
    // now, so it does not keep the old contents cached.
    if action == OpenAction::Overwritten {
        file.break_leases(Trigger::Open { overwrite: true });
    }

    // A stream created on a file leaves the file's attributes alone.
    if stream.is_none()
        && let Some(wanted) = new_attributes(args, action, &info)
        && wanted != info.attributes() & VALID_SET_ATTRIBUTES
    {
        apply_attributes(handle.as_ref(), wanted, path).await;
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
        Some((reg, _)) => FileId::new(reg.id(), tree.alloc_volatile()),
        None => tree.alloc_file_id(),
    };
    let (durable, durability) = durable.unzip();
    let open = Open {
        file_id,
        handle: Some(handle),
        granted_access: args.open_access,
        is_directory: info.is_directory && stream.is_none(),
        on_stream: stream.is_some(),
        delete_on_close: args.delete_on_close,
        search_state: None,
        fixed_times: FileTimes::default(),
        create_options: args.options,
        file: Some(file),
        slot: Some(slot),
        durable,
        watch: None,
        wrote: Default::default(),
        created: action != OpenAction::Opened,
        marked_deleted: Default::default(),
        ea_cursor: Default::default(),
        eas_changed: AtomicBool::new(made_with_eas),
        resized: AtomicBool::new(stream.is_some() && action == OpenAction::Overwritten),
        moved_data: false,
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
    if let (Some(query), Some(model)) = (&args.aapl, &server.config.apple_model) {
        answers.insert(0, aapl::reply(conn, &share, query, model));
    }
    if let Some(granted) = &granted {
        answers.push(lease_response(granted));
    }
    if let Some(durability) = durability {
        debug!(
            id = file_id.persistent,
            timeout = ?durability.timeout,
            v2 = durability.create_guid.is_some(),
            "durable open granted"
        );
        answers.push(match durability.create_guid {
            None => CreateContext {
                name: CreateContext::NAME_DHNQ.to_vec(),
                data: DurableResponse.encode(),
            },
            Some(_) => CreateContext {
                name: CreateContext::NAME_DH2Q.to_vec(),
                data: DurableResponseV2 {
                    timeout_ms: u32::try_from(durability.timeout.as_millis()).unwrap_or(u32::MAX),
                    flags: 0,
                }
                .encode(),
            },
        });
    }
    let shown = match stream {
        Some(_) => data_stream_info(info),
        None => info,
    };
    let buf = encode_response(&shown, file_id, granted.is_some(), create_action, &answers);
    let mut response = HandlerResponse::ok(buf);
    if let Some(guard) = after_send {
        response.after_send.push(Box::new(guard));
    }
    Step::Done(response)
}

/// Opens `path`, or its named stream `stream`, on the backend with `opts`
/// and tells the watchers of `share` when that created the file or
/// overwrote it (MS-FSA 2.1.5.1.1, 2.1.5.1.2). The report goes out right
/// after the backend call, so a CREATE that then waits for a lease break,
/// or fails, reports the change it made once. A creation is noted before
/// the call, so the backend's own report of it is left out whenever it
/// arrives. An overwrite of a file whose extended attributes the CREATE
/// replaced (`eas_replaced`) reports that with it.
async fn open_reported(
    share: &ShareBindings,
    path: &SmbPath,
    stream: Option<&StreamName>,
    opts: OpenOptions,
    eas_replaced: bool,
) -> Result<(Box<dyn Handle>, OpenAction), Failed> {
    let names = if opts.directory {
        FILE_NOTIFY_CHANGE_DIR_NAME
    } else {
        FILE_NOTIFY_CHANGE_FILE_NAME
    };
    let added = [Change {
        path,
        stream: None,
        action: FILE_ACTION_ADDED,
        filter: names,
        seen: true,
    }];
    let may_create = !matches!(opts.intent, OpenIntent::Open | OpenIntent::Truncate);
    let expected = may_create.then(|| share.watches.expect(&added, None));
    let (created, opened) = backend_open(share, path, stream, opts).await;
    let action = opened.as_ref().ok().map(|(_, action)| *action);
    let heard = share.named_streams && !share.watches.is_empty();
    // An overwrite of the file reports the removal of each of its named
    // streams first, but for those whose deletion was reported already.
    let removed = match &opened {
        Ok((handle, OpenAction::Overwritten)) if stream.is_none() && heard => {
            let case_sensitive = share.backend.capabilities().case_sensitive;
            match (handle.stat().await, handle.streams().await) {
                (Ok(info), Ok(streams)) => streams
                    .into_iter()
                    .map(|s| s.name)
                    .filter(|name| {
                        !share
                            .files
                            .stream_delete_pending(&info, path, name, case_sensitive)
                    })
                    .collect(),
                (Err(e), _) | (_, Err(e)) => {
                    debug!(error = %stream_error(e), "streams of an overwritten file not listed");
                    Vec::new()
                }
            }
        }
        _ => Vec::new(),
    };
    // The first named stream of a directory changes its attributes.
    let first_of_directory = match &opened {
        Ok((handle, OpenAction::Created)) if stream.is_some() && heard => {
            handle.stat().await.is_ok_and(|info| info.is_directory)
                && handle
                    .streams()
                    .await
                    .is_ok_and(|streams| streams.len() == 1)
        }
        _ => false,
    };
    let mut changes: Vec<Change<'_>> = removed
        .iter()
        .map(|name| Change {
            path,
            stream: Some(name),
            action: FILE_ACTION_REMOVED_STREAM,
            filter: FILE_NOTIFY_CHANGE_STREAM_NAME,
            seen: false,
        })
        .collect();
    let modified = |filter| Change {
        path,
        stream: None,
        action: FILE_ACTION_MODIFIED,
        filter,
        seen: true,
    };
    let of_stream = |action, filter| Change {
        path,
        stream,
        action,
        filter,
        seen: false,
    };
    match (action, stream) {
        (Some(OpenAction::Overwritten), None) => {
            let eas = if eas_replaced {
                FILE_NOTIFY_CHANGE_EA
            } else {
                0
            };
            changes.push(modified(CONTENT_CHANGED | eas));
        }
        (Some(OpenAction::Overwritten), Some(_)) => {
            changes.push(modified(STREAM_BASE_CHANGED));
            changes.push(of_stream(FILE_ACTION_MODIFIED_STREAM, STREAM_CHANGED));
        }
        (Some(OpenAction::Created), Some(_)) => {
            if first_of_directory {
                changes.push(modified(FILE_NOTIFY_CHANGE_ATTRIBUTES));
            }
            changes.push(of_stream(
                FILE_ACTION_ADDED_STREAM,
                FILE_NOTIFY_CHANGE_STREAM_NAME,
            ));
        }
        _ => {}
    }
    match expected {
        Some(expected) if created => {
            let mut all = Vec::from(added);
            all.append(&mut changes);
            expected.report(&share.watches, &all);
        }
        _ if !changes.is_empty() => share.watches.report(&changes),
        _ => {}
    }
    opened
}

/// Why a backend open for a CREATE failed.
#[derive(Debug)]
enum Failed {
    Backend(SmbError),
    /// The status the share's opens refuse it with before the backend
    /// opens it.
    Refused(u32),
}

impl From<SmbError> for Failed {
    fn from(e: SmbError) -> Self {
        Self::Backend(e)
    }
}

impl Failed {
    fn status(&self) -> u32 {
        match self {
            Self::Backend(e) => e.to_nt_status(),
            Self::Refused(status) => *status,
        }
    }

    /// No file or directory is at the path, or on the way to it.
    fn is_missing(&self) -> bool {
        matches!(
            self,
            Self::Backend(SmbError::NotFound | SmbError::PathNotFound)
        )
    }
}

/// Opens `path`, or its named stream `stream`, on the backend of `share`
/// with `opts`, and tells whether that created the file. A stream is opened
/// through its file, as MS-FSA 2.1.5.1 finds the File before the Stream:
/// the file is opened for reading, and created when the disposition may
/// create the stream, then the stream through the file's handle. A stream
/// that comes with a new file counts as created; a file made for a stream
/// that then fails to open is removed again. The caller holds the share's
/// names lock.
async fn backend_open(
    share: &ShareBindings,
    path: &SmbPath,
    stream: Option<&StreamName>,
    opts: OpenOptions,
) -> (bool, Result<(Box<dyn Handle>, OpenAction), Failed>) {
    let backend = share.backend.as_ref();
    let Some(stream) = stream else {
        let opened = backend.open(path, opts).await;
        let created = matches!(opened, Ok((_, OpenAction::Created)));
        return (created, opened.map_err(Failed::from));
    };
    let file_opts = OpenOptions {
        read: true,
        write: false,
        write_attributes: false,
        intent: match opts.intent {
            OpenIntent::Open | OpenIntent::Truncate => OpenIntent::Open,
            _ => OpenIntent::OpenOrCreate,
        },
        directory: false,
        non_directory: false,
        delete_on_close: false,
    };
    let (file, action) = match backend.open(path, file_opts).await {
        Ok(opened) => opened,
        Err(e) => return (false, Err(stream_error(e).into())),
    };
    let created = action == OpenAction::Created;
    let case_sensitive = backend.capabilities().case_sensitive;
    let (info, refused) = match file.stat().await {
        Ok(info) => {
            let refused = stream_refusal(share, &info, path, stream, opts);
            (Some(info), refused)
        }
        Err(e) => (None, Some(Failed::from(stream_error(e)))),
    };
    let opened = match refused {
        Some(refused) => {
            if let Err(e) = file.close().await {
                debug!(error = %e, path = %path, "backend close failed");
            }
            Err(refused)
        }
        None => {
            // On a read-only file a stream is not made, also by FILE_OPEN_IF.
            let read_only = info
                .as_ref()
                .is_some_and(|info| info.read_only && !info.is_directory);
            let intent = match opts.intent {
                OpenIntent::OpenOrCreate if read_only => OpenIntent::Open,
                intent => intent,
            };
            let stream_opts = OpenOptions {
                intent,
                directory: false,
                non_directory: false,
                ..opts
            };
            match backend.open_stream(file, path, stream, stream_opts).await {
                Err(SmbError::NotFound) if intent != opts.intent => {
                    Err(Failed::Refused(ntstatus::STATUS_ACCESS_DENIED))
                }
                opened => opened.map_err(|e| stream_error(e).into()),
            }
        }
    };
    match opened {
        Ok((handle, action)) => {
            let handle: Box<dyn Handle> = Box::new(StreamHandle(handle));
            (
                created,
                Ok((handle, if created { OpenAction::Created } else { action })),
            )
        }
        Err(failed) => {
            // A CREATE of the file itself may have opened it meanwhile; the
            // file then stays.
            let opened_elsewhere = info
                .as_ref()
                .is_none_or(|info| share.files.has_opens(info, path, case_sensitive));
            if created
                && !opened_elsewhere
                && let Err(e) = backend.unlink(path).await
            {
                debug!(error = %e, path = %path, "file made for a stream not removed");
            }
            (false, Err(failed))
        }
    }
}

/// Why the share refuses to open the named stream `stream` of the file
/// `info` describes at `path`, with `opts`, before the backend opens it:
/// the file or the stream is marked for deletion (MS-FSA 2.1.5.1), or the
/// file is read-only, which keeps every stream of it from being written
/// or made (MS-FSA 2.1.5.1.2.1).
fn stream_refusal(
    share: &ShareBindings,
    info: &FileInfo,
    path: &SmbPath,
    stream: &StreamName,
    opts: OpenOptions,
) -> Option<Failed> {
    let case_sensitive = share.backend.capabilities().case_sensitive;
    if share
        .files
        .stream_delete_pending(info, path, stream, case_sensitive)
    {
        return Some(Failed::Refused(ntstatus::STATUS_DELETE_PENDING));
    }
    let writes = opts.write || !matches!(opts.intent, OpenIntent::Open | OpenIntent::OpenOrCreate);
    if info.read_only && !info.is_directory && writes {
        return Some(Failed::Refused(ntstatus::STATUS_ACCESS_DENIED));
    }
    None
}

/// Marks the named streams of the file `handle` just overwrote for
/// deletion, and returns those no open is on, which go at once; the others
/// go when the last open on each closes.
async fn mark_streams(file: &FileRef, handle: &dyn Handle) -> Vec<StreamName> {
    match handle.streams().await {
        Ok(streams) => file.delete_streams(streams.into_iter().map(|s| s.name).collect()),
        Err(e) => {
            debug!(error = %stream_error(e), "streams of an overwritten file not listed");
            Vec::new()
        }
    }
}

/// The CREATE response body for an open of a file with `info`, holding a
/// lease when `leased`, with the response contexts `answers`.
pub(super) fn encode_response(
    info: &FileInfo,
    file_id: FileId,
    leased: bool,
    create_action: u32,
    answers: &[CreateContext],
) -> Vec<u8> {
    let mut contexts = Vec::new();
    CreateContext::encode_chain(answers, &mut contexts).expect("encoding into a Vec cannot fail");
    let resp = CreateResponse {
        structure_size: 89,
        oplock_level: if leased {
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
        allocation_size: info.sizes().1,
        end_of_file: info.sizes().0,
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
    buf
}

/// What the check before a truncating CREATE found.
enum Probe {
    /// No file at the path; the error the open reported.
    Missing(Failed),
    /// The open is in the table, with a wait when clients caching writes
    /// have to write back first.
    Reserved(FileRef, Option<BreakWait>),
}

/// Before a CREATE that truncates the file at `path`, or its named stream
/// `stream`, opens the existing file or stream without truncating it,
/// checks it against delete-on-close and the opens already on it, and
/// enters the new open in the share's table. That open asks for reading,
/// and for the access the CREATE was granted when reading is refused. Only
/// a missing file or stream passes without an entry; any other failure
/// fails the CREATE, as the truncating open would.
async fn reserve_existing(
    share: &Arc<ShareBindings>,
    path: &SmbPath,
    stream: Option<&StreamName>,
    opts: OpenOptions,
    checks: Checks,
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
    let mut opened = backend_open(share, path, stream, read_only).await.1;
    if matches!(opened, Err(ref e) if !e.is_missing()) && probe.write {
        opened = backend_open(share, path, stream, probe).await.1;
    }
    let handle = match opened {
        Ok((handle, _)) => handle,
        Err(e) if e.is_missing() => return Ok(Probe::Missing(e)),
        Err(e) => return Err(e.status().into()),
    };
    let dropped = |info: &FileInfo, asked: u32| {
        info.attributes() & (FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM) & !asked != 0
    };
    let result = match handle.stat().await {
        Ok(info) if checks.attributes.is_some_and(|asked| dropped(&info, asked)) => {
            Err(ntstatus::STATUS_ACCESS_DENIED.into())
        }
        Ok(info) if checks.delete_on_close && info.read_only => {
            Err(ntstatus::STATUS_CANNOT_DELETE.into())
        }
        Ok(info) => {
            let needed = if checks.no_ea_knowledge {
                refuse_needed_eas(handle.as_ref()).await
            } else {
                Ok(())
            };
            needed
                .map_err(Refused::from)
                .and_then(|()| FileRef::register(share, &info, path, req))
                .map(|(file, wait)| Probe::Reserved(file, wait))
        }
        Err(e) => Err(e.to_nt_status().into()),
    };
    let _ = handle.close().await;
    result
}

/// What [`reserve_existing`] checks of the existing file before it takes
/// its place in the table.
#[derive(Clone, Copy)]
struct Checks {
    /// The open asks for delete-on-close, which a read-only file refuses.
    delete_on_close: bool,
    /// The open asks for FILE_NO_EA_KNOWLEDGE.
    no_ea_knowledge: bool,
    /// The attributes of an open that overwrites or supersedes the file
    /// itself, which has to ask for HIDDEN and SYSTEM again where the file
    /// has them (MS-FSA 2.1.5.1.2).
    attributes: Option<u32>,
}

/// STATUS_ACCESS_DENIED for a file that has an extended attribute with
/// FILE_NEED_EA, which an open with FILE_NO_EA_KNOWLEDGE cannot open
/// (MS-FSA 2.1.5.1.2). A file whose attributes cannot be read needs none.
async fn refuse_needed_eas(handle: &dyn Handle) -> Result<(), u32> {
    match handle.eas().await {
        Ok(eas) if eas.iter().any(|ea| ea.needed) => Err(ntstatus::STATUS_ACCESS_DENIED),
        Ok(_) => Ok(()),
        Err(e) => {
            debug!(error = %e, "extended attributes not read for FILE_NO_EA_KNOWLEDGE");
            Ok(())
        }
    }
}

/// The extended attributes of an `ExtA` create context with `data`
/// (MS-SMB2 2.2.13.2.1, 3.3.5.9.1), for a file the CREATE makes,
/// overwrites or supersedes, or the status that refuses them there, and
/// whether the CREATE opens a named stream with them. Empty data carries
/// none. A share without extended attributes fails the CREATE with
/// STATUS_EAS_NOT_SUPPORTED, an open with FILE_NO_EA_KNOWLEDGE with
/// STATUS_ACCESS_DENIED (MS-SMB2 2.2.13), and a malformed list with
/// STATUS_EA_LIST_INCONSISTENT. Names, flags and the size limit count only
/// where the attributes apply. They belong to the file, so an open of one
/// of its named streams leaves them out.
fn create_eas(
    share: &ShareBindings,
    data: &[u8],
    on_stream: bool,
    options: u32,
) -> Result<(Result<Vec<Ea>, u32>, bool), u32> {
    if data.is_empty() {
        return Ok((Ok(Vec::new()), false));
    }
    if !share.extended_attributes {
        return Err(ntstatus::STATUS_EAS_NOT_SUPPORTED);
    }
    if options & FILE_NO_EA_KNOWLEDGE != 0 {
        return Err(ntstatus::STATUS_ACCESS_DENIED);
    }
    ea::check_full_list(data)?;
    if on_stream {
        return Ok((Ok(Vec::new()), true));
    }
    let eas = ea::parse_full_list(data).and_then(|mut eas| {
        ea::dedup(&mut eas);
        eas.retain(|ea| !ea.value.is_empty());
        if ea::stored_length(&eas) > ea::MAX_STORED_LENGTH {
            return Err(ntstatus::STATUS_EA_TOO_LARGE);
        }
        Ok(eas)
    });
    Ok((eas, false))
}

/// Refuses an open of a named stream that carries an `ExtA` context:
/// with STATUS_ACCESS_DENIED when the stream's file is missing, and with
/// STATUS_INVALID_PARAMETER when the open would overwrite the stream.
async fn refuse_stream_exta(
    share: &ShareBindings,
    path: &SmbPath,
    disposition: u32,
) -> Result<(), u32> {
    match share.backend.open(path, OpenOptions::default()).await {
        Ok((file, _)) => {
            let _ = file.close().await;
        }
        Err(SmbError::NotFound) => return Err(ntstatus::STATUS_ACCESS_DENIED),
        Err(e) => return Err(stream_error(e).to_nt_status()),
    }
    if matches!(
        disposition,
        FILE_SUPERSEDE | FILE_OVERWRITE | FILE_OVERWRITE_IF
    ) {
        return Err(ntstatus::STATUS_INVALID_PARAMETER);
    }
    Ok(())
}

/// Whether a file is at `path`, for a CREATE that would make one with
/// extended attributes it refuses: then it fails, and makes nothing.
async fn exists(share: &ShareBindings, path: &SmbPath, opts: OpenOptions) -> bool {
    let probe = OpenOptions {
        read: true,
        write: false,
        write_attributes: false,
        intent: OpenIntent::Open,
        delete_on_close: false,
        ..opts
    };
    match share.backend.open(path, probe).await {
        Ok((file, _)) => {
            let _ = file.close().await;
            true
        }
        Err(e) => !matches!(e, SmbError::NotFound),
    }
}

/// Gives the existing file at `path`, which `file` holds the place of in
/// the table, the extended attributes `args` carries in place of its own,
/// as an overwrite or supersede does. Returns the attributes it had when
/// that changed any.
async fn replace_eas_of(
    share: &ShareBindings,
    path: &SmbPath,
    file: &FileRef,
    args: &CreateArgs,
) -> Result<Option<Vec<Ea>>, u32> {
    let eas = args.eas.as_deref().map_err(|&status| status)?;
    let opts = OpenOptions {
        read: true,
        write: false,
        write_attributes: false,
        intent: OpenIntent::Open,
        delete_on_close: false,
        ..args.opts
    };
    let (handle, _) = share
        .backend
        .open(path, opts)
        .await
        .map_err(|e| e.to_nt_status())?;
    let setting = file.lock_eas().await;
    let replaced = replace_eas(handle.as_ref(), eas).await;
    drop(setting);
    let _ = handle.close().await;
    if matches!(replaced, Ok(Some(_))) {
        file.count_ea_change();
    }
    replaced
}

/// Puts back `old`, the extended attributes the file at `path` had before
/// [`replace_eas_of`] gave it `new`, when the overwrite then failed. A
/// failure to put them back fails the CREATE with an I/O error.
async fn restore_eas(
    share: &ShareBindings,
    path: &SmbPath,
    file: &FileRef,
    new: &Result<Vec<Ea>, u32>,
    old: &[Ea],
) -> Result<(), u32> {
    let new = new.as_deref().unwrap_or_default();
    let restored = async {
        let (handle, _) = share.backend.open(path, OpenOptions::default()).await?;
        let setting = file.lock_eas().await;
        let kept: HashSet<String> = old.iter().map(|ea| ea::name_key(&ea.name)).collect();
        let mut changes: Vec<Ea> = new
            .iter()
            .filter(|ea| !kept.contains(&ea::name_key(&ea.name)))
            .map(|ea| Ea::new(ea.name.as_str(), Vec::new()))
            .collect();
        changes.extend_from_slice(old);
        let result = handle.set_eas(&changes).await;
        drop(setting);
        let _ = handle.close().await;
        result
    };
    match restored.await {
        Ok(()) => {
            file.count_ea_change();
            Ok(())
        }
        Err(e) => {
            warn!(error = %e, path = %path, "extended attributes of a file not put back");
            Err(ntstatus::STATUS_UNEXPECTED_IO_ERROR)
        }
    }
}

/// Replaces the extended attributes of the file `handle` is open on with
/// `eas`. Returns the attributes it had when that changed any.
async fn replace_eas(handle: &dyn Handle, eas: &[Ea]) -> Result<Option<Vec<Ea>>, u32> {
    let new: HashSet<String> = eas.iter().map(|ea| ea::name_key(&ea.name)).collect();
    let old: Vec<Ea> = handle
        .eas()
        .await
        .map_err(|e| e.to_nt_status())?
        .into_iter()
        .filter(|old| ea::valid_name(old.name.as_bytes()))
        .collect();
    let mut changes: Vec<Ea> = old
        .iter()
        .filter(|old| !new.contains(&ea::name_key(&old.name)))
        .map(|old| Ea::new(old.name.as_str(), Vec::new()))
        .collect();
    changes.extend_from_slice(eas);
    if changes.is_empty() {
        return Ok(None);
    }
    handle
        .set_eas(&changes)
        .await
        .map_err(|e| e.to_nt_status())?;
    Ok(Some(old))
}

/// What an overwrite or supersede of `path` as a directory stream
/// (`::$INDEX_ALLOCATION`) does: an existing directory cannot be
/// overwritten, the share root with STATUS_ACCESS_DENIED and any other with
/// STATUS_OBJECT_NAME_COLLISION (MS-FSA 2.1.5.1.2), a file is not a
/// directory (MS-FSA 2.1.5.1 phase 7), and a missing directory is created
/// unless `intent` is [`OpenIntent::Truncate`] (MS-FSA 2.1.5.1 phase 6).
async fn overwritten_directory(
    share: &ShareBindings,
    path: &SmbPath,
    intent: OpenIntent,
) -> Result<OpenIntent, u32> {
    if path.is_root() {
        return Err(ntstatus::STATUS_ACCESS_DENIED);
    }
    let (handle, _) = match share.backend.open(path, OpenOptions::default()).await {
        Ok(opened) => opened,
        Err(SmbError::NotFound) if intent == OpenIntent::OverwriteOrCreate => {
            return Ok(OpenIntent::Create);
        }
        Err(e) => return Err(e.to_nt_status()),
    };
    let info = handle.stat().await;
    let _ = handle.close().await;
    match info {
        Ok(info) if info.is_directory => Err(ntstatus::STATUS_OBJECT_NAME_COLLISION),
        Ok(_) => Err(ntstatus::STATUS_NOT_A_DIRECTORY),
        Err(e) => Err(e.to_nt_status()),
    }
}

/// The attributes the file or directory `info` describes takes from a
/// CREATE that made or overwrote it with `action`: a new file or
/// directory, or a superseded file, has those the CREATE asks
/// for, and an overwritten file adds them to its own. A file also gets
/// ARCHIVE, and NOT_CONTENT_INDEXED in the request is ignored. `None` when
/// nothing is to be set: an open, and a new entry the CREATE asks no
/// attributes for.
fn new_attributes(args: &CreateArgs, action: OpenAction, info: &FileInfo) -> Option<u32> {
    let asked = if info.is_directory {
        args.new_attributes
    } else {
        (args.new_attributes & !FILE_ATTRIBUTE_NOT_CONTENT_INDEXED) | FILE_ATTRIBUTE_ARCHIVE
    };
    match action {
        OpenAction::Opened => None,
        OpenAction::Created if args.new_attributes == 0 => None,
        OpenAction::Overwritten if args.create_disposition != FILE_SUPERSEDE => {
            Some((info.attributes() & VALID_SET_ATTRIBUTES) | asked)
        }
        _ => Some(asked),
    }
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
    async fn an_overwrite_of_a_hidden_or_system_file_has_to_ask_for_those_attributes() {
        use crate::tests::peer::{Peer, status};
        let cases = [
            (FILE_ATTRIBUTE_HIDDEN, 0, ntstatus::STATUS_ACCESS_DENIED),
            (
                FILE_ATTRIBUTE_HIDDEN,
                FILE_ATTRIBUTE_HIDDEN,
                ntstatus::STATUS_SUCCESS,
            ),
            (
                FILE_ATTRIBUTE_SYSTEM,
                FILE_ATTRIBUTE_HIDDEN,
                ntstatus::STATUS_ACCESS_DENIED,
            ),
            (
                FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM,
                FILE_ATTRIBUTE_SYSTEM,
                ntstatus::STATUS_ACCESS_DENIED,
            ),
            (
                FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM,
                FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM,
                ntstatus::STATUS_SUCCESS,
            ),
        ];
        for (has, asked, expected) in cases {
            for disposition in [FILE_OVERWRITE, FILE_OVERWRITE_IF, FILE_SUPERSEDE] {
                let files = MemFsBackend::new()
                    .with_file("f.txt", b"precious")
                    .with_attributes("f.txt", has);
                let state = SmbServer::builder()
                    .listen("127.0.0.1:0".parse().unwrap())
                    .share(Share::new("home", files.clone()).public())
                    .build()
                    .unwrap()
                    .state();
                let mut peer = Peer::new(&state, false).await;
                let mut body = create_body("f.txt", disposition);
                body[28..32].copy_from_slice(&asked.to_le_bytes());
                let (_, reply) = peer.request(&state, Command::Create, &body).await;
                let case = format!("{has:#x} asked {asked:#x} disposition {disposition}");
                assert_eq!(status(&reply), expected, "{case}");
                let left = files.contents("f.txt").unwrap();
                let kept = expected != ntstatus::STATUS_SUCCESS;
                assert_eq!(left == b"precious", kept, "{case}");
            }
        }
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
                assert_eq!(ask(vec![q2()]), Ok(A::V2(DurableRequestV2::default())));
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
    /// A memory backend that claims named streams and opens none.
    struct NoStreams(MemFsBackend);

    #[async_trait]
    impl ShareBackend for NoStreams {
        async fn open(
            &self,
            path: &SmbPath,
            opts: OpenOptions,
        ) -> SmbResult<(Box<dyn Handle>, OpenAction)> {
            self.0.open(path, opts).await
        }

        async fn unlink(&self, path: &SmbPath) -> SmbResult<()> {
            self.0.unlink(path).await
        }

        async fn rename(&self, from: &SmbPath, to: &SmbPath, replace: bool) -> SmbResult<()> {
            self.0.rename(from, to, replace).await
        }

        fn capabilities(&self) -> BackendCapabilities {
            self.0.capabilities()
        }
    }

    #[tokio::test]
    async fn a_file_made_for_a_failed_stream_stays_while_it_is_open() {
        let share = crate::server::ShareBindings::new(
            "s".to_string(),
            Arc::new(NoStreams(MemFsBackend::new())),
            crate::server::ShareMode::Public,
            std::collections::HashMap::new(),
            false,
            true,
            true,
        );
        let path: SmbPath = "new".parse().unwrap();
        let stream: StreamName = "s".parse().unwrap();
        let opts = OpenOptions {
            intent: OpenIntent::OpenOrCreate,
            ..OpenOptions::default()
        };
        let exists = || async {
            share
                .backend
                .open(&path, OpenOptions::default())
                .await
                .is_ok()
        };

        let (created, opened) = backend_open(&share, &path, Some(&stream), opts).await;
        assert!(!created);
        assert_eq!(
            opened.err().map(|e| e.status()),
            Some(ntstatus::STATUS_ACCESS_DENIED)
        );
        assert!(!exists().await, "taken back");

        // Another CREATE has the new file open by the time the stream fails.
        let sharing = Sharing {
            access: FILE_READ_DATA,
            share: 0x7,
        };
        let other = FileRef::register(&share, &FileInfo::new("new"), &path, sharing.into())
            .unwrap()
            .0;
        let (created, opened) = backend_open(&share, &path, Some(&stream), opts).await;
        assert!(!created && opened.is_err());
        assert!(exists().await, "left to the other open");
        drop(other);
    }
}
