//! SMB2/3 file-sharing server with pluggable storage backends.
//!
//! Example:
//!
//! ```no_run
//! use smb_server::{SmbServer, Share, Access, ShareBackend};
//! # async fn run<B: ShareBackend>(backend: B) -> Result<(), Box<dyn std::error::Error>> {
//! SmbServer::builder()
//!     .listen("0.0.0.0:4445".parse()?)
//!     .user("alice", "password")
//!     .share(Share::new("home", backend).user("alice", Access::ReadWrite))
//!     .build()?
//!     .serve()
//!     .await?;
//! # Ok(()) }
//! ```
//!
//! # Writing a backend
//!
//! A share serves any [`ShareBackend`]. Each CREATE calls
//! [`ShareBackend::open`], which returns a [`Handle`] and the
//! [`OpenAction`] it took; CREATE reports the action to the client. The
//! handle serves READ, WRITE, FLUSH, QUERY_INFO, QUERY_DIRECTORY and
//! SET_INFO on that open until the open is closed. `LocalFsBackend`
//! (feature `localfs`) is the reference implementation.
//!
//! What the protocol layer does around the backend calls:
//!
//! - Paths arrive as [`SmbPath`], relative to the share root. `.` components
//!   are dropped; `..`, empty components, `<>:"|?*`, control characters and
//!   stream names are rejected before the backend sees them. The empty path
//!   is the share root.
//! - `open` fails with [`SmbError::PathNotFound`] when a directory on the
//!   way to the path is missing, and with [`SmbError::NotFound`] when only
//!   the last component is. Clients see STATUS_OBJECT_PATH_NOT_FOUND and
//!   STATUS_OBJECT_NAME_NOT_FOUND.
//! - Share permissions and the access the client asked for are checked
//!   before `open`. [`OpenOptions`] carries the result: `read`, `write` and
//!   `write_attributes` reflect the access granted to the open. READ and
//!   WRITE on a handle without the matching access fail before the handle
//!   is called. When [`BackendCapabilities::is_read_only`] is set, trees on
//!   the share get read access only, so opens that ask for write access,
//!   and dispositions that create or truncate, fail before `open`.
//! - Share modes, byte-range locks and the delete-pending flag are kept by
//!   the protocol layer per share, across every connection, keyed by
//!   [`FileInfo::file_index`], or by path when it is 0. Two shares over
//!   the same directory do not see each other's opens. A CREATE that would
//!   truncate first opens the file without truncating it, for reading or,
//!   when reading is refused, with the access the CREATE was granted. It
//!   runs the checks, enters the open in the table and waits for lease
//!   breaks, so the sharing mode holds and clients caching writes have
//!   written back before `open` truncates. When that first open finds no
//!   file, the CREATE calls `open` with [`OpenIntent::Create`] instead and
//!   starts over if the file appeared meanwhile. Any other CREATE refused
//!   by the share-mode check has already called `open` and closes the new
//!   handle again.
//! - [`Handle::close`] runs on every path that ends an open: CLOSE,
//!   TREE_DISCONNECT, LOGOFF, the end of a session or connection, and
//!   [`ConfigHandle`] changes that end sessions or trees. A durable open,
//!   described below, outlives LOGOFF and the end of its connection or
//!   session for a while. Before `close`, [`Handle::set_times`] puts back
//!   access and write times that FileBasicInformation froze or set through
//!   that open.
//! - Delete-on-close: [`OpenOptions::delete_on_close`] and
//!   FileDispositionInformation make the file delete-pending. When its last
//!   open ends, on any of the paths above, the protocol layer calls
//!   [`Handle::close`] and then [`ShareBackend::unlink`] on the file's
//!   current path. `open` doesn't delete anything itself. Read-only files
//!   are refused before that point, and so, for SET_INFO, are directories
//!   that [`Handle::dir_is_empty`] reports as not empty. `unlink` returns
//!   [`SmbError::NotEmpty`] for a directory that has entries; the directory
//!   then stays.
//! - A rename through SET_INFO calls [`ShareBackend::rename`] and then moves
//!   the path of every open at or below the old name. Renames on one share
//!   run one at a time. The backend keeps those handles working on the
//!   renamed file.
//! - A CREATE that makes or overwrites a file passes the attributes it asks
//!   for to [`Handle::set_attributes`] when they differ from what
//!   [`Handle::stat`] reports. If that returns [`SmbError::NotSupported`],
//!   it retries with READONLY alone when that was asked for; the CREATE
//!   succeeds either way.
//! - FileBasicInformation passes [`Handle::set_attributes`] and
//!   [`Handle::set_times`] only the values that differ from what
//!   [`Handle::stat`] reports. After a write or truncate, `set_times` also
//!   puts back the times FileBasicInformation froze or set.
//!   [`Handle::truncate`] is never called on a directory.
//! - QUERY_DIRECTORY calls [`Handle::list_dir`] with the search pattern on
//!   the first query and on a restart, then pages through the returned
//!   entries itself. Below the share root it adds `.` and `..`, and opens
//!   the parent directory to describe `..`.
//! - FileStandardInformation and FileAllInformation report
//!   [`Handle::link_count`] as NumberOfLinks, and DeletePending when the
//!   file is delete-pending or has no links left. The filesystem
//!   QUERY_INFO classes, and the VolumeId of the on-disk id CREATE context,
//!   come from [`ShareBackend::volume_info`].
//! - Leases: on every share unless [`Share::leases`] turns them off, files
//!   get read, handle and write caching leases. A client holding one
//!   caches what it reads, keeps files open after its applications close
//!   them, and caches writes while every other open of the file holds the
//!   same lease or is attribute-only. An open, write, size change,
//!   byte-range lock, rename or delete made through an open that does not
//!   hold the lease breaks it when it needs what the lease caches, whether
//!   that open belongs to another client or to the same client under
//!   another lease key or none; attribute-only opens and opens holding the
//!   same lease break nothing. An open or rename that needs the client to
//!   write back or close first waits until the client acknowledges the
//!   break or closes, or until the break times out 35 seconds after the
//!   server sent it; meanwhile its backend handle stays open, except for
//!   one that truncates, which calls `open` after the wait. A byte-range
//!   lock asked for while another lease still caches writes is refused
//!   with STATUS_LOCK_NOT_GRANTED until that client has written back.
//!   Changes made outside the server, including through another share over
//!   the same directory, break nothing: clients keep serving stale cached
//!   data. Turn leases off on such shares.
//! - Durable handles: on a share with leases, unless
//!   [`Share::durable_handles`] turns them off, a file opened with a
//!   durable handle request (DHnQ, or DH2Q on SMB 3.x) and a lease that
//!   caches handles stays open when the client's connection drops, when it
//!   logs off, when its session's reauthentication fails, or when a new
//!   session names its session as the previous one. A request without such
//!   a lease gets an open that is not durable and no durable context in the
//!   response. The backend handle stays open, and the file keeps its share
//!   mode, byte-range locks and lease, for
//!   [`SmbServerBuilder::durable_handle_timeout`], or for the time a DH2Q
//!   asked for, up to that timeout or 5 minutes, whichever is longer; the
//!   DH2Q response carries the time granted. The PERSISTENT flag is
//!   ignored. A file whose lease is being broken, or that holds byte-range
//!   locks under a lease that does not cache writes, closes with its
//!   session instead. Meanwhile the same user, from the same client, takes
//!   the file back with a durable handle reconnect (DHnC, or DH2C naming
//!   the CreateGuid of a DH2Q open) on a tree of the same share that names
//!   the file and its lease; the backend handle, share mode, byte-range
//!   locks and lease carry on, and later lease breaks go to the new
//!   connection. A reconnect fails with STATUS_ACCESS_DENIED from another
//!   user, STATUS_INVALID_PARAMETER for a DHnC naming another file, and
//!   STATUS_INSUFFICIENT_RESOURCES past the connection's open limit; from
//!   another client, on another share, naming another lease, lease version
//!   or CreateGuid, a DH2C naming another file, or for a file that is not
//!   kept, with STATUS_OBJECT_NAME_NOT_FOUND. The file stays kept after a
//!   failed reconnect. One that comes while the connection holding the file
//!   is still closing waits up to 5 seconds for it. A file whose rights
//!   exceed what the user's tree on the share grants now is closed instead
//!   of reconnected. [`Handle::close`] runs when the time runs out; at once
//!   when an open, write, size change, byte-range lock, rename or delete
//!   through an open that does not hold the lease needs what the lease
//!   caches, or when the lease stops caching handles; on [`ConfigHandle`]
//!   changes that end the user's sessions or the share's trees; and at
//!   shutdown. At most [`SmbServerBuilder::max_disconnected_opens`] files
//!   are kept at once, and a quarter of that, rounded up, for one user;
//!   past that, files close with their session. Anonymous sessions and
//!   clients that send a nil ClientGuid get no durable handle. A DH2Q that
//!   repeats the CreateGuid of a live version 2 open of the same client,
//!   with access to its data or to delete it, fails with
//!   STATUS_DUPLICATE_OBJECTID unless it is marked as a replay; one marked
//!   as a replay opens the file anew rather than answering with that
//!   open.
//! - READ and WRITE lengths are bounded by the negotiated maximum sizes.
//! - Each [`SmbError`] maps to one NTSTATUS for the client; see
//!   [`SmbError::to_nt_status`].
//!
//! A handle is dropped without [`Handle::close`] when the task serving its
//! connection panics or is cancelled, and when a [`ConfigHandle`] call that
//! ends its session or tree is cancelled, so release resources in `Drop` as
//! well.
//!
//! Later releases may add methods with default bodies, fields to
//! [`FileInfo`], [`BackendCapabilities`] and [`VolumeInfo`], and variants
//! to [`OpenIntent`]. A backend that implements the required methods,
//! builds those types through [`FileInfo::new`] and the `Default` impls, and
//! matches `OpenIntent` with a wildcard arm keeps compiling.

mod access_mask;
mod auth_policy;
mod backend;
mod builder;
pub(crate) mod conn;
mod dispatch;
mod error;
mod files;
#[cfg(feature = "localfs")]
mod fs;
mod handlers;
pub(crate) mod info_class;
pub mod ntstatus;
mod path;
mod proto;
mod server;
#[cfg(test)]
mod tests {
    mod async_requests;
    mod durable;
    mod dynamic_config;
    pub(crate) mod memfs;
    pub(crate) mod peer;
}
mod utils;
mod wildcard;

pub use backend::{
    BackendCapabilities, DirEntry, FileInfo, FileTimes, Handle, OpenAction, OpenIntent,
    OpenOptions, ShareBackend, VolumeInfo,
};
pub use builder::{Access, BuildError, Share, SmbServerBuilder};
pub use bytes::Bytes;
pub use error::{SmbError, SmbResult};
pub use files::{
    DEFAULT_DURABLE_HANDLE_TIMEOUT, DEFAULT_MAX_DISCONNECTED_OPENS, DEFAULT_MAX_LOCKS_PER_OPEN,
    DEFAULT_MAX_OPENS_PER_CONNECTION,
};
#[cfg(feature = "localfs")]
pub use fs::LocalFsBackend;
pub use path::SmbPath;
pub use proto::auth::ntlm::Identity;
pub use server::{ConfigError, ConfigHandle, ShareMode, ShutdownHandle, SmbServer};

pub mod wire {
    pub use crate::proto::header;
    pub use crate::proto::messages;
}

/// Entry points for the cargo-fuzz targets in `fuzz/`. Built only with
/// `--cfg fuzzing`, which `cargo fuzz` sets.
#[cfg(fuzzing)]
#[doc(hidden)]
pub mod fuzzing {
    use std::sync::Arc;

    use crate::conn::state::Connection;
    use crate::proto::auth::{ntlm, spnego};
    use crate::proto::framing;
    use crate::proto::header::Smb2Header;

    /// Decodes the start of `data` as a transport frame header.
    pub fn frame(data: &[u8]) {
        if let Some(hdr) = data.first_chunk::<{ framing::FRAME_HEADER_LEN }>() {
            let _ = framing::decode_frame_header(hdr);
        }
    }

    /// Parses `data` as an SMB2 header.
    pub fn header(data: &[u8]) {
        let _ = Smb2Header::parse(data);
    }

    /// Decodes `data` as a SPNEGO NegTokenInit and as a NegTokenResp.
    pub fn spnego(data: &[u8]) {
        let _ = spnego::decode_init_token(data);
        let _ = spnego::decode_resp_token(data);
    }

    /// Parses `data` as each NTLM message the server receives.
    pub fn ntlm(data: &[u8]) {
        let _ = ntlm::NtlmNegotiate::parse(data);
        let _ = ntlm::NtlmAuthenticate::parse(data);
    }

    /// Parses `data` as the data of a lease create context.
    pub fn lease_context(data: &[u8]) {
        let _ = crate::proto::messages::LeaseContext::parse(data);
    }

    /// Parses `data` as a lease break acknowledgment.
    pub fn lease_ack(data: &[u8]) {
        let _ = crate::proto::messages::LeaseBreakAck::parse(data);
    }

    /// Parses `data` as the data of each durable handle create context.
    pub fn durable_context(data: &[u8]) {
        use crate::proto::messages::{
            DurableReconnect, DurableReconnectV2, DurableRequest, DurableRequestV2,
        };
        let _ = DurableRequest::parse(data);
        let _ = DurableReconnect::parse(data);
        let _ = DurableRequestV2::parse(data);
        let _ = DurableReconnectV2::parse(data);
    }

    /// Parses `data` as a create context chain and reads its durable handle
    /// contexts on each dialect.
    pub fn durable_ask(data: &[u8]) {
        use crate::proto::messages::{CreateContext, Dialect};
        let Ok(contexts) = CreateContext::parse_chain(data) else {
            return;
        };
        for dialect in [
            None,
            Some(Dialect::Smb202),
            Some(Dialect::Smb210),
            Some(Dialect::Smb300),
            Some(Dialect::Smb302),
            Some(Dialect::Smb311),
            Some(Dialect::Smb2Wildcard),
        ] {
            let _ = crate::handlers::create::durable_ask(&contexts, dialect);
        }
    }

    /// Dispatches one frame payload on a fresh connection to `server`.
    pub async fn dispatch(server: &crate::SmbServer, frame: &[u8]) -> Option<Vec<u8>> {
        let state = server.state();
        let conn = Arc::new(Connection::new(
            state.config.server_guid,
            state.config.max_read_size,
            state.config.max_write_size,
        ));
        crate::dispatch::dispatch_frame(&state, &conn, frame)
            .await
            .map(|out| out.bytes)
    }
}
