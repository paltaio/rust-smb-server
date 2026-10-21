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
//!   truncate first opens the file without write access, runs the checks
//!   and enters the open in the table, so the sharing mode holds while
//!   `open` truncates. Any other CREATE refused by the share-mode check has
//!   already called `open` and closes the new handle again.
//! - [`Handle::close`] runs on every path that ends an open: CLOSE,
//!   TREE_DISCONNECT, LOGOFF, the end of a session or connection, and
//!   [`ConfigHandle`] changes that end sessions or trees. Before it,
//!   [`Handle::set_times`] puts back access and write times that
//!   FileBasicInformation froze or set through that open.
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
    mod dynamic_config;
    pub(crate) mod memfs;
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
pub use files::{DEFAULT_MAX_LOCKS_PER_OPEN, DEFAULT_MAX_OPENS_PER_CONNECTION};
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
