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
//! [`ShareBackend::open`], and the returned [`Handle`] serves READ, WRITE,
//! FLUSH, QUERY_INFO, QUERY_DIRECTORY and SET_INFO on that open until CLOSE.
//! `LocalFsBackend` (feature `localfs`) is the reference implementation.
//!
//! What the protocol layer does around the backend calls:
//!
//! - Paths arrive as [`SmbPath`], relative to the share root. `.` components
//!   are dropped; `..`, empty components, `<>:"|?*`, control characters and
//!   stream names are rejected before the backend sees them. The empty path
//!   is the share root.
//! - Share permissions and the access the client asked for are checked
//!   before `open`. [`OpenOptions`] carries the result: `read`, `write` and
//!   `write_attributes` reflect the access granted to the open. READ and
//!   WRITE on a handle without the matching access fail before the handle
//!   is called. When [`BackendCapabilities::is_read_only`] is set, trees on
//!   the share get read access only, so opens that ask for write access,
//!   and dispositions that create or truncate, fail before `open`.
//! - Delete-on-close: [`OpenOptions::delete_on_close`] and
//!   FileDispositionInformation are recorded on the open. At CLOSE the
//!   protocol layer calls [`Handle::close`] and then
//!   [`ShareBackend::unlink`] on the open's current path. `open` doesn't
//!   delete anything itself. Read-only files and, for SET_INFO, non-empty
//!   directories are refused before that point; `unlink` returns
//!   [`SmbError::NotEmpty`] for a directory that has entries.
//! - A rename through SET_INFO calls [`ShareBackend::rename`] and then moves
//!   the path of every open at or below the old name. The backend keeps
//!   those handles working on the renamed file.
//! - FileBasicInformation passes [`Handle::set_attributes`] and
//!   [`Handle::set_times`] only the values that differ from what
//!   [`Handle::stat`] reports. After a write or truncate and at CLOSE,
//!   `set_times` also puts back access and write times the client fixed on
//!   that open. [`Handle::truncate`] is never called on a directory.
//! - QUERY_DIRECTORY calls [`Handle::list_dir`] on the first query and on a
//!   restart, then pages through the returned entries itself.
//! - READ and WRITE lengths are bounded by the negotiated maximum sizes.
//! - Each [`SmbError`] maps to one NTSTATUS for the client; see
//!   [`SmbError::to_nt_status`].
//!
//! A handle can be dropped without [`Handle::close`], for example when its
//! connection ends, so release resources in `Drop` as well.
//!
//! Later releases may add trait methods with default bodies next to the
//! existing ones, as [`Handle::write_owned`] sits next to [`Handle::write`].
//! A backend that implements the required methods keeps compiling.

mod access_mask;
mod backend;
mod builder;
pub(crate) mod conn;
mod dispatch;
mod error;
#[cfg(feature = "localfs")]
mod fs;
mod handlers;
pub(crate) mod info_class;
pub mod ntstatus;
mod path;
mod proto;
mod server;
mod utils;

pub use backend::{
    BackendCapabilities, DirEntry, FileInfo, FileTimes, Handle, OpenIntent, OpenOptions,
    ShareBackend,
};
pub use builder::{Access, BuildError, Share, SmbServerBuilder};
pub use bytes::Bytes;
pub use error::{SmbError, SmbResult};
#[cfg(feature = "localfs")]
pub use fs::LocalFsBackend;
pub use path::SmbPath;
pub use proto::auth::ntlm::Identity;
pub use server::{ConfigError, ConfigHandle, ShareMode, ShutdownHandle, SmbServer};

pub mod wire {
    pub use crate::proto::header;
    pub use crate::proto::messages;
}

pub use backend::OpenAction;

mod files;

#[cfg(test)]
mod tests {
    mod dynamic_config;
    pub(crate) mod memfs;
}

mod auth_policy;
mod wildcard;

pub use backend::VolumeInfo;

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

    /// Dispatches one frame payload on a fresh connection to `server`.
    pub async fn dispatch(server: &crate::SmbServer, frame: &[u8]) -> Option<Vec<u8>> {
        let state = server.state();
        let conn = Arc::new(Connection::new(
            state.config.server_guid,
            state.config.max_read_size,
            state.config.max_write_size,
        ));
        crate::dispatch::dispatch_frame(&state, &conn, frame).await
    }
}
