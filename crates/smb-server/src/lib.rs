//! SMB2/3 file-sharing server with pluggable storage backends.
//!
//! See `docs/superpowers/specs/2026-04-27-rust-smb-server-design.md` for the
//! v1 design. The public API is small on purpose:
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

mod backend;
mod builder;
pub(crate) mod conn;
mod dispatch;
mod error;
#[cfg(feature = "localfs")]
mod fs;
mod handlers;
#[allow(dead_code)]
pub(crate) mod info_class;
pub mod ntstatus;
mod path;
#[allow(clippy::upper_case_acronyms, dead_code, unused_imports)]
mod proto;
mod server;
mod utils;

pub use backend::{DirEntry, FileInfo, Handle, OpenIntent, OpenOptions, ShareBackend};
pub use builder::{Access, Share};
#[cfg(feature = "localfs")]
pub use fs::LocalFsBackend;
pub use proto::auth::ntlm::Identity;
pub use server::{ConfigHandle, ShareMode, SmbServer};

pub mod wire {
    pub use crate::proto::header;
    pub use crate::proto::messages;
}

#[cfg(test)]
mod tests {
    mod dynamic_config;
    mod memfs;
}
