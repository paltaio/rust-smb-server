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

#[cfg(test)]
mod tests {
    mod dynamic_config;
    pub(crate) mod memfs;
}
