//! Backend that stores file contents and names encrypted under a caller key.

mod backend;
mod base32;
mod block;
mod builder;
mod clear;
mod content;
mod error;
mod format;
mod handle;
mod header;
mod inner;
mod keys;
mod locks;
mod marker;
mod names;
mod node;
#[cfg_attr(not(test), expect(dead_code, reason = "only tests call it"))]
mod random;
mod restore;
mod setup;
mod size;
#[cfg(test)]
mod testing;
#[cfg(test)]
mod wycheproof_gcm;
#[cfg(test)]
mod wycheproof_siv;

pub use backend::EncryptedBackend;
pub use builder::EncryptedBackendBuilder;
pub use error::EncryptionError;
