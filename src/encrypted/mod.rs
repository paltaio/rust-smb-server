//! Backend that stores file contents and names encrypted under a caller key.

mod backend;
mod base32;
mod block;
mod builder;
mod change;
mod clear;
mod content;
#[cfg(test)]
mod disk_full;
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
mod random;
mod restore;
mod setup;
mod size;
#[cfg(test)]
mod testing;
mod truncate;
mod write;
#[cfg(test)]
mod wycheproof_gcm;
#[cfg(test)]
mod wycheproof_siv;

pub use backend::EncryptedBackend;
pub use builder::EncryptedBackendBuilder;
pub use error::EncryptionError;
