//! Backend that stores file contents and names encrypted under a caller key.

mod backend;
mod base32;
mod block;
mod builder;
mod cache;
mod change;
mod clear;
mod content;
mod create;
#[cfg(test)]
mod disk_full;
mod error;
mod format;
mod handle;
mod header;
mod inner;
mod keys;
mod list;
#[cfg(test)]
mod listing_races;
mod locks;
mod lru;
mod marker;
mod names;
mod node;
#[cfg(test)]
mod open_races;
mod random;
mod rename;
mod resolve;
mod restore;
mod scan;
mod setup;
mod size;
#[cfg(test)]
pub(crate) mod testing;
mod truncate;
mod unlink;
mod write;
#[cfg(test)]
mod wycheproof_gcm;
#[cfg(test)]
mod wycheproof_siv;

pub use backend::EncryptedBackend;
pub use builder::EncryptedBackendBuilder;
pub use error::EncryptionError;
