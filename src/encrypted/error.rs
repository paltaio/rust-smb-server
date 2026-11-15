//! The error of building an encrypted backend.

use thiserror::Error;

use crate::error::SmbError;

/// Why [`EncryptedBackendBuilder::build`](crate::EncryptedBackendBuilder::build)
/// failed.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum EncryptionError {
    /// A setting is outside its range, or cannot go with another setting.
    /// `setting` names the builder method.
    #[error("invalid setting `{setting}`")]
    InvalidSetting { setting: &'static str },
    /// A setting the builder was given differs from the share's. `setting`
    /// names the builder method.
    #[error("setting `{setting}` differs from the share's")]
    SettingMismatch { setting: &'static str },
    /// The key is not the share's: the marker does not verify under it, or
    /// [`restore_marker`](crate::EncryptedBackendBuilder::restore_marker)
    /// found nothing in the share that the key authenticates. A marker with a
    /// changed byte after its version byte also gives this error.
    #[error("the key does not match the share")]
    KeyMismatch,
    /// The root of the inner backend holds entries and no marker.
    /// [`restore_marker`](crate::EncryptedBackendBuilder::restore_marker)
    /// writes a new one.
    #[error("the share has entries and no marker")]
    MarkerMissing,
    /// The marker is not a file of the right size, does not start with the
    /// marker magic, or holds field values outside their ranges. A crash
    /// during the first build can leave a short marker. Deleting a damaged
    /// marker lets
    /// [`restore_marker`](crate::EncryptedBackendBuilder::restore_marker)
    /// write a new one.
    #[error("the marker is not valid")]
    MarkerInvalid,
    /// The marker has a format version this release does not read.
    #[error("format version {version} is not supported")]
    UnsupportedFormat { version: u8 },
    /// The inner backend failed.
    #[error("the inner backend failed")]
    Backend(#[source] SmbError),
    /// The operating system's random generator failed.
    #[error("the random generator failed")]
    Random(#[source] getrandom::Error),
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use super::*;

    #[test]
    fn display_texts() {
        assert_eq!(
            EncryptionError::InvalidSetting {
                setting: "block_size"
            }
            .to_string(),
            "invalid setting `block_size`"
        );
        assert_eq!(
            EncryptionError::SettingMismatch {
                setting: "encrypt_names"
            }
            .to_string(),
            "setting `encrypt_names` differs from the share's"
        );
        assert_eq!(
            EncryptionError::UnsupportedFormat { version: 7 }.to_string(),
            "format version 7 is not supported"
        );
        assert_eq!(
            EncryptionError::Backend(SmbError::DiskFull).to_string(),
            "the inner backend failed"
        );
        assert_eq!(
            EncryptionError::Random(getrandom::Error::UNEXPECTED).to_string(),
            "the random generator failed"
        );
    }

    #[test]
    fn backend_and_random_errors_are_sources() {
        let backend = EncryptionError::Backend(SmbError::DiskFull);
        assert_eq!(backend.source().unwrap().to_string(), "disk full");

        let random = EncryptionError::Random(getrandom::Error::UNEXPECTED);
        assert!(random.source().is_some(), "the random error has a source");
    }
}
