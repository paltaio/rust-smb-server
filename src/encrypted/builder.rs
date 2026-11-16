//! The settings of an [`EncryptedBackend`] and the check that the inner
//! backend holds a share they fit.

use std::fmt;
use std::time::Duration;

use zeroize::Zeroizing;

use super::backend::{EncryptedBackend, Settings};
use super::error::EncryptionError;
use super::format::{BlockShift, MIN_LONG_NAME_THRESHOLD};
use super::keys::KeySchedule;
use super::setup::{Requested, establish};
use crate::backend::ShareBackend;
use crate::utils::fill_random;

const DEFAULT_NAME_CACHE_TTL: Duration = Duration::from_secs(30);

/// Settings of an [`EncryptedBackend`], set through the methods below and
/// applied by [`build`](EncryptedBackendBuilder::build).
///
/// `encrypt_names`, `block_size` and `long_name_threshold` are stored in the
/// share's marker. One that is left alone takes the share's value, or for a
/// new share the default named on its method. `case_insensitive` and
/// `name_cache_ttl` are not stored and default to the values named on their
/// methods.
pub struct EncryptedBackendBuilder<B> {
    inner: B,
    key: Zeroizing<[u8; 32]>,
    encrypt_names: Option<bool>,
    case_insensitive: bool,
    block_size: Option<u32>,
    long_name_threshold: Option<u8>,
    name_cache_ttl: Duration,
    restore_marker: bool,
}

impl<B> fmt::Debug for EncryptedBackendBuilder<B> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EncryptedBackendBuilder")
            .field("key", &format_args!("<redacted>"))
            .field("encrypt_names", &self.encrypt_names)
            .field("case_insensitive", &self.case_insensitive)
            .field("block_size", &self.block_size)
            .field("long_name_threshold", &self.long_name_threshold)
            .field("name_cache_ttl", &self.name_cache_ttl)
            .field("restore_marker", &self.restore_marker)
            .finish_non_exhaustive()
    }
}

impl<B: ShareBackend> EncryptedBackend<B> {
    /// Settings for an encrypted view of `inner` under `key`.
    ///
    /// `build` wipes the builder's buffer for `key` once the keys are derived,
    /// and dropping the builder wipes it too. Copies of `key` that the caller
    /// keeps are the caller's to wipe. The `hmac` and `sha2` crates keep
    /// key-derived bytes in internal state that they do not wipe. The GHASH
    /// subkey of `aes-gcm` is not wiped either: it sits in each cipher and in
    /// copies made during setup and for every operation, and `aes-gcm` wipes
    /// only one temporary copy.
    pub fn builder(inner: B, key: [u8; 32]) -> EncryptedBackendBuilder<B> {
        EncryptedBackendBuilder {
            inner,
            key: Zeroizing::new(key),
            encrypt_names: None,
            case_insensitive: true,
            block_size: None,
            long_name_threshold: None,
            name_cache_ttl: DEFAULT_NAME_CACHE_TTL,
            restore_marker: false,
        }
    }
}

impl<B: ShareBackend> EncryptedBackendBuilder<B> {
    /// Sets whether the names of files and directories are stored encrypted.
    /// On for a new share unless set. A value that differs from the share's
    /// fails [`build`](Self::build) with
    /// [`SettingMismatch`](EncryptionError::SettingMismatch).
    #[must_use]
    pub fn encrypt_names(mut self, on: bool) -> Self {
        self.encrypt_names = Some(on);
        self
    }

    /// Sets whether names match without regard to case. On by default. It
    /// applies to encrypted names; with names in the clear the inner
    /// backend's rule decides and this has no effect.
    #[must_use]
    pub fn case_insensitive(mut self, on: bool) -> Self {
        self.case_insensitive = on;
        self
    }

    /// Sets the number of plaintext bytes in a block: a power of two from
    /// 8192 to 1048576. The default for a new share is 65536. Another value
    /// fails [`build`](Self::build) with
    /// [`InvalidSetting`](EncryptionError::InvalidSetting), and one that
    /// differs from the share's with
    /// [`SettingMismatch`](EncryptionError::SettingMismatch).
    #[must_use]
    pub fn block_size(mut self, bytes: u32) -> Self {
        self.block_size = Some(bytes);
        self
    }

    /// Sets the longest stored name in characters, from 62 to 255. A name
    /// whose encrypted form is longer is stored under a short name made from
    /// a hash, with the encrypted form in a second object beside it. The
    /// default for a new share is 255. Another value, or any value together
    /// with [`encrypt_names(false)`](Self::encrypt_names), fails
    /// [`build`](Self::build) with
    /// [`InvalidSetting`](EncryptionError::InvalidSetting), and one that
    /// differs from the share's with
    /// [`SettingMismatch`](EncryptionError::SettingMismatch).
    #[must_use]
    pub fn long_name_threshold(mut self, chars: u8) -> Self {
        self.long_name_threshold = Some(chars);
        self
    }

    /// Sets how long the decrypted names of a directory are trusted for
    /// changes made outside this backend. The default is 30 seconds;
    /// `Duration::ZERO` lists the directory again on every lookup that needs
    /// it. The setting applies only to encrypted names that match without
    /// regard to case.
    #[must_use]
    pub fn name_cache_ttl(mut self, ttl: Duration) -> Self {
        self.name_cache_ttl = ttl;
        self
    }

    /// Lets [`build`](Self::build) write a new marker into a root that has
    /// entries and no marker. Without it that root fails with
    /// [`MarkerMissing`](EncryptionError::MarkerMissing).
    ///
    /// The new marker takes the settings set on the builder, else the
    /// defaults, so a share made with other settings has to be restored with
    /// them. Before it writes the marker, `build` checks the key and the
    /// block size against what the share holds. It does not check
    /// `encrypt_names` or `long_name_threshold`, so keep a record of them.
    /// With encrypted names, at least one entry of the root has to decode
    /// under the key, and entries whose names do not decode are passed over.
    /// Of the files, the first that holds data, found breadth first among at
    /// most 10,000 entries, has to have a header of the chosen block size
    /// and a first block that is a hole or verifies under the key. A share
    /// with no such file passes. A failed check is
    /// [`KeyMismatch`](EncryptionError::KeyMismatch), or
    /// [`SettingMismatch`](EncryptionError::SettingMismatch) for the block
    /// size.
    ///
    /// With names in the clear, a stray file such as `.DS_Store` can be the
    /// file that is checked, and fails with `KeyMismatch` until it is
    /// removed.
    #[must_use]
    pub fn restore_marker(mut self) -> Self {
        self.restore_marker = true;
        self
    }

    /// Checks the settings and the root of the inner backend, and returns the
    /// backend.
    ///
    /// An empty root is a new share: `build` writes the marker, unless the
    /// inner backend is read-only. A root with a marker is an existing share:
    /// the key has to verify, and the settings set on the builder have to
    /// equal the marker's. Settings not set take the marker's.
    ///
    /// # Errors
    ///
    /// Fails with an [`EncryptionError`]:
    ///
    /// - [`EncryptionError::InvalidSetting`]: a setting is out of range or clashes with another.
    /// - [`EncryptionError::SettingMismatch`]: a setting differs from the share's.
    /// - [`EncryptionError::KeyMismatch`]: the key is not the share's.
    /// - [`EncryptionError::MarkerMissing`]: the root has entries and no marker.
    /// - [`EncryptionError::MarkerInvalid`]: the marker is not a file of the right size, does
    ///   not start with the marker magic, or holds field values out of range.
    /// - [`EncryptionError::UnsupportedFormat`]: the marker has another format version.
    /// - [`EncryptionError::Backend`]: the inner backend failed.
    /// - [`EncryptionError::Random`]: the random generator failed.
    pub async fn build(self) -> Result<EncryptedBackend<B>, EncryptionError> {
        let requested = self.requested()?;
        let Self {
            inner,
            key,
            case_insensitive,
            name_cache_ttl,
            restore_marker,
            ..
        } = self;
        let keys = KeySchedule::new(key);
        let marker = establish(&inner, &keys, &requested, restore_marker, fill_random).await?;
        let settings = Settings {
            encrypt_names: marker.encrypt_names,
            case_insensitive: marker.encrypt_names && case_insensitive,
            block_shift: marker.block_shift,
            long_name_threshold: marker.long_name_threshold,
            name_cache_ttl,
        };
        Ok(EncryptedBackend::new(inner, keys, settings))
    }

    /// The settings that were set, checked against their ranges.
    fn requested(&self) -> Result<Requested, EncryptionError> {
        let block_shift = match self.block_size {
            None => None,
            Some(bytes) => Some(shift_of(bytes).ok_or(EncryptionError::InvalidSetting {
                setting: "block_size",
            })?),
        };
        if let Some(threshold) = self.long_name_threshold
            && (threshold < MIN_LONG_NAME_THRESHOLD || self.encrypt_names == Some(false))
        {
            return Err(EncryptionError::InvalidSetting {
                setting: "long_name_threshold",
            });
        }
        Ok(Requested {
            encrypt_names: self.encrypt_names,
            block_shift,
            long_name_threshold: self.long_name_threshold,
        })
    }
}

/// The shift of a block of `bytes`, if that is a power of two the format
/// allows.
fn shift_of(bytes: u32) -> Option<BlockShift> {
    if !bytes.is_power_of_two() {
        return None;
    }
    u8::try_from(bytes.trailing_zeros())
        .ok()
        .and_then(BlockShift::new)
}

#[cfg(test)]
mod tests {
    use super::super::format::MARKER_NAME;
    use super::super::testing::{assert_invalid, build, key};
    use super::*;
    use crate::tests::faulty::Faulty;
    use crate::tests::memfs::MemFsBackend;

    type FaultyBuilder = EncryptedBackendBuilder<Faulty<MemFsBackend>>;

    /// The error of a build that fails on its settings, before it opens
    /// anything in the inner backend.
    async fn refused(setup: impl FnOnce(FaultyBuilder) -> FaultyBuilder) -> EncryptionError {
        let files = MemFsBackend::new();
        let faulty = Faulty::new(files.clone());
        let error = setup(EncryptedBackend::builder(faulty.clone(), key()))
            .build()
            .await
            .unwrap_err();
        assert_eq!(faulty.opens(), 0, "the inner backend was not used");
        assert_eq!(files.contents(MARKER_NAME), None);
        error
    }

    #[tokio::test]
    async fn settings_that_are_set_are_in_force() {
        let files = MemFsBackend::new();
        let backend = build(&files, |builder| {
            builder
                .block_size(16_384)
                .long_name_threshold(100)
                .case_insensitive(false)
                .name_cache_ttl(Duration::from_secs(5))
        })
        .await
        .unwrap();
        let settings = backend.shared.settings;
        assert!(settings.encrypt_names);
        assert!(!settings.case_insensitive);
        assert_eq!(settings.block_shift.get(), 14);
        assert_eq!(settings.long_name_threshold, 100);
        assert_eq!(settings.name_cache_ttl, Duration::from_secs(5));
    }

    #[tokio::test]
    async fn case_insensitive_is_off_when_names_are_in_the_clear() {
        let files = MemFsBackend::new();
        let backend = build(&files, |builder| {
            builder.encrypt_names(false).case_insensitive(true)
        })
        .await
        .unwrap();
        assert!(!backend.shared.settings.case_insensitive);
    }

    #[tokio::test]
    async fn block_sizes_from_8192_to_1048576_in_powers_of_two_are_accepted() {
        for shift in [13u8, 20] {
            let files = MemFsBackend::new();
            let backend = build(&files, |builder| builder.block_size(1 << shift))
                .await
                .unwrap();
            assert_eq!(backend.shared.settings.block_shift.get(), shift);
        }
    }

    #[tokio::test]
    async fn other_block_sizes_are_invalid() {
        for bytes in [0, 4096, 12_288, 2_097_152] {
            let error = refused(|builder| builder.block_size(bytes)).await;
            assert_invalid(&error, "block_size");
        }
    }

    #[tokio::test]
    async fn thresholds_from_62_to_255_are_accepted() {
        for threshold in [62, 255] {
            let files = MemFsBackend::new();
            let backend = build(&files, |builder| {
                builder.encrypt_names(true).long_name_threshold(threshold)
            })
            .await
            .unwrap();
            assert_eq!(backend.shared.settings.long_name_threshold, threshold);
        }
    }

    #[tokio::test]
    async fn a_threshold_below_62_is_invalid() {
        let error = refused(|builder| builder.long_name_threshold(61)).await;
        assert_invalid(&error, "long_name_threshold");
    }

    #[tokio::test]
    async fn a_threshold_with_names_in_the_clear_is_invalid() {
        let error = refused(|builder| builder.encrypt_names(false).long_name_threshold(100)).await;
        assert_invalid(&error, "long_name_threshold");
    }

    #[test]
    fn debug_shows_the_settings_and_redacts_the_key() {
        let builder = EncryptedBackend::builder(MemFsBackend::new(), key());
        assert_eq!(
            format!("{builder:?}"),
            "EncryptedBackendBuilder { key: <redacted>, encrypt_names: None, \
             case_insensitive: true, block_size: None, long_name_threshold: None, \
             name_cache_ttl: 30s, restore_marker: false, .. }"
        );
        assert!(format!("{:?}", builder.restore_marker()).contains("restore_marker: true"));
    }
}
