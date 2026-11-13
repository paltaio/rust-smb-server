//! The backend type and its `ShareBackend` implementation.

use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;

use super::format::BlockShift;
use super::keys::KeySchedule;
use crate::backend::{
    BackendCapabilities, Handle, OpenAction, OpenOptions, ShareBackend, VolumeInfo,
};
use crate::error::{SmbError, SmbResult};
use crate::path::SmbPath;

/// Longest name a client can give, in characters.
const MAX_CLIENT_NAME_LEN: u32 = 255;

/// Serves the files of another backend with their contents encrypted, and by
/// default their names too, under a 32-byte key. The inner backend stores
/// ciphertext; clients see plaintext.
///
/// The root of the inner backend holds one object that is not a file of the
/// share, the marker `.smb-encryption`. It records the settings the share was
/// made with and a check value of the key.
/// [`build`](crate::EncryptedBackendBuilder::build) writes it into an empty
/// root and reads it from any other, so a wrong key, or settings that differ
/// from the share's, fail the build. A root with entries and no marker fails
/// it too, unless
/// [`restore_marker`](crate::EncryptedBackendBuilder::restore_marker) is set.
///
/// The block size, whether names are encrypted and the long-name threshold
/// are fixed when the share is made. The key is not stored anywhere, and the
/// data cannot be read without it. Each share needs a key of its own.
///
/// The backend reports no named streams and no extended attributes, and
/// answers [`copy_range`](ShareBackend::copy_range) and
/// [`clone_range`](ShareBackend::clone_range) with
/// [`NotSupported`](SmbError::NotSupported).
///
/// Clones share all state, so several shares can serve one encrypted tree
/// through clones of one backend. Two backends built separately over one
/// tree are not supported.
///
/// ```no_run
/// use smb_server::{Access, EncryptedBackend, Share, ShareBackend, SmbServer};
/// # async fn run<B: ShareBackend>(inner: B, key: [u8; 32]) -> Result<(), Box<dyn std::error::Error>> {
/// let vault = EncryptedBackend::builder(inner, key).build().await?;
/// SmbServer::builder()
///     .listen("0.0.0.0:4445".parse()?)
///     .user("alice", "password")
///     .share(Share::new("vault", vault).user("alice", Access::ReadWrite))
///     .build()?
///     .serve()
///     .await?;
/// # Ok(()) }
/// ```
pub struct EncryptedBackend<B> {
    pub(super) shared: Arc<Shared<B>>,
}

/// What the clones of a backend share.
pub(super) struct Shared<B> {
    pub(super) inner: B,
    #[cfg_attr(not(test), expect(dead_code, reason = "only tests call it"))]
    pub(super) keys: KeySchedule,
    pub(super) settings: Settings,
}

/// The settings in force.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Settings {
    pub(super) encrypt_names: bool,
    /// Encrypted names match without regard to case; false when names are
    /// not encrypted.
    pub(super) case_insensitive: bool,
    pub(super) block_shift: BlockShift,
    /// Longest stored name; 0 when names are not encrypted.
    pub(super) long_name_threshold: u8,
    pub(super) name_cache_ttl: Duration,
}

impl<B> EncryptedBackend<B> {
    pub(super) fn new(inner: B, keys: KeySchedule, settings: Settings) -> Self {
        Self {
            shared: Arc::new(Shared {
                inner,
                keys,
                settings,
            }),
        }
    }
}

impl<B> Clone for EncryptedBackend<B> {
    fn clone(&self) -> Self {
        Self {
            shared: Arc::clone(&self.shared),
        }
    }
}

impl<B> fmt::Debug for EncryptedBackend<B> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let settings = &self.shared.settings;
        f.debug_struct("EncryptedBackend")
            .field("encrypt_names", &settings.encrypt_names)
            .field("case_insensitive", &settings.case_insensitive)
            .field("block_size", &settings.block_shift.block_size())
            .field("long_name_threshold", &settings.long_name_threshold)
            .field("name_cache_ttl", &settings.name_cache_ttl)
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl<B: ShareBackend> ShareBackend for EncryptedBackend<B> {
    async fn open(
        &self,
        _path: &SmbPath,
        _opts: OpenOptions,
    ) -> SmbResult<(Box<dyn Handle>, OpenAction)> {
        Err(SmbError::NotSupported)
    }

    async fn unlink(&self, _path: &SmbPath) -> SmbResult<()> {
        Err(SmbError::NotSupported)
    }

    async fn rename(
        &self,
        _from: &SmbPath,
        _to: &SmbPath,
        _replace_if_exists: bool,
    ) -> SmbResult<()> {
        Err(SmbError::NotSupported)
    }

    fn capabilities(&self) -> BackendCapabilities {
        let inner = self.shared.inner.capabilities();
        let settings = &self.shared.settings;
        BackendCapabilities {
            case_sensitive: if settings.encrypt_names {
                !settings.case_insensitive
            } else {
                inner.case_sensitive
            },
            named_streams: false,
            extended_attributes: false,
            block_cloning: false,
            ..inner
        }
    }

    async fn volume_info(&self) -> SmbResult<VolumeInfo> {
        let mut volume = self.shared.inner.volume_info().await?;
        if self.shared.settings.encrypt_names {
            volume.max_name_length = MAX_CLIENT_NAME_LEN;
        }
        Ok(volume)
    }
}

#[cfg(test)]
mod tests {
    use super::super::names::encode_name;
    use super::super::testing::{Reporting, build, key, key_schedule, read_only};
    use super::*;
    use crate::backend::OpenIntent;
    use crate::tests::memfs::MemFsBackend;
    use crate::tests::util::{dir_opts, opts, path};

    async fn built(files: &MemFsBackend) -> EncryptedBackend<MemFsBackend> {
        build(files, |builder| builder).await.unwrap()
    }

    fn settings() -> Settings {
        Settings {
            encrypt_names: true,
            case_insensitive: true,
            block_shift: BlockShift::DEFAULT,
            long_name_threshold: 255,
            name_cache_ttl: Duration::from_secs(30),
        }
    }

    #[test]
    fn clones_share_one_state_whether_or_not_the_inner_backend_clones() {
        struct NotClone;
        fn assert_send_sync<T: Send + Sync + 'static>() {}
        assert_send_sync::<EncryptedBackend<NotClone>>();
        let backend = EncryptedBackend::new(NotClone, key_schedule(), settings());
        let clone = backend.clone();
        assert!(Arc::ptr_eq(&backend.shared, &clone.shared));
    }

    #[tokio::test]
    async fn the_backend_derives_its_keys_from_the_key() {
        let backend = built(&MemFsBackend::new()).await;
        let stored = |keys: &KeySchedule| encode_name(keys, "report.txt", 255).unwrap().entry;
        assert_eq!(stored(&backend.shared.keys), stored(&key_schedule()));
    }

    #[tokio::test]
    async fn debug_shows_the_settings_in_force_and_no_key() {
        let backend = built(&MemFsBackend::new()).await;
        assert_eq!(
            format!("{backend:?}"),
            "EncryptedBackend { encrypt_names: true, case_insensitive: true, \
             block_size: 65536, long_name_threshold: 255, name_cache_ttl: 30s, .. }"
        );
        let clear = build(&MemFsBackend::new(), |builder| {
            builder
                .encrypt_names(false)
                .case_insensitive(true)
                .block_size(8192)
                .name_cache_ttl(Duration::ZERO)
        })
        .await
        .unwrap();
        assert_eq!(
            format!("{clear:?}"),
            "EncryptedBackend { encrypt_names: false, case_insensitive: false, \
             block_size: 8192, long_name_threshold: 0, name_cache_ttl: 0ns, .. }"
        );
    }

    #[tokio::test]
    async fn capabilities_follow_the_settings_and_the_inner_backend() {
        let files = MemFsBackend::new();
        let inner = files.capabilities();
        assert!(!inner.case_sensitive && inner.named_streams && inner.extended_attributes);

        let backend = built(&files).await;
        let caps = backend.capabilities();
        assert!(!caps.is_read_only);
        assert!(!caps.case_sensitive, "case-insensitive names");
        assert!(!caps.named_streams);
        assert!(!caps.extended_attributes);
        assert!(!caps.block_cloning);

        let exact = build(&files, |builder| builder.case_insensitive(false))
            .await
            .unwrap();
        assert!(exact.capabilities().case_sensitive, "exact names");
    }

    #[tokio::test]
    async fn capabilities_with_names_in_the_clear_are_the_inner_backends() {
        for inner_case_sensitive in [false, true] {
            let files = MemFsBackend::new();
            let reported = BackendCapabilities {
                case_sensitive: inner_case_sensitive,
                block_cloning: true,
                ..files.capabilities()
            };
            let backend = EncryptedBackend::builder(Reporting::new(files, reported), key())
                .encrypt_names(false)
                .case_insensitive(inner_case_sensitive)
                .build()
                .await
                .unwrap();
            let caps = backend.capabilities();
            assert_eq!(
                caps.case_sensitive, inner_case_sensitive,
                "the inner backend decides"
            );
            assert!(!caps.named_streams && !caps.extended_attributes && !caps.block_cloning);
        }
    }

    #[tokio::test]
    async fn a_read_only_inner_backend_makes_a_read_only_backend() {
        let backend = EncryptedBackend::builder(read_only(&MemFsBackend::new()), key())
            .build()
            .await
            .unwrap();
        assert!(backend.capabilities().is_read_only);
    }

    #[tokio::test]
    async fn volume_info_is_the_inner_backends_with_names_of_any_client_length() {
        let volume = VolumeInfo {
            label: Some("disk".to_string()),
            serial_number: 7,
            max_name_length: 143,
            ..VolumeInfo::default()
        };
        let reported = || {
            Reporting::new(MemFsBackend::new(), BackendCapabilities::default())
                .with_volume(volume.clone())
        };

        let encrypted = EncryptedBackend::builder(reported(), key())
            .build()
            .await
            .unwrap();
        let got = encrypted.volume_info().await.unwrap();
        assert_eq!(got.max_name_length, 255);
        assert_eq!(got.label.as_deref(), Some("disk"));
        assert_eq!(got.serial_number, 7);

        let clear = EncryptedBackend::builder(reported(), key())
            .encrypt_names(false)
            .build()
            .await
            .unwrap();
        assert_eq!(clear.volume_info().await.unwrap().max_name_length, 143);
    }

    #[tokio::test]
    async fn open_unlink_and_rename_answer_not_supported() {
        let files = MemFsBackend::new();
        let backend = built(&files).await;
        files.clone().with_file("f", b"abc");
        assert!(matches!(
            backend.open(&path("f"), opts(OpenIntent::Open)).await,
            Err(SmbError::NotSupported)
        ));
        assert!(matches!(
            backend.unlink(&path("f")).await,
            Err(SmbError::NotSupported)
        ));
        assert!(matches!(
            backend.rename(&path("f"), &path("g"), false).await,
            Err(SmbError::NotSupported)
        ));
        assert_eq!(files.contents("f").unwrap(), b"abc");
    }

    #[tokio::test]
    async fn streams_and_copies_are_never_forwarded() {
        let files = MemFsBackend::new();
        let backend = built(&files).await;
        files.clone().with_file("f", b"abc");
        let stream = "s".parse().unwrap();
        let (src, _) = files
            .open(&path("f"), opts(OpenIntent::Open))
            .await
            .unwrap();
        let (dst, _) = files
            .open(&path(""), dir_opts(OpenIntent::Open))
            .await
            .unwrap();
        assert!(matches!(
            backend.copy_range(&*src, 0, &*dst, 0, 3).await,
            Err(SmbError::NotSupported)
        ));
        assert!(matches!(
            backend.clone_range(&*src, 0, &*dst, 0, 3).await,
            Err(SmbError::NotSupported)
        ));
        dst.close().await.unwrap();
        assert!(matches!(
            backend
                .open_stream(src, &path("f"), &stream, opts(OpenIntent::Create))
                .await,
            Err(SmbError::NotSupported)
        ));
        assert!(matches!(
            backend.remove_stream(&path("f"), 0, &stream).await,
            Err(SmbError::NotSupported)
        ));
        assert!(matches!(
            backend
                .rename_stream(&path("f"), 0, Some(&stream), None, false)
                .await,
            Err(SmbError::NotSupported)
        ));
        assert_eq!(files.contents("f").unwrap(), b"abc");
        assert!(files.stream_names("f").is_empty());
    }
}
