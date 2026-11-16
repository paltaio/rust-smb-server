//! The backends a suite runs over: `LocalFsBackend` itself and, with the
//! `encryption` feature, `EncryptedBackend` on top of it.

use std::path::Path;

#[cfg(feature = "encryption")]
use smb_server::{EncryptedBackend, OpenIntent, OpenOptions};
use smb_server::{LocalFsBackend, ShareBackend};

use super::client::local;
#[cfg(feature = "encryption")]
use super::client::{encrypted, encrypted_over};

/// A backend a suite runs over. `file` and `dir` seed the root before `at`
/// builds the share's backend.
pub trait Instance {
    type Over<B: ShareBackend>: ShareBackend;

    /// Wraps `inner` for this instance.
    async fn over<B: ShareBackend>(inner: B) -> Self::Over<B>;

    /// The backend of a share on the directory `root`.
    async fn at(root: &Path) -> Self::Over<LocalFsBackend> {
        Self::over(local(root)).await
    }

    /// Makes the file `name` below `root` hold `data`.
    async fn file(root: &Path, name: &str, data: &[u8]);

    /// Makes the directory `name` below `root`.
    async fn dir(root: &Path, name: &str);
}

/// `LocalFsBackend`, filled directly in the directory.
pub struct Plain;

impl Instance for Plain {
    type Over<B: ShareBackend> = B;

    async fn over<B: ShareBackend>(inner: B) -> B {
        inner
    }

    async fn file(root: &Path, name: &str, data: &[u8]) {
        std::fs::write(root.join(name), data).expect("write file");
    }

    async fn dir(root: &Path, name: &str) {
        std::fs::create_dir(root.join(name)).expect("make directory");
    }
}

/// `EncryptedBackend` over `LocalFsBackend`, filled through the layer.
#[cfg(feature = "encryption")]
pub struct Encrypted;

#[cfg(feature = "encryption")]
impl Instance for Encrypted {
    type Over<B: ShareBackend> = EncryptedBackend<B>;

    async fn over<B: ShareBackend>(inner: B) -> EncryptedBackend<B> {
        encrypted_over(inner).await
    }

    async fn file(root: &Path, name: &str, data: &[u8]) {
        let opts = OpenOptions {
            write: true,
            intent: OpenIntent::Create,
            ..OpenOptions::default()
        };
        let (handle, _) = encrypted(root)
            .await
            .open(&name.parse().expect("path"), opts)
            .await
            .expect("create file");
        handle.write(0, data).await.expect("write file");
        handle.close().await.expect("close file");
    }

    async fn dir(root: &Path, name: &str) {
        let opts = OpenOptions {
            directory: true,
            intent: OpenIntent::Create,
            ..OpenOptions::default()
        };
        let (handle, _) = encrypted(root)
            .await
            .open(&name.parse().expect("path"), opts)
            .await
            .expect("make directory");
        handle.close().await.expect("close directory");
    }
}

/// Runs each `both` function once per instance, in the modules `plain` and
/// `encrypted`, and each `plain_only` function in `plain`. `plain_only` holds
/// the tests that read or change the share directory directly, where the
/// encrypted instance holds ciphertext, and the tests whose asserted answer
/// comes from the handler alone.
#[macro_export]
macro_rules! instances {
    (
        both: [$($both:ident),* $(,)?],
        plain_only: [$($(#[$plain_meta:meta])* $plain:ident),* $(,)?] $(,)?
    ) => {
        mod plain {
            $(
                #[tokio::test]
                async fn $both() {
                    super::$both::<$crate::common::instances::Plain>().await
                }
            )*
            $(
                $(#[$plain_meta])*
                #[tokio::test]
                async fn $plain() {
                    super::$plain().await
                }
            )*
        }

        #[cfg(feature = "encryption")]
        mod encrypted {
            $(
                #[tokio::test]
                async fn $both() {
                    super::$both::<$crate::common::instances::Encrypted>().await
                }
            )*
        }
    };
}
