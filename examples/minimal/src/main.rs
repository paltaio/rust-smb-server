//! Minimal `smb-server` example.
//!
//! Defaults:
//! - listen on `127.0.0.1:4445` (override with `SMB_LISTEN`),
//! - share root at `smb-example` in the system temp directory (override with
//!   `SMB_ROOT`),
//! - users `alice` and `bob` with the password from `SMB_PASSWORD`, or a
//!   random one logged at startup,
//! - three shares: `public` (anonymous read+write), `media` (anonymous
//!   read-only), `home` (alice = read+write, bob = read),
//! - not announced on the network; `SMB_DISCOVERY=1` announces it when
//!   built with the `discovery` feature and listening on an address other
//!   than loopback,
//! - named streams on every directory share; `SMB_STREAMS=0` turns them off,
//! - server-side copy on every share; `SMB_COPY=0` turns it off,
//! - with the `s3` feature, `SMB_S3_BUCKET` replaces the three shares with one
//!   share, `s3` (alice = read+write, bob = read), that serves the bucket. It
//!   reads `SMB_S3_ENDPOINT`, `SMB_S3_REGION`, `SMB_S3_ACCESS_KEY`,
//!   `SMB_S3_SECRET_KEY` and `SMB_S3_CACHE` (the cache directory), and
//!   `SMB_S3_PREFIX` to serve only the keys below a prefix. After the server
//!   stops, the example waits until the changes are in the bucket; a second
//!   ctrl-c stops the wait.

use std::path::{Path, PathBuf};

use smb_server::{Access, LocalFsBackend, Share, SmbServer, SmbServerBuilder};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let root = std::env::var("SMB_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|_| std::env::temp_dir().join("smb-example"));

    let listen = std::env::var("SMB_LISTEN")
        .unwrap_or_else(|_| "127.0.0.1:4445".into())
        .parse()?;

    let password = match std::env::var("SMB_PASSWORD") {
        Ok(p) if !p.is_empty() => p,
        _ => {
            let p = uuid::Uuid::new_v4().simple().to_string();
            tracing::info!(password = %p, "SMB_PASSWORD is unset; generated a password for alice and bob");
            p
        }
    };

    let discovery = std::env::var("SMB_DISCOVERY").is_ok_and(|v| v == "1");
    let streams = !std::env::var("SMB_STREAMS").is_ok_and(|v| v == "0");
    let copy = !std::env::var("SMB_COPY").is_ok_and(|v| v == "0");
    let s3_bucket = std::env::var("SMB_S3_BUCKET")
        .ok()
        .filter(|b| !b.is_empty());
    #[cfg(not(feature = "s3"))]
    if s3_bucket.is_some() {
        tracing::warn!("SMB_S3_BUCKET needs the s3 feature; serving the directories of SMB_ROOT");
    }

    tracing::info!(?listen, "starting example smb server");

    let builder = SmbServer::builder()
        .listen(listen)
        .user("alice", password.as_str())
        .user("bob", password.as_str());
    #[cfg(feature = "s3")]
    let s3 = match &s3_bucket {
        Some(bucket) => Some(s3_backend(bucket).await?),
        None => None,
    };
    #[cfg(feature = "s3")]
    let builder = match &s3 {
        Some(backend) => builder.share(
            Share::new("s3", backend.clone())
                .user("alice", Access::ReadWrite)
                .user("bob", Access::Read)
                .server_side_copy(copy),
        ),
        None => dir_shares(builder, &root, streams, copy)?,
    };
    #[cfg(not(feature = "s3"))]
    let builder = dir_shares(builder, &root, streams, copy)?;
    #[cfg(feature = "discovery")]
    let builder = if discovery {
        builder.discovery(smb_server::Discovery::new())
    } else {
        builder
    };
    #[cfg(not(feature = "discovery"))]
    if discovery {
        tracing::warn!("SMB_DISCOVERY=1 needs the discovery feature; the server is not announced");
    }
    let server = builder.build()?;

    let addr = server.bind().await?;
    tracing::info!(%addr, "listening");
    let shutdown = server.shutdown_handle();
    let mut ctrl_c = ctrl_c_presses();
    let mut serve = std::pin::pin!(server.serve());
    let served = tokio::select! {
        res = &mut serve => res,
        Some(()) = ctrl_c.recv() => {
            tracing::info!("ctrl-c received, shutting down");
            shutdown.shutdown();
            serve.await
        }
    };
    #[cfg(feature = "s3")]
    if let Some(backend) = &s3 {
        store_changes(backend, &mut ctrl_c).await;
    }
    served?;
    Ok(())
}

/// Delivers each ctrl-c on the returned channel. This task queues the presses
/// made while the server drains, which a later `tokio::signal::ctrl_c` call
/// would miss.
fn ctrl_c_presses() -> tokio::sync::mpsc::UnboundedReceiver<()> {
    let (presses, received) = tokio::sync::mpsc::unbounded_channel();
    tokio::spawn(async move {
        while tokio::signal::ctrl_c().await.is_ok() && presses.send(()).is_ok() {}
    });
    received
}

/// The three directory shares below `root`, made if missing.
fn dir_shares(
    builder: SmbServerBuilder,
    root: &Path,
    streams: bool,
    copy: bool,
) -> Result<SmbServerBuilder, Box<dyn std::error::Error>> {
    std::fs::create_dir_all(root.join("public"))?;
    std::fs::create_dir_all(root.join("media"))?;
    std::fs::create_dir_all(root.join("home"))?;
    std::fs::write(root.join("public/hello.txt"), b"hello from smb-server\n")?;
    tracing::info!(?root, "serving directories");

    Ok(builder
        .share(
            Share::new("public", LocalFsBackend::new(root.join("public"))?)
                .public()
                .named_streams(streams)
                .server_side_copy(copy),
        )
        .share(
            Share::new(
                "media",
                LocalFsBackend::new(root.join("media"))?.read_only(),
            )
            .public_read_only()
            .named_streams(streams)
            .server_side_copy(copy),
        )
        .share(
            Share::new("home", LocalFsBackend::new(root.join("home"))?)
                .user("alice", Access::ReadWrite)
                .user("bob", Access::Read)
                .named_streams(streams)
                .server_side_copy(copy),
        ))
}

#[cfg(feature = "s3")]
fn required(name: &str) -> Result<String, String> {
    std::env::var(name).map_err(|_| format!("{name} is not set"))
}

/// Builds the backend from the `SMB_S3_*` variables.
#[cfg(feature = "s3")]
async fn s3_backend(bucket: &str) -> Result<smb_server::S3Backend, Box<dyn std::error::Error>> {
    let endpoint = required("SMB_S3_ENDPOINT")?;
    let region = required("SMB_S3_REGION")?;
    let access_key = required("SMB_S3_ACCESS_KEY")?;
    let secret_key = required("SMB_S3_SECRET_KEY")?;
    let cache = PathBuf::from(required("SMB_S3_CACHE")?);

    let mut builder = smb_server::S3Backend::builder(endpoint.as_str(), region, bucket)
        .credentials(access_key, secret_key)
        .cache_dir(cache.as_path());
    let prefix = std::env::var("SMB_S3_PREFIX").unwrap_or_default();
    if !prefix.is_empty() {
        builder = builder.prefix(prefix.as_str());
    }
    let backend = builder.build().await?;
    tracing::info!(%endpoint, %bucket, %prefix, ?cache, "serving an S3 bucket");
    Ok(backend)
}

/// Waits until the changes made through the share are in the bucket, and
/// logs what did not get there. The next ctrl-c stops the wait, including one
/// that arrived while the server was shutting down.
#[cfg(feature = "s3")]
async fn store_changes(
    backend: &smb_server::S3Backend,
    ctrl_c: &mut tokio::sync::mpsc::UnboundedReceiver<()>,
) {
    tracing::info!("storing changes in the bucket; ctrl-c stops the wait");
    let synced = tokio::select! {
        res = backend.sync() => Some(res),
        Some(()) = ctrl_c.recv() => None,
    };
    match synced {
        Some(Ok(())) => tracing::info!("all changes are in the bucket"),
        Some(Err(error)) => tracing::error!(%error, "not every change reached the bucket"),
        None => tracing::warn!("stopped waiting; changes not in the bucket yet may be lost"),
    }
    for (path, error) in backend.failures() {
        tracing::error!(%path, %error, "could not store the change");
    }
}
