//! Minimal `smb-server` example.
//!
//! Defaults:
//! - listen on `127.0.0.1:4445` (override with `SMB_LISTEN`),
//! - share root at `smb-example` in the system temp directory (override with
//!   `SMB_ROOT`),
//! - users `alice` and `bob` with the password from `SMB_PASSWORD`, or a
//!   random one logged at startup,
//! - three shares: `public` (anonymous read+write), `media` (anonymous
//!   read-only), `home` (alice = read+write, bob = read).

use std::path::PathBuf;

use smb_server::{Access, LocalFsBackend, Share, SmbServer};

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
    std::fs::create_dir_all(root.join("public"))?;
    std::fs::create_dir_all(root.join("media"))?;
    std::fs::create_dir_all(root.join("home"))?;
    std::fs::write(root.join("public/hello.txt"), b"hello from smb-server\n")?;

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

    tracing::info!(?listen, ?root, "starting example smb server");

    let server = SmbServer::builder()
        .listen(listen)
        .user("alice", password.as_str())
        .user("bob", password.as_str())
        .share(Share::new("public", LocalFsBackend::new(root.join("public"))?).public())
        .share(
            Share::new(
                "media",
                LocalFsBackend::new(root.join("media"))?.read_only(),
            )
            .public_read_only(),
        )
        .share(
            Share::new("home", LocalFsBackend::new(root.join("home"))?)
                .user("alice", Access::ReadWrite)
                .user("bob", Access::Read),
        )
        .build()?;

    let addr = server.bind().await?;
    tracing::info!(%addr, "listening");
    let shutdown = server.shutdown_handle();
    let mut serve = std::pin::pin!(server.serve());
    tokio::select! {
        res = &mut serve => res?,
        _ = tokio::signal::ctrl_c() => {
            tracing::info!("ctrl-c received, shutting down");
            shutdown.shutdown();
            serve.await?;
        }
    }
    Ok(())
}
