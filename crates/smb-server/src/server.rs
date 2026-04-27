//! Top-level `SmbServer` lifecycle: builder integration, accept loop,
//! graceful shutdown.

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use smb_proto::auth::ntlm::UserCreds;
use tokio::net::TcpListener;
use tokio::sync::Notify;
use tracing::{error, info, info_span, Instrument};
use uuid::Uuid;

use crate::backend::ShareBackend;
use crate::builder::{Access, SmbServerBuilder};
use crate::conn::connection_loop;
use crate::utils::now_filetime;

// ---------------------------------------------------------------------------
// ShareMode / ShareBindings
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShareMode {
    Public,
    PublicReadOnly,
    /// Default — closed share. Only users in the explicit `users` map allowed.
    AuthenticatedOnly,
}

/// Compiled binding for a single share — the per-server-state form of `Share`.
pub struct ShareBindings {
    pub name: String,
    pub backend: Arc<dyn ShareBackend>,
    pub mode: ShareMode,
    pub users: HashMap<String, Access>,
    /// `IPC$` synthetic share. Accepted at TREE_CONNECT for client compatibility
    /// (Windows always probes IPC$ before mounting an actual share). All
    /// downstream ops on an IPC$ tree return `STATUS_NOT_SUPPORTED`.
    pub is_ipc: bool,
}

impl ShareBindings {
    /// Synthetic IPC$ share. The backend is a no-op; clients that try to
    /// CREATE on it get `STATUS_NOT_SUPPORTED` from the CREATE handler.
    pub fn ipc() -> Arc<Self> {
        Arc::new(Self {
            name: "IPC$".to_string(),
            backend: Arc::new(crate::backend::NotSupportedBackend),
            mode: ShareMode::PublicReadOnly,
            users: HashMap::new(),
            is_ipc: true,
        })
    }
}

// ---------------------------------------------------------------------------
// ServerConfig / ServerUsers / ServerState
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub listen_addr: SocketAddr,
    pub netbios_name: String,
    pub max_read_size: u32,
    pub max_write_size: u32,
    pub server_guid: Uuid,
}

pub struct ServerUsers {
    /// Username → precomputed NT hash record.
    pub table: HashMap<String, UserCreds>,
}

/// Top-level immutable-ish state shared across connections.
pub struct ServerState {
    pub config: ServerConfig,
    pub users: ServerUsers,
    pub shares: Vec<Arc<ShareBindings>>,
    pub server_start_filetime: u64,
    /// Set when `shutdown()` is invoked; the accept loop stops on the next
    /// iteration and connection loops abandon their next read.
    pub shutdown: Arc<Notify>,
    pub shutting_down: Arc<AtomicBool>,
}

impl ServerState {
    pub fn new(config: ServerConfig, users: ServerUsers, shares: Vec<Arc<ShareBindings>>) -> Self {
        Self {
            config,
            users,
            shares,
            server_start_filetime: now_filetime(),
            shutdown: Arc::new(Notify::new()),
            shutting_down: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Find a share by case-insensitive name.
    pub fn find_share(&self, name: &str) -> Option<Arc<ShareBindings>> {
        self.shares
            .iter()
            .find(|s| s.name.eq_ignore_ascii_case(name))
            .cloned()
    }

    /// Look up a user's NT hash by name.
    pub fn lookup_user(&self, name: &str) -> Option<&UserCreds> {
        self.users.table.get(name)
    }

    /// Whether anonymous logon is permitted (i.e. at least one share is public).
    pub fn anonymous_allowed(&self) -> bool {
        self.shares
            .iter()
            .any(|s| matches!(s.mode, ShareMode::Public | ShareMode::PublicReadOnly))
    }
}

// ---------------------------------------------------------------------------
// SmbServer
// ---------------------------------------------------------------------------

/// A built but not-yet-running SMB server.
///
/// Use `serve()` to bind the configured listener and run until shutdown.
pub struct SmbServer {
    state: Arc<ServerState>,
    /// The listener is bound lazily inside `serve()` so we can return a
    /// useful `local_addr` only after binding. Pre-bind helpers: `serve` is
    /// the only path that opens the socket.
    bound: tokio::sync::Mutex<Option<TcpListener>>,
    /// Resolved local address once `bind_local()` has been called. Tests
    /// expect to ask for the address before serving (port 0 case).
    local_addr: tokio::sync::Mutex<Option<SocketAddr>>,
}

impl SmbServer {
    pub fn builder() -> SmbServerBuilder {
        SmbServerBuilder::default()
    }

    pub(crate) fn from_state(state: ServerState) -> Self {
        Self {
            state: Arc::new(state),
            bound: tokio::sync::Mutex::new(None),
            local_addr: tokio::sync::Mutex::new(None),
        }
    }

    /// Bind the configured listen address without yet entering the accept
    /// loop. Required for tests that need the actual port (e.g. when the
    /// builder used port 0).
    pub async fn bind(&self) -> io::Result<SocketAddr> {
        let mut bound = self.bound.lock().await;
        if let Some(l) = bound.as_ref() {
            return l.local_addr();
        }
        let listener = TcpListener::bind(self.state.config.listen_addr).await?;
        let addr = listener.local_addr()?;
        *bound = Some(listener);
        *self.local_addr.lock().await = Some(addr);
        Ok(addr)
    }

    /// Returns the actual bound address. `None` if `bind()`/`serve()` have
    /// not yet been called.
    pub async fn local_addr(&self) -> Option<SocketAddr> {
        *self.local_addr.lock().await
    }

    /// Configured listen address (the *intended* address; may be `0.0.0.0:0`
    /// before binding).
    pub fn configured_addr(&self) -> SocketAddr {
        self.state.config.listen_addr
    }

    /// Initiate a graceful shutdown. Stops the accept loop and lets in-flight
    /// connection tasks complete.
    pub fn shutdown(&self) {
        self.state.shutting_down.store(true, Ordering::Release);
        self.state.shutdown.notify_waiters();
    }

    /// Returns a clonable handle that can request shutdown after `serve()`
    /// has consumed the `SmbServer` value.
    pub fn shutdown_handle(&self) -> ShutdownHandle {
        ShutdownHandle {
            shutdown: self.state.shutdown.clone(),
            shutting_down: self.state.shutting_down.clone(),
        }
    }

    /// Run the accept loop until `shutdown()` is called.
    pub async fn serve(self) -> io::Result<()> {
        // Ensure the listener is bound. (The user may also have called
        // `bind()` to pre-extract `local_addr()` for a test.)
        if self.bound.lock().await.is_none() {
            self.bind().await?;
        }
        let listener = self
            .bound
            .lock()
            .await
            .take()
            .expect("listener bound above");
        let local = listener.local_addr().ok();
        let span = info_span!("smb_server", listen = ?local);
        async move {
            info!("server starting");
            let state = self.state.clone();
            let shutdown = state.shutdown.clone();
            let shutting_down = state.shutting_down.clone();

            loop {
                tokio::select! {
                    biased;
                    _ = shutdown.notified() => {
                        info!("shutdown requested; stopping accept loop");
                        break;
                    }
                    accept = listener.accept() => {
                        match accept {
                            Ok((stream, peer)) => {
                                if shutting_down.load(Ordering::Acquire) {
                                    drop(stream);
                                    break;
                                }
                                let server_state = state.clone();
                                let span = info_span!("conn", peer = %peer);
                                tokio::spawn(async move {
                                    if let Err(e) = connection_loop(stream, server_state).await {
                                        error!(error = %e, "connection loop exited with error");
                                    }
                                }.instrument(span));
                            }
                            Err(e) => {
                                error!(error = %e, "accept failed");
                                if shutting_down.load(Ordering::Acquire) {
                                    break;
                                }
                            }
                        }
                    }
                }
            }
            info!("server stopped");
            Ok::<(), io::Error>(())
        }
        .instrument(span)
        .await
    }

    /// Access shared state for in-crate tests/integrations.
    #[doc(hidden)]
    pub fn state(&self) -> Arc<ServerState> {
        self.state.clone()
    }
}

/// Cheaply-clonable shutdown handle. Outlives `SmbServer::serve` consuming
/// the server.
#[derive(Clone)]
pub struct ShutdownHandle {
    shutdown: Arc<Notify>,
    shutting_down: Arc<AtomicBool>,
}

impl ShutdownHandle {
    /// Request a graceful shutdown.
    pub fn shutdown(&self) {
        self.shutting_down.store(true, Ordering::Release);
        self.shutdown.notify_waiters();
    }
}
