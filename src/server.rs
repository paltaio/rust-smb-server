//! Top-level `SmbServer` lifecycle: builder integration, accept loop,
//! graceful shutdown.

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Weak};

use crate::proto::auth::ntlm::UserCreds;
use thiserror::Error;
use tokio::net::TcpListener;
use tokio::sync::{Notify, RwLock, Semaphore};
use tokio::task::JoinSet;
use tracing::{Instrument, debug, error, info, info_span, warn};
use uuid::Uuid;

use crate::backend::ShareBackend;
use crate::builder::{Access, Share, ShareNameError, SmbServerBuilder, check_share_name};
use crate::conn::connection_loop;
use crate::conn::limits::Limits;
use crate::conn::listener::{AcceptBackoff, configure_socket};
use crate::conn::state::Connection;
use crate::files::{DurableTable, close_opens};

// ---------------------------------------------------------------------------
// ShareMode / ShareBindings
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShareMode {
    Public,
    PublicReadOnly,
    /// Default: closed share. Only users in the explicit `users` map allowed.
    AuthenticatedOnly,
}

#[derive(Clone)]
pub struct ShareAcl {
    pub mode: ShareMode,
    pub users: HashMap<String, Access>,
}

/// Compiled binding for a single share: the per-server-state form of `Share`.
pub struct ShareBindings {
    pub name: String,
    pub backend: Arc<dyn ShareBackend>,
    pub acl: RwLock<ShareAcl>,
    /// `IPC$` synthetic share. Accepted at TREE_CONNECT; its opens are
    /// named pipes.
    pub is_ipc: bool,
    /// Share.EncryptData: traffic to the share is encrypted.
    pub encrypt_data: bool,
    /// Leases are granted on the share's files.
    pub(crate) leases: bool,
    /// Opens asking for a durable handle get one.
    pub(crate) durable_handles: bool,
    /// Every file on the share that has an open, on any connection.
    pub(crate) files: crate::files::FileTable,
}

impl ShareBindings {
    pub(crate) fn new(
        name: String,
        backend: Arc<dyn ShareBackend>,
        mode: ShareMode,
        users: HashMap<String, Access>,
        is_ipc: bool,
        leases: bool,
        durable_handles: bool,
    ) -> Arc<Self> {
        Arc::new(Self {
            name,
            backend,
            acl: RwLock::new(ShareAcl { mode, users }),
            is_ipc,
            encrypt_data: false,
            leases,
            durable_handles,
            files: crate::files::FileTable::default(),
        })
    }

    pub(crate) fn from_share(share: Share) -> Arc<Self> {
        Arc::new(Self {
            name: share.name,
            backend: share.backend,
            acl: RwLock::new(ShareAcl {
                mode: share.mode,
                users: share.users,
            }),
            is_ipc: false,
            encrypt_data: share.encrypt_data,
            leases: share.leases,
            durable_handles: share.durable_handles,
            files: crate::files::FileTable::default(),
        })
    }

    /// Synthetic IPC$ share, whose opens are named pipes.
    pub fn ipc() -> Arc<Self> {
        Self::new(
            "IPC$".to_string(),
            Arc::new(crate::backend::NotSupportedBackend),
            ShareMode::PublicReadOnly,
            HashMap::new(),
            true,
            false,
            false,
        )
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
    pub limits: Limits,
}

pub struct ServerUsers {
    /// Username -> precomputed NT hash record.
    pub table: RwLock<HashMap<String, UserCreds>>,
}

pub struct ServerShares {
    by_name: RwLock<HashMap<String, Arc<ShareBindings>>>,
}

impl ServerShares {
    pub fn new(shares: Vec<Arc<ShareBindings>>) -> Self {
        let mut by_name = HashMap::with_capacity(shares.len());
        for share in shares {
            by_name.insert(share.name.to_ascii_lowercase(), share);
        }
        Self {
            by_name: RwLock::new(by_name),
        }
    }

    pub async fn find(&self, name: &str) -> Option<Arc<ShareBindings>> {
        self.by_name
            .read()
            .await
            .get(&name.to_ascii_lowercase())
            .cloned()
    }

    pub async fn insert(&self, share: Arc<ShareBindings>) -> Result<(), ConfigError> {
        let key = share.name.to_ascii_lowercase();
        let mut by_name = self.by_name.write().await;
        if by_name.contains_key(&key) {
            return Err(ConfigError::DuplicateShare(share.name.clone()));
        }
        by_name.insert(key, share);
        Ok(())
    }

    pub async fn remove(&self, name: &str) -> Option<Arc<ShareBindings>> {
        self.by_name
            .write()
            .await
            .remove(&name.to_ascii_lowercase())
    }

    pub async fn all(&self) -> Vec<Arc<ShareBindings>> {
        self.by_name.read().await.values().cloned().collect()
    }
}

pub struct ActiveConnections {
    next_id: AtomicU64,
    conns: RwLock<HashMap<u64, Weak<Connection>>>,
}

impl ActiveConnections {
    pub fn new() -> Self {
        Self {
            next_id: AtomicU64::new(1),
            conns: RwLock::new(HashMap::new()),
        }
    }

    pub async fn register(&self, conn: &Arc<Connection>) -> u64 {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        self.conns.write().await.insert(id, Arc::downgrade(conn));
        id
    }

    pub async fn unregister(&self, id: u64) {
        self.conns.write().await.remove(&id);
    }

    pub async fn live(&self) -> Vec<Arc<Connection>> {
        let mut live = Vec::new();
        let mut conns = self.conns.write().await;
        conns.retain(|_, weak| {
            if let Some(conn) = weak.upgrade() {
                live.push(conn);
                true
            } else {
                false
            }
        });
        live
    }
}

impl Default for ActiveConnections {
    fn default() -> Self {
        Self::new()
    }
}

/// Server state shared across connections.
pub struct ServerState {
    pub config: ServerConfig,
    pub users: ServerUsers,
    pub shares: ServerShares,
    pub active_connections: ActiveConnections,
    /// Notified by `shutdown()`. The accept loop stops; each connection
    /// closes once it has answered the frame it is receiving, if any.
    pub shutdown: Arc<Notify>,
    pub shutting_down: Arc<AtomicBool>,
    /// Signing policy, session and tree limits, and the logon throttle.
    pub auth: crate::auth_policy::AuthPolicy,

    /// Opens one connection may hold at once. CREATE past it fails with
    /// STATUS_INSUFFICIENT_RESOURCES.
    pub max_opens_per_connection: std::sync::atomic::AtomicUsize,
    /// Byte-range locks one open may hold at once. LOCK past it fails with
    /// STATUS_INSUFFICIENT_RESOURCES.
    pub max_locks_per_open: std::sync::atomic::AtomicUsize,
    /// Every lease held on a file of any share.
    pub(crate) leases: Arc<crate::files::LeaseTable>,
    /// Every durable open, and the ones kept after their session ended.
    pub(crate) durable: Arc<DurableTable>,
}

impl ServerState {
    pub fn new(config: ServerConfig, users: ServerUsers, shares: Vec<Arc<ShareBindings>>) -> Self {
        let durable = Arc::new(DurableTable::new(
            config.limits.durable_handle_timeout,
            config.limits.max_disconnected_opens,
        ));
        Self {
            config,
            users,
            shares: ServerShares::new(shares),
            active_connections: ActiveConnections::new(),
            shutdown: Arc::new(Notify::new()),
            shutting_down: Arc::new(AtomicBool::new(false)),
            auth: crate::auth_policy::AuthPolicy::default(),
            max_opens_per_connection: std::sync::atomic::AtomicUsize::new(
                crate::files::DEFAULT_MAX_OPENS_PER_CONNECTION,
            ),
            max_locks_per_open: std::sync::atomic::AtomicUsize::new(
                crate::files::DEFAULT_MAX_LOCKS_PER_OPEN,
            ),
            leases: Arc::default(),
            durable,
        }
    }

    /// Find a share by case-insensitive name.
    pub async fn find_share(&self, name: &str) -> Option<Arc<ShareBindings>> {
        self.shares.find(name).await
    }

    /// Look up a user's NT hash by name.
    pub async fn lookup_user(&self, name: &str) -> Option<UserCreds> {
        self.users.table.read().await.get(name).cloned()
    }

    /// Whether anonymous logon is permitted (i.e. at least one share is public).
    pub async fn anonymous_allowed(&self) -> bool {
        for share in self.shares.all().await {
            let acl = share.acl.read().await;
            if matches!(acl.mode, ShareMode::Public | ShareMode::PublicReadOnly) {
                return true;
            }
        }
        false
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ConfigError {
    #[error("user `{0}` does not exist")]
    UnknownUser(String),
    #[error("share `{0}` does not exist")]
    UnknownShare(String),
    #[error("duplicate share `{0}`")]
    DuplicateShare(String),
    #[error("share `{0}` mixes public mode with explicit users")]
    PublicMixedWithUsers(String),
    #[error("user name `{0}` is reserved")]
    ReservedUserName(String),
    #[error("user name must be non-empty")]
    EmptyUserName,
    #[error("share name `{0}` is reserved")]
    ReservedShareName(String),
    #[error("share name `{0}` must be non-empty and contain no `\\` or `/`")]
    InvalidShareName(String),
}

#[derive(Clone)]
pub struct ConfigHandle {
    state: Arc<ServerState>,
}

impl ConfigHandle {
    /// Add a user, or replace the password of an existing one. Replacing a
    /// password ends the user's sessions and closes the user's durable
    /// opens kept after their session ended.
    pub async fn add_user(
        &self,
        name: impl Into<String>,
        password: impl AsRef<str>,
    ) -> Result<(), ConfigError> {
        let name = name.into();
        validate_user_name(&name)?;
        let creds = UserCreds::from_password(password.as_ref());
        let replaced = self
            .state
            .users
            .table
            .write()
            .await
            .insert(name.clone(), creds.clone());
        if replaced.is_some_and(|old| old.nt_hash != creds.nt_hash) {
            self.close_user_sessions(&name).await;
        }
        Ok(())
    }

    pub async fn remove_user(&self, name: &str) -> Result<(), ConfigError> {
        validate_user_name(name)?;
        let removed = self.state.users.table.write().await.remove(name);
        if removed.is_none() {
            return Err(ConfigError::UnknownUser(name.to_string()));
        }

        for share in self.state.shares.all().await {
            share.acl.write().await.users.remove(name);
        }

        self.close_user_sessions(name).await;
        Ok(())
    }

    pub async fn add_share(&self, share: Share) -> Result<(), ConfigError> {
        validate_share_name(&share.name)?;
        let is_public = matches!(share.mode, ShareMode::Public | ShareMode::PublicReadOnly);
        if is_public && !share.users.is_empty() {
            return Err(ConfigError::PublicMixedWithUsers(share.name));
        }
        let users = self.state.users.table.read().await;
        for user in share.users.keys() {
            if !users.contains_key(user) {
                return Err(ConfigError::UnknownUser(user.clone()));
            }
        }

        let binding = ShareBindings::from_share(share);
        self.state.shares.insert(binding).await
    }

    pub async fn remove_share(&self, name: &str) -> Result<(), ConfigError> {
        validate_share_name(name)?;
        let removed = self
            .state
            .shares
            .remove(name)
            .await
            .ok_or_else(|| ConfigError::UnknownShare(name.to_string()))?;

        self.close_share_trees(&removed, None).await;
        Ok(())
    }

    /// Grant `user` `access` to a share. Lowering a user's access ends the
    /// user's trees on the share, so it applies to open connections too, and
    /// closes the user's durable opens on the share kept after their session
    /// ended.
    pub async fn grant_share_user(
        &self,
        share_name: &str,
        user: &str,
        access: Access,
    ) -> Result<(), ConfigError> {
        validate_user_name(user)?;
        validate_share_name(share_name)?;
        let users = self.state.users.table.read().await;
        if !users.contains_key(user) {
            return Err(ConfigError::UnknownUser(user.to_string()));
        }
        drop(users);
        let share = self
            .state
            .find_share(share_name)
            .await
            .ok_or_else(|| ConfigError::UnknownShare(share_name.to_string()))?;
        let mut acl = share.acl.write().await;
        if matches!(acl.mode, ShareMode::Public | ShareMode::PublicReadOnly) {
            return Err(ConfigError::PublicMixedWithUsers(share.name.clone()));
        }
        let previous = acl.users.insert(user.to_string(), access);
        drop(acl);

        if previous.is_some_and(|old| old.allows_write() && !access.allows_write()) {
            self.close_share_trees(&share, Some(user)).await;
        }
        Ok(())
    }

    pub async fn revoke_share_user(&self, share_name: &str, user: &str) -> Result<(), ConfigError> {
        validate_user_name(user)?;
        validate_share_name(share_name)?;
        let share = self
            .state
            .find_share(share_name)
            .await
            .ok_or_else(|| ConfigError::UnknownShare(share_name.to_string()))?;
        share.acl.write().await.users.remove(user);

        self.close_share_trees(&share, Some(user)).await;
        Ok(())
    }

    pub async fn set_share_mode(
        &self,
        share_name: &str,
        mode: ShareMode,
    ) -> Result<(), ConfigError> {
        validate_share_name(share_name)?;
        let share = self
            .state
            .find_share(share_name)
            .await
            .ok_or_else(|| ConfigError::UnknownShare(share_name.to_string()))?;
        let mut acl = share.acl.write().await;
        if matches!(mode, ShareMode::Public | ShareMode::PublicReadOnly) && !acl.users.is_empty() {
            return Err(ConfigError::PublicMixedWithUsers(share.name.clone()));
        }
        if acl.mode == mode {
            return Ok(());
        }
        acl.mode = mode;
        drop(acl);

        self.close_share_trees(&share, None).await;
        Ok(())
    }

    /// Set how many files and named pipes one connection may hold open at
    /// once. A CREATE past the limit fails with STATUS_INSUFFICIENT_RESOURCES;
    /// opens already held stay open. The default is
    /// [`DEFAULT_MAX_OPENS_PER_CONNECTION`](crate::DEFAULT_MAX_OPENS_PER_CONNECTION).
    pub fn set_max_opens_per_connection(&self, limit: usize) {
        self.state
            .max_opens_per_connection
            .store(limit, Ordering::Relaxed);
    }

    /// Ends every session of `user` on every connection, and closes the
    /// user's durable opens kept after their session ended. All of them are
    /// cut off before any open is closed, and closing waits for requests
    /// still using an open.
    async fn close_user_sessions(&self, user: &str) {
        let mut opens = Vec::new();
        for conn in self.state.active_connections.live().await {
            opens.extend(conn.detach_sessions_for_user(user).await);
        }
        opens.extend(self.state.durable.take_for(None, Some(user)));
        close_opens(opens).await;
    }

    /// Ends the trees on `share`, only those of `user` when given, on every
    /// connection, and closes the matching durable opens kept after their
    /// session ended, cutting all of them off before closing any open.
    async fn close_share_trees(&self, share: &Arc<ShareBindings>, user: Option<&str>) {
        let mut opens = Vec::new();
        for conn in self.state.active_connections.live().await {
            opens.extend(match user {
                Some(user) => conn.detach_trees_for_user_share(user, share).await,
                None => conn.detach_trees_for_share(share).await,
            });
        }
        opens.extend(self.state.durable.take_for(Some(share), user));
        close_opens(opens).await;
    }
}

fn validate_user_name(name: &str) -> Result<(), ConfigError> {
    if name.is_empty() {
        return Err(ConfigError::EmptyUserName);
    }
    if name.eq_ignore_ascii_case("anonymous") {
        return Err(ConfigError::ReservedUserName(name.to_string()));
    }
    Ok(())
}

fn validate_share_name(name: &str) -> Result<(), ConfigError> {
    match check_share_name(name) {
        Ok(()) => Ok(()),
        Err(ShareNameError::Reserved) => Err(ConfigError::ReservedShareName(name.to_string())),
        Err(ShareNameError::Invalid) => Err(ConfigError::InvalidShareName(name.to_string())),
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
    /// Listener opened by `bind()`, or by `serve()` if `bind()` was not
    /// called.
    bound: tokio::sync::Mutex<Option<TcpListener>>,
    /// Bound address, set by `bind()`.
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

    pub fn config_handle(&self) -> ConfigHandle {
        ConfigHandle {
            state: self.state.clone(),
        }
    }

    /// Bind the listen address without starting the accept loop. Returns
    /// the bound address, which gives the real port when the configured port
    /// is 0.
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

    /// Listen address as configured. Use `local_addr()` for the bound
    /// address.
    pub fn configured_addr(&self) -> SocketAddr {
        self.state.config.listen_addr
    }

    /// Initiate a graceful shutdown. Stops the accept loop and closes each
    /// connection once its current request is answered. Takes effect even
    /// when called before `serve()`.
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

    /// Run the accept loop until `shutdown()` is called. Returns once every
    /// connection has closed and every durable open kept after its session
    /// ended is closed, including closes that expiry or a lease break had
    /// already started.
    pub async fn serve(self) -> io::Result<()> {
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
            let mut backoff = AcceptBackoff::new();
            let mut connections = JoinSet::new();
            let limits = &state.config.limits;
            let slots = Arc::new(Semaphore::new(
                limits.max_connections.min(Semaphore::MAX_PERMITS),
            ));
            let mut at_capacity = false;

            loop {
                let stopped = shutdown.notified();
                tokio::pin!(stopped);
                stopped.as_mut().enable();
                if shutting_down.load(Ordering::Acquire) {
                    info!("shutdown requested; stopping accept loop");
                    break;
                }
                let retry_after = tokio::select! {
                    biased;
                    _ = &mut stopped => {
                        info!("shutdown requested; stopping accept loop");
                        break;
                    }
                    Some(_) = connections.join_next(), if !connections.is_empty() => None,
                    accept = listener.accept() => {
                        match accept {
                            Ok((stream, peer)) => {
                                backoff.succeeded();
                                if shutting_down.load(Ordering::Acquire) {
                                    drop(stream);
                                    break;
                                }
                                let Ok(slot) = slots.clone().try_acquire_owned() else {
                                    if !at_capacity {
                                        warn!(
                                            max = limits.max_connections,
                                            "connection limit reached; closing new connections"
                                        );
                                        at_capacity = true;
                                    }
                                    debug!(%peer, "connection refused: limit reached");
                                    drop(stream);
                                    continue;
                                };
                                if at_capacity {
                                    info!("below the connection limit again");
                                    at_capacity = false;
                                }
                                configure_socket(&stream, limits.tcp_keepalive);
                                let server_state = state.clone();
                                let span = info_span!("conn", peer = %peer);
                                connections.spawn(async move {
                                    let _slot = slot;
                                    if let Err(e) = connection_loop(stream, peer, server_state).await {
                                        error!(error = %e, "connection loop exited with error");
                                    }
                                }.instrument(span));
                                None
                            }
                            Err(e) => {
                                if shutting_down.load(Ordering::Acquire) {
                                    break;
                                }
                                Some(backoff.failed(&e))
                            }
                        }
                    }
                };
                if let Some(delay) = retry_after {
                    tokio::select! {
                        biased;
                        _ = &mut stopped => {
                            info!("shutdown requested; stopping accept loop");
                            break;
                        }
                        _ = tokio::time::sleep(delay) => {}
                    }
                }
            }
            drop(listener);
            if !connections.is_empty() {
                info!(open = connections.len(), "waiting for connections to close");
            }
            while connections.join_next().await.is_some() {}
            close_opens(state.durable.take_for(None, None)).await;
            state.durable.closed().await;
            info!("server stopped");
            Ok::<(), io::Error>(())
        }
        .instrument(span)
        .await
    }

    #[cfg(any(test, fuzzing))]
    pub(crate) fn state(&self) -> Arc<ServerState> {
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
