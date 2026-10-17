//! Public builder API for `SmbServer` and `Share`.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use thiserror::Error;
use uuid::Uuid;

use crate::backend::ShareBackend;
use crate::conn::limits::Limits;
use crate::server::{ServerConfig, ServerState, ServerUsers, ShareBindings, ShareMode, SmbServer};

// ---------------------------------------------------------------------------
// Access
// ---------------------------------------------------------------------------

/// Access level granted to a user on a share, or to anonymous on a public
/// share.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Access {
    Read,
    ReadWrite,
}

impl Access {
    pub fn allows_write(self) -> bool {
        matches!(self, Access::ReadWrite)
    }

    pub fn clamp_to(self, cap: Access) -> Access {
        match (self, cap) {
            (Access::ReadWrite, Access::ReadWrite) => Access::ReadWrite,
            _ => Access::Read,
        }
    }
}

// ---------------------------------------------------------------------------
// Share
// ---------------------------------------------------------------------------

/// One share definition, attached to a single backend.
pub struct Share {
    pub(crate) name: String,
    pub(crate) backend: Arc<dyn ShareBackend>,
    pub(crate) mode: ShareMode,
    pub(crate) users: HashMap<String, Access>,
}

impl Share {
    /// Build a new share with the given name and backend.
    pub fn new(name: impl Into<String>, backend: impl ShareBackend) -> Self {
        Self {
            name: name.into(),
            backend: Arc::new(backend),
            mode: ShareMode::AuthenticatedOnly,
            users: HashMap::new(),
        }
    }

    /// Anonymous + authenticated read+write.
    pub fn public(mut self) -> Self {
        self.mode = ShareMode::Public;
        self
    }

    /// Anonymous + authenticated read-only.
    pub fn public_read_only(mut self) -> Self {
        self.mode = ShareMode::PublicReadOnly;
        self
    }

    /// Grant `access` to the given (already-registered) user. Multiple calls
    /// accumulate.
    pub fn user(mut self, name: impl Into<String>, access: Access) -> Self {
        self.users.insert(name.into(), access);
        self
    }
}

// ---------------------------------------------------------------------------
// BuildError
// ---------------------------------------------------------------------------

/// Errors raised by `SmbServerBuilder::build`.
#[derive(Debug, Error)]
pub enum BuildError {
    #[error("listen address must be set")]
    MissingListenAddr,
    #[error("share `{0}` is declared more than once")]
    DuplicateShare(String),
    #[error("share `{0}` mixes .public()/.public_read_only() with explicit .user(...) entries")]
    PublicMixedWithUsers(String),
    #[error("share `{share}` references unknown user `{user}`")]
    UnknownUser { share: String, user: String },
    #[error("user name `{0}` is reserved (use .public()/.public_read_only() for anonymous)")]
    ReservedUserName(String),
    #[error("user name must be non-empty")]
    EmptyUserName,
    #[error("share name `{0}` is reserved")]
    ReservedShareName(String),
    #[error("share name `{0}` must be non-empty and contain no `\\` or `/`")]
    InvalidShareName(String),
    #[error("`{setting}` must be {expected}")]
    OutOfRange {
        setting: &'static str,
        expected: &'static str,
    },
}

/// Why a share name cannot be configured.
pub(crate) enum ShareNameError {
    /// IPC$, which the server provides itself.
    Reserved,
    /// Empty, or contains `\` or `/`, so no UNC path reaches it.
    Invalid,
}

/// Checks a share name for [`SmbServerBuilder::build`] and
/// `ConfigHandle`.
pub(crate) fn check_share_name(name: &str) -> Result<(), ShareNameError> {
    if name.eq_ignore_ascii_case("IPC$") {
        return Err(ShareNameError::Reserved);
    }
    if name.is_empty() || name.contains(['\\', '/']) {
        return Err(ShareNameError::Invalid);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// SmbServerBuilder
// ---------------------------------------------------------------------------

/// Builder for `SmbServer`. See `SmbServer::builder`.
pub struct SmbServerBuilder {
    listen_addr: Option<SocketAddr>,
    users: HashMap<String, String>, // name -> password
    user_order: Vec<String>,
    shares: Vec<Share>,
    netbios_name: Option<String>,
    max_read_size: u32,
    max_write_size: u32,
    server_guid: Option<Uuid>,
    limits: Limits,
    auth: crate::auth_policy::AuthSettings,
    max_opens_per_connection: usize,
}

impl Default for SmbServerBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl SmbServerBuilder {
    pub(crate) fn new() -> Self {
        Self {
            listen_addr: None,
            users: HashMap::new(),
            user_order: Vec::new(),
            shares: Vec::new(),
            netbios_name: None,
            max_read_size: 1024 * 1024,
            max_write_size: 1024 * 1024,
            server_guid: None,
            limits: Limits::default(),
            auth: crate::auth_policy::AuthSettings::default(),
            max_opens_per_connection: crate::files::DEFAULT_MAX_OPENS_PER_CONNECTION,
        }
    }

    pub fn listen(mut self, addr: SocketAddr) -> Self {
        self.listen_addr = Some(addr);
        self
    }

    pub fn user(mut self, name: impl Into<String>, password: impl Into<String>) -> Self {
        let n = name.into();
        if !self.users.contains_key(&n) {
            self.user_order.push(n.clone());
        }
        self.users.insert(n, password.into());
        self
    }

    pub fn share(mut self, share: Share) -> Self {
        self.shares.push(share);
        self
    }

    pub fn netbios_name(mut self, name: impl Into<String>) -> Self {
        self.netbios_name = Some(name.into());
        self
    }

    /// Require every authenticated session to sign its requests, and set
    /// SMB2_NEGOTIATE_SIGNING_REQUIRED in the NEGOTIATE response. Anonymous
    /// sessions have no key and stay unsigned. Off by default; a client can
    /// still require signing for its own sessions.
    pub fn require_signing(mut self, required: bool) -> Self {
        self.auth.require_signing = required;
        self
    }

    /// Most sessions one connection may hold. SESSION_SETUP past the limit
    /// fails with STATUS_INSUFFICIENT_RESOURCES. Default 64.
    pub fn max_sessions_per_connection(mut self, sessions: usize) -> Self {
        self.auth.max_sessions_per_connection = sessions;
        self
    }

    /// Most tree connects one session may hold. TREE_CONNECT past the limit
    /// fails with STATUS_INSUFFICIENT_RESOURCES. Default 128.
    pub fn max_trees_per_session(mut self, trees: usize) -> Self {
        self.auth.max_trees_per_session = trees;
        self
    }

    /// Failed-logon throttle. After `max_failures` failed logons for one
    /// user name, each within `lockout` of the one before, logons with that
    /// name fail with STATUS_ACCOUNT_LOCKED_OUT until `lockout` has passed
    /// since the last failure. One client address is locked out the same
    /// way after ten times `max_failures` failed logons, whatever names they
    /// used. A connection is closed after `max_failures` failed logons.
    /// Unknown names are tracked the same way as configured ones.
    /// `max_failures` 0 turns the throttle off. Default 10 failures and 60
    /// seconds.
    pub fn logon_throttle(mut self, max_failures: u32, lockout: std::time::Duration) -> Self {
        self.auth.max_logon_failures = max_failures;
        self.auth.lockout = lockout;
        self
    }

    pub fn max_read_size(mut self, bytes: u32) -> Self {
        self.max_read_size = bytes;
        self
    }

    pub fn max_write_size(mut self, bytes: u32) -> Self {
        self.max_write_size = bytes;
        self
    }

    /// Override the random per-process server GUID. Mostly useful in tests.
    pub fn server_guid(mut self, guid: Uuid) -> Self {
        self.server_guid = Some(guid);
        self
    }

    /// Most connections served at once. A connection accepted beyond the
    /// limit is closed straight away. Defaults to 1024.
    pub fn max_connections(mut self, connections: usize) -> Self {
        self.limits.max_connections = connections;
        self
    }

    /// Time a new connection has to establish a session, and each
    /// SESSION_SETUP exchange has to finish. A connection still without a
    /// session at the deadline is closed, and an unfinished exchange is
    /// dropped. Defaults to 30 seconds.
    pub fn handshake_timeout(mut self, timeout: Duration) -> Self {
        self.limits.handshake_timeout = timeout;
        self
    }

    /// Closes a connection that has sent no request for this long and has no
    /// open files. Defaults to 15 minutes.
    pub fn idle_timeout(mut self, timeout: Duration) -> Self {
        self.limits.idle_timeout = timeout;
        self
    }

    /// Time allowed to receive the rest of a request once its first bytes
    /// have arrived, and to send one response. The connection closes when
    /// either takes longer. Defaults to 60 seconds.
    pub fn io_timeout(mut self, timeout: Duration) -> Self {
        self.limits.io_timeout = timeout;
        self
    }

    /// Idle time before TCP keepalive probes start on accepted connections,
    /// or `None` to leave keepalive off. Defaults to 60 seconds.
    pub fn tcp_keepalive(mut self, idle: Option<Duration>) -> Self {
        self.limits.tcp_keepalive = idle;
        self
    }

    /// Most files one connection may hold open at once. A CREATE past the
    /// limit fails with STATUS_INSUFFICIENT_RESOURCES. Defaults to 16384.
    /// [`ConfigHandle::set_max_opens_per_connection`](crate::ConfigHandle::set_max_opens_per_connection)
    /// changes it at run time.
    pub fn max_opens_per_connection(mut self, opens: usize) -> Self {
        self.max_opens_per_connection = opens;
        self
    }

    pub fn build(self) -> Result<SmbServer, BuildError> {
        let limits = &self.limits;
        if limits.max_connections == 0 {
            return Err(BuildError::OutOfRange {
                setting: "max_connections",
                expected: "at least 1",
            });
        }
        for (setting, size) in [
            ("max_read_size", self.max_read_size),
            ("max_write_size", self.max_write_size),
        ] {
            if !(MIN_IO_SIZE..=MAX_IO_SIZE).contains(&size) {
                return Err(BuildError::OutOfRange {
                    setting,
                    expected: "between 65536 and 8388608 bytes",
                });
            }
        }
        for (setting, timeout) in [
            ("handshake_timeout", Some(limits.handshake_timeout)),
            ("idle_timeout", Some(limits.idle_timeout)),
            ("io_timeout", Some(limits.io_timeout)),
            ("tcp_keepalive", limits.tcp_keepalive),
        ] {
            if timeout == Some(Duration::ZERO) {
                return Err(BuildError::OutOfRange {
                    setting,
                    expected: "greater than zero",
                });
            }
        }

        for name in &self.user_order {
            if name.is_empty() {
                return Err(BuildError::EmptyUserName);
            }
            if name.eq_ignore_ascii_case("anonymous") {
                return Err(BuildError::ReservedUserName(name.clone()));
            }
        }

        let mut seen_names = std::collections::HashSet::new();
        for share in &self.shares {
            match check_share_name(&share.name) {
                Err(ShareNameError::Reserved) => {
                    return Err(BuildError::ReservedShareName(share.name.clone()));
                }
                Err(ShareNameError::Invalid) => {
                    return Err(BuildError::InvalidShareName(share.name.clone()));
                }
                Ok(()) => {}
            }
            if !seen_names.insert(share.name.to_ascii_lowercase()) {
                return Err(BuildError::DuplicateShare(share.name.clone()));
            }
            let is_public = matches!(share.mode, ShareMode::Public | ShareMode::PublicReadOnly);
            if is_public && !share.users.is_empty() {
                return Err(BuildError::PublicMixedWithUsers(share.name.clone()));
            }
            // Each per-share user must exist in the global user table.
            for u in share.users.keys() {
                if !self.users.contains_key(u) {
                    return Err(BuildError::UnknownUser {
                        share: share.name.clone(),
                        user: u.clone(),
                    });
                }
            }
        }

        let listen = self.listen_addr.ok_or(BuildError::MissingListenAddr)?;

        let netbios = self.netbios_name.unwrap_or_else(default_netbios_name);

        let mut share_bindings: Vec<Arc<ShareBindings>> = Vec::with_capacity(self.shares.len());
        for s in self.shares {
            share_bindings.push(ShareBindings::new(
                s.name, s.backend, s.mode, s.users, false,
            ));
        }

        // Store NT hashes only; plaintext passwords are dropped.
        let mut user_table = HashMap::new();
        for name in &self.user_order {
            let pw = &self.users[name];
            let creds = crate::proto::auth::ntlm::UserCreds::from_password(pw);
            user_table.insert(name.clone(), creds);
        }

        let server_guid = self.server_guid.unwrap_or_else(Uuid::new_v4);

        let cfg = ServerConfig {
            listen_addr: listen,
            netbios_name: netbios,
            max_read_size: self.max_read_size,
            max_write_size: self.max_write_size,
            server_guid,
            limits: self.limits,
        };
        let users = ServerUsers {
            table: tokio::sync::RwLock::new(user_table),
        };

        let state = ServerState::new(cfg, users, share_bindings);
        let state = state.with_auth(self.auth);
        state
            .max_opens_per_connection
            .store(self.max_opens_per_connection, Ordering::Relaxed);
        Ok(SmbServer::from_state(state))
    }
}

/// Smallest and largest accepted `max_read_size` and `max_write_size`.
const MIN_IO_SIZE: u32 = 64 * 1024;
const MAX_IO_SIZE: u32 = 8 * 1024 * 1024;

/// The host name's first label, uppercased and cut to the 15 characters a
/// NetBIOS name holds, or `SMBSERVER` when the host name is unknown.
fn default_netbios_name() -> String {
    let host = host_name().unwrap_or_default();
    let label: String = host
        .split('.')
        .next()
        .unwrap_or("")
        .chars()
        .take(15)
        .collect();
    if label.is_empty() {
        "SMBSERVER".to_string()
    } else {
        label.to_uppercase()
    }
}

#[cfg(unix)]
fn host_name() -> Option<String> {
    let mut buf = [0u8; 256];
    // SAFETY: `buf` is valid for writes of `buf.len()` bytes.
    let rc = unsafe { libc::gethostname(buf.as_mut_ptr().cast(), buf.len()) };
    if rc != 0 {
        return None;
    }
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    String::from_utf8(buf[..end].to_vec()).ok()
}

#[cfg(windows)]
fn host_name() -> Option<String> {
    std::env::var("COMPUTERNAME").ok()
}

#[cfg(not(any(unix, windows)))]
fn host_name() -> Option<String> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::memfs::MemFsBackend;

    fn build_with_share(name: &str) -> Result<SmbServer, BuildError> {
        SmbServer::builder()
            .listen("127.0.0.1:0".parse().unwrap())
            .share(Share::new(name, MemFsBackend::new()).public())
            .build()
    }

    #[test]
    fn reserved_and_unreachable_share_names_are_rejected() {
        for name in ["IPC$", "ipc$"] {
            assert!(matches!(
                build_with_share(name),
                Err(BuildError::ReservedShareName(n)) if n == name
            ));
        }
        for name in ["", "a\\b", "a/b", "\\share"] {
            assert!(matches!(
                build_with_share(name),
                Err(BuildError::InvalidShareName(n)) if n == name
            ));
        }
        assert!(build_with_share("share$").is_ok());
    }

    #[test]
    fn io_sizes_must_fit_a_frame() {
        let build = |read: u32, write: u32| {
            SmbServer::builder()
                .listen("127.0.0.1:0".parse().unwrap())
                .max_read_size(read)
                .max_write_size(write)
                .build()
        };
        const MIB: u32 = 1024 * 1024;
        assert!(build(64 * 1024, 8 * MIB).is_ok());
        for (read, write, setting) in [
            (64 * 1024 - 1, MIB, "max_read_size"),
            (8 * MIB + 1, MIB, "max_read_size"),
            (MIB, 0, "max_write_size"),
            (MIB, 16 * MIB, "max_write_size"),
        ] {
            assert!(matches!(
                build(read, write),
                Err(BuildError::OutOfRange { setting: s, .. }) if s == setting
            ));
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn default_netbios_name_comes_from_the_host_name() {
        let host = std::fs::read_to_string("/proc/sys/kernel/hostname").expect("hostname");
        let label = host.trim().split('.').next().expect("label");
        let expected: String = label.chars().take(15).collect::<String>().to_uppercase();
        let server = SmbServer::builder()
            .listen("127.0.0.1:0".parse().unwrap())
            .build()
            .expect("build");
        assert_eq!(server.state().config.netbios_name, expected);
    }
}
