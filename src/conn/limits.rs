//! Connection limits and timeouts.

use std::time::Duration;

use crate::proto::header::Command;
use crate::proto::messages::Dialect;

/// Largest request other than READ, WRITE, IOCTL, QUERY_DIRECTORY,
/// CHANGE_NOTIFY, QUERY_INFO and SET_INFO (MS-SMB2 3.3.5.2), and the largest
/// frame accepted before NEGOTIATE completes.
pub const MAX_SMALL_REQUEST: usize = 68 * 1024;

/// Largest request frame accepted once a dialect is negotiated: the largest
/// negotiated transfer size plus 256 bytes of headers (MS-SMB2 3.3.5.2).
/// MaxTransactSize is advertised equal to `max_read_size`.
pub fn max_request_frame(dialect: Option<Dialect>, max_read: u32, max_write: u32) -> usize {
    match dialect {
        None | Some(Dialect::Smb2Wildcard) => MAX_SMALL_REQUEST,
        Some(_) => max_read.max(max_write) as usize + 256,
    }
}

/// Commands whose requests may exceed [`MAX_SMALL_REQUEST`].
pub fn is_bulk(command: Command) -> bool {
    matches!(
        command,
        Command::Read
            | Command::Write
            | Command::Ioctl
            | Command::QueryDirectory
            | Command::ChangeNotify
            | Command::QueryInfo
            | Command::SetInfo
    )
}

/// Connection.SupportsMultiCredit: SMB 2.1 and 3.x over TCP.
pub fn supports_multi_credit(dialect: Option<Dialect>) -> bool {
    matches!(
        dialect,
        Some(Dialect::Smb210 | Dialect::Smb300 | Dialect::Smb302 | Dialect::Smb311)
    )
}

/// Connection limits and timeouts, set through `SmbServerBuilder`.
#[derive(Debug, Clone)]
pub struct Limits {
    /// Most connections served at once.
    pub max_connections: usize,
    /// Time a new connection has to establish its first session, and each
    /// SESSION_SETUP exchange has to finish.
    pub handshake_timeout: Duration,
    /// Time without requests after which a connection with no open files
    /// closes.
    pub idle_timeout: Duration,
    /// Time allowed to receive the rest of a started frame, and to send one
    /// response.
    pub io_timeout: Duration,
    /// Idle time before TCP keepalive probes start; `None` leaves keepalive
    /// off.
    pub tcp_keepalive: Option<Duration>,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_connections: 1024,
            handshake_timeout: Duration::from_secs(30),
            idle_timeout: Duration::from_secs(15 * 60),
            io_timeout: Duration::from_secs(60),
            tcp_keepalive: Some(Duration::from_secs(60)),
        }
    }
}
