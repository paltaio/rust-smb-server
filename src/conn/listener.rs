//! Accept-loop helpers.

use std::io;
use std::time::Duration;

use tokio::net::TcpStream;
use tracing::{debug, error, info};

/// Sets TCP_NODELAY and, when `keepalive` is set, TCP keepalive with that
/// idle time and probes 10 seconds apart on an accepted connection.
pub fn configure_socket(stream: &TcpStream, keepalive: Option<Duration>) {
    if let Err(e) = stream.set_nodelay(true) {
        debug!(error = %e, "set TCP_NODELAY failed");
    }
    let Some(idle) = keepalive else {
        return;
    };
    let params = socket2::TcpKeepalive::new().with_time(idle);
    #[cfg(any(
        target_os = "android",
        target_os = "freebsd",
        target_os = "ios",
        target_os = "linux",
        target_os = "macos",
        target_os = "netbsd",
        target_os = "windows",
    ))]
    let params = params.with_interval(Duration::from_secs(10));
    if let Err(e) = socket2::SockRef::from(stream).set_tcp_keepalive(&params) {
        debug!(error = %e, "set TCP keepalive failed");
    }
}

/// Retry delay after a failed `accept`, doubling from 10 ms up to 1 s.
/// Logs the first failure of a run, and a summary once an accept succeeds.
pub struct AcceptBackoff {
    failures: u64,
    delay: Duration,
}

impl AcceptBackoff {
    const MIN: Duration = Duration::from_millis(10);
    const MAX: Duration = Duration::from_secs(1);

    pub fn new() -> Self {
        Self {
            failures: 0,
            delay: Self::MIN,
        }
    }

    /// Records a failure and returns how long to wait before the next try.
    pub fn failed(&mut self, error: &io::Error) -> Duration {
        if self.failures == 0 {
            error!(%error, "accept failed; retrying with backoff");
        } else {
            debug!(%error, failures = self.failures, "accept failed again");
        }
        self.failures += 1;
        let delay = self.delay;
        self.delay = (self.delay * 2).min(Self::MAX);
        delay
    }

    pub fn succeeded(&mut self) {
        if self.failures > 0 {
            info!(failures = self.failures, "accept recovered");
            *self = Self::new();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn delay_doubles_up_to_the_cap_and_resets() {
        let mut backoff = AcceptBackoff::new();
        let err = io::Error::other("EMFILE");
        let delays: Vec<u128> = (0..9).map(|_| backoff.failed(&err).as_millis()).collect();
        assert_eq!(delays, [10, 20, 40, 80, 160, 320, 640, 1000, 1000]);
        backoff.succeeded();
        assert_eq!(backoff.failed(&err), Duration::from_millis(10));
    }
}
