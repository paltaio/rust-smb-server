//! Server-wide logon policy: signing, per-connection session and tree
//! limits, the failed-logon throttle, and SessionId allocation.

use std::collections::HashMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

/// Most user names the failed-logon throttle tracks at once.
const THROTTLE_CAPACITY: usize = 4096;

/// Logon settings chosen on the builder.
#[derive(Debug, Clone, Copy)]
pub struct AuthSettings {
    /// Set Session.SigningRequired on every authenticated session
    /// (RequireMessageSigning in MS-SMB2 3.3.1.5).
    pub require_signing: bool,
    pub max_sessions_per_connection: usize,
    pub max_trees_per_session: usize,
    /// Failed logons before a user name is locked out and a connection is
    /// closed. 0 turns the throttle off.
    pub max_logon_failures: u32,
    pub lockout: Duration,
}

impl Default for AuthSettings {
    fn default() -> Self {
        Self {
            require_signing: false,
            max_sessions_per_connection: 64,
            max_trees_per_session: 128,
            max_logon_failures: 10,
            lockout: Duration::from_secs(60),
        }
    }
}

pub struct AuthPolicy {
    pub settings: AuthSettings,
    failures: Mutex<HashMap<String, Failures>>,
    next_session_id: AtomicU64,
}

#[derive(Debug, Clone, Copy)]
struct Failures {
    count: u32,
    last: Instant,
}

impl AuthPolicy {
    pub fn new(settings: AuthSettings) -> Self {
        Self {
            settings,
            failures: Mutex::new(HashMap::new()),
            next_session_id: AtomicU64::new(1),
        }
    }

    /// A SessionId no other session on this server has had.
    pub fn alloc_session_id(&self) -> u64 {
        self.next_session_id.fetch_add(1, Ordering::Relaxed)
    }

    /// True while `user` has failed `max_logon_failures` times, each within
    /// `lockout` of the previous one, and the last failure is under
    /// `lockout` old.
    pub fn is_locked_out(&self, user: &str) -> bool {
        let max = self.settings.max_logon_failures;
        if max == 0 {
            return false;
        }
        let failures = self.lock_failures();
        failures
            .get(&throttle_key(user))
            .is_some_and(|f| f.count >= max && f.last.elapsed() < self.settings.lockout)
    }

    /// Counts a failed logon for `user`. Names that are not configured
    /// count the same, so a lockout says nothing about which names exist.
    pub fn record_failure(&self, user: &str) {
        if self.settings.max_logon_failures == 0 {
            return;
        }
        let lockout = self.settings.lockout;
        let now = Instant::now();
        let key = throttle_key(user);
        let mut failures = self.lock_failures();
        if !failures.contains_key(&key) && failures.len() >= THROTTLE_CAPACITY {
            failures.retain(|_, f| now.duration_since(f.last) < lockout);
            if failures.len() >= THROTTLE_CAPACITY
                && let Some(oldest) = failures
                    .iter()
                    .min_by_key(|(_, f)| f.last)
                    .map(|(k, _)| k.clone())
            {
                failures.remove(&oldest);
            }
        }
        let entry = failures.entry(key).or_insert(Failures {
            count: 0,
            last: now,
        });
        if now.duration_since(entry.last) >= lockout {
            entry.count = 0;
        }
        entry.count = entry.count.saturating_add(1);
        entry.last = now;
    }

    /// Forgets the failures of `user` after a successful logon.
    pub fn record_success(&self, user: &str) {
        self.lock_failures().remove(&throttle_key(user));
    }

    /// True once a connection has seen enough failed logons to be closed.
    pub fn connection_exhausted(&self, failures: u32) -> bool {
        let max = self.settings.max_logon_failures;
        max != 0 && failures >= max
    }

    fn lock_failures(&self) -> std::sync::MutexGuard<'_, HashMap<String, Failures>> {
        self.failures
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    #[cfg(test)]
    fn tracked(&self) -> usize {
        self.lock_failures().len()
    }
}

impl Default for AuthPolicy {
    fn default() -> Self {
        Self::new(AuthSettings::default())
    }
}

impl crate::server::ServerState {
    /// The same state with the builder's logon settings.
    pub(crate) fn with_auth(self, settings: AuthSettings) -> Self {
        Self {
            auth: AuthPolicy::new(settings),
            ..self
        }
    }
}

fn throttle_key(user: &str) -> String {
    user.to_uppercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(max: u32, lockout: Duration) -> AuthPolicy {
        AuthPolicy::new(AuthSettings {
            max_logon_failures: max,
            lockout,
            ..AuthSettings::default()
        })
    }

    #[test]
    fn locks_after_max_failures_ignoring_case() {
        let p = policy(3, Duration::from_secs(60));
        for _ in 0..2 {
            p.record_failure("alice");
        }
        assert!(!p.is_locked_out("alice"));
        p.record_failure("ALICE");
        assert!(p.is_locked_out("Alice"));
        assert!(!p.is_locked_out("bob"));
        p.record_success("alice");
        assert!(!p.is_locked_out("alice"));
    }

    #[test]
    fn lockout_expires() {
        let p = policy(1, Duration::from_millis(20));
        p.record_failure("alice");
        assert!(p.is_locked_out("alice"));
        std::thread::sleep(Duration::from_millis(30));
        assert!(!p.is_locked_out("alice"));
        // The old count does not carry over into a new window.
        let p = policy(2, Duration::from_millis(20));
        p.record_failure("alice");
        std::thread::sleep(Duration::from_millis(30));
        p.record_failure("alice");
        assert!(!p.is_locked_out("alice"));
    }

    #[test]
    fn zero_turns_the_throttle_off() {
        let p = policy(0, Duration::from_secs(60));
        for _ in 0..100 {
            p.record_failure("alice");
        }
        assert!(!p.is_locked_out("alice"));
        assert!(!p.connection_exhausted(u32::MAX));
        assert_eq!(p.tracked(), 0);
    }

    #[test]
    fn tracked_names_are_bounded() {
        let p = policy(3, Duration::from_secs(60));
        for _ in 0..3 {
            p.record_failure("victim");
        }
        for i in 0..THROTTLE_CAPACITY + 10 {
            p.record_failure(&format!("user{i}"));
            assert!(p.tracked() <= THROTTLE_CAPACITY);
        }
        assert_eq!(p.tracked(), THROTTLE_CAPACITY);
    }

    #[test]
    fn session_ids_are_unique_and_never_zero() {
        let p = AuthPolicy::default();
        let a = p.alloc_session_id();
        let b = p.alloc_session_id();
        assert_ne!(a, 0);
        assert_ne!(a, b);
    }
}
