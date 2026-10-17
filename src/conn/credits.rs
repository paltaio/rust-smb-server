//! Connection.CommandSequenceWindow and credit grants (MS-SMB2 3.3.1.1,
//! 3.3.1.2, 3.3.4.1.2).

use std::collections::VecDeque;

/// Most credits a client holds at once.
pub const MAX_CREDITS: u64 = 512;

/// The MessageIds a client may use: each id from `low` up to
/// `low + received.len()` that has not been received yet. A new connection
/// may use only id 0.
pub struct CreditWindow {
    low: u64,
    /// Whether `low + i` has been received. The front entry is always
    /// false: id `low` stays available until it is received.
    received: VecDeque<bool>,
    /// Ids in the window not yet received: the client's credits.
    available: u64,
}

impl CreditWindow {
    pub fn new() -> Self {
        Self {
            low: 0,
            received: VecDeque::from([false]),
            available: 1,
        }
    }

    /// Takes the `count` ids starting at `message_id` out of the window.
    /// Fails, leaving the window as it was, when any of them is outside it or
    /// was received before.
    pub fn consume(&mut self, message_id: u64, count: u64) -> bool {
        let Some(start) = message_id.checked_sub(self.low) else {
            return false;
        };
        let Some(end) = start.checked_add(count) else {
            return false;
        };
        if end > self.received.len() as u64 {
            return false;
        }
        let (start, end) = (start as usize, end as usize);
        if self.received.range(start..end).any(|&r| r) {
            return false;
        }
        for r in self.received.range_mut(start..end) {
            *r = true;
        }
        self.available -= count;
        while self.received.front() == Some(&true) {
            self.received.pop_front();
            self.low += 1;
        }
        true
    }

    /// Credits for one response, added to the window. Grants what the
    /// client asked for while it holds at most [`MAX_CREDITS`] and the
    /// window spans at most twice that, and at least one when the client
    /// would otherwise hold none or `at_least_one` is set (NEGOTIATE).
    pub fn grant(&mut self, requested: u16, at_least_one: bool) -> u16 {
        let span = self.received.len() as u64;
        let mut granted = u64::from(requested)
            .min(MAX_CREDITS.saturating_sub(self.available))
            .min((2 * MAX_CREDITS).saturating_sub(span));
        if granted == 0 && (self.available == 0 || at_least_one) {
            granted = 1;
        }
        // MessageId 0xFFFFFFFFFFFFFFFF is never valid in a request.
        let high = self.low.saturating_add(span);
        granted = granted.min((u64::MAX - 1).saturating_sub(high));
        self.received
            .extend(std::iter::repeat_n(false, granted as usize));
        self.available += granted;
        granted as u16
    }
}

impl Default for CreditWindow {
    fn default() -> Self {
        Self::new()
    }
}

/// CreditCharge needed for a request whose larger direction carries
/// `payload` bytes (MS-SMB2 3.1.5.2).
pub fn charge_for(payload: u64) -> u64 {
    payload.saturating_sub(1) / 65536 + 1
}

/// Whether `credit_charge` covers `payload` bytes (MS-SMB2 3.3.5.2.5). A
/// zero charge covers up to 64 KiB.
pub fn charge_covers(credit_charge: u16, payload: u64) -> bool {
    match credit_charge {
        0 => payload <= 65536,
        charge => charge_for(payload) <= u64::from(charge),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn starts_with_message_id_zero_only() {
        let mut w = CreditWindow::new();
        assert!(!w.consume(1, 1));
        assert!(w.consume(0, 1));
        assert!(!w.consume(0, 1), "replayed id");
    }

    #[test]
    fn ids_are_used_once_in_any_order() {
        let mut w = CreditWindow::new();
        assert!(w.consume(0, 1));
        assert_eq!(w.grant(3, false), 3);
        assert!(w.consume(3, 1));
        assert!(w.consume(1, 1));
        assert!(!w.consume(3, 1));
        assert!(!w.consume(4, 1), "never granted");
        assert!(w.consume(2, 1));
    }

    #[test]
    fn multi_credit_requests_take_a_range() {
        let mut w = CreditWindow::new();
        assert!(w.consume(0, 1));
        assert_eq!(w.grant(16, false), 16);
        assert!(!w.consume(1, 17));
        assert!(w.consume(1, 16));
        assert!(!w.consume(16, 1));
        assert!(!w.consume(u64::MAX, 2));
    }

    #[test]
    fn grants_keep_the_client_between_one_and_the_maximum() {
        let mut w = CreditWindow::new();
        assert!(w.consume(0, 1));
        assert_eq!(w.grant(0, false), 1, "never down to zero");
        assert!(w.consume(1, 1));
        assert_eq!(w.grant(0, true), 1, "NEGOTIATE gets one");
        assert_eq!(w.grant(0, true), 1);
        assert_eq!(w.grant(u16::MAX, false), (MAX_CREDITS - 2) as u16);
        assert_eq!(w.grant(1, false), 0, "already at the maximum");
    }

    #[test]
    fn an_unused_id_stops_the_window_growing() {
        let mut w = CreditWindow::new();
        assert!(w.consume(0, 1));
        w.grant(64, false);
        // The client never sends id 1; the window cannot span more than
        // 2 * MAX_CREDITS ids from it.
        let mut next = 2;
        for _ in 0..4 * MAX_CREDITS {
            if !w.consume(next, 1) {
                break;
            }
            next += 1;
            w.grant(64, false);
        }
        assert_eq!(next, 2 * MAX_CREDITS + 1);
        assert!(w.consume(1, 1));
        assert!(w.grant(64, false) > 0);
    }

    #[test]
    fn credit_charge_covers_the_payload() {
        assert!(charge_covers(0, 0));
        assert!(charge_covers(0, 65536));
        assert!(!charge_covers(0, 65537));
        assert!(charge_covers(1, 65536));
        assert!(!charge_covers(1, 65537));
        assert!(charge_covers(16, 1 << 20));
        assert!(!charge_covers(15, 1 << 20));
        assert_eq!(charge_for(0), 1);
    }
}
