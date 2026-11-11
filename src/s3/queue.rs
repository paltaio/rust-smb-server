//! Values that wait for a background job, earliest due first.

use std::cmp::Reverse;
use std::collections::BinaryHeap;
use std::sync::Mutex;
use std::sync::PoisonError;
use std::time::Instant;

use tokio::sync::Notify;
use tokio::sync::futures::Notified;

/// A value and the time from which it may be taken.
struct Item<T> {
    due: Instant,
    /// Breaks ties: the value queued first comes out first.
    seq: u64,
    value: T,
}

impl<T> PartialEq for Item<T> {
    fn eq(&self, other: &Self) -> bool {
        (self.due, self.seq) == (other.due, other.seq)
    }
}

impl<T> Eq for Item<T> {}

impl<T> PartialOrd for Item<T> {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl<T> Ord for Item<T> {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        (self.due, self.seq).cmp(&(other.due, other.seq))
    }
}

struct Inner<T> {
    items: BinaryHeap<Reverse<Item<T>>>,
    next_seq: u64,
}

/// Values with the time from which each may be taken. The value with the
/// earliest time is taken first, and of equal times the one queued first.
pub(super) struct Queue<T> {
    inner: Mutex<Inner<T>>,
    wake: Notify,
}

impl<T> Queue<T> {
    pub(super) fn new() -> Self {
        Queue {
            inner: Mutex::new(Inner {
                items: BinaryHeap::new(),
                next_seq: 0,
            }),
            wake: Notify::new(),
        }
    }

    /// Queues `value` to be taken from `due`, and wakes the worker.
    pub(super) fn push(&self, value: T, due: Instant) {
        {
            let mut inner = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
            let seq = inner.next_seq;
            inner.next_seq += 1;
            inner.items.push(Reverse(Item { due, seq, value }));
        }
        self.wake.notify_one();
    }

    /// Takes the first value whose time has come at `now`.
    pub(super) fn pop_due(&self, now: Instant) -> Option<T> {
        let mut inner = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        if inner.items.peek()?.0.due > now {
            return None;
        }
        inner.items.pop().map(|Reverse(item)| item.value)
    }

    /// The time of the first value, if there is one.
    pub(super) fn next_due(&self) -> Option<Instant> {
        let inner = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        inner.items.peek().map(|item| item.0.due)
    }

    /// Wakes the worker. A wake-up that finds nobody waiting is kept for the
    /// next wait.
    #[cfg(test)]
    pub(super) fn wake(&self) {
        self.wake.notify_one();
    }

    /// Completes when the queue has a value pushed or [`wake`](Self::wake)
    /// called since the last wait. The future listens once
    /// [`enable`](Notified::enable) is called or it is polled.
    pub(super) fn woken(&self) -> Notified<'_> {
        self.wake.notified()
    }

    /// The number of values queued.
    #[cfg(test)]
    pub(super) fn len(&self) -> usize {
        self.inner
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .items
            .len()
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    fn queue() -> Queue<&'static str> {
        Queue::new()
    }

    fn drain(queue: &Queue<&'static str>, now: Instant) -> Vec<&'static str> {
        std::iter::from_fn(|| queue.pop_due(now)).collect()
    }

    #[test]
    fn the_value_due_first_comes_first() {
        let queue = queue();
        let start = Instant::now();
        queue.push("late", start + Duration::from_secs(30));
        queue.push("early", start + Duration::from_secs(10));
        queue.push("middle", start + Duration::from_secs(20));
        assert_eq!(
            drain(&queue, start + Duration::from_secs(60)),
            ["early", "middle", "late"]
        );
    }

    #[test]
    fn values_with_one_time_come_out_in_the_order_they_went_in() {
        let queue = queue();
        let at = Instant::now();
        for name in ["a", "b", "c", "d"] {
            queue.push(name, at);
        }
        assert_eq!(drain(&queue, at), ["a", "b", "c", "d"]);
    }

    #[test]
    fn nothing_comes_out_before_its_time() {
        let queue = queue();
        let start = Instant::now();
        queue.push("later", start + Duration::from_secs(10));
        queue.push("now", start);
        assert_eq!(queue.next_due(), Some(start));
        assert_eq!(drain(&queue, start + Duration::from_secs(9)), ["now"]);
        assert_eq!(queue.next_due(), Some(start + Duration::from_secs(10)));
        assert_eq!(queue.pop_due(start + Duration::from_secs(9)), None);
        assert_eq!(queue.len(), 1);
        assert_eq!(
            queue.pop_due(start + Duration::from_secs(10)),
            Some("later")
        );
        assert_eq!(queue.next_due(), None);
    }

    #[tokio::test]
    async fn a_push_with_nobody_waiting_wakes_the_next_wait() {
        let queue = queue();
        queue.push("a", Instant::now());
        tokio::time::timeout(Duration::from_secs(5), queue.woken())
            .await
            .unwrap();
        queue.wake();
        tokio::time::timeout(Duration::from_secs(5), queue.woken())
            .await
            .unwrap();
    }
}
