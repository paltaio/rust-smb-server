//! Requests answered asynchronously (MS-SMB2 3.3.4.2): the operations
//! waiting on a connection, and the tasks that complete them.

use std::collections::HashMap;
use std::future::Future;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use tokio::sync::watch;
use tokio::task::JoinSet;
use tracing::debug;

use crate::proto::header::Smb2Header;
use crate::proto::messages::FileId;

/// Most requests one connection may have waiting at once; the default
/// blocking-operation credit of Windows servers (MS-SMB2 3.3.4.2). Each
/// waiting CHANGE_NOTIFY holds one for as long as it waits.
pub(crate) const MAX_PENDING_REQUESTS: usize = 512;

/// Most bytes of request frames the waiting requests of one connection may
/// hold on to: each keeps itself and the requests compounded after it.
pub(crate) const MAX_PENDING_BYTES: usize = 8 << 20;

/// Why a waiting operation is told to stop waiting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Stop {
    /// CANCEL: the operation ends with STATUS_CANCELLED.
    Cancelled,
    /// Its session, tree or open went away: the operation tries again and
    /// fails the way a new request would.
    Retry,
}

/// Stop notices for one waiting operation.
pub(crate) type StopReceiver = watch::Receiver<Option<Stop>>;

/// One request answered asynchronously.
pub(crate) struct AsyncOp {
    /// Unique on the connection and never 0 (MS-SMB2 3.3.4.2).
    pub async_id: u64,
    pub message_id: u64,
    pub session_id: u64,
    pub tree_id: u32,
    /// The open the request works on, when closing it ends the request.
    pub file_id: Option<FileId>,
    /// Bytes of the request frame kept until the request completes.
    retained: usize,
    stop: watch::Sender<Option<Stop>>,
}

impl AsyncOp {
    /// Tells the operation to stop waiting. A cancellation stays: a later
    /// retry does not replace it.
    fn stop(&self, why: Stop) {
        self.stop.send_if_modified(|current| {
            if *current == Some(Stop::Cancelled) {
                return false;
            }
            *current = Some(why);
            true
        });
    }
}

/// Waits for the next stop notice sent to `rx`.
pub(crate) async fn stopped(rx: &mut StopReceiver) -> Stop {
    loop {
        if rx.changed().await.is_err() {
            return Stop::Cancelled;
        }
        if let Some(why) = *rx.borrow_and_update() {
            return why;
        }
    }
}

/// The asynchronous requests of one connection.
pub(crate) struct PendingOps {
    ops: Mutex<HashMap<u64, Arc<AsyncOp>>>,
    bytes: AtomicUsize,
    next_async_id: AtomicU64,
    /// Set once the connection is closing: no request goes asynchronous.
    closed: AtomicBool,
    tasks: Mutex<JoinSet<()>>,
}

impl Default for PendingOps {
    fn default() -> Self {
        Self {
            ops: Mutex::default(),
            bytes: AtomicUsize::new(0),
            next_async_id: AtomicU64::new(1),
            closed: AtomicBool::new(false),
            tasks: Mutex::default(),
        }
    }
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

impl PendingOps {
    /// Registers the request `hdr` as asynchronous, holding `retained`
    /// bytes of its frame. Returns it with the receiver of its stop
    /// notices, which sees every stop sent from here on. `None` when the
    /// connection is closing, already has [`MAX_PENDING_REQUESTS`] waiting,
    /// or the bytes would pass [`MAX_PENDING_BYTES`].
    pub(crate) fn reserve(
        &self,
        hdr: &Smb2Header,
        file_id: Option<FileId>,
        retained: usize,
    ) -> Option<(Arc<AsyncOp>, StopReceiver)> {
        let mut ops = lock(&self.ops);
        if self.closed.load(Ordering::Acquire) || ops.len() >= MAX_PENDING_REQUESTS {
            return None;
        }
        self.bytes
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |held| {
                (held + retained <= MAX_PENDING_BYTES).then_some(held + retained)
            })
            .ok()?;
        let (stop, rx) = watch::channel(None);
        let op = Arc::new(AsyncOp {
            async_id: self.next_async_id.fetch_add(1, Ordering::Relaxed),
            message_id: hdr.message_id,
            session_id: hdr.session_id,
            tree_id: hdr.tree_id().unwrap_or(0),
            file_id,
            retained,
            stop,
        });
        ops.insert(op.async_id, Arc::clone(&op));
        Some((op, rx))
    }

    /// Forgets the request `async_id` once it has its final response.
    pub(crate) fn finish(&self, async_id: u64) {
        if let Some(op) = lock(&self.ops).remove(&async_id) {
            self.bytes.fetch_sub(op.retained, Ordering::AcqRel);
        }
    }

    /// MS-SMB2 3.3.5.16: cancels the request a CANCEL names, by AsyncId when
    /// it is marked async and by MessageId otherwise, when it belongs to the
    /// CANCEL's session. Nothing answers the CANCEL itself.
    pub(crate) fn cancel(&self, hdr: &Smb2Header) {
        let ops = lock(&self.ops);
        let target = match hdr.async_id() {
            Some(async_id) => ops.get(&async_id),
            None => ops.values().find(|op| op.message_id == hdr.message_id),
        };
        match target {
            Some(op) if op.session_id == hdr.session_id => {
                debug!(async_id = op.async_id, "request cancelled");
                op.stop(Stop::Cancelled);
            }
            _ => debug!("CANCEL matches no waiting request"),
        }
    }

    /// Stops waiting, with `why`, every request for which `matches` holds.
    pub(crate) fn stop_where(&self, why: Stop, matches: impl Fn(&AsyncOp) -> bool) {
        for op in lock(&self.ops).values().filter(|op| matches(op)) {
            op.stop(why);
        }
    }

    /// Runs `task`, which completes a request, on the connection's task set.
    pub(crate) fn spawn(&self, task: impl Future<Output = ()> + Send + 'static) {
        let mut tasks = lock(&self.tasks);
        while tasks.try_join_next().is_some() {}
        tasks.spawn(task);
    }

    /// Refuses new asynchronous requests, cancels the waiting ones and
    /// waits up to `grace` for the tasks completing them. A cancelled
    /// request stops at its next wait, closing what it opened; only a task
    /// stuck past `grace`, in a backend call, is aborted, and a backend
    /// handle it holds is then dropped without being closed.
    pub(crate) async fn shutdown(&self, grace: Duration) {
        self.closed.store(true, Ordering::Release);
        self.stop_where(Stop::Cancelled, |_| true);
        let mut tasks = std::mem::take(&mut *lock(&self.tasks));
        let drained =
            tokio::time::timeout(grace, async { while tasks.join_next().await.is_some() {} }).await;
        if drained.is_err() {
            debug!(left = tasks.len(), "stopping requests that did not finish");
            tasks.shutdown().await;
        }
    }

    /// Requests waiting now.
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        lock(&self.ops).len()
    }

    /// Bytes the waiting requests hold.
    #[cfg(test)]
    pub(crate) fn held_bytes(&self) -> usize {
        self.bytes.load(Ordering::Acquire)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::header::{Command, HeaderTail, SMB2_FLAGS_ASYNC_COMMAND};

    fn header(message_id: u64, session_id: u64) -> Smb2Header {
        Smb2Header {
            command: Command::Create,
            message_id,
            session_id,
            tail: HeaderTail::sync(3),
            ..Smb2Header::default()
        }
    }

    fn cancel(id: u64, session_id: u64, by_async_id: bool) -> Smb2Header {
        let mut hdr = header(0, session_id);
        hdr.command = Command::Cancel;
        if by_async_id {
            hdr.flags |= SMB2_FLAGS_ASYNC_COMMAND;
            hdr.tail = HeaderTail::async_(id);
        } else {
            hdr.message_id = id;
        }
        hdr
    }

    #[test]
    fn requests_and_retained_bytes_are_bounded() {
        let ops = PendingOps::default();
        let mut first = None;
        for id in 0..MAX_PENDING_REQUESTS as u64 {
            let (op, _) = ops.reserve(&header(id + 1, 1), None, 0).unwrap();
            first.get_or_insert(op.async_id);
        }
        assert!(ops.reserve(&header(999, 1), None, 0).is_none());
        ops.finish(first.unwrap());
        assert!(ops.reserve(&header(1000, 1), None, 0).is_some());

        let ops = PendingOps::default();
        let (big, _) = ops.reserve(&header(1, 1), None, MAX_PENDING_BYTES).unwrap();
        assert_eq!(big.tree_id, 3);
        assert!(ops.reserve(&header(2, 1), None, 1).is_none());
        assert!(ops.reserve(&header(3, 1), None, 0).is_some());
        ops.finish(big.async_id);
        assert!(
            ops.reserve(&header(4, 1), None, MAX_PENDING_BYTES)
                .is_some()
        );
    }

    #[test]
    fn async_ids_are_unique_and_never_zero() {
        let ops = PendingOps::default();
        let (a, _) = ops.reserve(&header(0, 1), None, 0).unwrap();
        let (b, _) = ops.reserve(&header(0, 1), None, 0).unwrap();
        assert_ne!(a.async_id, 0);
        assert_ne!(a.async_id, b.async_id);
    }

    #[tokio::test]
    async fn cancel_matches_by_either_id_within_its_session() {
        let ops = PendingOps::default();
        let (op, mut rx) = ops.reserve(&header(7, 1), None, 0).unwrap();
        ops.cancel(&cancel(7, 2, false));
        ops.cancel(&cancel(op.async_id + 100, 1, true));
        assert!(!rx.has_changed().unwrap());
        ops.cancel(&cancel(op.async_id, 1, true));
        assert_eq!(stopped(&mut rx).await, Stop::Cancelled);

        let (op, mut rx) = ops.reserve(&header(9, 1), None, 0).unwrap();
        ops.cancel(&cancel(9, 1, false));
        assert_eq!(stopped(&mut rx).await, Stop::Cancelled);
        ops.finish(op.async_id);
        assert_eq!(ops.len(), 1);
    }

    #[tokio::test]
    async fn a_stop_right_after_reserve_is_seen() {
        let ops = PendingOps::default();
        let (_op, mut rx) = ops.reserve(&header(1, 1), None, 0).unwrap();
        ops.stop_where(Stop::Retry, |_| true);
        assert_eq!(stopped(&mut rx).await, Stop::Retry);
    }

    #[tokio::test]
    async fn a_cancellation_is_not_replaced_by_a_retry() {
        let ops = PendingOps::default();
        let (op, mut rx) = ops.reserve(&header(1, 1), None, 0).unwrap();
        ops.cancel(&cancel(op.async_id, 1, true));
        ops.stop_where(Stop::Retry, |_| true);
        assert_eq!(stopped(&mut rx).await, Stop::Cancelled);
    }

    #[tokio::test]
    async fn stop_where_reaches_only_matching_requests() {
        let ops = PendingOps::default();
        let open = FileId::new(5, 5);
        let (_a, mut ra) = ops.reserve(&header(1, 1), Some(open), 0).unwrap();
        let (_b, mut rb) = ops.reserve(&header(2, 2), None, 0).unwrap();
        ops.stop_where(Stop::Retry, |op| op.file_id == Some(open));
        assert_eq!(stopped(&mut ra).await, Stop::Retry);
        assert!(!rb.has_changed().unwrap());
        ops.stop_where(Stop::Retry, |op| op.session_id == 2);
        assert_eq!(stopped(&mut rb).await, Stop::Retry);
    }

    #[tokio::test(start_paused = true)]
    async fn shutdown_cancels_waiters_refuses_new_ones_and_stops_stragglers() {
        let ops = Arc::new(PendingOps::default());
        let (_op, mut rx) = ops.reserve(&header(1, 1), None, 0).unwrap();
        let (done_tx, done_rx) = tokio::sync::oneshot::channel();
        ops.spawn(async move {
            let why = stopped(&mut rx).await;
            let _ = done_tx.send(why);
        });
        ops.spawn(std::future::pending());
        ops.shutdown(Duration::from_secs(1)).await;
        assert_eq!(done_rx.await.unwrap(), Stop::Cancelled);
        assert!(lock(&ops.tasks).is_empty());
        assert!(ops.reserve(&header(2, 1), None, 0).is_none());
    }
}
