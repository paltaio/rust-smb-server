//! Per-connection writer task: adds the transport length prefix and writes
//! responses to the socket.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use crate::proto::framing::encode_frame;
use tokio::io::{AsyncWriteExt, WriteHalf};
use tokio::net::TcpStream;
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc};
use tracing::{debug, error, warn};

/// Responses one connection may have waiting for the writer.
pub const WRITER_CHANNEL: usize = 64;

/// Bytes of responses one connection may have waiting for the writer. A
/// larger response waits until the queue is empty.
pub const QUEUED_RESPONSE_BYTES: usize = 4 * 1024 * 1024;

/// Bytes of unsolicited messages, such as lease breaks, one connection may
/// have waiting for the writer. They never wait for room, so this bound is
/// separate from the response limits.
pub const QUEUED_NOTICE_BYTES: usize = 1024 * 1024;

/// One message to send: the final SMB2 header and body, *with signing
/// already applied if required*, and its share of the queue limits.
pub struct FramePayload {
    bytes: Vec<u8>,
    _budget: Option<OwnedSemaphorePermit>,
    _slot: Option<OwnedSemaphorePermit>,
    _notice: Option<NoticeBytes>,
}

/// Bytes of a queued unsolicited message, given back when it leaves the
/// queue.
struct NoticeBytes {
    queued: Arc<AtomicUsize>,
    len: usize,
}

impl Drop for NoticeBytes {
    fn drop(&mut self) {
        self.queued.fetch_sub(self.len, Ordering::AcqRel);
    }
}

/// Why an unsolicited message was not queued.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NoticeError {
    /// [`QUEUED_NOTICE_BYTES`] are already waiting: the client has not read
    /// for a long time.
    Full,
    /// The writer is gone.
    Closed,
}

/// Sending side of the response queue. Responses and unsolicited messages
/// share one queue, so they reach the socket in the order they were queued.
#[derive(Clone)]
pub struct ResponseQueue {
    tx: mpsc::UnboundedSender<FramePayload>,
    budget: Arc<Semaphore>,
    slots: Arc<Semaphore>,
    notices: Arc<AtomicUsize>,
}

/// Receiving side of the response queue, owned by the writer. Dropping it
/// wakes a reader waiting for queue space. The writer stops once every
/// [`ResponseQueue`] is dropped.
pub struct ResponseReceiver {
    rx: mpsc::UnboundedReceiver<FramePayload>,
    budget: Arc<Semaphore>,
    slots: Arc<Semaphore>,
}

/// Response queue bounded by [`WRITER_CHANNEL`] responses and
/// [`QUEUED_RESPONSE_BYTES`] bytes, plus [`QUEUED_NOTICE_BYTES`] of
/// unsolicited messages.
pub fn response_queue() -> (ResponseQueue, ResponseReceiver) {
    let (tx, rx) = mpsc::unbounded_channel();
    let budget = Arc::new(Semaphore::new(QUEUED_RESPONSE_BYTES));
    let slots = Arc::new(Semaphore::new(WRITER_CHANNEL));
    (
        ResponseQueue {
            tx,
            budget: budget.clone(),
            slots: slots.clone(),
            notices: Arc::default(),
        },
        ResponseReceiver { rx, budget, slots },
    )
}

impl ResponseQueue {
    /// Queues a response, waiting while the queue is full. Fails once the
    /// writer is gone.
    pub async fn send(&self, bytes: Vec<u8>) -> Result<(), ()> {
        let slot = self.slots.clone().acquire_owned().await.map_err(|_| ())?;
        let cost = bytes.len().clamp(1, QUEUED_RESPONSE_BYTES) as u32;
        let budget = self
            .budget
            .clone()
            .acquire_many_owned(cost)
            .await
            .map_err(|_| ())?;
        self.tx
            .send(FramePayload {
                bytes,
                _budget: Some(budget),
                _slot: Some(slot),
                _notice: None,
            })
            .map_err(|_| ())
    }

    /// Queues an unsolicited message without waiting.
    pub fn try_send_notice(&self, bytes: Vec<u8>) -> Result<(), NoticeError> {
        let len = bytes.len();
        self.notices
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |queued| {
                (queued + len <= QUEUED_NOTICE_BYTES).then_some(queued + len)
            })
            .map_err(|_| NoticeError::Full)?;
        let notice = NoticeBytes {
            queued: Arc::clone(&self.notices),
            len,
        };
        self.tx
            .send(FramePayload {
                bytes,
                _budget: None,
                _slot: None,
                _notice: Some(notice),
            })
            .map_err(|_| NoticeError::Closed)
    }

    /// Resolves once the writer is gone.
    pub async fn closed(&self) {
        self.tx.closed().await;
    }
}

#[cfg(test)]
impl ResponseReceiver {
    /// The next queued message, if one is waiting.
    pub(crate) fn try_recv(&mut self) -> Option<Vec<u8>> {
        self.rx.try_recv().ok().map(|payload| payload.bytes.clone())
    }

    /// The next queued message, waiting for one.
    pub(crate) async fn recv(&mut self) -> Option<Vec<u8>> {
        self.rx.recv().await.map(|payload| payload.bytes.clone())
    }
}

impl Drop for ResponseReceiver {
    fn drop(&mut self) {
        self.budget.close();
        self.slots.close();
    }
}

/// Writes each response, giving up on the connection when one takes longer
/// than `io_timeout` to send.
pub async fn writer_task(
    mut writer: WriteHalf<TcpStream>,
    mut queue: ResponseReceiver,
    io_timeout: Duration,
) {
    while let Some(payload) = queue.rx.recv().await {
        let mut out = Vec::with_capacity(payload.bytes.len() + 4);
        if let Err(e) = encode_frame(&payload.bytes, &mut out) {
            error!(
                error = %e,
                len = payload.bytes.len(),
                "cannot frame response; closing connection"
            );
            return;
        }
        drop(payload);
        match tokio::time::timeout(io_timeout, writer.write_all(&out)).await {
            Ok(Ok(())) => debug!(len = out.len(), "wrote frame"),
            Ok(Err(e)) => {
                error!(error = %e, "writer task: socket write failed");
                return;
            }
            Err(_) => {
                warn!(
                    len = out.len(),
                    "response not sent in time; closing connection"
                );
                return;
            }
        }
    }
    // Channel closed: flush and bail.
    if let Err(e) = writer.shutdown().await {
        debug!(error = %e, "writer shutdown error (best-effort)");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn notices_bypass_the_response_limits_and_keep_queue_order() {
        let (tx, mut rx) = response_queue();
        for n in 0..WRITER_CHANNEL {
            tx.send(vec![n as u8]).await.unwrap();
        }
        let blocked = tokio::time::timeout(Duration::from_millis(10), tx.send(vec![0xEE])).await;
        assert!(blocked.is_err(), "the response limit holds");
        tx.try_send_notice(vec![0xAA]).unwrap();
        for n in 0..WRITER_CHANNEL {
            assert_eq!(rx.rx.recv().await.unwrap().bytes, [n as u8]);
        }
        assert_eq!(rx.rx.recv().await.unwrap().bytes, [0xAA]);
    }

    #[tokio::test]
    async fn notices_stop_at_their_byte_limit() {
        let (tx, mut rx) = response_queue();
        tx.try_send_notice(vec![0; QUEUED_NOTICE_BYTES - 10])
            .unwrap();
        assert_eq!(tx.try_send_notice(vec![0; 11]), Err(NoticeError::Full));
        tx.try_send_notice(vec![0; 10]).unwrap();
        drop(rx.rx.recv().await.unwrap());
        tx.try_send_notice(vec![0; 11]).unwrap();
        drop(rx);
        assert_eq!(tx.try_send_notice(vec![0]), Err(NoticeError::Closed));
        assert!(tx.send(vec![0]).await.is_err());
    }
}
