//! Per-connection writer task: adds the transport length prefix and writes
//! responses to the socket.

use std::sync::Arc;
use std::time::Duration;

use crate::proto::framing::encode_frame;
use tokio::io::{AsyncWriteExt, WriteHalf};
use tokio::net::TcpStream;
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc};
use tracing::{debug, error, warn};

/// Capacity of the reader-to-writer channel.
pub const WRITER_CHANNEL: usize = 64;

/// Bytes of responses one connection may have waiting for the writer. A
/// larger response waits until the queue is empty.
pub const QUEUED_RESPONSE_BYTES: usize = 4 * 1024 * 1024;

/// One response to send: the final SMB2 header and body, *with signing
/// already applied if required*, and its share of the queue budget.
pub struct FramePayload {
    bytes: Vec<u8>,
    _budget: OwnedSemaphorePermit,
}

/// Sending side of the response queue, used by the reader.
pub struct ResponseQueue {
    tx: mpsc::Sender<FramePayload>,
    budget: Arc<Semaphore>,
}

/// Receiving side of the response queue, owned by the writer. Dropping it
/// wakes a reader waiting for queue space.
pub struct ResponseReceiver {
    rx: mpsc::Receiver<FramePayload>,
    budget: Arc<Semaphore>,
}

/// Response queue bounded by [`WRITER_CHANNEL`] responses and
/// [`QUEUED_RESPONSE_BYTES`] bytes.
pub fn response_queue() -> (ResponseQueue, ResponseReceiver) {
    let (tx, rx) = mpsc::channel(WRITER_CHANNEL);
    let budget = Arc::new(Semaphore::new(QUEUED_RESPONSE_BYTES));
    (
        ResponseQueue {
            tx,
            budget: budget.clone(),
        },
        ResponseReceiver { rx, budget },
    )
}

impl ResponseQueue {
    /// Queues a response, waiting while the queue is full. Fails once the
    /// writer is gone.
    pub async fn send(&self, bytes: Vec<u8>) -> Result<(), ()> {
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
                _budget: budget,
            })
            .await
            .map_err(|_| ())
    }

    /// Resolves once the writer is gone.
    pub async fn closed(&self) {
        self.tx.closed().await;
    }
}

impl Drop for ResponseReceiver {
    fn drop(&mut self) {
        self.budget.close();
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
