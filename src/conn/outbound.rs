//! A connection's way out for messages other connections raise, such as
//! lease breaks: queued without waiting, never holding the writer open.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, PoisonError};

use tokio::sync::Notify;

use crate::conn::writer::{NoticeError, ResponseQueue};

/// Unsolicited-message handle of one connection. File state refers to it
/// only weakly, and [`Outbound::close`] drops its queue, so neither keeps
/// the writer running after the reader is done.
#[derive(Default)]
pub(crate) struct Outbound {
    /// Never held across an await.
    queue: Mutex<Option<ResponseQueue>>,
    killed: Notify,
    is_killed: AtomicBool,
}

impl Outbound {
    /// Starts sending through `queue`.
    pub(crate) fn attach(&self, queue: ResponseQueue) {
        *self.queue.lock().unwrap_or_else(PoisonError::into_inner) = Some(queue);
    }

    /// Stops sending, so the writer can finish once the reader has.
    pub(crate) fn close(&self) {
        self.queue
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
    }

    /// Queues an unsolicited message without waiting.
    pub(crate) fn try_send_notice(&self, bytes: Vec<u8>) -> Result<(), NoticeError> {
        match &*self.queue.lock().unwrap_or_else(PoisonError::into_inner) {
            Some(queue) => queue.try_send_notice(bytes),
            None => Err(NoticeError::Closed),
        }
    }

    /// Queues a response to a request completed after its interim
    /// response, waiting while the queue is full.
    pub(crate) async fn send(&self, bytes: Vec<u8>) -> Result<(), ()> {
        let queue = self
            .queue
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        match queue {
            Some(queue) => queue.send(bytes).await,
            None => Err(()),
        }
    }

    /// Ends the connection: its reader stops at the next frame boundary.
    pub(crate) fn kill(&self) {
        self.is_killed.store(true, Ordering::Release);
        self.killed.notify_waiters();
    }

    /// Resolves once [`Outbound::kill`] has been called.
    pub(crate) async fn killed(&self) {
        loop {
            let notified = self.killed.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.is_killed.load(Ordering::Acquire) {
                return;
            }
            notified.await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::conn::writer::response_queue;

    #[tokio::test]
    async fn notices_need_an_attached_queue() {
        let outbound = Outbound::default();
        assert_eq!(outbound.try_send_notice(vec![1]), Err(NoticeError::Closed));
        let (tx, rx) = response_queue();
        outbound.attach(tx.clone());
        outbound.try_send_notice(vec![1]).unwrap();
        drop(tx);
        outbound.close();
        assert_eq!(outbound.try_send_notice(vec![1]), Err(NoticeError::Closed));
        drop(rx);
    }

    #[tokio::test]
    async fn kill_wakes_a_waiter_and_later_ones() {
        let outbound = std::sync::Arc::new(Outbound::default());
        let waiter = tokio::spawn({
            let outbound = std::sync::Arc::clone(&outbound);
            async move { outbound.killed().await }
        });
        tokio::task::yield_now().await;
        outbound.kill();
        waiter.await.unwrap();
        outbound.killed().await;
    }
}
