//! A named pipe open on IPC$: the association its writes drive and the
//! replies waiting to be read (MS-RPCE 2.1.1.2). Each reply fragment is one
//! message: a read returns bytes of one message only, and the rest of a
//! message too long for the read stays for the next one. Readers are
//! served in the order they came.

use std::collections::VecDeque;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use tokio::sync::{Mutex, Notify};
use tracing::{debug, warn};

use super::association::{Association, Step};
use super::pdu::Header;
use super::srvsvc;
use crate::files::OpenSlot;
use crate::ntstatus;
use crate::proto::messages::FileId;
use crate::server::{Caller, ServerState};

/// Pipes one connection may hold open at once.
pub(crate) const MAX_PIPES_PER_CONNECTION: usize = 16;

/// Bytes the pipes of one connection may hold, for unread replies and for
/// PDUs and requests not whole yet.
const MAX_CONNECTION_BYTES: usize = 4 << 20;

/// Unread reply bytes one pipe may hold.
const MAX_OUTBOX: usize = 1 << 20;

/// The pipes of one connection: how many are open and the bytes they hold.
#[derive(Default)]
pub(crate) struct PipeBudget {
    open: Arc<AtomicUsize>,
    bytes: AtomicUsize,
}

impl PipeBudget {
    fn exhausted(&self) -> bool {
        self.bytes.load(Ordering::Acquire) > MAX_CONNECTION_BYTES
    }

    /// Pipes open now.
    #[cfg(test)]
    pub(crate) fn open_pipes(&self) -> usize {
        self.open.load(Ordering::Acquire)
    }

    /// Bytes the pipes hold now.
    #[cfg(test)]
    pub(crate) fn held_bytes(&self) -> usize {
        self.bytes.load(Ordering::Acquire)
    }
}

pub(crate) struct Pipe {
    pub(crate) file_id: FileId,
    /// Open.GrantedAccess.
    pub(crate) granted_access: u32,
    /// The session that opened the pipe.
    caller: Caller,
    state: Mutex<State>,
    /// Held by the reader whose turn it is; the others queue for it.
    readers: Mutex<()>,
    /// Woken when a reply arrives in an empty outbox.
    readable: Notify,
    _open: OpenSlot,
    _pipe: OpenSlot,
    /// Held by a test to stop a waiting reader between finding the pipe
    /// empty and waiting.
    #[cfg(test)]
    gap: Mutex<()>,
}

struct State {
    assoc: Association,
    /// Reply messages not read yet, oldest first.
    outbox: VecDeque<Vec<u8>>,
    /// Bytes in `outbox`.
    queued: usize,
    budget: Arc<PipeBudget>,
    /// Bytes counted against `budget`.
    charged: usize,
}

/// What a read found.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Read {
    /// Bytes of the oldest message; `more` when it has bytes left.
    Data { bytes: Vec<u8>, more: bool },
    /// Nothing for this reader yet: no message, or another reader waits
    /// before it.
    Empty,
    /// The association ended and every reply was read.
    Disconnected,
}

impl Pipe {
    /// A new pipe for `caller`, counted by `open` and against `budget`, or
    /// `None` when the connection already holds
    /// [`MAX_PIPES_PER_CONNECTION`] pipes.
    pub(crate) fn new(
        file_id: FileId,
        granted_access: u32,
        caller: Caller,
        open: OpenSlot,
        budget: &Arc<PipeBudget>,
    ) -> Option<Self> {
        let pipe = OpenSlot::acquire(&budget.open, MAX_PIPES_PER_CONNECTION)?;
        Some(Self {
            file_id,
            granted_access,
            caller,
            state: Mutex::new(State {
                assoc: Association::default(),
                outbox: VecDeque::new(),
                queued: 0,
                budget: Arc::clone(budget),
                charged: 0,
            }),
            readers: Mutex::new(()),
            readable: Notify::new(),
            _open: open,
            _pipe: pipe,
            #[cfg(test)]
            gap: Mutex::new(()),
        })
    }

    /// Writes `data` to the server end. Every reply it causes is queued
    /// before this returns. Fails with STATUS_PIPE_DISCONNECTED once the
    /// association has ended, and with STATUS_INSUFFICIENT_RESOURCES while
    /// the pipe has [`MAX_OUTBOX`] reply bytes unread or the connection's
    /// pipes hold [`MAX_CONNECTION_BYTES`]; nothing is written then. A
    /// write that reaches either limit ends the association: the request
    /// that found no room is answered with a fault, and the bytes after it
    /// are dropped. Calls see the shares of `server`.
    pub(crate) async fn write(&self, server: &ServerState, data: &[u8]) -> Result<(), u32> {
        let mut state = self.state.lock().await;
        self.feed(server, &mut state, data).await
    }

    /// Reads up to `len` bytes of the oldest reply, unless another reader
    /// waits before this one.
    pub(crate) async fn read(&self, len: usize) -> Read {
        let Ok(_turn) = self.readers.try_lock() else {
            return Read::Empty;
        };
        self.state.lock().await.take(len)
    }

    /// Reads up to `len` bytes of the oldest reply, after the readers that
    /// came before, waiting until there is one. Never returns
    /// [`Read::Empty`].
    pub(crate) async fn read_waiting(&self, len: usize) -> Read {
        let _turn = self.readers.lock().await;
        loop {
            // Enabled before the outbox is checked, so a reply queued in
            // between still wakes it.
            let notified = self.readable.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            match self.state.lock().await.take(len) {
                Read::Empty => {}
                read => return read,
            }
            #[cfg(test)]
            drop(self.gap.lock().await);
            notified.await;
        }
    }

    /// Writes `data` and reads up to `len` bytes, as one operation
    /// (FSCTL_PIPE_TRANSCEIVE). Fails with STATUS_PIPE_BUSY while a reply is
    /// unread (MS-FSCC 2.3.48), and as [`Pipe::write`] does. The read part
    /// finds nothing while another reader waits before it.
    pub(crate) async fn transceive(
        &self,
        server: &ServerState,
        data: &[u8],
        len: usize,
    ) -> Result<Read, u32> {
        let turn = self.readers.try_lock();
        let mut state = self.state.lock().await;
        if !state.outbox.is_empty() {
            return Err(ntstatus::STATUS_PIPE_BUSY);
        }
        self.feed(server, &mut state, data).await?;
        Ok(match turn {
            Ok(_) => state.take(len),
            Err(_) => Read::Empty,
        })
    }

    /// Runs the PDUs in `data`. The share list a call answers from is
    /// read with the pipe locked, so calls on one pipe run in order.
    async fn feed(&self, server: &ServerState, state: &mut State, data: &[u8]) -> Result<(), u32> {
        if state.assoc.is_closed() {
            return Err(ntstatus::STATUS_PIPE_DISCONNECTED);
        }
        if state.full() {
            return Err(ntstatus::STATUS_INSUFFICIENT_RESOURCES);
        }
        let was_empty = state.outbox.is_empty();
        let mut rest = data;
        while let Some(step) = state.assoc.next_step(&mut rest) {
            if state.full() && !state.assoc.is_closed() {
                let call_id = match &step {
                    Step::Call(call) => call.call_id,
                    Step::Send(pdu) => Header::read(pdu).map_or(0, |h| h.call_id),
                };
                warn!(queued = state.queued, "pipe replies past their limit");
                let fault = state.assoc.abort(call_id);
                state.push(fault);
                break;
            }
            match step {
                Step::Send(pdu) => state.push(pdu),
                Step::Call(call) => {
                    let result = srvsvc::serve(server, &self.caller, call.opnum, &call.stub).await;
                    debug!(opnum = call.opnum, ok = result.is_ok(), "rpc call");
                    for reply in state.assoc.reply(&call, result) {
                        state.push(reply);
                    }
                }
            }
        }
        state.recharge();
        if was_empty && !state.outbox.is_empty() {
            self.readable.notify_waiters();
        }
        Ok(())
    }
}

impl State {
    fn push(&mut self, reply: Vec<u8>) {
        self.queued += reply.len();
        self.outbox.push_back(reply);
        self.recharge();
    }

    /// Counts what the pipe holds now against the connection's budget.
    fn recharge(&mut self) {
        let held = self.queued + self.assoc.held();
        if held > self.charged {
            self.budget
                .bytes
                .fetch_add(held - self.charged, Ordering::AcqRel);
        } else {
            self.budget
                .bytes
                .fetch_sub(self.charged - held, Ordering::AcqRel);
        }
        self.charged = held;
    }

    /// Whether the pipe, or the connection's pipes, hold all they may.
    fn full(&mut self) -> bool {
        self.recharge();
        self.queued > MAX_OUTBOX || self.budget.exhausted()
    }

    fn take(&mut self, len: usize) -> Read {
        let Some(head) = self.outbox.front_mut() else {
            return if self.assoc.is_closed() {
                Read::Disconnected
            } else {
                Read::Empty
            };
        };
        let (bytes, more) = if head.len() <= len {
            (self.outbox.pop_front().expect("a head message"), false)
        } else {
            (head.drain(..len).collect(), true)
        };
        self.queued -= bytes.len();
        self.recharge();
        Read::Data { bytes, more }
    }
}

impl Drop for State {
    fn drop(&mut self) {
        self.budget.bytes.fetch_sub(self.charged, Ordering::AcqRel);
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use std::sync::LazyLock;

    use super::*;
    use crate::rpc::pdu::tests::{BIND_3CTX, unhex};
    use crate::rpc::pdu::{NCA_SERVER_TOO_BUSY, PTYPE_BIND_ACK, PTYPE_FAULT};

    /// A server the calls in these tests run against.
    static SERVER: LazyLock<Arc<ServerState>> = LazyLock::new(|| {
        crate::SmbServer::builder()
            .listen("127.0.0.1:0".parse().unwrap())
            .build()
            .expect("build")
            .state()
    });

    fn pipe_on(budget: &Arc<PipeBudget>) -> Option<Pipe> {
        let count = Arc::new(AtomicUsize::new(0));
        let open = OpenSlot::acquire(&count, 1).expect("a slot");
        let caller = Caller {
            identity: crate::proto::auth::ntlm::Identity::Anonymous,
            can_encrypt: false,
        };
        Pipe::new(FileId::new(1, 1), 0x0012_019F, caller, open, budget)
    }

    fn pipe() -> Pipe {
        pipe_on(&Arc::default()).expect("a pipe")
    }

    fn request(call_id: u32, opnum: u16) -> Vec<u8> {
        let mut pdu = vec![5, 0, 0, 3, 0x10, 0, 0, 0, 24, 0, 0, 0];
        pdu.extend_from_slice(&call_id.to_le_bytes());
        pdu.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
        pdu.extend_from_slice(&opnum.to_le_bytes());
        pdu
    }

    /// `count` requests in a row, from call_id `first` on.
    fn requests(first: u32, count: u32) -> Vec<u8> {
        (first..first + count)
            .flat_map(|i| request(i, 15))
            .collect()
    }

    fn data(read: Read) -> (Vec<u8>, bool) {
        match read {
            Read::Data { bytes, more } => (bytes, more),
            other => panic!("no data: {other:?}"),
        }
    }

    fn status_of(fault: &[u8]) -> u32 {
        u32::from_le_bytes(fault[24..28].try_into().unwrap())
    }

    async fn queued(pipe: &Pipe) -> usize {
        pipe.state.lock().await.queued
    }

    #[tokio::test]
    async fn a_read_takes_from_one_message_only() {
        let pipe = pipe();
        assert_eq!(pipe.read(100).await, Read::Empty);
        let mut writes = unhex(BIND_3CTX);
        writes.extend(request(2, 15));
        pipe.write(&SERVER, &writes).await.unwrap();

        let (head, more) = data(pipe.read(10).await);
        assert!(more);
        assert_eq!(head[2], PTYPE_BIND_ACK);
        let (rest, more) = data(pipe.read(4280).await);
        assert!(!more);
        assert_eq!(head.len() + rest.len(), 116);
        let (fault, more) = data(pipe.read(4280).await);
        assert!(!more);
        assert_eq!((fault[2], fault.len()), (PTYPE_FAULT, 32));
        assert_eq!(pipe.read(4280).await, Read::Empty);
    }

    #[tokio::test]
    async fn transceive_refuses_while_a_reply_is_unread() {
        let pipe = pipe();
        pipe.write(&SERVER, &unhex(BIND_3CTX)).await.unwrap();
        assert_eq!(
            pipe.transceive(&SERVER, &request(2, 15), 4280).await,
            Err(ntstatus::STATUS_PIPE_BUSY)
        );
        data(pipe.read(4280).await);
        let (fault, _) = data(
            pipe.transceive(&SERVER, &request(2, 15), 4280)
                .await
                .unwrap(),
        );
        assert_eq!(fault[2], PTYPE_FAULT);
        assert_eq!(pipe.transceive(&SERVER, &[], 0).await, Ok(Read::Empty));
    }

    #[tokio::test]
    async fn after_a_protocol_error_the_replies_drain_and_the_pipe_disconnects() {
        let pipe = pipe();
        pipe.write(&SERVER, &request(1, 15)).await.unwrap();
        assert_eq!(
            pipe.write(&SERVER, &unhex(BIND_3CTX)).await,
            Err(ntstatus::STATUS_PIPE_DISCONNECTED)
        );
        let (nak, _) = data(pipe.read(4280).await);
        assert_eq!(nak.len(), 24);
        assert_eq!(pipe.read(4280).await, Read::Disconnected);
        assert_eq!(
            pipe.transceive(&SERVER, &[], 10).await,
            Err(ntstatus::STATUS_PIPE_DISCONNECTED)
        );
    }

    #[tokio::test]
    async fn a_write_past_the_outbox_limit_ends_the_association() {
        let pipe = pipe();
        pipe.write(&SERVER, &unhex(BIND_3CTX)).await.unwrap();
        data(pipe.read(4280).await);
        // Each request queues a 32-byte fault; the limit is crossed by the
        // request that comes after 32768 of them.
        let limit = (MAX_OUTBOX / 32) as u32;
        pipe.write(&SERVER, &requests(10, limit + 100))
            .await
            .unwrap();
        let mut faults = Vec::new();
        while let Read::Data { bytes, .. } = pipe.read(4280).await {
            faults.push(bytes);
        }
        assert_eq!(faults.len() as u32, limit + 2);
        let last = faults.last().unwrap();
        assert_eq!(status_of(last), NCA_SERVER_TOO_BUSY);
        assert_eq!(
            u32::from_le_bytes(last[12..16].try_into().unwrap()),
            10 + limit + 1
        );
        assert_eq!(pipe.read(4280).await, Read::Disconnected);
        assert_eq!(
            pipe.write(&SERVER, &request(1, 15)).await,
            Err(ntstatus::STATUS_PIPE_DISCONNECTED)
        );
    }

    #[tokio::test]
    async fn the_connection_budget_refuses_writes_and_ends_the_pipe_that_overruns_it() {
        let budget = Arc::default();
        let pipes: Vec<Pipe> = (0..5).map(|_| pipe_on(&budget).unwrap()).collect();
        for pipe in &pipes {
            pipe.write(&SERVER, &unhex(BIND_3CTX)).await.unwrap();
            data(pipe.read(4280).await);
        }
        // 1000 KiB of faults on each of four pipes stays under each pipe's
        // limit and under the connection's.
        let batch = requests(10, 320);
        for pipe in &pipes[..4] {
            for _ in 0..100 {
                pipe.write(&SERVER, &batch).await.unwrap();
            }
            assert_eq!(queued(pipe).await, 1000 * 1024);
        }
        assert!(budget.held_bytes() <= MAX_CONNECTION_BYTES);
        // A write whose last reply passes the connection's limit leaves it
        // past; until replies are read, the pipes take no write.
        let room = (MAX_CONNECTION_BYTES - budget.held_bytes()) / 32;
        pipes[4]
            .write(&SERVER, &requests(10, room as u32 + 1))
            .await
            .unwrap();
        assert!(budget.held_bytes() > MAX_CONNECTION_BYTES);
        for pipe in [&pipes[1], &pipes[4]] {
            assert_eq!(
                pipe.write(&SERVER, &request(1, 15)).await,
                Err(ntstatus::STATUS_INSUFFICIENT_RESOURCES)
            );
        }
        while let Read::Data { .. } = pipes[0].read(4280).await {}
        pipes[1].write(&SERVER, &request(1, 15)).await.unwrap();

        // A write that passes the limit before its end ends the
        // association of its pipe, and its last reply says why.
        pipes[4]
            .write(&SERVER, &requests(10, 40_000))
            .await
            .unwrap();
        let mut last = Vec::new();
        while let Read::Data { bytes, .. } = pipes[4].read(4280).await {
            last = bytes;
        }
        assert_eq!(status_of(&last), NCA_SERVER_TOO_BUSY);
        assert_eq!(pipes[4].read(4280).await, Read::Disconnected);

        drop(pipes);
        assert_eq!(budget.held_bytes(), 0);
        assert_eq!(budget.open_pipes(), 0);
    }

    #[tokio::test]
    async fn a_connection_holds_at_most_16_pipes() {
        let budget = Arc::default();
        let pipes: Vec<Pipe> = (0..MAX_PIPES_PER_CONNECTION)
            .map(|_| pipe_on(&budget).expect("under the limit"))
            .collect();
        assert!(pipe_on(&budget).is_none());
        drop(pipes);
        assert!(pipe_on(&budget).is_some());
    }

    #[tokio::test]
    async fn a_request_being_reassembled_counts_against_the_budget() {
        let budget = Arc::default();
        let pipe = pipe_on(&budget).unwrap();
        pipe.write(&SERVER, &unhex(BIND_3CTX)).await.unwrap();
        data(pipe.read(4280).await);
        let base = budget.held_bytes();
        let mut first = request(5, 15);
        first[3] = 1;
        first.extend_from_slice(&[0; 1000]);
        first[8..10].copy_from_slice(&1024u16.to_le_bytes());
        pipe.write(&SERVER, &first).await.unwrap();
        assert!(budget.held_bytes() >= base + 1000);
        let mut last = request(5, 15);
        last[3] = 2;
        pipe.write(&SERVER, &last).await.unwrap();
        data(pipe.read(4280).await);
        // The stub is gone; the buffer that held the largest PDU stays.
        assert!(budget.held_bytes() <= base + 1024);
    }

    #[tokio::test(start_paused = true)]
    async fn a_reply_queued_while_a_reader_finds_the_pipe_empty_wakes_it() {
        let pipe = Arc::new(pipe());
        pipe.write(&SERVER, &unhex(BIND_3CTX)).await.unwrap();
        data(pipe.read(4280).await);
        // The reader stops between finding the pipe empty and waiting;
        // the reply is queued then.
        let gap = pipe.gap.lock().await;
        let reader = tokio::spawn({
            let pipe = Arc::clone(&pipe);
            async move { pipe.read_waiting(4280).await }
        });
        for _ in 0..4 {
            tokio::task::yield_now().await;
        }
        assert!(pipe.readers.try_lock().is_err(), "the reader has its turn");
        pipe.write(&SERVER, &request(2, 15)).await.unwrap();
        drop(gap);
        let read = tokio::time::timeout(Duration::from_secs(60), reader)
            .await
            .expect("the reader wakes")
            .unwrap();
        assert_eq!(data(read).0[2], PTYPE_FAULT);
    }

    #[tokio::test]
    async fn waiting_readers_are_served_in_order() {
        let pipe = Arc::new(pipe());
        pipe.write(&SERVER, &unhex(BIND_3CTX)).await.unwrap();
        data(pipe.read(4280).await);
        let first = tokio::spawn({
            let pipe = Arc::clone(&pipe);
            async move { pipe.read_waiting(4280).await }
        });
        tokio::task::yield_now().await;
        let second = tokio::spawn({
            let pipe = Arc::clone(&pipe);
            async move { pipe.read_waiting(4280).await }
        });
        tokio::task::yield_now().await;
        // A read that comes while they wait finds nothing.
        pipe.write(&SERVER, &request(7, 15)).await.unwrap();
        assert_eq!(pipe.read(4280).await, Read::Empty);
        assert_eq!(data(first.await.unwrap()).0[12], 7);
        assert!(!second.is_finished());
        pipe.write(&SERVER, &request(8, 15)).await.unwrap();
        assert_eq!(data(second.await.unwrap()).0[12], 8);
    }
}
