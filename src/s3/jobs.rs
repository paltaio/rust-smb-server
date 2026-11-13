//! The worker: it takes entries off the queue of the overlay when their time
//! comes and runs the jobs that bring the bucket to their state, a few at a
//! time.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use tokio::sync::watch;
use tokio::task::{Id, JoinError, JoinHandle, JoinSet};
use tracing::error;

use super::backend::Shared;
use super::entry::{Entry, Progress};
use super::error::S3Error;
use super::job;
use super::overlay::{Claim, Held, Overlay};
use super::retry::Stop;
use super::tombs;

/// The two signals of a pause a test puts up: the job notifies the first when
/// it reaches the pause, and goes on when the second is notified.
#[cfg(test)]
pub(super) type Gates = (Arc<tokio::sync::Notify>, Arc<tokio::sync::Notify>);

/// Waits here if a test put up `gates`.
#[cfg(test)]
pub(super) async fn pause(gates: &std::sync::Mutex<Option<Gates>>) {
    if let Some((reached, resume)) = take_gates(gates) {
        reached.notify_one();
        resume.notified().await;
    }
}

/// [`pause`] for a thread that blocks.
#[cfg(test)]
pub(super) fn pause_blocking(gates: &std::sync::Mutex<Option<Gates>>) {
    if let Some((reached, resume)) = take_gates(gates) {
        reached.notify_one();
        tokio::runtime::Handle::current().block_on(resume.notified());
    }
}

#[cfg(test)]
fn take_gates(gates: &std::sync::Mutex<Option<Gates>>) -> Option<Gates> {
    gates
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .take()
}

/// A flag a test raises to make the code that checks it panic.
#[cfg(test)]
#[derive(Default)]
pub(super) struct PanicHook(std::sync::atomic::AtomicBool);

#[cfg(test)]
impl PanicHook {
    pub(super) fn raise(&self) {
        self.0.store(true, std::sync::atomic::Ordering::SeqCst);
    }

    /// Panics with `what` if a test raised the flag.
    pub(super) fn check(&self, what: &str) {
        assert!(!self.0.load(std::sync::atomic::Ordering::SeqCst), "{what}");
    }
}

/// The size of the largest object one CopyObject request takes.
const MAX_COPY: u64 = 5 << 30;

/// What the worker runs jobs with, and the signals it sends.
pub(super) struct Jobs {
    /// The size of the parts of a multipart upload; objects up to this size go
    /// up in one request.
    pub(super) part_size: u64,
    /// The size of the largest object one copy request takes; a larger one is
    /// copied in parts of this size.
    copy_limit: std::sync::atomic::AtomicU64,
    /// Jobs at once, and parts in flight for each.
    pub(super) concurrency: usize,
    /// Ends the worker, and the retries of the clean-up it does for jobs.
    pub(super) stop: Stop,
    /// Set when the worker has ended, however it ended.
    pub(super) exited: watch::Sender<bool>,
    /// How many tasks run on after the call that started them answered: those
    /// of a renamed directory and those that record a closed file. The worker
    /// does not end before those that began by then have. A task that begins
    /// later holds the backend state, so the cache directory stays locked until
    /// it ends.
    tasks: watch::Sender<usize>,
    /// How many of those tasks record closed files.
    #[cfg(test)]
    pub(super) saves: watch::Sender<usize>,
    /// Keeps the worker from starting jobs while set.
    #[cfg(test)]
    pub(super) held: std::sync::atomic::AtomicBool,
    /// Keeps the worker from deleting keys no entry owns while set.
    #[cfg(test)]
    pub(super) sweeps_held: std::sync::atomic::AtomicBool,
    /// Makes the worker panic.
    #[cfg(test)]
    pub(super) panic_worker: PanicHook,
    /// Makes the next job that has hashed a file wait.
    #[cfg(test)]
    pub(super) pause: std::sync::Mutex<Option<Gates>>,
    /// Makes the next job whose request has stored the file wait.
    #[cfg(test)]
    pub(super) pause_stored: std::sync::Mutex<Option<Gates>>,
    /// Makes the next job that has taken in what it stored wait, before it
    /// deletes keys.
    #[cfg(test)]
    pub(super) pause_landed: std::sync::Mutex<Option<Gates>>,
    /// Makes the next lookup that found an object wait before it takes a hold
    /// on the entry for it.
    #[cfg(test)]
    pub(super) pause_found: std::sync::Mutex<Option<Gates>>,
    /// Makes the next rename wait after it has reserved its name.
    #[cfg(test)]
    pub(super) pause_reserved: std::sync::Mutex<Option<Gates>>,
    /// Makes the next move of a directory wait before it records the entries
    /// it made.
    #[cfg(test)]
    pub(super) pause_batch: std::sync::Mutex<Option<Gates>>,
    /// Makes the next create wait once it has checked the directory it is in,
    /// before it enters the overlay.
    #[cfg(test)]
    pub(super) pause_create: std::sync::Mutex<Option<Gates>>,
    /// Makes the next move of a directory wait once it has read the keys below
    /// it.
    #[cfg(test)]
    pub(super) pause_listed: std::sync::Mutex<Option<Gates>>,
    /// Makes the next task that records a closed file wait before it takes the
    /// locks of the entry.
    #[cfg(test)]
    pub(super) pause_close: std::sync::Mutex<Option<Gates>>,
    /// Makes the task that records the entries of a moved directory panic.
    #[cfg(test)]
    pub(super) panic_dissolve: PanicHook,
    /// Makes the tasks that read the metadata of moved objects panic.
    #[cfg(test)]
    pub(super) panic_read_base: PanicHook,
    /// How many times a call waited for requests in flight or keys to clear.
    #[cfg(test)]
    pub(super) waits: std::sync::atomic::AtomicUsize,
}

impl Jobs {
    pub(super) fn new(part_size: u64, concurrency: usize) -> Arc<Jobs> {
        Arc::new(Jobs {
            part_size,
            copy_limit: std::sync::atomic::AtomicU64::new(MAX_COPY),
            concurrency,
            stop: Stop::new(),
            exited: watch::Sender::new(false),
            tasks: watch::Sender::new(0),
            #[cfg(test)]
            saves: watch::Sender::new(0),
            #[cfg(test)]
            held: std::sync::atomic::AtomicBool::new(false),
            #[cfg(test)]
            sweeps_held: std::sync::atomic::AtomicBool::new(false),
            #[cfg(test)]
            panic_worker: PanicHook::default(),
            #[cfg(test)]
            pause: std::sync::Mutex::new(None),
            #[cfg(test)]
            pause_stored: std::sync::Mutex::new(None),
            #[cfg(test)]
            pause_landed: std::sync::Mutex::new(None),
            #[cfg(test)]
            pause_found: std::sync::Mutex::new(None),
            #[cfg(test)]
            pause_reserved: std::sync::Mutex::new(None),
            #[cfg(test)]
            pause_batch: std::sync::Mutex::new(None),
            #[cfg(test)]
            pause_create: std::sync::Mutex::new(None),
            #[cfg(test)]
            pause_listed: std::sync::Mutex::new(None),
            #[cfg(test)]
            pause_close: std::sync::Mutex::new(None),
            #[cfg(test)]
            panic_dissolve: PanicHook::default(),
            #[cfg(test)]
            panic_read_base: PanicHook::default(),
            #[cfg(test)]
            waits: std::sync::atomic::AtomicUsize::new(0),
        })
    }

    /// Notes a task that runs on after the call that started it answered,
    /// until the value returned is dropped.
    pub(super) fn begin_task(self: &Arc<Self>) -> Task {
        self.tasks.send_modify(|count| *count += 1);
        Task(Arc::clone(self))
    }

    /// Notes a task that records a closed file, until the value returned is
    /// dropped.
    pub(super) fn begin_save(self: &Arc<Self>) -> Save {
        #[cfg(test)]
        self.saves.send_modify(|count| *count += 1);
        Save {
            _task: self.begin_task(),
            #[cfg(test)]
            jobs: Arc::clone(self),
        }
    }

    /// The size of the largest object one copy request takes.
    pub(super) fn copy_limit(&self) -> u64 {
        self.copy_limit.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Lowers the copy limit, for tests.
    #[cfg(test)]
    pub(super) fn limit_copy(&self, bytes: u64) {
        self.copy_limit
            .store(bytes, std::sync::atomic::Ordering::SeqCst);
    }

    #[cfg(test)]
    fn is_held(&self) -> bool {
        self.held.load(std::sync::atomic::Ordering::SeqCst)
    }

    #[cfg(not(test))]
    fn is_held(&self) -> bool {
        false
    }

    #[cfg(test)]
    fn are_sweeps_held(&self) -> bool {
        self.sweeps_held.load(std::sync::atomic::Ordering::SeqCst)
    }

    #[cfg(not(test))]
    fn are_sweeps_held(&self) -> bool {
        false
    }
}

/// A task that runs on after the call that started it answered.
pub(super) struct Task(Arc<Jobs>);

impl Drop for Task {
    fn drop(&mut self) {
        self.0.tasks.send_modify(|count| *count -= 1);
    }
}

/// A task that records a closed file.
pub(super) struct Save {
    _task: Task,
    #[cfg(test)]
    jobs: Arc<Jobs>,
}

#[cfg(test)]
impl Drop for Save {
    fn drop(&mut self) {
        self.jobs.saves.send_modify(|count| *count -= 1);
    }
}

/// The job running for an entry. When it ends the entry is free for the next
/// job, and the hold on it ends.
pub(super) struct Running {
    overlay: Arc<Overlay>,
    held: Option<Held>,
    pub(super) entry: Arc<Entry>,
    /// Stops the job when the entry changes.
    pub(super) stop: Stop,
    /// The job resolves a cycle of entries that each wait for the next.
    pub(super) cycle: bool,
}

impl Running {
    pub(super) fn held(&self) -> &Held {
        self.held.as_ref().expect("held until dropped")
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        self.entry.state().job = None;
        self.overlay.end_writes(&self.entry);
        // The release puts the entry back in the queue if it has more to
        // store.
        drop(self.held.take());
        self.overlay.touch();
    }
}

/// Owns the worker of a backend. The worker ends when the last clone of the
/// backend, and with it this, is dropped.
pub(super) struct Guard {
    jobs: Arc<Jobs>,
    _worker: Option<JoinHandle<()>>,
}

impl Guard {
    /// Starts the worker of `shared`, if it is writable.
    pub(super) fn start(shared: &Arc<Shared>) -> Guard {
        let worker = shared
            .local
            .is_some()
            .then(|| tokio::spawn(work(Arc::clone(shared))));
        Guard {
            jobs: Arc::clone(&shared.jobs),
            _worker: worker,
        }
    }
}

impl Drop for Guard {
    fn drop(&mut self) {
        self.jobs.stop.stop();
    }
}

/// Tells that the worker has ended when it is dropped, whether the worker
/// returned, panicked or was cancelled.
struct Exit(Arc<Jobs>);

impl Drop for Exit {
    fn drop(&mut self) {
        self.0.exited.send_replace(true);
    }
}

/// Runs jobs until the backend is dropped, then lets go of the backend's
/// state.
async fn work(shared: Arc<Shared>) {
    let _exit = Exit(Arc::clone(&shared.jobs));
    run_jobs(shared).await;
}

/// Runs jobs until the backend is dropped. Jobs that are running then are
/// stopped, and the worker waits for the requests they have in flight. A
/// multipart upload left that way stays in the record of its entry, and the
/// next backend aborts it.
async fn run_jobs(shared: Arc<Shared>) {
    let jobs = Arc::clone(&shared.jobs);
    let queue = shared.overlay.queue();
    let mut running: JoinSet<()> = JoinSet::new();
    let mut stops: HashMap<Id, Stop> = HashMap::new();
    // Listens from before the queue is read, so a push after the read ends
    // the wait below.
    let woken = queue.woken();
    tokio::pin!(woken);
    loop {
        woken.as_mut().enable();
        #[cfg(test)]
        jobs.panic_worker.check("a test made the worker panic");
        let may_start = !jobs.is_held() && running.len() < jobs.concurrency;
        // One clock reading serves the claims and the wait, so a time that
        // passes between them is not missed.
        let now = Instant::now();
        if may_start {
            start(&shared, &mut running, &mut stops, now);
        }
        let due = if may_start {
            [queue.next_due(), shared.overlay.tomb_next_due(now)]
                .into_iter()
                .flatten()
                .min()
        } else {
            None
        };
        tokio::select! {
            () = jobs.stop.stopped() => break,
            () = woken.as_mut() => woken.set(queue.woken()),
            ended = running.join_next_with_id(), if !running.is_empty() => {
                if let Some(ended) = ended {
                    ended_job(ended, &mut stops);
                }
            }
            () = wait_until(due) => {}
        }
    }
    for stop in stops.values() {
        stop.stop();
    }
    while let Some(ended) = running.join_next_with_id().await {
        ended_job(ended, &mut stops);
    }
    let _ = jobs.tasks.subscribe().wait_for(|count| *count == 0).await;
}

/// Waits until `at`, or for ever.
async fn wait_until(at: Option<Instant>) {
    match at {
        Some(at) => tokio::time::sleep_until(tokio::time::Instant::from_std(at)).await,
        None => std::future::pending().await,
    }
}

fn ended_job(ended: Result<(Id, ()), JoinError>, stops: &mut HashMap<Id, Stop>) {
    match ended {
        Ok((id, ())) => {
            stops.remove(&id);
        }
        Err(e) => {
            stops.remove(&e.id());
            error!(error = %e, "a background job ended without finishing");
        }
    }
}

/// Starts jobs for the entries of the queue whose time has come, while there
/// is room for them.
fn start(
    shared: &Arc<Shared>,
    running: &mut JoinSet<()>,
    stops: &mut HashMap<Id, Stop>,
    now: Instant,
) {
    let queue = shared.overlay.queue();
    while running.len() < shared.jobs.concurrency {
        let Some(entry) = queue.pop_due(now) else {
            break;
        };
        match shared.overlay.claim(entry, now) {
            Claim::Run(held, stop, cycle) => {
                let job = Running {
                    overlay: Arc::clone(&shared.overlay),
                    entry: Arc::clone(&held.entry),
                    held: Some(held),
                    stop: stop.clone(),
                    cycle,
                };
                let handle = running.spawn(job::run(Arc::clone(shared), job));
                stops.insert(handle.id(), stop);
            }
            Claim::Later(entry, due) => queue.push(entry, due),
            Claim::Skip => {}
        }
    }
    if running.len() < shared.jobs.concurrency
        && !shared.jobs.are_sweeps_held()
        && let Some(claim) = shared.overlay.claim_tombs(now)
    {
        let handle = running.spawn(tombs::delete(Arc::clone(shared), claim));
        stops.insert(handle.id(), shared.jobs.stop.clone());
    }
}

impl Shared {
    /// Waits until the files the backend holds bytes of, the changes of
    /// times, attributes, names and the directory markers it has not put, and
    /// the keys it is to delete, as they stand when the call begins, are in
    /// the bucket, or have failed for good.
    pub(super) async fn sync(&self) -> Result<(), S3Error> {
        if self.local.is_none() {
            return Ok(());
        }
        let mut ended = self.overlay.subscribe();
        let mut exited = self.jobs.exited.subscribe();
        let waits = self.overlay.work();
        let tombs = self.overlay.tomb_waits();
        loop {
            let mut waiting = false;
            for wait in &waits {
                match wait.entry.progress(wait.generation, &wait.gone) {
                    Progress::Done => {}
                    Progress::Waiting => {
                        if let Some(failure) = self.overlay.failure_behind(&wait.entry) {
                            return Err(failure);
                        }
                        waiting = true;
                    }
                    Progress::Failed(failure) => return Err(failure),
                }
            }
            for (key, seq) in &tombs {
                match self.overlay.tomb_progress(key, *seq) {
                    Progress::Done => {}
                    Progress::Waiting => waiting = true,
                    Progress::Failed(failure) => return Err(failure),
                }
            }
            if !waiting {
                return Ok(());
            }
            tokio::select! {
                _ = ended.changed() => {}
                _ = exited.wait_for(|exited| *exited) => return Err(S3Error::Stopped),
            }
        }
    }
}
