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
use super::overlay::{Claim, Held};
use super::retry::Stop;

/// The two signals of a pause a test puts up: the job notifies the first when
/// it reaches the pause, and goes on when the second is notified.
#[cfg(test)]
pub(super) type Gates = (Arc<tokio::sync::Notify>, Arc<tokio::sync::Notify>);

/// What the worker runs jobs with, and the signals it sends.
pub(super) struct Jobs {
    /// The size of the parts of a multipart upload; objects up to this size go
    /// up in one request.
    pub(super) part_size: u64,
    /// Jobs at once, and parts in flight for each.
    pub(super) concurrency: usize,
    /// Ends the worker, and the retries of the clean-up it does for jobs.
    pub(super) stop: Stop,
    /// A count of the jobs that have ended.
    progress: watch::Sender<u64>,
    /// Set when the worker has ended, however it ended.
    pub(super) exited: watch::Sender<bool>,
    /// Keeps the worker from starting jobs while set.
    #[cfg(test)]
    pub(super) held: std::sync::atomic::AtomicBool,
    /// Makes the worker panic.
    #[cfg(test)]
    pub(super) panic_worker: std::sync::atomic::AtomicBool,
    /// Makes the next job that has hashed a file wait.
    #[cfg(test)]
    pub(super) pause: std::sync::Mutex<Option<Gates>>,
    /// Makes the next job whose request has stored the file wait.
    #[cfg(test)]
    pub(super) pause_stored: std::sync::Mutex<Option<Gates>>,
}

impl Jobs {
    pub(super) fn new(part_size: u64, concurrency: usize) -> Arc<Jobs> {
        Arc::new(Jobs {
            part_size,
            concurrency,
            stop: Stop::new(),
            progress: watch::Sender::new(0),
            exited: watch::Sender::new(false),
            #[cfg(test)]
            held: std::sync::atomic::AtomicBool::new(false),
            #[cfg(test)]
            panic_worker: std::sync::atomic::AtomicBool::new(false),
            #[cfg(test)]
            pause: std::sync::Mutex::new(None),
            #[cfg(test)]
            pause_stored: std::sync::Mutex::new(None),
        })
    }

    #[cfg(test)]
    fn is_held(&self) -> bool {
        self.held.load(std::sync::atomic::Ordering::SeqCst)
    }

    #[cfg(not(test))]
    fn is_held(&self) -> bool {
        false
    }
}

/// The job running for an entry. When it ends the entry is free for the next
/// job, and the hold on it ends.
pub(super) struct Running {
    jobs: Arc<Jobs>,
    held: Option<Held>,
    pub(super) entry: Arc<Entry>,
    /// Stops the job when the entry changes.
    pub(super) stop: Stop,
}

impl Running {
    pub(super) fn held(&self) -> &Held {
        self.held.as_ref().expect("held until dropped")
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        self.entry.state().job = None;
        // The release puts the entry back in the queue if it has more to
        // store.
        drop(self.held.take());
        self.jobs.progress.send_modify(|ended| *ended += 1);
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
        assert!(
            !jobs.panic_worker.load(std::sync::atomic::Ordering::SeqCst),
            "a test made the worker panic"
        );
        let may_start = !jobs.is_held() && running.len() < jobs.concurrency;
        if may_start {
            start(&shared, &mut running, &mut stops);
        }
        let due = if may_start { queue.next_due() } else { None };
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
fn start(shared: &Arc<Shared>, running: &mut JoinSet<()>, stops: &mut HashMap<Id, Stop>) {
    let queue = shared.overlay.queue();
    let now = Instant::now();
    while running.len() < shared.jobs.concurrency {
        let Some(entry) = queue.pop_due(now) else {
            break;
        };
        match shared.overlay.claim(entry, now) {
            Claim::Run(held, stop) => {
                let job = Running {
                    jobs: Arc::clone(&shared.jobs),
                    entry: Arc::clone(&held.entry),
                    held: Some(held),
                    stop: stop.clone(),
                };
                let handle = running.spawn(job::run(Arc::clone(shared), job));
                stops.insert(handle.id(), stop);
            }
            Claim::Later(entry, due) => queue.push(entry, due),
            Claim::Skip => {}
        }
    }
}

impl Shared {
    /// Waits until the files the backend holds bytes of and the directory
    /// markers it has not put, as they stand when the call begins, are stored
    /// in the bucket, or have failed for good.
    pub(super) async fn sync(&self) -> Result<(), S3Error> {
        if self.local.is_none() {
            return Ok(());
        }
        let mut ended = self.jobs.progress.subscribe();
        let mut exited = self.jobs.exited.subscribe();
        let waits = self.overlay.work();
        loop {
            let mut waiting = false;
            for (entry, generation) in &waits {
                match entry.progress(*generation) {
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
