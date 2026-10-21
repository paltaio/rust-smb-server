//! Durable opens (MS-SMB2 3.3.1.10, 3.3.7.1): opens kept after their
//! session ends with the connection or a LOGOFF, until they expire or
//! another open needs what their lease caches.
//!
//! Lock order: the table, then `LeaseTable` bindings, a share's file table,
//! a file, a connection's outbound queue. An open is never dropped while the
//! table is locked: dropping it unregisters it, which locks the table.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, Weak};
use std::time::Duration;

use tokio::sync::{RwLock, watch};
use tokio::task::AbortHandle;
use tracing::debug;
use uuid::Uuid;

use crate::conn::state::Open;
use crate::ntstatus;
use crate::server::ShareBindings;
use crate::utils::fill_random;

use super::close_open;
use super::lease::LeaseId;

/// Default for
/// [`SmbServerBuilder::durable_handle_timeout`](crate::SmbServerBuilder::durable_handle_timeout).
pub const DEFAULT_DURABLE_HANDLE_TIMEOUT: Duration = Duration::from_secs(2 * 60);

/// Default for
/// [`SmbServerBuilder::max_disconnected_opens`](crate::SmbServerBuilder::max_disconnected_opens).
pub const DEFAULT_MAX_DISCONNECTED_OPENS: usize = 4096;

/// Every durable open on the server, by DurableFileId (MS-SMB2 3.3.1.5
/// GlobalOpenTable): the ones still in a session, so ids stay unique, and
/// the ones kept after their session ended.
pub(crate) struct DurableTable {
    inner: Mutex<Inner>,
    /// Open.DurableOpenTimeout of every durable open.
    pub(crate) timeout: Duration,
    /// Most opens kept at once, counting every user together.
    max_detached: usize,
    /// Kept opens taken out and still closing on tasks of their own.
    closing: Arc<watch::Sender<usize>>,
    /// Counts the times [`DurableTable::take_for`] ran.
    sweeps: AtomicU64,
}

/// One close of a kept open running on a task of its own, counted in
/// `DurableTable::closing` until it is dropped.
struct InFlight(Arc<watch::Sender<usize>>);

impl InFlight {
    fn new(closing: &Arc<watch::Sender<usize>>) -> Self {
        closing.send_modify(|n| *n += 1);
        Self(Arc::clone(closing))
    }
}

impl Drop for InFlight {
    fn drop(&mut self) {
        self.0.send_modify(|n| *n -= 1);
    }
}

#[derive(Default)]
struct Inner {
    entries: HashMap<u64, Entry>,
    /// Entries in [`State::Detached`].
    detached: usize,
    /// Entries in [`State::Detached`], by owner.
    detached_by_user: HashMap<String, usize>,
    next_generation: u64,
}

struct Entry {
    /// Open.DurableOwner: the configured name of the user who opened it.
    owner: String,
    share: Weak<ShareBindings>,
    /// The lease the open holds. Its key never changes.
    lease: LeaseId,
    state: State,
}

enum State {
    /// The open is in a session's tree.
    Attached,
    /// Kept after its session ended, until `timer` closes it.
    Detached {
        open: Arc<RwLock<Open>>,
        timer: Timer,
        /// Tells this stay from a later one of the same entry.
        generation: u64,
    },
    /// Taken out to be closed. The entry leaves with the open.
    Closing,
}

/// Expiry timer of a kept open. Dropping it stops the timer.
struct Timer(Option<AbortHandle>);

impl Timer {
    /// Lets the timer run on; used by the timer's own task.
    fn disarm(mut self) {
        self.0.take();
    }
}

impl Drop for Timer {
    fn drop(&mut self) {
        if let Some(timer) = self.0.take() {
            timer.abort();
        }
    }
}

/// A durable open's place in the [`DurableTable`]. Dropping it, with the
/// open, removes the entry.
pub(crate) struct DurableReg {
    table: Weak<DurableTable>,
    id: u64,
}

impl DurableReg {
    /// Open.DurableFileId: the persistent part of the open's FileId.
    pub(crate) fn id(&self) -> u64 {
        self.id
    }
}

impl Drop for DurableReg {
    fn drop(&mut self) {
        if let Some(table) = self.table.upgrade() {
            let removed = table.inner().remove(self.id);
            drop(removed);
        }
    }
}

/// What a request to reconnect a durable open presents (MS-SMB2
/// 3.3.5.9.7).
pub(crate) struct Claim<'a> {
    /// The share of the tree the request came on.
    pub share: &'a Arc<ShareBindings>,
    /// The configured name of the session's user; `None` for anonymous.
    pub user: Option<&'a str>,
    /// Connection.ClientGuid.
    pub client: Uuid,
    /// The lease the request names.
    pub lease: Option<LeaseId>,
}

impl Inner {
    /// Takes the open out of the entry `id` when it is kept and `pick`
    /// accepts it, leaving the entry [`State::Closing`].
    fn take_detached(
        &mut self,
        id: u64,
        pick: impl Fn(u64) -> bool,
    ) -> Option<(Arc<RwLock<Open>>, Timer)> {
        let entry = self.entries.get_mut(&id)?;
        match &entry.state {
            State::Detached { generation, .. } if pick(*generation) => {}
            _ => return None,
        }
        let State::Detached { open, timer, .. } =
            std::mem::replace(&mut entry.state, State::Closing)
        else {
            unreachable!("checked above");
        };
        let owner = entry.owner.clone();
        self.count_out(&owner);
        Some((open, timer))
    }

    /// Removes the entry `id`, returning it to be dropped once the table is
    /// unlocked.
    fn remove(&mut self, id: u64) -> Option<Entry> {
        let entry = self.entries.remove(&id)?;
        if matches!(entry.state, State::Detached { .. }) {
            self.count_out(&entry.owner);
        }
        Some(entry)
    }

    fn count_out(&mut self, owner: &str) {
        self.detached -= 1;
        if let Some(n) = self.detached_by_user.get_mut(owner) {
            *n -= 1;
            if *n == 0 {
                self.detached_by_user.remove(owner);
            }
        }
    }
}

impl DurableTable {
    pub(crate) fn new(timeout: Duration, max_detached: usize) -> Self {
        Self {
            inner: Mutex::default(),
            timeout,
            max_detached,
            closing: Arc::new(watch::Sender::new(0)),
            sweeps: AtomicU64::new(0),
        }
    }

    /// A stamp for [`DurableTable::preserve`], taken before the session
    /// whose opens are to be kept leaves its connection.
    pub(crate) fn sweeps(&self) -> u64 {
        self.sweeps.load(Ordering::SeqCst)
    }

    /// Resolves once no close of a kept open taken out earlier is still
    /// running on a task of its own.
    pub(crate) async fn closed(&self) {
        let mut closing = self.closing.subscribe();
        let _ = closing.wait_for(|n| *n == 0).await;
    }

    fn inner(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Most opens of one user kept at once: a quarter of the limit.
    fn max_detached_per_user(&self) -> usize {
        self.max_detached.div_ceil(4)
    }

    /// Registers a durable open of `owner` on `share` holding `lease`, under
    /// a random DurableFileId that is neither 0 nor all ones and that no
    /// other durable open has. `None` when the system has no randomness.
    pub(crate) fn register(
        self: &Arc<Self>,
        owner: &str,
        share: &Arc<ShareBindings>,
        lease: LeaseId,
    ) -> Option<DurableReg> {
        let mut inner = self.inner();
        let id = loop {
            let mut bytes = [0; 8];
            fill_random(&mut bytes).ok()?;
            let id = u64::from_le_bytes(bytes);
            if id != 0 && id != u64::MAX && !inner.entries.contains_key(&id) {
                break id;
            }
        };
        inner.entries.insert(
            id,
            Entry {
                owner: owner.to_string(),
                share: Arc::downgrade(share),
                lease,
                state: State::Attached,
            },
        );
        Some(DurableReg {
            table: Arc::downgrade(self),
            id,
        })
    }

    /// MS-SMB2 3.3.7.1, 3.3.5.6: keeps `open` after its session ends when it
    /// is durable, its lease caches handles with no break in progress, its
    /// byte-range locks, if any, are covered by write caching, and fewer
    /// than the limits are kept already (3.3.2.2 "resource constraints").
    /// A kept open is closed [`DurableTable::timeout`] later unless
    /// something closes it first. Returns the open when it is not kept, for
    /// the caller to close. Waits for requests still using the open.
    ///
    /// `since` is [`DurableTable::sweeps`] from before the open's session
    /// left its connection. A sweep since then may have missed the open, as
    /// it was neither in a session nor kept yet, so the open is not kept.
    pub(crate) async fn preserve(
        self: &Arc<Self>,
        open: Arc<RwLock<Open>>,
        since: u64,
    ) -> Option<Arc<RwLock<Open>>> {
        let mut guard = open.write().await;
        let Some(id) = guard.durable.as_ref().map(DurableReg::id) else {
            drop(guard);
            return Some(open);
        };
        let generation = {
            let mut inner = self.inner();
            let Inner {
                entries,
                detached,
                detached_by_user,
                next_generation,
            } = &mut *inner;
            match entries.get_mut(&id) {
                Some(entry) if matches!(entry.state, State::Attached) => {
                    let by_user = detached_by_user.get(&entry.owner).copied().unwrap_or(0);
                    if self.sweeps() != since {
                        debug!(id, "durable open closed: configuration change");
                        None
                    } else if *detached >= self.max_detached
                        || by_user >= self.max_detached_per_user()
                    {
                        debug!(id, "durable open closed: limit");
                        None
                    } else if guard.file.as_ref().is_some_and(|f| f.try_detach()) {
                        *detached += 1;
                        *detached_by_user.entry(entry.owner.clone()).or_default() += 1;
                        *next_generation += 1;
                        entry.state = State::Detached {
                            open: Arc::clone(&open),
                            timer: Timer(None),
                            generation: *next_generation,
                        };
                        Some(*next_generation)
                    } else {
                        None
                    }
                }
                _ => None,
            }
        };
        let Some(generation) = generation else {
            drop(guard);
            return Some(open);
        };
        guard.slot.take();
        guard.search_state = None;
        drop(guard);
        drop(open);
        debug!(id, timeout = ?self.timeout, "durable open kept");
        self.start_timer(id, generation);
        None
    }

    /// Starts the expiry timer of the stay `generation` of the kept open
    /// `id` (MS-SMB2 3.3.2.2, 3.3.6.2).
    fn start_timer(self: &Arc<Self>, id: u64, generation: u64) {
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            return;
        };
        let table = Arc::downgrade(self);
        let timeout = self.timeout;
        let task = runtime.spawn(async move {
            tokio::time::sleep(timeout).await;
            let expired = table.upgrade().and_then(|t| t.expire(id, generation));
            if let Some((open, _in_flight)) = expired {
                debug!(id, "durable open closed: expired");
                close_open(&open, false).await;
            }
        });
        let mut inner = self.inner();
        match inner.entries.get_mut(&id).map(|e| &mut e.state) {
            Some(State::Detached {
                timer,
                generation: g,
                ..
            }) if *g == generation => *timer = Timer(Some(task.abort_handle())),
            _ => task.abort(),
        }
    }

    /// Takes out the kept open `id` whose timer for the stay `generation`
    /// fired, for the timer's task to close.
    fn expire(&self, id: u64, generation: u64) -> Option<(Arc<RwLock<Open>>, InFlight)> {
        let mut inner = self.inner();
        let (open, timer) = inner.take_detached(id, |g| g == generation)?;
        let in_flight = InFlight::new(&self.closing);
        drop(inner);
        timer.disarm();
        Some((open, in_flight))
    }

    /// Closes the kept open `id`, which no client can take back any more:
    /// a break of its lease needed what the lease caches, or the lease lost
    /// handle caching (MS-SMB2 3.3.4.7). The close runs on a task of the
    /// current runtime.
    pub(crate) fn purge(&self, id: u64) {
        let mut inner = self.inner();
        let Some((open, timer)) = inner.take_detached(id, |_| true) else {
            return;
        };
        let in_flight = InFlight::new(&self.closing);
        drop(inner);
        drop(timer);
        debug!(id, "durable open closed: lease broken");
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            runtime.spawn(async move {
                close_open(&open, false).await;
                drop(in_flight);
            });
        }
    }

    /// Takes out the kept opens on `share` and of `user`, every share or
    /// user when `None`, for the caller to close. A sweep that ends sessions
    /// or trees calls this after it has cut them off; opens of sessions
    /// leaving their connection meanwhile are then not kept (see
    /// [`DurableTable::preserve`]).
    pub(crate) fn take_for(
        &self,
        share: Option<&Arc<ShareBindings>>,
        user: Option<&str>,
    ) -> Vec<Arc<RwLock<Open>>> {
        self.sweeps.fetch_add(1, Ordering::SeqCst);
        let mut inner = self.inner();
        let ids: Vec<u64> = inner
            .entries
            .iter()
            .filter(|(_, e)| {
                matches!(e.state, State::Detached { .. })
                    && share.is_none_or(|s| std::ptr::eq(e.share.as_ptr(), Arc::as_ptr(s)))
                    && user.is_none_or(|u| e.owner == u)
            })
            .map(|(id, _)| *id)
            .collect();
        let mut opens = Vec::with_capacity(ids.len());
        for id in ids {
            if let Some((open, _timer)) = inner.take_detached(id, |_| true) {
                debug!(id, "durable open closed: configuration or shutdown");
                opens.push(open);
            }
        }
        drop(inner);
        opens
    }

    /// MS-SMB2 3.3.5.9.7 on a server that hands no kept open back. Checks a
    /// request to reconnect the open `id` in the order the spec gives and,
    /// when the open is kept and the request comes from its owner, takes it
    /// out for the caller to close: the client opens the file anew next,
    /// and the old open's share mode, byte-range locks and lease would be
    /// in its way. The reconnect fails either way, with the returned status
    /// or, for an open taken out, STATUS_OBJECT_NAME_NOT_FOUND.
    pub(crate) fn give_up(&self, id: u64, claim: &Claim<'_>) -> Result<Arc<RwLock<Open>>, u32> {
        let not_found = ntstatus::STATUS_OBJECT_NAME_NOT_FOUND;
        let mut inner = self.inner();
        let entry = inner.entries.get(&id).ok_or(not_found)?;
        if entry.lease.client != claim.client
            || claim.lease.is_none()
            || !matches!(entry.state, State::Detached { .. })
            || claim.lease != Some(entry.lease)
            || !std::ptr::eq(entry.share.as_ptr(), Arc::as_ptr(claim.share))
        {
            return Err(not_found);
        }
        if claim.user != Some(entry.owner.as_str()) {
            return Err(ntstatus::STATUS_ACCESS_DENIED);
        }
        let (open, timer) = inner.take_detached(id, |_| true).ok_or(not_found)?;
        drop(inner);
        drop(timer);
        debug!(id, "durable open closed: client reconnected");
        Ok(open)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap as Map;

    use super::*;
    use crate::access_mask::{FILE_READ_DATA, FILE_WRITE_DATA};
    use crate::backend::{FileInfo, FileTimes, OpenOptions};
    use crate::conn::outbound::Outbound;
    use crate::files::lease::{LeaseRequest, LeaseState, LeaseVersion};
    use crate::files::leases::LeaseTable;
    use crate::files::table::{FileRef, OpenRequest, Sharing};
    use crate::path::SmbPath;
    use crate::proto::messages::FileId;
    use crate::server::ShareMode;
    use crate::tests::memfs::MemFsBackend;

    struct Fixture {
        table: Arc<DurableTable>,
        leases: Arc<LeaseTable>,
        share: Arc<ShareBindings>,
        files: MemFsBackend,
        outbound: Arc<Outbound>,
    }

    fn fixture(max_detached: usize) -> Fixture {
        let files = MemFsBackend::new();
        let share = ShareBindings::new(
            "s".to_string(),
            Arc::new(files.clone()),
            ShareMode::Public,
            Map::new(),
            false,
            true,
            true,
        );
        Fixture {
            table: Arc::new(DurableTable::new(Duration::from_secs(60), max_detached)),
            leases: Arc::default(),
            share,
            files,
            outbound: Arc::default(),
        }
    }

    fn lease(n: u8) -> LeaseId {
        LeaseId {
            client: Uuid::from_bytes([1; 16]),
            key: [n; 16],
        }
    }

    impl Fixture {
        /// A durable open of `name` by `owner` holding the lease `n` with
        /// `state`, as CREATE builds it.
        async fn open(
            &self,
            name: &str,
            owner: &str,
            n: u8,
            state: LeaseState,
        ) -> Arc<RwLock<Open>> {
            let path: SmbPath = name.parse().unwrap();
            let opts = OpenOptions {
                intent: crate::backend::OpenIntent::OpenOrCreate,
                ..OpenOptions::default()
            };
            let (handle, _) = self.share.backend.open(&path, opts).await.unwrap();
            let mut info = FileInfo::new("");
            info.file_index = u64::from(n);
            let lease_ref = self.leases.acquire(lease(n), &self.share, &path).unwrap();
            let req = OpenRequest {
                sharing: Sharing {
                    access: FILE_READ_DATA | FILE_WRITE_DATA,
                    share: 7,
                },
                owner: Arc::downgrade(&self.outbound),
                lease: Some(lease(n)),
                ..OpenRequest::default()
            };
            let mut file = FileRef::register(&self.share, &info, &path, req).unwrap().0;
            let request = LeaseRequest {
                id: lease(n),
                state,
                version: LeaseVersion::V2,
                epoch: 0,
                parent: None,
            };
            let (granted, guard) = self
                .leases
                .grant(lease_ref, &mut file, &request, LeaseState::RWH)
                .unwrap();
            drop(guard);
            assert_eq!(granted.state, state);
            let reg = self.table.register(owner, &self.share, lease(n)).unwrap();
            file.mark_durable(&self.table, reg.id());
            Arc::new(RwLock::new(Open {
                file_id: FileId::new(reg.id(), 1),
                handle: Some(handle),
                granted_access: FILE_READ_DATA | FILE_WRITE_DATA,
                is_directory: false,
                delete_on_close: false,
                search_state: None,
                fixed_times: FileTimes::default(),
                create_options: 0,
                file: Some(file),
                slot: None,
                durable: Some(reg),
            }))
        }

        fn counts(&self) -> (usize, usize, usize) {
            let inner = self.table.inner();
            (
                inner.entries.len(),
                inner.detached,
                inner.detached_by_user.values().sum(),
            )
        }
    }

    async fn id_of(open: &Arc<RwLock<Open>>) -> u64 {
        open.read().await.durable.as_ref().unwrap().id()
    }

    /// Lets spawned closes run.
    async fn settle() {
        for _ in 0..20 {
            tokio::task::yield_now().await;
        }
    }

    #[tokio::test]
    async fn ids_are_random_unique_and_never_reserved_values() {
        let f = fixture(8);
        let regs: Vec<_> = (0..64)
            .map(|n| f.table.register("alice", &f.share, lease(n)).unwrap())
            .collect();
        let mut ids: Vec<u64> = regs.iter().map(DurableReg::id).collect();
        assert!(ids.iter().all(|&id| id != 0 && id != u64::MAX));
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), 64);
        drop(regs);
        assert_eq!(f.counts(), (0, 0, 0));
    }

    #[tokio::test]
    async fn a_kept_open_counts_until_it_is_closed() {
        let f = fixture(8);
        let open = f.open("a", "alice", 1, LeaseState::RH).await;
        let id = id_of(&open).await;
        assert!(f.table.preserve(open, f.table.sweeps()).await.is_none());
        assert_eq!(f.counts(), (1, 1, 1));
        assert_eq!(f.files.open_handles(), 1);
        f.table.purge(id);
        assert_eq!(f.counts().1, 0);
        settle().await;
        assert_eq!(f.files.open_handles(), 0);
        assert_eq!(f.counts(), (0, 0, 0));
        assert!(!f.leases.exists(lease(1)));
    }

    #[tokio::test]
    async fn opens_past_the_limits_are_not_kept() {
        // A limit of 6 gives each user 2.
        let f = fixture(6);
        for n in 0..3 {
            let open = f.open(&format!("a{n}"), "alice", n, LeaseState::RH).await;
            let kept = f.table.preserve(open, f.table.sweeps()).await;
            assert_eq!(kept.is_none(), n < 2, "alice {n}");
        }
        for n in 3..8 {
            let user = ["bob", "carol", "dave"][usize::from(n - 3) / 2];
            let open = f.open(&format!("b{n}"), user, n, LeaseState::RH).await;
            let kept = f.table.preserve(open, f.table.sweeps()).await;
            assert_eq!(kept.is_none(), n < 7, "{user} {n}");
        }
        assert_eq!(f.counts().1, 6);
        let opens = f.table.take_for(None, None);
        assert_eq!(opens.len(), 6);
        drop(opens);
        settle().await;
        assert_eq!(f.counts(), (0, 0, 0));
    }

    #[tokio::test]
    async fn opens_without_handle_caching_are_not_kept() {
        let f = fixture(8);
        let open = f.open("a", "alice", 1, LeaseState::R).await;
        assert!(f.table.preserve(open, f.table.sweeps()).await.is_some());
        assert_eq!(f.counts().1, 0);
    }

    #[tokio::test]
    async fn an_open_whose_session_left_before_a_sweep_is_not_kept() {
        let f = fixture(8);
        let open = f.open("a", "alice", 1, LeaseState::RH).await;
        let since = f.table.sweeps();
        // The sweep runs while the session is gone but the open is not kept
        // yet, so it cannot see the open.
        assert!(f.table.take_for(None, Some("alice")).is_empty());
        assert!(f.table.preserve(open, since).await.is_some());
        let open = f.open("b", "alice", 2, LeaseState::RH).await;
        assert!(f.table.preserve(open, f.table.sweeps()).await.is_none());
        assert_eq!(f.counts().1, 1);
    }

    #[tokio::test]
    async fn take_for_picks_by_share_and_user() {
        let f = fixture(64);
        let other = fixture(64);
        for (n, user) in [(1, "alice"), (2, "alice"), (3, "bob")] {
            let open = f.open(&format!("f{n}"), user, n, LeaseState::RH).await;
            assert!(f.table.preserve(open, f.table.sweeps()).await.is_none());
        }
        assert!(f.table.take_for(Some(&other.share), None).is_empty());
        assert!(f.table.take_for(None, Some("carol")).is_empty());
        assert_eq!(f.table.take_for(Some(&f.share), Some("bob")).len(), 1);
        assert_eq!(f.table.take_for(None, Some("alice")).len(), 2);
        assert_eq!(f.counts().1, 0);
    }

    #[tokio::test]
    async fn only_a_closing_or_kept_entry_is_purged() {
        let f = fixture(8);
        let open = f.open("a", "alice", 1, LeaseState::RH).await;
        let id = id_of(&open).await;
        // Still in a session: nothing happens.
        f.table.purge(id);
        assert_eq!(f.counts(), (1, 0, 0));
        assert!(
            f.table
                .preserve(Arc::clone(&open), f.table.sweeps())
                .await
                .is_none()
        );
        f.table.purge(id);
        f.table.purge(id);
        drop(open);
        settle().await;
        assert_eq!(f.counts(), (0, 0, 0));
    }

    fn claim<'a>(
        share: &'a Arc<ShareBindings>,
        user: Option<&'a str>,
        client: Uuid,
        lease: Option<LeaseId>,
    ) -> Claim<'a> {
        Claim {
            share,
            user,
            client,
            lease,
        }
    }

    #[tokio::test]
    async fn a_reconnect_takes_out_only_its_owners_kept_open() {
        let f = fixture(8);
        let other = fixture(8);
        let open = f.open("a", "alice", 1, LeaseState::RH).await;
        let id = id_of(&open).await;
        let me = lease(1).client;
        let not_found = Err(ntstatus::STATUS_OBJECT_NAME_NOT_FOUND);
        let status = |r: Result<Arc<RwLock<Open>>, u32>| r.map(|_| ());
        let alice = claim(&f.share, Some("alice"), me, Some(lease(1)));

        // Still in a session.
        assert_eq!(status(f.table.give_up(id, &alice)), not_found);
        assert!(f.table.preserve(open, f.table.sweeps()).await.is_none());
        assert_eq!(status(f.table.give_up(id ^ 1, &alice)), not_found);
        for refused in [
            claim(&f.share, Some("alice"), Uuid::nil(), Some(lease(1))),
            claim(&f.share, Some("alice"), me, None),
            claim(&f.share, Some("alice"), me, Some(lease(2))),
            claim(&other.share, Some("alice"), me, Some(lease(1))),
        ] {
            assert_eq!(status(f.table.give_up(id, &refused)), not_found);
        }
        for user in [Some("bob"), None] {
            let refused = claim(&f.share, user, me, Some(lease(1)));
            assert_eq!(
                status(f.table.give_up(id, &refused)),
                Err(ntstatus::STATUS_ACCESS_DENIED)
            );
        }
        assert_eq!(f.counts().1, 1);
        let open = f.table.give_up(id, &alice).unwrap();
        assert_eq!(f.counts().1, 0);
        close_open(&open, false).await;
        drop(open);
        assert_eq!(f.files.open_handles(), 0);
        assert_eq!(f.counts(), (0, 0, 0));
    }
}
