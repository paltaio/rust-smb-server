//! Lease state of a file and the rules that grant and break it (MS-SMB2
//! 3.3.1.4, 3.3.5.9.8, 3.3.5.9.11; MS-FSA 2.1.4.12, 2.1.5.18). Plain data:
//! the file table builds the inputs and applies the results under its lock.

use uuid::Uuid;

use crate::access_mask::{FILE_READ_ATTRIBUTES, FILE_WRITE_ATTRIBUTES, READ_CONTROL, SYNCHRONIZE};
use crate::proto::messages::lease::{
    LEASE_HANDLE_CACHING, LEASE_READ_CACHING, LEASE_WRITE_CACHING,
};

/// A lease: the client that holds it and the key the client chose.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct LeaseId {
    pub client: Uuid,
    pub key: [u8; 16],
}

/// Caching a lease grants: NONE, R, RH, RW or RWH.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) struct LeaseState(u8);

impl LeaseState {
    pub const NONE: Self = Self(0);
    pub const R: Self = Self(LEASE_READ_CACHING as u8);
    pub const H: Self = Self(LEASE_HANDLE_CACHING as u8);
    pub const W: Self = Self(LEASE_WRITE_CACHING as u8);
    pub const RWH: Self = Self(Self::R.0 | Self::W.0 | Self::H.0);

    /// The state a CREATE asks for. Only NONE, R, RH, RW and RWH are lease
    /// states (MS-SMB2 2.2.13.2.8); any other request, which lacks R, asks
    /// for NONE, and unknown bits are ignored.
    pub fn requested(bits: u32) -> Self {
        let state = Self((bits & Self::RWH.bits()) as u8);
        if state.contains(Self::R) {
            state
        } else {
            Self::NONE
        }
    }

    pub fn bits(self) -> u32 {
        u32::from(self.0)
    }

    pub fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    fn without(self, other: Self) -> Self {
        Self(self.0 & !other.0)
    }
}

/// Lease.Version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LeaseVersion {
    V1,
    V2,
}

/// A lease request from a CREATE.
#[derive(Debug, Clone, Copy)]
pub(crate) struct LeaseRequest {
    pub id: LeaseId,
    pub state: LeaseState,
    pub version: LeaseVersion,
    /// Epoch of a version 2 request.
    pub epoch: u16,
    /// ParentLeaseKey of a version 2 request that sets it.
    pub parent: Option<[u8; 16]>,
}

/// One lease held on a file (MS-SMB2 3.3.1.12). It exists while at least
/// one open of the file holds it.
#[derive(Debug)]
pub(crate) struct FileLease {
    pub id: LeaseId,
    /// Tells this lease from an earlier one with the same id on the file.
    pub serial: u64,
    /// Lease.LeaseState.
    pub state: LeaseState,
    /// Lease.Epoch, version 2 only.
    pub epoch: u16,
    pub version: LeaseVersion,
    /// Lease.ParentLeaseKey, stored and returned only.
    pub parent: Option<[u8; 16]>,
    /// CREATE responses carrying this lease that are not yet queued. While
    /// any are, a break notification waits in `unsent` so the client never
    /// sees a break before the grant.
    pub grants_in_flight: u32,
    /// Lease.BreakNotification not yet sent.
    pub unsent: Option<Vec<u8>>,
}

impl FileLease {
    /// A lease created by `req` with `state` granted. A version 2 lease
    /// starts at the request's epoch, moved by one when something is
    /// granted.
    pub fn new(req: &LeaseRequest, state: LeaseState, serial: u64) -> Self {
        let epoch = match req.version {
            LeaseVersion::V1 => 0,
            LeaseVersion::V2 if state == LeaseState::NONE => req.epoch,
            LeaseVersion::V2 => req.epoch.wrapping_add(1),
        };
        Self {
            id: req.id,
            serial,
            state,
            epoch,
            version: req.version,
            parent: req.parent,
            grants_in_flight: 0,
            unsent: None,
        }
    }

    /// Moves the lease to `state`. A version 2 lease counts the change in
    /// its epoch (MS-SMB2 3.3.4.7, 3.3.5.9.11).
    pub fn set_state(&mut self, state: LeaseState) {
        if state != self.state {
            self.state = state;
            if self.version == LeaseVersion::V2 {
                self.epoch = self.epoch.wrapping_add(1);
            }
        }
    }
}

/// A lease as a CREATE response reports it.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Granted {
    pub id: LeaseId,
    pub state: LeaseState,
    pub epoch: u16,
    pub version: LeaseVersion,
    pub parent: Option<[u8; 16]>,
}

/// True for an open whose access is limited to attributes, security reads
/// and SYNCHRONIZE. Such an open breaks no lease (MS-FSA 2.1.4.12, OPEN).
pub(crate) fn stat_only(access: u32) -> bool {
    access & !(FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE) == 0
}

/// An open of the file, as the grant rules see it.
#[derive(Debug, Clone, Copy)]
pub(crate) struct OpenView {
    pub lease: Option<LeaseId>,
    pub stat_only: bool,
}

/// The file a lease is requested on.
pub(crate) struct FileView<'a> {
    /// Every open, the requester's own included.
    pub opens: &'a [OpenView],
    /// Every lease on the file.
    pub leases: &'a [(LeaseId, LeaseState)],
    pub has_locks: bool,
}

impl FileView<'_> {
    /// MS-FSA 2.1.5.18.1 and 2.1.5.18.2 for leases. Write caching needs every
    /// other open to be attribute-only and no other lease to hold anything.
    /// Read and handle caching need no other lease with write caching and no
    /// byte-range lock. Opens and leases with `me` as key never count.
    fn can_grant(&self, me: LeaseId, state: LeaseState) -> bool {
        let mut others = self.leases.iter().filter(|(id, _)| *id != me);
        if state.contains(LeaseState::W) {
            self.opens
                .iter()
                .all(|o| o.lease == Some(me) || o.stat_only)
                && others.all(|(_, s)| *s == LeaseState::NONE)
        } else {
            !self.has_locks && others.all(|(_, s)| !s.contains(LeaseState::W))
        }
    }
}

/// The states to try for a request, best first: the request, then without
/// W, then without W and H (MS-SMB2 3.3.5.9).
fn candidates(requested: LeaseState) -> impl Iterator<Item = LeaseState> {
    let without_w = requested.without(LeaseState::W);
    let without_wh = without_w.without(LeaseState::H);
    [requested, without_w, without_wh]
        .into_iter()
        .enumerate()
        .filter(move |&(at, c)| {
            c != LeaseState::NONE
                && match at {
                    0 => true,
                    1 => requested.contains(LeaseState::W),
                    _ => without_w.contains(LeaseState::H),
                }
        })
        .map(|(_, c)| c)
}

/// The state the lease `me` holds after a CREATE requests `requested` on
/// `file`, with `existing` the lease when another open already holds it.
/// Nothing outside `grantable` is granted. An existing lease is never
/// downgraded, and is upgraded only to a superset the request covers
/// (MS-SMB2 3.3.5.9.8: a request that is not a superset promotes nothing).
pub(crate) fn grant(
    me: LeaseId,
    requested: LeaseState,
    existing: Option<LeaseState>,
    file: &FileView<'_>,
    grantable: LeaseState,
) -> LeaseState {
    let fits = |c: LeaseState| grantable.contains(c) && file.can_grant(me, c);
    match existing {
        None => candidates(requested)
            .find(|&c| fits(c))
            .unwrap_or(LeaseState::NONE),
        Some(current) if !requested.contains(current) => current,
        Some(current) => candidates(requested)
            .find(|&c| c.contains(current) && c != current && fits(c))
            .unwrap_or(current),
    }
}

/// What makes the server break the leases on a file, all but the one the
/// acting open holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Trigger {
    /// An open that is not attribute-only joins the file; `overwrite` when
    /// it supersedes or overwrites the file (MS-FSA 2.1.4.12, OPEN).
    Open { overwrite: bool },
    /// WRITE, SET_INFO EndOfFile or Allocation, and LOCK (MS-FSA 2.1.4.12,
    /// WRITE, SET_INFORMATION, LOCK_CONTROL).
    Write,
}

/// The state a lease in `state` breaks to for `trigger`, or `None` when it
/// keeps its state. An open breaks write caching; an overwrite or a write
/// breaks every lease to NONE.
pub(crate) fn break_to(trigger: Trigger, state: LeaseState) -> Option<LeaseState> {
    let to = match trigger {
        Trigger::Open { overwrite: false } => state.without(LeaseState::W),
        Trigger::Open { overwrite: true } | Trigger::Write => LeaseState::NONE,
    };
    (to != state).then_some(to)
}

#[cfg(test)]
mod tests {
    use super::*;

    impl LeaseState {
        const RH: Self = Self(Self::R.0 | Self::H.0);
        const RW: Self = Self(Self::R.0 | Self::W.0);
    }

    const STATES: [LeaseState; 5] = [
        LeaseState::NONE,
        LeaseState::R,
        LeaseState::RH,
        LeaseState::RW,
        LeaseState::RWH,
    ];

    fn id(n: u8) -> LeaseId {
        LeaseId {
            client: Uuid::nil(),
            key: [n; 16],
        }
    }

    #[test]
    fn requests_normalize_to_lease_states() {
        let expected = [
            (0, LeaseState::NONE),
            (1, LeaseState::R),
            (2, LeaseState::NONE),
            (3, LeaseState::RH),
            (4, LeaseState::NONE),
            (5, LeaseState::RW),
            (6, LeaseState::NONE),
            (7, LeaseState::RWH),
            (0xF9, LeaseState::R),
        ];
        for (bits, state) in expected {
            assert_eq!(LeaseState::requested(bits), state, "{bits:#x}");
        }
    }

    #[test]
    fn retry_chain_drops_write_then_handle() {
        let chain = |s| candidates(s).collect::<Vec<_>>();
        assert_eq!(
            chain(LeaseState::RWH),
            [LeaseState::RWH, LeaseState::RH, LeaseState::R]
        );
        assert_eq!(chain(LeaseState::RW), [LeaseState::RW, LeaseState::R]);
        assert_eq!(chain(LeaseState::RH), [LeaseState::RH, LeaseState::R]);
        assert_eq!(chain(LeaseState::R), [LeaseState::R]);
        assert!(chain(LeaseState::NONE).is_empty());
    }

    #[test]
    fn break_table() {
        use LeaseState as S;
        let open = Trigger::Open { overwrite: false };
        let overwrite = Trigger::Open { overwrite: true };
        let rows = [
            (open, [None, None, None, Some(S::R), Some(S::RH)]),
            (
                overwrite,
                [
                    None,
                    Some(S::NONE),
                    Some(S::NONE),
                    Some(S::NONE),
                    Some(S::NONE),
                ],
            ),
            (
                Trigger::Write,
                [
                    None,
                    Some(S::NONE),
                    Some(S::NONE),
                    Some(S::NONE),
                    Some(S::NONE),
                ],
            ),
        ];
        for (trigger, expected) in rows {
            for (state, to) in STATES.into_iter().zip(expected) {
                assert_eq!(break_to(trigger, state), to, "{trigger:?} {state:?}");
            }
        }
    }

    #[test]
    fn epochs_move_with_state_changes_in_version_2() {
        let req = |version| LeaseRequest {
            id: id(1),
            state: LeaseState::RWH,
            version,
            epoch: 5,
            parent: None,
        };
        assert_eq!(
            FileLease::new(&req(LeaseVersion::V2), LeaseState::R, 0).epoch,
            6
        );
        assert_eq!(
            FileLease::new(&req(LeaseVersion::V2), LeaseState::NONE, 0).epoch,
            5
        );
        assert_eq!(
            FileLease::new(&req(LeaseVersion::V1), LeaseState::R, 0).epoch,
            0
        );

        let mut lease = FileLease::new(&req(LeaseVersion::V2), LeaseState::R, 0);
        lease.set_state(LeaseState::R);
        assert_eq!(lease.epoch, 6);
        lease.set_state(LeaseState::NONE);
        assert_eq!((lease.state, lease.epoch), (LeaseState::NONE, 7));

        let mut lease = FileLease::new(&req(LeaseVersion::V1), LeaseState::R, 0);
        lease.set_state(LeaseState::NONE);
        assert_eq!(lease.epoch, 0);
    }

    #[test]
    fn stat_only_access() {
        assert!(stat_only(FILE_READ_ATTRIBUTES | SYNCHRONIZE));
        assert!(stat_only(FILE_WRITE_ATTRIBUTES | READ_CONTROL));
        assert!(!stat_only(FILE_READ_ATTRIBUTES | 0x1));
        assert!(!stat_only(0x0001_0000));
    }

    /// Every file of up to three other opens, with leases in every state, is
    /// checked against the grant invariants for every request.
    #[test]
    fn grant_invariants_hold_for_every_small_file() {
        let me = id(1);
        let keys = [None, Some(me), Some(id(2)), Some(id(3))];
        let mut open_sets: Vec<Vec<OpenView>> = vec![Vec::new()];
        for _ in 0..3 {
            let mut next = Vec::new();
            for set in &open_sets {
                for lease in keys {
                    for stat_only in [false, true] {
                        let mut set = set.clone();
                        set.push(OpenView { lease, stat_only });
                        next.push(set);
                    }
                }
            }
            open_sets.extend(next);
        }
        let grantables = [LeaseState::R, LeaseState::RH, LeaseState::RWH];
        for others in &open_sets {
            let mut opens = others.clone();
            opens.push(OpenView {
                lease: Some(me),
                stat_only: false,
            });
            for (s2, s3) in STATES.iter().flat_map(|&a| STATES.map(|b| (a, b))) {
                let leases = [(id(2), s2), (id(3), s3)];
                for has_locks in [false, true] {
                    let file = FileView {
                        opens: &opens,
                        leases: &leases,
                        has_locks,
                    };
                    for bits in 0..8 {
                        let requested = LeaseState::requested(bits);
                        for grantable in grantables {
                            for existing in std::iter::once(None).chain(STATES.map(Some)) {
                                let got = grant(me, requested, existing, &file, grantable);
                                check(&file, me, requested, existing, grantable, got);
                            }
                        }
                    }
                }
            }
        }
    }

    fn check(
        file: &FileView<'_>,
        me: LeaseId,
        requested: LeaseState,
        existing: Option<LeaseState>,
        grantable: LeaseState,
        got: LeaseState,
    ) {
        let ctx = || format!("{requested:?} {existing:?} {grantable:?} -> {got:?}");
        assert!(STATES.contains(&got), "{}", ctx());
        if let Some(current) = existing {
            assert!(got.contains(current), "downgraded: {}", ctx());
            if !requested.contains(current) {
                assert_eq!(got, current, "promoted without a superset: {}", ctx());
            }
            if got == current {
                return;
            }
        }
        assert!(grantable.contains(got), "{}", ctx());
        assert!(requested.contains(got), "{}", ctx());
        let others = || file.leases.iter().filter(|(id, _)| *id != me);
        if got.contains(LeaseState::W) {
            assert!(
                file.opens
                    .iter()
                    .all(|o| o.lease == Some(me) || o.stat_only),
                "W beside another open: {}",
                ctx()
            );
            assert!(
                others().all(|(_, s)| *s == LeaseState::NONE),
                "W beside another lease: {}",
                ctx()
            );
        }
        if got != LeaseState::NONE && !got.contains(LeaseState::W) {
            assert!(!file.has_locks, "granted with locks: {}", ctx());
            assert!(
                others().all(|(_, s)| !s.contains(LeaseState::W)),
                "granted beside W: {}",
                ctx()
            );
        }
        if existing.is_none() && got == LeaseState::NONE {
            assert!(
                candidates(requested).all(|c| !grantable.contains(c) || !file.can_grant(me, c)),
                "nothing granted although a candidate fits: {}",
                ctx()
            );
        }
    }
}
