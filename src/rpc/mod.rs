//! DCE/RPC over the named pipes of IPC$ (C706 chapter 12, MS-RPCE 2.1.1.2).

use std::sync::atomic::{AtomicU32, Ordering};

pub(crate) mod association;
pub(crate) mod pdu;
pub(crate) mod pipe;

/// The pipe IPC$ serves, as a CREATE names it.
pub(crate) const SRVSVC_PIPE: &str = "srvsvc";

/// Source of association group ids for binds that ask for a new group.
static NEXT_ASSOC_GROUP: AtomicU32 = AtomicU32::new(1);

/// A new association group id, never 0 (C706 12.6.3.6).
pub(crate) fn new_assoc_group() -> u32 {
    loop {
        let id = NEXT_ASSOC_GROUP.fetch_add(1, Ordering::Relaxed);
        if id != 0 {
            return id;
        }
    }
}
