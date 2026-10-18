//! LOCK handler: byte-range locks (MS-SMB2 3.3.5.14).
//!
//! Requests run one at a time per connection, so a lock request cannot wait
//! for a conflicting range to be released without stalling every other
//! request on its connection, including the UNLOCK or CLOSE that would
//! release it. A lock request that conflicts therefore fails with
//! STATUS_LOCK_NOT_GRANTED whether or not SMB2_LOCKFLAG_FAIL_IMMEDIATELY is
//! set, as MS-SMB2 3.3.5.14.2 lets a server do in place of waiting.

use std::sync::Arc;
use std::sync::atomic::Ordering;

use crate::proto::header::Smb2Header;
use crate::proto::messages::{LockElement, LockRequest, LockResponse};

use crate::conn::state::Connection;
use crate::dispatch::HandlerResponse;
use crate::handlers::shared::{lookup_open, lookup_session_tree};
use crate::ntstatus;
use crate::server::ServerState;

const SHARED: u32 = LockElement::FLAG_SHARED_LOCK;
const EXCLUSIVE: u32 = LockElement::FLAG_EXCLUSIVE_LOCK;
const UNLOCK: u32 = LockElement::FLAG_UNLOCK;
const FAIL_IMMEDIATELY: u32 = LockElement::FLAG_FAIL_IMMEDIATELY;

pub async fn handle(
    server: &Arc<ServerState>,
    conn: &Arc<Connection>,
    hdr: &Smb2Header,
    body: &[u8],
) -> HandlerResponse {
    let req = match LockRequest::parse(body) {
        Ok(r) => r,
        Err(_) => return HandlerResponse::err(ntstatus::STATUS_INVALID_PARAMETER),
    };
    let tree_arc = match lookup_session_tree(conn, hdr).await {
        Ok(t) => t,
        Err(s) => return HandlerResponse::err(s),
    };
    let Some(open_arc) = lookup_open(&tree_arc, req.file_id).await else {
        return HandlerResponse::err(ntstatus::STATUS_FILE_CLOSED);
    };
    let Some(first) = req.locks.first() else {
        return HandlerResponse::err(ntstatus::STATUS_INVALID_PARAMETER);
    };
    let open = open_arc.read().await;
    // MS-FSA 2.1.5.8: directories take no byte-range locks.
    if open.is_directory {
        return HandlerResponse::err(ntstatus::STATUS_INVALID_PARAMETER);
    }
    let Some(file) = open.file.as_ref() else {
        return HandlerResponse::err(ntstatus::STATUS_FILE_CLOSED);
    };

    let result = if first.flags & UNLOCK != 0 {
        // MS-SMB2 3.3.5.14.1: unlocks done before a failure stay done.
        req.locks.iter().try_for_each(|l| {
            if l.flags & !FAIL_IMMEDIATELY != UNLOCK {
                return Err(ntstatus::STATUS_INVALID_PARAMETER);
            }
            file.unlock_range(l.offset, l.length)
        })
    } else {
        let valid = |flags: u32| {
            matches!(flags & !FAIL_IMMEDIATELY, SHARED | EXCLUSIVE)
                && (req.locks.len() == 1 || flags & FAIL_IMMEDIATELY != 0)
        };
        if !req.locks.iter().all(|l| valid(l.flags)) {
            return HandlerResponse::err(ntstatus::STATUS_INVALID_PARAMETER);
        }
        // MS-SMB2 3.3.5.14.2: a failed lock releases the ranges this request
        // locked before it.
        let limit = server.max_locks_per_open.load(Ordering::Relaxed);
        let mut taken = Vec::new();
        let mut result = Ok(());
        for l in &req.locks {
            match file.lock_range(l.offset, l.length, l.flags & EXCLUSIVE != 0, limit) {
                Ok(()) => taken.push(l),
                Err(status) => {
                    for t in &taken {
                        file.undo_lock(t.offset, t.length, t.flags & EXCLUSIVE != 0);
                    }
                    result = Err(status);
                    break;
                }
            }
        }
        result
    };
    drop(open);

    if let Err(status) = result {
        return HandlerResponse::err(status);
    }
    let mut buf = Vec::new();
    LockResponse::default().write_to(&mut buf).expect("encode");
    HandlerResponse::ok(buf)
}
