//! CREATE with a durable handle reconnect context (MS-SMB2 3.3.5.9.7,
//! 3.3.5.9.12): hands an open kept after its session ended back to its
//! client, in the client's new session and tree.

use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use tokio::sync::RwLock;
use tokio::time::Instant;
use tracing::{debug, warn};
use uuid::Uuid;

use crate::access_mask::maximal_access;
use crate::builder::Access;
use crate::conn::pending::{Stop, stopped};
use crate::conn::state::{Connection, Open, TreeConnect};
use crate::dispatch::HandlerResponse;
use crate::files::{Claim, LeaseRequest, OpenSlot, Unclaimed, close_open};
use crate::handlers::create::{ContextQueries, FILE_OPENED, encode_response, lease_response};
use crate::handlers::shared::lookup_session_tree;
use crate::handlers::{Outcome, Pending};
use crate::info_class::VOLUME_SERIAL_NUMBER;
use crate::ntstatus;
use crate::path::{SmbPath, same_path};
use crate::proto::header::Smb2Header;
use crate::proto::messages::FileId;
use crate::server::{ServerState, ShareBindings};

/// How long a reconnect waits for the connection that still holds the
/// open to finish closing.
const TEARDOWN_WAIT: Duration = Duration::from_secs(5);

/// A request to reconnect a durable open.
pub(super) struct Reconnect {
    /// The FileId the request names.
    pub file_id: FileId,
    /// DH2C rather than DHnC.
    pub v2: bool,
    /// The name in the request; `None` when it is not a valid name, which
    /// matches no open.
    pub name: Option<SmbPath>,
    /// The configured name of the session's user; `None` for anonymous.
    pub owner: Option<String>,
    /// Connection.ClientGuid.
    pub client: Uuid,
    /// The lease context of the request.
    pub lease: Option<LeaseRequest>,
    pub queries: ContextQueries,
}

pub(super) async fn handle(
    server: &Arc<ServerState>,
    conn: &Arc<Connection>,
    hdr: &Smb2Header,
    r: Reconnect,
    retained: usize,
) -> Outcome {
    let id = r.file_id.persistent;
    // No durable open on this server has a CreateGuid, so a DH2C names none
    // (MS-SMB2 3.3.5.9.12).
    if r.v2 {
        debug!(id, "durable reconnect refused");
        return Outcome::Done(HandlerResponse::err(ntstatus::STATUS_OBJECT_NAME_NOT_FOUND));
    }
    let wait = match attempt(server, conn, hdr, &r).await {
        Ok(response) => return Outcome::Done(response),
        Err(Unclaimed::Status(status)) => {
            debug!(id, status, "durable reconnect refused");
            return Outcome::Done(HandlerResponse::err(status));
        }
        Err(Unclaimed::Wait(wait)) => wait,
    };
    // MS-SMB2 3.3.4.2: past its limits the connection gets no more
    // asynchronous requests.
    let Some((op, mut stop)) = conn.pending.reserve(hdr, None, retained) else {
        warn!("too many waiting requests on the connection");
        return Outcome::Done(HandlerResponse::err(
            ntstatus::STATUS_INSUFFICIENT_RESOURCES,
        ));
    };
    let (server, conn, hdr) = (Arc::clone(server), Arc::clone(conn), *hdr);
    // The connection that holds the open is closing; once its sessions end,
    // the open is kept and the reconnect takes it. One that takes longer
    // than TEARDOWN_WAIT leaves the open in a session (MS-SMB2 3.3.5.9.7
    // "Open.Session is not NULL").
    let work = async move {
        let give_up = Instant::now() + TEARDOWN_WAIT;
        let mut wait = wait;
        loop {
            tokio::select! {
                biased;
                why = stopped(&mut stop) => {
                    if why == Stop::Cancelled {
                        return HandlerResponse::err(ntstatus::STATUS_CANCELLED);
                    }
                }
                _ = wait.changed() => {}
                () = tokio::time::sleep_until(give_up) => {
                    debug!(id, "durable reconnect refused: open still in a session");
                    return HandlerResponse::err(ntstatus::STATUS_OBJECT_NAME_NOT_FOUND);
                }
            }
            match attempt(&server, &conn, &hdr, &r).await {
                Ok(response) => return response,
                Err(Unclaimed::Status(status)) => {
                    debug!(id, status, "durable reconnect refused");
                    return HandlerResponse::err(status);
                }
                Err(Unclaimed::Wait(next)) => wait = next,
            }
        }
    };
    Outcome::Pending(Pending {
        op,
        work: Box::pin(work),
    })
}

/// One try at the reconnect: claims the open, then puts it in the tree the
/// request came on.
async fn attempt(
    server: &Arc<ServerState>,
    conn: &Arc<Connection>,
    hdr: &Smb2Header,
    r: &Reconnect,
) -> Result<HandlerResponse, Unclaimed> {
    let tree_arc = lookup_session_tree(conn, hdr)
        .await
        .map_err(Unclaimed::Status)?;
    let (share, access, volatile) = {
        let tree = tree_arc.read().await;
        (
            Arc::clone(&tree.share),
            tree.granted_access,
            tree.alloc_volatile(),
        )
    };
    let id = r.file_id.persistent;
    let since = server.durable.sweeps();
    let claim = Claim {
        share: &share,
        user: r.owner.as_deref(),
        client: r.client,
        lease: r.lease.map(|l| (l.id, l.version)),
    };
    let open = server.durable.claim(id, &claim)?;
    let tree = Tree {
        arc: &tree_arc,
        share: &share,
        access,
        session_id: hdr.session_id,
        since,
    };
    take_back(server, conn, &tree, r, open, FileId::new(id, volatile))
        .await
        .map_err(Unclaimed::Status)
}

/// The tree a reconnect came on.
struct Tree<'a> {
    arc: &'a Arc<RwLock<TreeConnect>>,
    share: &'a Arc<ShareBindings>,
    /// The access the tree grants now.
    access: Access,
    /// The session the tree belongs to.
    session_id: u64,
    /// [`DurableTable::sweeps`](crate::files::DurableTable::sweeps) from
    /// before the claim.
    since: u64,
}

/// Puts the claimed open `open_arc` in `tree` under `file_id`, on `conn`
/// (MS-SMB2 3.3.5.9.7), and answers the CREATE. A check that fails puts the
/// open back for a later reconnect, except that an open whose rights now
/// exceed what the tree grants is closed, and so is one a lease break
/// decided to close meanwhile.
async fn take_back(
    server: &Arc<ServerState>,
    conn: &Arc<Connection>,
    tree: &Tree<'_>,
    r: &Reconnect,
    open_arc: Arc<RwLock<Open>>,
    file_id: FileId,
) -> Result<HandlerResponse, u32> {
    let id = file_id.persistent;
    let not_found = ntstatus::STATUS_OBJECT_NAME_NOT_FOUND;
    let maximal = maximal_access(tree.access);
    let mut open = open_arc.write().await;
    // Share access changed while the client was away: a TREE_CONNECT under
    // the share's current rules decides what the open may keep.
    if open.granted_access & !maximal != 0 {
        drop(open);
        debug!(id, "durable open closed: access no longer granted");
        close_open(&open_arc, false).await;
        return Err(not_found);
    }
    let case_sensitive = tree.share.backend.capabilities().case_sensitive;
    let name_matches = open.file.as_ref().is_some_and(|f| {
        open.delete_on_close
            || f.delete_pending()
            || r.name
                .as_ref()
                .is_some_and(|name| same_path(&f.path(), name, case_sensitive))
    });
    if !name_matches {
        drop(open);
        server.durable.release_claim(id, open_arc).await;
        return Err(ntstatus::STATUS_INVALID_PARAMETER);
    }
    let limit = server.max_opens_per_connection.load(Ordering::Relaxed);
    let Some(slot) = OpenSlot::acquire(&conn.open_count, limit) else {
        warn!(limit, "open limit reached");
        drop(open);
        server.durable.release_claim(id, open_arc).await;
        return Err(ntstatus::STATUS_INSUFFICIENT_RESOURCES);
    };
    // A backend that cannot describe the file fails the reconnect as a
    // missing open would, whatever its error.
    let stat = match open.handle.as_ref() {
        Some(handle) => handle.stat().await.ok(),
        None => None,
    };
    let Some(info) = stat else {
        drop(open);
        server.durable.release_claim(id, open_arc).await;
        return Err(not_found);
    };
    let owner = Arc::downgrade(&conn.outbound);
    let Some((granted, guard)) = open.file.as_ref().and_then(|f| f.reattach(owner)) else {
        drop(open);
        debug!(id, "durable open closed: lease broken");
        close_open(&open_arc, false).await;
        return Err(not_found);
    };
    open.file_id = file_id;
    open.slot = Some(slot);
    drop(open);
    server.durable.attached(id, conn);

    // A tree that ended meanwhile takes no open. When its session went
    // with the connection, a LOGOFF or a sweep, the open is kept again as
    // that session would have kept it; a TREE_DISCONNECT, which leaves the
    // session, closes it.
    let mut tree_lock = tree.arc.write().await;
    if tree_lock.closed {
        drop(tree_lock);
        let session_gone =
            conn.is_closing() || !conn.sessions.read().await.contains_key(&tree.session_id);
        let left = if session_gone {
            server.durable.preserve(open_arc, tree.since).await
        } else {
            Some(open_arc)
        };
        drop(guard);
        if let Some(open) = left {
            close_open(&open, false).await;
        }
        return Err(ntstatus::STATUS_NETWORK_NAME_DELETED);
    }
    tree_lock.opens.get_mut().insert(file_id, open_arc);
    drop(tree_lock);

    let mut answers = r.queries.answer(&info, maximal, VOLUME_SERIAL_NUMBER);
    answers.push(lease_response(&granted));
    let body = encode_response(&info, file_id, true, FILE_OPENED, &answers);
    let mut response = HandlerResponse::ok(body);
    response.after_send.push(Box::new(guard));
    Ok(response)
}
