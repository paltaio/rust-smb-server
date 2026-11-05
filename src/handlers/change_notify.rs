//! CHANGE_NOTIFY handler (MS-SMB2 3.3.5.19). The first request on a
//! directory open arms a watch for it; every request is answered with the
//! changes buffered since the previous answer, at once when there are some
//! and asynchronously otherwise. On a share with change notifications off,
//! requests wait and nothing is watched.

use std::sync::Arc;
use std::sync::atomic::Ordering;

use tracing::warn;

use crate::proto::header::Smb2Header;
use crate::proto::messages::ChangeNotifyRequest;
use crate::proto::messages::ChangeNotifyResponse;
use crate::proto::messages::FileId;
use crate::proto::messages::change_notify::FILE_NOTIFY_VALID_MASK;

use crate::access_mask::FILE_LIST_DIRECTORY;
use crate::conn::pending::{AsyncOp, Stop, StopReceiver, stopped};
use crate::conn::state::Connection;
use crate::dispatch::HandlerResponse;
use crate::files::{Answer, WatchReg};
use crate::handlers::shared::{lookup_open, lookup_session_tree};
use crate::handlers::{Outcome, Pending};
use crate::ntstatus;
use crate::server::ServerState;

pub async fn handle(
    _server: &Arc<ServerState>,
    conn: &Arc<Connection>,
    hdr: &Smb2Header,
    body: &[u8],
    retained: usize,
) -> Outcome {
    let done = |status| Outcome::Done(HandlerResponse::err(status));
    let tree = match lookup_session_tree(conn, hdr).await {
        Ok(t) => t,
        Err(status) => return done(status),
    };
    let Ok(req) = ChangeNotifyRequest::parse(body) else {
        return done(ntstatus::STATUS_INVALID_PARAMETER);
    };
    let Some(open_arc) = lookup_open(&tree, req.file_id).await else {
        return done(ntstatus::STATUS_FILE_CLOSED);
    };
    if req.output_buffer_length > *conn.max_read_size.read().await {
        return done(ntstatus::STATUS_INVALID_PARAMETER);
    }
    let share = Arc::clone(&tree.read().await.share);
    let mut open = open_arc.write().await;
    if !open.is_directory {
        return done(ntstatus::STATUS_INVALID_PARAMETER);
    }
    if open.granted_access & FILE_LIST_DIRECTORY == 0 {
        return done(ntstatus::STATUS_ACCESS_DENIED);
    }
    // MS-FSA 2.1.5.11: an open that marked its directory for deletion, or
    // opened it delete-on-close, gets STATUS_DELETE_PENDING. So does any
    // open of a directory that is delete-pending: Windows answers so the
    // next request on a handle whose watch the mark ended.
    if open.marked_deleted.load(Ordering::Acquire) || open.delete_on_close || open.delete_pending()
    {
        return done(ntstatus::STATUS_DELETE_PENDING);
    }
    if !share.change_notify {
        drop(open);
        return unanswered(conn, hdr, req.file_id, retained).await;
    }
    // Arming reads the open's name, so no rename may run until the watch
    // is in the table under it. The lock comes before the open's, as a
    // rename takes them.
    let names = if open.watch.as_ref().is_none_or(WatchReg::ended) {
        drop(open);
        let names = share.files.names_lock().await;
        open = open_arc.write().await;
        Some(names)
    } else {
        None
    };
    let tree_flag = req.flags & ChangeNotifyRequest::FLAG_WATCH_TREE != 0;
    // MS-SMB2 3.3.1.3: the first request fixes the filter, WATCH_TREE and
    // buffer size; later requests take what the watch buffered.
    // A watch its directory's deletion ended is replaced once the mark is
    // cleared (MS-FSA 2.1.5.11).
    // A watch that ended while this request held the open stays: the
    // request takes its end. So does one whose directory was deleted
    // outside the server.
    let watch = match &open.watch {
        Some(reg) if !reg.ended() || names.is_none() || reg.gone() => Arc::clone(reg.watch()),
        _ => {
            // Closed while this request waited for the open.
            let Some(dir) = open.path() else {
                return done(ntstatus::STATUS_FILE_CLOSED);
            };
            let Some(reg) = WatchReg::arm(
                &share,
                dir,
                req.completion_filter & FILE_NOTIFY_VALID_MASK,
                tree_flag,
                req.output_buffer_length,
                &conn.notify_budget,
            ) else {
                warn!("too many change notification watches on the connection");
                return done(ntstatus::STATUS_INSUFFICIENT_RESOURCES);
            };
            // A mark set since the check above either found the watch in
            // the table and ended it, or shows here.
            if open.delete_pending() {
                return done(ntstatus::STATUS_DELETE_PENDING);
            }
            let watch = Arc::clone(reg.watch());
            open.watch = Some(reg);
            watch
        }
    };
    // Each request asks again for the backend's reports of the directory,
    // in case they stopped.
    if let Some(handle) = open.handle.as_deref() {
        share.watches.listen(&share, &watch, handle).await;
    }
    drop(open);
    drop(names);

    let ticket = watch.enqueue(req.output_buffer_length, tree_flag);
    let mut changed = watch.subscribe();
    if let Some(answer) = watch.take(&ticket) {
        return Outcome::Done(respond(answer));
    }
    // The watch keeps buffering for the next request when this one is
    // refused.
    let (op, mut stop) = match reserve(conn, hdr, req.file_id, retained) {
        Ok(reserved) => reserved,
        Err(refused) => return refused,
    };
    // A cancelled request leaves the queue and the changes stay buffered
    // for the next one. Its open, tree or session going away closes the
    // open, which ends the watch (MS-SMB2 3.3.4.17).
    let work = async move {
        loop {
            tokio::select! {
                biased;
                why = stopped(&mut stop) => return stopped_response(why),
                _ = changed.changed() => {}
            }
            if let Some(answer) = watch.take(&ticket) {
                return respond(answer);
            }
        }
    };
    Outcome::Pending(Pending {
        op,
        work: Box::pin(work),
    })
}

/// A request on a share with change notifications off, which waits as on a
/// share where nothing changes: until it is cancelled, or its open, tree,
/// session or connection goes away. A macOS client that got the `AAPL`
/// reply hangs on unmount if a CHANGE_NOTIFY fails with
/// STATUS_NOT_SUPPORTED.
async fn unanswered(
    conn: &Arc<Connection>,
    hdr: &Smb2Header,
    file_id: FileId,
    retained: usize,
) -> Outcome {
    let (op, mut stop) = match reserve(conn, hdr, file_id, retained) {
        Ok(reserved) => reserved,
        Err(refused) => return refused,
    };
    // An open closed, or a tree or session ended, before the request was
    // reserved stopped no request for it; one that ends later stops it.
    let reachable = match lookup_session_tree(conn, hdr).await {
        Ok(tree) => lookup_open(&tree, file_id).await.is_some(),
        Err(_) => false,
    };
    if !reachable {
        conn.pending.finish(op.async_id);
        return Outcome::Done(HandlerResponse::err(ntstatus::STATUS_FILE_CLOSED));
    }
    let work = async move { stopped_response(stopped(&mut stop).await) };
    Outcome::Pending(Pending {
        op,
        work: Box::pin(work),
    })
}

/// Registers the request `hdr` on `file_id` as asynchronous. MS-SMB2
/// 3.3.4.2: past its limits the connection gets no more asynchronous
/// requests, and the request fails with STATUS_INSUFFICIENT_RESOURCES.
fn reserve(
    conn: &Connection,
    hdr: &Smb2Header,
    file_id: FileId,
    retained: usize,
) -> Result<(Arc<AsyncOp>, StopReceiver), Outcome> {
    conn.pending
        .reserve(hdr, Some(file_id), retained)
        .ok_or_else(|| {
            warn!("too many waiting requests on the connection");
            Outcome::Done(HandlerResponse::err(
                ntstatus::STATUS_INSUFFICIENT_RESOURCES,
            ))
        })
}

/// The response of a waiting request told to stop: STATUS_CANCELLED for a
/// CANCEL, STATUS_NOTIFY_CLEANUP when its open, tree or session went away.
fn stopped_response(why: Stop) -> HandlerResponse {
    match why {
        Stop::Cancelled => HandlerResponse::err(ntstatus::STATUS_CANCELLED),
        Stop::Retry => respond(Answer::Ended(ntstatus::STATUS_NOTIFY_CLEANUP)),
    }
}

/// The response for `answer`. STATUS_NOTIFY_ENUM_DIR and
/// STATUS_NOTIFY_CLEANUP carry a CHANGE_NOTIFY body without entries
/// (MS-SMB2 3.3.5.19, 2.2.36); other failures an ERROR body.
fn respond(answer: Answer) -> HandlerResponse {
    let empty = |status| HandlerResponse {
        status,
        ..HandlerResponse::ok(ChangeNotifyResponse::encode(&[]))
    };
    match answer {
        Answer::Changes(entries) => HandlerResponse::ok(ChangeNotifyResponse::encode(&entries)),
        Answer::EnumDir => empty(ntstatus::STATUS_NOTIFY_ENUM_DIR),
        Answer::Ended(ntstatus::STATUS_NOTIFY_CLEANUP) => empty(ntstatus::STATUS_NOTIFY_CLEANUP),
        Answer::Ended(status) => HandlerResponse::err(status),
    }
}
