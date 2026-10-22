//! CHANGE_NOTIFY handler (MS-SMB2 3.3.5.19). The first request on a
//! directory open arms a watch for it; every request is answered with the
//! changes buffered since the previous answer, at once when there are some
//! and asynchronously otherwise.

use std::sync::Arc;

use tracing::warn;

use crate::proto::header::Smb2Header;
use crate::proto::messages::ChangeNotifyRequest;
use crate::proto::messages::ChangeNotifyResponse;
use crate::proto::messages::change_notify::FILE_NOTIFY_VALID_MASK;

use crate::access_mask::FILE_LIST_DIRECTORY;
use crate::conn::pending::{Stop, stopped};
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
    if !share.change_notify {
        return done(ntstatus::STATUS_NOT_SUPPORTED);
    }
    // Arming reads the open's name, so no rename may run until the watch
    // is in the table under it. The lock comes before the open's, as a
    // rename takes them.
    let names = if open.watch.is_none() {
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
    let watch = match &open.watch {
        Some(reg) => Arc::clone(reg.watch()),
        None => {
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
            let watch = Arc::clone(reg.watch());
            open.watch = Some(reg);
            watch
        }
    };
    drop(open);
    drop(names);

    let ticket = watch.enqueue(req.output_buffer_length, tree_flag);
    let mut changed = watch.subscribe();
    if let Some(answer) = watch.take(&ticket) {
        return Outcome::Done(respond(answer));
    }
    // MS-SMB2 3.3.4.2: past its limits the connection gets no more
    // asynchronous requests. The watch keeps buffering for the next one.
    let Some((op, mut stop)) = conn.pending.reserve(hdr, Some(req.file_id), retained) else {
        warn!("too many waiting requests on the connection");
        return done(ntstatus::STATUS_INSUFFICIENT_RESOURCES);
    };
    // A cancelled request leaves the queue and the changes stay buffered
    // for the next one. Its open, tree or session going away closes the
    // open, which ends the watch (MS-SMB2 3.3.4.17).
    let work = async move {
        loop {
            tokio::select! {
                biased;
                why = stopped(&mut stop) => {
                    return match why {
                        Stop::Cancelled => HandlerResponse::err(ntstatus::STATUS_CANCELLED),
                        Stop::Retry => respond(Answer::Ended(ntstatus::STATUS_NOTIFY_CLEANUP)),
                    };
                }
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
