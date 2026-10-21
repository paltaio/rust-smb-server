//! State of open files shared by every connection, and closing an open.

mod durable;
mod lease;
mod leases;
mod table;

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use tokio::sync::RwLock;
use tracing::debug;

use crate::backend::{FileInfo, Handle};
use crate::conn::state::Open;
use crate::handlers::shared::restore_fixed_times;

pub(crate) use durable::{Claim, DurableReg, DurableTable, Unclaimed};
pub use durable::{DEFAULT_DURABLE_HANDLE_TIMEOUT, DEFAULT_MAX_DISCONNECTED_OPENS};
pub(crate) use lease::{Granted, LeaseId, LeaseRequest, LeaseState, LeaseVersion, Trigger};
#[cfg(test)]
pub(crate) use leases::LEASE_BREAK_TIMEOUT;
pub(crate) use leases::{AfterSend, BreakWait, LeaseRef, LeaseTable, MAX_BREAK_WAIT};
pub(crate) use table::{FileRef, FileTable, OpenRequest, Refused, Sharing};

/// Default for
/// [`SmbServerBuilder::max_opens_per_connection`](crate::SmbServerBuilder::max_opens_per_connection)
/// and
/// [`ConfigHandle::set_max_opens_per_connection`](crate::ConfigHandle::set_max_opens_per_connection).
pub const DEFAULT_MAX_OPENS_PER_CONNECTION: usize = 16384;

/// Default for
/// [`SmbServerBuilder::max_locks_per_open`](crate::SmbServerBuilder::max_locks_per_open).
pub const DEFAULT_MAX_LOCKS_PER_OPEN: usize = 1024;

/// Counts one open against its connection's limit until dropped.
pub(crate) struct OpenSlot(Arc<AtomicUsize>);

impl OpenSlot {
    /// Takes a slot from `count`, or `None` when `limit` slots are taken.
    pub(crate) fn acquire(count: &Arc<AtomicUsize>, limit: usize) -> Option<Self> {
        count
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| {
                (n < limit).then_some(n + 1)
            })
            .ok()
            .map(|_| Self(Arc::clone(count)))
    }
}

impl Drop for OpenSlot {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

/// Closes an open that is no longer reachable by FileId (MS-SMB2 3.3.4.17,
/// MS-FSA 2.1.5.5): restores the times it fixed, closes the backend handle,
/// drops its byte-range locks and removes the file when this was the last
/// open of a delete-pending file. With `want_attrs`, returns the file's
/// attributes as they were before the handle closed. Waits for requests
/// still using the open.
pub(crate) async fn close_open(open_arc: &Arc<RwLock<Open>>, want_attrs: bool) -> Option<FileInfo> {
    let mut open = open_arc.write().await;
    restore_fixed_times(&open).await;
    let handle = open.handle.take()?;
    let info = if want_attrs {
        handle.stat().await.ok()
    } else {
        None
    };
    let file = open.file.take();
    open.slot.take();
    let delete_on_close = open.delete_on_close;
    let is_directory = open.is_directory;
    drop(open);
    finish_close(handle, file, delete_on_close, is_directory).await;
    info
}

/// Closes the backend handle of an open and takes the open out of its
/// share's file table. With `delete_on_close` the file becomes
/// delete-pending, unless it is a directory with entries (MS-FSA 2.1.5.5
/// phase 1), and is removed when this was its last open. Every path that
/// ends an open goes through here.
pub(crate) async fn finish_close(
    handle: Box<dyn Handle>,
    file: Option<FileRef>,
    delete_on_close: bool,
    is_directory: bool,
) {
    let delete_on_close =
        delete_on_close && (!is_directory || handle.dir_is_empty().await.unwrap_or(false));
    if let Err(e) = handle.close().await {
        let path = file.as_ref().map(FileRef::path).unwrap_or_default();
        debug!(error = %e, path = %path, "backend close failed");
    }
    if let Some(pending) = file.and_then(|f| f.release(delete_on_close)) {
        pending.run().await;
    }
}

/// Closes every open in `opens`, each on its own task, so one that waits
/// for a slow request does not hold up the others. Returns once all are
/// closed; the tasks finish even if the caller stops waiting.
pub(crate) async fn close_opens(opens: Vec<Arc<RwLock<Open>>>) {
    end_opens(opens, None).await;
}

/// Ends the opens of a session that is going away, each on its own task as
/// [`close_opens`] does. With `keep`, a durable open that qualifies stays
/// in that table for its client (MS-SMB2 3.3.7.1, 3.3.5.6); every other
/// open is closed. `keep` carries the table's [`DurableTable::sweeps`]
/// from before the session left its connection.
pub(crate) async fn end_opens(
    opens: Vec<Arc<RwLock<Open>>>,
    keep: Option<(&Arc<DurableTable>, u64)>,
) {
    let tasks: Vec<_> = opens
        .into_iter()
        .map(|open| {
            let keep = keep.map(|(table, since)| (Arc::clone(table), since));
            tokio::spawn(async move {
                let open = match keep {
                    Some((table, since)) => table.preserve(open, since).await,
                    None => Some(open),
                };
                if let Some(open) = open {
                    close_open(&open, false).await;
                }
            })
        })
        .collect();
    for task in tasks {
        let _ = task.await;
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;
    use crate::access_mask::DELETE;
    use crate::backend::{FileTimes, OpenIntent, OpenOptions};
    use crate::builder::Access;
    use crate::conn::state::{Connection, Session, TreeConnect};
    use crate::error::SmbError;
    use crate::path::SmbPath;
    use crate::proto::auth::ntlm::Identity;
    use crate::proto::messages::FileId;
    use crate::server::{ShareBindings, ShareMode};
    use crate::tests::memfs::MemFsBackend;

    fn share() -> Arc<ShareBindings> {
        share_on(MemFsBackend::new())
    }

    fn share_on(backend: MemFsBackend) -> Arc<ShareBindings> {
        ShareBindings::new(
            "s".to_string(),
            Arc::new(backend),
            ShareMode::Public,
            HashMap::new(),
            false,
            true,
            true,
        )
    }

    /// Opens `path` with FILE_DELETE_ON_CLOSE, creating it if needed, and
    /// drops the open without a CLOSE.
    async fn drop_without_close(
        share: &Arc<ShareBindings>,
        path: &str,
        directory: bool,
    ) -> SmbPath {
        let path: SmbPath = path.parse().unwrap();
        let opts = OpenOptions {
            directory,
            intent: OpenIntent::OpenOrCreate,
            ..OpenOptions::default()
        };
        let (handle, _) = share.backend.open(&path, opts).await.unwrap();
        let info = handle.stat().await.unwrap();
        let sharing = Sharing {
            access: DELETE,
            share: 0,
        };
        let file = FileRef::register(share, &info, &path, sharing.into())
            .unwrap()
            .0;
        drop(Open {
            file_id: FileId::default(),
            handle: Some(handle),
            granted_access: DELETE,
            is_directory: directory,
            delete_on_close: true,
            search_state: None,
            fixed_times: FileTimes::default(),
            create_options: 0,
            file: Some(file),
            slot: None,
            durable: None,
        });
        let in_table = || {
            share.files.path_is_open(&path, false) || share.files.delete_pending_at(&path, false)
        };
        for _ in 0..100 {
            if !in_table() {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert!(!in_table());
        path
    }

    #[tokio::test]
    async fn a_dropped_delete_on_close_open_removes_the_file() {
        let s = share();
        let path = drop_without_close(&s, "f", false).await;
        let missing = s.backend.open(&path, OpenOptions::default()).await;
        assert!(matches!(missing, Err(SmbError::NotFound)));
    }

    #[tokio::test]
    async fn a_dropped_delete_on_close_open_keeps_a_directory_with_entries() {
        let s = share_on(MemFsBackend::new().with_file("d\\f", b"x"));
        let path = drop_without_close(&s, "d", true).await;
        let opts = OpenOptions {
            directory: true,
            ..OpenOptions::default()
        };
        assert!(s.backend.open(&path, opts).await.is_ok());
    }

    #[tokio::test]
    async fn sweeps_match_the_share_not_its_name() {
        let removed = share();
        let added = share();
        let conn = Connection::new(uuid::Uuid::nil(), 1 << 16, 1 << 16);
        let session = Session::new(Identity::Anonymous, [0; 16], [0; 16], false, None);
        let tree = TreeConnect::new(1, Arc::clone(&added), Access::ReadWrite);
        session
            .trees
            .write()
            .await
            .insert(1, Arc::new(RwLock::new(tree)));
        let session = Arc::new(RwLock::new(session));
        conn.sessions.write().await.insert(1, Arc::clone(&session));

        assert!(conn.detach_trees_for_share(&removed).await.is_empty());
        assert_eq!(session.read().await.trees.read().await.len(), 1);
        conn.detach_trees_for_share(&added).await;
        assert!(session.read().await.trees.read().await.is_empty());
    }
}
