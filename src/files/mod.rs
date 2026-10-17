//! State of open files shared by every connection, and closing an open.

mod table;

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use tokio::sync::RwLock;
use tracing::{debug, warn};

use crate::backend::FileInfo;
use crate::conn::state::Open;
use crate::error::SmbError;
use crate::handlers::shared::restore_fixed_times;

pub(crate) use table::{FileRef, FileTable, Sharing};

/// Opens one connection may hold at once unless
/// `ConfigHandle::set_max_opens_per_connection` sets another limit.
pub(crate) const DEFAULT_MAX_OPENS_PER_CONNECTION: usize = 16384;

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
/// open of a delete-pending file. Every path that ends an open goes through
/// here. With `want_attrs`, returns the file's attributes as they were
/// before the handle closed. Waits for requests still using the open.
pub(crate) async fn close_open(open_arc: &Arc<RwLock<Open>>, want_attrs: bool) -> Option<FileInfo> {
    let mut open = open_arc.write().await;
    restore_fixed_times(&open).await;
    let handle = open.handle.take()?;
    let info = if want_attrs {
        handle.stat().await.ok()
    } else {
        None
    };
    // MS-FSA 2.1.5.5 phase 1: a directory that is not empty is not deleted.
    let delete_on_close = open.delete_on_close
        && (!open.is_directory
            || handle
                .list_dir(None)
                .await
                .is_ok_and(|entries| entries.is_empty()));
    if let Err(e) = handle.close().await {
        debug!(error = %e, path = %open.last_path, "backend close failed");
    }
    let file = open.file.take();
    open.slot.take();
    drop(open);

    if let Some(pending) = file.and_then(|f| f.release(delete_on_close)) {
        let path = pending.path();
        // A failed delete does not fail the close (MS-SMB2 3.3.4.17). A
        // directory that gained entries stays (MS-FSA 2.1.5.5).
        match pending.share().backend.unlink(path).await {
            Ok(()) => {}
            Err(SmbError::NotEmpty) => {
                debug!(path = %path, "delete-on-close skipped a non-empty directory");
            }
            Err(e) => warn!(error = %e, path = %path, "delete-on-close failed"),
        }
        pending.finish();
    }
    info
}

/// Closes every open in `opens`, each on its own task, so one that waits
/// for a slow request does not hold up the others. Returns once all are
/// closed; the tasks finish even if the caller stops waiting.
pub(crate) async fn close_opens(opens: Vec<Arc<RwLock<Open>>>) {
    let tasks: Vec<_> = opens
        .into_iter()
        .map(|open| {
            tokio::spawn(async move {
                close_open(&open, false).await;
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
    use crate::builder::Access;
    use crate::conn::state::{Connection, Session, TreeConnect};
    use crate::proto::auth::ntlm::Identity;
    use crate::server::{ShareBindings, ShareMode};
    use crate::tests::memfs::MemFsBackend;

    fn share() -> Arc<ShareBindings> {
        ShareBindings::new(
            "s".to_string(),
            Arc::new(MemFsBackend::new()),
            ShareMode::Public,
            HashMap::new(),
            false,
        )
    }

    #[tokio::test]
    async fn sweeps_match_the_share_not_its_name() {
        let removed = share();
        let added = share();
        let conn = Connection::new(uuid::Uuid::nil(), 1 << 16, 1 << 16);
        let session = Session::new(1, Identity::Anonymous, [0; 16], [0; 16], false, None);
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

    #[test]
    fn open_slots_stop_at_the_limit() {
        let count = Arc::new(AtomicUsize::new(0));
        let first = OpenSlot::acquire(&count, 2).unwrap();
        let _second = OpenSlot::acquire(&count, 2).unwrap();
        assert!(OpenSlot::acquire(&count, 2).is_none());
        drop(first);
        assert!(OpenSlot::acquire(&count, 2).is_some());
    }
}
