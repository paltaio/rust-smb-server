//! FSCTL_DUPLICATE_EXTENTS_TO_FILE (MS-SMB2 3.3.5.15.17, MS-FSA 2.1.5.10.4):
//! a range of the open the request names, which has to be in the session,
//! shares its storage with a range of the open the request is on. The
//! backend clones in one call. The extended form is not served.
//!
//! FSCTL_SET_SPARSE is accepted on the shares that clone.

use std::sync::Arc;
use std::sync::atomic::Ordering;

use tokio::sync::RwLock;

use super::{Call, Ends, Guards, find_open, permitted};
use crate::access_mask::{FILE_WRITE_ATTRIBUTES, FILE_WRITE_DATA};
use crate::conn::state::{Connection, Open, TreeConnect};
use crate::dispatch::HandlerResponse;
use crate::error::SmbError;
use crate::handlers::Outcome;
use crate::handlers::ioctl::response;
use crate::handlers::shared::restore_fixed_times;
use crate::ntstatus;
use crate::proto::messages::duplicate_extents::DuplicateExtentsRequest;
use crate::proto::messages::{Fsctl, IoctlRequest};
use crate::server::ShareBindings;
use crate::stream::unsupported;

/// Answers a request of FSCTL_DUPLICATE_EXTENTS_TO_FILE or its extended
/// form on `target`, an open of a file share on `tree`.
pub(in crate::handlers) async fn duplicate_extents(
    conn: &Arc<Connection>,
    call: &Call<'_>,
    tree: &Arc<RwLock<TreeConnect>>,
    target: &Arc<RwLock<Open>>,
) -> Outcome {
    let Call {
        hdr, req, input, ..
    } = *call;
    if req.fsctl() == Fsctl::DuplicateExtentsToFileEx {
        return Outcome::Done(HandlerResponse::err(
            ntstatus::STATUS_INVALID_DEVICE_REQUEST,
        ));
    }
    let Some(request) = DuplicateExtentsRequest::parse(input) else {
        return Outcome::Done(HandlerResponse::err(ntstatus::STATUS_INVALID_PARAMETER));
    };
    let Some(source) = find_open(conn, hdr.session_id, request.source).await else {
        return Outcome::Done(HandlerResponse::err(ntstatus::STATUS_INVALID_HANDLE));
    };
    let share = Arc::clone(&tree.read().await.share);
    if !share.block_cloning || !source.share.server_side_copy {
        return Outcome::Done(HandlerResponse::err(
            ntstatus::STATUS_INVALID_DEVICE_REQUEST,
        ));
    }
    let guards = Guards::take(&source.open, target).await;
    Outcome::Done(duplicate(&share, &guards, req, &request).await)
}

/// Checks the two opens and clones the range of the source into the target.
async fn duplicate(
    share: &ShareBindings,
    guards: &Guards<'_>,
    req: &IoctlRequest,
    request: &DuplicateExtentsRequest,
) -> HandlerResponse {
    let (source, target) = (guards.source(), guards.target());
    // A named stream never gets STATUS_NOT_SUPPORTED; see `refused`.
    if source.on_stream || target.on_stream {
        return HandlerResponse::err(ntstatus::STATUS_INVALID_DEVICE_REQUEST);
    }
    // Appending does not give the right to overwrite a range.
    if !permitted(req.fsctl(), source, target) || target.granted_access & FILE_WRITE_DATA == 0 {
        return HandlerResponse::err(ntstatus::STATUS_ACCESS_DENIED);
    }
    let ends = match guards.ends(share) {
        Ok(ends) => ends,
        Err(ntstatus::STATUS_OBJECT_NAME_NOT_FOUND) => {
            return HandlerResponse::err(ntstatus::STATUS_INVALID_HANDLE);
        }
        Err(status) => return HandlerResponse::err(status),
    };
    match ends.duplicate(target, request).await {
        Ok(()) => response(req.ctl_code, target.file_id, Vec::new()),
        Err(status) => HandlerResponse::err(status),
    }
}

impl Ends<'_> {
    /// Clones the part of the range that lies inside both files, when that
    /// part ends on a cluster boundary or at the end of both files. A clone
    /// never extends the target. A source range may end anywhere in the last
    /// cluster of the source, and the clone then stops at the end of the
    /// source. The leases on the target break before the clone and again
    /// after it, and the open `target` is marked written unless the backend
    /// refused the range.
    async fn duplicate(&self, target: &Open, request: &DuplicateExtentsRequest) -> Result<(), u32> {
        let DuplicateExtentsRequest {
            source_offset,
            target_offset,
            byte_count,
            ..
        } = *request;
        let volume = self.backend.volume_info().await.map_err(clone_status)?;
        let cluster = volume.allocation_unit();
        if [source_offset, target_offset, byte_count]
            .iter()
            .any(|field| !field.is_multiple_of(cluster))
        {
            return Err(ntstatus::STATUS_NOT_SUPPORTED);
        }
        if byte_count == 0 {
            return Ok(());
        }
        let source_size = self.source.stat().await.map_err(clone_status)?.end_of_file;
        let rounded = source_size
            .checked_next_multiple_of(cluster)
            .unwrap_or(u64::MAX);
        if request.source_end().is_none_or(|end| end > rounded) {
            return Err(ntstatus::STATUS_NOT_SUPPORTED);
        }
        let target_size = self.target.stat().await.map_err(clone_status)?.end_of_file;
        let len = byte_count
            .min(source_size.saturating_sub(source_offset))
            .min(target_size.saturating_sub(target_offset));
        if len == 0 {
            return Ok(());
        }
        if !len.is_multiple_of(cluster)
            && (source_offset + len != source_size || target_offset + len != target_size)
        {
            return Err(ntstatus::STATUS_NOT_SUPPORTED);
        }
        if self.source_file.same_data_as(self.target_file)
            && source_offset.abs_diff(target_offset) < len
        {
            return Err(ntstatus::STATUS_NOT_SUPPORTED);
        }
        self.source_file.check_io(source_offset, len, false)?;
        self.target_file.check_io(target_offset, len, true)?;

        let cloned = self
            .breaking_leases(self.backend.clone_range(
                self.source,
                source_offset,
                self.target,
                target_offset,
                len,
            ))
            .await;
        let changed = !cloned
            .as_ref()
            .is_err_and(SmbError::leaves_target_unchanged);
        if changed {
            target.wrote.store(true, Ordering::Release);
        }
        let mut status = cloned.map_or_else(clone_status, |()| ntstatus::STATUS_SUCCESS);
        if status == ntstatus::STATUS_SUCCESS
            && let Err(e) = self.flush_write_through(target).await
        {
            status = clone_status(e);
        }
        if changed {
            restore_fixed_times(target).await;
        }
        match status {
            ntstatus::STATUS_SUCCESS => Ok(()),
            status => Err(status),
        }
    }
}

/// The status for a backend error of a clone: STATUS_INVALID_PARAMETER for
/// files on different volumes, and STATUS_INVALID_DEVICE_REQUEST for storage
/// that cannot share blocks.
fn clone_status(error: SmbError) -> u32 {
    match error {
        SmbError::NotSupported => ntstatus::STATUS_INVALID_DEVICE_REQUEST,
        SmbError::NotSameDevice => ntstatus::STATUS_INVALID_PARAMETER,
        error => error.to_nt_status(),
    }
}

/// Answers a request of FSCTL_SET_SPARSE on `target`, an open of a file share
/// on `tree`. The request changes nothing: on a share that clones, the host
/// decides which files are sparse. Other shares answer as they do for any
/// FSCTL they do not serve.
pub(in crate::handlers) async fn set_sparse(
    req: &IoctlRequest,
    tree: &Arc<RwLock<TreeConnect>>,
    target: &Arc<RwLock<Open>>,
) -> HandlerResponse {
    let block_cloning = tree.read().await.share.block_cloning;
    let open = target.read().await;
    if !block_cloning || open.on_stream {
        return HandlerResponse::err(unsupported(open.on_stream));
    }
    if open.handle.is_none() {
        return HandlerResponse::err(ntstatus::STATUS_FILE_CLOSED);
    }
    if open.is_directory {
        return HandlerResponse::err(ntstatus::STATUS_INVALID_PARAMETER);
    }
    if open.granted_access & (FILE_WRITE_DATA | FILE_WRITE_ATTRIBUTES) == 0 {
        return HandlerResponse::err(ntstatus::STATUS_ACCESS_DENIED);
    }
    response(req.ctl_code, open.file_id, Vec::new())
}
