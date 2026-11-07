//! Apple's whole-file copy. A COPYCHUNK or COPYCHUNK_WRITE without chunks
//! from a connection that was offered OSX_COPYFILE copies the file the
//! resume key names into the open the request is on: its data, its named
//! streams, and its creation and last write times. The copy has no size
//! limit, so the request is answered asynchronously. The copy works in
//! pieces of 1 MiB and holds the opens only while it copies one.
//!
//! macOS deletes its target on any error, so a failed data or stream step
//! fails the request. Setting the times does not.

use std::sync::Arc;
use std::sync::atomic::Ordering;

use tokio::sync::{RwLock, SemaphorePermit};
use tracing::warn;

use super::{Call, Ends, Guards, Side, copy_response, find_source, permitted, reply_status};
use crate::access_mask::FILE_WRITE_DATA;
use crate::backend::{FileInfo, FileTimes, VolumeInfo};
use crate::conn::pending::{Stop, StopReceiver, stopped};
use crate::conn::state::{Connection, Open};
use crate::dispatch::HandlerResponse;
use crate::error::SmbError;
use crate::handlers::create::{CopyStream, WRITE_THROUGH_OPTIONS, open_copy_stream};
use crate::handlers::shared::{discard_open, lookup_open, lookup_tree};
use crate::handlers::{Outcome, Pending};
use crate::ntstatus;
use crate::proto::messages::copychunk::{Chunk, CopychunkResponse, MAX_CHUNK_LEN, RESUME_KEY_LEN};
use crate::proto::messages::{FileId, Fsctl};
use crate::server::{ServerState, ShareBindings};
use crate::stream::StreamName;

/// Bytes copied between two checks for a stop.
const PIECE: u64 = MAX_CHUNK_LEN as u64;

/// What the request does once its opens are checked.
enum Admitted {
    Copy,
    /// The source and the target are one file, which a copy leaves as it
    /// is. Holds its size.
    Itself(u64),
}

/// Starts the copy of the file open as `source`, which `key` names, into
/// `target`, the open the request is on.
pub(super) async fn start(
    server: &Arc<ServerState>,
    conn: &Arc<Connection>,
    call: &Call<'_>,
    key: [u8; RESUME_KEY_LEN],
    source: Side,
    target: Side,
) -> Outcome {
    let Call {
        hdr, req, retained, ..
    } = *call;
    let (file_id, write_through) = {
        let guards = Guards::take(&source.open, &target.open).await;
        let file_id = guards.target().file_id;
        match admit(req.fsctl(), &source.share, &target.share, &guards).await {
            Ok(Admitted::Copy) => {}
            Ok(Admitted::Itself(size)) => {
                return Outcome::Done(reply(req.ctl_code, file_id, ntstatus::STATUS_SUCCESS, size));
            }
            Err(status) => return Outcome::Done(HandlerResponse::err(status)),
        }
        let write_through = guards.target().create_options & WRITE_THROUGH_OPTIONS != 0;
        (file_id, write_through)
    };
    let Some((op, stop)) = conn.pending.reserve(hdr, Some(file_id), retained) else {
        warn!("too many waiting requests on the connection");
        return Outcome::Done(HandlerResponse::err(
            ntstatus::STATUS_INSUFFICIENT_RESOURCES,
        ));
    };
    let job = Job {
        server: Arc::clone(server),
        conn: Arc::clone(conn),
        session_id: hdr.session_id,
        ctl_code: req.ctl_code,
        key,
        file_id,
        write_through,
        source,
        target,
    };
    Outcome::Pending(Pending {
        op,
        work: Box::pin(job.run(stop)),
    })
}

/// Checks that the two opens are files on their default streams, with the
/// rights of a copy and the target open for writing data, which emptying it
/// takes. Tells whether they are one file.
async fn admit(
    code: Fsctl,
    source_share: &Arc<ShareBindings>,
    target_share: &Arc<ShareBindings>,
    guards: &Guards<'_>,
) -> Result<Admitted, u32> {
    let (source, target) = (guards.source(), guards.target());
    if !permitted(code, source, target)
        || source.on_stream
        || target.on_stream
        || target.granted_access & FILE_WRITE_DATA == 0
    {
        return Err(ntstatus::STATUS_ACCESS_DENIED);
    }
    let ends = guards.ends(target_share)?;
    let info = ends.source.stat().await.map_err(|e| ends.status_of(e))?;
    let itself = ends.source_file.same_data_as(ends.target_file)
        || same_file_on_two_shares(&ends, &info, source_share, target_share)
            .await
            .map_err(|e| ends.status_of(e))?;
    if itself {
        return Ok(Admitted::Itself(info.end_of_file));
    }
    Ok(Admitted::Copy)
}

/// Whether the source and the target are one file reached through two shares
/// over one directory, which neither share's file table can tell. A backend
/// that reports no file id, or no volume, leaves them apart.
async fn same_file_on_two_shares(
    ends: &Ends<'_>,
    source: &FileInfo,
    source_share: &Arc<ShareBindings>,
    target_share: &Arc<ShareBindings>,
) -> Result<bool, SmbError> {
    if Arc::ptr_eq(source_share, target_share) || source.file_index == 0 {
        return Ok(false);
    }
    if ends.target.stat().await?.file_index != source.file_index {
        return Ok(false);
    }
    let (Ok(from), Ok(to)) = (
        source_share.backend.volume_info().await,
        target_share.backend.volume_info().await,
    ) else {
        return Ok(false);
    };
    Ok(from.serial_number == to.serial_number && from != VolumeInfo::default())
}

/// The response with `status`, for a copy that moved `bytes` of data.
fn reply(ctl_code: u32, file_id: FileId, status: u32, bytes: u64) -> HandlerResponse {
    copy_response(
        ctl_code,
        file_id,
        status,
        CopychunkResponse {
            chunks_written: 0,
            chunk_bytes_written: 0,
            total_bytes_written: u32::try_from(bytes).unwrap_or(u32::MAX),
        },
    )
}

/// Why a copy stopped before it finished.
enum Halt {
    /// It was cancelled, or its session, tree or an open went away. The
    /// response is the bare status a new request would get.
    Stopped(u32),
    /// A step failed. The response carries the status and the bytes of data
    /// copied.
    Failed(u32, u64),
}

impl Halt {
    /// A step failed with `status` before any data was copied.
    fn failed(status: u32) -> Self {
        Self::Failed(status, 0)
    }

    /// This halt for a step that ran after `copied` bytes of data were
    /// copied.
    fn after(self, copied: u64) -> Self {
        match self {
            Self::Failed(status, _) => Self::Failed(status, copied),
            halt => halt,
        }
    }
}

impl Ends<'_> {
    /// The halt for a backend error of a step on these ends.
    fn halt(&self, error: SmbError) -> Halt {
        Halt::failed(self.status_of(error))
    }
}

/// A stream open the copy made.
struct StreamOpen {
    tree_id: u32,
    file_id: FileId,
    open: Arc<RwLock<Open>>,
}

struct Job {
    server: Arc<ServerState>,
    conn: Arc<Connection>,
    session_id: u64,
    ctl_code: u32,
    /// The resume key of the source.
    key: [u8; RESUME_KEY_LEN],
    /// The target's FileId.
    file_id: FileId,
    /// The target was opened for write-through.
    write_through: bool,
    source: Side,
    target: Side,
}

impl Job {
    async fn run(self, mut stop: StopReceiver) -> HandlerResponse {
        match self.copy_file(&mut stop).await {
            Ok(size) => reply(self.ctl_code, self.file_id, ntstatus::STATUS_SUCCESS, size),
            Err(Halt::Stopped(status)) => HandlerResponse::err(status),
            Err(Halt::Failed(status, copied)) => reply(self.ctl_code, self.file_id, status, copied),
        }
    }

    /// Copies the data, the streams and the times; returns the size of the
    /// data.
    async fn copy_file(&self, stop: &mut StopReceiver) -> Result<u64, Halt> {
        let info = self.empty_target(stop).await?;
        let size = info.end_of_file;
        self.copy_data(stop, &self.source.open, &self.target.open, size)
            .await?;
        self.finish(stop, &info)
            .await
            .map_err(|halt| halt.after(size))?;
        Ok(size)
    }

    /// The steps after the data: copies the named streams when both shares
    /// have them, and sets the times.
    async fn finish(&self, stop: &mut StopReceiver, info: &FileInfo) -> Result<(), Halt> {
        if self.source.share.named_streams && self.target.share.named_streams {
            self.copy_streams(stop).await?;
        }
        self.checkpoint(stop).await?;
        self.set_times(info).await;
        Ok(())
    }

    /// Fails once the copy is cancelled, or the session, the tree, the
    /// target or the source is gone, with the status a new request would
    /// get.
    async fn checkpoint(&self, stop: &StopReceiver) -> Result<(), Halt> {
        if *stop.borrow() == Some(Stop::Cancelled) {
            return Err(Halt::Stopped(ntstatus::STATUS_CANCELLED));
        }
        let tree = lookup_tree(&self.conn, self.session_id, self.target.tree_id)
            .await
            .map_err(Halt::Stopped)?;
        if lookup_open(&tree, self.file_id).await.is_none() {
            return Err(Halt::Stopped(ntstatus::STATUS_FILE_CLOSED));
        }
        if find_source(&self.server, &self.conn, self.session_id, &self.key)
            .await
            .is_none()
        {
            return Err(Halt::Stopped(ntstatus::STATUS_OBJECT_NAME_NOT_FOUND));
        }
        Ok(())
    }

    /// The two sides of the copy between the opens in `guards`.
    fn ends<'a>(&'a self, guards: &'a Guards<'_>) -> Result<Ends<'a>, Halt> {
        guards.ends(&self.target.share).map_err(Halt::Stopped)
    }

    /// Waits for the connection's copy turn, which one copy holds at a time,
    /// to copy a piece, empty a target or flush one. A stop ends the wait, and
    /// a stop that leaves the copy running keeps its place in line.
    async fn take_turn(&self, stop: &mut StopReceiver) -> Result<SemaphorePermit<'_>, Halt> {
        let acquire = self.conn.copy_turn.acquire();
        tokio::pin!(acquire);
        let turn = loop {
            tokio::select! {
                biased;
                why = stopped(stop) => {
                    if why == Stop::Cancelled {
                        return Err(Halt::Stopped(ntstatus::STATUS_CANCELLED));
                    }
                    self.checkpoint(stop).await?;
                }
                turn = &mut acquire => {
                    break turn.expect("the copy turn is never closed");
                }
            }
        };
        self.checkpoint(stop).await?;
        Ok(turn)
    }

    /// Empties the target and returns what the source holds.
    async fn empty_target(&self, stop: &mut StopReceiver) -> Result<FileInfo, Halt> {
        let _turn = self.take_turn(stop).await?;
        let guards = Guards::take(&self.source.open, &self.target.open).await;
        let ends = self.ends(&guards)?;
        let info = ends.source.stat().await.map_err(|e| ends.halt(e))?;
        ends.breaking_leases(ends.target.truncate(0))
            .await
            .map_err(|e| ends.halt(e))?;
        guards.target().wrote.store(true, Ordering::Release);
        Ok(info)
    }

    /// Copies the first `size` bytes of `from` to the start of `to`, a
    /// piece at a time. A piece that fails halts the copy with the bytes
    /// copied by then.
    async fn copy_pieces(
        &self,
        stop: &mut StopReceiver,
        from: &Arc<RwLock<Open>>,
        to: &Arc<RwLock<Open>>,
        size: u64,
    ) -> Result<(), Halt> {
        let mut copied = 0;
        while copied < size {
            let _turn = self.take_turn(stop).await?;
            let guards = Guards::take(from, to).await;
            let ends = self.ends(&guards)?;
            let chunk = Chunk {
                source_offset: copied,
                target_offset: copied,
                length: (size - copied).min(PIECE) as u32,
            };
            let run = ends.copy_chunks(guards.target(), &[chunk]).await;
            copied += u64::from(run.written());
            if let Some(failure) = run.failure {
                return Err(Halt::Failed(failure.status, copied));
            }
        }
        Ok(())
    }

    /// Copies the first `size` bytes of `from` to the start of `to`, and
    /// flushes `to` when the target was opened for write-through. A piece
    /// that fails halts the copy with the bytes copied by then; a flush that
    /// fails, with `size`.
    async fn copy_data(
        &self,
        stop: &mut StopReceiver,
        from: &Arc<RwLock<Open>>,
        to: &Arc<RwLock<Open>>,
        size: u64,
    ) -> Result<(), Halt> {
        self.copy_pieces(stop, from, to, size).await?;
        if self.write_through {
            self.flush(stop, from, to)
                .await
                .map_err(|halt| halt.after(size))?;
        }
        Ok(())
    }

    /// Flushes the target open `to` of a copy from `from`.
    async fn flush(
        &self,
        stop: &mut StopReceiver,
        from: &Arc<RwLock<Open>>,
        to: &Arc<RwLock<Open>>,
    ) -> Result<(), Halt> {
        let _turn = self.take_turn(stop).await?;
        let guards = Guards::take(from, to).await;
        let ends = self.ends(&guards)?;
        ends.target.flush().await.map_err(|e| ends.halt(e))
    }

    /// Copies each named stream of the source to the target.
    async fn copy_streams(&self, stop: &mut StopReceiver) -> Result<(), Halt> {
        let streams = {
            let guards = Guards::take(&self.source.open, &self.target.open).await;
            let ends = self.ends(&guards)?;
            ends.source
                .streams()
                .await
                .map_err(|e| Halt::failed(reply_status(e.to_nt_status(), true)))?
        };
        for stream in streams {
            self.copy_stream(stop, &stream.name).await?;
        }
        Ok(())
    }

    /// Copies the stream `name` of the source to that of the target,
    /// creating it or overwriting it.
    async fn copy_stream(&self, stop: &mut StopReceiver, name: &StreamName) -> Result<(), Halt> {
        self.checkpoint(stop).await?;
        let source = self.open_stream(stop, &self.source, name, false).await?;
        let target = match self.open_stream(stop, &self.target, name, true).await {
            Ok(target) => target,
            Err(halt) => {
                self.close_stream(source).await;
                return Err(halt);
            }
        };
        let copied = match self.empty_stream(stop, &source.open, &target.open).await {
            Ok(()) => {
                self.copy_stream_data(stop, &source.open, &target.open)
                    .await
            }
            Err(halt) => Err(halt),
        };
        self.close_stream(target).await;
        self.close_stream(source).await;
        copied
    }

    /// Opens the stream `name` of the file `side` is open on, by the name
    /// that open has now, for reading, or for writing with `write` set,
    /// creating it when it is missing and keeping the data of one that
    /// exists. Fails when the path names a different file than the one
    /// `side` is open on.
    async fn open_stream(
        &self,
        stop: &mut StopReceiver,
        side: &Side,
        name: &StreamName,
        write: bool,
    ) -> Result<StreamOpen, Halt> {
        let path = side.open.read().await.path();
        let Some(path) = path else {
            self.checkpoint(stop).await?;
            return Err(Halt::Stopped(ntstatus::STATUS_FILE_CLOSED));
        };
        let stream = CopyStream {
            session_id: self.session_id,
            tree_id: side.tree_id,
            path,
            name: name.clone(),
            write,
        };
        let (file_id, open) = match open_copy_stream(&self.server, &self.conn, &stream, stop).await
        {
            Ok(opened) => opened,
            Err(status) => {
                self.checkpoint(stop).await?;
                return Err(Halt::failed(reply_status(status, true)));
            }
        };
        let opened = StreamOpen {
            tree_id: side.tree_id,
            file_id,
            open,
        };
        if !on_file_of(&side.open, &opened.open).await {
            self.close_stream(opened).await;
            return Err(Halt::failed(ntstatus::STATUS_OBJECT_NAME_NOT_FOUND));
        }
        Ok(opened)
    }

    /// Empties the stream open `to` of a copy from `from`, unless the open
    /// made the stream. A stream that existed is reported as changed when
    /// its open closes.
    async fn empty_stream(
        &self,
        stop: &mut StopReceiver,
        from: &Arc<RwLock<Open>>,
        to: &Arc<RwLock<Open>>,
    ) -> Result<(), Halt> {
        if to.read().await.created {
            return Ok(());
        }
        let _turn = self.take_turn(stop).await?;
        let guards = Guards::take(from, to).await;
        let ends = self.ends(&guards)?;
        ends.breaking_leases(ends.target.truncate(0))
            .await
            .map_err(|e| ends.halt(e))?;
        guards.target().resized.store(true, Ordering::Release);
        Ok(())
    }

    /// Closes a stream open, which reports what the copy changed in it.
    async fn close_stream(&self, stream: StreamOpen) {
        if let Ok(tree) = lookup_tree(&self.conn, self.session_id, stream.tree_id).await {
            discard_open(&tree, stream.file_id).await;
        }
    }

    /// Copies the data of the stream open as `from` to the one open as `to`.
    async fn copy_stream_data(
        &self,
        stop: &mut StopReceiver,
        from: &Arc<RwLock<Open>>,
        to: &Arc<RwLock<Open>>,
    ) -> Result<(), Halt> {
        let size = {
            let guards = Guards::take(from, to).await;
            let ends = self.ends(&guards)?;
            let info = ends.source.stat().await.map_err(|e| ends.halt(e))?;
            info.end_of_file
        };
        self.copy_data(stop, from, to, size).await
    }

    /// Sets the target's creation and last write time to the source's and
    /// fixes the write time on the open, so its close keeps it. The
    /// attributes stay the target's.
    async fn set_times(&self, info: &FileInfo) {
        let known = |time: u64| (time != 0).then_some(time);
        let times = FileTimes {
            creation_time: known(info.creation_time),
            last_write_time: known(info.last_write_time),
            ..FileTimes::default()
        };
        if times == FileTimes::default() {
            return;
        }
        let mut open = self.target.open.write().await;
        let Some(handle) = open.handle.as_ref() else {
            return;
        };
        if let Err(e) = handle.set_times(times).await {
            warn!(error = %e, path = %open.path().unwrap_or_default(), "times of a copied file not set");
            return;
        }
        if times.last_write_time.is_some() {
            open.fixed_times.last_write_time = times.last_write_time;
        }
    }
}

/// Whether the stream open `stream` is on the file the open `open` is on.
async fn on_file_of(open: &Arc<RwLock<Open>>, stream: &Arc<RwLock<Open>>) -> bool {
    let guards = Guards::take(open, stream).await;
    matches!(
        (guards.source().file.as_ref(), guards.target().file.as_ref()),
        (Some(file), Some(on)) if file.same_file_as(on)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_count_of_a_file_over_four_gib_saturates() {
        let response = reply(
            Fsctl::SRV_COPYCHUNK,
            FileId::default(),
            ntstatus::STATUS_SUCCESS,
            5 << 30,
        );
        let output = &response.body[response.body.len() - 12..];
        assert_eq!(output[..8], [0; 8]);
        assert_eq!(output[8..], u32::MAX.to_le_bytes());
    }
}
