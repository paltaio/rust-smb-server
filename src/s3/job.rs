//! What a background job does for its entry: it brings the bucket to the
//! state the entry holds.
//!
//! A file with local data is filled where it still stands for bytes of its
//! base, hashed, and put in the bucket, in one request or in parts. A
//! directory gets its marker object. Everything that touches the disk runs on
//! a blocking thread, and nothing waits for the store while a lock is held.

use std::fs::File;
use std::io;
use std::ops::Range;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use bytes::{Bytes, BytesMut};
use tokio::task::{JoinError, JoinSet, spawn_blocking};
use tracing::{debug, error, warn};

use crate::error::{SmbError, SmbResult};

use super::backend::Shared;
use super::cache::Known;
use super::change;
use super::client::MAX_DELETE_KEYS;
use super::entry::{Body, Entry};
use super::error::S3Error;
use super::jobs::Running;
use super::keys::{FileStamp, RowKind};
use super::meta;
use super::object::{ByteRange, Metadata, ObjectHead};
use super::outcome;
use super::parts::{hash_range, part_size_for, parts};
use super::payload::Payload;
use super::read::same_version;
use super::retry::{Retry, Stop};
use super::xml::CompletedPart;

/// The content type of a file that was never in the bucket.
const NEW_FILE_TYPE: &str = "application/octet-stream";

/// The least an entry rests after a job met a full disk, whatever the upload
/// delay is.
const FULL_DISK_REST: Duration = Duration::from_secs(1);

/// Why a job ended before it stored what its entry holds.
#[derive(Debug)]
enum Halt {
    /// A change to the entry, or the end of the backend, stopped it.
    Stopped,
    /// The entry left the overlay.
    Gone,
    /// The bytes under the job changed or are not all there: the entry gets
    /// a job again after it has rested.
    Again,
    /// The disk of the cache directory is full: the entry gets a job again
    /// after it has rested for the upload delay, and at least
    /// [`FULL_DISK_REST`].
    Full,
    /// The object the entry starts from changed in the bucket, or is gone.
    Conflict(S3Error),
    /// The job failed for good.
    Failed(S3Error),
}

/// How a job ends for an error of the store, given whether it was stopped.
fn classify(error: S3Error, stopped: bool) -> Halt {
    if error.is_stopped() || (stopped && matches!(error, S3Error::SourceRead(_))) {
        Halt::Stopped
    } else if error.is_source_changed() {
        Halt::Again
    } else {
        Halt::Failed(error)
    }
}

/// The bytes a file holds when a job takes stock, and where they go.
struct Snapshot {
    key: String,
    generation: u64,
    file: Arc<File>,
    len: u64,
    /// The metadata every request that stores the object sends.
    metadata: Metadata,
    /// The ETag the key had before, if the entry knows it.
    replaced: Option<String>,
}

/// A piece of the file to fetch from the base.
struct Want {
    range: Range<u64>,
    base: Option<(String, Arc<ObjectHead>)>,
}

struct Job<'a> {
    shared: &'a Arc<Shared>,
    run: &'a Running,
    /// The path of the entry, for the log.
    path: String,
}

/// Runs the job of `running`, to its end.
pub(super) async fn run(shared: Arc<Shared>, running: Running) {
    let job = Job {
        path: running.entry.state().path(&shared.prefix),
        shared: &shared,
        run: &running,
    };
    let result = if running.entry.is_dir() {
        job.directory().await
    } else {
        job.file().await
    };
    match result {
        Ok(()) => debug!(path = %job.path, "the entry is in the bucket"),
        Err(halt) => job.end(halt).await,
    }
}

impl Job<'_> {
    fn entry(&self) -> &Arc<Entry> {
        &self.run.entry
    }

    fn stop(&self) -> &Stop {
        &self.run.stop
    }

    /// Retries until the job is stopped.
    fn retry(&self) -> Retry {
        Retry::until(self.stop())
    }

    fn halt(&self, error: S3Error) -> Halt {
        classify(error, self.stop().is_stopped())
    }

    /// The end of a job that failed on the disk.
    fn local(&self, error: SmbError) -> Halt {
        if self.entry().state().detached {
            return Halt::Gone;
        }
        let error = match error {
            SmbError::DiskFull => return Halt::Full,
            SmbError::Io(error) => error,
            other => io::Error::other(other.to_string()),
        };
        Halt::Failed(S3Error::Cache(Arc::new(error)))
    }

    /// Fails if the job was stopped, which every change to the entry does, or
    /// the entry left the overlay. No request begins after that.
    fn check(&self) -> Result<(), Halt> {
        if self.entry().state().detached {
            return Err(Halt::Gone);
        }
        if self.stop().is_stopped() {
            return Err(Halt::Stopped);
        }
        Ok(())
    }

    /// Runs `work` on a blocking thread.
    async fn blocking<T: Send + 'static>(
        &self,
        work: impl FnOnce(&Shared, &Arc<Entry>) -> SmbResult<T> + Send + 'static,
    ) -> Result<T, Halt> {
        let (shared, entry) = (Arc::clone(self.shared), Arc::clone(self.entry()));
        match spawn_blocking(move || work(&shared, &entry)).await {
            Ok(done) => done.map_err(|e| self.local(e)),
            Err(e) => Err(self.local(SmbError::Io(io::Error::other(e)))),
        }
    }

    async fn end(&self, halt: Halt) {
        match halt {
            Halt::Stopped => debug!(path = %self.path, "the job was stopped"),
            Halt::Gone => debug!(path = %self.path, "the entry left the overlay during its job"),
            Halt::Again => {
                debug!(path = %self.path, "the bytes changed under the job");
                // The entry rests again before its next job.
                self.entry().state().changed = Instant::now();
            }
            Halt::Full => {
                warn!(
                    path = %self.path,
                    "the disk of the cache directory is full; the upload is tried again after the file has rested"
                );
                let now = Instant::now();
                let mut state = self.entry().state();
                state.changed = now;
                state.rest_until = Some(now + FULL_DISK_REST);
            }
            Halt::Conflict(error) => self.conflict(error).await,
            Halt::Failed(error) => self.fail(error).await,
        }
    }

    /// The object the entry starts from changed in the bucket: what the
    /// entry holds moves to the conflicts directory. If that fails, the entry
    /// stays and the job fails for good.
    async fn conflict(&self, error: S3Error) {
        let (key, base) = {
            let state = self.entry().state();
            (
                state.key.clone(),
                state.base.as_ref().map(|base| base.key.clone()),
            )
        };
        let (status, code) = (error.http_status(), error.code().map(str::to_owned));
        let moved = self
            .blocking(move |shared, entry| outcome::conflict(shared, entry, error))
            .await;
        let code = code.as_deref();
        self.shared.forget_file(&key);
        if let Some(base) = base.filter(|base| *base != key) {
            self.shared.forget_file(&base);
        }
        match moved {
            Ok(_) => error!(
                path = %self.path,
                status,
                code,
                "the object changed or was deleted in the bucket while the file held changes of its own; \
                 the changes were moved to the conflicts directory"
            ),
            Err(halt) => {
                error!(
                    path = %self.path,
                    status,
                    code,
                    "the object changed or was deleted in the bucket while the file held changes of its own, \
                     and the changes could not be moved to the conflicts directory"
                );
                if let Halt::Failed(failure) = halt {
                    self.fail(failure).await;
                }
            }
        }
    }

    /// The job failed for good: the entry is marked, in its record too, and
    /// keeps what it holds.
    async fn fail(&self, failure: S3Error) {
        error!(
            path = %self.path,
            status = failure.http_status(),
            code = failure.code(),
            request_id = failure.request_id(),
            error = %failure,
            "a change could not be stored in the bucket, and is tried again when the next backend is built"
        );
        let marked = self
            .blocking(move |shared, entry| outcome::failed(shared, entry, failure))
            .await;
        if marked.is_err() {
            warn!(path = %self.path, "the record of a failed upload could not be written");
        }
    }

    async fn file(&self) -> Result<(), Halt> {
        self.abort_stale().await;
        self.blocking(|shared, entry| change::seal(shared, entry, false))
            .await?;
        let filled = self.fill().await?;
        let snapshot = self.snapshot()?;
        self.check()?;
        let jobs = &self.shared.jobs;
        let part_size =
            (snapshot.len > jobs.part_size).then(|| part_size_for(snapshot.len, jobs.part_size));
        let hashes = self.hash(&snapshot, part_size).await?;
        #[cfg(test)]
        self.pause(&self.shared.jobs.pause).await;
        self.check()?;
        self.blocking(move |shared, entry| outcome::before_store(shared, entry, filled))
            .await?;
        let etag = match part_size {
            None => self.put(&snapshot, &hashes[0]).await?,
            Some(size) => self.multipart(&snapshot, size, &hashes).await?,
        };
        #[cfg(test)]
        {
            self.pause(&self.shared.jobs.pause_stored).await;
            if self.shared.jobs.stop.is_stopped() {
                return Err(Halt::Stopped);
            }
        }
        let head = Arc::new(ObjectHead {
            size: snapshot.len,
            etag,
            last_modified: SystemTime::now(),
            metadata: snapshot.metadata.clone(),
        });
        self.remember(&snapshot.key, &head);
        let deleted = self.delete_gone().await?;
        let Snapshot {
            key,
            generation,
            file,
            ..
        } = snapshot;
        drop(file);
        self.blocking(move |shared, entry| {
            outcome::landed(shared, entry, generation, &key, head, &deleted)
        })
        .await
    }

    /// Aborts a multipart upload an earlier backend left running.
    async fn abort_stale(&self) {
        let stale = {
            let state = self.entry().state();
            match &state.body {
                Body::File {
                    upload_id: Some(id),
                    ..
                } => Some((state.key.clone(), id.clone())),
                _ => None,
            }
        };
        if let Some((key, id)) = stale {
            self.abort(&key, &id).await;
        }
    }

    /// Fills in the bytes the file still stands for from its base, a chunk at
    /// a time. A byte written after a request for it began stays as it was
    /// written, and no lock is held while the request runs. Returns whether
    /// the file holds more bytes than before.
    async fn fill(&self) -> Result<bool, Halt> {
        let mut from = 0;
        let mut filled = false;
        loop {
            self.check()?;
            let Some(want) = self.missing(from)? else {
                return Ok(filled);
            };
            from = want.range.end;
            let data = self.fetch(&want).await?;
            let range = want.range;
            filled |= self
                .blocking(move |shared, entry| outcome::fill(shared, entry, &range, data.as_ref()))
                .await?;
        }
    }

    /// The next chunk at or after `from` that the file does not hold, with
    /// the base it comes from.
    fn missing(&self, from: u64) -> Result<Option<Want>, Halt> {
        let state = self.entry().state();
        if state.detached {
            return Err(Halt::Gone);
        }
        let Some(local) = state.local() else {
            return Err(Halt::Gone);
        };
        if from >= local.len {
            return Ok(None);
        }
        let next = local
            .present
            .segments(from..local.len)
            .into_iter()
            .find(|(_, present)| !present);
        Ok(next.map(|(range, _)| Want {
            range: range.start..range.end.min(range.start + self.shared.read_chunk),
            base: state
                .base
                .as_ref()
                .map(|base| (base.key.clone(), Arc::clone(&base.head))),
        }))
    }

    /// The bytes of the base under `want`, with zeros where the base ends
    /// before the chunk does. `None` where the chunk lies past the end of the
    /// base, or the entry has no base.
    async fn fetch(&self, want: &Want) -> Result<Option<Bytes>, Halt> {
        let Some((key, head)) = &want.base else {
            return Ok(None);
        };
        let end = want.range.end.min(head.size);
        if want.range.start >= end {
            return Ok(None);
        }
        let range =
            ByteRange::new(want.range.start, end - want.range.start).map_err(Halt::Failed)?;
        let etag = Some(head.etag.as_str()).filter(|etag| !etag.is_empty());
        let object = match self
            .shared
            .client
            .get_object(key, range, etag, self.retry())
            .await
        {
            Ok(object) => object,
            Err(e) if e.is_precondition_failed() || e.is_no_such_key() => {
                return Err(Halt::Conflict(e));
            }
            Err(e) => return Err(self.halt(e)),
        };
        let whole = object.data.len() as u64 == range.len();
        if !whole || (etag.is_none() && !same_version(&object.head, head)) {
            return Err(Halt::Conflict(S3Error::status(
                412,
                Some("PreconditionFailed"),
                None,
            )));
        }
        let missing = (want.range.end - end) as usize;
        if missing == 0 {
            return Ok(Some(object.data));
        }
        let mut padded = BytesMut::with_capacity(object.data.len() + missing);
        padded.extend_from_slice(&object.data);
        padded.resize(object.data.len() + missing, 0);
        Ok(Some(padded.freeze()))
    }

    /// Takes stock of the file. Called once nothing is missing, which stays
    /// so: writes and truncates only add bytes.
    fn snapshot(&self) -> Result<Snapshot, Halt> {
        let state = self.entry().state();
        if state.detached {
            return Err(Halt::Gone);
        }
        let Some(local) = state.local() else {
            return Err(Halt::Gone);
        };
        if local
            .present
            .segments(0..local.len)
            .iter()
            .any(|(_, present)| !present)
        {
            return Err(Halt::Again);
        }
        let own = state.own_or_base(self.shared.built);
        let mut metadata = state.base.as_ref().map_or_else(
            || Metadata {
                content_type: Some(NEW_FILE_TYPE.to_owned()),
                ..Metadata::default()
            },
            |base| base.head.metadata.clone(),
        );
        metadata
            .user
            .extend(meta::stored_metadata(own.times, own.attributes));
        let replaced = state
            .base
            .as_ref()
            .filter(|base| base.key == state.key && !base.head.etag.is_empty())
            .map(|base| base.head.etag.clone());
        Ok(Snapshot {
            key: state.key.clone(),
            generation: state.generation,
            file: Arc::clone(&local.file),
            len: local.len,
            metadata,
            replaced,
        })
    }

    /// Waits here if a test put up `gates` for the job.
    #[cfg(test)]
    async fn pause(&self, gates: &std::sync::Mutex<Option<super::jobs::Gates>>) {
        let gates = gates
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        if let Some((reached, resume)) = gates {
            reached.notify_one();
            resume.notified().await;
        }
    }

    /// The hash of each part, or of the whole file for one request. The file
    /// is read in pieces of bounded size.
    async fn hash(&self, snapshot: &Snapshot, part_size: Option<u64>) -> Result<Vec<String>, Halt> {
        let ranges: Vec<Range<u64>> = match part_size {
            None => std::iter::once(0..snapshot.len).collect(),
            Some(size) => parts(snapshot.len, size).map(|(_, range)| range).collect(),
        };
        let mut hashes = Vec::with_capacity(ranges.len());
        for range in ranges {
            let hash = hash_range(Arc::clone(&snapshot.file), range, self.stop().clone())
                .await
                .map_err(|e| self.halt(e))?;
            hashes.push(hash);
        }
        Ok(hashes)
    }

    /// Stores the file with one request. Returns the ETag of the object.
    async fn put(&self, snapshot: &Snapshot, hash: &str) -> Result<String, Halt> {
        let payload = if snapshot.len == 0 {
            Payload::empty()
        } else {
            Payload::file(Arc::clone(&snapshot.file), 0, snapshot.len, hash)
                .map_err(|e| self.halt(e))?
        };
        self.shared
            .client
            .put_object(&snapshot.key, payload, &snapshot.metadata, self.retry())
            .await
            .map_err(|e| self.halt(e))
    }

    /// Stores the file as a multipart upload of parts of `part_size`. The
    /// upload id is in the record of the entry before the first part goes
    /// up, and a failed or stopped upload is aborted. Returns the ETag of the
    /// object.
    async fn multipart(
        &self,
        snapshot: &Snapshot,
        part_size: u64,
        hashes: &[String],
    ) -> Result<String, Halt> {
        let client = &self.shared.client;
        let id = client
            .create_multipart_upload(&snapshot.key, &snapshot.metadata, self.retry())
            .await
            .map_err(|e| self.halt(e))?;
        let noted = id.clone();
        let sent = match self
            .blocking(move |shared, entry| outcome::upload_id(shared, entry, Some(noted)))
            .await
        {
            Ok(()) => self.send_parts(snapshot, &id, part_size, hashes).await,
            Err(halt) => Err(halt),
        };
        let done = match sent {
            Ok(parts) => client
                .complete_multipart_upload(
                    &snapshot.key,
                    &id,
                    &parts,
                    snapshot.len,
                    snapshot.replaced.as_deref(),
                    self.retry(),
                )
                .await
                .map_err(|e| self.halt(e)),
            Err(halt) => Err(halt),
        };
        if done.is_err() {
            self.abort(&snapshot.key, &id).await;
        }
        done
    }

    /// Sends the parts, up to the upload concurrency of them at once. After
    /// the first failure or stop no part starts, and the ones in flight
    /// finish.
    async fn send_parts(
        &self,
        snapshot: &Snapshot,
        id: &str,
        part_size: u64,
        hashes: &[String],
    ) -> Result<Vec<CompletedPart>, Halt> {
        let concurrency = self.shared.jobs.concurrency;
        let mut sending: JoinSet<Result<CompletedPart, S3Error>> = JoinSet::new();
        let mut sent = Vec::new();
        let mut failure = None;
        for (number, range) in parts(snapshot.len, part_size) {
            while sending.len() >= concurrency {
                if let Some(joined) = sending.join_next().await {
                    note(joined, &mut sent, &mut failure);
                }
            }
            if failure.is_some() || self.stop().is_stopped() {
                break;
            }
            let hash = &hashes[(number - 1) as usize];
            let payload = match Payload::file(
                Arc::clone(&snapshot.file),
                range.start,
                range.end - range.start,
                hash,
            ) {
                Ok(payload) => payload,
                Err(e) => {
                    failure = Some(e);
                    break;
                }
            };
            let (client, key, id, retry) = (
                self.shared.client.clone(),
                snapshot.key.clone(),
                id.to_owned(),
                self.retry(),
            );
            sending.spawn(async move {
                client
                    .upload_part(&key, &id, number, payload, retry)
                    .await
                    .map(|etag| CompletedPart { number, etag })
            });
        }
        while let Some(joined) = sending.join_next().await {
            note(joined, &mut sent, &mut failure);
        }
        if let Some(failure) = failure {
            return Err(self.halt(failure));
        }
        if sent.len() as u64 != snapshot.len.div_ceil(part_size) {
            return Err(Halt::Stopped);
        }
        sent.sort_by_key(|part| part.number);
        Ok(sent)
    }

    /// Aborts the multipart upload `id` of `key`. The abort is not tied to the
    /// stop of the job: it tries until the store takes it or the backend
    /// ends, which leaves the id in the record of the entry for the next
    /// backend.
    async fn abort(&self, key: &str, id: &str) {
        let retry = Retry::until(&self.shared.jobs.stop);
        match self
            .shared
            .client
            .abort_multipart_upload(key, id, retry)
            .await
        {
            Ok(()) => {
                let cleared = self
                    .blocking(|shared, entry| outcome::upload_id(shared, entry, None))
                    .await;
                if cleared.is_err() {
                    warn!(path = %self.path, "the record of an aborted upload could not be written");
                }
            }
            Err(e) if e.is_stopped() => {}
            Err(e) => warn!(
                path = %self.path,
                error = %e,
                "a multipart upload could not be aborted"
            ),
        }
    }

    /// Deletes the keys in `gone`, now that the entry's content is stored.
    /// Returns them.
    async fn delete_gone(&self) -> Result<Vec<String>, Halt> {
        let gone = self.entry().state().gone.clone();
        for keys in gone.chunks(MAX_DELETE_KEYS) {
            let failed = self
                .shared
                .client
                .delete_objects(keys, self.retry())
                .await
                .map_err(|e| self.halt(e))?;
            if let Some(first) = failed.first() {
                return Err(Halt::Failed(S3Error::status(
                    200,
                    first.code.as_deref(),
                    None,
                )));
            }
        }
        Ok(gone)
    }

    /// Makes what the metadata cache holds for `key` the object `head`, and
    /// adds the file to the cached listing of its directory.
    fn remember(&self, key: &str, head: &Arc<ObjectHead>) {
        let stamp = FileStamp {
            size: head.size,
            etag: head.etag.clone(),
            last_modified: head.last_modified,
        };
        self.shared
            .remember(key, Known::File(Arc::clone(head)), RowKind::File(stamp));
    }

    /// Puts the marker object of a directory, with the times and attributes
    /// the entry holds.
    async fn directory(&self) -> Result<(), Halt> {
        let (key, generation, metadata) = {
            let state = self.entry().state();
            if state.detached {
                return Err(Halt::Gone);
            }
            let own = state.own_or_base(self.shared.built);
            (
                state.key.clone(),
                state.generation,
                meta::marker_metadata(own.times, own.attributes),
            )
        };
        self.check()?;
        let head = change::store_marker(self.shared, &key, metadata, self.retry())
            .await
            .map_err(|e| self.halt(e))?;
        change::marker_put(self.shared, self.run.held(), generation, &key, head)
            .await
            .map_err(|e| self.local(e))?;
        let mut state = self.entry().state();
        state.uploaded = generation;
        Ok(())
    }
}

/// Takes in the end of a part.
fn note(
    joined: Result<Result<CompletedPart, S3Error>, JoinError>,
    sent: &mut Vec<CompletedPart>,
    failure: &mut Option<S3Error>,
) {
    match joined {
        Ok(Ok(part)) => sent.push(part),
        Ok(Err(e)) => {
            failure.get_or_insert(e);
        }
        Err(e) => {
            failure.get_or_insert(S3Error::transport(e));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn status(status: u16, code: &str) -> S3Error {
        S3Error::status(status, Some(code), None)
    }

    #[test]
    fn a_stop_and_a_source_that_changed_are_not_failures() {
        assert!(matches!(classify(S3Error::Stopped, false), Halt::Stopped));
        assert!(matches!(
            classify(S3Error::SourceChanged, false),
            Halt::Again
        ));
    }

    #[test]
    fn a_failed_read_of_the_file_is_a_failure_unless_the_job_was_stopped() {
        let read = || S3Error::SourceRead(Arc::new(io::Error::other("read")));
        assert!(matches!(classify(read(), false), Halt::Failed(_)));
        assert!(matches!(classify(read(), true), Halt::Stopped));
    }

    #[test]
    fn what_the_store_refuses_for_good_is_a_failure_stopped_or_not() {
        for error in [
            status(403, "AccessDenied"),
            status(400, "EntityTooLarge"),
            status(404, "NoSuchBucket"),
            S3Error::InvalidResponse("bad"),
        ] {
            for stopped in [false, true] {
                assert!(
                    matches!(classify(error.clone(), stopped), Halt::Failed(_)),
                    "{error:?}, stopped {stopped}"
                );
            }
        }
    }
}
