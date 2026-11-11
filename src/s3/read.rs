//! Reads of file data.

use std::io;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use bytes::Bytes;
use tokio::sync::oneshot;
use tokio::time::timeout_at;
use tracing::debug;

use crate::backend::FileInfo;
use crate::error::{SmbError, SmbResult};

use super::backend::Shared;
use super::error::S3Error;
use super::lookup::FileRef;
use super::meta;
use super::object::{ByteRange, ObjectHead};
use super::readahead::{Claim, Outcome, Pin, ReadAhead, Version, assemble, extent, span};
use super::retry::Retry;

/// A file as opened: its key, and the object its reads go to.
pub(super) struct OpenFile {
    key: String,
    name: String,
    current: Mutex<Current>,
}

struct Current {
    /// The object as opened, or as a read found it after it changed.
    head: Arc<ObjectHead>,
    /// The pin that keeps the chunks of `head`, if it has an ETag.
    pin: Option<Pin>,
}

impl OpenFile {
    pub(super) fn new(ahead: &Arc<ReadAhead>, file: FileRef) -> Self {
        let pin = Version::of(&file.key, &file.head).map(|version| ahead.pin(version));
        OpenFile {
            key: file.key,
            name: file.name,
            current: Mutex::new(Current {
                head: file.head,
                pin,
            }),
        }
    }

    fn current(&self) -> MutexGuard<'_, Current> {
        self.current.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn head(&self) -> Arc<ObjectHead> {
        Arc::clone(&self.current().head)
    }

    /// Reads from `head` from now on.
    fn set_head(&self, ahead: &Arc<ReadAhead>, head: Arc<ObjectHead>) {
        let mut current = self.current();
        // The new pin is taken before the old one ends, so a version that
        // stays is never unpinned and the chunks other reads have in flight
        // for it are still kept.
        current.pin = Version::of(&self.key, &head).map(|version| ahead.pin(version));
        current.head = head;
    }

    pub(super) fn info(&self) -> FileInfo {
        meta::file_info(&self.name, &self.head())
    }

    /// Reads up to `len` bytes at `offset`. A read of an object with an ETag
    /// that finds the object changed or gone drops the chunks kept of it, asks
    /// the store for the object as it is, and reads again from that, once.
    pub(super) async fn read(&self, shared: &Shared, offset: u64, len: u32) -> SmbResult<Bytes> {
        let retry = shared.retry();
        let mut refreshed = false;
        loop {
            let head = self.head();
            let Some(version) = Version::of(&self.key, &head) else {
                return shared
                    .read_unversioned(&self.key, &head, offset, len, &retry)
                    .await;
            };
            let error = match shared.read_chunked(&version, offset, len, &retry).await {
                Ok(data) => return Ok(data),
                Err(error) => error,
            };
            if !is_changed(&error) {
                return Err(error.into_smb_error());
            }
            shared.ahead.drop_version(&version);
            if refreshed {
                shared.forget_file(&self.key);
                return Err(error.into_smb_error());
            }
            debug!("an object changed after it was opened");
            let head = shared
                .refresh(&self.key, &retry)
                .await
                .map_err(S3Error::into_smb_error)?;
            self.set_head(&shared.ahead, head);
            refreshed = true;
        }
    }
}

/// Whether `error` says the object is not the version that was read: another
/// ETag, or no object.
fn is_changed(error: &S3Error) -> bool {
    error.is_precondition_failed() || error.is_no_such_key()
}

/// The error for an answer that is not about the version asked for.
fn changed() -> S3Error {
    S3Error::status(412, Some("PreconditionFailed"), None)
}

impl Shared {
    /// The bytes `offset..offset + len` of the object at `version`, as far as
    /// it reaches. They come from its chunks. Each chunk not kept is requested
    /// with an `If-Match` for the ETag, and an object with another one fails
    /// the read as a failed precondition.
    async fn read_chunked(
        &self,
        version: &Version,
        offset: u64,
        len: u32,
        retry: &Retry,
    ) -> Result<Bytes, S3Error> {
        let size = version.size;
        if len == 0 || offset >= size {
            return Ok(Bytes::new());
        }
        let end = offset.saturating_add(u64::from(len)).min(size);
        let mut parts = Vec::new();
        for index in span(self.read_chunk, offset, end) {
            parts.push(self.chunk(version, index, retry).await?);
        }
        Ok(assemble(self.read_chunk, offset, end, &parts))
    }

    /// The chunk `index` of the object at `version`: kept, brought by another
    /// reader, or requested.
    async fn chunk(&self, version: &Version, index: u64, retry: &Retry) -> Result<Bytes, S3Error> {
        let (start, len) = extent(self.read_chunk, index, version.size);
        loop {
            match self.ahead.claim(version, index) {
                Claim::Held(data) => return Ok(data),
                Claim::Wait(done) => {
                    if let Some(outcome) = wait(done, retry).await? {
                        return outcome;
                    }
                }
                Claim::Fetch(fetch) => {
                    let outcome = self.fetch(version, start, len, retry).await;
                    fetch.finish(outcome.clone());
                    return outcome;
                }
            }
        }
    }

    async fn fetch(&self, version: &Version, start: u64, len: u64, retry: &Retry) -> Outcome {
        let range = ByteRange::new(start, len)?;
        let object = self
            .client
            .get_object(&version.key, range, Some(&version.etag), retry.clone())
            .await?;
        if object.data.len() as u64 != len {
            return Err(changed());
        }
        Ok(object.data)
    }

    /// Up to `len` bytes at `offset` of an object without an ETag, which
    /// `head` describes. Nothing ties a read to a version of such an object,
    /// and no chunk is kept: the bytes are requested as asked for, and a read
    /// fails if the answer has another size or modification time, or an ETag.
    async fn read_unversioned(
        &self,
        key: &str,
        head: &ObjectHead,
        offset: u64,
        len: u32,
        retry: &Retry,
    ) -> SmbResult<Bytes> {
        if len == 0 || offset >= head.size {
            return Ok(Bytes::new());
        }
        let range = ByteRange::new(offset, u64::from(len).min(head.size - offset))
            .map_err(S3Error::into_smb_error)?;
        match self
            .client
            .get_object(key, range, None, retry.clone())
            .await
        {
            Ok(object) if same_version(&object.head, head) => Ok(object.data),
            Ok(_) => {
                debug!("an object without an ETag changed after it was opened");
                self.forget_file(key);
                Err(SmbError::Io(io::Error::other(
                    "the object changed after it was opened",
                )))
            }
            Err(e) => {
                if is_changed(&e) {
                    self.forget_file(key);
                }
                Err(e.into_smb_error())
            }
        }
    }

    /// Asks the store for the object at `key`, which a read found changed,
    /// and drops what is cached of it and of its directory. The next lookup
    /// of the name resolves it again, which also looks for a directory.
    async fn refresh(&self, key: &str, retry: &Retry) -> Result<Arc<ObjectHead>, S3Error> {
        self.forget_file(key);
        self.client
            .head_object(key, retry.clone())
            .await
            .map(Arc::new)
    }
}

/// The outcome of the fetch another reader makes, or `None` if that reader
/// gave up, ran out of time, or failed in a way trying again can fix. Fails
/// when `retry` runs out of time first.
async fn wait(done: oneshot::Receiver<Outcome>, retry: &Retry) -> Result<Option<Outcome>, S3Error> {
    let outcome = match retry.deadline() {
        Some(deadline) => timeout_at(deadline, done)
            .await
            .map_err(|_| S3Error::DeadlineExceeded)?,
        None => done.await,
    };
    Ok(outcome.ok())
}

/// Whether the object a GET returned is the one that was opened, going by its
/// size, modification time and ETag.
fn same_version(got: &ObjectHead, opened: &ObjectHead) -> bool {
    got.size == opened.size && got.last_modified == opened.last_modified && got.etag == opened.etag
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    #[tokio::test(start_paused = true)]
    async fn a_waiter_stops_at_its_own_deadline() {
        let (_fetcher, done) = oneshot::channel::<Outcome>();
        let retry = Retry::within(Duration::from_secs(5));
        let started = tokio::time::Instant::now();
        let outcome = wait(done, &retry).await;
        assert!(matches!(outcome, Err(S3Error::DeadlineExceeded)));
        assert_eq!(started.elapsed(), Duration::from_secs(5));
    }

    #[tokio::test(start_paused = true)]
    async fn a_waiter_gets_the_outcome_or_learns_the_fetcher_gave_up() {
        let retry = Retry::within(Duration::from_secs(5));
        let (fetcher, done) = oneshot::channel::<Outcome>();
        let _ = fetcher.send(Ok(Bytes::from_static(b"abc")));
        assert_eq!(wait(done, &retry).await.unwrap().unwrap().unwrap(), "abc");
        let (fetcher, done) = oneshot::channel::<Outcome>();
        drop(fetcher);
        assert!(wait(done, &retry).await.unwrap().is_none());
    }
}
