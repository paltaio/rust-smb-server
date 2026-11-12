//! The jobs that need no local data: copying the base of a file to its key,
//! and storing new times and attributes on an object.

use std::sync::Arc;
use std::time::SystemTime;

use bytes::Bytes;
use tracing::warn;

use super::{CopyJob, Halt, Job, PartFuture, meta, outcome};
use crate::s3::client::CopyMetadata;
use crate::s3::error::S3Error;
use crate::s3::keys::slot;
use crate::s3::object::{ByteRange, ObjectHead, normalize_etag};
use crate::s3::payload::Payload;
use crate::s3::xml::CompletedPart;

/// The size of the parts a copy of an object of `len` bytes is made in, when
/// one request takes at most `limit` bytes: `limit`, or more when that would
/// take more than 10,000 parts.
pub(super) fn copy_part_size(len: u64, limit: u64) -> u64 {
    limit.max(len.div_ceil(10_000))
}

impl Job<'_> {
    /// The copy the entry needs.
    fn copy_job(&self) -> Result<CopyJob, Halt> {
        let state = self.entry().state();
        if state.detached {
            return Err(Halt::Gone);
        }
        let Some(base) = state.base.as_ref() else {
            return Err(Halt::Gone);
        };
        let mut metadata = base.head.metadata.clone();
        if let Some(own) = state.own {
            metadata
                .user
                .extend(meta::stored_metadata(own.times, own.attributes));
        }
        Ok(CopyJob {
            key: state.key.clone(),
            from: base.key.clone(),
            head: Arc::clone(&base.head),
            metadata,
            replace: state.own.is_some(),
            prior: state.prior.clone(),
            generation: state.generation,
        })
    }

    /// Copies the base of the file to its key, with the times and attributes
    /// it holds. A store that refuses to change the metadata of an object in
    /// place gets the object read and stored again.
    pub(super) async fn copy(&self) -> Result<(), Halt> {
        let job = self.copy_job()?;
        self.check()?;
        let existed = self.before_store(&job.key, false).await?;
        let stored = if job.head.size > self.shared.jobs.copy_limit() {
            self.copy_parts(&job, existed).await?
        } else {
            self.copy_whole(&job).await?
        };
        match stored {
            Some(head) => self.land(job.generation, job.key, head).await,
            None => Ok(()),
        }
    }

    fn copied(job: &CopyJob, etag: &str, modified: Option<SystemTime>) -> Arc<ObjectHead> {
        Arc::new(ObjectHead {
            size: job.head.size,
            etag: normalize_etag(etag),
            last_modified: modified.unwrap_or_else(SystemTime::now),
            metadata: job.metadata.clone(),
        })
    }

    /// The object the key and the base key both name, if names ignore case,
    /// they differ in case only, and the store holds them as one object.
    async fn folded(&self, job: &CopyJob) -> Result<Option<ObjectHead>, Halt> {
        let fold = self.shared.case_insensitive;
        if job.from == job.key || slot(&job.from, fold) != slot(&job.key, fold) {
            return Ok(None);
        }
        self.shared
            .one_object(&job.from, &job.key, self.stop())
            .await
            .map_err(|e| self.halt(e))
    }

    /// One CopyObject request. `None` when the change was dropped.
    async fn copy_whole(&self, job: &CopyJob) -> Result<Option<Arc<ObjectHead>>, Halt> {
        let folded = self.folded(job).await?;
        if let Some(head) = folded.as_ref().filter(|_| !job.replace) {
            return Ok(Some(Self::copied(
                job,
                &head.etag,
                Some(head.last_modified),
            )));
        }
        let from = if folded.is_some() {
            &job.key
        } else {
            &job.from
        };
        let how = if job.replace {
            CopyMetadata::Replace(&job.metadata)
        } else {
            CopyMetadata::Copy {
                storage_class: job.head.metadata.storage_class.as_deref(),
            }
        };
        let sent = self
            .shared
            .client
            .copy_object(from, &job.key, how, self.retry())
            .await;
        match sent {
            Ok(done) => Ok(Some(Self::copied(job, &done.etag, done.last_modified))),
            Err(e) if e.is_no_such_key() => Err(Halt::Conflict(e)),
            Err(e)
                if from == &job.key
                    && matches!(e.http_status(), Some(400 | 501))
                    && !self.stop().is_stopped() =>
            {
                self.rewrite(job).await
            }
            Err(e) => Err(self.halt(e)),
        }
    }

    /// Stores the object at its key again, read from the store, for a store
    /// that does not copy an object onto itself. An object larger than the
    /// part size is left as it is, with a note in the log.
    async fn rewrite(&self, job: &CopyJob) -> Result<Option<Arc<ObjectHead>>, Halt> {
        let size = job.head.size;
        if size > self.shared.jobs.part_size {
            warn!(
                path = %self.path,
                size,
                "the store does not change the metadata of an object in place and the object is too large to send again; the times and attributes were not stored"
            );
            let generation = job.generation;
            self.blocking(move |shared, entry| outcome::dropped(shared, entry, generation))
                .await?;
            return Ok(None);
        }
        let data = match ByteRange::new(0, size) {
            Err(_) => Bytes::new(),
            Ok(range) => {
                let etag = Some(job.head.etag.as_str()).filter(|etag| !etag.is_empty());
                let object = self
                    .shared
                    .client
                    .get_object(&job.key, range, etag, self.retry())
                    .await
                    .map_err(|e| {
                        if e.is_precondition_failed() || e.is_no_such_key() {
                            Halt::Conflict(e)
                        } else {
                            self.halt(e)
                        }
                    })?;
                if object.data.len() as u64 != size {
                    return Err(Halt::Conflict(S3Error::status(
                        412,
                        Some("PreconditionFailed"),
                        None,
                    )));
                }
                object.data
            }
        };
        let payload = if data.is_empty() {
            Payload::empty()
        } else {
            Payload::from(data)
        };
        let etag = self
            .shared
            .client
            .put_object(&job.key, payload, &job.metadata, self.retry())
            .await
            .map_err(|e| self.halt(e))?;
        Ok(Some(Self::copied(job, &etag, None)))
    }

    /// A multipart upload whose parts are copied from the base, for an object
    /// too large for one request.
    async fn copy_parts(
        &self,
        job: &CopyJob,
        existed: bool,
    ) -> Result<Option<Arc<ObjectHead>>, Halt> {
        let prior = self
            .prior_etag(&job.key, job.prior.clone(), existed)
            .await?;
        let size = copy_part_size(job.head.size, self.shared.jobs.copy_limit());
        let etag = self
            .multipart(
                &job.key,
                &job.metadata,
                job.head.size,
                size,
                prior.as_deref(),
                |id, number, range, retry| {
                    let range = ByteRange::new(range.start, range.end - range.start)?;
                    let (client, key, from, id) = (
                        self.shared.client.clone(),
                        job.key.clone(),
                        job.from.clone(),
                        id.to_owned(),
                    );
                    Ok(Box::pin(async move {
                        client
                            .upload_part_copy(&key, &id, number, &from, range, retry)
                            .await
                            .map(|done| CompletedPart {
                                number,
                                etag: done.etag,
                            })
                    }) as PartFuture)
                },
            )
            .await?;
        Ok(Some(Self::copied(job, &etag, None)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_copy_is_cut_into_parts_of_the_limit_or_into_at_most_10000() {
        assert_eq!(copy_part_size(12, 5), 5);
        assert_eq!(copy_part_size(10_000 * 7 + 1, 5), 8);
    }
}
