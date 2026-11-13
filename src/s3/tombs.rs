//! Deleting keys from the bucket: the keys no entry owns, which the worker
//! deletes in batches, and the requests the jobs of entries use for the keys
//! their entries own.

use std::io;
use std::sync::Arc;

use tokio::task::spawn_blocking;
use tokio::time::sleep;
use tracing::{debug, error, warn};

use super::backend::Shared;
use super::cache::Known;
use super::change;
use super::client::{ListRequest, MAX_DELETE_KEYS, MAX_LISTED};
use super::error::S3Error;
use super::keys::{dir_prefix, join_key};
use super::meta;
use super::object::ObjectHead;
use super::overlay::Deleting;
use super::retry::{BASE_DELAY, Retry, Stop};

/// The most pages of a directory listing that the comparison of two keys reads.
const MAX_LIST_PAGES: usize = 100;

/// What a run of DeleteObjects requests did.
#[derive(Default)]
pub(super) struct Deleted {
    /// The keys the bucket no longer holds as objects to delete: deleted,
    /// gone already, or the object of another spelling that stays.
    pub(super) deleted: Vec<String>,
    /// The keys the store refused to delete, with why.
    pub(super) failed: Vec<(String, S3Error)>,
    /// The backend ended before the requests did.
    pub(super) stopped: bool,
}

/// Why the keys of a claim could not be deleted: the store refused a request
/// made before the deletes.
pub(super) struct Refused {
    pub(super) error: S3Error,
    /// What was to be done, for the log.
    pub(super) what: &'static str,
}

/// The directories above `keys` that are below the share root with key
/// `prefix`, each once, outermost first.
pub(super) fn ancestors(prefix: &str, keys: &[String]) -> Vec<String> {
    let root = dir_prefix(prefix);
    let mut dirs: Vec<String> = Vec::new();
    for key in keys {
        let Some(path) = key.strip_prefix(&root) else {
            continue;
        };
        let mut names: Vec<&str> = path.trim_end_matches('/').split('/').collect();
        names.pop();
        let mut dir = prefix.to_owned();
        for name in names {
            dir = join_key(&dir, name);
            if !dirs.contains(&dir) {
                dirs.push(dir.clone());
            }
        }
    }
    dirs.sort();
    dirs
}

/// Whether the directory `dir` needs a marker once its keys to delete are
/// gone: the keys `listed` below it, which are the first ones the store has
/// there, hold no marker and nothing that `stays`.
pub(super) fn needs_marker(dir: &str, listed: &[String], stays: impl Fn(&str) -> bool) -> bool {
    let marker = dir_prefix(dir);
    !listed.iter().any(|key| *key == marker || stays(key))
}

/// Whether `error` says the store keeps the directory `key` for the objects
/// in it, which is all a marker key can name there: no marker object is left
/// to delete.
fn is_marker_kept(key: &str, error: &S3Error) -> bool {
    key.ends_with('/') && error.code() == Some("ErrDirectoryNotEmpty")
}

/// Whether the store refuses a marker for good where an object of the same
/// name is: the directory is left as it is.
fn is_marker_conflict(error: &S3Error) -> bool {
    matches!(
        error.code(),
        Some("ObjectParentIsFile" | "ExistingObjectIsDirectory")
    )
}

impl Shared {
    /// The object at `key`, or `None` if there is none.
    async fn head_if_there(&self, key: &str, stop: &Stop) -> Result<Option<ObjectHead>, S3Error> {
        match self.client.head_object(key, Retry::until(stop)).await {
            Ok(head) => Ok(Some(head)),
            Err(e) if e.is_no_such_key() => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Whether the store lists the object `key` under that spelling.
    async fn lists(&self, key: &str, stop: &Stop) -> Result<bool, S3Error> {
        let request = ListRequest {
            prefix: key,
            delimited: false,
            continuation_token: None,
            max_keys: Some(1),
        };
        let page = self
            .client
            .list_objects(&request, Retry::until(stop))
            .await?;
        Ok(page.objects.first().is_some_and(|object| object.key == key))
    }

    /// Whether the store lists the keys `a` and `b`, which differ in case
    /// only, as two objects. When the last name differs, each key is looked
    /// up in a listing. When a directory above it differs, a store that
    /// ignores case answers a listing under either spelling of the directory
    /// with the spelling asked for, so the directory above the first
    /// difference is listed instead: a store that tells the two apart lists
    /// both spellings there. A directory too large to list in full counts as
    /// one object, which keeps both keys.
    async fn listed_apart(&self, a: &str, b: &str, stop: &Stop) -> Result<bool, S3Error> {
        let (names_a, names_b): (Vec<&str>, Vec<&str>) =
            (a.split('/').collect(), b.split('/').collect());
        let Some(at) = names_a.iter().zip(&names_b).position(|(x, y)| x != y) else {
            return Ok(false);
        };
        if at + 1 == names_a.len().min(names_b.len()) {
            return Ok(self.lists(a, stop).await? && self.lists(b, stop).await?);
        }
        let above = dir_prefix(&names_a[..at].join("/"));
        let wanted = [
            format!("{above}{}/", names_a[at]),
            format!("{above}{}/", names_b[at]),
        ];
        let mut seen = [false, false];
        let mut token: Option<String> = None;
        for _ in 0..MAX_LIST_PAGES {
            let request = ListRequest {
                prefix: &above,
                delimited: true,
                continuation_token: token.as_deref(),
                max_keys: None,
            };
            let page = self
                .client
                .list_objects(&request, Retry::until(stop))
                .await?;
            for (found, name) in seen.iter_mut().zip(&wanted) {
                *found |= page.prefixes.contains(name);
            }
            if seen == [true, true] {
                return Ok(true);
            }
            token = page.next_token;
            if token.is_none() {
                break;
            }
        }
        Ok(false)
    }

    /// The object that `a` and `b`, which differ in case only, both name, as
    /// on a store that ignores case: a HEAD of each finds the same size, ETag
    /// and time, and the store does not list both names. `None` if they name
    /// two objects, or one is not there. The time has a resolution of a
    /// second, so two objects made within one second can agree in all three;
    /// only the listing tells them apart.
    ///
    /// # Errors
    ///
    /// Fails with the error of the first request the store refuses.
    pub(super) async fn one_object(
        &self,
        a: &str,
        b: &str,
        stop: &Stop,
    ) -> Result<Option<ObjectHead>, S3Error> {
        let (Some(first), Some(second)) = (
            self.head_if_there(a, stop).await?,
            self.head_if_there(b, stop).await?,
        ) else {
            return Ok(None);
        };
        let alike = (first.size, &first.etag, first.last_modified)
            == (second.size, &second.etag, second.last_modified);
        if alike && !self.listed_apart(a, b, stop).await? {
            return Ok(Some(second));
        }
        Ok(None)
    }

    /// The keys among `twins`, each with the other spelling of its name, that
    /// name the object of the other: they stay in the bucket, as the object
    /// is not to be deleted.
    ///
    /// # Errors
    ///
    /// Fails with the error of the first request the store refuses, or with
    /// `Stopped` once the backend ends.
    pub(super) async fn same_objects(
        &self,
        twins: &[(String, String)],
    ) -> Result<Vec<String>, S3Error> {
        let mut same = Vec::new();
        for (key, twin) in twins {
            if self.one_object(key, twin, &self.jobs.stop).await?.is_some() {
                same.push(key.clone());
            }
        }
        Ok(same)
    }

    /// Puts the marker objects of the directories above `keys` that would
    /// have no object left once `keys` are deleted, so a directory does not
    /// vanish with its last file. If the store answers a marker with
    /// `ObjectParentIsFile` or `ExistingObjectIsDirectory`, the directory is
    /// left without a marker; if it refuses a marker any other way, the
    /// call fails and no key is deleted. `OperationAborted` is tried again.
    ///
    /// # Errors
    ///
    /// Fails with the error of the first request the store refuses, or with
    /// `Stopped` once the backend ends.
    pub(super) async fn put_markers(&self, keys: &[String]) -> Result<(), S3Error> {
        let retry = Retry::until(&self.jobs.stop);
        for dir in ancestors(&self.prefix, keys) {
            let marker = dir_prefix(&dir);
            if self.overlay.tombstoned(&marker) {
                continue;
            }
            let known = self.cache().known(&dir, tokio::time::Instant::now());
            if matches!(known, Some(Known::Dir(Some(_)))) {
                continue;
            }
            let request = ListRequest {
                prefix: &marker,
                delimited: false,
                continuation_token: None,
                max_keys: u32::try_from(self.overlay.hidden_below(&marker) + 2)
                    .ok()
                    .map(|count| count.min(MAX_LISTED)),
            };
            let page = self.client.list_objects(&request, retry.clone()).await?;
            let listed: Vec<String> = page.objects.into_iter().map(|object| object.key).collect();
            let stays =
                |key: &str| !keys.iter().any(|gone| gone == key) && !self.overlay.tombstoned(key);
            if !needs_marker(&dir, &listed, stays) {
                continue;
            }
            let metadata = meta::marker_metadata(meta::same_times(self.built), 0);
            match change::store_marker(self, &dir, metadata, retry.clone()).await {
                Ok(_) => {}
                Err(e) if is_marker_conflict(&e) => {
                    debug!(
                        code = e.code(),
                        "the store holds an object where a directory marker was to go"
                    );
                }
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }

    /// Deletes the keys of `claim`: the markers of the directories above
    /// them first. A key that names the object of another spelling that
    /// stays is not deleted, and counts as deleted. The keys the store
    /// refuses are in `failed`.
    ///
    /// # Errors
    ///
    /// Fails with the error of the first comparison or marker the store
    /// refuses, or with `Stopped` once the backend ends. No key is deleted
    /// then.
    pub(super) async fn delete_claimed(&self, claim: &Deleting) -> Result<Deleted, Refused> {
        let same = self
            .same_objects(claim.twins())
            .await
            .map_err(|error| Refused {
                error,
                what: "an object could not be compared with another spelling of its name and stays in the bucket",
            })?;
        let keys: Vec<String> = claim
            .keys()
            .iter()
            .filter(|key| !same.contains(key))
            .cloned()
            .collect();
        self.put_markers(&keys).await.map_err(|error| Refused {
            error,
            what: "a directory marker could not be stored before deleting objects, which stay in the bucket",
        })?;
        let mut done = self.delete_keys(&keys).await;
        done.deleted.extend(same);
        Ok(done)
    }

    /// Deletes `keys`, a request for each 1000 of them. A key the store
    /// refuses for a reason that waiting can fix is asked for again.
    pub(super) async fn delete_keys(&self, keys: &[String]) -> Deleted {
        let stop = &self.jobs.stop;
        let mut done = Deleted::default();
        for chunk in keys.chunks(MAX_DELETE_KEYS) {
            let mut pending = chunk.to_vec();
            let mut round = 0;
            while !pending.is_empty() {
                let answer = self
                    .client
                    .delete_objects(&pending, Retry::until(stop))
                    .await;
                match answer {
                    Err(e) if e.is_stopped() => {
                        done.stopped = true;
                        return done;
                    }
                    Err(e) => done
                        .failed
                        .extend(pending.drain(..).map(|key| (key, e.clone()))),
                    Ok(failures) => {
                        let mut again = Vec::new();
                        for key in pending.drain(..) {
                            match failures.iter().find(|failure| failure.key == key) {
                                None => {
                                    self.deleted(&key);
                                    done.deleted.push(key);
                                }
                                Some(failure) => {
                                    let error = S3Error::status(200, failure.code.as_deref(), None);
                                    if error.is_no_such_key() || is_marker_kept(&key, &error) {
                                        self.deleted(&key);
                                        done.deleted.push(key);
                                    } else if error.is_transient() {
                                        again.push(key);
                                    } else {
                                        done.failed.push((key, error));
                                    }
                                }
                            }
                        }
                        pending = again;
                    }
                }
                if !pending.is_empty() {
                    round += 1;
                    let wait = Retry::until(stop).delay(round, BASE_DELAY);
                    tokio::select! {
                        () = sleep(wait) => {}
                        () = stop.stopped() => {
                            done.stopped = true;
                            return done;
                        }
                    }
                }
            }
        }
        done
    }
}

/// Deletes the keys of `claim`, which the overlay claimed: the markers of the
/// directories above them first. Keys the store deleted leave the overlay and
/// the records that name them; keys it refused stay, marked, and fail a call
/// that waits for them.
pub(super) async fn delete(shared: Arc<Shared>, claim: Deleting) {
    let overlay = &shared.overlay;
    let done = match shared.delete_claimed(&claim).await {
        Ok(done) => done,
        Err(refused) => {
            fail_all(&shared, claim.keys(), &refused.error, refused.what);
            return;
        }
    };
    let mut failed = done.failed;
    for (key, error) in &failed {
        error!(
            status = error.http_status(),
            code = error.code(),
            request_id = error.request_id(),
            key,
            "an object could not be deleted from the bucket, and is tried again when the next backend is built"
        );
    }
    if let Some(local) = shared.local.clone() {
        let (shared, listed) = (Arc::clone(&shared), done.deleted.clone());
        let dropped = spawn_blocking(move || shared.overlay.drop_tombs(&local, &listed))
            .await
            .unwrap_or_else(|e| Err(io::Error::other(e)));
        if let Err(e) = dropped {
            warn!(error = %e, "the record of deleted keys could not be updated");
            let error = S3Error::Cache(Arc::new(e));
            failed.extend(done.deleted.iter().map(|key| (key.clone(), error.clone())));
        }
    }
    overlay.finish_tombs(&failed);
}

/// Marks `keys` as failed with `error`, unless the backend ended.
fn fail_all(shared: &Shared, keys: &[String], error: &S3Error, what: &str) {
    let failed: Vec<(String, S3Error)> = if error.is_stopped() {
        Vec::new()
    } else {
        error!(
            status = error.http_status(),
            code = error.code(),
            request_id = error.request_id(),
            "{what}"
        );
        keys.iter()
            .map(|key| (key.clone(), error.clone()))
            .collect()
    };
    shared.overlay.finish_tombs(&failed);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keys(keys: &[&str]) -> Vec<String> {
        keys.iter().map(|key| (*key).to_owned()).collect()
    }

    #[test]
    fn a_store_that_keeps_a_directory_for_its_objects_has_no_marker_to_delete() {
        let kept = S3Error::status(200, Some("ErrDirectoryNotEmpty"), None);
        assert!(is_marker_kept("d/", &kept));
        assert!(!is_marker_kept("d/file", &kept));
        assert!(!is_marker_kept(
            "d/",
            &S3Error::status(200, Some("AccessDenied"), None)
        ));
    }

    #[test]
    fn the_directories_above_keys_are_each_listed_once_outermost_first() {
        assert_eq!(
            ancestors("", &keys(&["a/b/c.txt", "a/d.txt", "top.txt"])),
            ["a", "a/b"]
        );
        assert_eq!(
            ancestors("share", &keys(&["share/x/y", "share/z"])),
            ["share/x"]
        );
    }

    #[test]
    fn keys_outside_the_share_and_the_names_of_the_root_have_no_directory() {
        assert!(ancestors("share", &keys(&["other/x/y"])).is_empty());
        assert!(ancestors("", &keys(&["file"])).is_empty());
    }

    #[test]
    fn a_directory_needs_a_marker_when_every_object_below_it_goes() {
        let gone = keys(&["d/a", "d/b"]);
        let stays = |key: &str| !gone.iter().any(|held| held == key);
        assert!(needs_marker("d", &keys(&["d/a", "d/b"]), stays));
        assert!(
            !needs_marker("d", &keys(&["d/", "d/a"]), stays),
            "it has one"
        );
        assert!(
            !needs_marker("d", &keys(&["d/a", "d/c"]), stays),
            "d/c stays"
        );
        assert!(needs_marker("d", &[], stays));
    }
}
