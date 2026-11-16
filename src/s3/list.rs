//! The entries a directory handle lists, with their times.

use std::collections::VecDeque;
use std::sync::Arc;
use std::time::Duration;

use tokio::task::JoinSet;
use tokio::time::{Instant, timeout_at};
use tracing::debug;

use crate::backend::DirEntry;
use crate::error::{SmbError, SmbResult};
use crate::path::is_valid_component;
use crate::wildcard::{Pattern, has_wildcard, without_match_all};

use super::backend::Shared;
use super::cache::Known;
use super::keys::{Row, RowKind, dir_prefix, join_key};
use super::lookup::DirRef;
use super::merge::{Direct, Picked, Source, merge};
use super::meta;
use super::object::ObjectHead;
use super::retry::{Retry, deadline_after};

/// An entry whose times a HEAD request may supply.
struct Fetch {
    /// Where the entry is among the rows.
    at: usize,
    key: String,
    is_dir: bool,
}

/// How many times the listing of a directory is read, when the directory
/// changes while it is.
pub(super) const LIST_ATTEMPTS: usize = 4;

/// A read made again is given up on after as long as the read before it took,
/// or the request timeout divided by this, whichever is more.
const RETRY_SHARE: u32 = 4;

/// The entries of `dir` that match `pattern`: those of its listing in the
/// bucket, less the keys to delete, and the overlay's entries in their place.
pub(super) async fn list_entries(
    shared: &Arc<Shared>,
    dir: &DirRef,
    pattern: Option<&str>,
) -> SmbResult<Vec<DirEntry>> {
    let deadline = deadline_after(shared.request_timeout);
    let retry = Retry::Foreground { deadline };
    let pattern = without_match_all(pattern);
    if let Some(name) = pattern.filter(|p| !has_wildcard(p)) {
        return single(shared, dir, name, &retry).await;
    }

    // The rows of the store and what the overlay holds are read one after the
    // other, so a change made to the directory in between can show in only one
    // of them. A read that met a change to the rows or to the overlay is made
    // again; after LIST_ATTEMPTS reads, or when another would end past the
    // deadline, the last one stands. A change to the rows is noted before the
    // overlay lets go of the entry or key to delete that covered it, so a read
    // that met no change has every name in one of the two. The cache takes in
    // the changes made to the rows while they are read, so a read made again
    // is served by it. When a read made again fails or runs past its limit,
    // the one before it stands.
    let mut attempt = 1;
    let mut earlier = None;
    let mut limit = deadline;
    let (listing, below, direct, hidden) = loop {
        let started = Instant::now();
        let read_retry = Retry::Foreground { deadline: limit };
        let listed = match shared.listed(&dir.key, &read_retry).await {
            Ok(listed) => listed,
            Err(e) => match earlier.take() {
                Some(read) => {
                    debug!(error = %e, "a listing made again failed; the one before it stands");
                    break read;
                }
                None => return Err(e),
            },
        };
        #[cfg(test)]
        {
            change_rows(shared, &dir.key);
            super::jobs::pause(&shared.jobs.pause_rows).await;
        }
        // The watch comes first: a change made after it is noted, and one made
        // before it is in what the overlay holds.
        let watch = shared.overlay.watch(&dir.key);
        #[cfg(test)]
        super::jobs::pause(&shared.jobs.pause_watch).await;
        let below = shared.overlay.below(&dir.key);
        #[cfg(test)]
        super::jobs::pause(&shared.jobs.pause_below).await;
        let hidden = shared.overlay.hidden(&dir.key, &listed.rows.rows);
        let direct: Vec<Direct> = below
            .direct
            .iter()
            .map(|entry| Direct {
                name: entry.state().name().to_owned(),
                is_dir: entry.is_dir(),
            })
            .collect();
        let again = listed.changed() || watch.changed();
        let read = (Arc::clone(&listed.rows), below, direct, hidden);
        if !again || attempt == LIST_ATTEMPTS {
            break read;
        }
        let Some(next) = retry_limit(deadline, shared.request_timeout, started.elapsed()) else {
            break read;
        };
        limit = next;
        earlier = Some(read);
        attempt += 1;
    };
    let rows: Vec<&Row> = listing
        .rows
        .iter()
        .zip(&hidden)
        .filter(|(_, hidden)| !**hidden)
        .map(|(row, _)| row)
        .collect();
    let matcher = pattern.map(|p| Pattern::new(p, shared.case_insensitive));
    let picked: Vec<Picked> = merge(&rows, &direct, &below.implied, shared.case_insensitive)
        .into_iter()
        .filter(|picked| matcher.as_ref().is_none_or(|m| m.matches(&picked.name)))
        .collect();

    let from_store: Vec<&Row> = picked
        .iter()
        .filter_map(|picked| match picked.source {
            Source::Row(at) => Some(rows[at]),
            _ => None,
        })
        .collect();
    let mut heads = row_heads(shared, &dir.key, &from_store, deadline)
        .await
        .into_iter();
    let mut entries = Vec::with_capacity(picked.len());
    for picked in picked {
        let info = match picked.source {
            Source::Row(at) => {
                let head = heads.next().flatten();
                let row = rows[at];
                match (&row.kind, head) {
                    (RowKind::File(_), Some(head)) => meta::file_info(&row.name, &head),
                    (RowKind::File(stamp), None) => meta::stamp_info(&row.name, stamp),
                    (RowKind::Dir, marker) => {
                        meta::dir_info(&row.name, marker.as_deref(), shared.built)
                    }
                }
            }
            Source::Entry(at) => below.direct[at].info(shared.built),
            Source::Implied(_) => meta::dir_info(&picked.name, None, shared.built),
        };
        entries.push(DirEntry { info });
    }
    Ok(entries)
}

/// When a read made again is given up on, or `None` if it is not to be made:
/// one as long as the read that took `spent` would not end before `deadline`.
/// The read may take as long as that one, or a share of `timeout` if that is
/// more, and ends at `deadline` at the latest.
fn retry_limit(deadline: Instant, timeout: Duration, spent: Duration) -> Option<Instant> {
    let now = Instant::now();
    now.checked_add(spent).filter(|end| *end < deadline)?;
    let allowed = spent.max(timeout / RETRY_SHARE);
    Some(
        now.checked_add(allowed)
            .map_or(deadline, |end| end.min(deadline)),
    )
}

/// Changes the rows of `dir` if a test asked for it.
#[cfg(test)]
fn change_rows(shared: &Shared, dir: &str) {
    use std::sync::atomic::Ordering::SeqCst;
    let asked = shared
        .jobs
        .churn
        .fetch_update(SeqCst, SeqCst, |reads| reads.checked_sub(1));
    if asked.is_ok() {
        shared.forget_file(&join_key(dir, "changed"));
    }
}

/// The entry of `dir` named `name`, which has no wildcard.
async fn single(
    shared: &Arc<Shared>,
    dir: &DirRef,
    name: &str,
    retry: &Retry,
) -> SmbResult<Vec<DirEntry>> {
    if is_valid_component(name)
        && let Some(entry) = shared.overlay.peek(&join_key(&dir.key, name))
    {
        return Ok(vec![DirEntry {
            info: entry.info(shared.built),
        }]);
    }
    match shared.lookup_in(dir, name, retry).await {
        Ok(found) => Ok(vec![DirEntry {
            info: found.info(shared),
        }]),
        Err(SmbError::NotFound | SmbError::PathNotFound) => Ok(Vec::new()),
        Err(e) => Err(e),
    }
}

/// The description of the object, or the marker of the directory, of each
/// row, where known. What the cache lacks is read with HEAD requests for up
/// to `listing_metadata_max` rows, a few at a time, as far as `deadline`
/// allows.
async fn row_heads(
    shared: &Arc<Shared>,
    dir: &str,
    rows: &[&Row],
    deadline: Instant,
) -> Vec<Option<Arc<ObjectHead>>> {
    let mut heads: Vec<Option<Arc<ObjectHead>>> = vec![None; rows.len()];
    let mut wanted: VecDeque<Fetch> = VecDeque::new();
    {
        let now = Instant::now();
        let mut cache = shared.cache();
        for (at, row) in rows.iter().enumerate() {
            let key = join_key(dir, &row.name);
            match &row.kind {
                RowKind::File(stamp) => match cache.head_for_row(&key, stamp) {
                    Some(head) => heads[at] = Some(head),
                    None => wanted.push_back(Fetch {
                        at,
                        key,
                        is_dir: false,
                    }),
                },
                RowKind::Dir => match cache.known(&key, now) {
                    Some(Known::Dir(marker)) => heads[at] = marker,
                    _ => wanted.push_back(Fetch {
                        at,
                        key,
                        is_dir: true,
                    }),
                },
            }
        }
    }
    wanted.truncate(shared.listing_metadata_max);

    let retry = Retry::Foreground { deadline };
    let mut running = JoinSet::new();
    let read = async {
        loop {
            while running.len() < shared.head_concurrency
                && let Some(fetch) = wanted.pop_front()
            {
                let shared = Arc::clone(shared);
                let retry = retry.clone();
                running.spawn(async move {
                    let head = shared.fetch_head(&fetch.key, fetch.is_dir, &retry).await;
                    (fetch.at, head)
                });
            }
            match running.join_next().await {
                Some(Ok((at, head))) => heads[at] = head,
                Some(Err(e)) => {
                    debug!(error = %e, "a request for a listed entry's times did not finish")
                }
                None => break,
            }
        }
    };
    // Rows still waiting at the deadline report the time the store modified
    // them.
    let _ = timeout_at(deadline, read).await;
    heads
}

impl Shared {
    /// The description of the object at `key`, or of the marker of the
    /// directory with that key, remembered for later lookups. `None` when
    /// there is none or the request failed.
    async fn fetch_head(&self, key: &str, is_dir: bool, retry: &Retry) -> Option<Arc<ObjectHead>> {
        let at = if is_dir {
            dir_prefix(key)
        } else {
            key.to_owned()
        };
        let (known, head) = match self.head_if_any(&at, retry).await {
            Ok(Some(head)) => {
                let known = if is_dir {
                    Known::Dir(Some(Arc::clone(&head)))
                } else {
                    Known::File(Arc::clone(&head))
                };
                (Some(known), Some(head))
            }
            Ok(None) => (is_dir.then_some(Known::Dir(None)), None),
            Err(e) => {
                debug!(
                    status = e.http_status(),
                    code = e.code(),
                    request_id = e.request_id(),
                    "a listed entry's times were not read"
                );
                (None, None)
            }
        };
        if let Some(known) = known {
            self.cache().put_known(key, known, Instant::now());
        }
        head
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_read_is_made_again_only_if_it_fits_before_the_deadline() {
        let timeout = Duration::from_secs(40);
        let deadline = Instant::now() + timeout;
        assert!(retry_limit(deadline, timeout, Duration::from_secs(1)).is_some());
        assert!(retry_limit(deadline, timeout, Duration::from_secs(41)).is_none());
        assert!(retry_limit(Instant::now(), timeout, Duration::ZERO).is_none());
        assert!(retry_limit(deadline, timeout, Duration::MAX).is_none());
    }

    #[tokio::test(start_paused = true)]
    async fn a_read_made_again_may_take_as_long_as_the_one_before_or_a_share_of_the_timeout() {
        let timeout = Duration::from_secs(40);
        let now = Instant::now();
        let deadline = now + timeout;
        let share = timeout / RETRY_SHARE;
        assert_eq!(
            retry_limit(deadline, timeout, Duration::ZERO),
            Some(now + share)
        );
        assert_eq!(retry_limit(deadline, timeout, share / 2), Some(now + share));
        let long = Duration::from_secs(25);
        assert_eq!(retry_limit(deadline, timeout, long), Some(now + long));
    }

    #[tokio::test(start_paused = true)]
    async fn a_read_made_again_ends_by_the_deadline() {
        let timeout = Duration::from_secs(40);
        let now = Instant::now();
        let soon = now + Duration::from_secs(5);
        assert_eq!(retry_limit(soon, timeout, Duration::ZERO), Some(soon));
        let deadline = now + timeout;
        assert_eq!(
            retry_limit(deadline, Duration::MAX, Duration::ZERO),
            Some(deadline)
        );
    }
}
