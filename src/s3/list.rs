//! The entries a directory handle lists, with their times.

use std::collections::VecDeque;
use std::sync::Arc;

use tokio::task::JoinSet;
use tokio::time::{Instant, timeout_at};
use tracing::debug;

use crate::backend::DirEntry;
use crate::error::{SmbError, SmbResult};
use crate::wildcard::Pattern;

use super::backend::Shared;
use super::cache::Known;
use super::keys::{Row, RowKind, dir_prefix, join_key};
use super::lookup::DirRef;
use super::meta;
use super::object::ObjectHead;
use super::retry::{Retry, deadline_after};

/// Whether `pattern` has a character that matches more than itself.
fn has_wildcard(pattern: &str) -> bool {
    pattern.contains(['*', '?', '<', '>', '"'])
}

/// An entry whose times a HEAD request may supply.
struct Fetch {
    /// Where the entry is among the rows.
    at: usize,
    key: String,
    is_dir: bool,
}

/// The entries of `dir` that match `pattern`.
pub(super) async fn list_entries(
    shared: &Arc<Shared>,
    dir: &DirRef,
    pattern: Option<&str>,
) -> SmbResult<Vec<DirEntry>> {
    let deadline = deadline_after(shared.request_timeout);
    let retry = Retry::Foreground { deadline };
    let pattern = pattern.filter(|p| !matches!(*p, "" | "*" | "*.*"));
    if let Some(name) = pattern.filter(|p| !has_wildcard(p)) {
        return match shared.lookup_in(dir, name, &retry).await {
            Ok(found) => Ok(vec![DirEntry {
                info: found.info(shared),
            }]),
            Err(SmbError::NotFound | SmbError::PathNotFound) => Ok(Vec::new()),
            Err(e) => Err(e),
        };
    }

    let listing = shared.listing(&dir.key, &retry).await?;
    let matcher = pattern.map(|p| Pattern::new(p, shared.case_insensitive));
    let rows: Vec<&Row> = listing
        .rows
        .iter()
        .filter(|row| matcher.as_ref().is_none_or(|m| m.matches(&row.name)))
        .collect();
    let heads = row_heads(shared, &dir.key, &rows, deadline).await;
    Ok(rows
        .into_iter()
        .zip(heads)
        .map(|(row, head)| DirEntry {
            info: match (&row.kind, head) {
                (RowKind::File(_), Some(head)) => meta::file_info(&row.name, &head),
                (RowKind::File(stamp), None) => meta::stamp_info(&row.name, stamp),
                (RowKind::Dir, marker) => {
                    meta::dir_info(&row.name, marker.as_deref(), shared.built)
                }
            },
        })
        .collect())
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
    fn only_wildcard_characters_make_a_pattern_a_search() {
        for pattern in ["*", "a*", "?x", "<.txt", "a>", "\"x", "a.b?"] {
            assert!(has_wildcard(pattern), "{pattern}");
        }
        for pattern in ["a.txt", "name with spaces", "\u{e9}", "a-b_c", "..", "."] {
            assert!(!has_wildcard(pattern), "{pattern}");
        }
    }
}
