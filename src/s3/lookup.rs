//! What a path names in the store, and the entries of a directory.

use std::sync::Arc;

use tokio::time::Instant;

use crate::backend::FileInfo;
use crate::error::{SmbError, SmbResult};
use crate::path::{SmbPath, is_valid_component};

use super::backend::Shared;
use super::cache::Known;
use super::client::ListRequest;
use super::error::S3Error;
use super::keys::{
    DirListing, ListingBuilder, MAX_KEY_LEN, Row, RowKind, child_key, dir_prefix, path_key,
};
use super::meta;
use super::object::ObjectHead;
use super::retry::Retry;

/// A directory found in the store.
#[derive(Debug, Clone)]
pub(super) struct DirRef {
    /// The key of the directory, without the `/` its marker object has. The
    /// root of the share has the prefix of the share.
    pub(super) key: String,
    /// The name as the store spells it; empty for the root.
    pub(super) name: String,
    /// The object that marks the directory, if there is one.
    pub(super) marker: Option<Arc<ObjectHead>>,
}

/// An object found in the store.
#[derive(Debug, Clone)]
pub(super) struct FileRef {
    pub(super) key: String,
    /// The name as the store spells it.
    pub(super) name: String,
    pub(super) head: Arc<ObjectHead>,
}

/// What a name resolves to.
#[derive(Debug, Clone)]
pub(super) enum Found {
    Dir(DirRef),
    File(FileRef),
}

impl Found {
    /// The description of the entry. A directory with no marker object has
    /// the time the backend was built.
    pub(super) fn info(&self, shared: &Shared) -> FileInfo {
        match self {
            Found::File(file) => meta::file_info(&file.name, &file.head),
            Found::Dir(dir) => meta::dir_info(&dir.name, dir.marker.as_deref(), shared.built),
        }
    }
}

impl Shared {
    /// The share root.
    pub(super) fn root(&self) -> DirRef {
        DirRef {
            key: self.prefix.clone(),
            name: String::new(),
            marker: None,
        }
    }

    /// Drops what is cached of the object at `key`, which has changed, and of
    /// the listing of its directory.
    pub(super) fn forget_file(&self, key: &str) {
        let dir = key.rsplit_once('/').map_or("", |(dir, _)| dir);
        self.cache().forget_file(key, dir);
    }

    /// Resolves `path`. Fails with `NotFound` when the directory it is in
    /// exists and holds no such name, and with `PathNotFound` when that
    /// directory does not exist or is an object.
    pub(super) async fn lookup(&self, path: &SmbPath, retry: &Retry) -> SmbResult<Found> {
        let components = path.components();
        let Some((name, parents)) = components.split_last() else {
            return Ok(Found::Dir(self.root()));
        };
        let dir = path_key(&self.prefix, parents)?;
        if let Some(found) = self.exact(&dir, name, retry).await? {
            return Ok(found);
        }
        if !self.case_insensitive {
            return Err(self.missing_in(parents, retry).await?);
        }
        // A directory spelled as given is the one the name would be in: any
        // other spelling of it ranks after the exact one.
        let exact_parent = match parents.split_last() {
            None => true,
            Some((parent, above)) => {
                let grandparent = path_key(&self.prefix, above)?;
                let found = self.exact(&grandparent, parent, retry).await?;
                matches!(found, Some(Found::Dir(_)))
            }
        };
        if exact_parent {
            self.fold_in(&dir, name, retry).await
        } else {
            self.lookup_folded(parents, name, retry).await
        }
    }

    /// Resolves `name` in `dir`, as [`lookup`](Self::lookup) resolves the last
    /// component of a path. Fails with `NotFound` if there is none.
    pub(super) async fn lookup_in(
        &self,
        dir: &DirRef,
        name: &str,
        retry: &Retry,
    ) -> SmbResult<Found> {
        if !is_valid_component(name) {
            return Err(SmbError::NotFound);
        }
        if let Some(found) = self.exact(&dir.key, name, retry).await? {
            return Ok(found);
        }
        if self.case_insensitive {
            self.fold_in(&dir.key, name, retry).await
        } else {
            Err(SmbError::NotFound)
        }
    }

    /// The error for a name that no key spells exactly in the directory
    /// `parents` names, spelled as given: `NotFound` if the directory exists,
    /// else `PathNotFound`.
    async fn missing_in(&self, parents: &[String], retry: &Retry) -> SmbResult<SmbError> {
        let Some((name, above)) = parents.split_last() else {
            return Ok(SmbError::NotFound);
        };
        let dir = path_key(&self.prefix, above)?;
        Ok(match self.exact(&dir, name, retry).await? {
            Some(Found::Dir(_)) => SmbError::NotFound,
            _ => SmbError::PathNotFound,
        })
    }

    /// Resolves each component through the listing of the directory above it,
    /// with names that differ only in case matching.
    async fn lookup_folded(
        &self,
        parents: &[String],
        name: &str,
        retry: &Retry,
    ) -> SmbResult<Found> {
        let mut dir = self.prefix.clone();
        for component in parents {
            let listing = self.listing(&dir, retry).await?;
            let Some(row) = listing.find_folded(component, true) else {
                return Err(SmbError::PathNotFound);
            };
            dir = child_key(&dir, &row.name)?;
        }
        self.fold_in(&dir, name, retry).await
    }

    /// The entry of `dir` named `name` or, failing that, spelled with other
    /// case.
    async fn fold_in(&self, dir: &str, name: &str, retry: &Retry) -> SmbResult<Found> {
        let listing = self.listing(dir, retry).await?;
        let Some(row) = listing.find_folded(name, false) else {
            return Err(SmbError::NotFound);
        };
        let key = child_key(dir, &row.name)?;
        let known = self.known_from_row(&key, row, retry).await?;
        found(key, &row.name, known).ok_or(SmbError::NotFound)
    }

    /// The entry of `dir` named exactly `name`, from what is cached, or else
    /// from the store. `None` if there is no such entry.
    async fn exact(&self, dir: &str, name: &str, retry: &Retry) -> SmbResult<Option<Found>> {
        let key = child_key(dir, name)?;
        let now = Instant::now();
        let (known, parent) = {
            let mut cache = self.cache();
            let known = cache.known(&key, now);
            let parent = if known.is_none() {
                cache.listing(dir, now)
            } else {
                None
            };
            (known, parent)
        };
        let known = match (known, parent) {
            (Some(known), _) => known,
            (None, Some(listing)) => match listing.find_exact(name) {
                Some(row) => self.known_from_row(&key, row, retry).await?,
                None => Known::Missing,
            },
            (None, None) => self.known_from_store(&key, retry).await?,
        };
        Ok(found(key, name, known))
    }

    /// What the store has at `key`: a HEAD of the key and a listing of the
    /// keys below it go out together, and a directory wins over an object.
    async fn known_from_store(&self, key: &str, retry: &Retry) -> SmbResult<Known> {
        let prefix = dir_prefix(key);
        let (head, first) = tokio::join!(
            self.head_if_any(key, retry),
            self.first_key_below(&prefix, retry),
        );
        let known = match first.map_err(S3Error::into_smb_error)? {
            Some(first) => {
                let marker = if first == prefix {
                    self.marker_head(&prefix, retry).await?
                } else {
                    None
                };
                Known::Dir(marker)
            }
            None => match head.map_err(S3Error::into_smb_error)? {
                Some(head) => Known::File(head),
                None => Known::Missing,
            },
        };
        self.cache().put_known(key, known.clone(), Instant::now());
        Ok(known)
    }

    /// What the store has at `key` when a listing has named the entry.
    async fn known_from_row(&self, key: &str, row: &Row, retry: &Retry) -> SmbResult<Known> {
        let known = match &row.kind {
            RowKind::Dir => {
                if let Some(known @ Known::Dir(_)) = self.cache().known(key, Instant::now()) {
                    return Ok(known);
                }
                Known::Dir(self.marker_head(&dir_prefix(key), retry).await?)
            }
            RowKind::File(stamp) => {
                if let Some(head) = self.cache().head_for_row(key, stamp) {
                    return Ok(Known::File(head));
                }
                match self.head_if_any(key, retry).await {
                    Ok(Some(head)) => Known::File(head),
                    Ok(None) => Known::Missing,
                    Err(e) => return Err(e.into_smb_error()),
                }
            }
        };
        self.cache().put_known(key, known.clone(), Instant::now());
        Ok(known)
    }

    /// The first key below `prefix`, if there is any.
    async fn first_key_below(
        &self,
        prefix: &str,
        retry: &Retry,
    ) -> Result<Option<String>, S3Error> {
        // No key below a prefix longer than a key can be stored.
        if prefix.len() > MAX_KEY_LEN {
            return Ok(None);
        }
        let request = ListRequest {
            prefix,
            delimited: false,
            continuation_token: None,
            max_keys: Some(1),
        };
        let page = self.client.list_objects(&request, retry.clone()).await?;
        Ok(page
            .objects
            .into_iter()
            .map(|object| object.key)
            .find(|key| key.starts_with(prefix)))
    }

    /// The description of the object at `key`, or `None` if there is none.
    pub(super) async fn head_if_any(
        &self,
        key: &str,
        retry: &Retry,
    ) -> Result<Option<Arc<ObjectHead>>, S3Error> {
        match self.client.head_object(key, retry.clone()).await {
            Ok(head) => Ok(Some(Arc::new(head))),
            Err(e) if e.is_no_such_key() => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// The marker object of a directory whose keys start with `prefix`.
    async fn marker_head(&self, prefix: &str, retry: &Retry) -> SmbResult<Option<Arc<ObjectHead>>> {
        self.head_if_any(prefix, retry)
            .await
            .map_err(S3Error::into_smb_error)
    }

    /// All the entries of the directory with key `dir`, from the cache if it
    /// has them or else from the store, page by page. A directory with no
    /// keys below it has no entries.
    pub(super) async fn listing(&self, dir: &str, retry: &Retry) -> SmbResult<Arc<DirListing>> {
        if let Some(listing) = self.cache().listing(dir, Instant::now()) {
            return Ok(listing);
        }
        let prefix = dir_prefix(dir);
        let mut builder = ListingBuilder::new(prefix.clone());
        let mut token: Option<String> = None;
        loop {
            let request = ListRequest {
                prefix: &prefix,
                delimited: true,
                continuation_token: token.as_deref(),
                max_keys: None,
            };
            let page = self
                .client
                .list_objects(&request, retry.clone())
                .await
                .map_err(S3Error::into_smb_error)?;
            builder.add(&page);
            token = page.next_token;
            if token.is_none() {
                break;
            }
        }
        let listing = Arc::new(builder.finish().unwrap_or_default());
        self.cache()
            .put_listing(dir, Arc::clone(&listing), Instant::now());
        Ok(listing)
    }

    /// Whether no key but the marker of the directory with key `dir` is
    /// below it.
    pub(super) async fn is_empty(&self, dir: &str, retry: &Retry) -> SmbResult<bool> {
        let prefix = dir_prefix(dir);
        let request = ListRequest {
            prefix: &prefix,
            delimited: false,
            continuation_token: None,
            max_keys: Some(2),
        };
        let page = self
            .client
            .list_objects(&request, retry.clone())
            .await
            .map_err(S3Error::into_smb_error)?;
        Ok(page.objects.iter().all(|object| object.key == prefix))
    }
}

fn found(key: String, name: &str, known: Known) -> Option<Found> {
    match known {
        Known::File(head) => Some(Found::File(FileRef {
            key,
            name: name.to_owned(),
            head,
        })),
        Known::Dir(marker) => Some(Found::Dir(DirRef {
            key,
            name: name.to_owned(),
            marker,
        })),
        Known::Missing => None,
    }
}
