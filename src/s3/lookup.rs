//! What a path names in the store, and the entries of a directory.

use std::sync::Arc;

use tokio::time::Instant;

use crate::backend::FileInfo;
use crate::error::{SmbError, SmbResult};
use crate::path::{SmbPath, is_valid_component};

use super::backend::Shared;
use super::cache::Known;
use super::client::{ListRequest, MAX_LISTED};
use super::error::S3Error;
use super::keys::{
    DirListing, ListingBuilder, MAX_KEY_LEN, Row, RowKind, child_key, dir_prefix, last_name,
    parent_key, path_key,
};
use super::meta;
use super::object::ObjectHead;
use super::overlay::Held;
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
        let dir = parent_key(key);
        self.cache().forget_file(key, dir);
    }

    /// Drops what is cached of the object at `key`, which the backend
    /// deleted, and its row in the cached listing of its directory. The key
    /// of a directory marker drops the directory.
    pub(super) fn deleted(&self, key: &str) {
        let key = key.strip_suffix('/').unwrap_or(key);
        let dir = parent_key(key);
        self.cache().deleted_file(key, dir);
    }

    /// Makes what is cached of the object at `key` `known`, and puts `kind`
    /// as its row in the cached listing of its directory. The directories
    /// above the key are there now, with or without a marker object of their
    /// own: each gets its row in the cached listing of the directory above.
    pub(super) fn remember(&self, key: &str, known: Known, kind: RowKind) {
        let dir = parent_key(key);
        let mut cache = self.cache();
        cache.put_known(key, known, Instant::now());
        cache.add_row(
            dir,
            Row {
                name: last_name(key).to_owned(),
                kind,
            },
        );
        let mut above = dir;
        while above.len() > self.prefix.len() {
            cache.add_row(
                parent_key(above),
                Row {
                    name: last_name(above).to_owned(),
                    kind: RowKind::Dir,
                },
            );
            above = parent_key(above);
        }
    }

    /// Resolves `path`, as far as the bucket and the cache tell. Fails with
    /// `NotFound` when the directory it is in exists and holds no such name,
    /// and with `PathNotFound` when that directory does not exist or is an
    /// object. An object whose key is to be deleted does not resolve, and a
    /// directory that only entries of the overlay below it imply does.
    pub(super) async fn lookup(&self, path: &SmbPath, retry: &Retry) -> SmbResult<Found> {
        if self
            .overlay
            .dead_above(&path_key(&self.prefix, path.components())?)
        {
            return Err(SmbError::PathNotFound);
        }
        match self.resolve(path, retry).await {
            Ok(found) => self.visible(found),
            Err(e @ (SmbError::NotFound | SmbError::PathNotFound)) => {
                let key = path_key(&self.prefix, path.components())?;
                if let Some(found) = self.implied(&key) {
                    return Ok(found);
                }
                // A directory that only the overlay has holds names the
                // bucket does not know.
                let parent = path.parent().filter(|parent| !parent.is_root());
                let in_overlay = parent
                    .and_then(|parent| path_key(&self.prefix, parent.components()).ok())
                    .is_some_and(|parent| {
                        self.overlay
                            .peek(&parent)
                            .is_some_and(|entry| entry.is_dir())
                            || self.overlay.spelling(&parent).is_some()
                    });
                Err(if in_overlay { SmbError::NotFound } else { e })
            }
            Err(e) => Err(e),
        }
    }

    /// A hold on the entry of the overlay that `path` names: one that holds
    /// changes, else one for what the bucket has there.
    pub(super) async fn locate(self: &Arc<Self>, path: &SmbPath, retry: &Retry) -> SmbResult<Held> {
        let key = path_key(&self.prefix, path.components())?;
        if let Some(held) = self.overlay.take_pending(&key) {
            return Ok(held);
        }
        let found = self.lookup(path, retry).await?;
        #[cfg(test)]
        super::jobs::pause(&self.jobs.pause_found).await;
        self.overlay.take_found(found, &self.ahead)
    }

    /// The directory `path` is in, as the bucket spells it. Fails with
    /// `PathNotFound` if it is not a directory.
    pub(super) async fn parent_dir(&self, path: &SmbPath, retry: &Retry) -> SmbResult<DirRef> {
        let parent = path.parent().filter(|parent| !parent.is_root());
        let Some(parent) = parent else {
            return Ok(self.root());
        };
        let key = path_key(&self.prefix, parent.components())?;
        if let Some(entry) = self.overlay.peek(&key) {
            if !entry.is_dir() {
                return Err(SmbError::PathNotFound);
            }
            return Ok(entry.state().dir_ref());
        }
        match self.lookup(&parent, retry).await {
            Ok(Found::Dir(dir)) => Ok(dir),
            Ok(Found::File(_)) | Err(SmbError::NotFound) => Err(SmbError::PathNotFound),
            Err(e) => Err(e),
        }
    }

    /// The directory `key` names if entries of the overlay below it imply it.
    fn implied(&self, key: &str) -> Option<Found> {
        self.overlay.spelling(key).map(|key| {
            Found::Dir(DirRef {
                name: last_name(&key).to_owned(),
                key,
                marker: None,
            })
        })
    }

    /// `found`, unless the overlay has the key of the object to delete. An
    /// object that entries of the overlay are below is the directory they
    /// imply. A directory whose marker key is to be deleted is not there.
    fn visible(&self, found: Found) -> SmbResult<Found> {
        let file = match &found {
            Found::File(file) => file,
            Found::Dir(dir) => {
                return if self.overlay.dir_dead(&dir.key) {
                    Err(SmbError::NotFound)
                } else {
                    Ok(found)
                };
            }
        };
        if let Some(dir) = self.implied(&file.key) {
            return Ok(dir);
        }
        if self.overlay.tombstoned(&file.key) {
            return Err(SmbError::NotFound);
        }
        Ok(found)
    }

    async fn resolve(&self, path: &SmbPath, retry: &Retry) -> SmbResult<Found> {
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
        let found = if let Some(found) = self.exact(&dir.key, name, retry).await? {
            Ok(found)
        } else if self.case_insensitive {
            self.fold_in(&dir.key, name, retry).await
        } else {
            Err(SmbError::NotFound)
        };
        match found {
            Ok(found) => self.visible(found),
            Err(SmbError::NotFound) => self
                .implied(&child_key(&dir.key, name)?)
                .ok_or(SmbError::NotFound),
            Err(e) => Err(e),
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
        // A prefix longer than any key has no key below it.
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

    /// Whether the directory with key `dir` holds nothing: no entry of the
    /// overlay, and no key below it but its marker and the keys to delete.
    /// The store is asked for two keys, and for more when the keys to delete
    /// below the directory could fill the answer.
    pub(super) async fn is_empty(&self, dir: &str, retry: &Retry) -> SmbResult<bool> {
        if self.overlay.spelling(dir).is_some() {
            return Ok(false);
        }
        let prefix = dir_prefix(dir);
        let hidden = self.overlay.hidden_below(&prefix);
        let max_keys = u32::try_from(hidden + 2)
            .unwrap_or(u32::MAX)
            .min(MAX_LISTED);
        let mut token: Option<String> = None;
        loop {
            let request = ListRequest {
                prefix: &prefix,
                delimited: false,
                continuation_token: token.as_deref(),
                max_keys: Some(max_keys),
            };
            let page = self
                .client
                .list_objects(&request, retry.clone())
                .await
                .map_err(S3Error::into_smb_error)?;
            let stays = page
                .objects
                .iter()
                .any(|object| object.key != prefix && !self.overlay.tombstoned(&object.key));
            if stays {
                return Ok(false);
            }
            token = page.next_token;
            if token.is_none() {
                return Ok(true);
            }
        }
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
