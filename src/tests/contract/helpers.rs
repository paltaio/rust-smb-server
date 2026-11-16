//! Calls and checks the contract tests share.

use std::mem;

use crate::backend::{DirEntry, Handle, OpenAction, OpenIntent, ShareBackend};
use crate::error::{SmbError, SmbResult};
use crate::tests::util::{dir_opts, opts, path};

/// The backend a test runs against.
pub(super) type Backend<'a> = &'a dyn ShareBackend;

/// Plaintext bytes in a block of the encrypted layer.
pub(super) const BLOCK: usize = 65_536;

/// Opens the file `name` with read and write access and `intent`.
pub(super) async fn open(
    backend: Backend<'_>,
    name: &str,
    intent: OpenIntent,
) -> (Box<dyn Handle>, OpenAction) {
    backend
        .open(&path(name), opts(intent))
        .await
        .unwrap_or_else(|error| panic!("open {name} {intent:?}: {error:?}"))
}

pub(super) async fn open_file(backend: Backend<'_>, name: &str) -> Box<dyn Handle> {
    open(backend, name, OpenIntent::Open).await.0
}

/// Opens the existing directory `name`; the share root for `""`.
pub(super) async fn open_dir(backend: Backend<'_>, name: &str) -> Box<dyn Handle> {
    match backend.open(&path(name), dir_opts(OpenIntent::Open)).await {
        Ok((handle, _)) => handle,
        Err(error) => panic!("open directory {name}: {error:?}"),
    }
}

pub(super) async fn mkdir(backend: Backend<'_>, name: &str) {
    match backend
        .open(&path(name), dir_opts(OpenIntent::Create))
        .await
    {
        Ok((handle, action)) => {
            assert_eq!(action, OpenAction::Created, "mkdir {name}");
            handle.close().await.unwrap();
        }
        Err(error) => panic!("mkdir {name}: {error:?}"),
    }
}

/// Makes the file `name` hold `data`.
pub(super) async fn put(backend: Backend<'_>, name: &str, data: &[u8]) {
    let (handle, action) = open(backend, name, OpenIntent::Create).await;
    assert_eq!(action, OpenAction::Created, "create {name}");
    write(&*handle, 0, data).await;
    handle.close().await.unwrap();
}

/// Writes `data` at `offset` and checks that all of it was written.
pub(super) async fn write(handle: &dyn Handle, offset: u64, data: &[u8]) {
    let written = handle
        .write(offset, data)
        .await
        .unwrap_or_else(|error| panic!("write {} bytes at {offset}: {error:?}", data.len()));
    assert_eq!(
        usize::try_from(written).unwrap(),
        data.len(),
        "write at {offset}"
    );
}

/// What the file of `handle` holds, read in one call that asks for a byte
/// more than its size.
pub(super) async fn read_all(handle: &dyn Handle) -> Vec<u8> {
    let size = handle.stat().await.unwrap().end_of_file;
    let len = u32::try_from(size + 1).expect("a file that one read can ask for");
    handle.read(0, len).await.unwrap().to_vec()
}

/// What the file `name` holds.
pub(super) async fn contents(backend: Backend<'_>, name: &str) -> Vec<u8> {
    let handle = open_file(backend, name).await;
    let bytes = read_all(&*handle).await;
    handle.close().await.unwrap();
    bytes
}

/// The names `handle` lists for `pattern`, sorted.
pub(super) async fn listed(handle: &dyn Handle, pattern: Option<&str>) -> Vec<String> {
    let entries = handle
        .list_dir(pattern)
        .await
        .unwrap_or_else(|error| panic!("list {pattern:?}: {error:?}"));
    let mut names: Vec<_> = entries.into_iter().map(|entry| entry.info.name).collect();
    names.sort();
    names
}

/// The names in the directory `dir` that match `pattern`, sorted.
pub(super) async fn matching(
    backend: Backend<'_>,
    dir: &str,
    pattern: Option<&str>,
) -> Vec<String> {
    let handle = open_dir(backend, dir).await;
    let names = listed(&*handle, pattern).await;
    handle.close().await.unwrap();
    names
}

/// The names in the directory `dir`, sorted.
pub(super) async fn names(backend: Backend<'_>, dir: &str) -> Vec<String> {
    matching(backend, dir, None).await
}

/// The size that `entries` list for `name`.
pub(super) fn size(entries: &[DirEntry], name: &str) -> Option<u64> {
    entries
        .iter()
        .find(|entry| entry.info.name == name)
        .map(|entry| entry.info.end_of_file)
}

/// `name` shortened to what tells it apart in a failure message.
pub(super) fn shown(name: &str) -> String {
    match name.chars().next() {
        Some(first) if name.len() > 8 => format!("{first}x{}", name.len()),
        _ => name.to_string(),
    }
}

/// `actual` equals `expected`. A mismatch reports the sizes and the first
/// byte that differs, not the bytes.
#[track_caller]
pub(super) fn assert_bytes(actual: &[u8], expected: &[u8], what: &str) {
    if actual != expected {
        let first = actual.iter().zip(expected).position(|(a, b)| a != b);
        panic!(
            "{what}: got {} bytes, expected {}, first difference at {first:?}",
            actual.len(),
            expected.len()
        );
    }
}

/// `result` is an error of the same kind as `expected`.
#[track_caller]
pub(super) fn assert_refused<T>(result: SmbResult<T>, expected: SmbError, what: &str) {
    assert_refused_with(result, &[expected], what);
}

/// `result` is an error of the same kind as one of `expected`. For calls whose
/// error the contract leaves open.
#[track_caller]
pub(super) fn assert_refused_with<T>(result: SmbResult<T>, expected: &[SmbError], what: &str) {
    let Err(error) = result else {
        panic!("{what} succeeded");
    };
    assert!(
        expected
            .iter()
            .any(|kind| mem::discriminant(kind) == mem::discriminant(&error)),
        "{what}: expected one of {expected:?}, got {error:?}"
    );
}
