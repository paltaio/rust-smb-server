//! What reads of file data ask the store for, what they return, and how they
//! follow an object that changes.

use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use tokio::sync::Notify;

use super::fixture::{OLD, foreground, pattern, put};
use super::proxy::{Fault, Reply};
use super::share::{Rig, filetime, heads, is_data_read, open_handle, put_with, reads, requests};
use crate::Handle;
use crate::ntstatus::{
    STATUS_END_OF_FILE, STATUS_OBJECT_NAME_NOT_FOUND, STATUS_UNEXPECTED_IO_ERROR,
};

/// The chunk size of the rigs.
const CHUNK: u32 = 64 * 1024;

/// The offset where chunk `n` starts.
fn edge(n: u64) -> u64 {
    n * u64::from(CHUNK)
}

/// `n` as an index into a slice.
fn at(n: u64) -> usize {
    usize::try_from(n).unwrap()
}

/// An object of `chunks` chunks and `extra` bytes of the pattern from `seed`.
fn object(seed: usize, chunks: u64, extra: usize) -> Bytes {
    pattern(seed, at(edge(chunks)) + extra)
}

/// Up to `len` bytes of `data` from `offset`.
fn part(data: &[u8], offset: u64, len: u32) -> &[u8] {
    let start = at(offset).min(data.len());
    let end = (start + at(u64::from(len))).min(data.len());
    &data[start..end]
}

async fn rig() -> Rig {
    Rig::with(|builder| builder.read_chunk(CHUNK)).await
}

/// The `Range` header of each read of object data so far.
fn ranges(rig: &Rig) -> Vec<String> {
    rig.proxy
        .seen()
        .iter()
        .filter(|seen| is_data_read(seen))
        .filter_map(|seen| seen.header("range").map(str::to_owned))
        .collect()
}

/// Waits until `done` holds.
async fn until(what: &str, done: impl Fn() -> bool) {
    for _ in 0..500 {
        if done() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("timed out waiting for {what}");
}

/// Makes the store answer the next `times` requests for chunk 0 of the object
/// `data` with its bytes under the ETag `other`.
fn answer_with_other_etag(rig: &Rig, data: &[u8], times: usize) {
    let wrong = Reply::new(206, part(data, 0, CHUNK))
        .header(
            "Content-Range",
            &format!("bytes 0-{}/{}", edge(1) - 1, data.len()),
        )
        .header("ETag", "\"other\"")
        .header("Last-Modified", OLD);
    let range = format!("bytes=0-{}", edge(1) - 1);
    rig.proxy.inject(
        move |seen| is_data_read(seen) && seen.header("range") == Some(range.as_str()),
        Fault::Reply(wrong),
        times,
    );
}

/// Makes the store answer the next `times` requests for chunk 0 of the object
/// `data`, which has the ETag `etag`, with its first 10 bytes as if that was
/// the whole object.
fn answer_with_a_short_chunk(rig: &Rig, data: &[u8], etag: &str, times: usize) {
    let short = Reply::new(206, part(data, 0, 10))
        .header("Content-Range", "bytes 0-9/10")
        .header("ETag", etag)
        .header("Last-Modified", OLD);
    let range = format!("bytes=0-{}", edge(1) - 1);
    rig.proxy.inject(
        move |seen| is_data_read(seen) && seen.header("range") == Some(range.as_str()),
        Fault::Reply(short),
        times,
    );
}

/// Reads 10 bytes from 3 bytes into the chunk `chunk` of `handle`, an object
/// that holds `data`.
async fn read_in_chunk(handle: &dyn Handle, data: &[u8], chunk: u64) {
    let start = edge(chunk) + 3;
    let got = handle.read(start, 10).await.unwrap();
    assert_eq!(got, part(data, start, 10));
}

/// All of `handle`, read in pieces of `piece` bytes.
async fn whole(handle: &dyn Handle, piece: u32) -> Vec<u8> {
    let mut data = Vec::new();
    loop {
        let offset = u64::try_from(data.len()).unwrap();
        let got = handle.read(offset, piece).await.unwrap();
        if got.is_empty() {
            return data;
        }
        data.extend_from_slice(&got);
    }
}

#[tokio::test]
async fn reads_return_the_bytes_put_through_s3_at_every_edge() {
    let mut rig = rig().await;
    let data = object(0, 3, 1234);
    put(rig.store(), "data.bin", &data).await;
    let file = rig.smb.open("data.bin").await.unwrap();
    let size = file.size;
    assert_eq!(size, u64::try_from(data.len()).unwrap());

    let cases: &[(u64, u32)] = &[
        (0, 1),
        (0, 100),
        (1, 100),
        (edge(1) - 1, 1),
        (edge(1) - 1, 2),
        (edge(1) - 50, 100),
        (edge(1), 1),
        (edge(1), 100),
        (edge(1) + 1, 10),
        (edge(2) - 1, 2),
        (0, CHUNK),
        (100, CHUNK),
        (edge(1) / 2, CHUNK),
        (edge(1) + 1, CHUNK),
        (edge(3) - 10, 20),
        (edge(3), 100),
        (size - 100, 100),
        (size - 100, 1000),
        (size - 1, 1),
        (size - 1, 100),
    ];
    for &(offset, len) in cases {
        let got = rig.smb.read(file.id, offset, len).await.unwrap();
        assert_eq!(got, part(&data, offset, len), "{offset} {len}");
    }
    for offset in [size, size + 1, size + edge(5)] {
        assert_eq!(
            rig.smb.read(file.id, offset, 10).await,
            Err(STATUS_END_OF_FILE),
            "{offset}"
        );
    }
    rig.smb.close(file.id).await;

    for piece in [1000, 4096, CHUNK - 1, CHUNK] {
        assert_eq!(
            rig.smb.contents("data.bin", piece).await,
            data.to_vec(),
            "pieces of {piece}"
        );
    }
}

#[tokio::test]
async fn a_read_that_spans_more_chunks_than_a_version_keeps_returns_all_of_them() {
    let rig = rig().await;
    let data = object(0, 9, 77);
    put(rig.store(), "data.bin", &data).await;
    let handle = open_handle(&rig.backend, "data.bin").await;
    let size = u64::try_from(data.len()).unwrap();
    for (keep, cap) in [(4, usize::MAX), (2, usize::MAX), (4, at(edge(3))), (1, 1)] {
        rig.backend.limit_read_chunks(keep, cap);
        for (offset, len) in [
            (0, u32::try_from(size).unwrap()),
            (100, 8 * CHUNK),
            (edge(1) - 1, 3),
            (size - 1000, 5000),
        ] {
            let got = handle.read(offset, len).await.unwrap();
            assert_eq!(got, part(&data, offset, len), "{keep} {cap} {offset} {len}");
            assert!(rig.backend.read_chunk_bytes() <= cap);
        }
        assert_eq!(whole(&*handle, 1 << 20).await, data.to_vec());
    }
}

#[tokio::test]
async fn objects_of_a_whole_number_of_chunks_and_of_one_byte_read_back() {
    let mut rig = rig().await;
    let exact = object(5, 2, 0);
    put(rig.store(), "exact", &exact).await;
    put(rig.store(), "one", b"x").await;
    assert_eq!(rig.smb.contents("exact", 100).await, exact.to_vec());
    assert_eq!(rig.smb.contents("one", 100).await, b"x");
    assert_eq!(
        ranges(&rig),
        ["bytes=0-65535", "bytes=65536-131071", "bytes=0-0"]
    );
    assert_eq!(rig.smb.contents("exact", CHUNK).await, exact.to_vec());
    assert_eq!(rig.smb.contents("one", CHUNK).await, b"x");

    let file = rig.smb.open("exact").await.unwrap();
    let before = ranges(&rig).len();
    assert_eq!(
        rig.smb.read(file.id, edge(2) - 1, 10).await.unwrap(),
        &exact[exact.len() - 1..]
    );
    assert_eq!(
        rig.smb.read(file.id, edge(2), 10).await,
        Err(STATUS_END_OF_FILE)
    );
    assert_eq!(ranges(&rig)[before..], ["bytes=65536-131071"]);
}

#[tokio::test]
async fn a_read_asks_for_the_chunk_that_holds_it_with_the_etag_of_the_open() {
    let mut rig = rig().await;
    let data = object(0, 2, 100);
    let etag = put(rig.store(), "data.bin", &data).await;
    let file = rig.smb.open("data.bin").await.unwrap();
    for (offset, len) in [(10, 20), (edge(1) + 5, 10), (edge(2) + 50, 10)] {
        let got = rig.smb.read(file.id, offset, len).await.unwrap();
        assert_eq!(got, part(&data, offset, len));
    }
    assert_eq!(
        ranges(&rig),
        ["bytes=0-65535", "bytes=65536-131071", "bytes=131072-131171"]
    );
    for read in rig.proxy.seen().iter().filter(|seen| is_data_read(seen)) {
        assert_eq!(read.header("if-match"), Some(etag.as_str()));
    }
}

#[tokio::test]
async fn a_read_inside_a_fetched_chunk_makes_no_request() {
    let mut rig = rig().await;
    let data = object(0, 3, 10);
    put(rig.store(), "data.bin", &data).await;
    let first = rig.smb.open("data.bin").await.unwrap();
    let sent = requests(&rig.proxy);
    let expect = |reads_so_far: usize, rig: &Rig| {
        assert_eq!(reads(&rig.proxy), reads_so_far);
        assert_eq!(requests(&rig.proxy) - sent, reads_so_far);
    };

    for (offset, len) in [(10, 100), (5000, 100), (edge(1) - 100, 100), (0, CHUNK)] {
        let got = rig.smb.read(first.id, offset, len).await.unwrap();
        assert_eq!(got, part(&data, offset, len));
        expect(1, &rig);
    }
    // A read that crosses into the next chunk fetches that chunk only.
    let got = rig.smb.read(first.id, edge(1) - 50, 100).await.unwrap();
    assert_eq!(got, part(&data, edge(1) - 50, 100));
    expect(2, &rig);

    // Another open of the object reads the same chunks.
    let second = rig.smb.open("data.bin").await.unwrap();
    assert_eq!(
        rig.smb.read(second.id, 20, 50).await.unwrap(),
        part(&data, 20, 50)
    );
    assert_eq!(
        rig.smb.read(second.id, edge(1) + 1, 10).await.unwrap(),
        part(&data, edge(1) + 1, 10)
    );
    rig.smb.close(first.id).await;
    assert_eq!(
        rig.smb.read(second.id, 30, 10).await.unwrap(),
        part(&data, 30, 10)
    );
    expect(2, &rig);

    // A handle opened on the backend itself does too.
    let direct = open_handle(&rig.backend, "data.bin").await;
    assert_eq!(direct.read(40, 10).await.unwrap(), part(&data, 40, 10));
    expect(2, &rig);

    // A chunk not read yet is fetched once, whoever reads it.
    assert_eq!(
        direct.read(edge(2) + 7, 10).await.unwrap(),
        part(&data, edge(2) + 7, 10)
    );
    assert_eq!(
        rig.smb.read(second.id, edge(2) + 8, 10).await.unwrap(),
        part(&data, edge(2) + 8, 10)
    );
    expect(3, &rig);
}

#[tokio::test]
async fn chunks_are_kept_until_the_last_handle_on_their_version_closes() {
    let mut rig = rig().await;
    let data = object(0, 2, 10);
    put(rig.store(), "f.bin", &data).await;
    let first = rig.smb.open("f.bin").await.unwrap();
    let second = rig.smb.open("f.bin").await.unwrap();
    let direct = open_handle(&rig.backend, "f.bin").await;
    assert_eq!(
        rig.smb.read(first.id, 10, 10).await.unwrap(),
        part(&data, 10, 10)
    );
    assert_eq!(reads(&rig.proxy), 1);
    assert_eq!(rig.backend.read_chunk_bytes(), at(edge(1)));

    // The chunk stays while a handle on the version is open.
    rig.smb.close(first.id).await;
    assert_eq!(
        rig.smb.read(second.id, 20, 10).await.unwrap(),
        part(&data, 20, 10)
    );
    rig.smb.close(second.id).await;
    assert_eq!(direct.read(30, 10).await.unwrap(), part(&data, 30, 10));
    assert_eq!(reads(&rig.proxy), 1);
    assert_eq!(rig.backend.read_chunk_bytes(), at(edge(1)));

    // The last close drops it, and a handle opened later fetches again.
    direct.close().await.unwrap();
    assert_eq!(rig.backend.read_chunk_bytes(), 0);
    let later = rig.smb.open("f.bin").await.unwrap();
    assert_eq!(
        rig.smb.read(later.id, 10, 10).await.unwrap(),
        part(&data, 10, 10)
    );
    assert_eq!(reads(&rig.proxy), 2);
    assert_eq!(rig.backend.read_chunk_bytes(), at(edge(1)));

    // A handle that is dropped ends its hold the same way.
    let dropped = open_handle(&rig.backend, "f.bin").await;
    rig.smb.close(later.id).await;
    assert_eq!(dropped.read(40, 10).await.unwrap(), part(&data, 40, 10));
    assert_eq!(reads(&rig.proxy), 2);
    drop(dropped);
    assert_eq!(rig.backend.read_chunk_bytes(), 0);
}

#[tokio::test]
async fn a_handle_that_follows_an_overwrite_keeps_the_new_version_while_it_is_open() {
    let rig = rig().await;
    let old = object(0, 2, 0);
    let new = object(3, 2, 0);
    put(rig.store(), "f.bin", &old).await;
    let stale = open_handle(&rig.backend, "f.bin").await;
    let moved = open_handle(&rig.backend, "f.bin").await;
    assert_eq!(stale.read(0, 10).await.unwrap(), part(&old, 0, 10));
    assert_eq!(rig.backend.read_chunk_bytes(), at(edge(1)));
    put(rig.store(), "f.bin", &new).await;

    // The refresh of one handle moves its hold to the new version.
    assert_eq!(
        moved.read(edge(1), 10).await.unwrap(),
        part(&new, edge(1), 10)
    );
    assert_eq!(rig.backend.read_chunk_bytes(), at(edge(1)));
    stale.close().await.unwrap();
    assert_eq!(rig.backend.read_chunk_bytes(), at(edge(1)));
    moved.close().await.unwrap();
    assert_eq!(rig.backend.read_chunk_bytes(), 0);
}

#[tokio::test]
async fn reads_of_nothing_and_reads_past_the_end_make_no_request() {
    let mut rig = rig().await;
    put(rig.store(), "data.bin", pattern(0, 1000)).await;
    let file = rig.smb.open("data.bin").await.unwrap();
    let handle = open_handle(&rig.backend, "data.bin").await;
    let sent = requests(&rig.proxy);
    assert!(handle.read(5, 0).await.unwrap().is_empty());
    assert!(handle.read(5000, 0).await.unwrap().is_empty());
    assert_eq!(rig.smb.read(file.id, 5, 0).await, Ok(Vec::new()));
    assert_eq!(
        rig.smb.read(file.id, 1000, 10).await,
        Err(STATUS_END_OF_FILE)
    );
    assert!(handle.read(1000, 10).await.unwrap().is_empty());
    assert!(handle.read(u64::MAX, u32::MAX).await.unwrap().is_empty());
    assert_eq!(requests(&rig.proxy), sent);
}

#[tokio::test]
async fn a_version_keeps_its_chunk_limit_and_all_versions_the_byte_cap() {
    let rig = rig().await;
    let data = object(0, 4, 0);
    put(rig.store(), "a", &data).await;
    put(rig.store(), "b", &data).await;
    let a = open_handle(&rig.backend, "a").await;
    let b = open_handle(&rig.backend, "b").await;

    // Two chunks of a version: reading a third drops the least recently used.
    rig.backend.limit_read_chunks(2, usize::MAX);
    for (chunk, total) in [
        (0, 1),
        (1, 2),
        (2, 3),
        (2, 3),
        (1, 3),
        (0, 4),
        (1, 4),
        (2, 5),
    ] {
        read_in_chunk(&*a, &data, chunk).await;
        assert_eq!(reads(&rig.proxy), total, "chunk {chunk}");
        assert!(rig.backend.read_chunk_bytes() <= at(edge(2)));
    }

    // Two chunks of all: the least recently used of both objects goes.
    let cap = at(edge(2));
    rig.backend.limit_read_chunks(4, cap);
    let before = reads(&rig.proxy);
    for (handle, chunk, total) in [
        (&a, 0, 1),
        (&a, 1, 2),
        (&b, 0, 3),
        (&a, 0, 4),
        (&b, 0, 4),
        (&a, 1, 5),
    ] {
        read_in_chunk(&**handle, &data, chunk).await;
        assert_eq!(reads(&rig.proxy) - before, total, "chunk {chunk}");
        assert!(rig.backend.read_chunk_bytes() <= cap);
    }
    assert_eq!(rig.backend.read_chunk_bytes(), cap);
}

#[tokio::test]
async fn a_read_after_an_outside_overwrite_returns_the_new_object_and_never_a_mix() {
    let mut rig = rig().await;
    let old = object(0, 3, 10);
    let new = object(7, 2, 55);
    put_with(rig.store(), "f.bin", &old, &[("mtime", "1700000000")]).await;
    let handle = open_handle(&rig.backend, "f.bin").await;
    let info = handle.stat().await.unwrap();
    assert_eq!(info.end_of_file, u64::try_from(old.len()).unwrap());
    assert_eq!(info.last_write_time, filetime(1_700_000_000, 0));
    assert_eq!(handle.read(0, 100).await.unwrap(), &old[..100]);

    put_with(rig.store(), "f.bin", &new, &[("mtime", "1800000000")]).await;
    let (heads_before, reads_before) = (heads(&rig.proxy), reads(&rig.proxy));

    // Chunk 0 is kept from the old object, chunk 1 is not.
    let got = handle.read(edge(1) - 100, 200).await.unwrap();
    assert_eq!(got, part(&new, edge(1) - 100, 200));
    assert_eq!(heads(&rig.proxy) - heads_before, 1, "one HEAD");
    // The refused request for chunk 1, then both chunks of the new object.
    assert_eq!(reads(&rig.proxy) - reads_before, 3);
    assert_eq!(rig.backend.read_chunk_bytes(), at(edge(2)));

    let info = handle.stat().await.unwrap();
    assert_eq!(info.end_of_file, u64::try_from(new.len()).unwrap());
    assert_eq!(info.last_write_time, filetime(1_800_000_000, 0));
    assert_eq!(whole(&*handle, 100_000).await, new.to_vec());
    assert!(
        handle
            .read(u64::try_from(old.len()).unwrap() - 5, 5)
            .await
            .unwrap()
            .is_empty()
    );
    assert_eq!(heads(&rig.proxy) - heads_before, 1);

    // The refresh caches nothing: an open looks the object up again, with a
    // HEAD and a check for keys below it.
    let key_checks = |rig: &Rig| rig.proxy.count(|seen| seen.has_param("max-keys"));
    let key_checks_before = key_checks(&rig);
    let again = rig.smb.open("f.bin").await.unwrap();
    assert_eq!(again.size, u64::try_from(new.len()).unwrap());
    assert_eq!(heads(&rig.proxy) - heads_before, 2);
    assert_eq!(key_checks(&rig) - key_checks_before, 1);
}

#[tokio::test]
async fn every_handle_on_an_object_follows_an_outside_overwrite() {
    let rig = rig().await;
    let old = object(0, 2, 0);
    let new = object(3, 2, 0);
    put(rig.store(), "f.bin", &old).await;
    let first = open_handle(&rig.backend, "f.bin").await;
    let second = open_handle(&rig.backend, "f.bin").await;
    assert_eq!(first.read(0, 10).await.unwrap(), &old[..10]);
    put(rig.store(), "f.bin", &new).await;

    // The first read of a chunk not kept refreshes.
    assert_eq!(
        second.read(edge(1), 10).await.unwrap(),
        part(&new, edge(1), 10)
    );
    // The other handle reads the new object from then on, from its own refresh.
    assert_eq!(whole(&*first, 70_000).await, new.to_vec());
    assert_eq!(whole(&*second, 70_000).await, new.to_vec());
}

#[tokio::test]
async fn a_read_of_an_object_deleted_outside_fails_as_not_found() {
    let mut rig = rig().await;
    put(rig.store(), "f.bin", object(0, 3, 0)).await;
    let file = rig.smb.open("f.bin").await.unwrap();
    assert!(rig.smb.read(file.id, 0, 10).await.is_ok());
    rig.store()
        .delete_object("f.bin", foreground())
        .await
        .unwrap();
    let (heads_before, reads_before) = (heads(&rig.proxy), reads(&rig.proxy));
    assert_eq!(
        rig.smb.read(file.id, edge(1) + 1, 10).await,
        Err(STATUS_OBJECT_NAME_NOT_FOUND)
    );
    assert_eq!(heads(&rig.proxy) - heads_before, 1, "one refresh");
    assert_eq!(reads(&rig.proxy) - reads_before, 1, "no read after it");
    assert_eq!(rig.backend.read_chunk_bytes(), 0);
    assert_eq!(
        rig.smb.open("f.bin").await.unwrap_err(),
        STATUS_OBJECT_NAME_NOT_FOUND
    );
}

#[tokio::test]
async fn a_store_that_answers_a_range_past_the_start_with_200_serves_no_bytes() {
    let mut rig = rig().await;
    let data = object(0, 3, 0);
    let etag = put(rig.store(), "f.bin", &data).await;
    let file = rig.smb.open("f.bin").await.unwrap();
    let from_chunk_1 = format!("bytes={}-", edge(1));
    rig.proxy.inject(
        move |seen| {
            is_data_read(seen)
                && seen
                    .header("range")
                    .is_some_and(|range| range.starts_with(&from_chunk_1))
        },
        Fault::Reply(
            Reply::new(200, &data[..])
                .header("ETag", &etag)
                .header("Last-Modified", OLD),
        ),
        usize::MAX,
    );
    let heads_before = heads(&rig.proxy);
    assert_eq!(
        rig.smb.read(file.id, edge(1) + 5, 10).await,
        Err(STATUS_UNEXPECTED_IO_ERROR)
    );
    assert_eq!(rig.backend.read_chunk_bytes(), 0, "nothing was kept");
    assert_eq!(heads(&rig.proxy), heads_before, "the object did not change");

    rig.proxy.clear_rules();
    assert_eq!(
        rig.smb.read(file.id, edge(1) + 5, 10).await.unwrap(),
        part(&data, edge(1) + 5, 10)
    );
}

#[tokio::test]
async fn an_answer_with_another_etag_makes_the_read_refresh_and_try_once_more() {
    let mut rig = rig().await;
    let data = object(0, 2, 0);
    put(rig.store(), "f.bin", &data).await;
    let file = rig.smb.open("f.bin").await.unwrap();
    answer_with_other_etag(&rig, &data, 1);
    let heads_before = heads(&rig.proxy);
    assert_eq!(rig.smb.read(file.id, 10, 20).await.unwrap(), &data[10..30]);
    assert_eq!(heads(&rig.proxy) - heads_before, 1);
    assert_eq!(reads(&rig.proxy), 2);
}

#[tokio::test]
async fn an_answer_that_keeps_the_wrong_etag_fails_the_read_after_one_refresh() {
    let mut rig = rig().await;
    let data = object(0, 2, 0);
    put(rig.store(), "f.bin", &data).await;
    let file = rig.smb.open("f.bin").await.unwrap();
    answer_with_other_etag(&rig, &data, usize::MAX);
    let heads_before = heads(&rig.proxy);
    assert_eq!(
        rig.smb.read(file.id, 10, 20).await,
        Err(STATUS_UNEXPECTED_IO_ERROR)
    );
    assert_eq!(heads(&rig.proxy) - heads_before, 1);
    assert_eq!(reads(&rig.proxy), 2);
    assert_eq!(rig.backend.read_chunk_bytes(), 0);
}

#[tokio::test]
async fn an_answer_of_another_length_makes_the_read_refresh_and_try_once_more() {
    let mut rig = rig().await;
    let data = object(0, 2, 0);
    let etag = put(rig.store(), "f.bin", &data).await;
    let file = rig.smb.open("f.bin").await.unwrap();
    answer_with_a_short_chunk(&rig, &data, &etag, 1);
    let heads_before = heads(&rig.proxy);
    assert_eq!(rig.smb.read(file.id, 10, 20).await.unwrap(), &data[10..30]);
    assert_eq!(heads(&rig.proxy) - heads_before, 1);
    assert_eq!(reads(&rig.proxy), 2);
}

#[tokio::test]
async fn an_answer_that_keeps_the_wrong_length_fails_the_read_after_one_refresh() {
    let mut rig = rig().await;
    let data = object(0, 2, 0);
    let etag = put(rig.store(), "f.bin", &data).await;
    let file = rig.smb.open("f.bin").await.unwrap();
    answer_with_a_short_chunk(&rig, &data, &etag, usize::MAX);
    let heads_before = heads(&rig.proxy);
    assert_eq!(
        rig.smb.read(file.id, 10, 20).await,
        Err(STATUS_UNEXPECTED_IO_ERROR)
    );
    assert_eq!(heads(&rig.proxy) - heads_before, 1);
    assert_eq!(reads(&rig.proxy), 2);
    assert_eq!(rig.backend.read_chunk_bytes(), 0);
}

#[tokio::test]
async fn a_reader_waiting_for_a_dropped_fetch_fetches_the_chunk_itself() {
    let rig = rig().await;
    let data = object(0, 2, 0);
    put(rig.store(), "f.bin", &data).await;
    let handle: Arc<dyn Handle> = Arc::from(open_handle(&rig.backend, "f.bin").await);
    rig.proxy.inject(is_data_read, Fault::Stall, 1);
    let leader = tokio::spawn({
        let handle = Arc::clone(&handle);
        async move { handle.read(0, 10).await }
    });
    until("the stalled read", || reads(&rig.proxy) == 1).await;
    let follower = tokio::spawn({
        let handle = Arc::clone(&handle);
        async move { handle.read(20, 10).await }
    });
    until("the follower to wait", || {
        rig.backend.read_chunk_waiters() == 1
    })
    .await;
    leader.abort();
    assert_eq!(follower.await.unwrap().unwrap(), part(&data, 20, 10));
    assert_eq!(reads(&rig.proxy), 2);
}

#[tokio::test]
async fn a_reader_waiting_for_a_fetch_that_runs_out_of_time_fetches_the_chunk_itself() {
    let rig = Rig::with(|builder| {
        builder
            .read_chunk(CHUNK)
            .request_timeout(Duration::from_secs(4))
    })
    .await;
    let data = object(0, 2, 0);
    put(rig.store(), "f.bin", &data).await;
    let handle: Arc<dyn Handle> = Arc::from(open_handle(&rig.backend, "f.bin").await);
    rig.proxy.inject(is_data_read, Fault::Stall, 1);
    let leader = tokio::spawn({
        let handle = Arc::clone(&handle);
        async move { handle.read(0, 10).await }
    });
    until("the stalled read", || reads(&rig.proxy) == 1).await;
    // The follower starts two seconds after the leader, so its own deadline
    // is two seconds after the leader's.
    tokio::time::sleep(Duration::from_secs(2)).await;
    let follower = tokio::spawn({
        let handle = Arc::clone(&handle);
        async move { handle.read(20, 10).await }
    });
    until("the follower to wait", || {
        rig.backend.read_chunk_waiters() == 1
    })
    .await;
    assert!(leader.await.unwrap().is_err());
    assert_eq!(follower.await.unwrap().unwrap(), part(&data, 20, 10));
    assert_eq!(reads(&rig.proxy), 2);
}

#[tokio::test]
async fn a_reader_waiting_for_a_fetch_that_ends_on_a_transient_error_fetches_the_chunk_itself() {
    let rig = rig().await;
    let data = object(0, 2, 0);
    put(rig.store(), "f.bin", &data).await;
    let handle: Arc<dyn Handle> = Arc::from(open_handle(&rig.backend, "f.bin").await);
    // The leader's first four attempts fail at once and its fifth when the
    // gate opens. It gives up on that error with the follower waiting.
    let gate = Arc::new(Notify::new());
    let slow_down = Reply::error(503, "SlowDown");
    rig.proxy
        .inject(is_data_read, Fault::Reply(slow_down.clone()), 4);
    rig.proxy.inject(
        is_data_read,
        Fault::HoldReply(Arc::clone(&gate), slow_down),
        1,
    );
    let leader = tokio::spawn({
        let handle = Arc::clone(&handle);
        async move { handle.read(0, 10).await }
    });
    until("the fifth attempt", || reads(&rig.proxy) == 5).await;
    let follower = tokio::spawn({
        let handle = Arc::clone(&handle);
        async move { handle.read(20, 10).await }
    });
    until("the follower to wait", || {
        rig.backend.read_chunk_waiters() == 1
    })
    .await;
    gate.notify_one();
    assert!(leader.await.unwrap().is_err());
    assert_eq!(follower.await.unwrap().unwrap(), part(&data, 20, 10));
    assert_eq!(reads(&rig.proxy), 6);
}

#[tokio::test]
async fn reads_of_one_missing_chunk_at_the_same_time_make_one_request() {
    let rig = rig().await;
    let data = object(0, 2, 0);
    put(rig.store(), "f.bin", &data).await;
    let first: Arc<dyn Handle> = Arc::from(open_handle(&rig.backend, "f.bin").await);
    let second: Arc<dyn Handle> = Arc::from(open_handle(&rig.backend, "f.bin").await);
    let gate = Arc::new(Notify::new());
    rig.proxy
        .inject(is_data_read, Fault::Hold(Arc::clone(&gate)), 1);
    let mut running = Vec::new();
    for (n, handle) in [&first, &first, &second, &second].into_iter().enumerate() {
        let handle = Arc::clone(handle);
        let offset = 100 * u64::try_from(n).unwrap();
        running.push(tokio::spawn(async move { handle.read(offset, 50).await }));
    }
    until("three readers to wait", || {
        rig.backend.read_chunk_waiters() == 3
    })
    .await;
    gate.notify_one();
    for (n, read) in running.into_iter().enumerate() {
        let offset = 100 * u64::try_from(n).unwrap();
        assert_eq!(read.await.unwrap().unwrap(), part(&data, offset, 50));
    }
    assert_eq!(reads(&rig.proxy), 1);
}

#[tokio::test]
async fn the_refresh_of_a_read_counts_against_the_deadline_of_the_read() {
    let mut rig = Rig::with(|builder| {
        builder
            .read_chunk(CHUNK)
            .request_timeout(Duration::from_secs(2))
    })
    .await;
    put(rig.store(), "f.bin", object(0, 2, 0)).await;
    let file = rig.smb.open("f.bin").await.unwrap();
    put(rig.store(), "f.bin", object(1, 2, 0)).await;

    // The refused read answers after 1.2 s, and the refresh never answers.
    let gate = Arc::new(Notify::new());
    rig.proxy
        .inject(is_data_read, Fault::Hold(Arc::clone(&gate)), 1);
    let target = format!("/{}/f.bin", rig.bucket.name);
    rig.proxy.inject(
        move |seen| seen.method == "HEAD" && seen.target == target,
        Fault::Stall,
        usize::MAX,
    );
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(1200)).await;
        gate.notify_one();
    });
    let started = Instant::now();
    assert_eq!(
        rig.smb.read(file.id, 0, 10).await,
        Err(STATUS_UNEXPECTED_IO_ERROR)
    );
    let elapsed = started.elapsed();
    assert!(elapsed >= Duration::from_millis(1800), "{elapsed:?}");
    assert!(elapsed < Duration::from_millis(3000), "{elapsed:?}");
}
