//! Reads, writes, truncation and the sizes they leave.

use super::helpers::{
    BLOCK, Backend, assert_bytes, contents, mkdir, open, open_dir, open_file, put, read_all, size,
    write,
};
use crate::backend::{OpenAction, OpenIntent};
use crate::tests::data::{apply, nonzero_pattern, xorshift};

/// A read answers fewer bytes than asked only at the end of the file: the
/// server sends the bytes of one read as the whole answer.
pub(super) async fn reads_fill_to_the_end(backend: Backend<'_>) {
    let data = nonzero_pattern(200_000);
    put(backend, "f", &data).await;
    let handle = open_file(backend, "f").await;
    let reads: [(usize, usize); 9] = [
        (0, 300_000),
        (0, 200_000),
        (1, 199_999),
        (65_530, 20),
        (2 * BLOCK - 1, 2),
        (100_000, 1),
        (199_990, 100),
        (199_999, 1),
        (BLOCK, BLOCK),
    ];
    for (from, len) in reads {
        let to = (from + len).min(data.len());
        assert_bytes(
            &handle
                .read(u64::try_from(from).unwrap(), u32::try_from(len).unwrap())
                .await
                .unwrap(),
            &data[from..to],
            &format!("read {len} at {from}"),
        );
    }
    for offset in [200_000, 200_001, 1_000_000] {
        let bytes = handle.read(offset, 10).await.unwrap();
        assert!(bytes.is_empty(), "read at {offset}");
    }
    assert!(handle.read(5, 0).await.unwrap().is_empty());
    handle.close().await.unwrap();

    let whole_blocks = nonzero_pattern(2 * BLOCK);
    let end = whole_blocks.len();
    put(backend, "g", &whole_blocks).await;
    let handle = open_file(backend, "g").await;
    assert_bytes(
        &handle.read(end as u64 - 1, 10).await.unwrap(),
        &whole_blocks[end - 1..],
        "read across the last byte",
    );
    assert!(handle.read(end as u64, 10).await.unwrap().is_empty());
    handle.close().await.unwrap();
}

pub(super) async fn write_owned_and_flush_keep_the_data(backend: Backend<'_>) {
    let (handle, _) = open(backend, "f", OpenIntent::Create).await;
    assert_eq!(handle.write(0, b"hello").await.unwrap(), 5);
    assert_eq!(handle.write_owned(5, b" world".to_vec()).await.unwrap(), 6);
    handle.flush().await.unwrap();
    assert_bytes(&read_all(&*handle).await, b"hello world", "the file");
    handle.close().await.unwrap();
    assert_bytes(&contents(backend, "f").await, b"hello world", "the file");
}

pub(super) async fn a_write_past_the_end_leaves_a_gap_of_zeros(backend: Backend<'_>) {
    let (handle, _) = open(backend, "f", OpenIntent::Create).await;
    let mut model = Vec::new();
    for (offset, data) in [
        (0, &b"abc"[..]),
        (100_000, b"tail!"),
        (100_005, b"z"),
        (300_000, b"far"),
    ] {
        write(&*handle, offset as u64, data).await;
        apply(&mut model, offset, data);
        assert_eq!(handle.stat().await.unwrap().end_of_file, model.len() as u64);
        assert_bytes(
            &read_all(&*handle).await,
            &model,
            &format!("after a write at {offset}"),
        );
    }
    handle.close().await.unwrap();

    let (handle, _) = open(backend, "g", OpenIntent::Create).await;
    write(&*handle, 70_000, &[9; 4]).await;
    let mut model = vec![0; 70_004];
    model[70_000..].fill(9);
    assert_bytes(
        &read_all(&*handle).await,
        &model,
        "a write into an empty file",
    );
    handle.close().await.unwrap();
}

pub(super) async fn a_write_inside_the_file_keeps_the_rest(backend: Backend<'_>) {
    let mut model = nonzero_pattern(200_000);
    put(backend, "f", &model).await;
    let handle = open_file(backend, "f").await;
    for (offset, data) in [
        (65_530, vec![1; 10]),
        (0, vec![2]),
        (2 * BLOCK, vec![3; BLOCK]),
        (199_999, vec![4; 3]),
        (10, vec![5; 100_000]),
    ] {
        write(&*handle, offset as u64, &data).await;
        apply(&mut model, offset, &data);
        assert_bytes(
            &read_all(&*handle).await,
            &model,
            &format!("after {} bytes at {offset}", data.len()),
        );
    }
    handle.close().await.unwrap();
    assert_bytes(
        &contents(backend, "f").await,
        &model,
        "the file once closed",
    );
}

pub(super) async fn truncate_shrinks_the_file(backend: Backend<'_>) {
    let data = nonzero_pattern(200_000);
    put(backend, "f", &data).await;
    let handle = open_file(backend, "f").await;
    for len in [
        199_999,
        2 * BLOCK + 1,
        2 * BLOCK,
        70_000,
        BLOCK,
        BLOCK - 1,
        1,
        0,
    ] {
        handle.truncate(len as u64).await.unwrap();
        assert_eq!(handle.stat().await.unwrap().end_of_file, len as u64);
        assert_bytes(
            &read_all(&*handle).await,
            &data[..len],
            &format!("truncated to {len}"),
        );
    }
    write(&*handle, 0, b"again").await;
    assert_bytes(
        &read_all(&*handle).await,
        b"again",
        "written after truncation to 0",
    );
    handle.close().await.unwrap();
    assert_bytes(
        &contents(backend, "f").await,
        b"again",
        "the file once closed",
    );
}

pub(super) async fn truncate_extends_with_zeros(backend: Backend<'_>) {
    let (handle, _) = open(backend, "f", OpenIntent::Create).await;
    handle.truncate(0).await.unwrap();
    assert_eq!(handle.stat().await.unwrap().end_of_file, 0);
    assert!(read_all(&*handle).await.is_empty());
    write(&*handle, 0, b"0123456789").await;
    let mut model = b"0123456789".to_vec();
    for len in [10, 70_000, 70_001, 2 * BLOCK, 300_000] {
        handle.truncate(len as u64).await.unwrap();
        model.resize(len, 0);
        assert_eq!(handle.stat().await.unwrap().end_of_file, len as u64);
        assert_bytes(
            &read_all(&*handle).await,
            &model,
            &format!("extended to {len}"),
        );
    }
    write(&*handle, 299_990, b"end").await;
    apply(&mut model, 299_990, b"end");
    write(&*handle, 5, b"mid").await;
    apply(&mut model, 5, b"mid");
    assert_bytes(&read_all(&*handle).await, &model, "written after extension");
    handle.close().await.unwrap();
}

pub(super) async fn shrinking_then_extending_brings_back_no_data(backend: Backend<'_>) {
    put(backend, "f", &nonzero_pattern(100_000)).await;
    let handle = open_file(backend, "f").await;
    handle.truncate(70_000).await.unwrap();
    handle.truncate(150_000).await.unwrap();
    let bytes = read_all(&*handle).await;
    assert_eq!(bytes.len(), 150_000);
    assert_bytes(&bytes[..70_000], &nonzero_pattern(70_000), "what was kept");
    assert!(
        bytes[70_000..].iter().all(|&byte| byte == 0),
        "what was cut reads as zeros"
    );
    handle.close().await.unwrap();
}

pub(super) async fn truncating_to_the_size_changes_nothing(backend: Backend<'_>) {
    for len in [0, 1, BLOCK, 100_000] {
        let name = format!("f{len}");
        let data = nonzero_pattern(len);
        put(backend, &name, &data).await;
        let handle = open_file(backend, &name).await;
        handle.truncate(len as u64).await.unwrap();
        assert_bytes(&read_all(&*handle).await, &data, &format!("size {len}"));
        handle.close().await.unwrap();
    }
}

pub(super) async fn writes_and_truncates_match_a_model(backend: Backend<'_>) {
    let mut next = xorshift(0x2545_f491_4f6c_dd1d);
    let mut model: Vec<u8> = Vec::new();
    let (handle, _) = open(backend, "m", OpenIntent::Create).await;
    for step in 0..48 {
        let roll = next() % 8;
        let what = if roll < 5 {
            let offset = usize::try_from(next() % (model.len() as u64 + 80_000)).unwrap();
            let len = usize::try_from(1 + next() % 30_000).unwrap();
            let data: Vec<u8> = (0..len)
                .map(|_| u8::try_from(next() % 255).unwrap() + 1)
                .collect();
            write(&*handle, offset as u64, &data).await;
            apply(&mut model, offset, &data);
            format!("write {len} at {offset}")
        } else if roll < 7 && !model.is_empty() {
            let len = usize::try_from(next() % model.len() as u64).unwrap();
            handle.truncate(len as u64).await.unwrap();
            model.truncate(len);
            format!("shrink to {len}")
        } else {
            let len = model.len() + usize::try_from(1 + next() % 90_000).unwrap();
            handle.truncate(len as u64).await.unwrap();
            model.resize(len, 0);
            format!("extend to {len}")
        };
        assert_eq!(
            handle.stat().await.unwrap().end_of_file,
            model.len() as u64,
            "size after step {step}, {what}"
        );
        assert_bytes(
            &read_all(&*handle).await,
            &model,
            &format!("content after step {step}, {what}"),
        );
    }
    handle.close().await.unwrap();
    assert_bytes(
        &contents(backend, "m").await,
        &model,
        "the file once closed",
    );
}

pub(super) async fn stat_and_listings_report_the_size(backend: Backend<'_>) {
    mkdir(backend, "d").await;
    put(backend, "d\\f", &nonzero_pattern(200_000)).await;

    let dir = open_dir(backend, "d").await;
    let handle = open_file(backend, "d\\f").await;
    assert_eq!(handle.stat().await.unwrap().end_of_file, 200_000);
    assert_eq!(size(&dir.list_dir(None).await.unwrap(), "f"), Some(200_000));

    handle.truncate(70_000).await.unwrap();
    assert_eq!(handle.stat().await.unwrap().end_of_file, 70_000);
    assert_eq!(size(&dir.list_dir(None).await.unwrap(), "f"), Some(70_000));
    write(&*handle, 70_000, b"x").await;
    assert_eq!(handle.stat().await.unwrap().end_of_file, 70_001);
    assert_eq!(size(&dir.list_dir(None).await.unwrap(), "f"), Some(70_001));
    assert_eq!(
        size(&dir.list_dir(Some("f")).await.unwrap(), "f"),
        Some(70_001)
    );
    handle.close().await.unwrap();
    dir.close().await.unwrap();

    let dir = open_dir(backend, "d").await;
    assert_eq!(
        size(&dir.list_dir(Some("f")).await.unwrap(), "f"),
        Some(70_001)
    );
    dir.close().await.unwrap();
}

pub(super) async fn handles_of_one_file_see_each_others_writes(backend: Backend<'_>) {
    let (first, _) = open(backend, "f", OpenIntent::Create).await;
    let second = open_file(backend, "f").await;
    write(&*first, 0, b"hello").await;
    assert_bytes(&read_all(&*second).await, b"hello", "the second handle");
    write(&*second, 5, b" there").await;
    assert_bytes(&read_all(&*first).await, b"hello there", "the first handle");
    second.truncate(3).await.unwrap();
    assert_eq!(first.stat().await.unwrap().end_of_file, 3);
    assert_bytes(&read_all(&*first).await, b"hel", "the first handle");
    first.close().await.unwrap();
    second.close().await.unwrap();
    assert_bytes(&contents(backend, "f").await, b"hel", "the file");
}

pub(super) async fn two_handles_write_alternating_ranges(backend: Backend<'_>) {
    let (first, _) = open(backend, "f", OpenIntent::Create).await;
    let second = open_file(backend, "f").await;
    let mut model = Vec::new();
    for chunk in 0..20_usize {
        let offset = chunk * 10_007;
        let data = vec![u8::try_from(chunk).unwrap() + 1; 10_007];
        let handle = if chunk.is_multiple_of(2) {
            &first
        } else {
            &second
        };
        write(&**handle, offset as u64, &data).await;
        apply(&mut model, offset, &data);
    }
    assert_bytes(&read_all(&*first).await, &model, "the first handle");
    assert_bytes(&read_all(&*second).await, &model, "the second handle");
    // Overlapping ranges: the later write wins where they meet.
    write(&*second, 65_000, &[0xAA; 2_000]).await;
    write(&*first, 65_500, &[0xBB; 2_000]).await;
    apply(&mut model, 65_000, &[0xAA; 2_000]);
    apply(&mut model, 65_500, &[0xBB; 2_000]);
    assert_bytes(
        &read_all(&*second).await,
        &model,
        "after overlapping writes",
    );
    first.close().await.unwrap();
    second.close().await.unwrap();
    assert_bytes(&contents(backend, "f").await, &model, "the file");
}

pub(super) async fn a_truncating_open_empties_the_file_for_other_handles(backend: Backend<'_>) {
    put(backend, "f", &nonzero_pattern(100_000)).await;
    let held = open_file(backend, "f").await;
    let (truncating, action) = open(backend, "f", OpenIntent::Truncate).await;
    assert_eq!(action, OpenAction::Overwritten);
    assert_eq!(held.stat().await.unwrap().end_of_file, 0);
    assert!(held.read(0, 100).await.unwrap().is_empty());

    write(&*held, 0, b"after").await;
    assert_bytes(&read_all(&*truncating).await, b"after", "the second handle");
    write(&*truncating, 70_000, b"far").await;
    let mut model = b"after".to_vec();
    apply(&mut model, 70_000, b"far");
    assert_bytes(&read_all(&*held).await, &model, "the first handle");
    held.close().await.unwrap();
    truncating.close().await.unwrap();
    assert_bytes(&contents(backend, "f").await, &model, "the file");
}

pub(super) async fn writes_at_block_boundaries_match_a_model(backend: Backend<'_>) {
    let (handle, _) = open(backend, "f", OpenIntent::Create).await;
    let mut model = Vec::new();
    let mut fill = 0_u8;
    for offset in [0, 1, BLOCK - 1, BLOCK, BLOCK + 1, 2 * BLOCK - 1, 2 * BLOCK] {
        for len in [1, 2, BLOCK - 1, BLOCK, BLOCK + 1] {
            fill = fill % 250 + 1;
            let data = vec![fill; len];
            write(&*handle, offset as u64, &data).await;
            apply(&mut model, offset, &data);
            assert_eq!(
                handle.stat().await.unwrap().end_of_file,
                model.len() as u64,
                "size after {len} bytes at {offset}"
            );
            assert_bytes(
                &read_all(&*handle).await,
                &model,
                &format!("after {len} bytes at {offset}"),
            );
        }
    }
    for len in [
        4 * BLOCK,
        4 * BLOCK + 1,
        2 * BLOCK,
        BLOCK,
        BLOCK + 1,
        BLOCK - 1,
        0,
    ] {
        handle.truncate(len as u64).await.unwrap();
        model.resize(len, 0);
        assert_bytes(
            &read_all(&*handle).await,
            &model,
            &format!("truncated to {len}"),
        );
    }
    handle.close().await.unwrap();
}
