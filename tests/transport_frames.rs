//! Request frame size limits and queued response memory.

mod common;

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicIsize, AtomicUsize, Ordering};
use std::time::Duration;

use common::transport::{
    ECHO_BODY, WAIT, anonymous_tree, assert_closed, assert_open, compound, connect,
    connect_in_session_setup, connect_negotiated, open_file, read_body, read_response, with_share,
};
use common::{build_header, framed, message, start_server};
use smb_server::SmbServer;
use smb_server::ntstatus::STATUS_INVALID_PARAMETER;
use smb_server::wire::header::{Command, Smb2Header};
use tokio::io::AsyncWriteExt;

/// Records the largest single allocation and the bytes in use.
struct Tracking;

static LARGEST: AtomicUsize = AtomicUsize::new(0);
static LIVE: AtomicIsize = AtomicIsize::new(0);

fn allocated(size: usize) {
    LARGEST.fetch_max(size, Ordering::Relaxed);
    LIVE.fetch_add(size as isize, Ordering::Relaxed);
}

unsafe impl GlobalAlloc for Tracking {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        allocated(layout.size());
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        allocated(layout.size());
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        allocated(new_size);
        LIVE.fetch_sub(layout.size() as isize, Ordering::Relaxed);
        unsafe { System.realloc(ptr, layout, new_size) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        LIVE.fetch_sub(layout.size() as isize, Ordering::Relaxed);
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static ALLOC: Tracking = Tracking;

/// Held by the tests that read the allocation counters.
static MEASURING: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

#[tokio::test]
async fn frames_longer_than_the_negotiated_limit_close_the_connection() {
    let (addr, handle) = start_server(SmbServer::builder()).await;
    let mut before_negotiate = connect(addr).await;
    before_negotiate
        .write_all(&[0, 0x01, 0x20, 0x00])
        .await
        .expect("write");
    let mut negotiated = connect_negotiated(addr).await;
    negotiated
        .write_all(&[0, 0xFF, 0xFF, 0xFF])
        .await
        .expect("write");
    assert_closed(&mut before_negotiate, WAIT).await;
    assert_closed(&mut negotiated, WAIT).await;
    handle.abort();
}

#[tokio::test]
async fn small_commands_over_68_kib_close_the_connection() {
    let (addr, handle) = start_server(SmbServer::builder()).await;
    let mut s = connect_in_session_setup(addr).await;

    let mut body = ECHO_BODY.to_vec();
    body.resize(64 * 1024, 0);
    let hdr = build_header(Command::Echo, 2, 0, 0);
    s.write_all(&framed(&message(&hdr, &body)))
        .await
        .expect("write");
    let (hdr, _) = read_response(&mut s).await;
    assert_eq!(hdr.command, Command::Echo);

    body.resize(68 * 1024 + 1, 0);
    let hdr = build_header(Command::Echo, 3, 0, 0);
    s.write_all(&framed(&message(&hdr, &body)))
        .await
        .expect("write");
    assert_closed(&mut s, WAIT).await;
    handle.abort();
}

#[tokio::test]
async fn frame_buffers_grow_with_the_bytes_received() {
    let _measuring = MEASURING.lock().await;
    let (addr, handle) = start_server(SmbServer::builder()).await;
    let mut s = connect_negotiated(addr).await;

    LARGEST.store(0, Ordering::Relaxed);
    let declared: u32 = 1024 * 1024;
    let mut partial = declared.to_be_bytes().to_vec();
    partial.extend_from_slice(&[0xFE; 1000]);
    s.write_all(&partial).await.expect("write");
    assert_open(&mut s, Duration::from_millis(300)).await;
    let largest = LARGEST.load(Ordering::Relaxed);
    assert!(
        largest < declared as usize / 2,
        "largest allocation {largest} bytes"
    );
    handle.abort();
}

#[tokio::test]
async fn responses_a_peer_does_not_read_stay_bounded() {
    let _measuring = MEASURING.lock().await;
    const MIB: u32 = 1024 * 1024;
    let (builder, _td) = with_share(&[("f.txt", &vec![0x5A; MIB as usize])]);
    let (addr, handle) = start_server(builder).await;
    let (mut s, session_id, tree_id) = anonymous_tree(addr).await;
    let file_id = open_file(&mut s, 4, session_id, tree_id, "f.txt").await;

    let mut requests = Vec::new();
    for i in 0..64 {
        let mut hdr = build_header(Command::Read, 5 + 16 * i, session_id, tree_id);
        hdr.credit_charge = 16;
        hdr.credit_request_response = 16;
        requests.extend_from_slice(&framed(&message(&hdr, &read_body(file_id, MIB))));
    }
    let before = LIVE.load(Ordering::Relaxed);
    s.write_all(&requests).await.expect("write");
    tokio::time::sleep(Duration::from_millis(1500)).await;
    let pinned = LIVE.load(Ordering::Relaxed) - before;
    assert!(
        pinned < 16 * MIB as isize,
        "{} MiB held for unread responses",
        pinned / MIB as isize
    );
    handle.abort();
}

#[tokio::test]
async fn responses_too_large_for_a_frame_fail_instead_of_wrapping() {
    let _measuring = MEASURING.lock().await;
    const MIB: u32 = 1024 * 1024;
    let (builder, _td) = with_share(&[("f.txt", &vec![0x5A; 8 * MIB as usize])]);
    let (addr, handle) = start_server(builder.max_read_size(8 * MIB)).await;
    let (mut s, session_id, tree_id) = anonymous_tree(addr).await;
    let file_id = open_file(&mut s, 4, session_id, tree_id, "f.txt").await;
    let mut hdr = build_header(Command::Echo, 5, 0, 0);
    hdr.credit_request_response = 1024;
    s.write_all(&framed(&message(&hdr, &ECHO_BODY)))
        .await
        .expect("write");
    read_response(&mut s).await;

    // Two 8 MiB READs: their responses together exceed 16 MiB - 1.
    let read = |message_id| {
        let mut hdr = build_header(Command::Read, message_id, session_id, tree_id);
        hdr.credit_charge = 128;
        message(&hdr, &read_body(file_id, 8 * MIB))
    };
    s.write_all(&compound(&[read(6), read(134)]))
        .await
        .expect("write");
    let (first, frame) = read_response(&mut s).await;
    assert_eq!(first.channel_sequence_status, 0, "first READ");
    let next = first.next_command as usize;
    assert_ne!(next, 0, "two responses");
    let (second, _) = Smb2Header::parse(&frame[next..]).expect("second response");
    assert_eq!(second.channel_sequence_status, STATUS_INVALID_PARAMETER);

    // The stream is still framed correctly.
    let echo = build_header(Command::Echo, 262, 0, 0);
    s.write_all(&framed(&message(&echo, &ECHO_BODY)))
        .await
        .expect("write");
    let (hdr, _) = read_response(&mut s).await;
    assert_eq!(hdr.command, Command::Echo);
    handle.abort();
}
