//! Duplicate extents over the dispatcher: the attribute that offers them,
//! the status of each rule, rights, byte-range locks, leases, change reports,
//! named streams, shares that do not clone, and FSCTL_SET_SPARSE.

use super::*;
use crate::proto::messages::{QueryInfoRequest, QueryInfoResponse};

const DUPLICATE: u32 = Fsctl::DUPLICATE_EXTENTS_TO_FILE;
const DUPLICATE_EX: u32 = Fsctl::DUPLICATE_EXTENTS_TO_FILE_EX;
const SET_SPARSE: u32 = Fsctl::SET_SPARSE;

const WRITE_ATTRIBUTES: u32 = 0x100;
const FILE_SUPPORTS_BLOCK_REFCOUNTING: u32 = 0x0800_0000;
const INVALID_HANDLE: u32 = ntstatus::STATUS_INVALID_HANDLE;

/// The bytes of a cluster in a spying share.
const CLUSTER: u64 = 4096;
/// Bytes of the files of a spying share: four clusters.
const LEN: usize = 4 * CLUSTER as usize;

/// The input of a duplicate extents request.
fn dup_input(source: FileId, source_offset: u64, target_offset: u64, count: u64) -> Vec<u8> {
    let mut input = source.persistent.to_le_bytes().to_vec();
    input.extend_from_slice(&source.volatile.to_le_bytes());
    for field in [source_offset, target_offset, count] {
        input.extend_from_slice(&field.to_le_bytes());
    }
    input
}

impl Client {
    /// A duplicate extents request on the open `target` at `at`; returns the
    /// status and the output of the reply, `None` for a reply without any.
    async fn duplicate_at(
        &mut self,
        at: At,
        target: FileId,
        input: &[u8],
    ) -> (u32, Option<Vec<u8>>) {
        self.fsctl(at, DUPLICATE, target, input, 16384).await
    }

    /// Clones `count` bytes at `source_offset` of `source` to `target_offset`
    /// of `target`, both on [`HOME`].
    async fn duplicate(
        &mut self,
        source: FileId,
        source_offset: u64,
        target: FileId,
        target_offset: u64,
        count: u64,
    ) -> (u32, Option<Vec<u8>>) {
        let input = dup_input(source, source_offset, target_offset, count);
        self.duplicate_at(HOME, target, &input).await
    }

    /// The attributes FileFsAttributeInformation reports for [`HOME`].
    async fn fs_attributes(&mut self) -> u32 {
        let root = self
            .open(Create::new("").access(READ).options(FILE_DIRECTORY_FILE))
            .await;
        let mut body = Vec::new();
        QueryInfoRequest {
            structure_size: 41,
            info_type: 2,
            file_information_class: 5,
            output_buffer_length: 1024,
            input_buffer_offset: 0,
            reserved: 0,
            input_buffer_length: 0,
            additional_information: 0,
            flags: 0,
            file_id: root,
            input_buffer: vec![],
        }
        .write_to(&mut body)
        .expect("query info");
        let (status, body) = self.send(Command::QueryInfo, &body).await;
        assert_eq!(status, OK);
        let reply = QueryInfoResponse::parse(&body).expect("a response");
        self.close(root).await;
        u32::from_le_bytes(reply.buffer[..4].try_into().unwrap())
    }
}

/// A server whose public share `home` is `files` on a spying backend that
/// clones as `cloning` says.
fn cloning_server(files: &MemFsBackend, cloning: Cloning) -> (Arc<Spy>, Arc<ServerState>) {
    let spy = Spy::new(Fast::Unsupported);
    spy.clone_as(cloning);
    let state = server_on(vec![Share::new("home", SpyFs::new(files, &spy)).public()]);
    (spy, state)
}

/// A spying share whose backend clones as `cloning` says, holding `s` of
/// [`LEN`] bytes and a `t` of as many zeros, and a client with both open.
async fn cloning(cloning: Cloning) -> (MemFsBackend, Arc<Spy>, Client, FileId, FileId, Vec<u8>) {
    let data = pattern(LEN, 0x42);
    let files = MemFsBackend::new()
        .with_file("s", &data)
        .with_file("t", &[0; LEN]);
    let (spy, state) = cloning_server(&files, cloning);
    let mut c = Client::new(&state).await;
    let source = c.open(Create::new("s")).await;
    let target = c.open(Create::new("t")).await;
    (files, spy, c, source, target, data)
}

// ---------------------------------------------------------------------------
// The attribute
// ---------------------------------------------------------------------------

#[tokio::test]
async fn the_volume_reports_block_refcounting_only_when_the_share_clones() {
    let files = MemFsBackend::new();
    let (spy, state) = cloning_server(&files, Cloning::Full);
    let attributes = Client::new(&state).await.fs_attributes().await;
    assert_eq!(
        attributes & FILE_SUPPORTS_BLOCK_REFCOUNTING,
        FILE_SUPPORTS_BLOCK_REFCOUNTING
    );

    let off = Share::new("home", SpyFs::new(&files, &spy))
        .public()
        .server_side_copy(false);
    let state = server_on(vec![off]);
    let attributes = Client::new(&state).await.fs_attributes().await;
    assert_eq!(
        attributes & FILE_SUPPORTS_BLOCK_REFCOUNTING,
        0,
        "copies off"
    );

    let state = server(&files);
    let attributes = Client::new(&state).await.fs_attributes().await;
    assert_eq!(
        attributes & FILE_SUPPORTS_BLOCK_REFCOUNTING,
        0,
        "no cloning"
    );
}

// ---------------------------------------------------------------------------
// Clones
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_range_is_cloned_to_its_target_offset() {
    let (files, spy, mut c, source, target, data) = cloning(Cloning::Full).await;
    assert_eq!(
        c.duplicate(source, 4096, target, 8192, 8192).await,
        (OK, Some(Vec::new()))
    );
    assert_eq!(spy.clone_calls(), [(4096, 8192, 8192)]);
    let mut expected = vec![0; 8192];
    expected.extend_from_slice(&data[4096..12_288]);
    assert_eq!(files.contents("t"), Some(expected));
    assert_eq!(files.contents("s"), Some(data));
}

#[tokio::test]
async fn a_clone_between_shares_of_one_session_goes_to_the_backend_of_the_target() {
    let data = pattern(LEN, 5);
    let (home_files, other_files) = (
        MemFsBackend::new().with_file("s", &data),
        MemFsBackend::new().with_file("t", &[0; LEN]),
    );
    let (home_spy, other_spy) = (Spy::new(Fast::Unsupported), Spy::new(Fast::Unsupported));
    home_spy.clone_as(Cloning::Full);
    other_spy.clone_as(Cloning::Full);
    let state = server_on(vec![
        Share::new("home", SpyFs::new(&home_files, &home_spy)).public(),
        Share::new("other", SpyFs::new(&other_files, &other_spy)).public(),
    ]);
    let mut c = Client::new(&state)
        .await
        .with_other_share(Access::ReadWrite)
        .await;
    let source = c.open(Create::new("s")).await;
    let target = c.open_at(OTHER, Create::new("t")).await;
    let request = dup_input(source, 0, 0, LEN as u64);
    assert_eq!(
        c.duplicate_at(OTHER, target, &request).await,
        (OK, Some(Vec::new()))
    );
    assert_eq!(other_spy.clone_calls(), [(0, 0, LEN as u64)]);
    assert_eq!(home_spy.clone_calls(), []);
    assert_eq!(other_files.contents("t"), Some(data));
}

#[tokio::test]
async fn a_zero_length_request_succeeds_and_changes_nothing() {
    let (files, spy, mut c, source, target, _) = cloning(Cloning::Full).await;
    assert_eq!(
        c.duplicate(source, 1 << 40, target, 1 << 41, 0).await,
        (OK, Some(Vec::new()))
    );
    assert_eq!(spy.clone_calls(), []);
    assert!(!c.wrote(target).await);
    assert_eq!(files.contents("t"), Some(vec![0; LEN]));
}

// ---------------------------------------------------------------------------
// Malformed requests and sources that name nothing
// ---------------------------------------------------------------------------

#[tokio::test]
async fn input_shorter_than_the_structure_is_an_invalid_parameter() {
    let (_, spy, mut c, _, target, _) = cloning(Cloning::Full).await;
    let nothing = dup_input(FileId::new(0x77, 0x77), 0, 0, CLUSTER);
    assert_eq!(
        c.duplicate_at(HOME, target, &nothing[..39]).await,
        (INVALID, None),
        "before the source is looked up"
    );
    assert_eq!(spy.clone_calls(), []);
}

#[tokio::test]
async fn a_source_that_is_no_open_of_the_session_is_an_invalid_handle() {
    let (_, spy, mut c, source, target, _) = cloning(Cloning::Full).await;
    assert_eq!(
        c.duplicate(FileId::new(0x77, 0x77), 0, target, 0, CLUSTER)
            .await,
        (INVALID_HANDLE, None),
        "an unknown id"
    );
    c.close(source).await;
    assert_eq!(
        c.duplicate(source, 0, target, 0, CLUSTER).await,
        (INVALID_HANDLE, None),
        "a closed open"
    );
    assert_eq!(spy.clone_calls(), []);
}

#[tokio::test]
async fn an_open_of_another_session_is_not_a_source() {
    let files = MemFsBackend::new()
        .with_file("s", &pattern(LEN, 1))
        .with_file("t", &[0; LEN]);
    let (_, state) = cloning_server(&files, Cloning::Full);
    let mut c = Client::new(&state).await.with_second_session().await;
    let target = c.open(Create::new("t")).await;
    let source_there = c.open_at(SECOND, Create::new("s")).await;
    let request = dup_input(source_there, 0, 0, CLUSTER);
    assert_eq!(
        c.duplicate_at(HOME, target, &request).await,
        (INVALID_HANDLE, None)
    );
    let target_there = c.open_at(SECOND, Create::new("t")).await;
    assert_eq!(
        c.duplicate_at(SECOND, target_there, &request).await,
        (OK, Some(Vec::new())),
        "both in session 2"
    );
}

#[tokio::test]
async fn a_source_that_closes_while_the_clone_waits_for_it_is_an_invalid_handle() {
    let (files, spy, mut c, source, target, _) = cloning(Cloning::Full).await;
    let open = c.open_of(source).await;
    let mut closing = open.write().await;
    let request = dup_input(source, 0, 0, CLUSTER);
    let mut clone = pin!(c.duplicate_at(HOME, target, &request));
    let waiting = poll_fn(|cx| Poll::Ready(clone.as_mut().poll(cx).is_pending())).await;
    assert!(waiting, "the clone waits for the source");
    closing.handle = None;
    drop(closing);
    assert_eq!(clone.await, (INVALID_HANDLE, None));
    assert_eq!(spy.clone_calls(), []);
    assert_eq!(files.contents("t"), Some(vec![0; LEN]));
}

// ---------------------------------------------------------------------------
// Shares that do not clone
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_share_that_does_not_clone_refuses_with_invalid_device_request() {
    let files = MemFsBackend::new()
        .with_file("s", &pattern(LEN, 1))
        .with_file("t", &[0; LEN]);
    let spy = Spy::new(Fast::Unsupported);
    spy.clone_as(Cloning::Full);
    let off = Share::new("home", SpyFs::new(&files, &spy))
        .public()
        .server_side_copy(false);
    let shares = [
        ("a backend that does not clone", server(&files)),
        ("copies off", server_on(vec![off])),
    ];
    for (name, state) in shares {
        let mut c = Client::new(&state).await;
        let source = c.open(Create::new("s")).await;
        let target = c.open(Create::new("t")).await;
        assert_eq!(
            c.duplicate(source, 0, target, 0, CLUSTER).await,
            (DEVICE, None),
            "{name}"
        );
    }
    assert_eq!(spy.clone_calls(), []);
}

#[tokio::test]
async fn a_clone_needs_copies_on_for_the_share_of_the_source() {
    let data = pattern(LEN, 4);
    let (home_files, other_files) = (
        MemFsBackend::new().with_file("t", &[0; LEN]),
        MemFsBackend::new().with_file("s", &data),
    );
    let (home_spy, other_spy) = (Spy::new(Fast::Unsupported), Spy::new(Fast::Unsupported));
    home_spy.clone_as(Cloning::Full);
    other_spy.clone_as(Cloning::Full);
    let state = server_on(vec![
        Share::new("home", SpyFs::new(&home_files, &home_spy)).public(),
        Share::new("other", SpyFs::new(&other_files, &other_spy))
            .public()
            .server_side_copy(false),
    ]);
    let mut c = Client::new(&state)
        .await
        .with_other_share(Access::ReadWrite)
        .await;
    let source = c.open_at(OTHER, Create::new("s")).await;
    let target = c.open(Create::new("t")).await;
    assert_eq!(
        c.duplicate(source, 0, target, 0, CLUSTER).await,
        (DEVICE, None)
    );
    assert_eq!(home_spy.clone_calls(), []);
    assert_eq!(home_files.contents("t"), Some(vec![0; LEN]));
}

#[tokio::test]
async fn the_extended_form_is_not_served() {
    let (_, spy, mut c, source, target, _) = cloning(Cloning::Full).await;
    let mut request = vec![0x30, 0, 0, 0, 0, 0, 0, 0];
    request.extend_from_slice(&dup_input(source, 0, 0, CLUSTER));
    request.extend_from_slice(&[0; 8]);
    assert_eq!(
        c.fsctl(HOME, DUPLICATE_EX, target, &request, 0).await,
        (DEVICE, None)
    );
    assert_eq!(spy.clone_calls(), []);
}

// ---------------------------------------------------------------------------
// Ranges
// ---------------------------------------------------------------------------

#[tokio::test]
async fn offsets_and_length_must_be_multiples_of_the_allocation_unit() {
    let (_, spy, mut c, source, target, _) = cloning(Cloning::Full).await;
    let bad = [
        (1, 0, CLUSTER),
        (0, 1, CLUSTER),
        (0, 0, CLUSTER - 1),
        (1, 1, 0),
    ];
    for (source_offset, target_offset, count) in bad {
        assert_eq!(
            c.duplicate(source, source_offset, target, target_offset, count)
                .await,
            (UNSUPPORTED, None),
            "{source_offset} {target_offset} {count}"
        );
    }
    assert_eq!(spy.clone_calls(), [], "nothing was cloned");
    assert_eq!(
        c.duplicate(source, CLUSTER, target, 2 * CLUSTER, CLUSTER)
            .await,
        (OK, Some(Vec::new()))
    );
}

#[tokio::test]
async fn the_allocation_unit_is_the_one_the_volume_reports() {
    let files = MemFsBackend::new()
        .with_file("s", &pattern(LEN, 6))
        .with_file("t", &[0; LEN]);
    let (spy, state) = cloning_server(&files, Cloning::Full);
    spy.sectors_of(8192);
    let mut c = Client::new(&state).await;
    let source = c.open(Create::new("s")).await;
    let target = c.open(Create::new("t")).await;
    assert_eq!(
        c.duplicate(source, 0, target, 4096, 4096).await,
        (UNSUPPORTED, None)
    );
    assert_eq!(
        c.duplicate(source, 0, target, 8192, 8192).await,
        (OK, Some(Vec::new()))
    );
    assert_eq!(spy.clone_calls(), [(0, 8192, 8192)]);
}

#[tokio::test]
async fn a_source_range_past_the_end_of_the_source_is_not_supported() {
    let (_, spy, mut c, source, target, _) = cloning(Cloning::Full).await;
    let past = [
        (LEN as u64, 0, CLUSTER),
        (u64::MAX - (CLUSTER - 1), 0, 2 * CLUSTER),
    ];
    for (source_offset, target_offset, count) in past {
        assert_eq!(
            c.duplicate(source, source_offset, target, target_offset, count)
                .await,
            (UNSUPPORTED, None),
            "{source_offset} {target_offset} {count}"
        );
    }
    assert_eq!(spy.clone_calls(), []);
    assert_eq!(
        c.duplicate(source, 3 * CLUSTER, target, 0, CLUSTER).await,
        (OK, Some(Vec::new())),
        "up to the end"
    );
}

#[tokio::test]
async fn a_source_range_may_end_in_the_last_cluster_of_the_source() {
    const SIZE: u64 = 3 * CLUSTER + 1000;
    let data = pattern(SIZE as usize, 7);
    let files = MemFsBackend::new()
        .with_file("s", &data)
        .with_file("t", &[0; SIZE as usize])
        .with_file("longer", &[0; LEN]);
    let (spy, state) = cloning_server(&files, Cloning::Full);
    let mut c = Client::new(&state).await;
    let source = c.open(Create::new("s")).await;
    let target = c.open(Create::new("t")).await;
    let longer = c.open(Create::new("longer")).await;
    assert_eq!(
        c.duplicate(source, 0, target, 0, SIZE).await,
        (UNSUPPORTED, None),
        "a length that is not a multiple of the allocation unit"
    );
    assert_eq!(
        c.duplicate(source, 0, target, 0, 5 * CLUSTER).await,
        (UNSUPPORTED, None),
        "a range that ends past the last cluster"
    );
    assert_eq!(
        c.duplicate(source, 0, longer, 0, 4 * CLUSTER).await,
        (UNSUPPORTED, None),
        "a target that goes on past the end of the source"
    );
    assert_eq!(spy.clone_calls(), []);
    assert_eq!(
        c.duplicate(source, 0, target, 0, 4 * CLUSTER).await,
        (OK, Some(Vec::new()))
    );
    assert_eq!(spy.clone_calls(), [(0, 0, SIZE)]);
    assert_eq!(files.contents("t"), Some(data));
    assert_eq!(files.contents("longer"), Some(vec![0; LEN]));
}

#[tokio::test]
async fn a_target_range_past_the_end_of_the_target_is_cloned_only_below_it() {
    let (files, spy, mut c, source, target, data) = cloning(Cloning::Full).await;
    let past = [
        (0, LEN as u64, CLUSTER),
        (0, u64::MAX - (CLUSTER - 1), 2 * CLUSTER),
    ];
    for (source_offset, target_offset, count) in past {
        assert_eq!(
            c.duplicate(source, source_offset, target, target_offset, count)
                .await,
            (OK, Some(Vec::new())),
            "{source_offset} {target_offset} {count}"
        );
    }
    assert_eq!(spy.clone_calls(), []);
    assert!(!c.wrote(target).await);
    assert_eq!(
        c.duplicate(source, 0, target, 3 * CLUSTER, 2 * CLUSTER)
            .await,
        (OK, Some(Vec::new()))
    );
    assert_eq!(spy.clone_calls(), [(0, 3 * CLUSTER, CLUSTER)]);
    let mut expected = vec![0; 3 * CLUSTER as usize];
    expected.extend_from_slice(&data[..CLUSTER as usize]);
    assert_eq!(files.contents("t"), Some(expected), "the size is the same");
}

#[tokio::test]
async fn a_clone_cut_short_by_the_target_inside_a_cluster_is_not_supported() {
    let files = MemFsBackend::new()
        .with_file("s", &pattern(LEN, 1))
        .with_file("t", &[0; CLUSTER as usize + 1000]);
    let (spy, state) = cloning_server(&files, Cloning::Full);
    let mut c = Client::new(&state).await;
    let source = c.open(Create::new("s")).await;
    let target = c.open(Create::new("t")).await;
    assert_eq!(
        c.duplicate(source, 0, target, CLUSTER, 2 * CLUSTER).await,
        (UNSUPPORTED, None)
    );
    assert_eq!(spy.clone_calls(), []);
}

#[tokio::test]
async fn ranges_of_one_file_that_overlap_are_not_supported() {
    for two_opens in [false, true] {
        let files = MemFsBackend::new().with_file("f", &pattern(LEN, 8));
        let (spy, state) = cloning_server(&files, Cloning::Full);
        let mut c = Client::new(&state).await;
        let source = c.open(Create::new("f")).await;
        let target = if two_opens {
            c.open(Create::new("f")).await
        } else {
            source
        };
        for (source_offset, target_offset, count) in
            [(0, CLUSTER, 2 * CLUSTER), (CLUSTER, 0, 2 * CLUSTER)]
        {
            assert_eq!(
                c.duplicate(source, source_offset, target, target_offset, count)
                    .await,
                (UNSUPPORTED, None),
                "{source_offset} {target_offset} {count}, two opens {two_opens}"
            );
        }
        assert_eq!(spy.clone_calls(), []);
        assert_eq!(
            c.duplicate(source, 0, target, 2 * CLUSTER, 2 * CLUSTER)
                .await,
            (OK, Some(Vec::new())),
            "ranges side by side, two opens {two_opens}"
        );
        assert_eq!(spy.clone_calls(), [(0, 2 * CLUSTER, 2 * CLUSTER)]);
    }
}

// ---------------------------------------------------------------------------
// Rights
// ---------------------------------------------------------------------------

#[tokio::test]
async fn each_open_needs_the_rights_a_clone_uses() {
    let data = pattern(LEN, 8);
    let cases = [
        // Source access, target access, whether it works.
        (READ_ATTRIBUTES, RW, false),
        (READ, READ, false),
        (READ, FILE_APPEND_DATA | READ_ATTRIBUTES, false),
        (READ, WRITE, true),
    ];
    for (at, (source_access, target_access, works)) in cases.into_iter().enumerate() {
        let files = MemFsBackend::new()
            .with_file("s", &data)
            .with_file("t", &[0; LEN]);
        let (spy, state) = cloning_server(&files, Cloning::Full);
        let mut c = Client::new(&state).await;
        let source = c.open(Create::new("s").access(source_access)).await;
        let target = c.open(Create::new("t").access(target_access)).await;
        let expected = if works {
            (OK, Some(Vec::new()))
        } else {
            (DENIED, None)
        };
        assert_eq!(
            c.duplicate(source, 0, target, 0, CLUSTER).await,
            expected,
            "case {at}: {source_access:#x} to {target_access:#x}"
        );
        assert_eq!(spy.clone_calls().len(), usize::from(works), "case {at}");
    }
}

#[tokio::test]
async fn a_directory_is_not_cloned_from_or_to() {
    let files = MemFsBackend::new()
        .with_file("s", &pattern(LEN, 1))
        .with_file("t", &[0; LEN])
        .with_dir("d");
    let (spy, state) = cloning_server(&files, Cloning::Full);
    let mut c = Client::new(&state).await;
    let dir = c.open(Create::new("d").options(FILE_DIRECTORY_FILE)).await;
    let source = c.open(Create::new("s")).await;
    let target = c.open(Create::new("t")).await;
    assert_eq!(
        c.duplicate(dir, 0, target, 0, CLUSTER).await,
        (DENIED, None),
        "a directory as source"
    );
    assert_eq!(
        c.duplicate(source, 0, dir, 0, CLUSTER).await,
        (DENIED, None),
        "a directory as target"
    );
    assert_eq!(spy.clone_calls(), []);
}

#[tokio::test]
async fn a_named_stream_is_never_cloned_from_or_to_and_never_refused_as_not_supported() {
    let files = MemFsBackend::new()
        .with_file("f", &pattern(LEN, 1))
        .with_stream("f", "x", &[0; LEN])
        .with_file("g", &[0; LEN])
        .with_stream("g", "y", &[0; LEN]);
    let (spy, state) = cloning_server(&files, Cloning::Full);
    let mut c = Client::new(&state).await;
    let file = c.open(Create::new("f")).await;
    let other = c.open(Create::new("g")).await;
    let stream = c.open(Create::new("f:x")).await;
    let other_stream = c.open(Create::new("g:y")).await;
    for (name, source, target) in [
        ("file to stream", file, other_stream),
        ("stream to file", stream, other),
    ] {
        for count in [CLUSTER, 0, 1] {
            let (status, out) = c.duplicate(source, 0, target, 0, count).await;
            assert_eq!((status, out), (DEVICE, None), "{name}, {count} bytes");
        }
    }
    assert_eq!(spy.clone_calls(), []);
}

#[tokio::test]
async fn a_named_pipe_is_not_a_source() {
    const PIPE_ACCESS: u32 = 0x0012_019F;
    const PIPE_OPTIONS: u32 = 0x0040_0040;
    const IPC: At = At {
        session: 1,
        tree: 2,
    };

    let (_, spy, c, _, target, _) = cloning(Cloning::Full).await;
    let mut c = c.with_second_tree(ShareBindings::ipc(), Access::Read).await;
    let pipe = c
        .open_at(
            IPC,
            Create::new("srvsvc")
                .access(PIPE_ACCESS)
                .options(PIPE_OPTIONS)
                .share(3),
        )
        .await;
    assert_eq!(
        c.duplicate(pipe, 0, target, 0, CLUSTER).await,
        (INVALID_HANDLE, None)
    );
    let request = dup_input(pipe, 0, 0, CLUSTER);
    assert_eq!(
        c.duplicate_at(IPC, pipe, &request).await,
        (UNSUPPORTED, None),
        "a pipe as target"
    );
    assert_eq!(spy.clone_calls(), []);
}

// ---------------------------------------------------------------------------
// Byte-range locks
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_lock_of_another_open_on_either_range_stops_the_clone() {
    let (files, spy, mut c, source, target, data) = cloning(Cloning::Full).await;
    let source_locker = c.open(Create::new("s")).await;
    let target_locker = c.open(Create::new("t")).await;
    assert_eq!(c.lock(source_locker, 5000, 10, false).await, OK);
    assert_eq!(c.lock(target_locker, 9000, 10, false).await, OK);

    assert_eq!(
        c.duplicate(source, 4096, target, 0, 4096).await,
        (LOCKED, None),
        "a lock on the source range"
    );
    assert_eq!(
        c.duplicate(source, 0, target, 8192, 4096).await,
        (LOCKED, None),
        "a lock on the target range"
    );
    assert_eq!(spy.clone_calls(), []);
    assert_eq!(files.contents("t"), Some(vec![0; LEN]));

    assert_eq!(
        c.duplicate(source, 0, target, 0, 4096).await,
        (OK, Some(Vec::new())),
        "ranges the locks do not cover"
    );
    assert_eq!(c.lock(source_locker, 5000, 10, true).await, OK);
    assert_eq!(c.lock(target_locker, 9000, 10, true).await, OK);
    assert_eq!(
        c.duplicate(source, 4096, target, 8192, 4096).await,
        (OK, Some(Vec::new())),
        "after the unlock"
    );
    let mut expected = data[..4096].to_vec();
    expected.extend_from_slice(&[0; 4096]);
    expected.extend_from_slice(&data[4096..8192]);
    expected.extend_from_slice(&[0; 4096]);
    assert_eq!(files.contents("t"), Some(expected));
}

#[tokio::test]
async fn the_locks_of_the_cloning_opens_do_not_stop_it() {
    let (files, _, mut c, source, target, data) = cloning(Cloning::Full).await;
    assert_eq!(c.lock(source, 0, LEN as u64, false).await, OK);
    assert_eq!(c.lock(target, 0, LEN as u64, false).await, OK);
    assert_eq!(
        c.duplicate(source, 0, target, 0, LEN as u64).await,
        (OK, Some(Vec::new()))
    );
    assert_eq!(files.contents("t"), Some(data));
}

// ---------------------------------------------------------------------------
// Leases and change reports
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_clone_breaks_the_leases_of_others_and_leaves_its_own() {
    let files = MemFsBackend::new()
        .with_file("s", &pattern(LEN, 1))
        .with_file("t", &[0; LEN]);
    let (_, state) = cloning_server(&files, Cloning::Full);
    let mut reader = Client::from_client(&state, 1).await;
    let mut cacher = Client::from_client(&state, 3).await;
    let mut cloner = Client::from_client(&state, 2).await;
    let read_cached = reader
        .open(Create::new("t").access(READ).lease(1, LEASE_R))
        .await;
    let handle_cached = cacher
        .open(Create::new("t").access(READ).lease(3, LEASE_RH))
        .await;
    let source = cloner.open(Create::new("s").lease(4, LEASE_R)).await;
    let target = cloner.open(Create::new("t").lease(2, LEASE_R)).await;
    reader.quiet().await;
    cacher.quiet().await;

    assert_eq!(
        cloner.duplicate(source, 1, target, 0, CLUSTER).await,
        (UNSUPPORTED, None)
    );
    reader.quiet().await;
    cacher.quiet().await;

    assert_eq!(
        cloner.duplicate(source, 0, target, 0, CLUSTER).await,
        (OK, Some(Vec::new()))
    );
    let flags = reader.breaks(1, LEASE_R, LEASE_NONE).await;
    assert_eq!(flags & LeaseBreakNotification::FLAG_ACK_REQUIRED, 0);
    let flags = cacher.breaks(3, LEASE_RH, LEASE_NONE).await;
    assert_eq!(
        flags & LeaseBreakNotification::FLAG_ACK_REQUIRED,
        LeaseBreakNotification::FLAG_ACK_REQUIRED
    );
    cacher.ack(3, LEASE_NONE).await;
    cloner.quiet().await;
    reader.close(read_cached).await;
    cacher.close(handle_cached).await;
}

#[tokio::test]
async fn a_lease_granted_while_a_clone_runs_is_broken_when_it_ends() {
    let files = MemFsBackend::new()
        .with_file("s", &pattern(LEN, 1))
        .with_file("t", &[0; LEN]);
    let (spy, state) = cloning_server(&files, Cloning::Full);
    let mut cloner = Client::from_client(&state, 2).await;
    let mut late = Client::from_client(&state, 1).await;
    let source = cloner.open(Create::new("s")).await;
    let target = cloner.open(Create::new("t")).await;
    let request = dup_input(source, 0, 0, LEN as u64);
    let reached = Arc::new(Notify::new());
    let resume = Arc::new(Notify::new());
    spy.stall(1, &reached, &resume);

    let clone = cloner.duplicate_at(HOME, target, &request);
    let grant = async {
        reached.notified().await;
        let opened = late
            .create_at(HOME, Create::new("t").access(READ).lease(5, LEASE_R))
            .await
            .expect("an open");
        assert_eq!(lease_state(&opened), Some(LEASE_R));
        resume.notify_one();
        opened.file_id
    };
    let (cloned, cached) = tokio::join!(clone, grant);
    assert_eq!(cloned, (OK, Some(Vec::new())));
    late.breaks(5, LEASE_R, LEASE_NONE).await;
    late.close(cached).await;
}

#[tokio::test]
async fn a_clone_marks_its_target_written_only_when_it_cloned() {
    let (_, _, mut c, source, target, _) = cloning(Cloning::Full).await;
    assert_eq!(
        c.duplicate(source, 1, target, 0, CLUSTER).await.0,
        UNSUPPORTED
    );
    assert!(!c.wrote(target).await);
    assert_eq!(c.duplicate(source, 0, target, 0, 0).await.0, OK);
    assert!(!c.wrote(target).await, "a request of no bytes");
    assert_eq!(c.duplicate(source, 0, target, 0, CLUSTER).await.0, OK);
    assert!(c.wrote(target).await);

    let (_, _, mut c, source, target, _) = cloning(Cloning::NotSameDevice).await;
    assert_eq!(c.duplicate(source, 0, target, 0, CLUSTER).await.0, INVALID);
    assert!(!c.wrote(target).await, "a clone the backend refused");

    let (_, _, mut c, source, target, _) = cloning(Cloning::DiskFull).await;
    assert_eq!(
        c.duplicate(source, 0, target, 0, CLUSTER).await.0,
        DISK_FULL
    );
    assert!(c.wrote(target).await, "a clone that may have cloned part");
}

#[tokio::test]
async fn a_clone_puts_back_the_write_time_its_target_fixed() {
    const FIXED: i64 = 133_000_000_000_000_000;
    let (_, spy, mut c, source, target, _) = cloning(Cloning::Full).await;
    assert_eq!(c.set_times(target, [0, 0, FIXED, 0]).await, OK);
    let fixed = FileTimes {
        last_write_time: Some(FIXED as u64),
        ..FileTimes::default()
    };
    assert_eq!(spy.times(), [fixed]);

    assert_eq!(
        c.duplicate(source, 1, target, 0, CLUSTER).await.0,
        UNSUPPORTED
    );
    assert_eq!(
        spy.times().len(),
        1,
        "a clone that changed nothing sets none"
    );
    assert_eq!(c.duplicate(source, 0, target, 0, CLUSTER).await.0, OK);
    assert_eq!(spy.times(), [fixed, fixed]);

    let (_, spy, mut c, source, target, _) = cloning(Cloning::DiskFull).await;
    assert_eq!(c.set_times(target, [0, 0, FIXED, 0]).await, OK);
    assert_eq!(
        c.duplicate(source, 0, target, 0, CLUSTER).await.0,
        DISK_FULL
    );
    assert_eq!(spy.times(), [fixed, fixed], "a clone that may have changed");
}

#[tokio::test]
async fn the_target_reports_one_change_at_its_close_and_the_source_none() {
    let files = MemFsBackend::new()
        .with_file("s", &pattern(LEN, 1))
        .with_file("t", &[0; LEN]);
    let (_, state) = cloning_server(&files, Cloning::Full);
    let mut watcher = Client::new(&state).await;
    let mut c = Client::new(&state).await;
    let root = watcher
        .open(Create::new("").access(READ).options(FILE_DIRECTORY_FILE))
        .await;
    let source = c.open(Create::new("s").access(READ)).await;
    let target = c.open(Create::new("t")).await;

    let w = watcher.watch(root).await;
    assert_eq!(
        c.duplicate(source, 0, target, 0, LEN as u64).await,
        (OK, Some(Vec::new()))
    );
    watcher.quiet().await;
    c.close(source).await;
    watcher.quiet().await;
    c.close(target).await;
    assert_eq!(watcher.events(w).await, [(MODIFIED, "t".to_string())]);
}

#[tokio::test]
async fn a_write_through_target_is_flushed_once() {
    let (_, spy, mut c, source, _, _) = cloning(Cloning::Full).await;
    let target = c.open(Create::new("t").options(FILE_WRITE_THROUGH)).await;
    assert_eq!(c.duplicate(source, 0, target, 0, CLUSTER).await.0, OK);
    assert_eq!(spy.flushes(), 1);

    let (_, spy, mut c, source, target, _) = cloning(Cloning::Full).await;
    assert_eq!(c.duplicate(source, 0, target, 0, CLUSTER).await.0, OK);
    assert_eq!(spy.flushes(), 0);
}

// ---------------------------------------------------------------------------
// Backend errors
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_backend_error_is_answered_with_its_status() {
    for (cloning_mode, expected) in [
        (Cloning::NotSupported, DEVICE),
        (Cloning::NotSameDevice, INVALID),
        (Cloning::InvalidParameter, INVALID),
        (Cloning::DiskFull, DISK_FULL),
    ] {
        let (files, spy, mut c, source, target, _) = cloning(cloning_mode).await;
        assert_eq!(
            c.duplicate(source, 0, target, 0, CLUSTER).await,
            (expected, None)
        );
        assert_eq!(spy.clone_calls(), [(0, 0, CLUSTER)]);
        assert_eq!(files.contents("t"), Some(vec![0; LEN]));
    }
}

// ---------------------------------------------------------------------------
// FSCTL_SET_SPARSE
// ---------------------------------------------------------------------------

#[tokio::test]
async fn set_sparse_on_a_share_that_clones_needs_a_file_open_for_writing() {
    let files = MemFsBackend::new()
        .with_file("f", &[0; 100])
        .with_stream("f", "x", b"")
        .with_dir("d");
    let (_, state) = cloning_server(&files, Cloning::Full);
    let mut c = Client::new(&state).await;
    let file = c.open(Create::new("f")).await;
    let dir = c.open(Create::new("d").options(FILE_DIRECTORY_FILE)).await;
    let stream = c.open(Create::new("f:x")).await;
    let attributes = c.open(Create::new("f").access(READ_ATTRIBUTES)).await;
    let read = c.open(Create::new("f").access(READ)).await;
    let set_attributes = c
        .open(Create::new("f").access(READ | WRITE_ATTRIBUTES))
        .await;
    assert_eq!(
        c.fsctl(HOME, SET_SPARSE, file, &[1], 16384).await,
        (OK, Some(Vec::new()))
    );
    assert_eq!(
        c.fsctl(HOME, SET_SPARSE, set_attributes, &[1], 0).await,
        (OK, Some(Vec::new())),
        "write attributes alone"
    );
    for (name, id, expected) in [
        ("attributes only", attributes, DENIED),
        ("read only", read, DENIED),
        ("a directory", dir, INVALID),
        ("a stream", stream, INVALID),
    ] {
        assert_eq!(
            c.fsctl(HOME, SET_SPARSE, id, &[1], 0).await,
            (expected, None),
            "{name}"
        );
    }
}

#[tokio::test]
async fn set_sparse_is_not_served_on_the_other_shares() {
    let files = MemFsBackend::new()
        .with_file("f", &[0; 100])
        .with_stream("f", "x", b"");
    let spy = Spy::new(Fast::Unsupported);
    spy.clone_as(Cloning::Full);
    let off = Share::new("home", SpyFs::new(&files, &spy))
        .public()
        .server_side_copy(false);
    let shares = [
        ("a backend that does not clone", server(&files)),
        ("copies off", server_on(vec![off])),
    ];
    for (name, state) in shares {
        let mut c = Client::new(&state).await;
        let file = c.open(Create::new("f")).await;
        let stream = c.open(Create::new("f:x")).await;
        for (on, id, expected) in [("a file", file, UNSUPPORTED), ("a stream", stream, INVALID)] {
            assert_eq!(
                c.fsctl(HOME, SET_SPARSE, id, &[1], 0).await,
                (expected, None),
                "{name}, on {on}"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Files on the host
// ---------------------------------------------------------------------------

#[cfg(all(feature = "localfs", target_os = "linux"))]
mod local {
    use super::*;
    use crate::fs::LocalFsBackend;
    use crate::tests::data::allocation_unit;

    #[tokio::test]
    async fn a_clone_works_where_the_share_says_it_does_and_is_refused_elsewhere() {
        let td = tempfile::tempdir().unwrap();
        let backend = LocalFsBackend::new(td.path()).unwrap();
        let unit = allocation_unit(&backend).await;
        let len = 4 * unit as usize;
        let data = pattern(len, 0x51);
        std::fs::write(td.path().join("s"), &data).unwrap();
        std::fs::write(td.path().join("t"), vec![0; len]).unwrap();
        let clones = backend.capabilities().block_cloning;
        let state = server_on(vec![Share::new("home", backend).public()]);
        let mut c = Client::new(&state).await;
        assert_eq!(
            c.fs_attributes().await & FILE_SUPPORTS_BLOCK_REFCOUNTING != 0,
            clones
        );
        let source = c.open(Create::new("s")).await;
        let target = c.open(Create::new("t")).await;
        let expected = if clones {
            (OK, Some(Vec::new()))
        } else {
            (DEVICE, None)
        };
        assert_eq!(
            c.duplicate(source, unit, target, 0, 2 * unit).await,
            expected
        );
        let mut target_data = vec![0; len];
        if clones {
            target_data[..2 * unit as usize]
                .copy_from_slice(&data[unit as usize..3 * unit as usize]);
        }
        assert_eq!(std::fs::read(td.path().join("t")).unwrap(), target_data);
    }

    #[tokio::test]
    async fn a_source_that_ends_inside_its_last_unit_is_cloned_to_a_target_of_its_size_only() {
        let td = tempfile::tempdir().unwrap();
        let backend = LocalFsBackend::new(td.path()).unwrap();
        let unit = allocation_unit(&backend).await;
        let size = 3 * unit as usize + 1000;
        let data = pattern(size, 0x52);
        std::fs::write(td.path().join("s"), &data).unwrap();
        std::fs::write(td.path().join("same"), vec![0; size]).unwrap();
        std::fs::write(td.path().join("longer"), vec![0; 4 * unit as usize]).unwrap();
        let clones = backend.capabilities().block_cloning;
        let state = server_on(vec![Share::new("home", backend).public()]);
        let mut c = Client::new(&state).await;
        let source = c.open(Create::new("s")).await;
        let same = c.open(Create::new("same")).await;
        let longer = c.open(Create::new("longer")).await;
        let (to_same, to_longer) = if clones {
            ((OK, Some(Vec::new())), (UNSUPPORTED, None))
        } else {
            ((DEVICE, None), (DEVICE, None))
        };
        assert_eq!(c.duplicate(source, 0, longer, 0, 4 * unit).await, to_longer);
        assert_eq!(c.duplicate(source, 0, same, 0, 4 * unit).await, to_same);
        let expected = if clones { data } else { vec![0; size] };
        assert_eq!(std::fs::read(td.path().join("same")).unwrap(), expected);
        assert_eq!(
            std::fs::read(td.path().join("longer")).unwrap(),
            vec![0; 4 * unit as usize]
        );
    }
}
