//! File operations against `LocalFsBackend` over TCP loopback, each test on
//! its own server with an anonymous session.

mod common;

use common::client::*;
use common::{
    anonymous_session_setup, build_header, id_both_entries, negotiate, parse_response_header,
    read_frame, start_server, tree_connect, utf16le, write_frame,
};
use smb_server::ntstatus::STATUS_SUCCESS;
use smb_server::wire::header::Command;
use smb_server::wire::messages::{
    CloseRequest, CloseResponse, CreateContext, CreateRequest, CreateResponse,
    QueryDirectoryRequest, ReadRequest, ReadResponse, WriteRequest, WriteResponse,
};
use smb_server::{
    BackendCapabilities, Handle, LocalFsBackend, OpenAction, OpenOptions, ShareBackend, SmbError,
    SmbPath, SmbResult,
};
use smb_server::{Share, SmbServer, ntstatus};
use tempfile::tempdir;
use tokio::net::TcpStream;

#[tokio::test]
async fn end_to_end_anon_write_then_read_localfs() {
    // Empty share root; CREATE makes `out.txt`.
    let td = tempdir().expect("tempdir");
    let backend = LocalFsBackend::new(td.path()).expect("open root");

    let (addr, handle) =
        start_server(SmbServer::builder().share(Share::new("share", backend).public())).await;

    let mut s = TcpStream::connect(addr).await.expect("connect");

    let _ = negotiate(&mut s).await;
    let session_id = anonymous_session_setup(&mut s).await;
    let tree_id = tree_connect(&mut s, "\\\\127.0.0.1\\share", session_id, 3).await;

    // ---- CREATE out.txt with write+create-new intent --------------------
    let name_u16 = utf16le("out.txt");
    let cr_req = CreateRequest {
        structure_size: 57,
        security_flags: 0,
        requested_oplock_level: 0,
        impersonation_level: 2,
        smb_create_flags: 0,
        reserved: 0,
        // FILE_GENERIC_READ | FILE_GENERIC_WRITE.
        desired_access: 0x0012_0089 | 0x0012_0116,
        file_attributes: 0,
        share_access: 0x0000_0007,
        // FILE_OVERWRITE_IF
        create_disposition: 5,
        create_options: 0,
        name_offset: 0x78,
        name_length: name_u16.len() as u16,
        create_contexts_offset: 0,
        create_contexts_length: 0,
        name: name_u16,
        create_contexts: vec![],
    };
    let mut body = Vec::new();
    cr_req.write_to(&mut body).expect("write");
    let hdr = build_header(Command::Create, 4, session_id, tree_id);
    write_frame(&mut s, &hdr, &body).await;
    let resp = read_frame(&mut s).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(
        rh.channel_sequence_status, STATUS_SUCCESS,
        "CREATE failed with status {:#010x}",
        rh.channel_sequence_status
    );
    let cr_resp = CreateResponse::parse(rb).expect("parse create resp");
    let file_id = cr_resp.file_id;

    // ---- WRITE the bytes ------------------------------------------------
    let payload = b"written-from-smb";
    let wr_req = WriteRequest {
        structure_size: 49,
        data_offset: WriteRequest::STANDARD_DATA_OFFSET,
        length: payload.len() as u32,
        offset: 0,
        file_id,
        channel: 0,
        remaining_bytes: 0,
        write_channel_info_offset: 0,
        write_channel_info_length: 0,
        flags: 0,
        data: payload.to_vec(),
    };
    let mut body = Vec::new();
    wr_req.write_to(&mut body).expect("write");
    let hdr = build_header(Command::Write, 5, session_id, tree_id);
    write_frame(&mut s, &hdr, &body).await;
    let resp = read_frame(&mut s).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(
        rh.channel_sequence_status, STATUS_SUCCESS,
        "WRITE failed with status {:#010x}",
        rh.channel_sequence_status
    );
    let wr_resp = WriteResponse::parse(rb).expect("parse write resp");
    assert_eq!(wr_resp.count as usize, payload.len());

    // ---- READ back to confirm the bytes landed --------------------------
    let rd_req = ReadRequest {
        structure_size: 49,
        padding: ReadResponse::STANDARD_DATA_OFFSET,
        flags: 0,
        length: 64,
        offset: 0,
        file_id,
        minimum_count: 0,
        channel: 0,
        remaining_bytes: 0,
        read_channel_info_offset: 0,
        read_channel_info_length: 0,
        buffer: vec![0],
    };
    let mut body = Vec::new();
    rd_req.write_to(&mut body).expect("write");
    let hdr = build_header(Command::Read, 6, session_id, tree_id);
    write_frame(&mut s, &hdr, &body).await;
    let resp = read_frame(&mut s).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let rd_resp = ReadResponse::parse(rb).expect("parse read resp");
    assert_eq!(rd_resp.data.as_slice(), payload);

    // ---- CLOSE ----------------------------------------------------------
    let cl_req = CloseRequest {
        structure_size: 24,
        flags: 0,
        reserved: 0,
        file_id,
    };
    let mut body = Vec::new();
    cl_req.write_to(&mut body).expect("write");
    let hdr = build_header(Command::Close, 7, session_id, tree_id);
    write_frame(&mut s, &hdr, &body).await;
    let resp = read_frame(&mut s).await;
    let (rh, rb) = parse_response_header(&resp);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let _ = CloseResponse::parse(rb).expect("parse close resp");

    // The file on disk holds the written bytes.
    let on_disk = std::fs::read(td.path().join("out.txt")).expect("file on disk");
    assert_eq!(on_disk, payload);

    drop(s);
    handle.abort();
}

fn rename_info(new_name: &str, replace: bool) -> Vec<u8> {
    let name = utf16le(new_name);
    let mut buf = vec![0u8; 16];
    buf[0] = replace.into(); // ReplaceIfExists
    buf.extend_from_slice(&(name.len() as u32).to_le_bytes());
    buf.extend_from_slice(&name);
    buf
}

fn basic_info_with_write_time() -> Vec<u8> {
    let mut buf = vec![0u8; 40];
    buf[16..24].copy_from_slice(&0x01D0_0000_0000_0000u64.to_le_bytes());
    buf
}

#[tokio::test]
async fn read_only_share_denies_delete_and_write_opens() {
    let td = tempdir().expect("tempdir");
    std::fs::write(td.path().join("keep.txt"), b"keep").expect("write keep.txt");
    let backend = LocalFsBackend::new(td.path()).expect("open root");
    let server =
        Server::start(SmbServer::builder().share(Share::new("share", backend).public_read_only()))
            .await;
    let mut c = server.client().await;

    for access in [DELETE, FILE_WRITE_ATTRIBUTES] {
        assert_eq!(
            c.open("keep.txt", FILE_GENERIC_READ | access, SHARE_ALL)
                .await
                .unwrap_err(),
            ntstatus::STATUS_ACCESS_DENIED,
            "access {access:#x}"
        );
    }
    assert_eq!(
        c.open_with_options("keep.txt", FILE_GENERIC_READ, FILE_DELETE_ON_CLOSE)
            .await
            .unwrap_err(),
        ntstatus::STATUS_ACCESS_DENIED
    );
    assert!(td.path().join("keep.txt").exists());
}

#[tokio::test]
async fn read_write_share_checks_open_access() {
    let td = tempdir().expect("tempdir");
    for name in ["doc.txt", "disp.txt", "ren.txt", "ro.txt"] {
        std::fs::write(td.path().join(name), b"x").expect("write file");
    }
    let backend = LocalFsBackend::new(td.path()).expect("open root");
    let server = Server::public(backend).await;
    let mut c = server.client().await;

    // Delete-on-close with DELETE access removes the file on CLOSE.
    let file_id = c
        .open_with_options("doc.txt", FILE_GENERIC_READ | DELETE, FILE_DELETE_ON_CLOSE)
        .await
        .unwrap();
    c.close(file_id).await;
    assert!(!td.path().join("doc.txt").exists());

    // Delete-on-close without DELETE access is rejected.
    assert_eq!(
        c.open_with_options("ro.txt", FILE_GENERIC_READ, FILE_DELETE_ON_CLOSE)
            .await
            .unwrap_err(),
        ntstatus::STATUS_INVALID_PARAMETER
    );

    // FileDispositionInformation on an open with DELETE access.
    let file_id = c.open("disp.txt", DELETE, SHARE_ALL).await.unwrap();
    assert_eq!(
        c.set_info(file_id, FILE_DISPOSITION_INFORMATION, vec![1])
            .await,
        STATUS_SUCCESS
    );
    c.close(file_id).await;
    assert!(!td.path().join("disp.txt").exists());

    // Rename and timestamps on an open with DELETE and FILE_WRITE_ATTRIBUTES.
    let file_id = c
        .open(
            "ren.txt",
            FILE_GENERIC_READ | DELETE | FILE_WRITE_ATTRIBUTES,
            SHARE_ALL,
        )
        .await
        .unwrap();
    assert_eq!(
        c.set_info(
            file_id,
            FILE_BASIC_INFORMATION,
            basic_info_with_write_time()
        )
        .await,
        STATUS_SUCCESS
    );
    assert_eq!(
        c.set_info(
            file_id,
            FILE_RENAME_INFORMATION,
            rename_info("renamed.txt", false)
        )
        .await,
        STATUS_SUCCESS
    );
    c.close(file_id).await;
    assert!(td.path().join("renamed.txt").exists());

    // A read-only open on a writable share lacks DELETE and FILE_WRITE_ATTRIBUTES.
    let file_id = c
        .open("ro.txt", FILE_GENERIC_READ, SHARE_ALL)
        .await
        .unwrap();
    for (class, buffer) in [
        (FILE_DISPOSITION_INFORMATION, vec![1]),
        (FILE_RENAME_INFORMATION, rename_info("ro-moved.txt", false)),
        (FILE_BASIC_INFORMATION, basic_info_with_write_time()),
    ] {
        assert_eq!(
            c.set_info(file_id, class, buffer).await,
            ntstatus::STATUS_ACCESS_DENIED
        );
    }
    // SET_INFO for a class it does not handle returns STATUS_NOT_SUPPORTED
    // whatever the open's access.
    assert_eq!(
        c.set_info(file_id, FILE_SHORT_NAME_INFORMATION, vec![0; 8])
            .await,
        ntstatus::STATUS_NOT_SUPPORTED
    );
    c.close(file_id).await;
    assert!(td.path().join("ro.txt").exists());
    assert!(!td.path().join("ro-moved.txt").exists());
}

#[tokio::test]
async fn rename_with_replace_if_exists() {
    let td = tempdir().expect("tempdir");
    let root = td.path();
    for (name, data) in [("doc.txt", "old"), ("tmp.txt", "new"), ("busy.txt", "busy")] {
        std::fs::write(root.join(name), data).expect("write file");
    }
    std::fs::create_dir(root.join("dir")).expect("mkdir");
    let backend = LocalFsBackend::new(root).expect("open root");
    let server = Server::public(backend).await;
    let mut c = server.client().await;

    let tmp = c.open("tmp.txt", DELETE, SHARE_ALL).await.unwrap();
    assert_eq!(
        c.set_info(tmp, FILE_RENAME_INFORMATION, rename_info("doc.txt", false))
            .await,
        ntstatus::STATUS_OBJECT_NAME_COLLISION
    );
    assert_eq!(
        c.set_info(tmp, FILE_RENAME_INFORMATION, rename_info("dir", true))
            .await,
        ntstatus::STATUS_ACCESS_DENIED
    );
    let busy = c
        .open("busy.txt", FILE_GENERIC_READ, SHARE_ALL)
        .await
        .unwrap();
    assert_eq!(
        c.set_info(tmp, FILE_RENAME_INFORMATION, rename_info("busy.txt", true))
            .await,
        ntstatus::STATUS_ACCESS_DENIED
    );
    c.close(busy).await;
    assert_eq!(
        c.set_info(tmp, FILE_RENAME_INFORMATION, rename_info("doc.txt", true))
            .await,
        STATUS_SUCCESS
    );
    c.close(tmp).await;

    assert_eq!(std::fs::read(root.join("doc.txt")).unwrap(), b"new");
    assert!(!root.join("tmp.txt").exists());
    assert_eq!(std::fs::read(root.join("busy.txt")).unwrap(), b"busy");
    assert!(root.join("dir").is_dir());
}

#[tokio::test]
async fn file_id_is_stable_across_opens_and_matches_listing() {
    let td = tempdir().expect("tempdir");
    std::fs::write(td.path().join("f.txt"), b"x").expect("write file");
    let backend = LocalFsBackend::new(td.path()).expect("open root");
    let server = Server::public(backend).await;
    let mut c = server.client().await;

    let first = c.open("f.txt", FILE_GENERIC_READ, SHARE_ALL).await.unwrap();
    let second = c.open("f.txt", FILE_GENERIC_READ, SHARE_ALL).await.unwrap();
    let id = c
        .query_file_info(first, FILE_INTERNAL_INFORMATION)
        .await
        .unwrap();
    let id = u64::from_le_bytes(id[..8].try_into().unwrap());
    assert_ne!(id, 0);
    let second_id = c
        .query_file_info(second, FILE_INTERNAL_INFORMATION)
        .await
        .unwrap();
    assert_eq!(second_id, id.to_le_bytes());
    // FileAllInformation: Basic (40) and Standard (24) come before Internal.
    let all = c
        .query_file_info(second, FILE_ALL_INFORMATION)
        .await
        .unwrap();
    assert_eq!(all[64..72], id.to_le_bytes());

    let root = c.open_dir("").await;
    let (status, buf) = c
        .query_directory(
            root,
            FILE_ID_BOTH_DIRECTORY_INFORMATION,
            QueryDirectoryRequest::FLAG_RESTART_SCANS,
            "*",
            4096,
        )
        .await;
    assert_eq!(status, STATUS_SUCCESS);
    let listed = id_both_entries(&buf);
    assert!(
        listed
            .iter()
            .any(|(name, file_id, _)| name == "f.txt" && *file_id == id),
        "id {id:#x}, listed {listed:?}"
    );
}

/// AccessFlags of a FileAllInformation buffer: after Basic (40), Standard
/// (24), Internal (8) and EA (4).
fn all_info_access(buf: &[u8]) -> u32 {
    u32::from_le_bytes(buf[76..80].try_into().unwrap())
}

#[tokio::test]
async fn read_and_write_check_the_open_access() {
    let td = tempdir().expect("tempdir");
    let path = td.path().join("f.txt");
    std::fs::write(&path, b"data").expect("write file");
    let backend = LocalFsBackend::new(td.path()).expect("open root");
    let server = Server::public(backend).await;
    let mut c = server.client().await;

    let attrs = c
        .open("f.txt", FILE_READ_DATA | FILE_WRITE_ATTRIBUTES, SHARE_ALL)
        .await
        .unwrap();
    assert_eq!(
        c.write(attrs, 0, b"XXXX").await.unwrap_err(),
        ntstatus::STATUS_ACCESS_DENIED
    );
    c.read(attrs, 0, 64).await.unwrap();
    c.close(attrs).await;

    let write_only = c.open("f.txt", FILE_WRITE_DATA, SHARE_ALL).await.unwrap();
    assert_eq!(
        c.read(write_only, 0, 64).await.unwrap_err(),
        ntstatus::STATUS_ACCESS_DENIED
    );
    c.write(write_only, 0, b"D").await.unwrap();
    c.close(write_only).await;

    let append = c.open("f.txt", FILE_APPEND_DATA, SHARE_ALL).await.unwrap();
    c.write(append, 4, b"!").await.unwrap();
    c.close(append).await;

    assert_eq!(std::fs::read(&path).unwrap(), b"Data!");
}

#[tokio::test]
async fn query_info_reports_the_open_access() {
    let td = tempdir().expect("tempdir");
    std::fs::write(td.path().join("f.txt"), b"x").expect("write file");
    let backend = LocalFsBackend::new(td.path()).expect("open root");
    let server = Server::public(backend).await;
    let mut c = server.client().await;

    let access = FILE_READ_ATTRIBUTES | DELETE | SYNCHRONIZE;
    let file_id = c.open("f.txt", access, SHARE_ALL).await.unwrap();
    let info = c
        .query_file_info(file_id, FILE_ACCESS_INFORMATION)
        .await
        .unwrap();
    assert_eq!(info, access.to_le_bytes());
    let all = c
        .query_file_info(file_id, FILE_ALL_INFORMATION)
        .await
        .unwrap();
    assert_eq!(all_info_access(&all), access);
    c.close(file_id).await;
}

#[tokio::test]
async fn maximum_allowed_on_read_only_share_grants_read_access() {
    let td = tempdir().expect("tempdir");
    std::fs::write(td.path().join("f.txt"), b"data").expect("write file");
    let backend = LocalFsBackend::new(td.path()).expect("open root");
    let server =
        Server::start(SmbServer::builder().share(Share::new("share", backend).public_read_only()))
            .await;
    let mut c = server.client().await;

    let file_id = c.open("f.txt", MAXIMUM_ALLOWED, SHARE_ALL).await.unwrap();
    let info = c
        .query_file_info(file_id, FILE_ACCESS_INFORMATION)
        .await
        .unwrap();
    assert_eq!(
        info,
        (FILE_GENERIC_READ | FILE_GENERIC_EXECUTE).to_le_bytes()
    );
    c.read(file_id, 0, 64).await.unwrap();
    assert_eq!(
        c.write(file_id, 0, b"X").await.unwrap_err(),
        ntstatus::STATUS_ACCESS_DENIED
    );
    c.close(file_id).await;

    assert_eq!(std::fs::read(td.path().join("f.txt")).unwrap(), b"data");
}

/// `LocalFsBackend` whose host refuses to open files for writing, as for a
/// file without write permission.
struct NoWriteOpens(LocalFsBackend);

#[async_trait::async_trait]
impl ShareBackend for NoWriteOpens {
    async fn open(
        &self,
        path: &SmbPath,
        opts: OpenOptions,
    ) -> SmbResult<(Box<dyn Handle>, OpenAction)> {
        if opts.write {
            return Err(SmbError::AccessDenied);
        }
        self.0.open(path, opts).await
    }

    async fn unlink(&self, path: &SmbPath) -> SmbResult<()> {
        self.0.unlink(path).await
    }

    async fn rename(&self, from: &SmbPath, to: &SmbPath, replace_if_exists: bool) -> SmbResult<()> {
        self.0.rename(from, to, replace_if_exists).await
    }

    fn capabilities(&self) -> BackendCapabilities {
        self.0.capabilities()
    }
}

#[tokio::test]
async fn delete_style_open_needs_no_host_write_access() {
    let td = tempdir().expect("tempdir");
    for name in ["doc.txt", "disp.txt"] {
        std::fs::write(td.path().join(name), b"x").expect("write file");
    }
    let backend = NoWriteOpens(LocalFsBackend::new(td.path()).expect("open root"));
    let server = Server::public(backend).await;
    let mut c = server.client().await;

    let delete_access = DELETE | FILE_READ_ATTRIBUTES | SYNCHRONIZE;
    let file_id = c
        .open_with_options("doc.txt", delete_access, FILE_DELETE_ON_CLOSE)
        .await
        .unwrap();
    c.close(file_id).await;
    assert!(!td.path().join("doc.txt").exists());

    let file_id = c.open("disp.txt", delete_access, SHARE_ALL).await.unwrap();
    assert_eq!(
        c.set_info(file_id, FILE_DISPOSITION_INFORMATION, vec![1])
            .await,
        STATUS_SUCCESS
    );
    c.close(file_id).await;
    assert!(!td.path().join("disp.txt").exists());
}

#[tokio::test]
async fn rename_moves_other_opens_of_the_file() {
    let td = tempdir().expect("tempdir");
    let root = td.path();
    for (name, data) in [("x.txt", "x"), ("z.txt", "z")] {
        std::fs::write(root.join(name), data).expect("write file");
    }
    let backend = LocalFsBackend::new(root).expect("open root");
    let server = Server::public(backend).await;
    let mut c = server.client().await;

    let a = c.open("x.txt", DELETE, SHARE_ALL).await.unwrap();
    let b = c
        .open("x.txt", FILE_GENERIC_READ | DELETE, SHARE_ALL)
        .await
        .unwrap();
    assert_eq!(
        c.set_info(a, FILE_RENAME_INFORMATION, rename_info("y.txt", false))
            .await,
        STATUS_SUCCESS
    );
    c.close(a).await;

    // `b` has y.txt open after the rename, so y.txt is not replaced.
    let z = c.open("z.txt", DELETE, SHARE_ALL).await.unwrap();
    assert_eq!(
        c.set_info(z, FILE_RENAME_INFORMATION, rename_info("y.txt", true))
            .await,
        ntstatus::STATUS_ACCESS_DENIED
    );
    c.close(z).await;

    // Delete-on-close through `b` removes y.txt, not a new x.txt.
    std::fs::write(root.join("x.txt"), b"new").expect("write file");
    assert_eq!(
        c.set_info(b, FILE_DISPOSITION_INFORMATION, vec![1]).await,
        STATUS_SUCCESS
    );
    c.close(b).await;
    assert!(!root.join("y.txt").exists());
    assert_eq!(std::fs::read(root.join("x.txt")).unwrap(), b"new");
    assert_eq!(std::fs::read(root.join("z.txt")).unwrap(), b"z");
}

#[tokio::test]
async fn a_directory_with_an_open_file_below_is_not_renamed() {
    let td = tempdir().expect("tempdir");
    let root = td.path();
    std::fs::create_dir_all(root.join("d").join("sub")).expect("mkdir");
    std::fs::write(root.join("d").join("sub").join("f.txt"), b"f").expect("write file");
    let backend = LocalFsBackend::new(root).expect("open root");
    let server = Server::public(backend).await;
    let mut c = server.client().await;

    let child = c
        .open_with_options(
            "d\\sub\\f.txt",
            FILE_GENERIC_READ | DELETE,
            FILE_DELETE_ON_CLOSE,
        )
        .await
        .unwrap();
    let dir = c
        .open_with_options("d", DELETE, FILE_DIRECTORY_FILE)
        .await
        .unwrap();
    let status = c
        .set_info(dir, FILE_RENAME_INFORMATION, rename_info("e", false))
        .await;
    assert_eq!(status, ntstatus::STATUS_ACCESS_DENIED);
    c.close(child).await;
    assert!(!root.join("d").join("sub").join("f.txt").exists());
    assert!(!root.join("e").exists());

    let status = c
        .set_info(dir, FILE_RENAME_INFORMATION, rename_info("e", false))
        .await;
    assert_eq!(status, STATUS_SUCCESS);
    c.close(dir).await;
    assert!(root.join("e").join("sub").is_dir());
}

#[tokio::test]
async fn directory_renames_while_it_is_open() {
    let td = tempdir().expect("tempdir");
    let root = td.path();
    std::fs::create_dir_all(root.join("d").join("sub")).expect("mkdir");
    let backend = LocalFsBackend::new(root).expect("open root");
    let server = Server::public(backend).await;
    let mut c = server.client().await;

    let listing = c.open_dir("d").await;
    let dir = c
        .open_with_options("d", DELETE, FILE_DIRECTORY_FILE)
        .await
        .unwrap();
    assert_eq!(
        c.set_info(dir, FILE_RENAME_INFORMATION, rename_info("e", false))
            .await,
        STATUS_SUCCESS
    );
    c.close(dir).await;
    assert_eq!(
        c.list(listing, QueryDirectoryRequest::FLAG_RESTART_SCANS, "*")
            .await
            .unwrap(),
        [".", "..", "sub"]
    );
    c.close(listing).await;
    assert!(root.join("e").join("sub").is_dir());
    assert!(!root.join("d").exists());
}

/// FileBasicInformation buffer: creation, access, write and change times,
/// then attributes.
fn basic_info(times: [i64; 4], attributes: u32) -> Vec<u8> {
    let mut buf = Vec::with_capacity(40);
    for t in times {
        buf.extend_from_slice(&t.to_le_bytes());
    }
    buf.extend_from_slice(&attributes.to_le_bytes());
    buf.extend_from_slice(&[0; 4]);
    buf
}

fn filetime(t: std::time::SystemTime) -> i64 {
    let since_epoch = t.duration_since(std::time::UNIX_EPOCH).unwrap();
    116_444_736_000_000_000 + (since_epoch.as_nanos() / 100) as i64
}

fn attributes_of(basic: &[u8]) -> u32 {
    u32::from_le_bytes(basic[32..36].try_into().unwrap())
}

#[tokio::test]
async fn allocation_below_end_of_file_truncates() {
    let td = tempdir().expect("tempdir");
    let path = td.path().join("f.txt");
    std::fs::write(&path, b"hello world").expect("write file");
    let backend = LocalFsBackend::new(td.path()).expect("open root");
    let server = Server::public(backend).await;
    let mut c = server.client().await;

    let file_id = c
        .open("f.txt", FILE_GENERIC_WRITE, SHARE_ALL)
        .await
        .unwrap();
    for (size, expected) in [(100u64, &b"hello world"[..]), (5, b"hello")] {
        assert_eq!(
            c.set_info(
                file_id,
                FILE_ALLOCATION_INFORMATION,
                size.to_le_bytes().to_vec()
            )
            .await,
            STATUS_SUCCESS
        );
        assert_eq!(std::fs::read(&path).unwrap(), expected, "allocation {size}");
    }
    c.close(file_id).await;
}

#[tokio::test]
async fn directory_attribute_is_accepted_on_a_directory() {
    let td = tempdir().expect("tempdir");
    std::fs::create_dir(td.path().join("d")).expect("mkdir");
    let backend = LocalFsBackend::new(td.path()).expect("open root");
    let server = Server::public(backend).await;
    let mut c = server.client().await;

    let dir = c
        .open_with_options(
            "d",
            FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES,
            FILE_DIRECTORY_FILE,
        )
        .await
        .unwrap();
    assert_eq!(
        c.set_info(
            dir,
            FILE_BASIC_INFORMATION,
            basic_info([0; 4], FILE_ATTRIBUTE_DIRECTORY)
        )
        .await,
        STATUS_SUCCESS
    );
    c.close(dir).await;
}

#[tokio::test]
async fn special_time_values_are_not_written_as_times() {
    let td = tempdir().expect("tempdir");
    let path = td.path().join("f.txt");
    std::fs::write(&path, b"data").expect("write file");
    let t0 = std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_577_934_245);
    std::fs::OpenOptions::new()
        .write(true)
        .open(&path)
        .unwrap()
        .set_times(std::fs::FileTimes::new().set_accessed(t0).set_modified(t0))
        .unwrap();
    let times = || {
        let md = std::fs::metadata(&path).unwrap();
        (md.accessed().unwrap(), md.modified().unwrap())
    };
    let backend = LocalFsBackend::new(td.path()).expect("open root");
    let server = Server::public(backend).await;
    let mut c = server.client().await;
    let file_id = c
        .open("f.txt", FILE_GENERIC_READ | FILE_GENERIC_WRITE, SHARE_ALL)
        .await
        .unwrap();

    // Setting -2 or -1 leaves both times unchanged.
    for t in [-2, -1] {
        assert_eq!(
            c.set_info(file_id, FILE_BASIC_INFORMATION, basic_info([t; 4], 0))
                .await,
            STATUS_SUCCESS
        );
        assert_eq!(times(), (t0, t0), "time value {t}");
    }
    // After -1 a write through the open leaves the write time alone.
    c.write(file_id, 4, b"more").await.unwrap();
    assert_eq!(times().1, t0);
    // After -2 it updates it again. NTFS keeps a time fixed for a handle
    // once a time is set through it, so a Windows host keeps it.
    assert_eq!(
        c.set_info(
            file_id,
            FILE_BASIC_INFORMATION,
            basic_info([0, 0, -2, 0], 0)
        )
        .await,
        STATUS_SUCCESS
    );
    c.write(file_id, 8, b"!").await.unwrap();
    if cfg!(windows) {
        assert_eq!(times().1, t0);
    } else {
        assert_ne!(times().1, t0);
    }
    assert_eq!(
        c.set_info(
            file_id,
            FILE_BASIC_INFORMATION,
            basic_info([0, -3, 0, 0], 0)
        )
        .await,
        ntstatus::STATUS_INVALID_PARAMETER
    );
    c.close(file_id).await;
    assert_eq!(std::fs::read(&path).unwrap(), b"datamore!");
}

#[tokio::test]
async fn deleting_a_non_empty_directory_fails() {
    let td = tempdir().expect("tempdir");
    let root = td.path();
    std::fs::create_dir(root.join("full")).expect("mkdir");
    std::fs::write(root.join("full").join("f.txt"), b"f").expect("write file");
    std::fs::create_dir(root.join("empty")).expect("mkdir");
    let backend = LocalFsBackend::new(root).expect("open root");
    let server = Server::public(backend).await;
    let mut c = server.client().await;

    let dir = c
        .open_with_options("full", DELETE, FILE_DIRECTORY_FILE)
        .await
        .unwrap();
    assert_eq!(
        c.set_info(dir, FILE_DISPOSITION_INFORMATION, vec![1]).await,
        ntstatus::STATUS_DIRECTORY_NOT_EMPTY
    );
    c.close(dir).await;
    assert!(root.join("full").join("f.txt").exists());

    // MS-FSA 2.1.5.1 accepts delete-on-close on a non-empty directory and
    // 2.1.5.5 keeps the directory at close.
    let dir = c
        .open_with_options("full", DELETE, FILE_DIRECTORY_FILE | FILE_DELETE_ON_CLOSE)
        .await
        .unwrap();
    c.close(dir).await;
    assert!(root.join("full").join("f.txt").exists());

    let dir = c
        .open_with_options("empty", DELETE, FILE_DIRECTORY_FILE)
        .await
        .unwrap();
    assert_eq!(
        c.set_info(dir, FILE_DISPOSITION_INFORMATION, vec![1]).await,
        STATUS_SUCCESS
    );
    c.close(dir).await;
    assert!(!root.join("empty").exists());
}

#[tokio::test]
async fn read_only_attribute_is_applied_and_others_are_rejected() {
    let td = tempdir().expect("tempdir");
    let path = td.path().join("f.txt");
    std::fs::write(&path, b"x").expect("write file");
    let backend = LocalFsBackend::new(td.path()).expect("open root");
    let server = Server::public(backend).await;
    let mut c = server.client().await;
    let attrs_access = FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES;

    let file_id = c.open("f.txt", attrs_access, SHARE_ALL).await.unwrap();
    assert_eq!(
        c.set_info(
            file_id,
            FILE_BASIC_INFORMATION,
            basic_info([0; 4], FILE_ATTRIBUTE_READONLY)
        )
        .await,
        STATUS_SUCCESS
    );
    let basic = c
        .query_file_info(file_id, FILE_BASIC_INFORMATION)
        .await
        .unwrap();
    assert_eq!(attributes_of(&basic), FILE_ATTRIBUTE_READONLY);
    assert!(std::fs::metadata(&path).unwrap().permissions().readonly());
    c.close(file_id).await;

    // A read-only file cannot be deleted.
    let file_id = c.open("f.txt", DELETE, SHARE_ALL).await.unwrap();
    assert_eq!(
        c.set_info(file_id, FILE_DISPOSITION_INFORMATION, vec![1])
            .await,
        ntstatus::STATUS_CANNOT_DELETE
    );
    c.close(file_id).await;
    assert_eq!(
        c.open_with_options("f.txt", DELETE, FILE_DELETE_ON_CLOSE)
            .await
            .unwrap_err(),
        ntstatus::STATUS_CANNOT_DELETE
    );
    assert!(path.exists());

    let file_id = c.open("f.txt", attrs_access, SHARE_ALL).await.unwrap();
    assert_eq!(
        c.set_info(
            file_id,
            FILE_BASIC_INFORMATION,
            basic_info([0; 4], FILE_ATTRIBUTE_HIDDEN)
        )
        .await,
        ntstatus::STATUS_NOT_SUPPORTED
    );
    for attributes in [FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_ARCHIVE] {
        assert_eq!(
            c.set_info(
                file_id,
                FILE_BASIC_INFORMATION,
                basic_info([0; 4], attributes)
            )
            .await,
            STATUS_SUCCESS,
            "attributes {attributes:#x}"
        );
    }
    let basic = c
        .query_file_info(file_id, FILE_BASIC_INFORMATION)
        .await
        .unwrap();
    assert_eq!(attributes_of(&basic), FILE_ATTRIBUTE_NORMAL);
    assert_eq!(
        c.set_info(
            file_id,
            FILE_BASIC_INFORMATION,
            basic_info([0; 4], FILE_ATTRIBUTE_DIRECTORY)
        )
        .await,
        ntstatus::STATUS_INVALID_PARAMETER
    );
    c.close(file_id).await;
    assert!(!std::fs::metadata(&path).unwrap().permissions().readonly());
}

/// A creation time in the same FileBasicInformation does not stop the write
/// time from applying.
#[tokio::test]
async fn write_time_applies_with_a_creation_time() {
    let td = tempdir().expect("tempdir");
    std::fs::write(td.path().join("f.txt"), b"x").expect("write file");
    std::fs::create_dir(td.path().join("d")).expect("mkdir");
    let backend = LocalFsBackend::new(td.path()).expect("open root");
    let server = Server::public(backend).await;
    let mut c = server.client().await;

    let t = std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_577_934_245);
    for (name, options) in [("f.txt", 0), ("d", FILE_DIRECTORY_FILE)] {
        let file_id = c
            .open_with_options(name, FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES, options)
            .await
            .unwrap();
        assert_eq!(
            c.set_info(
                file_id,
                FILE_BASIC_INFORMATION,
                basic_info([filetime(t), 0, filetime(t), 0], FILE_ATTRIBUTE_NORMAL)
            )
            .await,
            STATUS_SUCCESS,
            "{name}"
        );
        c.close(file_id).await;
        let md = std::fs::metadata(td.path().join(name)).unwrap();
        assert_eq!(md.modified().unwrap(), t, "{name}");
        if cfg!(any(windows, target_os = "macos")) {
            assert_eq!(md.created().unwrap(), t, "{name}");
        }
    }
}

#[tokio::test]
async fn alternate_name_query_reports_no_short_name() {
    let td = tempdir().expect("tempdir");
    std::fs::write(td.path().join("a long name.txt"), b"x").expect("write file");
    let backend = LocalFsBackend::new(td.path()).expect("open root");
    let server = Server::public(backend).await;
    let mut c = server.client().await;

    let file_id = c
        .open("a long name.txt", FILE_READ_ATTRIBUTES, SHARE_ALL)
        .await
        .unwrap();
    assert_eq!(
        c.query_file_info(file_id, FILE_ALTERNATE_NAME_INFORMATION)
            .await
            .unwrap_err(),
        ntstatus::STATUS_OBJECT_NAME_NOT_FOUND
    );
    c.close(file_id).await;
}

#[tokio::test]
async fn query_directory_applies_dos_wildcards() {
    let td = tempdir().expect("tempdir");
    for name in ["ow.txt", "sw.txt", "w.txt"] {
        std::fs::write(td.path().join(name), b"x").expect("write file");
    }
    let backend = LocalFsBackend::new(td.path()).expect("open root");
    let server = Server::public(backend).await;
    let mut c = server.client().await;

    let root = c.open_dir("").await;
    assert_eq!(
        c.list(root, QueryDirectoryRequest::FLAG_RESTART_SCANS, ">w.txt")
            .await
            .unwrap(),
        ["ow.txt", "sw.txt"]
    );
    c.close(root).await;
}

fn context_chain(contexts: &[(&[u8], &[u8])]) -> Vec<u8> {
    let list: Vec<CreateContext> = contexts
        .iter()
        .map(|&(name, data)| CreateContext {
            name: name.to_vec(),
            data: data.to_vec(),
        })
        .collect();
    let mut chain = Vec::new();
    CreateContext::encode_chain(&list, &mut chain).expect("encode");
    chain
}

/// Response create contexts, after checking that they start right after the
/// fixed response fields and that every context and data field is 8-aligned.
fn response_contexts(rb: &[u8]) -> Vec<CreateContext> {
    let resp = CreateResponse::parse(rb).expect("parse create resp");
    if resp.create_contexts_length == 0 {
        assert_eq!(resp.create_contexts_offset, 0);
        return Vec::new();
    }
    assert_eq!(resp.create_contexts_offset, 64 + 88);
    let chain = &rb[88..];
    assert_eq!(chain.len(), resp.create_contexts_length as usize);
    let mut at = 0;
    loop {
        let entry = &chain[at..];
        let next = u32::from_le_bytes(entry[0..4].try_into().unwrap()) as usize;
        let data_offset = u16::from_le_bytes(entry[10..12].try_into().unwrap());
        assert_eq!(next % 8, 0);
        assert_eq!(data_offset % 8, 0);
        if next == 0 {
            break;
        }
        at += next;
    }
    CreateContext::parse_chain(chain).expect("parse contexts")
}

fn context_data<'a>(contexts: &'a [CreateContext], name: &[u8; 4]) -> &'a [u8] {
    &contexts
        .iter()
        .find(|c| c.name == name)
        .unwrap_or_else(|| panic!("no {} context", String::from_utf8_lossy(name)))
        .data
}

#[tokio::test]
async fn create_answers_maximal_access_and_on_disk_id() {
    let td = tempdir().expect("tempdir");
    let backend = LocalFsBackend::new(td.path()).expect("open root");
    let volume = backend.volume_info().await.expect("volume info");
    let server = Server::public(backend).await;
    let mut c = server.client().await;

    let queries = context_chain(&[
        (CreateContext::NAME_MXAC, &[]),
        (CreateContext::NAME_QFID, &[]),
    ]);
    let (status, rb) = c
        .create_raw(Create {
            name: "new.txt",
            access: FILE_GENERIC_READ,
            disposition: FILE_CREATE,
            contexts: queries,
            ..Create::default()
        })
        .await;
    assert_eq!(status, STATUS_SUCCESS);
    let resp = CreateResponse::parse(&rb).unwrap();
    let contexts = response_contexts(&rb);
    assert_eq!(contexts.len(), 2);

    let mxac = context_data(&contexts, CreateContext::NAME_MXAC);
    assert_eq!(mxac[0..4], STATUS_SUCCESS.to_le_bytes());
    assert_eq!(mxac[4..8], FILE_ALL_ACCESS.to_le_bytes());

    let qfid = context_data(&contexts, CreateContext::NAME_QFID);
    assert_eq!(qfid.len(), 32);
    let id = c
        .query_file_info(resp.file_id, FILE_INTERNAL_INFORMATION)
        .await
        .unwrap();
    assert_eq!(qfid[0..8], id[0..8]);
    assert_ne!(qfid[0..8], [0; 8]);
    assert_eq!(qfid[8..16], u64::from(volume.serial_number).to_le_bytes());
    assert_eq!(qfid[16..32], [0; 16]);
    c.close(resp.file_id).await;

    // A timestamp equal to the change time gets no answer.
    let unchanged = context_chain(&[(CreateContext::NAME_MXAC, &resp.change_time.to_le_bytes())]);
    let changed = context_chain(&[(
        CreateContext::NAME_MXAC,
        &(resp.change_time - 1).to_le_bytes(),
    )]);
    for (chain, status, access) in [
        (unchanged, ntstatus::STATUS_NONE_MAPPED, 0),
        (changed, STATUS_SUCCESS, FILE_ALL_ACCESS),
    ] {
        let (open_status, rb) = c
            .create_raw(Create {
                name: "new.txt",
                access: FILE_READ_ATTRIBUTES,
                disposition: FILE_OPEN,
                contexts: chain,
                ..Create::default()
            })
            .await;
        assert_eq!(open_status, STATUS_SUCCESS);
        let contexts = response_contexts(&rb);
        let mxac = context_data(&contexts, CreateContext::NAME_MXAC);
        assert_eq!(mxac[0..4], status.to_le_bytes());
        assert_eq!(mxac[4..8], access.to_le_bytes());
        c.close(CreateResponse::parse(&rb).unwrap().file_id).await;
    }
}

#[tokio::test]
async fn maximal_access_on_a_read_only_share_is_read_access() {
    let td = tempdir().expect("tempdir");
    std::fs::write(td.path().join("f.txt"), b"x").expect("write file");
    let backend = LocalFsBackend::new(td.path()).expect("open root");
    let server =
        Server::start(SmbServer::builder().share(Share::new("share", backend).public_read_only()))
            .await;
    let mut c = server.client().await;

    let queries = context_chain(&[(CreateContext::NAME_MXAC, &[])]);
    let (status, rb) = c
        .create_raw(Create {
            name: "f.txt",
            access: FILE_READ_ATTRIBUTES,
            disposition: FILE_OPEN,
            contexts: queries,
            ..Create::default()
        })
        .await;
    assert_eq!(status, STATUS_SUCCESS);
    let contexts = response_contexts(&rb);
    let mxac = context_data(&contexts, CreateContext::NAME_MXAC);
    assert_eq!(mxac[0..4], STATUS_SUCCESS.to_le_bytes());
    assert_eq!(
        mxac[4..8],
        (FILE_GENERIC_READ | FILE_GENERIC_EXECUTE).to_le_bytes()
    );
    c.close(CreateResponse::parse(&rb).unwrap().file_id).await;
}

#[tokio::test]
async fn create_ignores_other_contexts_and_rejects_malformed_ones() {
    let td = tempdir().expect("tempdir");
    let backend = LocalFsBackend::new(td.path()).expect("open root");
    let server = Server::public(backend).await;
    let mut c = server.client().await;

    let others = context_chain(&[
        (CreateContext::NAME_RQLS, &[0; 32]),
        (CreateContext::NAME_DHNQ, &[0; 16]),
        (b"XXXX", &[1, 2, 3]),
    ]);
    let (status, rb) = c
        .create_raw(Create {
            name: "a.txt",
            access: FILE_GENERIC_READ,
            disposition: FILE_CREATE,
            contexts: others,
            ..Create::default()
        })
        .await;
    assert_eq!(status, STATUS_SUCCESS);
    assert!(response_contexts(&rb).is_empty());
    c.close(CreateResponse::parse(&rb).unwrap().file_id).await;

    for (case, chain) in [
        ("short name", context_chain(&[(b"Mx", &[])])),
        (
            "maximal access data",
            context_chain(&[(CreateContext::NAME_MXAC, &[0; 4])]),
        ),
    ] {
        let (status, _) = c
            .create_raw(Create {
                name: "b.txt",
                access: FILE_GENERIC_READ,
                disposition: FILE_CREATE,
                contexts: chain,
                ..Create::default()
            })
            .await;
        assert_eq!(status, ntstatus::STATUS_INVALID_PARAMETER, "{case}");
        assert!(!td.path().join("b.txt").exists(), "{case}");
    }
}
