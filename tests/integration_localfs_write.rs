//! File operations against `LocalFsBackend` over TCP loopback, each test on
//! its own server with an anonymous session.

mod common;

use common::{
    STATUS_SUCCESS, anonymous_session_setup, build_header, decode_file_id_both_directory_info,
    negotiate, parse_response_header, read_frame, start_server, tree_connect, utf16le, write_frame,
};
use smb_server::wire::header::Command;
use smb_server::wire::messages::{
    CloseRequest, CloseResponse, CreateContext, CreateRequest, CreateResponse, FileId, InfoType,
    QueryDirectoryRequest, QueryDirectoryResponse, QueryInfoRequest, QueryInfoResponse,
    ReadRequest, ReadResponse, SetInfoRequest, WriteRequest, WriteResponse,
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

const FILE_READ_DATA: u32 = 0x0000_0001;
const FILE_WRITE_DATA: u32 = 0x0000_0002;
const FILE_APPEND_DATA: u32 = 0x0000_0004;
const FILE_READ_ATTRIBUTES: u32 = 0x0000_0080;
const SYNCHRONIZE: u32 = 0x0010_0000;
const MAXIMUM_ALLOWED: u32 = 0x0200_0000;
const FILE_GENERIC_READ: u32 = 0x0012_0089;
const FILE_GENERIC_EXECUTE: u32 = 0x0012_00A0;
const FILE_WRITE_ATTRIBUTES: u32 = 0x0000_0100;
const DELETE: u32 = 0x0001_0000;
const FILE_DIRECTORY_FILE: u32 = 0x0000_0001;
const FILE_OPEN: u32 = 0x0000_0001;
const FILE_CREATE: u32 = 0x0000_0002;
const FILE_DELETE_ON_CLOSE: u32 = 0x0000_1000;
const FILE_BASIC_INFORMATION: u8 = 0x04;
const FILE_INTERNAL_INFORMATION: u8 = 0x06;
const FILE_ACCESS_INFORMATION: u8 = 0x08;
const FILE_ALL_INFORMATION: u8 = 0x12;
const FILE_ID_BOTH_DIRECTORY_INFORMATION: u8 = 0x25;
const FILE_RENAME_INFORMATION: u8 = 0x0A;
const FILE_DISPOSITION_INFORMATION: u8 = 0x0D;
const FILE_SHORT_NAME_INFORMATION: u8 = 0x28;

/// Connected client on one tree of a server serving `share`.
struct Client {
    s: TcpStream,
    session_id: u64,
    tree_id: u32,
    next_mid: u64,
}

impl Client {
    async fn connect(share: Share) -> (Self, tokio::task::JoinHandle<()>) {
        let (addr, handle) = start_server(SmbServer::builder().share(share)).await;
        let mut s = TcpStream::connect(addr).await.expect("connect");
        let _ = negotiate(&mut s).await;
        let session_id = anonymous_session_setup(&mut s).await;
        let tree_id = tree_connect(&mut s, "\\\\127.0.0.1\\share", session_id, 3).await;
        let client = Self {
            s,
            session_id,
            tree_id,
            next_mid: 4,
        };
        (client, handle)
    }

    async fn send(&mut self, command: Command, body: &[u8]) -> (u32, Vec<u8>) {
        let hdr = build_header(command, self.next_mid, self.session_id, self.tree_id);
        self.next_mid += 1;
        write_frame(&mut self.s, &hdr, body).await;
        let resp = read_frame(&mut self.s).await;
        let (rh, rb) = parse_response_header(&resp);
        assert_eq!(rh.command, command);
        (rh.channel_sequence_status, rb.to_vec())
    }

    /// Opens an existing file; returns its FileId, or the status on failure.
    async fn open(&mut self, name: &str, access: u32, options: u32) -> Result<FileId, u32> {
        let (status, rb) = self.create(name, access, FILE_OPEN, options, &[]).await;
        if status != STATUS_SUCCESS {
            return Err(status);
        }
        Ok(CreateResponse::parse(&rb)
            .expect("parse create resp")
            .file_id)
    }

    /// CREATE with the create context chain `contexts`, placed 8-aligned
    /// after the name. Returns the status and the response body.
    async fn create(
        &mut self,
        name: &str,
        access: u32,
        disposition: u32,
        options: u32,
        contexts: &[u8],
    ) -> (u32, Vec<u8>) {
        let mut name = utf16le(name);
        let name_length = name.len() as u16;
        name.resize(name.len().next_multiple_of(8), 0);
        let contexts_offset = if contexts.is_empty() {
            0
        } else {
            0x78 + name.len() as u32
        };
        let req = CreateRequest {
            structure_size: 57,
            security_flags: 0,
            requested_oplock_level: 0,
            impersonation_level: 2,
            smb_create_flags: 0,
            reserved: 0,
            desired_access: access,
            file_attributes: 0,
            share_access: 0x0000_0007,
            create_disposition: disposition,
            create_options: options,
            name_offset: 0x78,
            name_length,
            create_contexts_offset: contexts_offset,
            create_contexts_length: contexts.len() as u32,
            name,
            create_contexts: contexts.to_vec(),
        };
        let mut body = Vec::new();
        req.write_to(&mut body).expect("write");
        self.send(Command::Create, &body).await
    }

    async fn set_info(&mut self, file_id: FileId, class: u8, buffer: Vec<u8>) -> u32 {
        let req = SetInfoRequest {
            structure_size: 33,
            info_type: InfoType::File as u8,
            file_information_class: class,
            buffer_length: buffer.len() as u32,
            buffer_offset: 0x60,
            reserved: 0,
            additional_information: 0,
            file_id,
            buffer,
        };
        let mut body = Vec::new();
        req.write_to(&mut body).expect("write");
        self.send(Command::SetInfo, &body).await.0
    }

    /// QUERY_INFO for a file information class; returns the output buffer.
    async fn query_file_info(&mut self, file_id: FileId, class: u8) -> Vec<u8> {
        let req = QueryInfoRequest {
            structure_size: 41,
            info_type: InfoType::File as u8,
            file_information_class: class,
            output_buffer_length: 4096,
            input_buffer_offset: 0,
            reserved: 0,
            input_buffer_length: 0,
            additional_information: 0,
            flags: 0,
            file_id,
            input_buffer: vec![],
        };
        let mut body = Vec::new();
        req.write_to(&mut body).expect("write");
        let (status, rb) = self.send(Command::QueryInfo, &body).await;
        assert_eq!(status, STATUS_SUCCESS);
        QueryInfoResponse::parse(&rb).expect("parse").buffer
    }

    /// QUERY_DIRECTORY for every entry in a file information class; returns
    /// the output buffer.
    async fn query_directory(&mut self, dir_id: FileId, class: u8) -> Vec<u8> {
        let pattern = utf16le("*");
        let req = QueryDirectoryRequest {
            structure_size: 33,
            file_information_class: class,
            flags: QueryDirectoryRequest::FLAG_RESTART_SCANS,
            file_index: 0,
            file_id: dir_id,
            file_name_offset: 64 + 32,
            file_name_length: pattern.len() as u16,
            output_buffer_length: 4096,
            file_name: pattern,
        };
        let mut body = Vec::new();
        req.write_to(&mut body).expect("write");
        let (status, rb) = self.send(Command::QueryDirectory, &body).await;
        assert_eq!(status, STATUS_SUCCESS);
        QueryDirectoryResponse::parse(&rb).expect("parse").buffer
    }

    /// QUERY_INFO for a file information class; returns the status.
    async fn query_file_info_status(&mut self, file_id: FileId, class: u8) -> u32 {
        let req = QueryInfoRequest {
            structure_size: 41,
            info_type: InfoType::File as u8,
            file_information_class: class,
            output_buffer_length: 4096,
            input_buffer_offset: 0,
            reserved: 0,
            input_buffer_length: 0,
            additional_information: 0,
            flags: 0,
            file_id,
            input_buffer: vec![],
        };
        let mut body = Vec::new();
        req.write_to(&mut body).expect("write");
        self.send(Command::QueryInfo, &body).await.0
    }

    /// Names QUERY_DIRECTORY returns for `pattern`, or the status.
    async fn list(&mut self, dir_id: FileId, pattern: &str) -> Result<Vec<String>, u32> {
        let pattern = utf16le(pattern);
        let req = QueryDirectoryRequest {
            structure_size: 33,
            file_information_class: FILE_ID_BOTH_DIRECTORY_INFORMATION,
            flags: QueryDirectoryRequest::FLAG_RESTART_SCANS,
            file_index: 0,
            file_id: dir_id,
            file_name_offset: 64 + 32,
            file_name_length: pattern.len() as u16,
            output_buffer_length: 4096,
            file_name: pattern,
        };
        let mut body = Vec::new();
        req.write_to(&mut body).expect("write");
        let (status, rb) = self.send(Command::QueryDirectory, &body).await;
        if status != STATUS_SUCCESS {
            return Err(status);
        }
        let buf = QueryDirectoryResponse::parse(&rb).expect("parse").buffer;
        let mut names: Vec<String> = decode_file_id_both_directory_info(&buf)
            .into_iter()
            .map(|(name, _)| name)
            .collect();
        names.sort();
        Ok(names)
    }

    /// READ of up to 64 bytes at offset 0; returns the status.
    async fn read(&mut self, file_id: FileId) -> u32 {
        let req = ReadRequest {
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
        req.write_to(&mut body).expect("write");
        self.send(Command::Read, &body).await.0
    }

    /// WRITE of `data` at `offset`; returns the status.
    async fn write(&mut self, file_id: FileId, offset: u64, data: &[u8]) -> u32 {
        let req = WriteRequest {
            structure_size: 49,
            data_offset: WriteRequest::STANDARD_DATA_OFFSET,
            length: data.len() as u32,
            offset,
            file_id,
            channel: 0,
            remaining_bytes: 0,
            write_channel_info_offset: 0,
            write_channel_info_length: 0,
            flags: 0,
            data: data.to_vec(),
        };
        let mut body = Vec::new();
        req.write_to(&mut body).expect("write");
        self.send(Command::Write, &body).await.0
    }

    async fn close(&mut self, file_id: FileId) {
        let req = CloseRequest {
            structure_size: 24,
            flags: 0,
            reserved: 0,
            file_id,
        };
        let mut body = Vec::new();
        req.write_to(&mut body).expect("write");
        assert_eq!(self.send(Command::Close, &body).await.0, STATUS_SUCCESS);
    }
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
    let (mut c, handle) = Client::connect(Share::new("share", backend).public_read_only()).await;

    for access in [DELETE, FILE_WRITE_ATTRIBUTES] {
        assert_eq!(
            c.open("keep.txt", FILE_GENERIC_READ | access, 0)
                .await
                .unwrap_err(),
            ntstatus::STATUS_ACCESS_DENIED,
            "access {access:#x}"
        );
    }
    assert_eq!(
        c.open("keep.txt", FILE_GENERIC_READ, FILE_DELETE_ON_CLOSE)
            .await
            .unwrap_err(),
        ntstatus::STATUS_ACCESS_DENIED
    );
    assert!(td.path().join("keep.txt").exists());

    handle.abort();
}

#[tokio::test]
async fn read_write_share_checks_open_access() {
    let td = tempdir().expect("tempdir");
    for name in ["doc.txt", "disp.txt", "ren.txt", "ro.txt"] {
        std::fs::write(td.path().join(name), b"x").expect("write file");
    }
    let backend = LocalFsBackend::new(td.path()).expect("open root");
    let (mut c, handle) = Client::connect(Share::new("share", backend).public()).await;

    // Delete-on-close with DELETE access removes the file on CLOSE.
    let file_id = c
        .open("doc.txt", FILE_GENERIC_READ | DELETE, FILE_DELETE_ON_CLOSE)
        .await
        .unwrap();
    c.close(file_id).await;
    assert!(!td.path().join("doc.txt").exists());

    // Delete-on-close without DELETE access is rejected.
    assert_eq!(
        c.open("ro.txt", FILE_GENERIC_READ, FILE_DELETE_ON_CLOSE)
            .await
            .unwrap_err(),
        ntstatus::STATUS_INVALID_PARAMETER
    );

    // FileDispositionInformation on an open with DELETE access.
    let file_id = c.open("disp.txt", DELETE, 0).await.unwrap();
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
            0,
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
    let file_id = c.open("ro.txt", FILE_GENERIC_READ, 0).await.unwrap();
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

    handle.abort();
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
    let (mut c, handle) = Client::connect(Share::new("share", backend).public()).await;

    let tmp = c.open("tmp.txt", DELETE, 0).await.unwrap();
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
    let busy = c.open("busy.txt", FILE_GENERIC_READ, 0).await.unwrap();
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

    handle.abort();
}

#[tokio::test]
async fn file_id_is_stable_across_opens_and_matches_listing() {
    let td = tempdir().expect("tempdir");
    std::fs::write(td.path().join("f.txt"), b"x").expect("write file");
    let backend = LocalFsBackend::new(td.path()).expect("open root");
    let (mut c, handle) = Client::connect(Share::new("share", backend).public()).await;

    let first = c.open("f.txt", FILE_GENERIC_READ, 0).await.unwrap();
    let second = c.open("f.txt", FILE_GENERIC_READ, 0).await.unwrap();
    let id = c.query_file_info(first, FILE_INTERNAL_INFORMATION).await;
    let id = u64::from_le_bytes(id[..8].try_into().unwrap());
    assert_ne!(id, 0);
    let second_id = c.query_file_info(second, FILE_INTERNAL_INFORMATION).await;
    assert_eq!(second_id, id.to_le_bytes());
    // FileAllInformation: Basic (40) and Standard (24) come before Internal.
    let all = c.query_file_info(second, FILE_ALL_INFORMATION).await;
    assert_eq!(all[64..72], id.to_le_bytes());

    let root = c
        .open("", FILE_GENERIC_READ, FILE_DIRECTORY_FILE)
        .await
        .unwrap();
    let buf = c
        .query_directory(root, FILE_ID_BOTH_DIRECTORY_INFORMATION)
        .await;
    let listed = decode_file_id_both_directory_info(&buf);
    assert!(
        listed.contains(&("f.txt".to_string(), id)),
        "id {id:#x}, listed {listed:?}"
    );

    handle.abort();
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
    let (mut c, handle) = Client::connect(Share::new("share", backend).public()).await;

    let attrs = c
        .open("f.txt", FILE_READ_DATA | FILE_WRITE_ATTRIBUTES, 0)
        .await
        .unwrap();
    assert_eq!(
        c.write(attrs, 0, b"XXXX").await,
        ntstatus::STATUS_ACCESS_DENIED
    );
    assert_eq!(c.read(attrs).await, STATUS_SUCCESS);
    c.close(attrs).await;

    let write_only = c.open("f.txt", FILE_WRITE_DATA, 0).await.unwrap();
    assert_eq!(c.read(write_only).await, ntstatus::STATUS_ACCESS_DENIED);
    assert_eq!(c.write(write_only, 0, b"D").await, STATUS_SUCCESS);
    c.close(write_only).await;

    let append = c.open("f.txt", FILE_APPEND_DATA, 0).await.unwrap();
    assert_eq!(c.write(append, 4, b"!").await, STATUS_SUCCESS);
    c.close(append).await;

    assert_eq!(std::fs::read(&path).unwrap(), b"Data!");
    handle.abort();
}

#[tokio::test]
async fn query_info_reports_the_open_access() {
    let td = tempdir().expect("tempdir");
    std::fs::write(td.path().join("f.txt"), b"x").expect("write file");
    let backend = LocalFsBackend::new(td.path()).expect("open root");
    let (mut c, handle) = Client::connect(Share::new("share", backend).public()).await;

    let access = FILE_READ_ATTRIBUTES | DELETE | SYNCHRONIZE;
    let file_id = c.open("f.txt", access, 0).await.unwrap();
    let info = c.query_file_info(file_id, FILE_ACCESS_INFORMATION).await;
    assert_eq!(info, access.to_le_bytes());
    let all = c.query_file_info(file_id, FILE_ALL_INFORMATION).await;
    assert_eq!(all_info_access(&all), access);
    c.close(file_id).await;

    handle.abort();
}

#[tokio::test]
async fn maximum_allowed_on_read_only_share_grants_read_access() {
    let td = tempdir().expect("tempdir");
    std::fs::write(td.path().join("f.txt"), b"data").expect("write file");
    let backend = LocalFsBackend::new(td.path()).expect("open root");
    let (mut c, handle) = Client::connect(Share::new("share", backend).public_read_only()).await;

    let file_id = c.open("f.txt", MAXIMUM_ALLOWED, 0).await.unwrap();
    let info = c.query_file_info(file_id, FILE_ACCESS_INFORMATION).await;
    assert_eq!(
        info,
        (FILE_GENERIC_READ | FILE_GENERIC_EXECUTE).to_le_bytes()
    );
    assert_eq!(c.read(file_id).await, STATUS_SUCCESS);
    assert_eq!(
        c.write(file_id, 0, b"X").await,
        ntstatus::STATUS_ACCESS_DENIED
    );
    c.close(file_id).await;

    assert_eq!(std::fs::read(td.path().join("f.txt")).unwrap(), b"data");
    handle.abort();
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
    let (mut c, handle) = Client::connect(Share::new("share", backend).public()).await;

    let delete_access = DELETE | FILE_READ_ATTRIBUTES | SYNCHRONIZE;
    let file_id = c
        .open("doc.txt", delete_access, FILE_DELETE_ON_CLOSE)
        .await
        .unwrap();
    c.close(file_id).await;
    assert!(!td.path().join("doc.txt").exists());

    let file_id = c.open("disp.txt", delete_access, 0).await.unwrap();
    assert_eq!(
        c.set_info(file_id, FILE_DISPOSITION_INFORMATION, vec![1])
            .await,
        STATUS_SUCCESS
    );
    c.close(file_id).await;
    assert!(!td.path().join("disp.txt").exists());

    handle.abort();
}

#[tokio::test]
async fn rename_moves_other_opens_of_the_file() {
    let td = tempdir().expect("tempdir");
    let root = td.path();
    for (name, data) in [("x.txt", "x"), ("z.txt", "z")] {
        std::fs::write(root.join(name), data).expect("write file");
    }
    let backend = LocalFsBackend::new(root).expect("open root");
    let (mut c, handle) = Client::connect(Share::new("share", backend).public()).await;

    let a = c.open("x.txt", DELETE, 0).await.unwrap();
    let b = c
        .open("x.txt", FILE_GENERIC_READ | DELETE, 0)
        .await
        .unwrap();
    assert_eq!(
        c.set_info(a, FILE_RENAME_INFORMATION, rename_info("y.txt", false))
            .await,
        STATUS_SUCCESS
    );
    c.close(a).await;

    // `b` has y.txt open after the rename, so y.txt is not replaced.
    let z = c.open("z.txt", DELETE, 0).await.unwrap();
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

    handle.abort();
}

#[tokio::test]
async fn rename_of_a_directory_moves_opens_below_it() {
    let td = tempdir().expect("tempdir");
    let root = td.path();
    std::fs::create_dir_all(root.join("d").join("sub")).expect("mkdir");
    std::fs::write(root.join("d").join("sub").join("f.txt"), b"f").expect("write file");
    let backend = LocalFsBackend::new(root).expect("open root");
    let (mut c, handle) = Client::connect(Share::new("share", backend).public()).await;

    let child = c
        .open(
            "d\\sub\\f.txt",
            FILE_GENERIC_READ | DELETE,
            FILE_DELETE_ON_CLOSE,
        )
        .await
        .unwrap();
    let dir = c.open("d", DELETE, FILE_DIRECTORY_FILE).await.unwrap();
    let status = c
        .set_info(dir, FILE_RENAME_INFORMATION, rename_info("e", false))
        .await;
    c.close(dir).await;

    // NTFS refuses to rename a directory while a file below it is open, as
    // MS-FSA 2.1.5.15.12 specifies; other hosts rename it and the open moves
    // along.
    if cfg!(windows) {
        assert_eq!(status, ntstatus::STATUS_ACCESS_DENIED);
        c.close(child).await;
        assert!(!root.join("d").join("sub").join("f.txt").exists());
        assert!(!root.join("e").exists());
        handle.abort();
        return;
    }
    assert_eq!(status, STATUS_SUCCESS);

    std::fs::create_dir_all(root.join("d").join("sub")).expect("mkdir");
    std::fs::write(root.join("d").join("sub").join("f.txt"), b"new").expect("write file");
    c.close(child).await;
    assert!(!root.join("e").join("sub").join("f.txt").exists());
    assert!(root.join("e").join("sub").is_dir());
    assert_eq!(
        std::fs::read(root.join("d").join("sub").join("f.txt")).unwrap(),
        b"new"
    );

    handle.abort();
}

#[tokio::test]
async fn directory_renames_while_it_is_open() {
    let td = tempdir().expect("tempdir");
    let root = td.path();
    std::fs::create_dir_all(root.join("d").join("sub")).expect("mkdir");
    let backend = LocalFsBackend::new(root).expect("open root");
    let (mut c, handle) = Client::connect(Share::new("share", backend).public()).await;

    let listing = c
        .open("d", FILE_GENERIC_READ, FILE_DIRECTORY_FILE)
        .await
        .unwrap();
    let dir = c.open("d", DELETE, FILE_DIRECTORY_FILE).await.unwrap();
    assert_eq!(
        c.set_info(dir, FILE_RENAME_INFORMATION, rename_info("e", false))
            .await,
        STATUS_SUCCESS
    );
    c.close(dir).await;
    assert_eq!(c.list(listing, "*").await.unwrap(), [".", "..", "sub"]);
    c.close(listing).await;
    assert!(root.join("e").join("sub").is_dir());
    assert!(!root.join("d").exists());

    handle.abort();
}

const FILE_GENERIC_WRITE: u32 = 0x0012_0116;
const FILE_ALLOCATION_INFORMATION: u8 = 0x13;
const FILE_ALTERNATE_NAME_INFORMATION: u8 = 0x15;
const FILE_ATTRIBUTE_READONLY: u32 = 0x0000_0001;
const FILE_ATTRIBUTE_HIDDEN: u32 = 0x0000_0002;
const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x0000_0010;
const FILE_ATTRIBUTE_ARCHIVE: u32 = 0x0000_0020;
const FILE_ATTRIBUTE_NORMAL: u32 = 0x0000_0080;

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
    let (mut c, handle) = Client::connect(Share::new("share", backend).public()).await;

    let file_id = c.open("f.txt", FILE_GENERIC_WRITE, 0).await.unwrap();
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

    handle.abort();
}

#[tokio::test]
async fn directory_attribute_is_accepted_on_a_directory() {
    let td = tempdir().expect("tempdir");
    std::fs::create_dir(td.path().join("d")).expect("mkdir");
    let backend = LocalFsBackend::new(td.path()).expect("open root");
    let (mut c, handle) = Client::connect(Share::new("share", backend).public()).await;

    let dir = c
        .open(
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

    handle.abort();
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
    let (mut c, handle) = Client::connect(Share::new("share", backend).public()).await;
    let file_id = c
        .open("f.txt", FILE_GENERIC_READ | FILE_GENERIC_WRITE, 0)
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
    assert_eq!(c.write(file_id, 4, b"more").await, STATUS_SUCCESS);
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
    assert_eq!(c.write(file_id, 8, b"!").await, STATUS_SUCCESS);
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

    handle.abort();
}

#[tokio::test]
async fn deleting_a_non_empty_directory_fails() {
    let td = tempdir().expect("tempdir");
    let root = td.path();
    std::fs::create_dir(root.join("full")).expect("mkdir");
    std::fs::write(root.join("full").join("f.txt"), b"f").expect("write file");
    std::fs::create_dir(root.join("empty")).expect("mkdir");
    let backend = LocalFsBackend::new(root).expect("open root");
    let (mut c, handle) = Client::connect(Share::new("share", backend).public()).await;

    let dir = c.open("full", DELETE, FILE_DIRECTORY_FILE).await.unwrap();
    assert_eq!(
        c.set_info(dir, FILE_DISPOSITION_INFORMATION, vec![1]).await,
        ntstatus::STATUS_DIRECTORY_NOT_EMPTY
    );
    c.close(dir).await;
    assert!(root.join("full").join("f.txt").exists());

    // MS-FSA 2.1.5.1 accepts delete-on-close on a non-empty directory and
    // 2.1.5.5 keeps the directory at close.
    let dir = c
        .open("full", DELETE, FILE_DIRECTORY_FILE | FILE_DELETE_ON_CLOSE)
        .await
        .unwrap();
    c.close(dir).await;
    assert!(root.join("full").join("f.txt").exists());

    let dir = c.open("empty", DELETE, FILE_DIRECTORY_FILE).await.unwrap();
    assert_eq!(
        c.set_info(dir, FILE_DISPOSITION_INFORMATION, vec![1]).await,
        STATUS_SUCCESS
    );
    c.close(dir).await;
    assert!(!root.join("empty").exists());

    handle.abort();
}

#[tokio::test]
async fn read_only_attribute_is_applied_and_others_are_rejected() {
    let td = tempdir().expect("tempdir");
    let path = td.path().join("f.txt");
    std::fs::write(&path, b"x").expect("write file");
    let backend = LocalFsBackend::new(td.path()).expect("open root");
    let (mut c, handle) = Client::connect(Share::new("share", backend).public()).await;
    let attrs_access = FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES;

    let file_id = c.open("f.txt", attrs_access, 0).await.unwrap();
    assert_eq!(
        c.set_info(
            file_id,
            FILE_BASIC_INFORMATION,
            basic_info([0; 4], FILE_ATTRIBUTE_READONLY)
        )
        .await,
        STATUS_SUCCESS
    );
    let basic = c.query_file_info(file_id, FILE_BASIC_INFORMATION).await;
    assert_eq!(attributes_of(&basic), FILE_ATTRIBUTE_READONLY);
    assert!(std::fs::metadata(&path).unwrap().permissions().readonly());
    c.close(file_id).await;

    // A read-only file cannot be deleted.
    let file_id = c.open("f.txt", DELETE, 0).await.unwrap();
    assert_eq!(
        c.set_info(file_id, FILE_DISPOSITION_INFORMATION, vec![1])
            .await,
        ntstatus::STATUS_CANNOT_DELETE
    );
    c.close(file_id).await;
    assert_eq!(
        c.open("f.txt", DELETE, FILE_DELETE_ON_CLOSE)
            .await
            .unwrap_err(),
        ntstatus::STATUS_CANNOT_DELETE
    );
    assert!(path.exists());

    let file_id = c.open("f.txt", attrs_access, 0).await.unwrap();
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
    let basic = c.query_file_info(file_id, FILE_BASIC_INFORMATION).await;
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

    handle.abort();
}

/// A creation time in the same FileBasicInformation does not stop the write
/// time from applying.
#[tokio::test]
async fn write_time_applies_with_a_creation_time() {
    let td = tempdir().expect("tempdir");
    std::fs::write(td.path().join("f.txt"), b"x").expect("write file");
    std::fs::create_dir(td.path().join("d")).expect("mkdir");
    let backend = LocalFsBackend::new(td.path()).expect("open root");
    let (mut c, handle) = Client::connect(Share::new("share", backend).public()).await;

    let t = std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_577_934_245);
    for (name, options) in [("f.txt", 0), ("d", FILE_DIRECTORY_FILE)] {
        let file_id = c
            .open(name, FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES, options)
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

    handle.abort();
}

#[tokio::test]
async fn alternate_name_query_reports_no_short_name() {
    let td = tempdir().expect("tempdir");
    std::fs::write(td.path().join("a long name.txt"), b"x").expect("write file");
    let backend = LocalFsBackend::new(td.path()).expect("open root");
    let (mut c, handle) = Client::connect(Share::new("share", backend).public()).await;

    let file_id = c
        .open("a long name.txt", FILE_READ_ATTRIBUTES, 0)
        .await
        .unwrap();
    assert_eq!(
        c.query_file_info_status(file_id, FILE_ALTERNATE_NAME_INFORMATION)
            .await,
        ntstatus::STATUS_OBJECT_NAME_NOT_FOUND
    );
    c.close(file_id).await;

    handle.abort();
}

#[tokio::test]
async fn query_directory_applies_dos_wildcards() {
    let td = tempdir().expect("tempdir");
    for name in ["ow.txt", "sw.txt", "w.txt"] {
        std::fs::write(td.path().join(name), b"x").expect("write file");
    }
    let backend = LocalFsBackend::new(td.path()).expect("open root");
    let (mut c, handle) = Client::connect(Share::new("share", backend).public()).await;

    let root = c
        .open("", FILE_GENERIC_READ, FILE_DIRECTORY_FILE)
        .await
        .unwrap();
    assert_eq!(c.list(root, ">w.txt").await.unwrap(), ["ow.txt", "sw.txt"]);
    c.close(root).await;

    handle.abort();
}

const FILE_ALL_ACCESS: u32 = 0x001F_01FF;

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
    let (mut c, handle) = Client::connect(Share::new("share", backend).public()).await;

    let queries = context_chain(&[
        (CreateContext::NAME_MXAC, &[]),
        (CreateContext::NAME_QFID, &[]),
    ]);
    let (status, rb) = c
        .create("new.txt", FILE_GENERIC_READ, FILE_CREATE, 0, &queries)
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
        .await;
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
            .create("new.txt", FILE_READ_ATTRIBUTES, FILE_OPEN, 0, &chain)
            .await;
        assert_eq!(open_status, STATUS_SUCCESS);
        let contexts = response_contexts(&rb);
        let mxac = context_data(&contexts, CreateContext::NAME_MXAC);
        assert_eq!(mxac[0..4], status.to_le_bytes());
        assert_eq!(mxac[4..8], access.to_le_bytes());
        c.close(CreateResponse::parse(&rb).unwrap().file_id).await;
    }

    handle.abort();
}

#[tokio::test]
async fn maximal_access_on_a_read_only_share_is_read_access() {
    let td = tempdir().expect("tempdir");
    std::fs::write(td.path().join("f.txt"), b"x").expect("write file");
    let backend = LocalFsBackend::new(td.path()).expect("open root");
    let (mut c, handle) = Client::connect(Share::new("share", backend).public_read_only()).await;

    let queries = context_chain(&[(CreateContext::NAME_MXAC, &[])]);
    let (status, rb) = c
        .create("f.txt", FILE_READ_ATTRIBUTES, FILE_OPEN, 0, &queries)
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

    handle.abort();
}

#[tokio::test]
async fn create_ignores_other_contexts_and_rejects_malformed_ones() {
    let td = tempdir().expect("tempdir");
    let backend = LocalFsBackend::new(td.path()).expect("open root");
    let (mut c, handle) = Client::connect(Share::new("share", backend).public()).await;

    let others = context_chain(&[
        (CreateContext::NAME_RQLS, &[0; 32]),
        (CreateContext::NAME_DHNQ, &[0; 16]),
        (b"XXXX", &[1, 2, 3]),
    ]);
    let (status, rb) = c
        .create("a.txt", FILE_GENERIC_READ, FILE_CREATE, 0, &others)
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
            .create("b.txt", FILE_GENERIC_READ, FILE_CREATE, 0, &chain)
            .await;
        assert_eq!(status, ntstatus::STATUS_INVALID_PARAMETER, "{case}");
        assert!(!td.path().join("b.txt").exists(), "{case}");
    }

    handle.abort();
}
