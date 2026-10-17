//! SMB2 client for the QUERY_DIRECTORY and QUERY_INFO tests: an anonymous
//! session on a public share named `share`.
#![allow(dead_code, reason = "each test crate uses part of the client")]

use smb_server::wire::header::Command;
use smb_server::wire::messages::{
    CloseRequest, CreateRequest, CreateResponse, FileId, QueryDirectoryRequest,
    QueryDirectoryResponse, QueryInfoRequest, QueryInfoResponse,
};
use smb_server::{Share, SmbServer};
use tokio::net::TcpStream;
use tokio::task::JoinHandle;

// Cargo also builds this file as a test crate of its own, so it brings in
// the shared helpers itself.
#[path = "common/mod.rs"]
mod common;

use common::{
    STATUS_SUCCESS, anonymous_session_setup, build_header, negotiate, parse_response_header,
    read_frame, start_server, tree_connect, utf16le, write_frame,
};

pub const FILE_DIRECTORY_FILE: u32 = 0x0000_0001;
pub const FILE_GENERIC_READ: u32 = 0x0012_0089;
pub const FILE_ID_BOTH_DIRECTORY_INFORMATION: u8 = 0x25;
pub const INFO_FILE: u8 = 0x01;
pub const INFO_FILESYSTEM: u8 = 0x02;
pub const INFO_SECURITY: u8 = 0x03;

pub struct Client {
    s: TcpStream,
    session_id: u64,
    tree_id: u32,
    next_mid: u64,
}

impl Client {
    pub async fn connect(share: Share) -> (Self, JoinHandle<()>) {
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

    /// Opens an existing file or directory with `access`.
    pub async fn open(&mut self, name: &str, access: u32, options: u32) -> Result<FileId, u32> {
        let mut name = utf16le(name);
        let name_length = name.len() as u16;
        name.resize(name.len().next_multiple_of(8), 0);
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
            create_disposition: 1, // FILE_OPEN
            create_options: options,
            name_offset: 0x78,
            name_length,
            create_contexts_offset: 0,
            create_contexts_length: 0,
            name,
            create_contexts: vec![],
        };
        let mut body = Vec::new();
        req.write_to(&mut body).expect("write");
        let (status, rb) = self.send(Command::Create, &body).await;
        if status != STATUS_SUCCESS {
            return Err(status);
        }
        Ok(CreateResponse::parse(&rb).expect("parse").file_id)
    }

    /// Opens a directory for listing.
    pub async fn open_dir(&mut self, name: &str) -> FileId {
        self.open(name, FILE_GENERIC_READ, FILE_DIRECTORY_FILE)
            .await
            .expect("open directory")
    }

    pub async fn close(&mut self, file_id: FileId) {
        let req = CloseRequest {
            structure_size: 24,
            flags: 0,
            reserved: 0,
            file_id,
        };
        let mut body = Vec::new();
        req.write_to(&mut body).expect("write");
        let (status, _) = self.send(Command::Close, &body).await;
        assert_eq!(status, STATUS_SUCCESS);
    }

    /// QUERY_DIRECTORY; returns the status and the output buffer, empty
    /// for an error.
    pub async fn query_directory(
        &mut self,
        dir: FileId,
        class: u8,
        flags: u8,
        pattern: &str,
        output_buffer_length: u32,
    ) -> (u32, Vec<u8>) {
        let pattern = utf16le(pattern);
        let req = QueryDirectoryRequest {
            structure_size: 33,
            file_information_class: class,
            flags,
            file_index: 0,
            file_id: dir,
            file_name_offset: 64 + 32,
            file_name_length: pattern.len() as u16,
            output_buffer_length,
            file_name: pattern,
        };
        let mut body = Vec::new();
        req.write_to(&mut body).expect("write");
        let (status, rb) = self.send(Command::QueryDirectory, &body).await;
        if status & 0xC000_0000 == 0xC000_0000 {
            return (status, Vec::new());
        }
        let resp = QueryDirectoryResponse::parse(&rb).expect("parse");
        (status, resp.buffer)
    }

    /// Sorted names QUERY_DIRECTORY returns for `pattern` in
    /// FileIdBothDirectoryInformation, or the status.
    pub async fn list(
        &mut self,
        dir: FileId,
        flags: u8,
        pattern: &str,
    ) -> Result<Vec<String>, u32> {
        let (status, buf) = self
            .query_directory(
                dir,
                FILE_ID_BOTH_DIRECTORY_INFORMATION,
                flags,
                pattern,
                65536,
            )
            .await;
        if status != STATUS_SUCCESS {
            return Err(status);
        }
        let mut names: Vec<String> = id_both_entries(&buf).into_iter().map(|e| e.0).collect();
        names.sort();
        Ok(names)
    }

    /// QUERY_INFO; returns the status and the response body after the
    /// header.
    pub async fn query_info_raw(
        &mut self,
        file_id: FileId,
        info_type: u8,
        class: u8,
        output_buffer_length: u32,
    ) -> (u32, Vec<u8>) {
        let req = QueryInfoRequest {
            structure_size: 41,
            info_type,
            file_information_class: class,
            output_buffer_length,
            input_buffer_offset: 0,
            reserved: 0,
            input_buffer_length: 0,
            additional_information: 0x7,
            flags: 0,
            file_id,
            input_buffer: vec![],
        };
        let mut body = Vec::new();
        req.write_to(&mut body).expect("write");
        self.send(Command::QueryInfo, &body).await
    }

    /// QUERY_INFO; returns the status and the output buffer, empty for an
    /// error.
    pub async fn query_info(
        &mut self,
        file_id: FileId,
        info_type: u8,
        class: u8,
        output_buffer_length: u32,
    ) -> (u32, Vec<u8>) {
        let (status, rb) = self
            .query_info_raw(file_id, info_type, class, output_buffer_length)
            .await;
        if status & 0xC000_0000 == 0xC000_0000 {
            return (status, Vec::new());
        }
        (status, QueryInfoResponse::parse(&rb).expect("parse").buffer)
    }
}

/// Name, FileId and FileNameLength of each FileIdBothDirectoryInformation
/// entry in `buf`. A name cut short by the buffer is decoded as far as it
/// goes.
pub fn id_both_entries(mut buf: &[u8]) -> Vec<(String, u64, usize)> {
    let mut out = Vec::new();
    while buf.len() >= 104 {
        let next = u32::from_le_bytes(buf[0..4].try_into().unwrap()) as usize;
        let name_len = u32::from_le_bytes(buf[60..64].try_into().unwrap()) as usize;
        let file_id = u64::from_le_bytes(buf[96..104].try_into().unwrap());
        let end = (104 + name_len).min(buf.len());
        let units: Vec<u16> = buf[104..end]
            .chunks_exact(2)
            .map(|b| u16::from_le_bytes([b[0], b[1]]))
            .collect();
        out.push((
            String::from_utf16(&units).expect("utf16"),
            file_id,
            name_len,
        ));
        if next == 0 {
            break;
        }
        buf = &buf[next..];
    }
    out
}

pub fn u32_at(buf: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(buf[offset..offset + 4].try_into().unwrap())
}

pub fn u64_at(buf: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(buf[offset..offset + 8].try_into().unwrap())
}
