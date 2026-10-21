//! A client for the named pipes of IPC$: the SMB2 commands that carry
//! DCE/RPC PDUs, and PDUs built and read by hand (C706 12.6).

use std::net::SocketAddr;

use smb_server::ntstatus::{STATUS_BUFFER_OVERFLOW, STATUS_SUCCESS};
use smb_server::wire::header::Command;
use smb_server::wire::messages::{
    CreateResponse, FileId, Fsctl, IoctlRequest, IoctlResponse, ReadRequest, ReadResponse,
    TreeConnectResponse,
};
use tokio::net::TcpStream;

use super::auth::{LoginOptions, ioctl_body, login_with};
use super::client::{Client, Create, write_request};
use super::{
    CLIENT_GUID, anonymous_session_setup, build_header, negotiate_dialects_from,
    parse_response_header, read_frame, tree_connect_body, write_frame,
};

/// What Windows asks for on a pipe: FILE_GENERIC_READ | FILE_GENERIC_WRITE.
pub const PIPE_ACCESS: u32 = 0x0012_019F;

pub const PTYPE_REQUEST: u8 = 0;
pub const PTYPE_RESPONSE: u8 = 2;
pub const PTYPE_FAULT: u8 = 3;
pub const PTYPE_BIND: u8 = 11;
pub const PTYPE_BIND_ACK: u8 = 12;
pub const PTYPE_BIND_NAK: u8 = 13;

pub const FIRST: u8 = 0x01;
pub const LAST: u8 = 0x02;

pub const NCA_OP_RNG_ERROR: u32 = 0x1C01_0002;
pub const NCA_UNK_IF: u32 = 0x1C01_0003;

/// srvsvc 3.0 (MS-SRVS 2.1), as on the wire.
pub const SRVSVC: [u8; 20] = [
    0xc8, 0x4f, 0x32, 0x4b, 0x70, 0x16, 0xd3, 0x01, 0x12, 0x78, 0x5a, 0x47, 0xbf, 0x6e, 0xe1, 0x88,
    3, 0, 0, 0,
];
/// NDR 2.0 (MS-RPCE 2.2.4.12).
pub const NDR: [u8; 20] = [
    0x04, 0x5d, 0x88, 0x8a, 0xeb, 0x1c, 0xc9, 0x11, 0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10, 0x48, 0x60,
    2, 0, 0, 0,
];
/// NDR64 1.0 (MS-RPCE 2.2.5.1).
pub const NDR64: [u8; 20] = [
    0x33, 0x05, 0x71, 0x71, 0xba, 0xbe, 0x37, 0x49, 0x83, 0x19, 0xb5, 0xdb, 0xef, 0x9c, 0xcc, 0x36,
    1, 0, 0, 0,
];

/// The bind time feature negotiation syntax with `bits` (MS-RPCE
/// 3.3.1.5.3).
pub fn features(bits: u64) -> [u8; 20] {
    let mut out = [0; 20];
    out[..8].copy_from_slice(&[0x2c, 0x1c, 0xb7, 0x6c, 0x12, 0x98, 0x40, 0x45]);
    out[8..16].copy_from_slice(&bits.to_le_bytes());
    out[16] = 1;
    out
}

fn header(ptype: u8, flags: u8, call_id: u32) -> Vec<u8> {
    let mut out = vec![5, 0, ptype, flags, 0x10, 0, 0, 0, 0, 0, 0, 0];
    out.extend_from_slice(&call_id.to_le_bytes());
    out
}

fn finish(mut pdu: Vec<u8>) -> Vec<u8> {
    let len = pdu.len() as u16;
    pdu[8..10].copy_from_slice(&len.to_le_bytes());
    pdu
}

/// A bind offering `max_frag` both ways, with one transfer syntax per
/// context: (context id, abstract syntax, transfer syntax).
pub fn bind_pdu(call_id: u32, max_frag: u16, contexts: &[(u16, [u8; 20], [u8; 20])]) -> Vec<u8> {
    let mut out = header(PTYPE_BIND, FIRST | LAST, call_id);
    out.extend_from_slice(&max_frag.to_le_bytes());
    out.extend_from_slice(&max_frag.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&[contexts.len() as u8, 0, 0, 0]);
    for (id, abstract_syntax, transfer) in contexts {
        out.extend_from_slice(&id.to_le_bytes());
        out.extend_from_slice(&[1, 0]);
        out.extend_from_slice(abstract_syntax);
        out.extend_from_slice(transfer);
    }
    finish(out)
}

/// The bind Windows clients send: srvsvc over NDR, over NDR64, and the
/// feature negotiation element.
pub fn srvsvc_bind(call_id: u32) -> Vec<u8> {
    bind_pdu(
        call_id,
        4280,
        &[
            (0, SRVSVC, NDR),
            (1, SRVSVC, NDR64),
            (2, SRVSVC, features(3)),
        ],
    )
}

/// `pdu` with an auth verifier carrying `token`, after its sec_trailer
/// (MS-RPCE 2.2.2.11).
pub fn with_auth(pdu: Vec<u8>, auth_type: u8, token: &[u8]) -> Vec<u8> {
    let mut out = pdu;
    out.extend_from_slice(&[auth_type, 2, 0, 0, 0, 0, 0, 0]);
    out.extend_from_slice(token);
    out[10..12].copy_from_slice(&(token.len() as u16).to_le_bytes());
    finish(out)
}

/// A request fragment.
pub fn request_pdu(call_id: u32, flags: u8, context: u16, opnum: u16, stub: &[u8]) -> Vec<u8> {
    let mut out = header(PTYPE_REQUEST, flags, call_id);
    out.extend_from_slice(&(stub.len() as u32).to_le_bytes());
    out.extend_from_slice(&context.to_le_bytes());
    out.extend_from_slice(&opnum.to_le_bytes());
    out.extend_from_slice(stub);
    finish(out)
}

pub fn ptype(pdu: &[u8]) -> u8 {
    pdu[2]
}

pub fn pfc_flags(pdu: &[u8]) -> u8 {
    pdu[3]
}

pub fn call_id(pdu: &[u8]) -> u32 {
    u32::from_le_bytes(pdu[12..16].try_into().unwrap())
}

/// Checks the common header of a PDU the server sent and that it is whole.
pub fn assert_pdu(pdu: &[u8], expected_ptype: u8) {
    assert_eq!(&pdu[..2], [5, 0], "version 5.0");
    assert_eq!(&pdu[4..8], [0x10, 0, 0, 0], "little-endian");
    assert_eq!(usize::from(u16::from_le_bytes([pdu[8], pdu[9]])), pdu.len());
    assert_eq!(&pdu[10..12], [0, 0], "no auth");
    assert_eq!(ptype(pdu), expected_ptype, "{pdu:02x?}");
}

/// The status of a fault.
pub fn fault_status(pdu: &[u8]) -> u32 {
    assert_pdu(pdu, PTYPE_FAULT);
    u32::from_le_bytes(pdu[24..28].try_into().unwrap())
}

/// The reason of a bind_nak.
pub fn nak_reason(pdu: &[u8]) -> u16 {
    assert_pdu(pdu, PTYPE_BIND_NAK);
    u16::from_le_bytes([pdu[16], pdu[17]])
}

/// The (result, reason) of each element of a bind_ack.
pub fn ack_results(pdu: &[u8]) -> Vec<(u16, u16)> {
    assert_pdu(pdu, PTYPE_BIND_ACK);
    let addr = usize::from(u16::from_le_bytes([pdu[24], pdu[25]]));
    let at = (26 + addr).next_multiple_of(4);
    (0..usize::from(pdu[at]))
        .map(|i| {
            let r = &pdu[at + 4 + 24 * i..];
            (
                u16::from_le_bytes([r[0], r[1]]),
                u16::from_le_bytes([r[2], r[3]]),
            )
        })
        .collect()
}

/// An anonymous client, or one signed in as `user`, negotiated at
/// `dialect`, on IPC$.
pub async fn ipc_client(addr: SocketAddr, dialect: u16, user: Option<&str>) -> Client {
    let mut s = TcpStream::connect(addr).await.expect("connect");
    negotiate_dialects_from(&mut s, &[dialect], CLIENT_GUID).await;
    let session_id = match user {
        None => anonymous_session_setup(&mut s).await,
        Some(user) => {
            let login = login_with(&mut s, 1, 0, user, "password", LoginOptions::default()).await;
            assert_eq!(login.status, STATUS_SUCCESS, "login as {user}");
            login.session_id
        }
    };
    let hdr = build_header(Command::TreeConnect, 3, session_id, 0);
    write_frame(&mut s, &hdr, &tree_connect_body("\\\\127.0.0.1\\IPC$")).await;
    let frame = read_frame(&mut s).await;
    let (rh, rb) = parse_response_header(&frame);
    assert_eq!(rh.channel_sequence_status, STATUS_SUCCESS);
    let tc = TreeConnectResponse::parse(rb).expect("tree connect response");
    assert_eq!(tc.share_type, TreeConnectResponse::SHARE_TYPE_PIPE);
    Client::from_parts(s, session_id, rh.tree_id().expect("tree id"))
}

/// A CREATE of the pipe `name` as Windows sends it.
pub fn pipe_create(name: &str) -> Create<'_> {
    Create {
        name,
        oplock: 9,
        access: PIPE_ACCESS,
        share: 0x3,
        disposition: 1,
        options: 0x0040_0040,
        ..Create::default()
    }
}

impl Client {
    /// Opens the pipe `name`.
    pub async fn open_pipe(&mut self, name: &str) -> Result<CreateResponse, u32> {
        self.create(pipe_create(name)).await
    }

    /// Opens srvsvc and binds it; returns the pipe and the bind_ack.
    pub async fn bound_pipe(&mut self) -> (FileId, Vec<u8>) {
        let file_id = self.open_pipe("srvsvc").await.expect("open srvsvc").file_id;
        assert_eq!(
            self.pipe_write(file_id, &srvsvc_bind(1)).await,
            STATUS_SUCCESS
        );
        let (status, ack) = self.pipe_read(file_id, 4280).await;
        assert_eq!(status, STATUS_SUCCESS);
        assert_pdu(&ack, PTYPE_BIND_ACK);
        (file_id, ack)
    }

    /// WRITE of `data` to a pipe; returns the status.
    pub async fn pipe_write(&mut self, file_id: FileId, data: &[u8]) -> u32 {
        match self.write_raw(write_request(file_id, 0, data)).await {
            Ok(count) => {
                assert_eq!(count as usize, data.len());
                STATUS_SUCCESS
            }
            Err(status) => status,
        }
    }

    /// READ of up to `length` bytes from a pipe at `offset`; returns the
    /// status and the data, which a pipe sends with STATUS_SUCCESS and
    /// STATUS_BUFFER_OVERFLOW.
    pub async fn pipe_read_at(
        &mut self,
        file_id: FileId,
        offset: u64,
        length: u32,
    ) -> (u32, Vec<u8>) {
        let req = ReadRequest {
            structure_size: 49,
            padding: ReadResponse::STANDARD_DATA_OFFSET,
            flags: 0,
            length,
            offset,
            file_id,
            minimum_count: 0,
            channel: 0,
            remaining_bytes: 0,
            read_channel_info_offset: 0,
            read_channel_info_length: 0,
            buffer: vec![0],
        };
        let mut body = Vec::new();
        req.write_to(&mut body).expect("read");
        let (status, rb) = self.send(Command::Read, &body).await;
        (status, read_data(status, &rb))
    }

    pub async fn pipe_read(&mut self, file_id: FileId, length: u32) -> (u32, Vec<u8>) {
        self.pipe_read_at(file_id, 0, length).await
    }

    /// FSCTL_PIPE_TRANSCEIVE; returns the status and the output.
    pub async fn transceive(
        &mut self,
        file_id: FileId,
        input: &[u8],
        max_output: u32,
    ) -> (u32, Vec<u8>) {
        let body = transceive_body(file_id, input, max_output);
        let (status, rb) = self.send(Command::Ioctl, &body).await;
        (status, ioctl_output(status, &rb))
    }
}

/// An FSCTL_PIPE_TRANSCEIVE request body.
pub fn transceive_body(file_id: FileId, input: &[u8], max_output: u32) -> Vec<u8> {
    ioctl_body(
        Fsctl::PIPE_TRANSCEIVE,
        file_id,
        input,
        max_output,
        IoctlRequest::FLAG_IS_FSCTL,
    )
}

/// The data of a READ response body with `status`; empty for an error.
pub fn read_data(status: u32, body: &[u8]) -> Vec<u8> {
    if status != STATUS_SUCCESS && status != STATUS_BUFFER_OVERFLOW {
        return Vec::new();
    }
    ReadResponse::parse(body).expect("read response").data
}

/// The output of an IOCTL response body with `status`; empty for an
/// error.
pub fn ioctl_output(status: u32, body: &[u8]) -> Vec<u8> {
    if status != STATUS_SUCCESS && status != STATUS_BUFFER_OVERFLOW {
        return Vec::new();
    }
    let resp = IoctlResponse::parse(body).expect("ioctl response");
    assert_eq!(resp.ctl_code, Fsctl::PIPE_TRANSCEIVE);
    assert_eq!(resp.input_count, 0);
    assert_eq!(resp.output_offset, 0x70);
    resp.output
}

pub const OPNUM_SHARE_ENUM: u16 = 15;
pub const OPNUM_SHARE_GET_INFO: u16 = 16;
pub const OPNUM_SERVER_GET_INFO: u16 = 21;
/// NetrShareEnumSticky, which the server does not serve.
pub const OPNUM_SHARE_ENUM_STICKY: u16 = 36;

pub const BAD_STUB_DATA: u32 = 0x0000_06F7;
pub const ERROR_ACCESS_DENIED: u32 = 5;
pub const ERROR_INVALID_PARAMETER: u32 = 87;
pub const ERROR_INVALID_LEVEL: u32 = 124;
pub const ERROR_MORE_DATA: u32 = 234;
pub const NERR_NET_NAME_NOT_FOUND: u32 = 2310;

pub const STYPE_DISKTREE: u32 = 0;
pub const STYPE_IPC_SPECIAL: u32 = 0x8000_0003;

/// NDR as a client writes it (C706 chapter 14): aligned integers, referent
/// ids from 0x20000, conformant varying strings with their NUL.
pub struct NdrOut {
    buf: Vec<u8>,
    next: u32,
}

impl Default for NdrOut {
    fn default() -> Self {
        Self::new()
    }
}

impl NdrOut {
    pub fn new() -> Self {
        Self {
            buf: Vec::new(),
            next: 0x0002_0000,
        }
    }

    pub fn u32(&mut self, value: u32) -> &mut Self {
        self.buf.resize(self.buf.len().next_multiple_of(4), 0);
        self.buf.extend_from_slice(&value.to_le_bytes());
        self
    }

    pub fn pointer(&mut self, present: bool) -> &mut Self {
        let id = if present { self.next } else { 0 };
        if present {
            self.next += 4;
        }
        self.u32(id)
    }

    pub fn string(&mut self, text: &str) -> &mut Self {
        let units: Vec<u16> = text.encode_utf16().chain([0]).collect();
        self.u32(units.len() as u32).u32(0).u32(units.len() as u32);
        for unit in units {
            self.buf.extend_from_slice(&unit.to_le_bytes());
        }
        self
    }

    pub fn finish(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.buf)
    }
}

/// NetrShareEnum: ServerName `\\127.0.0.1`, an empty container of
/// `level`, PreferedMaximumLength and ResumeHandle.
pub fn enum_request(level: u32, preferred_max: u32, resume: Option<u32>) -> Vec<u8> {
    let mut w = NdrOut::new();
    w.pointer(true)
        .string("\\\\127.0.0.1")
        .u32(level)
        .u32(level);
    w.pointer(true).u32(0).pointer(false).u32(preferred_max);
    w.pointer(resume.is_some());
    if let Some(resume) = resume {
        w.u32(resume);
    }
    w.finish()
}

/// NetrShareGetInfo for the share `name` at `level`.
pub fn get_info_request(name: &str, level: u32) -> Vec<u8> {
    NdrOut::new()
        .pointer(true)
        .string("127.0.0.1")
        .string(name)
        .u32(level)
        .finish()
}

/// NetrServerGetInfo at `level`, with no ServerName.
pub fn server_info_request(level: u32) -> Vec<u8> {
    NdrOut::new().pointer(false).u32(level).finish()
}

/// Reads a response stub.
pub struct NdrIn<'a> {
    buf: &'a [u8],
    at: usize,
}

impl<'a> NdrIn<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, at: 0 }
    }

    pub fn u32(&mut self) -> u32 {
        self.at = self.at.next_multiple_of(4);
        let value = u32::from_le_bytes(self.buf[self.at..self.at + 4].try_into().unwrap());
        self.at += 4;
        value
    }

    /// A conformant varying string, without its NUL.
    pub fn string(&mut self) -> String {
        let max = self.u32();
        assert_eq!(self.u32(), 0, "offset");
        let actual = self.u32() as usize;
        assert_eq!(max as usize, actual);
        let units: Vec<u16> = self.buf[self.at..self.at + 2 * actual]
            .chunks_exact(2)
            .map(|b| u16::from_le_bytes([b[0], b[1]]))
            .collect();
        self.at += 2 * actual;
        assert_eq!(units.last(), Some(&0), "NUL");
        String::from_utf16(&units[..actual - 1]).expect("UTF-16")
    }

    pub fn end(&self) {
        assert_eq!(self.at, self.buf.len(), "bytes after the stub");
    }
}

/// One share of a SHARE_INFO_0, _1 or _501.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub name: String,
    pub kind: Option<u32>,
    pub remark: Option<String>,
    pub flags: Option<u32>,
}

impl Entry {
    /// The fixed part of an entry of `level`, its strings still to come.
    fn read_fixed(r: &mut NdrIn<'_>, level: u32) -> Self {
        assert_ne!(r.u32(), 0, "netname pointer");
        let mut entry = Entry {
            name: String::new(),
            kind: None,
            remark: None,
            flags: None,
        };
        if level != 0 {
            entry.kind = Some(r.u32());
            assert_ne!(r.u32(), 0, "remark pointer");
            entry.remark = Some(String::new());
        }
        if level == 501 {
            entry.flags = Some(r.u32());
        }
        entry
    }

    fn read_strings(&mut self, r: &mut NdrIn<'_>) {
        self.name = r.string();
        if self.remark.is_some() {
            self.remark = Some(r.string());
        }
    }
}

/// A NetrShareEnum response.
#[derive(Debug)]
pub struct EnumReply {
    pub level: u32,
    pub entries: Vec<Entry>,
    pub total: u32,
    pub resume: Option<u32>,
    pub status: u32,
}

impl EnumReply {
    pub fn names(&self) -> Vec<&str> {
        self.entries.iter().map(|e| e.name.as_str()).collect()
    }
}

pub fn decode_enum(stub: &[u8]) -> EnumReply {
    let mut r = NdrIn::new(stub);
    let level = r.u32();
    assert_eq!(r.u32(), level, "discriminant");
    let mut entries = Vec::new();
    if [0, 1, 2, 501, 502, 503].contains(&level) && r.u32() != 0 {
        let count = r.u32();
        if r.u32() != 0 {
            assert_eq!(r.u32(), count, "max_count");
            for _ in 0..count {
                entries.push(Entry::read_fixed(&mut r, level));
            }
            for entry in &mut entries {
                entry.read_strings(&mut r);
            }
        } else {
            assert_eq!(count, 0);
        }
    }
    let total = r.u32();
    let resume = (r.u32() != 0).then(|| r.u32());
    let status = r.u32();
    r.end();
    EnumReply {
        level,
        entries,
        total,
        resume,
        status,
    }
}

/// A NetrShareGetInfo response: the level, the share and the status. A
/// level 1005 answer is an entry with only flags.
pub fn decode_get_info(stub: &[u8]) -> (u32, Option<Entry>, u32) {
    let mut r = NdrIn::new(stub);
    let level = r.u32();
    let arms = [0, 1, 2, 501, 502, 503, 1004, 1005, 1006, 1501];
    let mut entry = None;
    if arms.contains(&level) && r.u32() != 0 {
        if level == 1005 {
            entry = Some(Entry {
                name: String::new(),
                kind: None,
                remark: None,
                flags: Some(r.u32()),
            });
        } else {
            let mut e = Entry::read_fixed(&mut r, level);
            e.read_strings(&mut r);
            entry = Some(e);
        }
    }
    let status = r.u32();
    r.end();
    (level, entry, status)
}

/// What a SERVER_INFO_100 or _101 holds.
#[derive(Debug, PartialEq, Eq)]
pub struct ServerInfo {
    pub platform_id: u32,
    pub name: String,
    /// Major and minor version, server type and comment, at level 101.
    pub details: Option<(u32, u32, u32, String)>,
}

/// A NetrServerGetInfo response with an arm for level 100, 101 or 102:
/// the level, the information and the status.
pub fn decode_server_info(stub: &[u8]) -> (u32, Option<ServerInfo>, u32) {
    let mut r = NdrIn::new(stub);
    let level = r.u32();
    let mut info = None;
    if r.u32() != 0 {
        let platform_id = r.u32();
        assert_ne!(r.u32(), 0);
        let mut details = None;
        if level == 101 {
            let (major, minor, kind) = (r.u32(), r.u32(), r.u32());
            assert_ne!(r.u32(), 0);
            details = Some((major, minor, kind, String::new()));
        }
        let name = r.string();
        if let Some(d) = details.as_mut() {
            d.3 = r.string();
        }
        info = Some(ServerInfo {
            platform_id,
            name,
            details,
        });
    }
    let status = r.u32();
    r.end();
    (level, info, status)
}

impl Client {
    /// Runs one call on a bound pipe: the request goes in one fragment by
    /// FSCTL_PIPE_TRANSCEIVE, and the rest of the response is read. Returns
    /// the response stub, or the status of the fault that answers it.
    pub async fn call(
        &mut self,
        file_id: FileId,
        call_id: u32,
        opnum: u16,
        stub: &[u8],
    ) -> Result<Vec<u8>, u32> {
        let request = request_pdu(call_id, FIRST | LAST, 0, opnum, stub);
        let (status, mut pdu) = self.transceive(file_id, &request, 4280).await;
        assert_eq!(status, STATUS_SUCCESS);
        let mut out = Vec::new();
        loop {
            assert_eq!(super::rpc::call_id(&pdu), call_id);
            if ptype(&pdu) == PTYPE_FAULT {
                return Err(fault_status(&pdu));
            }
            assert_pdu(&pdu, PTYPE_RESPONSE);
            out.extend_from_slice(&pdu[24..]);
            if pfc_flags(&pdu) & LAST != 0 {
                return Ok(out);
            }
            let (status, next) = self.pipe_read(file_id, 4280).await;
            assert_eq!(status, STATUS_SUCCESS);
            pdu = next;
        }
    }

    /// A pipe open and bound to srvsvc.
    pub async fn srvsvc(&mut self) -> FileId {
        self.bound_pipe().await.0
    }

    /// NetrShareEnum at `level`, every entry at once, decoded.
    pub async fn list_shares(&mut self, file_id: FileId, level: u32) -> EnumReply {
        let stub = self
            .call(
                file_id,
                7,
                OPNUM_SHARE_ENUM,
                &enum_request(level, u32::MAX, Some(0)),
            )
            .await
            .expect("NetrShareEnum");
        decode_enum(&stub)
    }
}
