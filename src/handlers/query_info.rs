//! QUERY_INFO handler (MS-SMB2 3.3.5.20).

use std::sync::Arc;

use crate::proto::header::Smb2Header;
use crate::proto::messages::{Dialect, InfoType, QueryInfoRequest, QueryInfoResponse};

use crate::backend::{FileInfo, Handle, OpenOptions};
use crate::conn::state::{Connection, EaCursor, Open};
use crate::dispatch::HandlerResponse;
use crate::ea::{self, Ea};
use crate::handlers::shared::{lookup_open, lookup_session_tree};
use crate::info_class as ic;
use crate::ntstatus;
use crate::server::{ServerState, ShareBindings};
use crate::stream::{StreamInfo, data_stream_info, stream_error, unsupported};

const FILE_DEVICE_DISK: u32 = 0x0000_0007;
const FILE_REMOTE_DEVICE: u32 = 0x0000_0010;

// FS attribute flags (MS-FSCC §2.5.1)
const FILE_CASE_SENSITIVE_SEARCH: u32 = 0x0000_0001;
const FILE_CASE_PRESERVED_NAMES: u32 = 0x0000_0002;
const FILE_UNICODE_ON_DISK: u32 = 0x0000_0004;
const FILE_NAMED_STREAMS: u32 = 0x0004_0000;
const FILE_SUPPORTS_EXTENDED_ATTRIBUTES: u32 = 0x0080_0000;

// Access mask bits (MS-SMB2 2.2.13.1.1)
const FILE_READ_EA: u32 = 0x0000_0008;
const FILE_READ_ATTRIBUTES: u32 = 0x0000_0080;

/// How a reply longer than OutputBufferLength is cut down.
#[derive(Clone, Copy)]
enum Overflow {
    /// Fixed size: the minimum length is the whole reply.
    Never,
    /// The trailing name is cut to fit, with STATUS_BUFFER_OVERFLOW.
    Truncate,
    /// Only whole entries are returned, with STATUS_BUFFER_OVERFLOW.
    WholeEntries,
}

pub async fn handle(
    _server: &Arc<ServerState>,
    conn: &Arc<Connection>,
    hdr: &Smb2Header,
    body: &[u8],
) -> HandlerResponse {
    let req = match QueryInfoRequest::parse(body) {
        Ok(r) => r,
        Err(_) => return HandlerResponse::err(ntstatus::STATUS_INVALID_PARAMETER),
    };
    let info_type = match req.info_type_enum() {
        Some(t) => t,
        None => return HandlerResponse::err(ntstatus::STATUS_INVALID_INFO_CLASS),
    };

    let tree_arc = match lookup_session_tree(conn, hdr).await {
        Ok(t) => t,
        Err(s) => return HandlerResponse::err(s),
    };
    let open_arc = match lookup_open(&tree_arc, req.file_id).await {
        Some(o) => o,
        None => return HandlerResponse::err(ntstatus::STATUS_FILE_CLOSED),
    };
    // NEGOTIATE advertises MaxTransactSize equal to MaxReadSize.
    if req.output_buffer_length > *conn.max_read_size.read().await {
        return HandlerResponse::err(ntstatus::STATUS_INVALID_PARAMETER);
    }
    let smb311 = *conn.dialect.read().await == Some(Dialect::Smb311);
    let cap = req.output_buffer_length as usize;

    let share = Arc::clone(&tree_arc.read().await.share);
    // FileStreamInformation of a named stream opens its file by name, with
    // no rename in between. The names lock comes before the open's.
    let _names = if matches!(info_type, InfoType::File)
        && req.file_information_class == ic::FILE_STREAM_INFORMATION
        && share.named_streams
    {
        Some(share.files.names_lock().await)
    } else {
        None
    };
    let open = open_arc.read().await;
    let on_stream = open.on_stream;
    if matches!(info_type, InfoType::File)
        && req.file_information_class == ic::FILE_FULL_EA_INFORMATION
    {
        let result = query_eas(&open, &share, &req, cap).await;
        drop(open);
        return match result {
            Ok((buf, status)) => {
                let mut response = info_response(buf);
                response.status = status;
                response
            }
            Err(ntstatus::STATUS_BUFFER_TOO_SMALL) => buffer_too_small(smb311),
            Err(status) => HandlerResponse::err(status),
        };
    }
    let result = match info_type {
        InfoType::File => query_file(&open, &share, req.file_information_class, cap).await,
        InfoType::FileSystem => {
            query_filesystem(&open, &share, req.file_information_class, cap).await
        }
        // MS-FSA 2.1.5.14: the store keeps no security descriptors.
        InfoType::Security => Err(ntstatus::STATUS_INVALID_DEVICE_REQUEST),
        InfoType::Quota => Err(ntstatus::STATUS_NOT_SUPPORTED),
    };
    drop(open);
    let (mut buf, overflow) = match result {
        Ok(reply) => reply,
        Err(ntstatus::STATUS_INFO_LENGTH_MISMATCH) => return info_length_mismatch(smb311),
        Err(ntstatus::STATUS_NOT_SUPPORTED) => return HandlerResponse::err(unsupported(on_stream)),
        Err(status) => return HandlerResponse::err(status),
    };

    let mut status = ntstatus::STATUS_SUCCESS;
    if buf.len() > cap {
        match overflow {
            Overflow::Never => return info_length_mismatch(smb311),
            Overflow::Truncate => buf.truncate(cap),
            Overflow::WholeEntries => ic::fit_stream_entries(&mut buf, cap),
        }
        status = ntstatus::STATUS_BUFFER_OVERFLOW;
    }
    let mut response = info_response(buf);
    response.status = status;
    response
}

/// A QUERY_INFO response carrying `buf`.
fn info_response(buf: Vec<u8>) -> HandlerResponse {
    let resp = QueryInfoResponse {
        structure_size: 9,
        output_buffer_offset: 64 + 8,
        output_buffer_length: buf.len() as u32,
        buffer: buf,
    };
    let mut out = Vec::new();
    resp.write_to(&mut out)
        .expect("QUERY_INFO response encodes");
    HandlerResponse::ok(out)
}

/// STATUS_INFO_LENGTH_MISMATCH with the error data of MS-SMB2 3.3.5.20.1:
/// on SMB 3.1.1 one empty error context, otherwise none.
pub(super) fn info_length_mismatch(smb311: bool) -> HandlerResponse {
    let mut response = HandlerResponse::err(ntstatus::STATUS_INFO_LENGTH_MISMATCH);
    if smb311 {
        // StructureSize, ErrorContextCount, Reserved, ByteCount, then an
        // ERROR Context with ErrorDataLength 0 and ErrorId 0.
        let mut body = Vec::with_capacity(16);
        body.extend_from_slice(&9u16.to_le_bytes());
        body.push(1);
        body.push(0);
        body.extend_from_slice(&8u32.to_le_bytes());
        body.extend_from_slice(&[0; 8]);
        response.body = body;
    }
    response
}

/// A reply and how to cut it down when it is longer than OutputBufferLength.
type Reply = Result<(Vec<u8>, Overflow), u32>;

/// SMB2_0_INFO_FILE (MS-SMB2 3.3.5.20.1) for an OutputBufferLength of `cap`.
/// On an open of a named stream, the sizes are the stream's and the rest is
/// the file's.
async fn query_file(open: &Open, share: &ShareBindings, class: u8, cap: usize) -> Reply {
    let (min_len, overflow, access) = match class {
        ic::FILE_BASIC_INFORMATION => (40, Overflow::Never, FILE_READ_ATTRIBUTES),
        ic::FILE_STANDARD_INFORMATION => (24, Overflow::Never, 0),
        ic::FILE_INTERNAL_INFORMATION => (8, Overflow::Never, 0),
        ic::FILE_EA_INFORMATION => (4, Overflow::Never, 0),
        ic::FILE_ACCESS_INFORMATION => (4, Overflow::Never, 0),
        ic::FILE_POSITION_INFORMATION => (8, Overflow::Never, 0),
        ic::FILE_MODE_INFORMATION => (4, Overflow::Never, 0),
        ic::FILE_ALIGNMENT_INFORMATION => (4, Overflow::Never, 0),
        // BlockAlign(FieldOffset(NameInformation.FileName) + 2, 8).
        ic::FILE_ALL_INFORMATION => (104, Overflow::Truncate, FILE_READ_ATTRIBUTES),
        ic::FILE_NETWORK_OPEN_INFORMATION => (56, Overflow::Never, FILE_READ_ATTRIBUTES),
        ic::FILE_STREAM_INFORMATION => (24, Overflow::WholeEntries, 0),
        ic::FILE_ALTERNATE_NAME_INFORMATION => (8, Overflow::Never, 0),
        // MS-FSA 2.1.5.12.19: not available to remote clients.
        ic::FILE_NAME_INFORMATION => return Err(ntstatus::STATUS_NOT_SUPPORTED),
        c if is_file_class(c) => return Err(ntstatus::STATUS_NOT_SUPPORTED),
        _ => return Err(ntstatus::STATUS_INVALID_INFO_CLASS),
    };
    if open.granted_access & access != access {
        return Err(ntstatus::STATUS_ACCESS_DENIED);
    }
    if cap < min_len {
        return Err(ntstatus::STATUS_INFO_LENGTH_MISMATCH);
    }
    let handle = open.handle.as_ref().ok_or(ntstatus::STATUS_FILE_CLOSED)?;
    let info = handle.stat().await.map_err(|e| e.to_nt_status())?;
    if class == ic::FILE_STREAM_INFORMATION {
        return Ok((stream_information(open, share, info).await?, overflow));
    }
    let info = if open.on_stream {
        data_stream_info(info)
    } else {
        info
    };
    let ea_size = if share.extended_attributes {
        info.ea_size
    } else {
        0
    };
    let buf = match class {
        ic::FILE_BASIC_INFORMATION => ic::encode_file_basic_information(&info),
        ic::FILE_STANDARD_INFORMATION | ic::FILE_ALL_INFORMATION => {
            let links = handle.link_count().await.map_err(|e| e.to_nt_status())?;
            if class == ic::FILE_STANDARD_INFORMATION {
                ic::encode_file_standard_information(&info, links, open.delete_pending())
            } else {
                ic::encode_file_all_information(
                    &info,
                    open.granted_access,
                    links,
                    open.delete_pending(),
                    ea_size,
                )
            }
        }
        ic::FILE_INTERNAL_INFORMATION => ic::encode_file_internal_information(info.file_index),
        ic::FILE_EA_INFORMATION => ic::encode_file_ea_information(ea_size),
        ic::FILE_ACCESS_INFORMATION => ic::encode_file_access_information(open.granted_access),
        ic::FILE_POSITION_INFORMATION => ic::encode_file_position_information(),
        ic::FILE_MODE_INFORMATION => ic::encode_file_mode_information(0),
        ic::FILE_ALIGNMENT_INFORMATION => ic::encode_file_alignment_information(),
        ic::FILE_NETWORK_OPEN_INFORMATION => ic::encode_file_network_open_information(&info),
        // MS-FSA 2.1.5.12.4. Files here have no 8.3 short name.
        ic::FILE_ALTERNATE_NAME_INFORMATION => return Err(ntstatus::STATUS_OBJECT_NAME_NOT_FOUND),
        _ => unreachable!("class checked above"),
    };
    Ok((buf, overflow))
}

/// FileStreamInformation (MS-FSA 2.1.5.12.29): every stream of the file
/// `open` is on, whichever stream that is, the default stream first unless
/// the file is a directory. A share without named streams lists the
/// default stream alone. The handle lists the named streams; on an open of
/// a named stream, the default stream's size comes from a new open of the
/// file. The caller holds the share's names lock, so no rename moves the
/// file in between.
async fn stream_information(
    open: &Open,
    share: &ShareBindings,
    info: FileInfo,
) -> Result<Vec<u8>, u32> {
    let default =
        |info: &FileInfo| (!info.is_directory).then_some((info.end_of_file, info.allocation_size));
    if !share.named_streams {
        return Ok(ic::encode_file_stream_information(default(&info), &[]));
    }
    let handle = open.handle.as_deref().ok_or(ntstatus::STATUS_FILE_CLOSED)?;
    let streams = streams_of(handle).await?;
    if !open.on_stream {
        return Ok(ic::encode_file_stream_information(default(&info), &streams));
    }
    let path = open.path().ok_or(ntstatus::STATUS_FILE_CLOSED)?;
    let (file, _) = share
        .backend
        .open(&path, OpenOptions::default())
        .await
        .map_err(|e| stream_error(e).to_nt_status())?;
    let info = file.stat().await;
    let _ = file.close().await;
    let info = info.map_err(|e| stream_error(e).to_nt_status())?;
    Ok(ic::encode_file_stream_information(default(&info), &streams))
}

/// The named streams `handle` lists.
async fn streams_of(handle: &dyn Handle) -> Result<Vec<StreamInfo>, u32> {
    handle
        .streams()
        .await
        .map_err(|e| stream_error(e).to_nt_status())
}

/// SMB2_0_INFO_FILESYSTEM (MS-SMB2 3.3.5.20.2) for an OutputBufferLength
/// of `cap`.
async fn query_filesystem(open: &Open, share: &ShareBindings, class: u8, cap: usize) -> Reply {
    let (min_len, overflow) = match class {
        // BlockAlign(FieldOffset(VolumeLabel), 8).
        ic::FS_VOLUME_INFORMATION => (24, Overflow::Truncate),
        ic::FS_SIZE_INFORMATION => (24, Overflow::Never),
        ic::FS_DEVICE_INFORMATION => (8, Overflow::Never),
        // BlockAlign(FieldOffset(FileSystemName), 4).
        ic::FS_ATTRIBUTE_INFORMATION => (12, Overflow::Truncate),
        ic::FS_FULL_SIZE_INFORMATION => (32, Overflow::Never),
        ic::FS_SECTOR_SIZE_INFORMATION => (28, Overflow::Never),
        // FileFsLabelInformation through FileFsVolumeFlagsInformation.
        2 | 6 | 8 | 9 | 10 => return Err(ntstatus::STATUS_NOT_SUPPORTED),
        _ => return Err(ntstatus::STATUS_INVALID_INFO_CLASS),
    };
    if cap < min_len {
        return Err(ntstatus::STATUS_INFO_LENGTH_MISMATCH);
    }
    if class == ic::FS_DEVICE_INFORMATION {
        let buf = ic::encode_fs_device_information(FILE_DEVICE_DISK, FILE_REMOTE_DEVICE);
        return Ok((buf, overflow));
    }
    let volume = share
        .backend
        .volume_info()
        .await
        .map_err(|e| e.to_nt_status())?;
    let buf = match class {
        ic::FS_VOLUME_INFORMATION => {
            let handle = open.handle.as_ref().ok_or(ntstatus::STATUS_FILE_CLOSED)?;
            let creation_time = handle.stat().await.map_or(0, |i| i.creation_time);
            let label = volume.label.as_deref().unwrap_or(&share.name);
            ic::encode_fs_volume_information(creation_time, volume.serial_number, label)
        }
        ic::FS_SIZE_INFORMATION => ic::encode_fs_size_information(
            volume.total_allocation_units,
            volume.caller_available_allocation_units,
            volume.sectors_per_allocation_unit,
            volume.bytes_per_sector,
        ),
        ic::FS_ATTRIBUTE_INFORMATION => {
            let case_sensitive = if share.backend.capabilities().case_sensitive {
                FILE_CASE_SENSITIVE_SEARCH
            } else {
                0
            };
            let named_streams = if share.named_streams {
                FILE_NAMED_STREAMS
            } else {
                0
            };
            let eas = if share.extended_attributes {
                FILE_SUPPORTS_EXTENDED_ATTRIBUTES
            } else {
                0
            };
            ic::encode_fs_attribute_information(
                case_sensitive
                    | named_streams
                    | eas
                    | FILE_CASE_PRESERVED_NAMES
                    | FILE_UNICODE_ON_DISK,
                volume.max_name_length,
                "NTFS",
            )
        }
        ic::FS_FULL_SIZE_INFORMATION => ic::encode_fs_full_size_information(
            volume.total_allocation_units,
            volume.caller_available_allocation_units,
            volume.actual_available_allocation_units,
            volume.sectors_per_allocation_unit,
            volume.bytes_per_sector,
        ),
        ic::FS_SECTOR_SIZE_INFORMATION => {
            ic::encode_fs_sector_size_information(volume.bytes_per_sector)
        }
        _ => unreachable!("class checked above"),
    };
    Ok((buf, overflow))
}

/// FileFullEaInformation (MS-SMB2 3.3.5.20.1, MS-FSA 2.1.5.12.12) for an
/// OutputBufferLength of `cap`: the reply and its status. A share without
/// extended attributes answers STATUS_INVALID_DEVICE_REQUEST.
///
/// A list of names gets one entry per name, with an empty value for a
/// name the file does not have, or STATUS_BUFFER_OVERFLOW and nothing when
/// they do not all fit. Otherwise the entries start at EaIndex with
/// SL_INDEX_SPECIFIED, at the first with SL_RESTART_SCAN, and else where
/// the open's last such query stopped; as many whole entries as fit are
/// returned, one with SL_RETURN_SINGLE_ENTRY, with STATUS_BUFFER_OVERFLOW
/// when more follow, and the open's place moves past them. A query that
/// carries on from there after the file's attributes were set fails with
/// STATUS_EA_CORRUPT_ERROR until one restarts.
async fn query_eas(
    open: &Open,
    share: &ShareBindings,
    req: &QueryInfoRequest,
    cap: usize,
) -> Result<(Vec<u8>, u32), u32> {
    if open.granted_access & FILE_READ_EA == 0 {
        return Err(ntstatus::STATUS_ACCESS_DENIED);
    }
    if open.on_stream {
        return Err(ntstatus::STATUS_INVALID_PARAMETER);
    }
    if !share.extended_attributes {
        return Err(ntstatus::STATUS_INVALID_DEVICE_REQUEST);
    }
    let names = if req.input_buffer.is_empty() {
        None
    } else {
        Some(ea::parse_get_list(&req.input_buffer)?)
    };
    let handle = open.handle.as_ref().ok_or(ntstatus::STATUS_FILE_CLOSED)?;
    let file = open.file.as_ref().ok_or(ntstatus::STATUS_FILE_CLOSED)?;
    let changes = file.ea_changes();
    let mut eas = handle.eas().await.map_err(|e| e.to_nt_status())?;
    eas.retain(ea::listable);
    let single = req.flags & QueryInfoRequest::FLAG_RETURN_SINGLE_ENTRY != 0;

    if let Some(names) = names {
        let names = if single { &names[..1] } else { &names[..] };
        let asked = ea::select(&eas, names);
        return Ok(match fitting(&asked, cap) {
            n if n == asked.len() => (ea::encode_full_list(&asked), ntstatus::STATUS_SUCCESS),
            _ => (Vec::new(), ntstatus::STATUS_BUFFER_OVERFLOW),
        });
    }

    let mut cursor = open.ea_cursor.lock().unwrap_or_else(|e| e.into_inner());
    let start = if req.flags & QueryInfoRequest::FLAG_INDEX_SPECIFIED != 0 {
        let index = req.additional_information as usize;
        if index == 0 || index > eas.len() + 1 || eas.is_empty() {
            return Err(ntstatus::STATUS_NONEXISTENT_EA_ENTRY);
        }
        index - 1
    } else if eas.is_empty() {
        return Err(ntstatus::STATUS_NO_EAS_ON_FILE);
    } else if req.flags & QueryInfoRequest::FLAG_RESTART_SCAN != 0 {
        0
    } else if cursor.changes.is_some_and(|seen| seen != changes) {
        return Err(ntstatus::STATUS_EA_CORRUPT_ERROR);
    } else {
        cursor.next
    };
    if start >= eas.len() {
        *cursor = EaCursor {
            next: start,
            changes: Some(changes),
        };
        return Err(ntstatus::STATUS_NO_MORE_EAS);
    }
    let rest = &eas[start..];
    let count = match fitting(rest, cap) {
        0 => return Err(ntstatus::STATUS_BUFFER_TOO_SMALL),
        n if single => 1.min(n),
        n => n,
    };
    *cursor = EaCursor {
        next: start + count,
        changes: Some(changes),
    };
    let status = if count < rest.len() && !single {
        ntstatus::STATUS_BUFFER_OVERFLOW
    } else {
        ntstatus::STATUS_SUCCESS
    };
    Ok((ea::encode_full_list(&rest[..count]), status))
}

/// How many of the first entries of `eas` fit in `cap` bytes as one
/// FILE_FULL_EA_INFORMATION list, the last of them unpadded.
fn fitting(eas: &[Ea], cap: usize) -> usize {
    let mut used = 0usize;
    let mut count = 0;
    for ea in eas {
        let end = used.next_multiple_of(4) + ea::entry_len(ea);
        if end > cap {
            break;
        }
        used = end;
        count += 1;
    }
    count
}

/// STATUS_BUFFER_TOO_SMALL with the error data of MS-SMB2 3.3.5.20.3 and
/// a required length of 0: on SMB 3.1.1 in one error context.
fn buffer_too_small(smb311: bool) -> HandlerResponse {
    let mut response = HandlerResponse::err(ntstatus::STATUS_BUFFER_TOO_SMALL);
    let mut body = Vec::with_capacity(20);
    body.extend_from_slice(&9u16.to_le_bytes());
    if smb311 {
        // ErrorContextCount, Reserved, ByteCount, then an ERROR Context
        // with ErrorDataLength 4, ErrorId 0 and the length.
        body.push(1);
        body.push(0);
        body.extend_from_slice(&12u32.to_le_bytes());
        body.extend_from_slice(&4u32.to_le_bytes());
        body.extend_from_slice(&0u32.to_le_bytes());
    } else {
        body.extend_from_slice(&[0, 0]);
        body.extend_from_slice(&4u32.to_le_bytes());
    }
    body.extend_from_slice(&0u32.to_le_bytes());
    response.body = body;
    response
}

/// True if MS-FSCC 2.4 documents `class` as a file information class.
fn is_file_class(class: u8) -> bool {
    matches!(class, 1..=29 | 31..=40 | 44..=46 | 48 | 50 | 54 | 59 | 60 | 64 | 65 | 78..=81)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn length_error_on_smb311_carries_one_empty_error_context() {
        let response = info_length_mismatch(true);
        assert_eq!(response.status, ntstatus::STATUS_INFO_LENGTH_MISMATCH);
        assert_eq!(
            response.body,
            [9, 0, 1, 0, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        );
        let response = info_length_mismatch(false);
        assert_eq!(response.body, [9, 0, 0, 0, 0, 0, 0, 0]);
    }

    #[tokio::test]
    async fn directories_are_reported_with_a_size_of_zero_whatever_the_backend_says() {
        use crate::proto::header::{Command, SMB2_HEADER_LEN};
        use crate::proto::messages::{
            CloseRequest, CloseResponse, CreateRequest, CreateResponse, FileId,
            QueryDirectoryRequest, QueryDirectoryResponse,
        };
        use crate::tests::memfs::MemFsBackend;
        use crate::tests::peer::{Peer, status};
        use crate::{Share, SmbServer};

        let backend = MemFsBackend::new()
            .with_dir("d")
            .with_dir("d\\sub")
            .with_file("d\\a.txt", b"hello\n")
            .with_dir_size(4096);
        let state = SmbServer::builder()
            .listen("127.0.0.1:0".parse().unwrap())
            .share(Share::new("home", backend).public())
            .build()
            .expect("build")
            .state();
        let mut peer = Peer::new(&state, false).await;
        let u64_at =
            |buf: &[u8], at: usize| u64::from_le_bytes(buf[at..at + 8].try_into().unwrap());

        let name = crate::utils::utf16le("d");
        let mut body = Vec::new();
        CreateRequest {
            structure_size: 57,
            security_flags: 0,
            requested_oplock_level: 0,
            impersonation_level: 2,
            smb_create_flags: 0,
            reserved: 0,
            desired_access: 0x0012_0089,
            file_attributes: 0,
            share_access: 0x7,
            create_disposition: 1,
            create_options: 0x1,
            name_offset: 0x78,
            name_length: name.len() as u16,
            create_contexts_offset: 0,
            create_contexts_length: 0,
            name: name.clone(),
            create_contexts: vec![],
        }
        .write_to(&mut body)
        .unwrap();
        let (_, reply) = peer.request(&state, Command::Create, &body).await;
        assert_eq!(status(&reply), 0);
        let created = CreateResponse::parse(&reply[SMB2_HEADER_LEN..]).unwrap();
        assert_eq!((created.allocation_size, created.end_of_file), (0, 0));
        let dir: FileId = created.file_id;

        // FileStandardInformation, FileAllInformation and
        // FileNetworkOpenInformation, with where their sizes are.
        for (class, at) in [(5, 0), (18, 40), (34, 32)] {
            let mut body = Vec::new();
            QueryInfoRequest {
                structure_size: 41,
                info_type: 1,
                file_information_class: class,
                output_buffer_length: 4096,
                input_buffer_offset: 0,
                reserved: 0,
                input_buffer_length: 0,
                additional_information: 0,
                flags: 0,
                file_id: dir,
                input_buffer: vec![],
            }
            .write_to(&mut body)
            .unwrap();
            let (_, reply) = peer.request(&state, Command::QueryInfo, &body).await;
            assert_eq!(status(&reply), 0, "class {class}");
            let buf = QueryInfoResponse::parse(&reply[SMB2_HEADER_LEN..])
                .unwrap()
                .buffer;
            assert_eq!(u64_at(&buf, at), 0, "AllocationSize in class {class}");
            assert_eq!(u64_at(&buf, at + 8), 0, "EndOfFile in class {class}");
        }

        let pattern = crate::utils::utf16le("*");
        let mut body = Vec::new();
        QueryDirectoryRequest {
            structure_size: 33,
            file_information_class: 37,
            flags: QueryDirectoryRequest::FLAG_RESTART_SCANS,
            file_index: 0,
            file_id: dir,
            file_name_offset: 96,
            file_name_length: pattern.len() as u16,
            output_buffer_length: 65536,
            file_name: pattern,
        }
        .write_to(&mut body)
        .unwrap();
        let (_, reply) = peer.request(&state, Command::QueryDirectory, &body).await;
        assert_eq!(status(&reply), 0);
        let buf = QueryDirectoryResponse::parse(&reply[SMB2_HEADER_LEN..])
            .unwrap()
            .buffer;
        let mut listed = Vec::new();
        let mut at = 0;
        loop {
            let entry = &buf[at..];
            let len = u32::from_le_bytes(entry[60..64].try_into().unwrap()) as usize;
            let units: Vec<u16> = entry[104..104 + len]
                .chunks_exact(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .collect();
            let name = String::from_utf16(&units).unwrap();
            listed.push((name, u64_at(entry, 40), u64_at(entry, 48)));
            match u32::from_le_bytes(entry[0..4].try_into().unwrap()) as usize {
                0 => break,
                next => at += next,
            }
        }
        listed.sort();
        let expected = [(".", 0), ("..", 0), ("a.txt", 6), ("sub", 0)]
            .map(|(name, size)| (name.to_string(), size, size));
        assert_eq!(listed, expected);

        let mut body = Vec::new();
        CloseRequest {
            structure_size: 24,
            flags: 1,
            reserved: 0,
            file_id: dir,
        }
        .write_to(&mut body)
        .unwrap();
        let (_, reply) = peer.request(&state, Command::Close, &body).await;
        assert_eq!(status(&reply), 0);
        let closed = CloseResponse::parse(&reply[SMB2_HEADER_LEN..]).unwrap();
        assert_eq!((closed.allocation_size, closed.end_of_file), (0, 0));
    }
}
