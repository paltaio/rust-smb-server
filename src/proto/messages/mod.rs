//! Per-command request/response wire structs.
//!
//! One submodule per SMB2 command (MS-SMB2 §2.2.3 to §2.2.40), plus the ERROR
//! response (§2.2.2). The structs are `binrw` encoders and decoders for the
//! wire bytes only.

use binrw::io::SeekFrom;

use crate::proto::header::SMB2_HEADER_LEN;

pub mod cancel;
pub mod change_notify;
pub mod close;
pub mod create;
pub mod echo;
pub mod error_response;
pub mod flush;
pub mod ioctl;
pub mod lock;
pub mod logoff;
pub mod negotiate;
pub mod oplock_break;
pub mod query_directory;
pub mod query_info;
pub mod read;
pub mod session_setup;
pub mod set_info;
pub mod tree_connect;
pub mod tree_disconnect;
pub mod write;

pub use cancel::CancelRequest;
pub use change_notify::{ChangeNotifyRequest, ChangeNotifyResponse};
pub use close::{CloseRequest, CloseResponse};
pub use create::{
    CreateContext, CreateRequest, CreateResponse, FileId, ImpersonationLevel, OplockLevel,
};
pub use echo::{EchoRequest, EchoResponse};
pub use error_response::{ErrorContext, ErrorResponse};
pub use flush::{FlushRequest, FlushResponse};
pub use ioctl::{Fsctl, IoctlRequest, IoctlResponse};
pub use lock::{LockElement, LockRequest, LockResponse};
pub use logoff::{LogoffRequest, LogoffResponse};
pub use negotiate::{
    Dialect, EncryptionCapabilities, NegotiateContext, NegotiateRequest, NegotiateResponse,
    PreauthIntegrityCapabilities, SigningCapabilities,
};
pub use oplock_break::{OplockBreakAck, OplockBreakNotification};
pub use query_directory::{FileInfoClass, QueryDirectoryRequest, QueryDirectoryResponse};
pub use query_info::{InfoType, QueryInfoRequest, QueryInfoResponse};
pub use read::{ReadRequest, ReadResponse};
pub use session_setup::{SessionSetupRequest, SessionSetupResponse};
pub use set_info::{SetInfoRequest, SetInfoResponse};
pub use tree_connect::{TreeConnectRequest, TreeConnectResponse};
pub use tree_disconnect::{TreeDisconnectRequest, TreeDisconnectResponse};
pub use write::{WriteRequest, WriteResponse};

/// Reads a `len`-byte buffer, failing before it allocates when fewer than
/// `len` bytes remain in the input.
#[binrw::parser(reader)]
fn read_buf(len: usize) -> binrw::BinResult<Vec<u8>> {
    let pos = reader.stream_position()?;
    let end = reader.seek(SeekFrom::End(0))?;
    reader.seek(SeekFrom::Start(pos))?;
    if end.saturating_sub(pos) < len as u64 {
        return Err(binrw::Error::Io(std::io::ErrorKind::UnexpectedEof.into()));
    }
    let mut buf = vec![0; len];
    reader.read_exact(&mut buf)?;
    Ok(buf)
}

/// Reads a `len`-byte buffer at `offset`, counted from the start of the SMB2
/// header; position 0 of the reader is the first byte after the header. Fails
/// when a non-empty buffer starts before `min_offset` or ends past the
/// request. An empty buffer reads nothing, whatever its offset.
#[binrw::parser(reader)]
fn read_buf_at(offset: u64, len: usize, min_offset: u64) -> binrw::BinResult<Vec<u8>> {
    if len == 0 {
        return Ok(Vec::new());
    }
    if offset < min_offset {
        return Err(binrw::Error::AssertFail {
            pos: reader.stream_position()?,
            message: format!("buffer offset {offset:#x} is below {min_offset:#x}"),
        });
    }
    reader.seek(SeekFrom::Start(offset - SMB2_HEADER_LEN as u64))?;
    read_buf(reader, binrw::Endian::Little, (len,))
}
