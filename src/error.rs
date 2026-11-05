//! Backend error type and its NTSTATUS mapping.

use thiserror::Error;

use crate::ntstatus;

pub type SmbResult<T> = Result<T, SmbError>;

/// Errors returned by `ShareBackend` and surfaced through the SMB protocol.
///
/// `to_nt_status` maps each variant to one NTSTATUS code. Protocol-layer
/// failures (malformed frames, bad signatures) are handled by the dispatcher
/// and never become `SmbError`.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum SmbError {
    #[error("not found")]
    NotFound,
    #[error("path not found")]
    PathNotFound,
    #[error("access denied")]
    AccessDenied,
    #[error("exists")]
    Exists,
    #[error("not empty")]
    NotEmpty,
    #[error("is a directory")]
    IsDirectory,
    #[error("not a directory")]
    NotADirectory,
    #[error("name too long / invalid")]
    NameInvalid,
    #[error("sharing violation")]
    Sharing,
    #[error("not supported")]
    NotSupported,
    #[error("source and target are on different devices")]
    NotSameDevice,
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("disk full")]
    DiskFull,
    #[error("disk quota exceeded")]
    QuotaExceeded,
    /// The request carries a value the backend does not take, such as data
    /// a stream with a fixed layout cannot hold.
    #[error("invalid parameter")]
    InvalidParameter,
    /// The name is a FIFO, a socket or a device node, which the backend
    /// does not open.
    #[error("not a regular file or directory")]
    SpecialFile,
    /// The extended attributes of a file would take more room than the
    /// backend gives them.
    #[error("extended attributes too large")]
    EaTooLarge,
    /// The backend cannot store an extended attribute under this name.
    #[error("invalid extended attribute name")]
    EaNameInvalid,
}

impl SmbError {
    /// NTSTATUS code for this error.
    pub fn to_nt_status(&self) -> u32 {
        match self {
            SmbError::NotFound => ntstatus::STATUS_OBJECT_NAME_NOT_FOUND,
            SmbError::PathNotFound => ntstatus::STATUS_OBJECT_PATH_NOT_FOUND,
            SmbError::AccessDenied => ntstatus::STATUS_ACCESS_DENIED,
            SmbError::Exists => ntstatus::STATUS_OBJECT_NAME_COLLISION,
            SmbError::NotEmpty => ntstatus::STATUS_DIRECTORY_NOT_EMPTY,
            SmbError::IsDirectory => ntstatus::STATUS_FILE_IS_A_DIRECTORY,
            SmbError::NotADirectory => ntstatus::STATUS_NOT_A_DIRECTORY,
            SmbError::NameInvalid => ntstatus::STATUS_OBJECT_NAME_INVALID,
            SmbError::Sharing => ntstatus::STATUS_SHARING_VIOLATION,
            SmbError::NotSupported => ntstatus::STATUS_NOT_SUPPORTED,
            SmbError::NotSameDevice => ntstatus::STATUS_NOT_SAME_DEVICE,
            SmbError::Io(_) => ntstatus::STATUS_UNEXPECTED_IO_ERROR,
            SmbError::DiskFull => ntstatus::STATUS_DISK_FULL,
            SmbError::QuotaExceeded => ntstatus::STATUS_DISK_QUOTA_EXCEEDED,
            SmbError::InvalidParameter => ntstatus::STATUS_INVALID_PARAMETER,
            SmbError::SpecialFile => ntstatus::STATUS_IO_REPARSE_TAG_NOT_HANDLED,
            SmbError::EaTooLarge => ntstatus::STATUS_EA_TOO_LARGE,
            SmbError::EaNameInvalid => ntstatus::STATUS_INVALID_EA_NAME,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_each_variant_to_nt_status() {
        assert_eq!(SmbError::NotFound.to_nt_status(), 0xC000_0034);
        assert_eq!(SmbError::PathNotFound.to_nt_status(), 0xC000_003A);
        assert_eq!(SmbError::AccessDenied.to_nt_status(), 0xC000_0022);
        assert_eq!(SmbError::Exists.to_nt_status(), 0xC000_0035);
        assert_eq!(SmbError::NotEmpty.to_nt_status(), 0xC000_0101);
        assert_eq!(SmbError::IsDirectory.to_nt_status(), 0xC000_00BA);
        assert_eq!(SmbError::NotADirectory.to_nt_status(), 0xC000_0103);
        assert_eq!(SmbError::NameInvalid.to_nt_status(), 0xC000_0033);
        assert_eq!(SmbError::Sharing.to_nt_status(), 0xC000_0043);
        assert_eq!(SmbError::NotSupported.to_nt_status(), 0xC000_00BB);
        assert_eq!(SmbError::NotSameDevice.to_nt_status(), 0xC000_00D4);
        assert_eq!(SmbError::InvalidParameter.to_nt_status(), 0xC000_000D);
        assert_eq!(SmbError::SpecialFile.to_nt_status(), 0xC000_0279);
        assert_eq!(SmbError::EaTooLarge.to_nt_status(), 0xC000_0050);
        assert_eq!(SmbError::EaNameInvalid.to_nt_status(), 0x8000_0013);

        let io_err = SmbError::Io(std::io::Error::other("boom"));
        assert_eq!(io_err.to_nt_status(), 0xC000_00E9);
    }
}
