//! QUERY_INFO against `LocalFsBackend` over TCP loopback.
#![cfg(feature = "localfs")]

mod common;

use common::client::*;
use smb_server::{LocalFsBackend, ShareBackend, ntstatus};
use tempfile::tempdir;

#[tokio::test]
async fn volume_size_and_identity_come_from_the_backend() {
    let td = tempdir().expect("tempdir");
    let backend = LocalFsBackend::new(td.path()).expect("open root");
    let volume = backend.volume_info().await.expect("volume info");
    let server = Server::public(backend).await;
    let mut c = server.client().await;
    let root = c.open_dir("").await;

    let (status, full) = c
        .query_info(root, INFO_FILESYSTEM, FS_FULL_SIZE_INFORMATION, 4096)
        .await;
    assert_eq!(status, ntstatus::STATUS_SUCCESS);
    assert_eq!(u64_at(&full, 0), volume.total_allocation_units);
    assert_ne!(u64_at(&full, 0), 1 << 40);
    assert_eq!(u32_at(&full, 24), volume.sectors_per_allocation_unit);
    assert_eq!(u32_at(&full, 28), volume.bytes_per_sector);

    let (status, size) = c
        .query_info(root, INFO_FILESYSTEM, FS_SIZE_INFORMATION, 4096)
        .await;
    assert_eq!(status, ntstatus::STATUS_SUCCESS);
    assert_eq!(u64_at(&size, 0), volume.total_allocation_units);

    // The label defaults to the share name.
    let (status, vol) = c
        .query_info(root, INFO_FILESYSTEM, FS_VOLUME_INFORMATION, 4096)
        .await;
    assert_eq!(status, ntstatus::STATUS_SUCCESS);
    assert_eq!(u32_at(&vol, 8), volume.serial_number);
    let label: Vec<u16> = vol[18..]
        .chunks_exact(2)
        .map(|b| u16::from_le_bytes([b[0], b[1]]))
        .collect();
    assert_eq!(String::from_utf16(&label).unwrap(), "share");

    let (status, sector) = c
        .query_info(root, INFO_FILESYSTEM, FS_SECTOR_SIZE_INFORMATION, 4096)
        .await;
    assert_eq!(status, ntstatus::STATUS_SUCCESS);
    assert_eq!(sector.len(), 28);
    assert_eq!(u32_at(&sector, 0), volume.bytes_per_sector);

    c.close(root).await;
}

#[tokio::test]
async fn short_buffers_get_partial_data_or_a_length_error() {
    let td = tempdir().expect("tempdir");
    std::fs::write(td.path().join("f.txt"), b"data").expect("write");
    let backend = LocalFsBackend::new(td.path()).expect("open root");
    let server = Server::public(backend).await;
    let mut c = server.client().await;
    let root = c.open_dir("").await;
    let file = c.open("f.txt", FILE_GENERIC_READ, SHARE_ALL).await.unwrap();

    // FileFsAttributeInformation: 12 fixed bytes, then "NTFS".
    let (status, buf) = c
        .query_info(root, INFO_FILESYSTEM, FS_ATTRIBUTE_INFORMATION, 14)
        .await;
    assert_eq!(status, ntstatus::STATUS_BUFFER_OVERFLOW);
    assert_eq!(buf.len(), 14);
    assert_eq!(u32_at(&buf, 8), 8);
    let (status, _) = c
        .query_info(root, INFO_FILESYSTEM, FS_ATTRIBUTE_INFORMATION, 11)
        .await;
    assert_eq!(status, ntstatus::STATUS_INFO_LENGTH_MISMATCH);

    // FileFsVolumeInformation: 18 fixed bytes, then the 10-byte label.
    let (status, buf) = c
        .query_info(root, INFO_FILESYSTEM, FS_VOLUME_INFORMATION, 24)
        .await;
    assert_eq!(status, ntstatus::STATUS_BUFFER_OVERFLOW);
    assert_eq!(buf.len(), 24);
    assert_eq!(u32_at(&buf, 12), 10);

    // Fixed-size classes need their whole size.
    let (status, _) = c
        .query_info(file, INFO_FILE, FILE_BASIC_INFORMATION, 39)
        .await;
    assert_eq!(status, ntstatus::STATUS_INFO_LENGTH_MISMATCH);
    let (status, buf) = c
        .query_info(file, INFO_FILE, FILE_BASIC_INFORMATION, 40)
        .await;
    assert_eq!((status, buf.len()), (ntstatus::STATUS_SUCCESS, 40));

    // FileStreamInformation returns whole entries only.
    let (status, buf) = c
        .query_info(file, INFO_FILE, FILE_STREAM_INFORMATION, 30)
        .await;
    assert_eq!(status, ntstatus::STATUS_BUFFER_OVERFLOW);
    assert!(buf.is_empty());

    // Below SMB 3.1.1 the length error carries no error data.
    let (status, body) = c
        .query_info_raw(file, INFO_FILE, FILE_BASIC_INFORMATION, 8)
        .await;
    assert_eq!(status, ntstatus::STATUS_INFO_LENGTH_MISMATCH);
    assert_eq!(u32_at(&body, 4), 0);

    c.close(file).await;
    c.close(root).await;
}

#[tokio::test]
async fn names_follow_the_rules_for_remote_queries() {
    let td = tempdir().expect("tempdir");
    std::fs::create_dir(td.path().join("d")).expect("mkdir");
    std::fs::write(td.path().join("d").join("f.txt"), b"x").expect("write");
    let backend = LocalFsBackend::new(td.path()).expect("open root");
    let server = Server::public(backend).await;
    let mut c = server.client().await;
    let file = c
        .open("d\\f.txt", FILE_GENERIC_READ, SHARE_ALL)
        .await
        .unwrap();

    let (status, _) = c
        .query_info(file, INFO_FILE, FILE_NAME_INFORMATION, 4096)
        .await;
    assert_eq!(status, ntstatus::STATUS_NOT_SUPPORTED);
    let (status, all) = c
        .query_info(file, INFO_FILE, FILE_ALL_INFORMATION, 4096)
        .await;
    assert_eq!(status, ntstatus::STATUS_SUCCESS);
    // FileNameLength after Basic, Standard, Internal, EA, Access, Position,
    // Mode and Alignment.
    assert_eq!(u32_at(&all, 96), 0);

    c.close(file).await;
}

#[tokio::test]
async fn unimplemented_classes_get_the_spec_statuses() {
    let td = tempdir().expect("tempdir");
    let backend = LocalFsBackend::new(td.path()).expect("open root");
    let server = Server::public(backend).await;
    let mut c = server.client().await;
    let root = c.open_dir("").await;

    for (info_type, class, expected) in [
        (
            INFO_FILE,
            FILE_ATTRIBUTE_TAG_INFORMATION,
            ntstatus::STATUS_NOT_SUPPORTED,
        ),
        // FileHardLinkInformation, documented for local use.
        (INFO_FILE, 0x2E, ntstatus::STATUS_NOT_SUPPORTED),
        // Not documented in MS-FSCC 2.4.
        (INFO_FILE, 0x2A, ntstatus::STATUS_INVALID_INFO_CLASS),
        (INFO_FILE, 0x7F, ntstatus::STATUS_INVALID_INFO_CLASS),
        (
            INFO_FILESYSTEM,
            FS_CONTROL_INFORMATION,
            ntstatus::STATUS_NOT_SUPPORTED,
        ),
        (INFO_FILESYSTEM, 0x0C, ntstatus::STATUS_INVALID_INFO_CLASS),
        (INFO_SECURITY, 0, ntstatus::STATUS_INVALID_DEVICE_REQUEST),
    ] {
        let (status, _) = c.query_info(root, info_type, class, 4096).await;
        assert_eq!(status, expected, "type {info_type} class {class:#x}");
    }

    c.close(root).await;
}

#[tokio::test]
async fn attribute_classes_require_read_attributes_access() {
    let td = tempdir().expect("tempdir");
    std::fs::write(td.path().join("f.txt"), b"x").expect("write");
    let backend = LocalFsBackend::new(td.path()).expect("open root");
    let server = Server::public(backend).await;
    let mut c = server.client().await;
    let file = c.open("f.txt", SYNCHRONIZE, SHARE_ALL).await.unwrap();

    for class in [FILE_BASIC_INFORMATION, FILE_ALL_INFORMATION, 0x22] {
        let (status, _) = c.query_info(file, INFO_FILE, class, 4096).await;
        assert_eq!(status, ntstatus::STATUS_ACCESS_DENIED, "class {class:#x}");
    }
    let (status, _) = c
        .query_info(file, INFO_FILE, FILE_STANDARD_INFORMATION, 4096)
        .await;
    assert_eq!(status, ntstatus::STATUS_SUCCESS);

    c.close(file).await;
}

#[tokio::test]
async fn output_buffer_is_capped_at_max_transact_size() {
    let td = tempdir().expect("tempdir");
    let backend = LocalFsBackend::new(td.path()).expect("open root");
    let server = Server::public(backend).await;
    let mut c = server.client().await;
    let root = c.open_dir("").await;
    let (status, _) = c
        .query_info(root, INFO_FILE, FILE_BASIC_INFORMATION, 0x7FFF_FFFF)
        .await;
    assert_eq!(status, ntstatus::STATUS_INVALID_PARAMETER);
    c.close(root).await;
}

#[cfg(unix)]
#[tokio::test]
async fn standard_information_reports_the_link_count() {
    let td = tempdir().expect("tempdir");
    std::fs::write(td.path().join("a"), b"x").expect("write");
    std::fs::hard_link(td.path().join("a"), td.path().join("b")).expect("link");
    let backend = LocalFsBackend::new(td.path()).expect("open root");
    let server = Server::public(backend).await;
    let mut c = server.client().await;
    let file = c.open("a", FILE_GENERIC_READ, SHARE_ALL).await.unwrap();

    let (status, standard) = c
        .query_info(file, INFO_FILE, FILE_STANDARD_INFORMATION, 4096)
        .await;
    assert_eq!(status, ntstatus::STATUS_SUCCESS);
    assert_eq!(u32_at(&standard, 16), 2);
    assert_eq!(standard[20], 0, "DeletePending");

    c.close(file).await;
}
