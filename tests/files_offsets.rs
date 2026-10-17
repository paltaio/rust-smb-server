//! WRITE and SET_INFO buffers are read where their offsets point.

#[path = "support_files.rs"]
mod support;

use smb_server::ntstatus;
use smb_server::wire::messages::WriteRequest;
use support::*;
use tempfile::tempdir;

#[tokio::test]
async fn zero_length_write_writes_nothing() {
    let td = tempdir().unwrap();
    std::fs::write(td.path().join("f.txt"), b"abc").unwrap();
    let server = Server::public(local(td.path())).await;
    let mut c = server.client().await;
    let f = c.open("f.txt", RW, SHARE_ALL).await.unwrap();

    // The client sends one padding byte with an empty WRITE.
    let mut req = write_request(f, 3, b"A");
    req.length = 0;
    assert_eq!(c.write_raw(req).await, Ok(0));
    c.close(f).await;
    assert_eq!(std::fs::read(td.path().join("f.txt")).unwrap(), b"abc");
}

#[tokio::test]
async fn write_data_starts_at_data_offset() {
    let td = tempdir().unwrap();
    std::fs::write(td.path().join("f.txt"), b"0123456789").unwrap();
    let server = Server::public(local(td.path())).await;
    let mut c = server.client().await;
    let f = c.open("f.txt", RW, SHARE_ALL).await.unwrap();

    let mut req = write_request(f, 2, b"PADPADPAXYZ");
    req.data_offset = 0x78;
    req.length = 3;
    assert_eq!(c.write_raw(req).await, Ok(3));

    let mut inside = write_request(f, 0, b"Q");
    inside.data_offset = WriteRequest::STANDARD_DATA_OFFSET - 8;
    assert_eq!(
        c.write_raw(inside).await,
        Err(ntstatus::STATUS_INVALID_PARAMETER)
    );
    c.close(f).await;
    assert_eq!(
        std::fs::read(td.path().join("f.txt")).unwrap(),
        b"01XYZ56789"
    );
}

#[tokio::test]
async fn set_info_buffer_starts_at_buffer_offset() {
    let td = tempdir().unwrap();
    std::fs::write(td.path().join("f.txt"), b"0123456789").unwrap();
    let server = Server::public(local(td.path())).await;
    let mut c = server.client().await;
    let f = c.open("f.txt", RW, SHARE_ALL).await.unwrap();

    // FileEndOfFileInformation of 4, eight bytes after the fixed part.
    let req = smb_server::wire::messages::SetInfoRequest {
        structure_size: 33,
        info_type: 1,
        file_information_class: FILE_END_OF_FILE_INFORMATION,
        buffer_length: 8,
        buffer_offset: 0x68,
        reserved: 0,
        additional_information: 0,
        file_id: f,
        buffer: [[9; 8], 4u64.to_le_bytes()].concat(),
    };
    let mut body = Vec::new();
    req.write_to(&mut body).unwrap();
    let (status, _) = c
        .send(smb_server::wire::header::Command::SetInfo, &body)
        .await;
    assert_eq!(status, 0);
    c.close(f).await;
    assert_eq!(std::fs::read(td.path().join("f.txt")).unwrap(), b"0123");
}
