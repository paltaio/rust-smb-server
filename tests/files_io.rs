//! READ, WRITE and FLUSH request rules.

mod common;

use common::client::*;
use smb_server::ntstatus;
use smb_server::wire::messages::WriteRequest;
use tempfile::tempdir;

const SMB21: u16 = 0x0210;
const SMB302: u16 = 0x0302;

fn through(req: WriteRequest, flags: u32) -> WriteRequest {
    WriteRequest { flags, ..req }
}

#[tokio::test]
async fn write_through_needs_an_unbuffered_write_and_reaches_storage() {
    let td = tempdir().unwrap();
    std::fs::write(td.path().join("f.txt"), b"data").unwrap();
    let (backend, counters) = Probe::new(td.path(), Counters::default());
    let server = Server::public(backend).await;
    let wt = WriteRequest::FLAG_WRITE_THROUGH;
    let unbuffered = WriteRequest::FLAG_WRITE_UNBUFFERED;

    let mut c = server.client_at(SMB21).await;
    let f = c.open("f.txt", RW, SHARE_ALL).await.unwrap();
    assert_eq!(
        c.write_raw(through(write_request(f, 0, b"a"), wt)).await,
        Err(ntstatus::STATUS_INVALID_PARAMETER)
    );
    c.close(f).await;
    let f = c
        .create(Create {
            name: "f.txt",
            options: FILE_NO_INTERMEDIATE_BUFFERING,
            ..Create::default()
        })
        .await
        .unwrap()
        .file_id;
    let before = Counters::get(&counters.flushes);
    assert_eq!(
        c.write_raw(through(write_request(f, 0, b"a"), wt)).await,
        Ok(1)
    );
    assert_eq!(Counters::get(&counters.flushes), before + 1);
    c.close(f).await;

    let mut c = server.client_at(SMB302).await;
    let f = c.open("f.txt", RW, SHARE_ALL).await.unwrap();
    assert_eq!(
        c.write_raw(through(write_request(f, 0, b"b"), wt)).await,
        Err(ntstatus::STATUS_INVALID_PARAMETER)
    );
    let before = Counters::get(&counters.flushes);
    assert_eq!(
        c.write_raw(through(write_request(f, 0, b"b"), wt | unbuffered))
            .await,
        Ok(1)
    );
    assert_eq!(Counters::get(&counters.flushes), before + 1);
    c.close(f).await;

    // An open made with FILE_WRITE_THROUGH writes through every time.
    let f = c
        .create(Create {
            name: "f.txt",
            options: FILE_WRITE_THROUGH,
            ..Create::default()
        })
        .await
        .unwrap()
        .file_id;
    let before = Counters::get(&counters.flushes);
    assert_eq!(c.write(f, 0, b"c").await, Ok(1));
    assert_eq!(Counters::get(&counters.flushes), before + 1);
}

#[tokio::test]
async fn rdma_channels_are_refused_on_smb3() {
    let td = tempdir().unwrap();
    std::fs::write(td.path().join("f.txt"), b"data").unwrap();
    let server = Server::public(local(td.path())).await;
    let mut c = server.client_at(SMB302).await;
    let f = c.open("f.txt", RW, SHARE_ALL).await.unwrap();
    for channel in [1, 2, 3] {
        assert_eq!(
            c.read_full(f, 0, 4, 0, channel).await,
            Err(ntstatus::STATUS_INVALID_PARAMETER)
        );
        let req = WriteRequest {
            channel,
            ..write_request(f, 0, b"x")
        };
        assert_eq!(
            c.write_raw(req).await,
            Err(ntstatus::STATUS_INVALID_PARAMETER)
        );
    }
    assert_eq!(c.read(f, 0, 4).await.unwrap(), b"data");
}

#[tokio::test]
async fn data_offset_past_0x100_is_refused() {
    let td = tempdir().unwrap();
    std::fs::write(td.path().join("f.txt"), b"data").unwrap();
    let server = Server::public(local(td.path())).await;
    let mut c = server.client().await;
    let f = c.open("f.txt", RW, SHARE_ALL).await.unwrap();
    let mut req = write_request(f, 0, &[b'z'; 0x100]);
    req.data_offset = 0x101;
    req.length = 1;
    assert_eq!(
        c.write_raw(req).await,
        Err(ntstatus::STATUS_INVALID_PARAMETER)
    );
    c.close(f).await;
    assert_eq!(std::fs::read(td.path().join("f.txt")).unwrap(), b"data");
}

#[tokio::test]
async fn append_only_open_only_appends() {
    let td = tempdir().unwrap();
    std::fs::write(td.path().join("f.txt"), b"data").unwrap();
    let server = Server::public(local(td.path())).await;
    let mut c = server.client().await;

    let f = c.open("f.txt", FILE_APPEND_DATA, SHARE_ALL).await.unwrap();
    assert_eq!(
        c.write(f, 0, b"X").await,
        Err(ntstatus::STATUS_ACCESS_DENIED)
    );
    assert_eq!(c.write(f, 4, b"++").await, Ok(2));
    c.close(f).await;

    let f = c.open("f.txt", FILE_WRITE_DATA, SHARE_ALL).await.unwrap();
    assert_eq!(c.write(f, 0, b"D").await, Ok(1));
    assert_eq!(
        c.write(f, 6, b"!").await,
        Err(ntstatus::STATUS_ACCESS_DENIED)
    );
    c.close(f).await;
    assert_eq!(std::fs::read(td.path().join("f.txt")).unwrap(), b"Data++");
}

#[tokio::test]
async fn flush_needs_write_access_on_files() {
    let td = tempdir().unwrap();
    std::fs::write(td.path().join("f.txt"), b"data").unwrap();
    std::fs::create_dir(td.path().join("d")).unwrap();
    let server = Server::public(local(td.path())).await;
    let mut c = server.client().await;

    let f = c.open("f.txt", FILE_GENERIC_READ, SHARE_ALL).await.unwrap();
    assert_eq!(c.flush(f).await, ntstatus::STATUS_ACCESS_DENIED);
    let w = c.open("f.txt", RW, SHARE_ALL).await.unwrap();
    assert_eq!(c.flush(w).await, 0);
    let d = c.open("d", FILE_GENERIC_READ, SHARE_ALL).await.unwrap();
    assert_eq!(c.flush(d).await, 0);
}

#[tokio::test]
async fn read_shorter_than_minimum_count_is_end_of_file() {
    let td = tempdir().unwrap();
    std::fs::write(td.path().join("f.txt"), b"0123456789").unwrap();
    let server = Server::public(local(td.path())).await;
    let mut c = server.client().await;
    let f = c.open("f.txt", FILE_GENERIC_READ, SHARE_ALL).await.unwrap();
    assert_eq!(
        c.read_full(f, 0, 5, 100, 0).await,
        Err(ntstatus::STATUS_END_OF_FILE)
    );
    assert_eq!(
        c.read_full(f, 8, 5, 3, 0).await,
        Err(ntstatus::STATUS_END_OF_FILE)
    );
    assert_eq!(c.read_full(f, 8, 5, 2, 0).await.unwrap(), b"89");
}
