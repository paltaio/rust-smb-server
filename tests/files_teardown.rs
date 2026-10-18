//! Every way an open ends closes it the way CLOSE does.

mod common;

use common::client::*;
use tempfile::tempdir;

async fn delete_on_close(c: &mut Client, name: &str) {
    c.create(Create {
        name,
        access: RW | DELETE,
        disposition: FILE_CREATE,
        options: FILE_DELETE_ON_CLOSE,
        ..Create::default()
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn dropped_connection_closes_its_opens() {
    let td = tempdir().unwrap();
    let (backend, counters) = Probe::new(td.path(), Counters::default());
    let server = Server::public(backend).await;
    let mut c = server.client().await;
    delete_on_close(&mut c, "tmp.txt").await;
    let _kept = c.open("tmp.txt", FILE_READ_DATA, SHARE_ALL).await.unwrap();
    drop(c);

    let path = td.path().join("tmp.txt");
    assert!(eventually(|| !path.exists()).await, "file left behind");
    assert!(eventually(|| Counters::get(&counters.closes) == 2).await);
}

#[tokio::test]
async fn tree_disconnect_and_logoff_close_their_opens() {
    let td = tempdir().unwrap();
    let (backend, counters) = Probe::new(td.path(), Counters::default());
    let server = Server::public(backend).await;

    let mut c = server.client().await;
    delete_on_close(&mut c, "tree.txt").await;
    assert_eq!(c.tree_disconnect().await, 0);
    assert!(!td.path().join("tree.txt").exists());
    assert_eq!(Counters::get(&counters.closes), 1);

    let mut c = server.client().await;
    delete_on_close(&mut c, "session.txt").await;
    assert_eq!(c.logoff().await, 0);
    assert!(!td.path().join("session.txt").exists());
    assert_eq!(Counters::get(&counters.closes), 2);
}

#[tokio::test]
async fn revoked_share_closes_its_opens() {
    let td = tempdir().unwrap();
    let (backend, counters) = Probe::new(td.path(), Counters::default());
    let server = Server::public(backend).await;
    let mut c = server.client().await;
    delete_on_close(&mut c, "gone.txt").await;

    server.config.remove_share("share").await.unwrap();
    assert!(!td.path().join("gone.txt").exists());
    assert_eq!(Counters::get(&counters.closes), 1);
}

#[tokio::test]
async fn close_without_attributes_clears_the_flag() {
    let td = tempdir().unwrap();
    std::fs::write(td.path().join("f.txt"), b"data").unwrap();
    let counters = Counters::default();
    // CREATE stats once; the CLOSE stat fails.
    counters
        .fail_stats_after
        .store(1, std::sync::atomic::Ordering::SeqCst);
    let (backend, _counters) = Probe::new(td.path(), counters);
    let server = Server::public(backend).await;
    let mut c = server.client().await;
    let f = c.open("f.txt", FILE_READ_DATA, SHARE_ALL).await.unwrap();
    let (status, resp) = c.close_with(f, 1).await;
    assert_eq!(status, 0);
    let resp = resp.unwrap();
    assert_eq!(resp.flags, 0);
    assert_eq!(resp.end_of_file, 0);
}
