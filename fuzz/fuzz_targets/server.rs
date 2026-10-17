use std::sync::LazyLock;

use smb_server::{LocalFsBackend, Share, SmbServer};
use tokio::runtime::Runtime;

static RUNTIME: LazyLock<Runtime> = LazyLock::new(|| {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime")
});

static SERVER: LazyLock<SmbServer> = LazyLock::new(|| {
    let root = std::env::temp_dir().join("smb-server-fuzz");
    std::fs::create_dir_all(&root).expect("share root");
    let backend = LocalFsBackend::new(&root).expect("backend").read_only();
    SmbServer::builder()
        .listen("127.0.0.1:0".parse().expect("addr"))
        .user("alice", "password")
        .share(Share::new("public", backend).public_read_only())
        .build()
        .expect("server")
});

/// Dispatches `frame` on a fresh connection to a server with one user and an
/// anonymous read-only share.
pub fn dispatch(frame: &[u8]) {
    RUNTIME.block_on(smb_server::fuzzing::dispatch(&SERVER, frame));
}
