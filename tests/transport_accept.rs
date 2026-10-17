//! The accept loop when the process runs out of file descriptors. Lowers
//! RLIMIT_NOFILE for the whole process, so it lives in its own test binary.
#![cfg(target_os = "linux")]

#[path = "support_transport.rs"]
mod support;

use std::fs::File;
use std::time::Duration;

use smb_server::SmbServer;
use smb_server::wire::header::Command;
use support::{negotiate_request, read_response, start};
use tokio::io::AsyncWriteExt;

fn cpu_time() -> Duration {
    // SAFETY: `usage` is a valid out-pointer for getrusage.
    let usage = unsafe {
        let mut usage = std::mem::zeroed::<libc::rusage>();
        assert_eq!(libc::getrusage(libc::RUSAGE_SELF, &mut usage), 0);
        usage
    };
    let tv = |t: libc::timeval| Duration::new(t.tv_sec as u64, t.tv_usec as u32 * 1000);
    tv(usage.ru_utime) + tv(usage.ru_stime)
}

fn set_fd_limit(soft: u64) -> u64 {
    // SAFETY: `limit` is a valid pointer for getrlimit and setrlimit.
    unsafe {
        let mut limit = std::mem::zeroed::<libc::rlimit>();
        assert_eq!(libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit), 0);
        let old = limit.rlim_cur;
        limit.rlim_cur = soft;
        assert_eq!(libc::setrlimit(libc::RLIMIT_NOFILE, &limit), 0);
        old
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn accept_errors_back_off_and_recover() {
    let (addr, handle) = start(SmbServer::builder()).await;

    let open = std::fs::read_dir("/proc/self/fd").expect("fd dir").count() as u64;
    let old_limit = set_fd_limit(open + 16);
    let mut hogs = Vec::new();
    while let Ok(f) = File::open("/dev/null") {
        hogs.push(f);
    }
    // One free descriptor for the client; the server's accept then fails.
    hogs.pop();
    let client = std::net::TcpStream::connect(addr).expect("connect");

    let before = cpu_time();
    tokio::time::sleep(Duration::from_secs(1)).await;
    let spent = cpu_time() - before;

    drop(hogs);
    set_fd_limit(old_limit);
    assert!(
        spent < Duration::from_millis(300),
        "accept loop used {spent:?} of CPU in one second"
    );

    // Once descriptors are free again, the waiting connection is served.
    client.set_nonblocking(true).expect("nonblocking");
    let mut client = tokio::net::TcpStream::from_std(client).expect("tokio stream");
    client.write_all(&negotiate_request()).await.expect("write");
    let (hdr, _) = read_response(&mut client).await;
    assert_eq!(hdr.command, Command::Negotiate);
    handle.abort();
}
