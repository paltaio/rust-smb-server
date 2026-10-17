//! Socket options on accepted connections.

#[path = "support_transport.rs"]
mod support;

use std::time::{Duration, Instant};

use smb_server::SmbServer;
use smb_server::wire::header::Command;
use support::{connect_negotiated, echo, read_response, start};
use tokio::io::AsyncWriteExt;

#[tokio::test]
async fn pipelined_responses_are_not_delayed() {
    let (addr, handle) = start(SmbServer::builder()).await;
    let mut s = connect_negotiated(addr).await;

    const ROUNDS: u64 = 10;
    let begin = Instant::now();
    for round in 0..ROUNDS {
        let mut both = echo(1 + 2 * round);
        both.extend_from_slice(&echo(2 + 2 * round));
        s.write_all(&both).await.expect("write");
        for _ in 0..2 {
            let (hdr, _) = read_response(&mut s).await;
            assert_eq!(hdr.command, Command::Echo);
        }
    }
    let elapsed = begin.elapsed();
    assert!(
        elapsed < Duration::from_millis(20 * ROUNDS),
        "{ROUNDS} rounds of two pipelined ECHOs took {elapsed:?}"
    );
    handle.abort();
}
