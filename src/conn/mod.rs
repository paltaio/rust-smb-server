//! Per-connection task layout.

pub mod chain;
pub mod credits;
pub mod limits;
pub mod listener;
pub mod outbound;
pub mod pending;
pub mod reader;
pub mod related;
pub mod state;
pub mod writer;

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::Ordering;

use tokio::net::TcpStream;
use tracing::{debug, info};

use crate::server::ServerState;
use state::Connection;

/// Runs the reader and writer tasks for a single connection accepted from
/// `peer` until either side hangs up. Returns once both halves are done.
pub async fn connection_loop(
    stream: TcpStream,
    peer: SocketAddr,
    server: Arc<ServerState>,
) -> io::Result<()> {
    let (read_half, write_half) = tokio::io::split(stream);
    let mut conn = Connection::new(
        server.config.server_guid,
        server.config.max_read_size,
        server.config.max_write_size,
    );
    conn.peer_addr = Some(peer);
    let conn = Arc::new(conn);
    let conn_id = server.active_connections.register(&conn).await;
    let (tx, rx) = writer::response_queue();
    conn.outbound.attach(tx.clone());

    let writer_handle = tokio::spawn(writer::writer_task(
        write_half,
        rx,
        server.config.limits.io_timeout,
    ));

    info!("connection accepted");
    let reader_result = reader::reader_task(read_half, server.clone(), conn.clone(), tx).await;
    debug!(?reader_result, "reader exited");
    // Requests still waiting are cancelled and answered while the writer
    // runs. Then the writer drains; messages for this connection raised
    // from now on are not sent.
    conn.pending.shutdown(server.config.limits.io_timeout).await;
    conn.outbound.close();
    let _ = writer_handle.await;
    // Durable opens outlive a lost connection, but not a shutdown.
    let keep = (!server.shutting_down.load(Ordering::Acquire)).then_some(&server.durable);
    conn.close_all(keep).await;
    server.active_connections.unregister(conn_id).await;
    info!("connection closed");
    reader_result
}
