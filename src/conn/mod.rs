//! Per-connection task layout.

pub mod chain;
pub mod credits;
pub mod limits;
pub mod listener;
pub mod reader;
pub mod related;
pub mod state;
pub mod writer;

use std::io;
use std::sync::Arc;

use tokio::net::TcpStream;
use tracing::{debug, info};

use crate::server::ServerState;
use state::Connection;

/// Runs the reader and writer tasks for a single accepted connection until
/// either side hangs up. Returns once both halves are done.
pub async fn connection_loop(stream: TcpStream, server: Arc<ServerState>) -> io::Result<()> {
    let (read_half, write_half) = tokio::io::split(stream);
    let conn = Arc::new(Connection::new(
        server.config.server_guid,
        server.config.max_read_size,
        server.config.max_write_size,
    ));
    let conn_id = server.active_connections.register(&conn).await;
    let (tx, rx) = writer::response_queue();

    let writer_handle = tokio::spawn(writer::writer_task(
        write_half,
        rx,
        server.config.limits.io_timeout,
    ));

    info!("connection accepted");
    let reader_result = reader::reader_task(read_half, server.clone(), conn.clone(), tx).await;
    debug!(?reader_result, "reader exited");
    // Wait for writer to drain.
    let _ = writer_handle.await;
    conn.close_all().await;
    server.active_connections.unregister(conn_id).await;
    info!("connection closed");
    reader_result
}
