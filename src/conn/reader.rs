//! Per-connection frame reader: pulls bytes off the socket, frames them,
//! hands each frame to the dispatcher.

use std::io;
use std::sync::Arc;
use std::sync::atomic::Ordering;

use crate::proto::framing::{FRAME_HEADER_LEN, decode_frame_header};
use tokio::io::{AsyncReadExt, ReadHalf};
use tokio::net::TcpStream;
use tokio::time::Instant;
use tracing::{debug, error, info};

use crate::conn::limits::max_request_frame;
use crate::conn::state::Connection;
use crate::server::ServerState;

/// Reads the rest of a frame whose first `filled` prefix bytes are already
/// in `prefix`, and returns its payload (without the 4-byte length prefix).
/// A frame longer than the connection accepts fails before its payload is
/// read; the payload buffer grows with the bytes that arrive.
async fn read_frame_rest(
    reader: &mut ReadHalf<TcpStream>,
    conn: &Connection,
    prefix: &mut [u8; FRAME_HEADER_LEN],
    filled: usize,
) -> io::Result<Vec<u8>> {
    reader.read_exact(&mut prefix[filled..]).await?;
    let len = match decode_frame_header(prefix) {
        Ok(n) => n as usize,
        Err(e) => {
            return Err(io::Error::new(io::ErrorKind::InvalidData, e.to_string()));
        }
    };
    let limit = max_request_frame(
        *conn.dialect.read().await,
        *conn.max_read_size.read().await,
        *conn.max_write_size.read().await,
    );
    if len > limit {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("frame of {len} bytes exceeds the {limit}-byte limit"),
        ));
    }
    let mut payload = Vec::with_capacity(len.min(INITIAL_FRAME_BUFFER));
    reader.take(len as u64).read_to_end(&mut payload).await?;
    if payload.len() < len {
        return Err(io::ErrorKind::UnexpectedEof.into());
    }
    Ok(payload)
}

/// Initial payload buffer; larger frames grow it as their bytes arrive.
const INITIAL_FRAME_BUFFER: usize = 64 * 1024;

/// Whether any tree on the connection has an open file.
async fn has_open_files(conn: &Connection) -> bool {
    let sessions: Vec<_> = conn.sessions.read().await.values().cloned().collect();
    for session in sessions {
        let session = session.read().await;
        let trees: Vec<_> = session.trees.read().await.values().cloned().collect();
        for tree in trees {
            if !tree.read().await.opens.read().await.is_empty() {
                return true;
            }
        }
    }
    false
}

/// Read frames and dispatch them one at a time, in arrival order, sending
/// each response to the writer. Returns between frames once the server
/// shuts down; a frame that has started to arrive is still answered.
pub async fn reader_task(
    mut reader: ReadHalf<TcpStream>,
    server: Arc<ServerState>,
    conn: Arc<Connection>,
    tx: crate::conn::writer::ResponseQueue,
) -> io::Result<()> {
    let limits = &server.config.limits;
    // Until a session exists this is the handshake deadline; after that it
    // is the idle deadline.
    let mut deadline = Instant::now() + limits.handshake_timeout;
    let mut has_session = false;
    loop {
        let stopped = server.shutdown.notified();
        tokio::pin!(stopped);
        stopped.as_mut().enable();
        if server.shutting_down.load(Ordering::Acquire) {
            debug!("server shutting down; closing connection");
            return Ok(());
        }

        let mut prefix = [0u8; FRAME_HEADER_LEN];
        let filled = tokio::select! {
            biased;
            read = reader.read(&mut prefix) => read,
            _ = &mut stopped => {
                debug!("server shutting down; closing connection");
                return Ok(());
            }
            _ = tx.closed() => {
                debug!("writer closed; reader exiting");
                return Ok(());
            }
            _ = conn.outbound.killed() => {
                info!("client stopped reading lease breaks; closing connection");
                return Ok(());
            }
            _ = tokio::time::sleep_until(deadline) => {
                if !has_session {
                    info!("no session established in time; closing connection");
                    return Ok(());
                }
                if !has_open_files(&conn).await {
                    info!("closing idle connection");
                    return Ok(());
                }
                deadline = Instant::now() + limits.idle_timeout;
                continue;
            }
        };
        let frame = match filled {
            Ok(0) => {
                debug!("client closed connection");
                return Ok(());
            }
            Ok(filled) => {
                let rest = read_frame_rest(&mut reader, &conn, &mut prefix, filled);
                match tokio::time::timeout(limits.io_timeout, rest).await {
                    Ok(frame) => frame,
                    Err(_) => Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "frame not received in time",
                    )),
                }
            }
            Err(e) => Err(e),
        };
        let frame = match frame {
            Ok(frame) => frame,
            Err(e) => {
                error!(error = %e, "frame read error");
                return Err(e);
            }
        };
        let response = crate::dispatch::dispatch_frame(&server, &conn, &frame).await;
        if conn.disconnect_requested() {
            debug!("closing connection without a reply");
            return Ok(());
        }
        if let Some(out) = response {
            if tx.send(out.bytes).await.is_err() {
                debug!("writer channel closed; reader exiting");
                return Ok(());
            }
            // Lease breaks held back for these responses follow them.
            drop(out.after_send);
            // The interim response is queued, so the final one cannot pass
            // it.
            if let Some(continuation) = out.continuation {
                conn.pending
                    .spawn(continuation.run(Arc::clone(&server), Arc::clone(&conn)));
            }
        }
        has_session = has_session || !conn.sessions.read().await.is_empty();
        if has_session {
            deadline = Instant::now() + limits.idle_timeout;
        }
    }
}
