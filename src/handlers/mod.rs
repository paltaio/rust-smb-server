//! Per-command handlers.
//!
//! Each function here builds a `HandlerResponse` for a specific SMB2 command.
//! Handlers receive the parsed request header and a slice of the body bytes;
//! they return either a successful body or `HandlerResponse::err(ntstatus)`.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use crate::proto::header::{Command, Smb2Header};

use crate::conn::pending::AsyncOp;

use crate::conn::state::Connection;
use crate::dispatch::HandlerResponse;
use crate::ntstatus;
use crate::server::ServerState;

mod change_notify;
mod close;
mod create;
mod echo;
mod flush;
mod ioctl;
mod lock;
mod logoff;
pub(crate) mod negotiate;
mod oplock_break;
mod query_directory;
mod query_info;
mod read;
mod session_setup;
mod set_info;
pub(crate) mod shared;
mod tree_connect;
mod tree_disconnect;
mod write;

/// What a handler produced: a response, or a request that completes later.
pub(crate) enum Outcome {
    Done(HandlerResponse),
    Pending(Pending),
}

/// A request answered asynchronously (MS-SMB2 3.3.4.2): its registration
/// and the work that produces its final response. The work owns what it
/// needs, so it runs after the frame that carried the request is done.
pub(crate) struct Pending {
    pub op: Arc<AsyncOp>,
    pub work: Pin<Box<dyn Future<Output = HandlerResponse> + Send>>,
}

/// Top-level command router. `encrypted` tells whether the request arrived
/// encrypted; `retained` is the size of the request and the requests
/// compounded after it, which a request that goes asynchronous keeps until
/// it completes.
pub(crate) async fn dispatch_command(
    server: &Arc<ServerState>,
    conn: &Arc<Connection>,
    hdr: &Smb2Header,
    body: &[u8],
    encrypted: bool,
    retained: usize,
) -> Outcome {
    let response = match hdr.command {
        Command::Create => return create::handle(server, conn, hdr, body, retained).await,
        Command::SetInfo => return set_info::handle(server, conn, hdr, body, retained).await,
        Command::Negotiate => negotiate::handle(server, conn, hdr, body).await,
        Command::SessionSetup => session_setup::handle(server, conn, hdr, body).await,
        Command::Logoff => logoff::handle(server, conn, hdr, body).await,
        Command::TreeConnect => tree_connect::handle(server, conn, hdr, body, encrypted).await,
        Command::TreeDisconnect => tree_disconnect::handle(server, conn, hdr, body).await,
        Command::Close => close::handle(server, conn, hdr, body).await,
        Command::Flush => flush::handle(server, conn, hdr, body).await,
        Command::Read => read::handle(server, conn, hdr, body).await,
        Command::Write => write::handle(server, conn, hdr, body).await,
        Command::Lock => lock::handle(server, conn, hdr, body).await,
        Command::Ioctl => ioctl::handle(server, conn, hdr, body).await,
        Command::Echo => echo::handle(server, conn, hdr, body).await,
        Command::QueryDirectory => query_directory::handle(server, conn, hdr, body).await,
        Command::ChangeNotify => change_notify::handle(server, conn, hdr, body).await,
        Command::QueryInfo => query_info::handle(server, conn, hdr, body).await,
        Command::OplockBreak => oplock_break::handle(server, conn, hdr, body).await,
        Command::Cancel => HandlerResponse::err(ntstatus::STATUS_INVALID_PARAMETER),
    };
    Outcome::Done(response)
}
