//! Durable handle contexts, and clients that sign in as a user.

use std::net::SocketAddr;
use std::time::Duration;

use smb_server::ntstatus::STATUS_SUCCESS;
use smb_server::wire::header::Command;
use smb_server::wire::messages::{CreateContext, CreateResponse, FileId, LeaseContext};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

use super::auth::{Login, LoginOptions, login_with};
use super::client::Client;
use super::{build_header, framed, message, negotiate_body_from, tree_connect, try_read_frame};

pub const SMB202: u16 = 0x0202;
pub const SMB21: u16 = 0x0210;
pub const SMB302: u16 = 0x0302;

/// A create context chain holding `list`.
pub fn contexts(list: &[CreateContext]) -> Vec<u8> {
    let mut chain = Vec::new();
    CreateContext::encode_chain(list, &mut chain).expect("encode");
    chain
}

fn context(name: &[u8; 4], data: Vec<u8>) -> CreateContext {
    CreateContext {
        name: name.to_vec(),
        data,
    }
}

/// SMB2_CREATE_REQUEST_LEASE for `key` and `state`.
pub fn lease_v1(key: [u8; 16], state: u32) -> CreateContext {
    let data = LeaseContext {
        key,
        state,
        ..LeaseContext::default()
    };
    context(CreateContext::NAME_RQLS, data.encode())
}

/// SMB2_CREATE_REQUEST_LEASE_V2 for `key` and `state`.
pub fn lease_v2(key: [u8; 16], state: u32) -> CreateContext {
    let data = LeaseContext {
        key,
        state,
        v2: true,
        ..LeaseContext::default()
    };
    context(CreateContext::NAME_RQLS, data.encode())
}

/// SMB2_CREATE_DURABLE_HANDLE_REQUEST.
pub fn dhnq() -> CreateContext {
    context(CreateContext::NAME_DHNQ, vec![0; 16])
}

/// SMB2_CREATE_DURABLE_HANDLE_RECONNECT for `file_id`.
pub fn dhnc(file_id: FileId) -> CreateContext {
    let mut data = file_id.persistent.to_le_bytes().to_vec();
    data.extend_from_slice(&file_id.volatile.to_le_bytes());
    context(CreateContext::NAME_DHNC, data)
}

/// SMB2_CREATE_DURABLE_HANDLE_REQUEST_V2.
pub fn dh2q(timeout_ms: u32, flags: u32, create_guid: [u8; 16]) -> CreateContext {
    let mut data = timeout_ms.to_le_bytes().to_vec();
    data.extend_from_slice(&flags.to_le_bytes());
    data.extend_from_slice(&[0; 8]);
    data.extend_from_slice(&create_guid);
    context(CreateContext::NAME_DH2Q, data)
}

/// SMB2_CREATE_DURABLE_HANDLE_RECONNECT_V2.
pub fn dh2c(file_id: FileId, create_guid: [u8; 16], flags: u32) -> CreateContext {
    let mut data = file_id.persistent.to_le_bytes().to_vec();
    data.extend_from_slice(&file_id.volatile.to_le_bytes());
    data.extend_from_slice(&create_guid);
    data.extend_from_slice(&flags.to_le_bytes());
    context(CreateContext::NAME_DH2C, data)
}

/// The data of the durable handle context in a CREATE response, if it has
/// one.
pub fn durable_reply(resp: &CreateResponse) -> Option<Vec<u8>> {
    CreateContext::parse_chain(&resp.create_contexts)
        .expect("response contexts")
        .into_iter()
        .find(|c| c.name == CreateContext::NAME_DHNQ || c.name == CreateContext::NAME_DH2Q)
        .map(|c| c.data)
}

/// A connection from `client_guid` that negotiated `dialect`. While the
/// server is at its connection limit it closes new connections at once;
/// this retries for up to two seconds, so it also waits for an earlier
/// connection to be torn down.
pub async fn negotiated(addr: SocketAddr, dialect: u16, client_guid: [u8; 16]) -> TcpStream {
    for _ in 0..200 {
        let mut s = TcpStream::connect(addr).await.expect("connect");
        let body = negotiate_body_from(&[dialect], 0x0001, 0, client_guid);
        let request = framed(&message(&build_header(Command::Negotiate, 0, 0, 0), &body));
        if s.write_all(&request).await.is_ok() && try_read_frame(&mut s).await.is_ok() {
            return s;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("the server took no connection");
}

/// Who signs in, from where, and what PreviousSessionId names.
#[derive(Clone, Copy)]
pub struct SignIn<'a> {
    pub dialect: u16,
    pub client_guid: [u8; 16],
    pub share: &'a str,
    pub user: &'a str,
    pub previous: u64,
}

impl Default for SignIn<'_> {
    fn default() -> Self {
        Self {
            dialect: SMB21,
            client_guid: [0xA1; 16],
            share: "share",
            user: "alice",
            previous: 0,
        }
    }
}

/// A client signed in as `who` says, with the password `password`.
pub async fn user_client(addr: SocketAddr, who: SignIn<'_>) -> Client {
    let mut s = negotiated(addr, who.dialect, who.client_guid).await;
    let opts = LoginOptions {
        previous_session_id: who.previous,
        ..LoginOptions::default()
    };
    let Login {
        status, session_id, ..
    } = login_with(&mut s, 1, 0, who.user, "password", opts).await;
    assert_eq!(status, STATUS_SUCCESS, "login as {}", who.user);
    let path = format!("\\\\127.0.0.1\\{}", who.share);
    let tree_id = tree_connect(&mut s, &path, session_id, 3).await;
    Client::from_parts(s, session_id, tree_id)
}

/// Drops the client's connection with a reset instead of a FIN.
pub fn reset(client: Client) {
    socket2::SockRef::from(&client.s)
        .set_linger(Some(Duration::ZERO))
        .expect("linger");
    drop(client);
}
