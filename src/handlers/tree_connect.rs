//! TREE_CONNECT handler: share lookup and authorization.

use std::sync::Arc;

use crate::proto::header::{SMB2_FLAGS_SIGNED, Smb2Header};
use crate::proto::messages::{Dialect, TreeConnectRequest, TreeConnectResponse};
use tracing::{info, warn};

use crate::access_mask::maximal_access;
use crate::builder::Access;
use crate::conn::state::{Connection, TreeConnect};
use crate::dispatch::HandlerResponse;
use crate::handlers::shared::lookup_session;
use crate::ntstatus;
use crate::server::{Caller, ServerState};
use crate::utils::utf16le_to_units;

const SHARE_TYPE_DISK: u8 = 0x01;
const SHARE_TYPE_PIPE: u8 = 0x02;
const SHAREFLAG_ENCRYPT_DATA: u32 = 0x0000_8000;

pub async fn handle(
    server: &Arc<ServerState>,
    conn: &Arc<Connection>,
    hdr: &Smb2Header,
    body: &[u8],
    encrypted: bool,
) -> HandlerResponse {
    let sess_arc = match lookup_session(conn, hdr.session_id).await {
        Ok(s) => s,
        Err(s) => return HandlerResponse::err(s),
    };
    let sess = sess_arc.read().await;
    let caller = Caller::of(&sess);
    let anonymous = sess.is_anonymous();
    drop(sess);

    // MS-SMB2 3.3.5.7: on 3.1.1 an authenticated session's TREE_CONNECT
    // must be signed or encrypted, or the connection is dropped.
    if *conn.dialect.read().await == Some(Dialect::Smb311)
        && !anonymous
        && !encrypted
        && hdr.flags & SMB2_FLAGS_SIGNED == 0
    {
        warn!("unsigned SMB 3.1.1 TREE_CONNECT; closing the connection");
        conn.request_disconnect();
        return HandlerResponse::err(ntstatus::STATUS_ACCESS_DENIED);
    }

    let req = match TreeConnectRequest::parse(body) {
        Ok(r) => r,
        Err(_) => return HandlerResponse::err(ntstatus::STATUS_INVALID_PARAMETER),
    };
    let Some(path) = req
        .path_in(body)
        .and_then(utf16le_to_units)
        .map(|units| String::from_utf16_lossy(&units))
    else {
        return HandlerResponse::err(ntstatus::STATUS_INVALID_PARAMETER);
    };
    tracing::debug!(?path, "tree connect path");
    let Some(share_name) = share_name(&path) else {
        warn!(?path, "tree connect path is not \\\\server\\share");
        return HandlerResponse::err(ntstatus::STATUS_INVALID_PARAMETER);
    };

    // IPC$: synthetic share, whose opens are named pipes.
    let is_ipc = share_name.eq_ignore_ascii_case("IPC$");
    let share = if is_ipc {
        crate::server::ShareBindings::ipc()
    } else {
        match server.find_share(share_name).await {
            Some(s) => s,
            None => return HandlerResponse::err(ntstatus::STATUS_BAD_NETWORK_NAME),
        }
    };
    // The share and its ACL are checked with the session's tree table
    // locked. ConfigHandle changes them first and then sweeps the trees,
    // and the sweep waits for this lock, so a tree inserted here is either
    // authorized by the new configuration or removed by the sweep.
    let sess = sess_arc.read().await;
    let mut trees = sess.trees.write().await;
    if trees.len() >= server.auth.settings.max_trees_per_session {
        warn!(trees = trees.len(), "tree connect limit reached on session");
        return HandlerResponse::err(ntstatus::STATUS_INSUFFICIENT_RESOURCES);
    }
    if !is_ipc
        && !server
            .find_share(share_name)
            .await
            .is_some_and(|current| Arc::ptr_eq(&current, &share))
    {
        return HandlerResponse::err(ntstatus::STATUS_BAD_NETWORK_NAME);
    }
    let acl = share.acl.read().await;
    let granted = match server.admits(&share, &acl, &caller) {
        Some(a) => a,
        None => {
            warn!(identity = ?caller.identity, share = %share.name, "TREE_CONNECT denied");
            return HandlerResponse::err(ntstatus::STATUS_ACCESS_DENIED);
        }
    };
    drop(acl);
    // Backend cap.
    let granted = if share.backend.capabilities().is_read_only {
        granted.clamp_to(Access::Read)
    } else {
        granted
    };

    let tc = TreeConnect::new(sess.alloc_tree_id(), share.clone(), granted);
    let tree_id = tc.id;
    trees.insert(tree_id, Arc::new(tokio::sync::RwLock::new(tc)));
    drop(trees);
    drop(sess);

    let maximal_access = maximal_access(granted);
    let resp = TreeConnectResponse {
        structure_size: 16,
        share_type: if share.is_ipc {
            SHARE_TYPE_PIPE
        } else {
            SHARE_TYPE_DISK
        },
        reserved: 0,
        share_flags: if share.encrypt_data && caller.can_encrypt {
            SHAREFLAG_ENCRYPT_DATA
        } else {
            0
        },
        capabilities: 0,
        maximal_access,
    };
    let mut buf = Vec::new();
    resp.write_to(&mut buf).expect("encode");
    info!(tree_id, share = %share.name, ?granted, "tree connect");
    let mut hr = HandlerResponse::ok(buf);
    hr.override_tree_id = Some(tree_id);
    hr
}

/// The share component of a `\\server\share` path (MS-SMB2 2.2.9), or
/// `None` when the path has another form: the server part is 1 to 255
/// characters, and the share part 1 to 80 characters with none of the
/// characters MS-FSCC 2.1.6 forbids in share names.
fn share_name(unc: &str) -> Option<&str> {
    let rest = unc.strip_prefix(r"\\")?;
    let (server, share) = rest.split_once('\\')?;
    let server_len = server.chars().count();
    let share_len = share.chars().count();
    if !(1..256).contains(&server_len) || !(1..=80).contains(&share_len) {
        return None;
    }
    const INVALID: &[char] = &[
        '"', '\\', '/', '[', ']', ':', '|', '<', '>', '+', '=', ';', ',', '*', '?',
    ];
    if share.chars().any(|c| c < ' ' || INVALID.contains(&c)) {
        return None;
    }
    Some(share)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::conn::state::Session;
    use crate::proto::auth::ntlm::Identity;
    use crate::proto::header::{Command, HeaderTail};
    use tokio::sync::RwLock;

    fn alice() -> Identity {
        Identity::User {
            user: "alice".to_string(),
            domain: String::new(),
        }
    }

    async fn connection(
        dialect: Dialect,
        identity: Identity,
    ) -> (Arc<ServerState>, Arc<Connection>) {
        let server = crate::SmbServer::builder()
            .listen("127.0.0.1:0".parse().unwrap())
            .user("alice", "password")
            .share(crate::Share::new("home", crate::tests::memfs::MemFsBackend::new()).public())
            .build()
            .expect("build")
            .state();
        let conn = Arc::new(Connection::new(server.config.server_guid, 65536, 65536));
        *conn.dialect.write().await = Some(dialect);
        let session = Session::new(identity, [0; 16], [0; 16], false, None);
        conn.sessions
            .write()
            .await
            .insert(7, Arc::new(RwLock::new(session)));
        (server, conn)
    }

    fn request(path: &str, flags: u32) -> (Smb2Header, Vec<u8>) {
        let hdr = Smb2Header {
            credit_charge: 1,
            channel_sequence_status: 0,
            command: Command::TreeConnect,
            credit_request_response: 1,
            flags,
            next_command: 0,
            message_id: 5,
            tail: HeaderTail::sync(0),
            session_id: 7,
            signature: [0; 16],
        };
        let path: Vec<u8> = path.encode_utf16().flat_map(u16::to_le_bytes).collect();
        let mut body = Vec::new();
        TreeConnectRequest {
            structure_size: 9,
            flags: 0,
            path_offset: 64 + 8,
            path_length: path.len() as u16,
            path,
        }
        .write_to(&mut body)
        .unwrap();
        (hdr, body)
    }

    #[tokio::test]
    async fn unsigned_smb311_tree_connect_requests_a_disconnect() {
        let (server, conn) = connection(Dialect::Smb311, alice()).await;
        let (hdr, body) = request(r"\\srv\home", 0);
        let resp = handle(&server, &conn, &hdr, &body, false).await;
        assert_ne!(resp.status, ntstatus::STATUS_SUCCESS);
        assert!(conn.disconnect_requested());

        // Signed, anonymous, or an older dialect: no disconnect.
        let (server, conn) = connection(Dialect::Smb311, alice()).await;
        let (hdr, body) = request(r"\\srv\home", SMB2_FLAGS_SIGNED);
        assert_eq!(handle(&server, &conn, &hdr, &body, false).await.status, 0);
        let (server, conn) = connection(Dialect::Smb311, Identity::Anonymous).await;
        let (hdr, body) = request(r"\\srv\home", 0);
        assert_eq!(handle(&server, &conn, &hdr, &body, false).await.status, 0);
        let (server, conn) = connection(Dialect::Smb302, alice()).await;
        let (hdr, body) = request(r"\\srv\home", 0);
        assert_eq!(handle(&server, &conn, &hdr, &body, false).await.status, 0);
        assert!(!conn.disconnect_requested());
    }

    #[test]
    fn share_name_needs_the_server_share_form() {
        assert_eq!(share_name(r"\\srv\home"), Some("home"));
        assert_eq!(share_name(r"\\10.0.0.1\IPC$"), Some("IPC$"));
        let long_share = format!(r"\\srv\{}", "x".repeat(81));
        let long_server = format!(r"\\{}\home", "s".repeat(256));
        for bad in [
            "home",
            r"\home",
            r"\\srv",
            r"\\\home",
            r"\\srv\",
            r"\\srv\a\b",
            r"\\srv\a:b",
            r"\\srv\a*",
            "//srv/home",
            "\\\\srv\\a\u{1}",
            &long_share,
            &long_server,
        ] {
            assert!(share_name(bad).is_none(), "{bad:?}");
        }
    }

    /// A TREE_CONNECT that read the share before `remove_share` and
    /// inserts after it does not leave a tree on the removed share.
    #[tokio::test]
    async fn tree_connect_racing_remove_share_leaves_no_tree() {
        let server = crate::SmbServer::builder()
            .listen("127.0.0.1:0".parse().unwrap())
            .share(crate::Share::new("home", crate::tests::memfs::MemFsBackend::new()).public())
            .build()
            .expect("build");
        let state = server.state();
        let config = server.config_handle();
        let conn = Arc::new(Connection::new(state.config.server_guid, 65536, 65536));
        state.active_connections.register(&conn).await;
        *conn.dialect.write().await = Some(Dialect::Smb302);
        let session = Arc::new(RwLock::new(Session::new(
            Identity::Anonymous,
            [0; 16],
            [0; 16],
            false,
            None,
        )));
        conn.sessions.write().await.insert(7, session.clone());

        // Hold the ACL so the TREE_CONNECT stops after its share lookup.
        let share = state.find_share("home").await.unwrap();
        let acl = share.acl.write().await;
        let (hdr, body) = request(r"\\srv\home", 0);
        let tc = tokio::spawn({
            let (state, conn) = (state.clone(), conn.clone());
            async move { handle(&state, &conn, &hdr, &body, false).await.status }
        });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let remove = tokio::spawn(async move { config.remove_share("home").await });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        drop(acl);
        tc.await.unwrap();
        remove.await.unwrap().unwrap();

        assert!(session.read().await.trees.read().await.is_empty());
    }

    #[tokio::test]
    async fn trees_per_session_are_capped() {
        let (server, conn) = connection(Dialect::Smb302, alice()).await;
        let max = server.auth.settings.max_trees_per_session;
        let (hdr, body) = request(r"\\srv\home", 0);
        for _ in 0..max {
            assert_eq!(handle(&server, &conn, &hdr, &body, false).await.status, 0);
        }
        assert_eq!(
            handle(&server, &conn, &hdr, &body, false).await.status,
            ntstatus::STATUS_INSUFFICIENT_RESOURCES
        );
    }
}
