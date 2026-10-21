//! Lease contexts, lease break notifications and acknowledgments.

use std::time::Duration;

use smb_server::wire::header::{Command, SMB2_FLAGS_SERVER_TO_REDIR, Smb2Header};
use smb_server::wire::messages::{
    CreateContext, CreateResponse, LeaseBreakAck, LeaseBreakNotification, LeaseContext,
};

use super::client::{Client, Create};

pub use smb_server::wire::messages::lease::{
    LEASE_HANDLE_CACHING, LEASE_READ_CACHING, LEASE_WRITE_CACHING,
};

pub const RWH: u32 = LEASE_READ_CACHING | LEASE_WRITE_CACHING | LEASE_HANDLE_CACHING;

/// SMB2_OPLOCK_LEVEL_LEASE.
pub const OPLOCK_LEVEL_LEASE: u8 = 0xFF;

/// A create context chain holding one `RqLs` context with `data`.
pub fn rqls(data: Vec<u8>) -> Vec<u8> {
    let mut chain = Vec::new();
    CreateContext::encode_chain(
        &[CreateContext {
            name: CreateContext::NAME_RQLS.to_vec(),
            data,
        }],
        &mut chain,
    )
    .expect("encode");
    chain
}

/// SMB2_CREATE_REQUEST_LEASE for `key` and `state`.
pub fn rqls_v1(key: [u8; 16], state: u32) -> Vec<u8> {
    rqls(
        LeaseContext {
            key,
            state,
            ..LeaseContext::default()
        }
        .encode(),
    )
}

/// SMB2_CREATE_REQUEST_LEASE_V2 for `key` and `state`.
pub fn rqls_v2(key: [u8; 16], state: u32, parent: Option<[u8; 16]>, epoch: u16) -> Vec<u8> {
    rqls(
        LeaseContext {
            key,
            state,
            flags: if parent.is_some() {
                LeaseContext::FLAG_PARENT_LEASE_KEY_SET
            } else {
                0
            },
            parent_key: parent.unwrap_or_default(),
            epoch,
            v2: true,
        }
        .encode(),
    )
}

/// A CREATE of `name` that asks for the lease in `contexts`.
pub fn leased(name: &str, contexts: Vec<u8>) -> Create<'_> {
    Create {
        name,
        oplock: OPLOCK_LEVEL_LEASE,
        contexts,
        ..Create::default()
    }
}

/// The data of the lease context in a CREATE response, if it has one.
pub fn lease_data(resp: &CreateResponse) -> Option<Vec<u8>> {
    CreateContext::parse_chain(&resp.create_contexts)
        .expect("response contexts")
        .into_iter()
        .find(|c| c.name == CreateContext::NAME_RQLS)
        .map(|c| c.data)
}

/// The lease a CREATE response grants, if it has one.
pub fn lease_reply(resp: &CreateResponse) -> Option<LeaseContext> {
    lease_data(resp).map(|data| LeaseContext::parse(&data).expect("lease context"))
}

/// Whether `frame` is a lease or oplock break notification.
pub fn is_break(frame: &[u8]) -> bool {
    Smb2Header::parse(frame)
        .is_ok_and(|(h, _)| h.command == Command::OplockBreak && h.message_id == u64::MAX)
}

/// The header and notification of a lease break frame.
pub fn parse_break(frame: &[u8]) -> (Smb2Header, LeaseBreakNotification) {
    let (hdr, body) = Smb2Header::parse(frame).expect("break header");
    assert!(is_break(frame), "not a break notification");
    (
        hdr,
        LeaseBreakNotification::parse(body).expect("break body"),
    )
}

/// LEASE_BREAK acknowledgment body for `key` and `state`.
pub fn lease_ack_body(key: [u8; 16], state: u32) -> Vec<u8> {
    let mut body = Vec::new();
    LeaseBreakAck {
        structure_size: 36,
        reserved: 0,
        flags: 0,
        lease_key: key,
        lease_state: state,
        lease_duration: 0,
    }
    .write_to(&mut body)
    .expect("lease ack");
    body
}

impl Client {
    /// The next lease break for this client, waiting up to `within`.
    pub async fn next_break(&mut self, within: Duration) -> Option<LeaseBreakNotification> {
        let frame = tokio::time::timeout(within, self.read_break()).await.ok()?;
        let (hdr, notification) = parse_break(&frame);
        assert_eq!(hdr.flags, SMB2_FLAGS_SERVER_TO_REDIR);
        assert_eq!(hdr.credit_charge, 0);
        assert_eq!(hdr.channel_sequence_status, 0);
        assert_eq!(hdr.next_command, 0);
        assert_eq!(hdr.session_id, 0);
        assert_eq!(hdr.tree_id(), Some(0));
        assert_eq!(hdr.credit_request_response, 0);
        assert_eq!(hdr.signature, [0; 16]);
        Some(notification)
    }

    /// Waits for every message already queued for this client, then
    /// returns the lease breaks among them.
    pub async fn drain_breaks(&mut self) -> Vec<LeaseBreakNotification> {
        let (status, _) = self.send(Command::Echo, &[4, 0, 0, 0]).await;
        assert_eq!(status, 0, "ECHO");
        self.breaks
            .drain(..)
            .map(|frame| parse_break(&frame).1)
            .collect()
    }

    /// Acknowledges a lease break; returns the status.
    pub async fn ack(&mut self, key: [u8; 16], state: u32) -> u32 {
        self.send(Command::OplockBreak, &lease_ack_body(key, state))
            .await
            .0
    }
}
