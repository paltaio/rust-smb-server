//! The server end of a DCE/RPC association on one pipe (C706 chapter 12,
//! MS-RPCE 3.3.3): binds, presentation contexts, request reassembly and
//! response fragmentation. Binds that carry authentication are refused.
//!
//! A protocol error ends the association: the client is sent a bind_nak
//! before the bind and a fault after it, and nothing more is read.

use tracing::debug;

use super::pdu::{
    self, Body, ContextElem, ContextResult, FAULT_ACCESS_DENIED, Header, MAX_FRAG, NCA_PROTO_ERROR,
    NCA_SERVER_TOO_BUSY, NCA_UNK_IF, NDR, PFC_DID_NOT_EXECUTE, PFC_FIRST_FRAG, PFC_LAST_FRAG,
    PTYPE_ALTER_CONTEXT, PTYPE_ALTER_CONTEXT_RESP, PTYPE_BIND, PTYPE_BIND_ACK, RESPONSE_HEADER_LEN,
    Request, SRVSVC, SyntaxId,
};

/// Largest request stub one call may reassemble.
const MAX_REQUEST_STUB: usize = 64 << 10;

/// Presentation contexts one association may bind.
const MAX_CONTEXTS: usize = 8;

/// Smallest fragment size the server negotiates.
const MIN_FRAG: u16 = 2048;

/// How far behind the highest call_id seen a stray request fragment may be
/// and still be dropped quietly (MS-RPCE 3.3.3.5.6).
const OLD_CALL_WINDOW: u32 = 150;

/// The secondary address of a bind_ack (MS-RPCE 3.3.1.5.5).
const SECONDARY_ADDRESS: &str = "\\PIPE\\srvsvc";

/// Bind time features the server supports: KeepConnectionOnOrphan
/// (MS-RPCE 2.2.2.14). Orphaned PDUs never end the association.
const SUPPORTED_FEATURES: u64 = 0x0002;

// bind_nak reasons (C706 12.6.3.1, MS-RPCE 2.2.2.5).
const NAK_NOT_SPECIFIED: u16 = 0;
const NAK_LOCAL_LIMIT_EXCEEDED: u16 = 2;
const NAK_PROTOCOL_VERSION_NOT_SUPPORTED: u16 = 4;
const NAK_AUTHENTICATION_TYPE_NOT_RECOGNIZED: u16 = 8;

// Presentation context results and reasons (C706 12.6.3.1, MS-RPCE 2.2.2.4).
const ACCEPTANCE: u16 = 0;
const PROVIDER_REJECTION: u16 = 2;
const NEGOTIATE_ACK: u16 = 3;
const ABSTRACT_SYNTAX_NOT_SUPPORTED: u16 = 1;
const TRANSFER_SYNTAXES_NOT_SUPPORTED: u16 = 2;

const FIRST_AND_LAST: u8 = PFC_FIRST_FRAG | PFC_LAST_FRAG;

/// A complete request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Call {
    pub call_id: u32,
    pub context_id: u16,
    pub opnum: u16,
    pub stub: Vec<u8>,
}

/// How a call failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Fault {
    pub status: u32,
    /// The call failed before the operation ran.
    pub did_not_execute: bool,
}

/// What a PDU the association received asks for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Step {
    /// Send this PDU to the client.
    Send(Vec<u8>),
    /// Run this call and send its [`Association::reply`].
    Call(Call),
}

pub(crate) struct Association {
    bound: bool,
    closed: bool,
    /// Largest fragment either side sends, once bound.
    max_frag: u16,
    assoc_group_id: u32,
    /// Bound presentation context ids, all on srvsvc over NDR.
    contexts: Vec<u16>,
    /// The request being reassembled.
    partial: Option<Call>,
    /// The highest call_id received (MS-RPCE 3.3.3.1.1, Current call_id).
    current_call_id: u32,
    /// The start of a PDU whose last bytes have not arrived.
    inbox: Vec<u8>,
}

impl Default for Association {
    fn default() -> Self {
        Self {
            bound: false,
            closed: false,
            max_frag: MIN_FRAG,
            assoc_group_id: 0,
            contexts: Vec::new(),
            partial: None,
            current_call_id: 0,
            inbox: Vec::new(),
        }
    }
}

impl Association {
    /// Whether the association has ended.
    pub(crate) fn is_closed(&self) -> bool {
        self.closed
    }

    /// Bytes kept for a PDU or a request that is not whole yet.
    pub(crate) fn held(&self) -> usize {
        self.inbox.capacity() + self.partial.as_ref().map_or(0, |call| call.stub.capacity())
    }

    /// Takes bytes written to the pipe from the front of `data` until a
    /// complete PDU asks for something, and returns that; `None` once
    /// `data` is used up. PDUs are cut by their frag_length, so one may
    /// span writes and a write may hold several. A frag_length below 16,
    /// or above [`MAX_FRAG`] for anything but a bind or alter_context, is a
    /// protocol error. Once the association is closed, bytes are dropped.
    pub(crate) fn next_step(&mut self, data: &mut &[u8]) -> Option<Step> {
        while !self.closed && !data.is_empty() {
            if self.inbox.len() < pdu::HEADER_LEN {
                let take = (pdu::HEADER_LEN - self.inbox.len()).min(data.len());
                self.inbox.extend_from_slice(&data[..take]);
                *data = &data[take..];
                if self.inbox.len() < pdu::HEADER_LEN {
                    break;
                }
            }
            let header = Header::read(&self.inbox).expect("a whole header");
            // A bind or alter_context may carry a large auth token, so it
            // is read whole and refused for its authentication.
            let large = matches!(header.ptype, PTYPE_BIND | PTYPE_ALTER_CONTEXT);
            let frag = usize::from(header.frag_length);
            if frag < pdu::HEADER_LEN || (!large && header.frag_length > MAX_FRAG) {
                debug!(frag, "rpc fragment length out of range");
                return Some(self.protocol_error(header.call_id));
            }
            let take = (frag - self.inbox.len()).min(data.len());
            // Exact, so what is held stays within the largest PDU.
            self.inbox.reserve_exact(frag - self.inbox.len());
            self.inbox.extend_from_slice(&data[..take]);
            *data = &data[take..];
            if self.inbox.len() < frag {
                break;
            }
            let pdu = std::mem::take(&mut self.inbox);
            let step = self.receive_pdu(&pdu);
            self.inbox = pdu;
            self.inbox.clear();
            if step.is_some() {
                if self.closed {
                    self.inbox = Vec::new();
                }
                return step;
            }
        }
        if self.closed {
            self.inbox = Vec::new();
        }
        None
    }

    /// Ends the association instead of answering the request `call_id`,
    /// with a fault that reports the server too busy. The caller drops the
    /// bytes not taken yet.
    pub(crate) fn abort(&mut self, call_id: u32) -> Vec<u8> {
        debug!(call_id, "rpc association ended for lack of room");
        self.closed = true;
        self.partial = None;
        self.inbox = Vec::new();
        pdu::fault(
            call_id,
            FIRST_AND_LAST | PFC_DID_NOT_EXECUTE,
            0,
            NCA_SERVER_TOO_BUSY,
        )
    }

    /// The fragments that answer `call` with `result`: the response stub
    /// cut to the negotiated fragment size, or a fault.
    pub(crate) fn reply(&self, call: &Call, result: Result<Vec<u8>, Fault>) -> Vec<Vec<u8>> {
        let stub = match result {
            Ok(stub) => stub,
            Err(fault) => {
                debug!(call_id = call.call_id, status = fault.status, "rpc fault");
                let flags = if fault.did_not_execute {
                    FIRST_AND_LAST | PFC_DID_NOT_EXECUTE
                } else {
                    FIRST_AND_LAST
                };
                return vec![pdu::fault(
                    call.call_id,
                    flags,
                    call.context_id,
                    fault.status,
                )];
            }
        };
        // Every fragment but the last carries a multiple of 16 stub bytes.
        let chunk = (usize::from(self.max_frag) - RESPONSE_HEADER_LEN) & !15;
        let mut fragments = Vec::new();
        let mut rest = stub.as_slice();
        loop {
            let len = rest.len().min(chunk);
            let mut flags = 0;
            if fragments.is_empty() {
                flags |= PFC_FIRST_FRAG;
            }
            if len == rest.len() {
                flags |= PFC_LAST_FRAG;
            }
            let alloc_hint = u32::try_from(rest.len()).unwrap_or(u32::MAX);
            fragments.push(pdu::response(
                call.call_id,
                flags,
                alloc_hint,
                call.context_id,
                &rest[..len],
            ));
            rest = &rest[len..];
            if rest.is_empty() {
                return fragments;
            }
        }
    }

    fn receive_pdu(&mut self, bytes: &[u8]) -> Option<Step> {
        let Some(pdu) = pdu::parse(bytes) else {
            let call_id = Header::read(bytes).map_or(0, |h| h.call_id);
            debug!(call_id, "malformed rpc pdu");
            return Some(self.protocol_error(call_id));
        };
        let header = pdu.header;
        let step = self.dispatch(&header, pdu.body);
        self.current_call_id = self.current_call_id.max(header.call_id);
        step
    }

    fn dispatch(&mut self, header: &Header, body: Body<'_>) -> Option<Step> {
        if !self.bound {
            return Some(match body {
                Body::Bind(bind) => self.bind(header, bind),
                _ => {
                    debug!(ptype = header.ptype, "rpc pdu before bind");
                    self.close(pdu::bind_nak(
                        header.call_id,
                        NAK_PROTOCOL_VERSION_NOT_SUPPORTED,
                    ))
                }
            });
        }
        match body {
            Body::Bind(_) => {
                debug!("second rpc bind");
                Some(self.close(pdu::bind_nak(header.call_id, NAK_NOT_SPECIFIED)))
            }
            Body::AlterContext(bind) => Some(self.alter_context(header, &bind.contexts)),
            Body::Request(request) => self.request(header, &request),
            Body::CoCancel => None,
            // An orphaned PDU aborts the request it names (C706 12.6.4.8).
            Body::Orphaned => {
                if self
                    .partial
                    .as_ref()
                    .is_some_and(|call| call.call_id == header.call_id)
                {
                    self.partial = None;
                }
                None
            }
            Body::Unexpected(ptype) => {
                debug!(ptype, "unexpected rpc pdu");
                Some(self.protocol_error(header.call_id))
            }
        }
    }

    /// C706 12.6.4.3. The fragment size is the smaller of the two the
    /// client offers, kept between 2048 and [`MAX_FRAG`] and cut to a
    /// multiple of 8.
    fn bind(&mut self, header: &Header, bind: pdu::Bind) -> Step {
        let nak = |reason| pdu::bind_nak(header.call_id, reason);
        if bind.contexts.is_empty() {
            return self.close(nak(NAK_PROTOCOL_VERSION_NOT_SUPPORTED));
        }
        if bind.contexts.iter().any(|c| c.transfer_syntaxes.is_empty()) {
            return self.close(nak(NAK_NOT_SPECIFIED));
        }
        let feature_elements = bind
            .contexts
            .iter()
            .filter(|c| c.transfer_syntaxes[0].features().is_some())
            .count();
        if feature_elements > 1 {
            return self.close(nak(NAK_NOT_SPECIFIED));
        }
        // MS-RPCE 3.3.3.5.3: the server knows no authentication provider.
        if header.auth_length > 0 {
            debug!("authenticated rpc bind refused");
            return self.close(nak(NAK_AUTHENTICATION_TYPE_NOT_RECOGNIZED));
        }
        let Some(results) = self.negotiate(&bind.contexts, true) else {
            debug!("rpc bind past the context limit");
            return self.close(nak(NAK_LOCAL_LIMIT_EXCEEDED));
        };
        self.max_frag = bind
            .max_xmit_frag
            .min(bind.max_recv_frag)
            .clamp(MIN_FRAG, MAX_FRAG)
            & 0xFFF8;
        self.assoc_group_id = match bind.assoc_group_id {
            0 => super::new_assoc_group(),
            id => id,
        };
        self.bound = true;
        debug!(
            max_frag = self.max_frag,
            assoc_group = self.assoc_group_id,
            contexts = ?self.contexts,
            "rpc bind"
        );
        Step::Send(pdu::bind_ack(
            PTYPE_BIND_ACK,
            header.call_id,
            self.max_frag,
            self.assoc_group_id,
            SECONDARY_ADDRESS,
            &results,
        ))
    }

    /// C706 12.6.4.1: more presentation contexts on the association.
    /// Feature negotiation belongs to the bind, so a feature element here
    /// is a transfer syntax the server does not support. Errors, including
    /// a context past the limit, are protocol errors: C706 defines no
    /// rejection for an alter_context.
    fn alter_context(&mut self, header: &Header, contexts: &[ContextElem]) -> Step {
        if header.auth_length > 0
            || contexts.is_empty()
            || contexts.iter().any(|c| c.transfer_syntaxes.is_empty())
        {
            return self.protocol_error(header.call_id);
        }
        let Some(results) = self.negotiate(contexts, false) else {
            debug!("rpc alter_context past the context limit");
            return self.protocol_error(header.call_id);
        };
        Step::Send(pdu::bind_ack(
            PTYPE_ALTER_CONTEXT_RESP,
            header.call_id,
            self.max_frag,
            self.assoc_group_id,
            "",
            &results,
        ))
    }

    /// One result per element, in order (MS-RPCE 3.3.1.5.3, 3.3.1.5.6).
    /// srvsvc over NDR 2.0 is accepted; NDR64 and every other interface are
    /// rejected. `None`, binding nothing, when the elements would take the
    /// association past [`MAX_CONTEXTS`] (MS-RPCE 3.3.3.5.5).
    fn negotiate(
        &mut self,
        contexts: &[ContextElem],
        features: bool,
    ) -> Option<Vec<ContextResult>> {
        let reject = |reason| ContextResult {
            result: PROVIDER_REJECTION,
            reason,
            transfer_syntax: SyntaxId::default(),
        };
        let mut added = Vec::new();
        let results = contexts
            .iter()
            .map(|c| {
                if features && let Some(bits) = c.transfer_syntaxes[0].features() {
                    // Only bits the server supports are echoed (MS-RPCE
                    // 2.2.2.15); SecurityContextMultiplexing is not one.
                    let bits = u16::try_from(bits & SUPPORTED_FEATURES).expect("16 bits");
                    return ContextResult {
                        result: NEGOTIATE_ACK,
                        reason: bits,
                        transfer_syntax: SyntaxId::default(),
                    };
                }
                if c.abstract_syntax != SRVSVC {
                    return reject(ABSTRACT_SYNTAX_NOT_SUPPORTED);
                }
                if !c.transfer_syntaxes.contains(&NDR) {
                    return reject(TRANSFER_SYNTAXES_NOT_SUPPORTED);
                }
                if !self.contexts.contains(&c.id) && !added.contains(&c.id) {
                    added.push(c.id);
                }
                ContextResult {
                    result: ACCEPTANCE,
                    reason: 0,
                    transfer_syntax: NDR,
                }
            })
            .collect();
        if self.contexts.len() + added.len() > MAX_CONTEXTS {
            return None;
        }
        self.contexts.extend(added);
        Some(results)
    }

    /// C706 12.6.4.9, MS-RPCE 3.3.3.5.2. Fragments of one call share its
    /// call_id; its context and opnum come from the first.
    fn request(&mut self, header: &Header, request: &Request<'_>) -> Option<Step> {
        if header.auth_length > 0 {
            return Some(self.protocol_error(header.call_id));
        }
        let first = header.flags & PFC_FIRST_FRAG != 0;
        let mut call = match (self.partial.take(), first) {
            (None, true) => Call {
                call_id: header.call_id,
                context_id: request.context_id,
                opnum: request.opnum,
                stub: Vec::new(),
            },
            (Some(call), false) if call.call_id == header.call_id => call,
            (Some(call), _) => {
                debug!(call_id = call.call_id, "rpc fragment out of sequence");
                return Some(self.protocol_error(call.call_id));
            }
            // MS-RPCE 3.3.3.5.6: the rest of a call that was orphaned, or
            // otherwise ended, is dropped while its call_id is recent.
            (None, false)
                if self.current_call_id.wrapping_sub(header.call_id) < OLD_CALL_WINDOW =>
            {
                return None;
            }
            (None, false) => {
                debug!(call_id = header.call_id, "rpc fragment without a first");
                return Some(self.protocol_error(header.call_id));
            }
        };
        if call.stub.len() + request.stub.len() > MAX_REQUEST_STUB {
            debug!(call_id = call.call_id, "rpc request too large");
            let fault = pdu::fault(
                call.call_id,
                FIRST_AND_LAST | PFC_DID_NOT_EXECUTE,
                call.context_id,
                FAULT_ACCESS_DENIED,
            );
            return Some(self.close(fault));
        }
        call.stub.reserve_exact(request.stub.len());
        call.stub.extend_from_slice(request.stub);
        if header.flags & PFC_LAST_FRAG == 0 {
            self.partial = Some(call);
            return None;
        }
        if !self.contexts.contains(&call.context_id) {
            debug!(
                context = call.context_id,
                "rpc request on an unbound context"
            );
            return Some(Step::Send(pdu::fault(
                call.call_id,
                FIRST_AND_LAST | PFC_DID_NOT_EXECUTE,
                0,
                NCA_UNK_IF,
            )));
        }
        Some(Step::Call(call))
    }

    /// Ends the association: a bind_nak before the bind, a fault after it
    /// (MS-RPCE 3.3.3.5.7).
    fn protocol_error(&mut self, call_id: u32) -> Step {
        let pdu = if self.bound {
            pdu::fault(
                call_id,
                FIRST_AND_LAST | PFC_DID_NOT_EXECUTE,
                0,
                NCA_PROTO_ERROR,
            )
        } else {
            pdu::bind_nak(call_id, NAK_PROTOCOL_VERSION_NOT_SUPPORTED)
        };
        self.close(pdu)
    }

    /// Sends `pdu` and ends the association.
    fn close(&mut self, pdu: Vec<u8>) -> Step {
        self.closed = true;
        self.partial = None;
        Step::Send(pdu)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rpc::pdu::tests::{BIND_3CTX, NDR64, unhex};
    use crate::rpc::pdu::{
        NCA_OP_RNG_ERROR, NCA_SERVER_TOO_BUSY, PTYPE_ALTER_CONTEXT, PTYPE_BIND, PTYPE_BIND_NAK,
        PTYPE_CO_CANCEL, PTYPE_FAULT, PTYPE_ORPHANED, PTYPE_REQUEST, PTYPE_RESPONSE,
    };

    impl Association {
        /// Every step the PDUs in `data` ask for.
        fn receive(&mut self, mut data: &[u8]) -> Vec<Step> {
            std::iter::from_fn(|| self.next_step(&mut data)).collect()
        }
    }

    const OTHER: SyntaxId = SyntaxId {
        uuid: [0x77; 16],
        version: 1,
    };

    fn features(bits: u64) -> SyntaxId {
        let mut uuid = [0; 16];
        uuid[..8].copy_from_slice(&[0x2c, 0x1c, 0xb7, 0x6c, 0x12, 0x98, 0x40, 0x45]);
        uuid[8..].copy_from_slice(&bits.to_le_bytes());
        SyntaxId { uuid, version: 1 }
    }

    fn header(ptype: u8, flags: u8, call_id: u32) -> Vec<u8> {
        let mut out = vec![5, 0, ptype, flags, 0x10, 0, 0, 0, 0, 0, 0, 0];
        out.extend_from_slice(&call_id.to_le_bytes());
        out
    }

    fn finish(mut pdu: Vec<u8>) -> Vec<u8> {
        let len = pdu.len() as u16;
        pdu[8..10].copy_from_slice(&len.to_le_bytes());
        pdu
    }

    /// A bind (or alter_context) with `contexts`, each an id, an abstract
    /// syntax and its transfer syntaxes.
    fn bind_pdu(
        ptype: u8,
        call_id: u32,
        frags: (u16, u16),
        group: u32,
        contexts: &[(u16, SyntaxId, &[SyntaxId])],
    ) -> Vec<u8> {
        let mut out = header(ptype, 3, call_id);
        out.extend_from_slice(&frags.0.to_le_bytes());
        out.extend_from_slice(&frags.1.to_le_bytes());
        out.extend_from_slice(&group.to_le_bytes());
        out.extend_from_slice(&[contexts.len() as u8, 0, 0, 0]);
        for (id, abstract_syntax, transfer) in contexts {
            out.extend_from_slice(&id.to_le_bytes());
            out.extend_from_slice(&[transfer.len() as u8, 0]);
            abstract_syntax.write(&mut out);
            for t in *transfer {
                t.write(&mut out);
            }
        }
        finish(out)
    }

    fn srvsvc_bind(call_id: u32) -> Vec<u8> {
        bind_pdu(PTYPE_BIND, call_id, (4280, 4280), 0, &[(0, SRVSVC, &[NDR])])
    }

    /// `pdu` with an auth verifier of `len` bytes after its sec_trailer.
    fn with_auth(pdu: Vec<u8>, len: u16) -> Vec<u8> {
        let mut out = pdu;
        out.extend_from_slice(&[10, 2, 0, 0, 0, 0, 0, 0]);
        out.extend(std::iter::repeat_n(0x4E, len.into()));
        out[10..12].copy_from_slice(&len.to_le_bytes());
        finish(out)
    }

    fn request_pdu(call_id: u32, flags: u8, context: u16, opnum: u16, stub: &[u8]) -> Vec<u8> {
        let mut out = header(PTYPE_REQUEST, flags, call_id);
        out.extend_from_slice(&(stub.len() as u32).to_le_bytes());
        out.extend_from_slice(&context.to_le_bytes());
        out.extend_from_slice(&opnum.to_le_bytes());
        out.extend_from_slice(stub);
        finish(out)
    }

    fn sent(steps: Vec<Step>) -> Vec<Vec<u8>> {
        steps
            .into_iter()
            .map(|s| match s {
                Step::Send(pdu) => pdu,
                Step::Call(call) => panic!("unexpected call {call:?}"),
            })
            .collect()
    }

    /// The single PDU `steps` sends.
    fn one(steps: Vec<Step>) -> Vec<u8> {
        let mut pdus = sent(steps);
        assert_eq!(pdus.len(), 1, "one reply");
        pdus.pop().unwrap()
    }

    fn ptype(pdu: &[u8]) -> u8 {
        pdu[2]
    }

    fn call_id(pdu: &[u8]) -> u32 {
        u32::from_le_bytes(pdu[12..16].try_into().unwrap())
    }

    fn nak_reason(pdu: &[u8]) -> u16 {
        assert_eq!(ptype(pdu), PTYPE_BIND_NAK);
        u16::from_le_bytes([pdu[16], pdu[17]])
    }

    /// Flags, context id and status of a fault.
    fn fault_of(pdu: &[u8]) -> (u8, u16, u32) {
        assert_eq!(ptype(pdu), PTYPE_FAULT);
        assert_eq!(pdu.len(), 32);
        (
            pdu[3],
            u16::from_le_bytes([pdu[20], pdu[21]]),
            u32::from_le_bytes(pdu[24..28].try_into().unwrap()),
        )
    }

    /// max_xmit, assoc group and (result, reason, transfer syntax) of each
    /// element of a bind_ack or alter_context_resp.
    fn ack_of(pdu: &[u8]) -> (u16, u32, Vec<(u16, u16, SyntaxId)>) {
        let max = u16::from_le_bytes([pdu[16], pdu[17]]);
        assert_eq!(max, u16::from_le_bytes([pdu[18], pdu[19]]));
        let group = u32::from_le_bytes(pdu[20..24].try_into().unwrap());
        let addr = usize::from(u16::from_le_bytes([pdu[24], pdu[25]]));
        let at = (26 + addr).next_multiple_of(4);
        let n = usize::from(pdu[at]);
        let results = (0..n)
            .map(|i| {
                let r = &pdu[at + 4 + 24 * i..];
                (
                    u16::from_le_bytes([r[0], r[1]]),
                    u16::from_le_bytes([r[2], r[3]]),
                    SyntaxId::read(&r[4..]).unwrap(),
                )
            })
            .collect();
        assert_eq!(pdu.len(), at + 4 + 24 * n);
        (max, group, results)
    }

    fn bound() -> Association {
        let mut a = Association::default();
        let ack = one(a.receive(&srvsvc_bind(1)));
        assert_eq!(ptype(&ack), PTYPE_BIND_ACK);
        a
    }

    fn zero() -> SyntaxId {
        SyntaxId::default()
    }

    #[test]
    fn the_first_pdu_must_be_a_bind() {
        for first in [
            request_pdu(5, 3, 0, 15, b""),
            bind_pdu(
                PTYPE_ALTER_CONTEXT,
                5,
                (4280, 4280),
                0,
                &[(0, SRVSVC, &[NDR])],
            ),
            finish(header(PTYPE_CO_CANCEL, 3, 5)),
        ] {
            let mut a = Association::default();
            let nak = one(a.receive(&first));
            assert_eq!(nak_reason(&nak), 4);
            assert_eq!(call_id(&nak), 5);
            assert!(a.is_closed());
            assert!(a.receive(&srvsvc_bind(6)).is_empty());
        }
    }

    #[test]
    fn binds_that_break_the_rules_are_refused() {
        let cases: [(&str, Vec<u8>, u16); 5] = [
            (
                "authenticated",
                with_auth(srvsvc_bind(1), 32),
                NAK_AUTHENTICATION_TYPE_NOT_RECOGNIZED,
            ),
            (
                "no contexts",
                bind_pdu(PTYPE_BIND, 1, (4280, 4280), 0, &[]),
                NAK_PROTOCOL_VERSION_NOT_SUPPORTED,
            ),
            (
                "no transfer syntax",
                bind_pdu(PTYPE_BIND, 1, (4280, 4280), 0, &[(0, SRVSVC, &[])]),
                NAK_NOT_SPECIFIED,
            ),
            (
                "two feature elements",
                bind_pdu(
                    PTYPE_BIND,
                    1,
                    (4280, 4280),
                    0,
                    &[(0, SRVSVC, &[features(2)]), (1, SRVSVC, &[features(1)])],
                ),
                NAK_NOT_SPECIFIED,
            ),
            (
                "version 5.1",
                {
                    let mut b = srvsvc_bind(1);
                    b[1] = 1;
                    b
                },
                NAK_PROTOCOL_VERSION_NOT_SUPPORTED,
            ),
        ];
        for (what, bind, reason) in cases {
            let mut a = Association::default();
            assert_eq!(nak_reason(&one(a.receive(&bind))), reason, "{what}");
            assert!(a.is_closed(), "{what}");
        }
    }

    #[test]
    fn a_second_bind_ends_the_association() {
        let mut a = bound();
        assert_eq!(nak_reason(&one(a.receive(&srvsvc_bind(2)))), 0);
        assert!(a.is_closed());
    }

    #[test]
    fn contexts_are_negotiated_one_by_one() {
        let mut a = Association::default();
        let (max, _, results) = ack_of(&one(a.receive(&unhex(BIND_3CTX))));
        assert_eq!(max, 4280);
        // Only KeepConnectionOnOrphan of the offered 0x3 is supported.
        assert_eq!(results, [(0, 0, NDR), (2, 2, zero()), (3, 2, zero())]);

        let mut a = Association::default();
        let bind = bind_pdu(
            PTYPE_BIND,
            1,
            (4280, 4280),
            0,
            &[
                (0, OTHER, &[NDR]),
                (1, SRVSVC, &[NDR64, NDR]),
                (2, SRVSVC, &[features(0xFFFF_FFFF)]),
                (1, SRVSVC, &[NDR]),
            ],
        );
        let (_, _, results) = ack_of(&one(a.receive(&bind)));
        assert_eq!(
            results,
            [(2, 1, zero()), (0, 0, NDR), (3, 2, zero()), (0, 0, NDR)]
        );
    }

    #[test]
    fn at_most_eight_contexts_are_bound() {
        let contexts = |ids: std::ops::Range<u16>| -> Vec<(u16, SyntaxId, &[SyntaxId])> {
            ids.map(|id| (id, SRVSVC, &[NDR][..])).collect()
        };
        let mut a = Association::default();
        let bind = bind_pdu(PTYPE_BIND, 1, (4280, 4280), 0, &contexts(0..9));
        assert_eq!(nak_reason(&one(a.receive(&bind))), 2);
        assert!(a.is_closed());

        let mut a = Association::default();
        let mut eight = contexts(0..8);
        eight.push((0, SRVSVC, &[NDR]));
        eight.push((9, OTHER, &[NDR]));
        let bind = bind_pdu(PTYPE_BIND, 1, (4280, 4280), 0, &eight);
        let (_, _, results) = ack_of(&one(a.receive(&bind)));
        assert!(results[..9].iter().all(|r| *r == (0, 0, NDR)));
        assert_eq!(results[9], (2, 1, zero()));
        // A bound id is accepted again; a ninth one ends the association.
        let alter = bind_pdu(PTYPE_ALTER_CONTEXT, 2, (4280, 4280), 0, &contexts(3..5));
        assert_eq!(ack_of(&one(a.receive(&alter))).2, [(0, 0, NDR); 2]);
        let alter = bind_pdu(PTYPE_ALTER_CONTEXT, 3, (4280, 4280), 0, &contexts(8..9));
        assert_eq!(fault_of(&one(a.receive(&alter))).2, NCA_PROTO_ERROR);
        assert!(a.is_closed());
    }

    #[test]
    fn fragment_sizes_follow_the_smaller_offer_within_bounds() {
        for (offer, size) in [
            ((1432, 1432), 2048),
            ((5840, 5840), 4280),
            ((4281, 4281), 4280 & 0xFFF8),
            ((3000, 2049), 2048),
            ((4000, 3001), 3000),
        ] {
            let mut a = Association::default();
            let bind = bind_pdu(PTYPE_BIND, 1, offer, 0, &[(0, SRVSVC, &[NDR])]);
            assert_eq!(ack_of(&one(a.receive(&bind))).0, size, "{offer:?}");
        }
    }

    #[test]
    fn a_new_group_is_never_0_and_a_named_one_is_kept() {
        let mut a = Association::default();
        let (_, group, _) = ack_of(&one(a.receive(&srvsvc_bind(1))));
        assert_ne!(group, 0);
        let mut a = Association::default();
        let bind = bind_pdu(PTYPE_BIND, 1, (4280, 4280), 7, &[(0, SRVSVC, &[NDR])]);
        assert_eq!(ack_of(&one(a.receive(&bind))).1, 7);
    }

    #[test]
    fn the_bind_ack_names_the_pipe() {
        let mut a = Association::default();
        let ack = one(a.receive(&srvsvc_bind(1)));
        assert_eq!(&ack[24..39], b"\x0d\x00\\PIPE\\srvsvc\0");
        assert_eq!(ack[3], 0x03);
    }

    #[test]
    fn a_request_on_an_unbound_context_faults_and_the_association_stays() {
        let mut a = bound();
        let fault = one(a.receive(&request_pdu(2, 3, 5, 15, b"")));
        assert_eq!(fault_of(&fault), (0x23, 0, NCA_UNK_IF));
        assert_eq!(call_id(&fault), 2);
        assert!(!a.is_closed());
        let steps = a.receive(&request_pdu(3, 3, 0, 15, b"x"));
        assert!(matches!(&steps[..], [Step::Call(c)] if c.call_id == 3));
    }

    #[test]
    fn a_failed_call_faults_on_its_context() {
        let a = bound();
        let call = Call {
            call_id: 4,
            context_id: 0,
            opnum: 99,
            stub: Vec::new(),
        };
        let fault = Fault {
            status: NCA_OP_RNG_ERROR,
            did_not_execute: true,
        };
        let pdus = a.reply(&call, Err(fault));
        assert_eq!(pdus.len(), 1);
        assert_eq!(fault_of(&pdus[0]), (0x23, 0, NCA_OP_RNG_ERROR));
        let fault = Fault {
            status: 0x6F7,
            did_not_execute: false,
        };
        assert_eq!(fault_of(&a.reply(&call, Err(fault))[0]).0, 0x03);
    }

    #[test]
    fn fragments_of_a_request_are_reassembled() {
        let mut a = bound();
        assert!(a.receive(&request_pdu(7, 1, 0, 15, b"abc")).is_empty());
        assert!(a.receive(&request_pdu(7, 0, 3, 99, b"def")).is_empty());
        let steps = a.receive(&request_pdu(7, 2, 3, 99, b"g"));
        let [Step::Call(call)] = &steps[..] else {
            panic!("one call");
        };
        assert_eq!(
            *call,
            Call {
                call_id: 7,
                context_id: 0,
                opnum: 15,
                stub: b"abcdefg".to_vec(),
            }
        );
    }

    #[test]
    fn fragments_out_of_sequence_end_the_association() {
        let cases = [
            ("first twice", request_pdu(8, 1, 0, 15, b"")),
            ("another call_id", request_pdu(9, 2, 0, 15, b"")),
        ];
        for (what, second) in cases {
            let mut a = bound();
            assert!(a.receive(&request_pdu(7, 1, 0, 15, b"abc")).is_empty());
            let fault = one(a.receive(&second));
            assert_eq!(fault_of(&fault), (0x23, 0, NCA_PROTO_ERROR), "{what}");
            assert_eq!(call_id(&fault), 7, "{what}");
            assert!(a.is_closed(), "{what}");
        }
    }

    #[test]
    fn stray_fragments_of_recent_calls_are_dropped() {
        // Within 150 of the highest call_id seen, a fragment of no call is
        // dropped; further back, or ahead, it is a protocol error.
        let mut a = bound();
        let steps = a.receive(&request_pdu(200, 3, 0, 15, b""));
        assert!(matches!(&steps[..], [Step::Call(_)]));
        for call_id in [200, 199, 51] {
            assert!(a.receive(&request_pdu(call_id, 2, 0, 15, b"")).is_empty());
        }
        assert!(!a.is_closed());
        let fault = one(a.receive(&request_pdu(50, 2, 0, 15, b"")));
        assert_eq!((fault_of(&fault).2, call_id(&fault)), (NCA_PROTO_ERROR, 50));

        let mut a = bound();
        let fault = one(a.receive(&request_pdu(7, 2, 0, 15, b"")));
        assert_eq!(fault_of(&fault).2, NCA_PROTO_ERROR);
        assert!(a.is_closed());
    }

    #[test]
    fn a_request_stub_past_64_kib_ends_the_association() {
        let mut a = bound();
        let chunk = [0u8; 4000];
        let mut sent_bytes = 0;
        let mut flags = 1;
        while sent_bytes + chunk.len() <= MAX_REQUEST_STUB {
            assert!(a.receive(&request_pdu(7, flags, 0, 15, &chunk)).is_empty());
            sent_bytes += chunk.len();
            flags = 0;
        }
        let fault = one(a.receive(&request_pdu(7, 0, 0, 15, &chunk)));
        assert_eq!(fault_of(&fault), (0x23, 0, FAULT_ACCESS_DENIED));
        assert!(a.is_closed());
    }

    #[test]
    fn co_cancel_is_ignored_and_orphaned_drops_the_partial_call() {
        let mut a = bound();
        assert!(a.receive(&request_pdu(7, 1, 0, 15, b"abc")).is_empty());
        assert!(a.receive(&finish(header(PTYPE_CO_CANCEL, 3, 7))).is_empty());
        assert!(a.receive(&finish(header(PTYPE_ORPHANED, 3, 6))).is_empty());
        assert!(a.receive(&finish(header(PTYPE_ORPHANED, 3, 7))).is_empty());
        // The rest of the orphaned call is dropped.
        assert!(a.receive(&request_pdu(7, 2, 0, 15, b"def")).is_empty());
        let steps = a.receive(&request_pdu(8, 3, 0, 15, b"x"));
        assert!(matches!(&steps[..], [Step::Call(c)] if c.call_id == 8 && c.stub == b"x"));
        assert!(!a.is_closed());
    }

    #[test]
    fn pdus_only_a_server_sends_end_the_association() {
        for ptype in [16, 17, PTYPE_RESPONSE, PTYPE_FAULT, PTYPE_BIND_ACK, 99] {
            let mut a = bound();
            let fault = one(a.receive(&finish(header(ptype, 3, 4))));
            assert_eq!(fault_of(&fault), (0x23, 0, NCA_PROTO_ERROR), "{ptype}");
            assert!(a.is_closed());
        }
    }

    #[test]
    fn fragment_lengths_out_of_range_are_protocol_errors() {
        for len in [15u16, 4281] {
            let mut pdu = request_pdu(3, 3, 0, 15, b"");
            pdu[8..10].copy_from_slice(&len.to_le_bytes());
            let mut a = Association::default();
            assert_eq!(nak_reason(&one(a.receive(&pdu[..16]))), 4);

            let mut a = bound();
            let fault = one(a.receive(&pdu[..16]));
            assert_eq!(fault_of(&fault).2, NCA_PROTO_ERROR);
            assert_eq!(call_id(&fault), 3);
        }
        let mut a = bound();
        let mut request = request_pdu(5, 3, 0, 15, b"");
        request[0] = 4;
        assert_eq!(fault_of(&one(a.receive(&request))).2, NCA_PROTO_ERROR);
    }

    #[test]
    fn a_bind_past_4280_bytes_is_read_for_its_authentication() {
        let mut a = Association::default();
        let bind = with_auth(srvsvc_bind(1), 12000);
        assert!(bind.len() > 4280);
        assert!(a.receive(&bind[..5000]).is_empty());
        assert_eq!(nak_reason(&one(a.receive(&bind[5000..]))), 8);

        let mut a = bound();
        let alter = bind_pdu(
            PTYPE_ALTER_CONTEXT,
            5,
            (4280, 4280),
            0,
            &[(1, SRVSVC, &[NDR])],
        );
        let fault = one(a.receive(&with_auth(alter, 12000)));
        assert_eq!(fault_of(&fault).2, NCA_PROTO_ERROR);
    }

    #[test]
    fn abort_ends_the_association_with_a_busy_fault() {
        let mut a = bound();
        assert!(a.receive(&request_pdu(7, 1, 0, 15, b"abc")).is_empty());
        assert!(a.held() >= 3);
        let fault = a.abort(9);
        assert_eq!(fault_of(&fault), (0x23, 0, NCA_SERVER_TOO_BUSY));
        assert_eq!(call_id(&fault), 9);
        assert!(a.is_closed());
        assert_eq!(a.held(), 0);
        assert!(a.receive(&request_pdu(8, 3, 0, 15, b"")).is_empty());
    }

    #[test]
    fn authenticated_requests_and_alter_contexts_end_the_association() {
        let mut a = bound();
        let request = with_auth(request_pdu(5, 3, 0, 15, b"abcd"), 16);
        assert_eq!(fault_of(&one(a.receive(&request))).2, NCA_PROTO_ERROR);
        assert!(a.is_closed());

        let mut a = bound();
        let alter = bind_pdu(
            PTYPE_ALTER_CONTEXT,
            5,
            (4280, 4280),
            0,
            &[(1, SRVSVC, &[NDR])],
        );
        assert_eq!(
            fault_of(&one(a.receive(&with_auth(alter, 16)))).2,
            NCA_PROTO_ERROR
        );
        assert!(a.is_closed());
    }

    #[test]
    fn alter_context_adds_contexts_and_answers_with_no_address() {
        let mut a = bound();
        let alter = bind_pdu(
            PTYPE_ALTER_CONTEXT,
            5,
            (1000, 1000),
            99,
            &[(1, SRVSVC, &[NDR]), (2, SRVSVC, &[features(2)])],
        );
        let resp = one(a.receive(&alter));
        assert_eq!(ptype(&resp), PTYPE_ALTER_CONTEXT_RESP);
        assert_eq!(&resp[24..28], [0, 0, 0, 0]);
        let (max, _, results) = ack_of(&resp);
        assert_eq!(max, 4280);
        assert_eq!(results, [(0, 0, NDR), (2, 2, zero())]);
        let steps = a.receive(&request_pdu(6, 3, 1, 15, b""));
        assert!(matches!(&steps[..], [Step::Call(c)] if c.context_id == 1));

        let mut a = bound();
        let empty = bind_pdu(PTYPE_ALTER_CONTEXT, 5, (4280, 4280), 0, &[]);
        assert_eq!(fault_of(&one(a.receive(&empty))).2, NCA_PROTO_ERROR);
    }

    #[test]
    fn pdus_are_cut_from_the_byte_stream() {
        let mut stream = srvsvc_bind(1);
        stream.extend(request_pdu(2, 3, 0, 15, b"one"));
        stream.extend(request_pdu(3, 3, 0, 16, b"two"));
        let mut a = Association::default();
        let mut steps = Vec::new();
        for byte in &stream {
            steps.extend(a.receive(std::slice::from_ref(byte)));
        }
        assert!(matches!(&steps[0], Step::Send(ack) if ptype(ack) == PTYPE_BIND_ACK));
        assert!(matches!(&steps[1], Step::Call(c) if c.stub == b"one"));
        assert!(matches!(&steps[2], Step::Call(c) if c.stub == b"two"));
        assert_eq!(steps.len(), 3);

        let mut a = Association::default();
        assert_eq!(a.receive(&stream).len(), 3);
    }

    #[test]
    fn bytes_after_a_protocol_error_are_dropped() {
        let mut stream = request_pdu(1, 3, 0, 15, b"");
        stream.extend(srvsvc_bind(2));
        let mut a = Association::default();
        assert_eq!(nak_reason(&one(a.receive(&stream))), 4);
        assert!(a.receive(&srvsvc_bind(3)).is_empty());
    }

    /// Flags, alloc_hint, context id and stub length of a response.
    fn response_of(pdu: &[u8]) -> (u8, u32, u16, usize) {
        assert_eq!(ptype(pdu), PTYPE_RESPONSE);
        assert_eq!(usize::from(u16::from_le_bytes([pdu[8], pdu[9]])), pdu.len());
        (
            pdu[3],
            u32::from_le_bytes(pdu[16..20].try_into().unwrap()),
            u16::from_le_bytes([pdu[20], pdu[21]]),
            pdu.len() - 24,
        )
    }

    #[test]
    fn responses_are_cut_into_fragments() {
        let a = bound();
        let call = Call {
            call_id: 9,
            context_id: 0x0102,
            opnum: 15,
            stub: Vec::new(),
        };
        for (len, count) in [(0, 1), (1, 1), (4256, 1), (4257, 2), (3 * 4256 + 7, 4)] {
            let stub: Vec<u8> = (0..len).map(|i| i as u8).collect();
            let pdus = a.reply(&call, Ok(stub.clone()));
            assert_eq!(pdus.len(), count, "{len}");
            let mut joined = Vec::new();
            let mut left = len;
            for (i, pdu) in pdus.iter().enumerate() {
                assert!(pdu.len() <= 4280);
                assert_eq!(call_id(pdu), 9);
                let (flags, hint, context, n) = response_of(pdu);
                let expected = u8::from(i == 0) | if i == count - 1 { 2 } else { 0 };
                assert_eq!(flags, expected, "{len} #{i}");
                assert_eq!(hint as usize, left);
                assert_eq!(context, 0x0102);
                assert!(i == count - 1 || n == 4256);
                left -= n;
                joined.extend_from_slice(&pdu[24..]);
            }
            assert_eq!(joined, stub);
        }

        let mut a = Association::default();
        let bind = bind_pdu(PTYPE_BIND, 1, (2048, 2048), 0, &[(0, SRVSVC, &[NDR])]);
        one(a.receive(&bind));
        let pdus = a.reply(&call, Ok(vec![0; 5000]));
        assert_eq!(pdus.len(), 3);
        assert!(pdus.iter().all(|p| p.len() <= 2048));
        assert_eq!(response_of(&pdus[0]).3, 2016);
    }
}
