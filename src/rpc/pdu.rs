//! Connection-oriented DCE/RPC PDUs (C706 12.6, MS-RPCE 2.2.2): parsers for
//! what a client sends and encoders for what the server answers. Only the
//! little-endian, ASCII, IEEE data representation is accepted and sent.

/// Size of the common header.
pub(crate) const HEADER_LEN: usize = 16;
/// Size of a response PDU before its stub.
pub(crate) const RESPONSE_HEADER_LEN: usize = 24;
/// Largest fragment either side sends on a named pipe.
pub(crate) const MAX_FRAG: u16 = 4280;

pub(crate) const PTYPE_REQUEST: u8 = 0;
pub(crate) const PTYPE_RESPONSE: u8 = 2;
pub(crate) const PTYPE_FAULT: u8 = 3;
pub(crate) const PTYPE_BIND: u8 = 11;
pub(crate) const PTYPE_BIND_ACK: u8 = 12;
pub(crate) const PTYPE_BIND_NAK: u8 = 13;
pub(crate) const PTYPE_ALTER_CONTEXT: u8 = 14;
pub(crate) const PTYPE_ALTER_CONTEXT_RESP: u8 = 15;
pub(crate) const PTYPE_CO_CANCEL: u8 = 18;
pub(crate) const PTYPE_ORPHANED: u8 = 19;

pub(crate) const PFC_FIRST_FRAG: u8 = 0x01;
pub(crate) const PFC_LAST_FRAG: u8 = 0x02;
pub(crate) const PFC_DID_NOT_EXECUTE: u8 = 0x20;
pub(crate) const PFC_OBJECT_UUID: u8 = 0x80;

/// Fault statuses (C706 Appendix E.1, MS-RPCE 3.3.3.5.4).
pub(crate) const NCA_OP_RNG_ERROR: u32 = 0x1C01_0002;
pub(crate) const NCA_UNK_IF: u32 = 0x1C01_0003;
pub(crate) const NCA_PROTO_ERROR: u32 = 0x1C01_000B;
pub(crate) const NCA_SERVER_TOO_BUSY: u32 = 0x1C01_0014;
pub(crate) const FAULT_ACCESS_DENIED: u32 = 0x0000_0005;

/// alloc_hint of a fault PDU, which carries no stub.
const FAULT_ALLOC_HINT: u32 = 24;

/// Little-endian integers, ASCII characters, IEEE floats (C706 14.1).
const DREP: [u8; 4] = [0x10, 0, 0, 0];

/// Size of the sec_trailer before an auth verifier (MS-RPCE 2.2.2.11).
const SEC_TRAILER_LEN: usize = 8;

/// An interface or transfer syntax: the UUID as it is on the wire and the
/// version, major in the low 16 bits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) struct SyntaxId {
    pub uuid: [u8; 16],
    pub version: u32,
}

/// NDR 2.0, 8a885d04-1ceb-11c9-9fe8-08002b104860 (MS-RPCE 2.2.4.12).
pub(crate) const NDR: SyntaxId = SyntaxId {
    uuid: [
        0x04, 0x5d, 0x88, 0x8a, 0xeb, 0x1c, 0xc9, 0x11, 0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10, 0x48,
        0x60,
    ],
    version: 2,
};

/// srvsvc 3.0, 4b324fc8-1670-01d3-1278-5a47bf6ee188 (MS-SRVS 2.1).
pub(crate) const SRVSVC: SyntaxId = SyntaxId {
    uuid: [
        0xc8, 0x4f, 0x32, 0x4b, 0x70, 0x16, 0xd3, 0x01, 0x12, 0x78, 0x5a, 0x47, 0xbf, 0x6e, 0xe1,
        0x88,
    ],
    version: 3,
};

/// First half of a bind time feature negotiation syntax, 6cb71c2c-9812-4540
/// (MS-RPCE 3.3.1.5.3). The other eight bytes are the feature bitmask.
const FEATURE_PREFIX: [u8; 8] = [0x2c, 0x1c, 0xb7, 0x6c, 0x12, 0x98, 0x40, 0x45];

impl SyntaxId {
    /// The bitmask of a bind time feature negotiation syntax, version 1.0,
    /// or `None` for any other syntax.
    pub(crate) fn features(&self) -> Option<u64> {
        let (prefix, bits) = self.uuid.split_at(8);
        (prefix == FEATURE_PREFIX && self.version == 1)
            .then(|| u64::from_le_bytes(bits.try_into().expect("8 bytes")))
    }

    pub(crate) fn read(bytes: &[u8]) -> Option<Self> {
        Some(Self {
            uuid: bytes.get(..16)?.try_into().ok()?,
            version: u32_at(bytes, 16)?,
        })
    }

    pub(crate) fn write(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.uuid);
        out.extend_from_slice(&self.version.to_le_bytes());
    }
}

/// The common header (C706 12.6.3.1), as read, before any check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Header {
    pub rpc_vers: u8,
    pub rpc_vers_minor: u8,
    pub ptype: u8,
    pub flags: u8,
    pub drep: [u8; 4],
    pub frag_length: u16,
    pub auth_length: u16,
    pub call_id: u32,
}

impl Header {
    /// Reads the header fields at the start of `bytes`, or `None` when
    /// there are fewer than 16 bytes.
    pub(crate) fn read(bytes: &[u8]) -> Option<Self> {
        let h = bytes.get(..HEADER_LEN)?;
        Some(Self {
            rpc_vers: h[0],
            rpc_vers_minor: h[1],
            ptype: h[2],
            flags: h[3],
            drep: h[4..8].try_into().ok()?,
            frag_length: u16::from_le_bytes([h[8], h[9]]),
            auth_length: u16::from_le_bytes([h[10], h[11]]),
            call_id: u32_at(h, 12)?,
        })
    }
}

/// One element of a bind's presentation context list (C706 12.6.3.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ContextElem {
    pub id: u16,
    pub abstract_syntax: SyntaxId,
    pub transfer_syntaxes: Vec<SyntaxId>,
}

/// The body of a bind or alter_context PDU (C706 12.6.4.1, 12.6.4.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Bind {
    pub max_xmit_frag: u16,
    pub max_recv_frag: u16,
    pub assoc_group_id: u32,
    pub contexts: Vec<ContextElem>,
}

/// The body of a request PDU (C706 12.6.4.9).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Request<'a> {
    pub alloc_hint: u32,
    pub context_id: u16,
    pub opnum: u16,
    pub stub: &'a [u8],
}

/// What a client sent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Body<'a> {
    Bind(Bind),
    AlterContext(Bind),
    Request(Request<'a>),
    CoCancel,
    Orphaned,
    /// auth3, shutdown, a PDU only servers send, or an unknown PTYPE.
    Unexpected(u8),
}

/// A PDU a client sent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Pdu<'a> {
    pub header: Header,
    pub body: Body<'a>,
}

/// Parses `pdu`, which holds exactly one PDU, or returns `None` when it is
/// malformed: shorter than its header or its frag_length says, a version
/// other than 5.0, another data representation, an auth_length that does
/// not fit, or a body that runs past the PDU.
pub(crate) fn parse(pdu: &[u8]) -> Option<Pdu<'_>> {
    let header = Header::read(pdu)?;
    if header.rpc_vers != 5
        || header.rpc_vers_minor != 0
        || header.drep != DREP
        || usize::from(header.frag_length) != pdu.len()
    {
        return None;
    }
    // An auth verifier ends the PDU, after its sec_trailer (MS-RPCE 2.2.2.11).
    let end = match usize::from(header.auth_length) {
        0 => pdu.len(),
        auth => pdu.len().checked_sub(auth + SEC_TRAILER_LEN)?,
    };
    if end < HEADER_LEN {
        return None;
    }
    let body = &pdu[..end];
    let body = match header.ptype {
        PTYPE_BIND => Body::Bind(parse_bind(body)?),
        PTYPE_ALTER_CONTEXT => Body::AlterContext(parse_bind(body)?),
        PTYPE_REQUEST => Body::Request(parse_request(body, header.flags)?),
        PTYPE_CO_CANCEL => Body::CoCancel,
        PTYPE_ORPHANED => Body::Orphaned,
        other => Body::Unexpected(other),
    };
    Some(Pdu { header, body })
}

/// The body of a bind or alter_context in `pdu`, which ends where the body
/// does.
fn parse_bind(pdu: &[u8]) -> Option<Bind> {
    let count = *pdu.get(24)?;
    let mut at = 28;
    let mut contexts = Vec::with_capacity(count.into());
    for _ in 0..count {
        let elem = pdu.get(at..at + 24)?;
        let syntaxes = usize::from(elem[2]);
        let transfer = pdu.get(at + 24..at + 24 + 20 * syntaxes)?;
        contexts.push(ContextElem {
            id: u16::from_le_bytes([elem[0], elem[1]]),
            abstract_syntax: SyntaxId::read(&elem[4..])?,
            transfer_syntaxes: transfer
                .chunks_exact(20)
                .map(SyntaxId::read)
                .collect::<Option<_>>()?,
        });
        at += 24 + 20 * syntaxes;
    }
    Some(Bind {
        max_xmit_frag: u16_at(pdu, 16)?,
        max_recv_frag: u16_at(pdu, 18)?,
        assoc_group_id: u32_at(pdu, 20)?,
        contexts,
    })
}

/// The body of a request in `pdu`, which ends where the stub does. The
/// object UUID, when there is one, is skipped.
fn parse_request(pdu: &[u8], flags: u8) -> Option<Request<'_>> {
    let stub_at = if flags & PFC_OBJECT_UUID != 0 { 40 } else { 24 };
    Some(Request {
        alloc_hint: u32_at(pdu, 16)?,
        context_id: u16_at(pdu, 20)?,
        opnum: u16_at(pdu, 22)?,
        stub: pdu.get(stub_at..)?,
    })
}

/// The result for one element of a bind or alter_context (C706 12.6.3.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ContextResult {
    pub result: u16,
    pub reason: u16,
    /// The accepted transfer syntax; zeros when none is.
    pub transfer_syntax: SyntaxId,
}

/// A bind_ack, or an alter_context_resp with `ptype` 15 (C706 12.6.4.2,
/// 12.6.4.4). Both fragment sizes are `max_frag`. An empty
/// `secondary_address` is sent as length 0.
pub(crate) fn bind_ack(
    ptype: u8,
    call_id: u32,
    max_frag: u16,
    assoc_group_id: u32,
    secondary_address: &str,
    results: &[ContextResult],
) -> Vec<u8> {
    let mut out = header(ptype, PFC_FIRST_FRAG | PFC_LAST_FRAG, call_id);
    out.extend_from_slice(&max_frag.to_le_bytes());
    out.extend_from_slice(&max_frag.to_le_bytes());
    out.extend_from_slice(&assoc_group_id.to_le_bytes());
    if secondary_address.is_empty() {
        out.extend_from_slice(&0u16.to_le_bytes());
    } else {
        let len = u16::try_from(secondary_address.len() + 1).expect("short address");
        out.extend_from_slice(&len.to_le_bytes());
        out.extend_from_slice(secondary_address.as_bytes());
        out.push(0);
    }
    out.resize(out.len().next_multiple_of(4), 0);
    out.push(u8::try_from(results.len()).expect("a result per context element"));
    out.extend_from_slice(&[0; 3]);
    for r in results {
        out.extend_from_slice(&r.result.to_le_bytes());
        out.extend_from_slice(&r.reason.to_le_bytes());
        r.transfer_syntax.write(&mut out);
    }
    finish(out)
}

/// A bind_nak with `reason` that lists protocol version 5.0 (C706
/// 12.6.4.5), padded to 24 bytes.
pub(crate) fn bind_nak(call_id: u32, reason: u16) -> Vec<u8> {
    let mut out = header(PTYPE_BIND_NAK, PFC_FIRST_FRAG | PFC_LAST_FRAG, call_id);
    out.extend_from_slice(&reason.to_le_bytes());
    out.extend_from_slice(&[1, 5, 0, 0, 0, 0]);
    finish(out)
}

/// One response fragment carrying `stub` (C706 12.6.4.10).
pub(crate) fn response(
    call_id: u32,
    flags: u8,
    alloc_hint: u32,
    context_id: u16,
    stub: &[u8],
) -> Vec<u8> {
    let mut out = header(PTYPE_RESPONSE, flags, call_id);
    out.extend_from_slice(&alloc_hint.to_le_bytes());
    out.extend_from_slice(&context_id.to_le_bytes());
    out.extend_from_slice(&[0, 0]);
    out.extend_from_slice(stub);
    finish(out)
}

/// A fault with `status` and no stub (C706 12.6.4.7, MS-RPCE 2.2.2.8).
pub(crate) fn fault(call_id: u32, flags: u8, context_id: u16, status: u32) -> Vec<u8> {
    let mut out = header(PTYPE_FAULT, flags, call_id);
    out.extend_from_slice(&FAULT_ALLOC_HINT.to_le_bytes());
    out.extend_from_slice(&context_id.to_le_bytes());
    out.extend_from_slice(&[0, 0]);
    out.extend_from_slice(&status.to_le_bytes());
    out.extend_from_slice(&[0; 4]);
    finish(out)
}

/// The common header of a reply, frag_length left at 0.
fn header(ptype: u8, flags: u8, call_id: u32) -> Vec<u8> {
    let mut out = Vec::with_capacity(64);
    out.extend_from_slice(&[5, 0, ptype, flags]);
    out.extend_from_slice(&DREP);
    out.extend_from_slice(&[0; 4]);
    out.extend_from_slice(&call_id.to_le_bytes());
    out
}

/// Sets frag_length to the size of `pdu`.
fn finish(mut pdu: Vec<u8>) -> Vec<u8> {
    let len = u16::try_from(pdu.len()).expect("a PDU fits in a fragment");
    pdu[8..10].copy_from_slice(&len.to_le_bytes());
    pdu
}

fn u16_at(bytes: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes(bytes.get(at..at + 2)?.try_into().ok()?))
}

fn u32_at(bytes: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(bytes.get(at..at + 4)?.try_into().ok()?))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// NDR64 1.0, 71710533-beba-4937-8319-b5dbef9ccc36 (MS-RPCE 2.2.5.1).
    pub(crate) const NDR64: SyntaxId = SyntaxId {
        uuid: [
            0x33, 0x05, 0x71, 0x71, 0xba, 0xbe, 0x37, 0x49, 0x83, 0x19, 0xb5, 0xdb, 0xef, 0x9c,
            0xcc, 0x36,
        ],
        version: 1,
    };

    // Vectors packed by Samba 4.22.11's NDR marshaller: python3-samba,
    // `samba.ndr.ndr_pack` of a `samba.dcerpc.dcerpc.ncacn_packet` with
    // frag_length set to the packed length.

    /// bind, call_id 2, 4280/4280, group 0; context 0 srvsvc + NDR,
    /// context 1 srvsvc + NDR64, context 2 srvsvc + features 0x3.
    pub(crate) const BIND_3CTX: &str = "05000b0310000000a000000002000000b810b810000000000300000000000100c84f324b7016d30112785a47bf6ee18803000000045d888aeb1cc9119fe808002b1048600200000001000100c84f324b7016d30112785a47bf6ee1880300000033057171babe37498319b5dbef9ccc360100000002000100c84f324b7016d30112785a47bf6ee188030000002c1cb76c12984045030000000000000001000000";

    /// bind_ack for BIND_3CTX: 4280/4280, group 0x12345, `\PIPE\srvsvc`;
    /// results 0/0/NDR, 2/2/zeros, 3/3/zeros.
    const BIND_ACK_3CTX: &str = "05000c03100000007400000002000000b810b810452301000d005c504950455c73727673766300000300000000000000045d888aeb1cc9119fe808002b10486002000000020002000000000000000000000000000000000000000000030003000000000000000000000000000000000000000000";

    /// fault, call_id 3, flags 0x23, alloc_hint 32, status 0x1C010002.
    const FAULT_OP_RNG: &str = "0500032310000000200000000300000020000000000000000200011c00000000";

    pub(crate) fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
            .collect()
    }

    #[test]
    fn a_bind_parses_into_its_contexts() {
        let bytes = unhex(BIND_3CTX);
        let pdu = parse(&bytes).expect("bind");
        assert_eq!(pdu.header.ptype, PTYPE_BIND);
        assert_eq!(pdu.header.call_id, 2);
        assert_eq!(pdu.header.frag_length, 160);
        let Body::Bind(bind) = pdu.body else {
            panic!("not a bind");
        };
        assert_eq!((bind.max_xmit_frag, bind.max_recv_frag), (4280, 4280));
        assert_eq!(bind.assoc_group_id, 0);
        let ids: Vec<u16> = bind.contexts.iter().map(|c| c.id).collect();
        assert_eq!(ids, [0, 1, 2]);
        assert!(bind.contexts.iter().all(|c| c.abstract_syntax == SRVSVC));
        assert_eq!(bind.contexts[0].transfer_syntaxes, [NDR]);
        assert_eq!(bind.contexts[1].transfer_syntaxes, [NDR64]);
        assert_eq!(bind.contexts[2].transfer_syntaxes[0].features(), Some(3));
        assert_eq!(NDR.features(), None);
    }

    #[test]
    fn a_bind_ack_matches_samba() {
        let zero = SyntaxId::default();
        let results = [
            ContextResult {
                result: 0,
                reason: 0,
                transfer_syntax: NDR,
            },
            ContextResult {
                result: 2,
                reason: 2,
                transfer_syntax: zero,
            },
            ContextResult {
                result: 3,
                reason: 2,
                transfer_syntax: zero,
            },
        ];
        let ack = bind_ack(PTYPE_BIND_ACK, 2, 4280, 0x12345, "\\PIPE\\srvsvc", &results);
        // The feature element's reason is ours: 0x0002, where the vector
        // was generated with 0x0003.
        let mut expected = unhex(BIND_ACK_3CTX);
        expected[94] = 2;
        assert_eq!(ack, expected);
    }

    #[test]
    fn an_empty_secondary_address_is_a_zero_length() {
        let ack = bind_ack(PTYPE_ALTER_CONTEXT_RESP, 9, 2048, 7, "", &[]);
        assert_eq!(ack.len(), 32);
        assert_eq!(&ack[24..28], [0, 0, 0, 0]);
        assert_eq!(ack[28], 0);
        assert_eq!(Header::read(&ack).unwrap().frag_length, 32);
    }

    #[test]
    fn a_bind_nak_lists_version_5_0() {
        assert_eq!(
            bind_nak(2, 8),
            unhex("05000d031000000018000000020000000800010500000000")
        );
    }

    #[test]
    fn a_fault_matches_samba() {
        let mut expected = unhex(FAULT_OP_RNG);
        // Our alloc_hint is 24, where the vector was generated with 32.
        expected[16] = 24;
        assert_eq!(fault(3, 0x23, 0, NCA_OP_RNG_ERROR), expected);
    }

    #[test]
    fn a_response_carries_its_stub_after_24_bytes() {
        let pdu = response(4, PFC_FIRST_FRAG, 3, 1, b"abc");
        assert_eq!(pdu.len(), 27);
        let hdr = Header::read(&pdu).unwrap();
        assert_eq!((hdr.ptype, hdr.flags, hdr.call_id), (PTYPE_RESPONSE, 1, 4));
        assert_eq!(&pdu[16..24], [3, 0, 0, 0, 1, 0, 0, 0]);
        assert_eq!(&pdu[24..], b"abc");
    }

    fn request_pdu(flags: u8, stub: &[u8]) -> Vec<u8> {
        let mut pdu = header(PTYPE_REQUEST, flags, 7);
        pdu.extend_from_slice(&(stub.len() as u32).to_le_bytes());
        pdu.extend_from_slice(&1u16.to_le_bytes());
        pdu.extend_from_slice(&15u16.to_le_bytes());
        if flags & PFC_OBJECT_UUID != 0 {
            pdu.extend_from_slice(&[0xAB; 16]);
        }
        pdu.extend_from_slice(stub);
        finish(pdu)
    }

    #[test]
    fn a_request_stub_follows_the_object_uuid_when_there_is_one() {
        for flags in [0x03, 0x83] {
            let bytes = request_pdu(flags, b"stub");
            let Some(Pdu {
                body: Body::Request(r),
                ..
            }) = parse(&bytes)
            else {
                panic!("not a request");
            };
            assert_eq!((r.alloc_hint, r.context_id, r.opnum), (4, 1, 15));
            assert_eq!(r.stub, b"stub");
        }
        // Object UUID flagged but missing.
        let mut bytes = request_pdu(0x03, &[0; 8]);
        bytes[3] = 0x83;
        assert!(parse(&bytes).is_none());
    }

    #[test]
    fn malformed_pdus_are_refused() {
        let good = unhex(BIND_3CTX);
        assert!(parse(&good).is_some());
        let with = |at: usize, value: &[u8]| {
            let mut b = good.clone();
            b[at..at + value.len()].copy_from_slice(value);
            b
        };
        let cases = [
            ("truncated header", good[..15].to_vec()),
            ("frag_length below 16", with(8, &[15, 0])),
            ("frag_length past the buffer", with(8, &[161, 0])),
            ("frag_length short of the buffer", with(8, &[159, 0])),
            ("version 4", with(0, &[4])),
            ("minor version 1", with(1, &[1])),
            ("big-endian", with(4, &[0, 0, 0, 0])),
            ("context count past the end", with(24, &[4])),
            ("transfer syntax count past the end", with(118, &[2])),
            ("auth_length past frag_length", with(10, &[0xA0, 0])),
            ("auth_length past the body", with(10, &[100, 0])),
        ];
        for (what, bytes) in cases {
            assert!(parse(&bytes).is_none(), "{what}");
        }
        assert!(parse(&with(3, &[0xFF])).is_some(), "flags are not checked");
    }

    #[test]
    fn other_ptypes_parse_with_their_header_only() {
        for (ptype, body) in [
            (PTYPE_CO_CANCEL, Body::CoCancel),
            (PTYPE_ORPHANED, Body::Orphaned),
            (16, Body::Unexpected(16)),
            (PTYPE_RESPONSE, Body::Unexpected(PTYPE_RESPONSE)),
            (200, Body::Unexpected(200)),
        ] {
            let pdu = finish(header(ptype, 3, 1));
            assert_eq!(parse(&pdu).expect("parses").body, body);
        }
    }
}
