//! The messages of a WS-Discovery target service, in the namespaces
//! Windows uses: the April 2005 WS-Discovery draft, the August 2004
//! WS-Addressing, DPWS of February 2006 and the Publication Services
//! metadata of MS-PBSD.

use std::fmt::Write as _;

use uuid::Uuid;

use tracing::debug;

use super::xml::{self, Body, Malformed, Name, WSA, WSD, escape};
use crate::discovery::Device;

const WSDP: &str = "http://schemas.xmlsoap.org/ws/2006/02/devprof";
const WSX: &str = "http://schemas.xmlsoap.org/ws/2004/09/mex";
const PNPX: &str = "http://schemas.microsoft.com/windows/pnpx/2005/10";
const PUB: &str = "http://schemas.microsoft.com/windows/pub/2005/07";

/// `wsa:To` of multicast messages.
const DISCOVERY_URN: &str = "urn:schemas-xmlsoap-org:ws:2005:04:discovery";
/// `wsa:To` of replies, and the only `wsa:ReplyTo` answered.
const ANONYMOUS: &str = "http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous";

const HELLO: &str = "http://schemas.xmlsoap.org/ws/2005/04/discovery/Hello";
const BYE: &str = "http://schemas.xmlsoap.org/ws/2005/04/discovery/Bye";
const PROBE: &str = "http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe";
const PROBE_MATCHES: &str = "http://schemas.xmlsoap.org/ws/2005/04/discovery/ProbeMatches";
const RESOLVE: &str = "http://schemas.xmlsoap.org/ws/2005/04/discovery/Resolve";
const RESOLVE_MATCHES: &str = "http://schemas.xmlsoap.org/ws/2005/04/discovery/ResolveMatches";
const GET: &str = "http://schemas.xmlsoap.org/ws/2004/09/transfer/Get";
const GET_RESPONSE: &str = "http://schemas.xmlsoap.org/ws/2004/09/transfer/GetResponse";

/// The types the server is a target service of.
const TYPES: &str = "wsdp:Device pub:Computer";

/// A Probe or Resolve, as received over UDP.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct Request {
    pub(super) message_id: String,
    pub(super) kind: Kind,
}

#[derive(Debug, PartialEq, Eq)]
pub(super) enum Kind {
    /// Empty lists match any type or scope.
    Probe {
        types: Vec<Name>,
        scopes: Vec<String>,
    },
    Resolve {
        address: String,
    },
}

/// Reads a Probe or Resolve. `None` for anything else, including requests
/// that ask for replies to go anywhere but back to the sender.
pub(super) fn read_request(datagram: &[u8]) -> Option<Request> {
    let envelope = parse(datagram).ok()?;
    if envelope
        .reply_to
        .as_deref()
        .is_some_and(|to| to != ANONYMOUS)
    {
        return None;
    }
    let message_id = envelope.message_id.filter(|id| !id.is_empty())?;
    let kind = match (envelope.action.as_deref()?, envelope.body) {
        (PROBE, Body::Probe { types, scopes }) => Kind::Probe {
            types: types.unwrap_or_default(),
            scopes: scopes.unwrap_or_default(),
        },
        (RESOLVE, Body::Resolve { address }) => Kind::Resolve { address: address? },
        _ => return None,
    };
    Some(Request { message_id, kind })
}

/// Parses `bytes` as an envelope, logging why when it cannot.
fn parse(bytes: &[u8]) -> Result<xml::Envelope, Malformed> {
    let parsed = std::str::from_utf8(bytes)
        .map_err(|_| Malformed("not UTF-8"))
        .and_then(xml::parse);
    if let Err(Malformed(reason)) = &parsed {
        debug!(reason, "WS-Discovery envelope rejected");
    }
    parsed
}

/// Whether a Probe for `types` and `scopes` matches the server: every type
/// is one of its types, and it has no scopes to match any scope.
pub(super) fn matches(types: &[Name], scopes: &[String]) -> bool {
    scopes.is_empty()
        && types.iter().all(|name| {
            matches!(
                (name.namespace.as_deref(), name.local.as_str()),
                (Some(WSDP), "Device") | (Some(PUB), "Computer")
            )
        })
}

/// Whether `address` is `urn:uuid:<endpoint>`, compared as RFC 3986 and
/// RFC 4122 allow: scheme, namespace and hex digits in any case.
pub(super) fn is_endpoint(address: &str, endpoint: Uuid) -> bool {
    let address = address.trim();
    let Some((prefix, uuid)) = address.split_at_checked("urn:uuid:".len()) else {
        return false;
    };
    prefix.eq_ignore_ascii_case("urn:uuid:")
        && uuid.len() == 36
        && Uuid::try_parse(uuid).is_ok_and(|uuid| uuid == endpoint)
}

/// The application sequence of a message: a number that grows each time
/// the server starts, one sequence per run, and the message's number in
/// it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Sequence {
    pub(super) instance_id: u64,
    pub(super) sequence_id: Uuid,
    pub(super) message_number: u64,
}

/// What every message the server sends over UDP carries.
pub(super) struct Header<'a> {
    pub(super) message_id: Uuid,
    pub(super) sequence: Sequence,
    /// MessageID of the request answered.
    pub(super) relates_to: Option<&'a str>,
    /// Sent in Hello, ProbeMatches and ResolveMatches.
    pub(super) metadata_version: u32,
}

/// Hello, announcing the server at `xaddr`.
pub(super) fn hello(device: &Device, xaddr: &str, header: &Header<'_>) -> String {
    let body = format!(
        "<wsd:Hello>{}<wsd:Types>{TYPES}</wsd:Types><wsd:XAddrs>{}</wsd:XAddrs>\
         <wsd:MetadataVersion>{}</wsd:MetadataVersion></wsd:Hello>",
        endpoint_reference(device.endpoint),
        escape(xaddr),
        header.metadata_version,
    );
    udp_envelope(HELLO, header, &body)
}

/// Bye, withdrawing the server.
pub(super) fn bye(device: &Device, header: &Header<'_>) -> String {
    let body = format!("<wsd:Bye>{}</wsd:Bye>", endpoint_reference(device.endpoint));
    udp_envelope(BYE, header, &body)
}

/// ProbeMatches, answering a Probe with the server at `xaddr`.
pub(super) fn probe_matches(device: &Device, xaddr: &str, header: &Header<'_>) -> String {
    let body = format!(
        "<wsd:ProbeMatches><wsd:ProbeMatch>{}</wsd:ProbeMatch></wsd:ProbeMatches>",
        match_content(device, xaddr, header.metadata_version)
    );
    udp_envelope(PROBE_MATCHES, header, &body)
}

/// ResolveMatches, answering a Resolve with the server at `xaddr`.
pub(super) fn resolve_matches(device: &Device, xaddr: &str, header: &Header<'_>) -> String {
    let body = format!(
        "<wsd:ResolveMatches><wsd:ResolveMatch>{}</wsd:ResolveMatch></wsd:ResolveMatches>",
        match_content(device, xaddr, header.metadata_version)
    );
    udp_envelope(RESOLVE_MATCHES, header, &body)
}

fn match_content(device: &Device, xaddr: &str, metadata_version: u32) -> String {
    format!(
        "{}<wsd:Types>{TYPES}</wsd:Types><wsd:XAddrs>{}</wsd:XAddrs>\
         <wsd:MetadataVersion>{metadata_version}</wsd:MetadataVersion>",
        endpoint_reference(device.endpoint),
        escape(xaddr),
    )
}

fn endpoint_reference(endpoint: Uuid) -> String {
    format!(
        "<wsa:EndpointReference><wsa:Address>urn:uuid:{endpoint}</wsa:Address></wsa:EndpointReference>"
    )
}

fn udp_envelope(action: &str, header: &Header<'_>, body: &str) -> String {
    let to = if header.relates_to.is_some() {
        ANONYMOUS
    } else {
        DISCOVERY_URN
    };
    let mut out = format!(
        "<?xml version=\"1.0\" encoding=\"utf-8\"?>\
         <soap:Envelope xmlns:soap=\"{}\" xmlns:wsa=\"{WSA}\" xmlns:wsd=\"{WSD}\" \
         xmlns:wsdp=\"{WSDP}\" xmlns:pub=\"{PUB}\"><soap:Header>\
         <wsa:To>{to}</wsa:To><wsa:Action>{action}</wsa:Action>\
         <wsa:MessageID>urn:uuid:{}</wsa:MessageID>",
        xml::SOAP,
        header.message_id,
    );
    if let Some(relates_to) = header.relates_to {
        let _ = write!(out, "<wsa:RelatesTo>{}</wsa:RelatesTo>", escape(relates_to));
    }
    let sequence = header.sequence;
    let _ = write!(
        out,
        "<wsd:AppSequence InstanceId=\"{}\" SequenceId=\"urn:uuid:{}\" MessageNumber=\"{}\"/>\
         </soap:Header><soap:Body>{body}</soap:Body></soap:Envelope>",
        sequence.instance_id, sequence.sequence_id, sequence.message_number,
    );
    out
}

/// Why a metadata request was refused.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum GetError {
    /// Not a SOAP envelope the server reads.
    Malformed,
    /// Not a WS-Transfer Get for the server's endpoint, or one whose reply
    /// is to go elsewhere.
    Unexpected,
}

/// Reads a WS-Transfer Get for `endpoint` and returns its MessageID.
pub(super) fn read_get(body: &[u8], endpoint: Uuid) -> Result<String, GetError> {
    let envelope = parse(body).map_err(|_| GetError::Malformed)?;
    let expected = envelope.action.as_deref() == Some(GET)
        && envelope.body == Body::Empty
        && envelope
            .to
            .as_deref()
            .is_some_and(|to| is_endpoint(to, endpoint))
        && envelope
            .reply_to
            .as_deref()
            .is_none_or(|to| to == ANONYMOUS);
    match envelope.message_id {
        Some(id) if expected && !id.is_empty() => Ok(id),
        _ => Err(GetError::Unexpected),
    }
}

/// The GetResponse with the server's metadata: the device, its model, and
/// the computer it hosts, `<name>/Workgroup:<workgroup>`.
pub(super) fn get_response(device: &Device, message_id: Uuid, relates_to: &str) -> String {
    let info = &device.info;
    let endpoint = device.endpoint;
    format!(
        "<?xml version=\"1.0\" encoding=\"utf-8\"?>\
         <soap:Envelope xmlns:soap=\"{soap}\" xmlns:wsa=\"{WSA}\" xmlns:wsx=\"{WSX}\" \
         xmlns:wsdp=\"{WSDP}\" xmlns:pnpx=\"{PNPX}\" xmlns:pub=\"{PUB}\"><soap:Header>\
         <wsa:To>{ANONYMOUS}</wsa:To><wsa:Action>{GET_RESPONSE}</wsa:Action>\
         <wsa:MessageID>urn:uuid:{message_id}</wsa:MessageID>\
         <wsa:RelatesTo>{relates_to}</wsa:RelatesTo></soap:Header><soap:Body><wsx:Metadata>\
         <wsx:MetadataSection Dialect=\"{WSDP}/ThisDevice\"><wsdp:ThisDevice>\
         <wsdp:FriendlyName>{computer}</wsdp:FriendlyName>\
         <wsdp:FirmwareVersion>{firmware}</wsdp:FirmwareVersion></wsdp:ThisDevice>\
         </wsx:MetadataSection>\
         <wsx:MetadataSection Dialect=\"{WSDP}/ThisModel\"><wsdp:ThisModel>\
         <wsdp:Manufacturer>{manufacturer}</wsdp:Manufacturer>\
         <wsdp:ModelName>{model}</wsdp:ModelName>\
         <pnpx:DeviceCategory>Computers</pnpx:DeviceCategory></wsdp:ThisModel>\
         </wsx:MetadataSection>\
         <wsx:MetadataSection Dialect=\"{WSDP}/Relationship\">\
         <wsdp:Relationship Type=\"{WSDP}/host\"><wsdp:Host>{epr}\
         <wsdp:Types>pub:Computer</wsdp:Types>\
         <wsdp:ServiceId>urn:uuid:{endpoint}</wsdp:ServiceId>\
         <pub:Computer>{computer}/Workgroup:{workgroup}</pub:Computer></wsdp:Host>\
         </wsdp:Relationship></wsx:MetadataSection></wsx:Metadata></soap:Body></soap:Envelope>",
        soap = xml::SOAP,
        relates_to = escape(relates_to),
        computer = escape(&info.computer),
        firmware = escape(&info.firmware_version),
        manufacturer = escape(&info.manufacturer),
        model = escape(&info.model_name),
        workgroup = escape(&info.workgroup),
        epr = endpoint_reference(endpoint),
    )
}

#[cfg(test)]
pub(super) mod tests {
    use quick_xml::XmlVersion;
    use quick_xml::events::Event;
    use quick_xml::name::{Namespace, ResolveResult};
    use quick_xml::reader::NsReader;

    use super::*;
    use crate::discovery::wsd::samples;

    /// An element of a rendered message.
    #[derive(Debug)]
    pub(crate) struct Element {
        pub(crate) namespace: String,
        pub(crate) local: String,
        pub(crate) attributes: Vec<(String, String)>,
        pub(crate) text: String,
    }

    /// Every element of `xml` in document order, failing on anything that
    /// is not well-formed.
    pub(crate) fn elements(xml: &str) -> Vec<Element> {
        let mut reader = NsReader::from_str(xml);
        let mut out: Vec<Element> = Vec::new();
        let mut open: Vec<usize> = Vec::new();
        loop {
            let (ns, event) = reader.read_resolved_event().expect("well-formed");
            let namespace = match ns {
                ResolveResult::Bound(Namespace(ns)) => ns.to_string(),
                _ => String::new(),
            };
            match event {
                Event::Start(ref e) | Event::Empty(ref e) => {
                    let attributes = e
                        .attributes()
                        .map(|a| {
                            let a = a.expect("attribute");
                            let value = a
                                .normalized_value(XmlVersion::Explicit1_0)
                                .expect("value")
                                .into_owned();
                            (a.key.as_ref().to_string(), value)
                        })
                        .collect();
                    out.push(Element {
                        namespace,
                        local: e.local_name().as_ref().to_string(),
                        attributes,
                        text: String::new(),
                    });
                    if matches!(event, Event::Start(_)) {
                        open.push(out.len() - 1);
                    }
                }
                Event::End(_) => {
                    open.pop();
                }
                Event::Text(t) => {
                    if let Some(&i) = open.last() {
                        out[i].text.push_str(&t.xml10_content());
                    }
                }
                Event::GeneralRef(r) => {
                    let c = match &*r {
                        "lt" => '<',
                        "gt" => '>',
                        "amp" => '&',
                        "quot" => '"',
                        "apos" => '\'',
                        _ => r.resolve_char_ref().expect("reference").expect("character"),
                    };
                    if let Some(&i) = open.last() {
                        out[i].text.push(c);
                    }
                }
                Event::Eof => return out,
                _ => {}
            }
        }
    }

    /// The text of the only element `local` in `namespace`.
    pub(crate) fn text<'a>(elements: &'a [Element], namespace: &str, local: &str) -> &'a str {
        let found: Vec<_> = elements
            .iter()
            .filter(|e| e.namespace == namespace && e.local == local)
            .collect();
        assert_eq!(found.len(), 1, "{namespace} {local}");
        found[0].text.as_str()
    }

    fn probe(types: &str, extra: &str) -> String {
        format!(
            "<s:Envelope xmlns:s=\"{}\" xmlns:a=\"{WSA}\" xmlns:d=\"{WSD}\" xmlns:dp=\"{WSDP}\" \
             xmlns:p=\"{PUB}\"><s:Header><a:Action>{PROBE}</a:Action>\
             <a:MessageID>urn:uuid:1</a:MessageID></s:Header><s:Body><d:Probe>{types}{extra}\
             </d:Probe></s:Body></s:Envelope>",
            xml::SOAP
        )
    }

    fn kind(text: &str) -> Option<Kind> {
        read_request(text.as_bytes()).map(|request| request.kind)
    }

    fn probe_matches_server(text: &str) -> Option<bool> {
        match kind(text)? {
            Kind::Probe { types, scopes } => Some(matches(&types, &scopes)),
            Kind::Resolve { .. } => None,
        }
    }

    #[test]
    fn windows_requests_are_read() {
        let probe = read_request(samples::PROBE.as_bytes()).expect("probe");
        assert_eq!(probe.message_id, samples::PROBE_ID);
        let Kind::Probe { types, scopes } = probe.kind else {
            panic!("{:?}", probe.kind)
        };
        assert_eq!(
            types,
            [Name {
                namespace: Some(WSDP.to_string()),
                local: "Device".to_string()
            }]
        );
        assert!(scopes.is_empty());
        assert!(matches(&types, &scopes));

        let resolve = read_request(samples::RESOLVE.as_bytes()).expect("resolve");
        assert_eq!(resolve.message_id, samples::RESOLVE_ID);
        let Kind::Resolve { address } = resolve.kind else {
            panic!("{:?}", resolve.kind)
        };
        assert!(is_endpoint(&address, samples::ENDPOINT));

        assert_eq!(
            read_get(samples::GET.as_bytes(), samples::ENDPOINT).as_deref(),
            Ok(samples::GET_ID)
        );
        assert!(read_request(samples::GET.as_bytes()).is_none());
    }

    #[test]
    fn names_resolve_by_namespace_not_prefix() {
        let spaced = format!(
            "<?xml version='1.0'?>\n<!-- c -->\n<Envelope xmlns='{}'>\n  <Header>\n    \
             <x:Action xmlns:x='{WSA}'> {PROBE} </x:Action>\n    \
             <x:MessageID xmlns:x='{WSA}'>\n urn:uuid:2 \n</x:MessageID>\n  </Header>\n  \
             <Body><Probe xmlns='{WSD}'><Types xmlns:q='{PUB}' xmlns:r='{WSDP}'>\n \
             q:Computer\t r:Device \n</Types></Probe></Body>\n</Envelope>\n",
            xml::SOAP
        );
        let request = read_request(spaced.as_bytes()).expect("probe");
        assert_eq!(request.message_id, "urn:uuid:2");
        let Kind::Probe { types, .. } = request.kind else {
            panic!()
        };
        assert_eq!(types.len(), 2);
        assert!(matches(&types, &[]));
    }

    #[test]
    fn probes_match_by_every_type_and_scope() {
        let table = [
            ("<d:Types>dp:Device</d:Types>", "", true),
            ("<d:Types>dp:Device p:Computer</d:Types>", "", true),
            ("<d:Types>p:Computer</d:Types>", "", true),
            ("<d:Types/>", "", true),
            ("<d:Types>  </d:Types>", "", true),
            ("", "", true),
            ("<d:Types>dp:Printer</d:Types>", "", false),
            ("<d:Types>dp:Device dp:Printer</d:Types>", "", false),
            ("<d:Types>d:Device</d:Types>", "", false),
            ("<d:Types>Device</d:Types>", "", false),
            ("", "<d:Scopes>ldap:///ou=x</d:Scopes>", false),
            (
                "<d:Types>dp:Device</d:Types>",
                "<d:Scopes>http://x/y</d:Scopes>",
                false,
            ),
            ("<d:Types>dp:Device</d:Types>", "<d:Scopes/>", true),
        ];
        for (types, scopes, matched) in table {
            assert_eq!(
                probe_matches_server(&probe(types, scopes)),
                Some(matched),
                "{types} {scopes}"
            );
        }
    }

    #[test]
    fn resolves_match_the_endpoint_in_any_case() {
        let endpoint = samples::ENDPOINT;
        for address in [
            "urn:uuid:3f2b8c1e-7a4d-8e5f-9b6c-2d1e0f3a4b5c",
            "URN:UUID:3F2B8C1E-7A4D-8E5F-9B6C-2D1E0F3A4B5C",
            "  urn:uuid:3f2b8c1e-7a4d-8e5f-9b6c-2d1e0f3a4b5c\n",
        ] {
            assert!(is_endpoint(address, endpoint), "{address:?}");
        }
        for address in [
            "urn:uuid:3f2b8c1e7a4d8e5f9b6c2d1e0f3a4b5c",
            "urn:uuid:{3f2b8c1e-7a4d-8e5f-9b6c-2d1e0f3a4b5c}",
            "urn:uuid:00000000-0000-0000-0000-000000000000",
            "3f2b8c1e-7a4d-8e5f-9b6c-2d1e0f3a4b5c",
            "uuid:3f2b8c1e-7a4d-8e5f-9b6c-2d1e0f3a4b5c",
            "urn:uuid:3f2b8c1e-7a4d-8e5f-9b6c-2d1e0f3a4b5c\u{e9}",
            "",
        ] {
            assert!(!is_endpoint(address, endpoint), "{address:?}");
        }
    }

    #[test]
    fn malformed_and_foreign_requests_are_rejected() {
        let good = probe("<d:Types>dp:Device</d:Types>", "");
        assert!(kind(&good).is_some());
        let with = |from: &str, to: &str| {
            assert!(good.contains(from), "{from}");
            good.replacen(from, to, 1)
        };
        let cases = [
            format!("<!DOCTYPE x [<!ENTITY e \"y\">]>{good}"),
            format!("<?pi data?>{good}"),
            format!("<?xml version=\"1.0\"?><?xml version=\"1.0\"?>{good}"),
            with("dp:Device", "&e;"),
            with("dp:Device", "&#0;"),
            with("dp:Device", "&#xFFFE;"),
            with("dp:Device", "x:Device"),
            with(&format!("<a:Action>{PROBE}</a:Action>"), ""),
            with("<a:MessageID>urn:uuid:1</a:MessageID>", ""),
            with("<a:MessageID>urn:uuid:1</a:MessageID>", "<a:MessageID/>"),
            with(
                "<a:MessageID>urn:uuid:1</a:MessageID>",
                "<a:MessageID>urn:uuid:1</a:MessageID><a:MessageID>urn:uuid:3</a:MessageID>",
            ),
            with(
                "<a:MessageID>urn:uuid:1</a:MessageID>",
                &format!("<a:MessageID>urn:uuid:{}</a:MessageID>", "1".repeat(250)),
            ),
            with(
                "</s:Header>",
                "<a:ReplyTo><a:Address>http://198.51.100.7/</a:Address></a:ReplyTo></s:Header>",
            ),
            with(WSD, "http://docs.oasis-open.org/ws-dd/ns/discovery/2009/01"),
            with(xml::SOAP, "http://schemas.xmlsoap.org/soap/envelope/"),
            with(PROBE, RESOLVE),
            with("</d:Probe>", "</d:Probe><d:Probe/>"),
            with("dp:Device", &"dp:Device ".repeat(33)),
            with(
                "dp:Device",
                &format!("{}{}", "<x>".repeat(13), "</x>".repeat(13)),
            ),
            with("</s:Envelope>", ""),
            format!("{good}<s:Envelope/>"),
            format!("{good}text"),
        ];
        for case in cases {
            assert_eq!(kind(&case), None, "{case}");
        }
        assert_eq!(read_request(b"\xff\xfe<"), None);
        assert_eq!(read_request(b""), None);
    }

    #[test]
    fn anonymous_replies_and_predefined_references_are_accepted() {
        let good = probe("<d:Types>dp:Device</d:Types>", "");
        let anonymous = good.replacen(
            "</s:Header>",
            &format!("<a:ReplyTo><a:Address>{ANONYMOUS}</a:Address></a:ReplyTo></s:Header>"),
            1,
        );
        assert!(kind(&anonymous).is_some());
        let referenced = good.replacen("urn:uuid:1", "urn:&lt;&#x41;&#66;&amp;&quot;&apos;&gt;", 1);
        let request = read_request(referenced.as_bytes()).expect("probe");
        assert_eq!(request.message_id, "urn:<AB&\"'>");
        let cdata = good.replacen("dp:Device", "<![CDATA[dp:Device]]>", 1);
        assert_eq!(probe_matches_server(&cdata), Some(true));
        let bom = format!("\u{feff}{good}");
        assert!(kind(&bom).is_some());
    }

    fn header(relates_to: Option<&str>) -> Header<'_> {
        Header {
            message_id: Uuid::from_u128(7),
            sequence: Sequence {
                instance_id: 1_700_000_000,
                sequence_id: Uuid::from_u128(9),
                message_number: 42,
            },
            relates_to,
            metadata_version: 1_700_000_100,
        }
    }

    #[test]
    fn announcements_carry_the_endpoint_types_and_sequence() {
        let device = samples::device();
        let xaddr = "http://192.168.1.10:5357/3f2b8c1e-7a4d-8e5f-9b6c-2d1e0f3a4b5c";
        let urn = format!("urn:uuid:{}", samples::ENDPOINT);

        let hello = elements(&hello(&device, xaddr, &header(None)));
        assert_eq!(text(&hello, WSA, "Action"), HELLO);
        assert_eq!(text(&hello, WSA, "To"), DISCOVERY_URN);
        assert_eq!(
            text(&hello, WSA, "MessageID"),
            format!("urn:uuid:{}", Uuid::from_u128(7))
        );
        assert_eq!(text(&hello, WSA, "Address"), urn);
        assert_eq!(text(&hello, WSD, "Types"), "wsdp:Device pub:Computer");
        assert_eq!(text(&hello, WSD, "XAddrs"), xaddr);
        assert_eq!(text(&hello, WSD, "MetadataVersion"), "1700000100");
        let sequence = hello
            .iter()
            .find(|e| e.namespace == WSD && e.local == "AppSequence")
            .expect("AppSequence");
        assert_eq!(
            sequence.attributes,
            [
                ("InstanceId".to_string(), "1700000000".to_string()),
                (
                    "SequenceId".to_string(),
                    format!("urn:uuid:{}", Uuid::from_u128(9))
                ),
                ("MessageNumber".to_string(), "42".to_string()),
            ]
        );
        assert!(!hello.iter().any(|e| e.local == "RelatesTo"));

        let bye = elements(&bye(&device, &header(None)));
        assert_eq!(text(&bye, WSA, "Action"), BYE);
        assert_eq!(text(&bye, WSA, "Address"), urn);
        assert!(
            !bye.iter()
                .any(|e| e.local == "XAddrs" || e.local == "Types")
        );

        for (message, action, outer) in [
            (
                probe_matches(&device, xaddr, &header(Some(samples::PROBE_ID))),
                PROBE_MATCHES,
                "ProbeMatch",
            ),
            (
                resolve_matches(&device, xaddr, &header(Some(samples::PROBE_ID))),
                RESOLVE_MATCHES,
                "ResolveMatch",
            ),
        ] {
            let reply = elements(&message);
            assert_eq!(text(&reply, WSA, "Action"), action);
            assert_eq!(text(&reply, WSA, "To"), ANONYMOUS);
            assert_eq!(text(&reply, WSA, "RelatesTo"), samples::PROBE_ID);
            assert_eq!(text(&reply, WSA, "Address"), urn);
            assert_eq!(text(&reply, WSD, "Types"), "wsdp:Device pub:Computer");
            assert_eq!(text(&reply, WSD, "XAddrs"), xaddr);
            assert_eq!(text(&reply, WSD, "MetadataVersion"), "1700000100");
            assert_eq!(text(&reply, WSD, outer), "");
        }
    }

    #[test]
    fn metadata_names_the_computer_and_workgroup() {
        let device = samples::device();
        let response = elements(&get_response(&device, Uuid::from_u128(5), samples::GET_ID));
        let urn = format!("urn:uuid:{}", samples::ENDPOINT);
        assert_eq!(text(&response, WSA, "Action"), GET_RESPONSE);
        assert_eq!(text(&response, WSA, "To"), ANONYMOUS);
        assert_eq!(text(&response, WSA, "RelatesTo"), samples::GET_ID);
        assert_eq!(text(&response, WSDP, "FriendlyName"), "FILES");
        assert_eq!(text(&response, WSDP, "FirmwareVersion"), "0.7.0");
        assert_eq!(text(&response, WSDP, "Manufacturer"), "smb-server");
        assert_eq!(text(&response, WSDP, "ModelName"), "smb-server");
        assert_eq!(text(&response, PNPX, "DeviceCategory"), "Computers");
        assert_eq!(text(&response, WSA, "Address"), urn);
        assert_eq!(text(&response, WSDP, "Types"), "pub:Computer");
        assert_eq!(text(&response, WSDP, "ServiceId"), urn);
        assert_eq!(
            text(&response, PUB, "Computer"),
            "FILES/Workgroup:WORKGROUP"
        );
        let dialects: Vec<_> = response
            .iter()
            .filter(|e| e.local == "MetadataSection")
            .map(|e| e.attributes[0].1.as_str())
            .collect();
        assert_eq!(
            dialects,
            [
                format!("{WSDP}/ThisDevice"),
                format!("{WSDP}/ThisModel"),
                format!("{WSDP}/Relationship")
            ]
        );
    }

    #[test]
    fn text_is_escaped() {
        let mut device = samples::device();
        device.info.computer = "A<&\"'>B".to_string();
        device.info.manufacturer = "x</wsdp:Manufacturer><evil/>".to_string();
        device.info.model_name = "bell\u{7}".to_string();
        let response = elements(&get_response(&device, Uuid::from_u128(5), "<&>"));
        assert_eq!(text(&response, WSDP, "FriendlyName"), "A<&\"'>B");
        assert_eq!(
            text(&response, WSDP, "Manufacturer"),
            "x</wsdp:Manufacturer><evil/>"
        );
        assert_eq!(text(&response, WSDP, "ModelName"), "bell\u{fffd}");
        assert_eq!(text(&response, WSA, "RelatesTo"), "<&>");
        assert!(!response.iter().any(|e| e.local == "evil"));
    }

    #[test]
    fn gets_must_name_the_endpoint_and_transfer_get() {
        let endpoint = samples::ENDPOINT;
        let other = samples::GET.replacen("3f2b8c1e", "00000000", 1);
        assert_eq!(
            read_get(other.as_bytes(), endpoint),
            Err(GetError::Unexpected)
        );
        let put = samples::GET.replacen("transfer/Get", "transfer/Put", 1);
        assert_eq!(
            read_get(put.as_bytes(), endpoint),
            Err(GetError::Unexpected)
        );
        let elsewhere = samples::GET.replacen(ANONYMOUS, "http://198.51.100.7/", 1);
        assert_eq!(
            read_get(elsewhere.as_bytes(), endpoint),
            Err(GetError::Unexpected)
        );
        let body = samples::GET.replacen("<soap:Body/>", "<soap:Body><x/></soap:Body>", 1);
        assert_eq!(
            read_get(body.as_bytes(), endpoint),
            Err(GetError::Unexpected)
        );
        assert_eq!(read_get(b"<a", endpoint), Err(GetError::Malformed));
    }
}
