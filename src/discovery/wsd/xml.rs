//! Reading the few SOAP envelopes the server answers, and escaping text
//! for the ones it writes.

use quick_xml::events::{BytesRef, BytesStart, Event};
use quick_xml::name::{Namespace, QName, ResolveResult};
use quick_xml::reader::NsReader;

pub(super) const SOAP: &str = "http://www.w3.org/2003/05/soap-envelope";
pub(super) const WSA: &str = "http://schemas.xmlsoap.org/ws/2004/08/addressing";
pub(super) const WSD: &str = "http://schemas.xmlsoap.org/ws/2005/04/discovery";

/// Longest field, in characters: DPWS lets receivers reject longer ones.
const MAX_FIELD_CHARS: usize = 256;
/// Most names in a Types or values in a Scopes list.
const MAX_TOKENS: usize = 32;
/// Deepest element nesting.
const MAX_DEPTH: usize = 16;
/// Most elements in one envelope.
const MAX_ELEMENTS: usize = 256;
/// Most namespace declarations in scope at once.
const MAX_BINDINGS: usize = 32;

/// Why an envelope was rejected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Malformed(pub(super) &'static str);

/// A qualified name in element content: a namespace, `None` when the name
/// has no prefix and no default namespace applies, and a local name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Name {
    pub(super) namespace: Option<String>,
    pub(super) local: String,
}

/// The parts of a SOAP 1.2 envelope the server reads.
#[derive(Debug, Default, PartialEq, Eq)]
pub(super) struct Envelope {
    pub(super) action: Option<String>,
    pub(super) message_id: Option<String>,
    pub(super) to: Option<String>,
    /// Address of `wsa:ReplyTo`.
    pub(super) reply_to: Option<String>,
    pub(super) body: Body,
}

#[derive(Debug, Default, PartialEq, Eq)]
pub(super) enum Body {
    /// No Body element, or one without children.
    #[default]
    Empty,
    /// `wsd:Probe`. `None` for an absent list.
    Probe {
        types: Option<Vec<Name>>,
        scopes: Option<Vec<String>>,
    },
    /// `wsd:Resolve`, with the address of its endpoint reference.
    Resolve { address: Option<String> },
    /// Any other element.
    Other,
}

/// Elements the reader knows, by their place in the envelope.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Tag {
    Envelope,
    Header,
    Body,
    Action,
    MessageId,
    To,
    ReplyTo,
    ReplyToAddress,
    Probe,
    Types,
    Scopes,
    Resolve,
    Endpoint,
    EndpointAddress,
    Other,
}

impl Tag {
    /// Whether the text of the element is read.
    fn has_text(self) -> bool {
        matches!(
            self,
            Tag::Action
                | Tag::MessageId
                | Tag::To
                | Tag::ReplyToAddress
                | Tag::Types
                | Tag::Scopes
                | Tag::EndpointAddress
        )
    }
}

/// Parses a SOAP 1.2 envelope. Rejects anything that is not well-formed,
/// document type declarations, processing instructions, entity references
/// other than the predefined ones, a header field or body given twice,
/// and input past the limits on depth, elements, namespace declarations,
/// field length and list length.
pub(super) fn parse(text: &str) -> Result<Envelope, Malformed> {
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    let mut reader = NsReader::from_str(text);
    reader
        .resolver_mut()
        .set_max_namespace_bindings(MAX_BINDINGS);
    let mut envelope = Envelope::default();
    let mut path: Vec<Tag> = Vec::new();
    let mut field = String::new();
    let mut elements = 0;
    let mut first = true;
    let mut root_seen = false;
    let mut body_children = 0;
    loop {
        let event = reader
            .read_event()
            .map_err(|_| Malformed("not well-formed XML"))?;
        let at_start = std::mem::replace(&mut first, false);
        match event {
            Event::Start(ref start) | Event::Empty(ref start) => {
                let empty = matches!(event, Event::Empty(_));
                elements += 1;
                if elements > MAX_ELEMENTS {
                    return Err(Malformed("too many elements"));
                }
                if path.len() >= MAX_DEPTH {
                    return Err(Malformed("nested too deep"));
                }
                if path.is_empty() && root_seen {
                    return Err(Malformed("more than one root element"));
                }
                root_seen = true;
                let parent = path.last().copied();
                let tag = tag_of(&reader, parent, start)?;
                if parent == Some(Tag::Body) {
                    body_children += 1;
                    if body_children > 1 {
                        return Err(Malformed("more than one element in the body"));
                    }
                }
                begin(&mut envelope, parent, tag)?;
                path.push(tag);
                if tag.has_text() {
                    field.clear();
                }
                if empty {
                    end(&reader, &mut envelope, &mut path, &mut field)?;
                }
            }
            Event::End(_) => end(&reader, &mut envelope, &mut path, &mut field)?,
            Event::Text(text) => {
                let content = text.xml10_content();
                if path.is_empty() {
                    if !content.trim().is_empty() {
                        return Err(Malformed("text outside the root element"));
                    }
                } else if reading(&path) {
                    push_text(&mut field, &content)?;
                }
            }
            Event::CData(data) => {
                if path.is_empty() {
                    return Err(Malformed("text outside the root element"));
                }
                if reading(&path) {
                    push_text(&mut field, &data.xml10_content())?;
                }
            }
            Event::GeneralRef(reference) => {
                let c = resolve_reference(&reference)?;
                if path.is_empty() {
                    return Err(Malformed("text outside the root element"));
                }
                if reading(&path) {
                    push_text(&mut field, c.encode_utf8(&mut [0; 4]))?;
                }
            }
            Event::Decl(_) if at_start => {}
            Event::Decl(_) | Event::PI(_) => {
                return Err(Malformed("processing instruction"));
            }
            Event::DocType(_) => return Err(Malformed("document type declaration")),
            Event::Comment(_) => {}
            Event::Eof => {
                if !root_seen || !path.is_empty() {
                    return Err(Malformed("incomplete document"));
                }
                return Ok(envelope);
            }
        }
    }
}

/// Whether text at `path` belongs to a field being read.
fn reading(path: &[Tag]) -> bool {
    path.last().is_some_and(|tag| tag.has_text())
}

fn push_text(field: &mut String, text: &str) -> Result<(), Malformed> {
    if field.chars().count() + text.chars().count() > MAX_FIELD_CHARS {
        return Err(Malformed("field too long"));
    }
    field.push_str(text);
    Ok(())
}

/// The character a reference stands for: a character reference to a
/// character XML allows, or one of the five predefined entities.
fn resolve_reference(reference: &BytesRef<'_>) -> Result<char, Malformed> {
    if reference.is_char_ref() {
        return match reference.resolve_char_ref() {
            Ok(Some(c)) if is_xml_char(c) => Ok(c),
            _ => Err(Malformed("bad character reference")),
        };
    }
    match &**reference {
        "lt" => Ok('<'),
        "gt" => Ok('>'),
        "amp" => Ok('&'),
        "apos" => Ok('\''),
        "quot" => Ok('"'),
        _ => Err(Malformed("undeclared entity")),
    }
}

/// Whether XML 1.0 allows `c` in a document.
fn is_xml_char(c: char) -> bool {
    matches!(c, '\t' | '\n' | '\r' | '\u{20}'..='\u{d7ff}' | '\u{e000}'..='\u{fffd}' | '\u{10000}'..)
}

fn namespace_of<'r>(
    reader: &'r NsReader<&[u8]>,
    name: QName<'_>,
) -> Result<Option<&'r str>, Malformed> {
    match reader.resolver().resolve_element(name).0 {
        ResolveResult::Bound(Namespace(ns)) => Ok(Some(ns)),
        ResolveResult::Unbound => Ok(None),
        ResolveResult::Unknown(_) => Err(Malformed("undeclared namespace prefix")),
    }
}

/// The tag of element `start` under an element tagged `parent`.
fn tag_of(
    reader: &NsReader<&[u8]>,
    parent: Option<Tag>,
    start: &BytesStart<'_>,
) -> Result<Tag, Malformed> {
    let ns = namespace_of(reader, start.name())?;
    let local = start.local_name();
    let local: &str = local.as_ref();
    let tag = match (parent, ns, local) {
        (None, Some(SOAP), "Envelope") => Tag::Envelope,
        (None, _, _) => return Err(Malformed("not a SOAP 1.2 envelope")),
        (Some(Tag::Envelope), Some(SOAP), "Header") => Tag::Header,
        (Some(Tag::Envelope), Some(SOAP), "Body") => Tag::Body,
        (Some(Tag::Header), Some(WSA), "Action") => Tag::Action,
        (Some(Tag::Header), Some(WSA), "MessageID") => Tag::MessageId,
        (Some(Tag::Header), Some(WSA), "To") => Tag::To,
        (Some(Tag::Header), Some(WSA), "ReplyTo") => Tag::ReplyTo,
        (Some(Tag::ReplyTo), Some(WSA), "Address") => Tag::ReplyToAddress,
        (Some(Tag::Body), Some(WSD), "Probe") => Tag::Probe,
        (Some(Tag::Body), Some(WSD), "Resolve") => Tag::Resolve,
        (Some(Tag::Probe), Some(WSD), "Types") => Tag::Types,
        (Some(Tag::Probe), Some(WSD), "Scopes") => Tag::Scopes,
        (Some(Tag::Resolve), Some(WSA), "EndpointReference") => Tag::Endpoint,
        (Some(Tag::Endpoint), Some(WSA), "Address") => Tag::EndpointAddress,
        _ => Tag::Other,
    };
    Ok(tag)
}

/// Takes note of element `tag` starting under `parent`, rejecting a field
/// given twice.
fn begin(envelope: &mut Envelope, parent: Option<Tag>, tag: Tag) -> Result<(), Malformed> {
    let twice = match tag {
        Tag::Action => envelope.action.is_some(),
        Tag::MessageId => envelope.message_id.is_some(),
        Tag::To => envelope.to.is_some(),
        Tag::ReplyToAddress => envelope.reply_to.is_some(),
        Tag::Types => matches!(envelope.body, Body::Probe { types: Some(_), .. }),
        Tag::Scopes => matches!(
            envelope.body,
            Body::Probe {
                scopes: Some(_),
                ..
            }
        ),
        Tag::EndpointAddress => matches!(envelope.body, Body::Resolve { address: Some(_) }),
        _ => false,
    };
    if twice {
        return Err(Malformed("element given twice"));
    }
    match tag {
        Tag::Probe => {
            envelope.body = Body::Probe {
                types: None,
                scopes: None,
            }
        }
        Tag::Resolve => envelope.body = Body::Resolve { address: None },
        Tag::Other if parent == Some(Tag::Body) => envelope.body = Body::Other,
        _ => {}
    }
    Ok(())
}

/// Ends the innermost element, storing the field read in it. Runs before
/// the reader leaves the element's namespace scope, so that names in
/// Types resolve with the declarations in force there.
fn end(
    reader: &NsReader<&[u8]>,
    envelope: &mut Envelope,
    path: &mut Vec<Tag>,
    field: &mut String,
) -> Result<(), Malformed> {
    let Some(tag) = path.pop() else {
        return Err(Malformed("unbalanced end tag"));
    };
    if !tag.has_text() {
        return Ok(());
    }
    let text = std::mem::take(field);
    let text = text.trim();
    match tag {
        Tag::Action => envelope.action = Some(text.to_string()),
        Tag::MessageId => envelope.message_id = Some(text.to_string()),
        Tag::To => envelope.to = Some(text.to_string()),
        Tag::ReplyToAddress => envelope.reply_to = Some(text.to_string()),
        Tag::EndpointAddress => {
            if let Body::Resolve { address } = &mut envelope.body {
                *address = Some(text.to_string());
            }
        }
        Tag::Types => {
            let names = tokens(text)?
                .map(|token| {
                    let ns = namespace_of(reader, QName(token))?;
                    let local = token.rsplit(':').next().unwrap_or(token);
                    Ok(Name {
                        namespace: ns.map(str::to_string),
                        local: local.to_string(),
                    })
                })
                .collect::<Result<Vec<_>, Malformed>>()?;
            if let Body::Probe { types, .. } = &mut envelope.body {
                *types = Some(names);
            }
        }
        Tag::Scopes => {
            let values = tokens(text)?.map(str::to_string).collect();
            if let Body::Probe { scopes, .. } = &mut envelope.body {
                *scopes = Some(values);
            }
        }
        _ => {}
    }
    Ok(())
}

/// The whitespace-separated tokens of `text`, at most [`MAX_TOKENS`].
fn tokens(text: &str) -> Result<std::str::SplitWhitespace<'_>, Malformed> {
    if text.split_whitespace().count() > MAX_TOKENS {
        return Err(Malformed("list too long"));
    }
    Ok(text.split_whitespace())
}

/// `text` escaped for element content and attribute values. Characters
/// XML cannot carry become U+FFFD.
pub(super) fn escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '&' => out.push_str("&amp;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            c if is_xml_char(c) => out.push(c),
            _ => out.push('\u{fffd}'),
        }
    }
    out
}
