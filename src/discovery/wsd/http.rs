//! The metadata endpoint: one WS-Transfer Get per HTTP/1.1 connection.

use std::io;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::{Semaphore, watch};
use tokio::task::JoinSet;
use tracing::debug;
use uuid::Uuid;

use super::engine::Link;
use super::{msg, until_stopped};
use crate::discovery::Device;

/// Longest request line and headers, without the blank line after them.
const MAX_HEAD: usize = 8 * 1024;
const MAX_HEADER_LINES: usize = 64;
/// Longest body: DPWS lets receivers reject longer envelopes.
const MAX_BODY: usize = 32767;
/// Longest chunked body as sent, chunk sizes and trailers included.
const MAX_CHUNKED: usize = 2 * MAX_BODY;
/// Longest chunk size line, extensions included.
const MAX_CHUNK_LINE: usize = 64;
/// Longest request read.
const MAX_REQUEST: usize = MAX_HEAD + 4 + MAX_CHUNKED;
/// Longest time a client has to send its request.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
/// Most connections served at once, over every interface. Past it, new
/// connections are closed.
pub(super) const MAX_CONNECTIONS: usize = 8;

/// The status of a response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Status {
    Ok,
    BadRequest,
    NotFound,
    MethodNotAllowed,
    LengthRequired,
    PayloadTooLarge,
    HeadersTooLarge,
    NotImplemented,
    VersionNotSupported,
}

impl Status {
    fn line(self) -> &'static str {
        match self {
            Status::Ok => "200 OK",
            Status::BadRequest => "400 Bad Request",
            Status::NotFound => "404 Not Found",
            Status::MethodNotAllowed => "405 Method Not Allowed",
            Status::LengthRequired => "411 Length Required",
            Status::PayloadTooLarge => "413 Content Too Large",
            Status::HeadersTooLarge => "431 Request Header Fields Too Large",
            Status::NotImplemented => "501 Not Implemented",
            Status::VersionNotSupported => "505 HTTP Version Not Supported",
        }
    }
}

/// How the length of a body is given.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Framing {
    Length(usize),
    Chunked,
}

/// Serves Get requests for `device` on `listener`, from peers on the
/// current `link`, with at most [`MAX_CONNECTIONS`] open over every
/// listener sharing `slots`, until `stop` turns true. Connections are
/// closed after one request, and all of them when serving stops.
pub(super) async fn serve(
    listener: TcpListener,
    link: watch::Receiver<Arc<Link>>,
    device: Arc<Device>,
    slots: Arc<Semaphore>,
    mut stop: watch::Receiver<bool>,
) {
    let mut connections = JoinSet::new();
    loop {
        while connections.try_join_next().is_some() {}
        let accepted = tokio::select! {
            () = until_stopped(&mut stop) => break,
            accepted = listener.accept() => accepted,
        };
        let (mut stream, peer) = match accepted {
            Ok(accepted) => accepted,
            Err(e) => {
                debug!(error = %e, "cannot accept a metadata request");
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        if !link.borrow().on_link(peer.ip()) {
            debug!(%peer, "metadata request from off the link refused");
            continue;
        }
        let Ok(slot) = slots.clone().try_acquire_owned() else {
            debug!(%peer, "metadata request refused: too many connections");
            continue;
        };
        let device = device.clone();
        connections.spawn(async move {
            let _slot = slot;
            match answer_in_time(&mut stream, &device).await {
                Ok(Ok(())) => {}
                Ok(Err(e)) => debug!(%peer, error = %e, "metadata request failed"),
                Err(_) => debug!(%peer, "metadata request timed out"),
            }
        });
    }
    connections.shutdown().await;
}

/// Answers one request on `stream`, giving the client [`REQUEST_TIMEOUT`]
/// to send it.
async fn answer_in_time<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    device: &Device,
) -> Result<io::Result<()>, tokio::time::error::Elapsed> {
    tokio::time::timeout(REQUEST_TIMEOUT, answer(stream, device)).await
}

/// Reads one request from `stream` and answers it.
async fn answer<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    device: &Device,
) -> io::Result<()> {
    let mut buf = Vec::with_capacity(2048);
    let mut chunk = [0; 4096];
    let mut reader = Reader::default();
    loop {
        if let Some(response) = reader.feed(&buf, device) {
            stream.write_all(&response).await?;
            return stream.shutdown().await;
        }
        let want = (MAX_REQUEST - buf.len()).min(chunk.len());
        match stream.read(&mut chunk[..want]).await? {
            0 => return Ok(()),
            n => buf.extend_from_slice(&chunk[..n]),
        }
    }
}

/// The response to `request`, read as a whole HTTP request: what the
/// endpoint sends back when the request arrives at once, and 400 for a
/// request that ends early, where the endpoint sends nothing.
#[cfg_attr(not(any(test, fuzzing)), allow(dead_code))]
pub(super) fn respond(request: &[u8], device: &Device) -> Vec<u8> {
    process(request, device).unwrap_or_else(|| error(Status::BadRequest))
}

/// The response to the request at the start of `buf`, or `None` while
/// more of it is needed. Like [`answer`], it reads at most
/// [`MAX_REQUEST`] bytes.
#[cfg_attr(not(any(test, fuzzing)), allow(dead_code))]
fn process(buf: &[u8], device: &Device) -> Option<Vec<u8>> {
    Reader::default().feed(&buf[..buf.len().min(MAX_REQUEST)], device)
}

/// A request read as it arrives. It keeps its place across reads, so
/// that a client sending a byte at a time costs work in proportion to
/// the bytes sent.
#[derive(Debug, Default)]
struct Reader {
    /// How much of the head was searched for its end.
    searched: usize,
    /// Where the body starts, and how it is framed, once the head is read.
    head: Option<(usize, Framing)>,
    chunks: Dechunker,
}

impl Reader {
    /// The response once `buf`, the request received so far, is complete
    /// or known to be wrong. `buf` only grows between calls. Past
    /// [`MAX_REQUEST`] bytes, there is always a response.
    fn feed(&mut self, buf: &[u8], device: &Device) -> Option<Vec<u8>> {
        let response = self.advance(buf, device);
        if response.is_none() && buf.len() >= MAX_REQUEST {
            return Some(error(Status::PayloadTooLarge));
        }
        response
    }

    fn advance(&mut self, buf: &[u8], device: &Device) -> Option<Vec<u8>> {
        let (start, framing) = match self.head {
            Some(head) => head,
            None => {
                let window = &buf[..buf.len().min(MAX_HEAD + 4)];
                // The end may straddle what was searched and what is new.
                let from = self.searched.saturating_sub(3);
                let Some(end) = head_end(&window[from..]).map(|end| from + end) else {
                    self.searched = window.len();
                    return (buf.len() >= MAX_HEAD + 4).then(|| error(Status::HeadersTooLarge));
                };
                let path = format!("/{}", device.endpoint);
                match parse_head(&buf[..end], &path) {
                    Ok(framing) => *self.head.insert((end, framing)),
                    Err(status) => return Some(error(status)),
                }
            }
        };
        let body = match framing {
            Framing::Length(length) => buf[start..].get(..length)?.to_vec(),
            Framing::Chunked => match self.chunks.feed(&buf[start..]) {
                Ok(body) => body?,
                Err(status) => return Some(error(status)),
            },
        };
        Some(body_response(&body, device))
    }
}

/// Where the body starts: after the blank line that ends the head.
fn head_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|at| at + 4)
}

/// Checks the request line and headers of `head` for a POST of a SOAP
/// envelope to `path`, and returns how the body is framed.
fn parse_head(head: &[u8], path: &str) -> Result<Framing, Status> {
    let head = std::str::from_utf8(head).map_err(|_| Status::BadRequest)?;
    let head = head.strip_suffix("\r\n\r\n").ok_or(Status::BadRequest)?;
    let mut lines = head.split("\r\n");
    let request_line = lines.next().ok_or(Status::BadRequest)?;
    let mut parts = request_line.split(' ');
    let (Some(method), Some(target), Some(version), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(Status::BadRequest);
    };
    if !version.starts_with("HTTP/1.") {
        return Err(Status::BadRequest);
    }
    if version != "HTTP/1.1" {
        return Err(Status::VersionNotSupported);
    }
    if method != "POST" {
        return Err(Status::MethodNotAllowed);
    }
    if target != path {
        return Err(Status::NotFound);
    }

    let mut length = None;
    let mut soap = false;
    let mut encoding = None;
    for (n, line) in lines.enumerate() {
        if n >= MAX_HEADER_LINES {
            return Err(Status::HeadersTooLarge);
        }
        let (name, value) = line.split_once(':').ok_or(Status::BadRequest)?;
        if name.is_empty() || name.contains(|c: char| c.is_ascii_whitespace() || c.is_control()) {
            return Err(Status::BadRequest);
        }
        let value = value.trim_matches([' ', '\t']);
        if name.eq_ignore_ascii_case("content-length") {
            if length.is_some() || value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
                return Err(Status::BadRequest);
            }
            let n = value.parse::<usize>().unwrap_or(usize::MAX);
            if n > MAX_BODY {
                return Err(Status::PayloadTooLarge);
            }
            length = Some(n);
        } else if name.eq_ignore_ascii_case("transfer-encoding") {
            if encoding.is_some() {
                return Err(Status::BadRequest);
            }
            encoding = Some(value);
        } else if name.eq_ignore_ascii_case("content-type") {
            soap = value
                .get(.."application/soap+xml".len())
                .is_some_and(|t| t.eq_ignore_ascii_case("application/soap+xml"));
        }
    }
    let framing = match (encoding, length) {
        // Both would leave the end of the body ambiguous.
        (Some(_), Some(_)) => return Err(Status::BadRequest),
        (Some(encoding), None) if encoding.eq_ignore_ascii_case("chunked") => Framing::Chunked,
        (Some(_), None) => return Err(Status::NotImplemented),
        (None, Some(length)) => Framing::Length(length),
        (None, None) => return Err(Status::LengthRequired),
    };
    if !soap {
        return Err(Status::BadRequest);
    }
    Ok(framing)
}

/// A chunked body read as it arrives, keeping its place across reads.
/// Chunk extensions and trailers are skipped.
#[derive(Debug, Default)]
struct Dechunker {
    /// Offset of the first byte not consumed.
    pos: usize,
    /// How far the current line was searched for its end.
    searched: usize,
    state: Chunk,
    body: Vec<u8>,
    trailers: usize,
}

#[derive(Debug, Default, Clone, Copy)]
enum Chunk {
    #[default]
    Size,
    /// A chunk of this many bytes, then CRLF.
    Data(usize),
    Trailers,
}

impl Dechunker {
    /// Continues with `data`, the body received so far, which only grows
    /// between calls. Returns the body once its last chunk and trailers
    /// are read, `Ok(None)` while more is needed.
    fn feed(&mut self, data: &[u8]) -> Result<Option<Vec<u8>>, Status> {
        loop {
            match self.state {
                Chunk::Size => {
                    let Some(line) = self.line(data, MAX_CHUNK_LINE)? else {
                        return Ok(None);
                    };
                    let size = chunk_size(line)?;
                    self.state = if size == 0 {
                        Chunk::Trailers
                    } else if size > MAX_BODY - self.body.len() {
                        return Err(Status::PayloadTooLarge);
                    } else {
                        Chunk::Data(size)
                    };
                }
                Chunk::Data(size) => {
                    let Some(chunk) = data.get(self.pos..self.pos + size + 2) else {
                        return Ok(None);
                    };
                    if !chunk.ends_with(b"\r\n") {
                        return Err(Status::BadRequest);
                    }
                    self.body.extend_from_slice(&chunk[..size]);
                    self.pos += size + 2;
                    self.searched = self.pos;
                    self.state = Chunk::Size;
                }
                Chunk::Trailers => {
                    let Some(line) = self.line(data, MAX_HEAD)? else {
                        return Ok(None);
                    };
                    if line.is_empty() {
                        return Ok(Some(std::mem::take(&mut self.body)));
                    }
                    self.trailers += 1;
                    if self.trailers > MAX_HEADER_LINES {
                        return Err(Status::HeadersTooLarge);
                    }
                }
            }
        }
    }

    /// The next line of `data` without its CRLF, consumed, `Ok(None)`
    /// while its end is missing, or an error when it is longer than `max`.
    fn line<'a>(&mut self, data: &'a [u8], max: usize) -> Result<Option<&'a [u8]>, Status> {
        let start = self.pos;
        let limit = data.len().min(start + max + 2);
        // A CR searched last time may be followed by a new LF.
        let from = self.searched.saturating_sub(1).max(start);
        match data[from..limit].windows(2).position(|w| w == b"\r\n") {
            Some(at) => {
                let end = from + at;
                self.pos = end + 2;
                self.searched = self.pos;
                Ok(Some(&data[start..end]))
            }
            None if limit - start >= max + 2 => Err(Status::BadRequest),
            None => {
                self.searched = limit;
                Ok(None)
            }
        }
    }
}

/// The size on a chunk size line: 1 to 8 hex digits, then any extensions.
fn chunk_size(line: &[u8]) -> Result<usize, Status> {
    let size = line.split(|&b| b == b';').next().unwrap_or_default();
    let size = size.trim_ascii();
    if !(1..=8).contains(&size.len()) || !size.iter().all(u8::is_ascii_hexdigit) {
        return Err(Status::BadRequest);
    }
    let size = std::str::from_utf8(size).map_err(|_| Status::BadRequest)?;
    usize::from_str_radix(size, 16).map_err(|_| Status::BadRequest)
}

/// The response to the body of a request that passed [`parse_head`].
fn body_response(body: &[u8], device: &Device) -> Vec<u8> {
    match msg::read_get(body, device.endpoint) {
        Ok(message_id) => {
            let envelope = msg::get_response(device, Uuid::new_v4(), &message_id);
            response(Status::Ok, envelope.as_bytes())
        }
        Err(_) => error(Status::BadRequest),
    }
}

fn error(status: Status) -> Vec<u8> {
    response(status, b"")
}

fn response(status: Status, body: &[u8]) -> Vec<u8> {
    let mut out = format!("HTTP/1.1 {}\r\n", status.line());
    if !body.is_empty() {
        out.push_str("Content-Type: application/soap+xml\r\n");
    }
    out.push_str(&format!(
        "Content-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    ));
    let mut out = out.into_bytes();
    out.extend_from_slice(body);
    out
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, SocketAddr};

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    use super::*;
    use crate::discovery::wsd::msg::tests::{elements, text};
    use crate::discovery::wsd::samples;

    const PUB: &str = "http://schemas.microsoft.com/windows/pub/2005/07";

    fn status(response: &[u8]) -> &str {
        let line = response.split(|&b| b == b'\r').next().unwrap();
        std::str::from_utf8(&line[b"HTTP/1.1 ".len()..]).unwrap()
    }

    fn body(response: &[u8]) -> &str {
        let end = head_end(response).expect("head");
        std::str::from_utf8(&response[end..]).unwrap()
    }

    /// The sample request with `from` replaced by `to` in its head.
    fn edited(from: &str, to: &str) -> Vec<u8> {
        let request = String::from_utf8(samples::get_request()).unwrap();
        let (head, body) = request.split_once("\r\n\r\n").unwrap();
        assert!(head.contains(from), "{from}");
        format!("{}\r\n\r\n{body}", head.replacen(from, to, 1)).into_bytes()
    }

    #[test]
    fn the_windows_get_is_answered_with_the_metadata() {
        let response = respond(&samples::get_request(), &samples::device());
        assert_eq!(status(&response), "200 OK");
        let head = std::str::from_utf8(&response[..head_end(&response).unwrap()]).unwrap();
        assert!(head.contains("\r\nContent-Type: application/soap+xml\r\n"));
        assert!(head.contains(&format!(
            "\r\nContent-Length: {}\r\n",
            body(&response).len()
        )));
        assert!(head.contains("\r\nConnection: close\r\n"));
        let metadata = elements(body(&response));
        assert_eq!(
            text(&metadata, PUB, "Computer"),
            "FILES/Workgroup:WORKGROUP"
        );
    }

    #[test]
    fn bad_requests_get_an_error_status() {
        let device = samples::device();
        let big = format!("X-Pad: {}", "a".repeat(MAX_HEAD));
        let many: String = (0..MAX_HEADER_LINES)
            .map(|n| format!("X-{n}: 1\r\n"))
            .collect();
        let length = format!("Content-Length: {}", samples::GET.len());
        let with_length = |value: &str| edited(&length, &format!("Content-Length: {value}"));
        let cases = [
            (edited("POST /", "POST /x"), "404 Not Found"),
            (edited("POST /", "GET /"), "405 Method Not Allowed"),
            (
                edited("HTTP/1.1", "HTTP/1.0"),
                "505 HTTP Version Not Supported",
            ),
            (edited("HTTP/1.1", "HTTP/2"), "400 Bad Request"),
            (edited("POST /", "POST  /"), "400 Bad Request"),
            (
                edited("application/soap+xml", "text/xml"),
                "400 Bad Request",
            ),
            (
                edited("Content-Type: application/soap+xml\r\n", ""),
                "400 Bad Request",
            ),
            (edited("Content-Length", "X-Length"), "411 Length Required"),
            (
                edited(
                    "Content-Length",
                    "Transfer-Encoding: chunked\r\nContent-Length",
                ),
                "400 Bad Request",
            ),
            (
                edited(&length, "Transfer-Encoding: gzip"),
                "501 Not Implemented",
            ),
            (with_length("32768"), "413 Content Too Large"),
            (
                with_length("99999999999999999999999"),
                "413 Content Too Large",
            ),
            (
                with_length(&format!("+{}", samples::GET.len())),
                "400 Bad Request",
            ),
            (with_length(""), "400 Bad Request"),
            (
                edited(&length, &format!("{length}\r\n{length}")),
                "400 Bad Request",
            ),
            (
                with_length(&(samples::GET.len() + 1).to_string()),
                "400 Bad Request",
            ),
            (edited("User-Agent", " User-Agent"), "400 Bad Request"),
            (
                edited("Pragma: no-cache", &big),
                "431 Request Header Fields Too Large",
            ),
            (
                edited("Pragma: no-cache\r\n", &many),
                "431 Request Header Fields Too Large",
            ),
            (
                String::from_utf8(samples::get_request())
                    .unwrap()
                    .replacen("transfer/Get", "transfer/Put", 1)
                    .into_bytes(),
                "400 Bad Request",
            ),
        ];
        for (request, expected) in cases {
            let response = respond(&request, &device);
            assert_eq!(
                status(&response),
                expected,
                "{}",
                String::from_utf8_lossy(&request)
            );
            assert!(body(&response).is_empty());
        }
    }

    /// The sample request with its body sent in `chunks`, each line of
    /// it followed by CRLF, and `tail` after the body.
    fn chunked(chunks: &[&str], tail: &str) -> Vec<u8> {
        let request = String::from_utf8(samples::get_request()).unwrap();
        let (head, _) = request.split_once("\r\n\r\n").unwrap();
        let length = format!("Content-Length: {}", samples::GET.len());
        let head = head.replacen(&length, "Transfer-Encoding: chunked", 1);
        let mut out = format!("{head}\r\n\r\n");
        for chunk in chunks {
            out.push_str(chunk);
            out.push_str("\r\n");
        }
        out.push_str(tail);
        out.into_bytes()
    }

    #[test]
    fn chunked_bodies_are_read_within_the_caps() {
        let device = samples::device();
        let (a, b) = samples::GET.split_at(300);
        let size = |s: &str| format!("{:x}", s.len());
        let sizes = (size(a), size(b));
        let ok = chunked(
            &[&sizes.0, a, &format!("{};ext=1", sizes.1), b, "0"],
            "\r\n",
        );
        assert_eq!(status(&respond(&ok, &device)), "200 OK");
        let trailers = chunked(&[&sizes.0, a, &sizes.1, b, "0", "X-Trailer: 1"], "\r\n");
        assert_eq!(status(&respond(&trailers, &device)), "200 OK");

        let cases = [
            (chunked(&[&sizes.0, a, "0"], ""), "400 Bad Request"),
            (chunked(&["123456789", a, "0"], "\r\n"), "400 Bad Request"),
            (chunked(&["8000"], ""), "413 Content Too Large"),
            (
                chunked(&[&size(&format!("{a}x")), a, "0"], "\r\n"),
                "400 Bad Request",
            ),
            (chunked(&[&"1;".repeat(40)], ""), "400 Bad Request"),
            (chunked(&["+1a", a, "0"], "\r\n"), "400 Bad Request"),
            // A size past what is left once a chunk was read: an overflow
            // on 32-bit targets if added to the body length.
            (
                chunked(&["1", "x", "ffffffff"], ""),
                "413 Content Too Large",
            ),
            (
                chunked(&["7fff", &"x".repeat(0x7fff), "1"], ""),
                "413 Content Too Large",
            ),
        ];
        for (request, expected) in cases {
            let response = respond(&request, &device);
            assert_eq!(
                status(&response),
                expected,
                "{}",
                String::from_utf8_lossy(&request)
            );
        }
    }

    /// A chunked request longer than [`MAX_REQUEST`] whose body is not
    /// over [`MAX_BODY`]: one-byte chunks cost six bytes each.
    fn over_long() -> Vec<u8> {
        let tiny: Vec<String> = std::iter::repeat_n(["1".to_string(), " ".to_string()], 13_000)
            .flatten()
            .collect();
        let tiny: Vec<&str> = tiny.iter().map(String::as_str).collect();
        let request = chunked(&tiny, "0\r\n\r\n");
        assert!(request.len() > MAX_REQUEST);
        request
    }

    #[tokio::test]
    async fn an_over_long_request_gets_413() {
        let device = samples::device();
        let request = over_long();
        assert_eq!(status(&respond(&request, &device)), "413 Content Too Large");

        let (client, mut server) = tokio::io::duplex(1 << 16);
        let (mut from_server, mut to_server) = tokio::io::split(client);
        let writer = tokio::spawn(async move {
            let _ = to_server.write_all(&request).await;
        });
        answer(&mut server, &device).await.unwrap();
        drop(server);
        let mut response = Vec::new();
        from_server.read_to_end(&mut response).await.unwrap();
        assert_eq!(status(&response), "413 Content Too Large");
        writer.await.unwrap();
    }

    #[test]
    fn a_request_read_a_byte_at_a_time_is_answered_at_its_end() {
        let device = samples::device();
        let (a, b) = samples::GET.split_at(300);
        let sizes = (format!("{:x}", a.len()), format!("{:x}", b.len()));
        let request = chunked(&[&sizes.0, a, &sizes.1, b, "0", "X-Trailer: 1"], "\r\n");
        for whole in [request, samples::get_request()] {
            let mut reader = Reader::default();
            for n in 1..whole.len() {
                assert_eq!(reader.feed(&whole[..n], &device), None, "{n}");
            }
            let response = reader.feed(&whole, &device).expect("answered");
            assert_eq!(status(&response), "200 OK");
        }
    }

    #[test]
    fn content_type_parameters_are_accepted() {
        let request = edited(
            "application/soap+xml",
            "Application/SOAP+XML; charset=utf-8",
        );
        assert_eq!(status(&respond(&request, &samples::device())), "200 OK");
    }

    fn loopback(networks: &str) -> Link {
        let (ip, len) = networks.split_once('/').unwrap();
        Link {
            index: 1,
            addr: "127.0.0.1".parse().unwrap(),
            networks: vec![(ip.parse::<IpAddr>().unwrap(), len.parse().unwrap())],
        }
    }

    /// A metadata endpoint serving on loopback.
    struct Endpoint {
        addr: SocketAddr,
        task: tokio::task::JoinHandle<()>,
        slots: Arc<Semaphore>,
        link: watch::Sender<Arc<Link>>,
        stop: watch::Sender<bool>,
    }

    async fn endpoint(link: Link) -> Endpoint {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let slots = Arc::new(Semaphore::new(MAX_CONNECTIONS));
        let (link, link_rx) = watch::channel(Arc::new(link));
        let (stop, stop_rx) = watch::channel(false);
        let task = tokio::spawn(serve(
            listener,
            link_rx,
            Arc::new(samples::device()),
            slots.clone(),
            stop_rx,
        ));
        Endpoint {
            addr,
            task,
            slots,
            link,
            stop,
        }
    }

    /// Waits until `slots` has `free` permits.
    async fn wait_for_free(slots: &Semaphore, free: usize) {
        tokio::time::timeout(Duration::from_secs(10), async {
            while slots.available_permits() != free {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("slots");
    }

    /// Sends `request` and reads the response, empty when the connection
    /// is closed or reset without one.
    async fn exchange(addr: SocketAddr, request: &[u8]) -> Vec<u8> {
        let mut stream = TcpStream::connect(addr).await.unwrap();
        let mut response = Vec::new();
        if stream.write_all(request).await.is_ok() {
            let read =
                tokio::time::timeout(Duration::from_secs(10), stream.read_to_end(&mut response));
            let _ = read.await.expect("answered");
        }
        response
    }

    #[tokio::test]
    async fn the_endpoint_answers_over_tcp_and_closes() {
        let endpoint = endpoint(loopback("127.0.0.1/8")).await;
        // The request in pieces, with the body after the head.
        let request = samples::get_request();
        let mut stream = TcpStream::connect(endpoint.addr).await.unwrap();
        for piece in request.chunks(100) {
            stream.write_all(piece).await.unwrap();
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        let mut response = Vec::new();
        stream.read_to_end(&mut response).await.unwrap();
        assert_eq!(status(&response), "200 OK");
        endpoint.task.abort();
    }

    #[tokio::test]
    async fn peers_off_the_current_link_are_refused() {
        let endpoint = endpoint(loopback("10.0.0.1/8")).await;
        assert!(
            exchange(endpoint.addr, &samples::get_request())
                .await
                .is_empty()
        );
        endpoint
            .link
            .send_replace(Arc::new(loopback("127.0.0.1/8")));
        let response = exchange(endpoint.addr, &samples::get_request()).await;
        assert_eq!(status(&response), "200 OK");
        endpoint.task.abort();
    }

    #[tokio::test]
    async fn stopping_closes_the_listener_and_its_connections() {
        let endpoint = endpoint(loopback("127.0.0.1/8")).await;
        let mut idle = TcpStream::connect(endpoint.addr).await.unwrap();
        wait_for_free(&endpoint.slots, MAX_CONNECTIONS - 1).await;
        endpoint.stop.send_replace(true);
        tokio::time::timeout(Duration::from_secs(10), endpoint.task)
            .await
            .expect("stopped")
            .unwrap();
        assert_eq!(endpoint.slots.available_permits(), MAX_CONNECTIONS);
        let mut rest = Vec::new();
        let _ = idle.read_to_end(&mut rest).await;
        assert!(rest.is_empty());
        // The port is free again.
        TcpListener::bind(endpoint.addr).await.expect("rebind");
    }

    #[tokio::test]
    async fn connections_past_the_limit_are_closed() {
        let endpoint = endpoint(loopback("127.0.0.1/8")).await;
        let (addr, slots) = (endpoint.addr, &endpoint.slots);
        let mut idle = Vec::new();
        for _ in 0..MAX_CONNECTIONS {
            idle.push(TcpStream::connect(addr).await.unwrap());
        }
        wait_for_free(slots, 0).await;
        assert!(exchange(addr, &samples::get_request()).await.is_empty());
        drop(idle);
        wait_for_free(slots, MAX_CONNECTIONS).await;
        let response = exchange(addr, &samples::get_request()).await;
        assert_eq!(status(&response), "200 OK");
        endpoint.task.abort();
    }

    #[tokio::test(start_paused = true)]
    async fn a_slow_client_is_cut_off() {
        let (mut client, mut server) = tokio::io::duplex(1 << 16);
        let request = samples::get_request();
        client
            .write_all(&request[..request.len() - 1])
            .await
            .unwrap();
        let start = tokio::time::Instant::now();
        let answered = answer_in_time(&mut server, &samples::device()).await;
        assert!(answered.is_err());
        assert_eq!(start.elapsed(), REQUEST_TIMEOUT);
    }
}
