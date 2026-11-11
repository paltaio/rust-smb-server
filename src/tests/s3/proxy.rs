//! An HTTP proxy between a client and the gateway. It passes requests along
//! and fails the ones it is told to.
//!
//! The proxy serves one request per connection and answers with
//! `Connection: close`, so every request of a client opens a connection.

use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Notify;
use tokio::task::{JoinHandle, JoinSet};

const HEAD_END: &[u8] = b"\r\n\r\n";

/// What the proxy does with a request it was told to fail.
#[derive(Debug, Clone)]
pub(super) enum Fault {
    /// Answers with this response; the gateway never sees the request.
    Reply(Reply),
    /// Passes the request on, then closes the connection without an answer.
    DropAnswer,
    /// Passes the request on and sends the head of the answer and half of its
    /// body, then closes the connection.
    CutBody,
    /// Passes the request on and sends the head of the answer and half of its
    /// body, then sends nothing more.
    StallBody,
    /// Sends the head of this response and half of its body, then closes the
    /// connection. The gateway never sees the request.
    CutReply(Reply),
    /// Answers with this response as soon as the head of the request is in,
    /// then reads the rest of the request slowly until the client closes the
    /// connection. The recorded request has no body.
    AnswerEarly(Reply),
    /// Reads the request and never answers.
    Stall,
    /// Waits until the `Notify` is notified, then passes the request on as usual.
    Hold(Arc<Notify>),
    /// Waits until the `Notify` is notified, then answers with this response.
    /// The gateway never sees the request.
    HoldReply(Arc<Notify>, Reply),
}

/// A canned response.
#[derive(Debug, Clone)]
pub(super) struct Reply {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
    /// The `Content-Length` to send when it is not the length of the body, as
    /// for the answer to a HEAD.
    declared_length: Option<usize>,
}

impl Reply {
    pub(super) fn new(status: u16, body: impl Into<Vec<u8>>) -> Self {
        Reply {
            status,
            headers: Vec::new(),
            body: body.into(),
            declared_length: None,
        }
    }

    /// Sends `length` as the `Content-Length`.
    pub(super) fn declaring(mut self, length: usize) -> Self {
        self.declared_length = Some(length);
        self
    }

    pub(super) fn header(mut self, name: &str, value: &str) -> Self {
        self.headers.push((name.to_owned(), value.to_owned()));
        self
    }

    /// An S3 error document with `code`.
    pub(super) fn error(status: u16, code: &str) -> Self {
        Reply::new(
            status,
            format!(
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<Error><Code>{code}</Code>\
                 <Message>refused</Message><RequestId>PROXYREQ</RequestId></Error>"
            ),
        )
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut out = format!("HTTP/1.1 {} Canned\r\n", self.status).into_bytes();
        for (name, value) in &self.headers {
            out.extend_from_slice(format!("{name}: {value}\r\n").as_bytes());
        }
        out.extend_from_slice(
            format!(
                "Content-Length: {}\r\nConnection: close\r\n\r\n",
                self.declared_length.unwrap_or(self.body.len())
            )
            .as_bytes(),
        );
        out.extend_from_slice(&self.body);
        out
    }
}

/// A request the proxy received.
#[derive(Debug, Clone)]
pub(super) struct Seen {
    pub(super) method: String,
    /// The path and query as sent.
    pub(super) target: String,
    /// Header names in lowercase.
    headers: Vec<(String, String)>,
    pub(super) body: Vec<u8>,
}

impl Seen {
    fn parse(head: &[u8]) -> Seen {
        let text = String::from_utf8_lossy(head);
        let mut lines = text.split("\r\n");
        let mut request_line = lines.next().unwrap_or_default().split(' ');
        let method = request_line.next().unwrap_or_default().to_owned();
        let target = request_line.next().unwrap_or_default().to_owned();
        let headers = lines
            .filter_map(|line| line.split_once(':'))
            .map(|(name, value)| (name.trim().to_ascii_lowercase(), value.trim().to_owned()))
            .collect();
        Seen {
            method,
            target,
            headers,
            body: Vec::new(),
        }
    }

    /// The value of the header `name`, given in lowercase.
    pub(super) fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(header, _)| header == name)
            .map(|(_, value)| value.as_str())
    }

    /// Every header as a lowercase name and its value.
    pub(super) fn headers(&self) -> impl Iterator<Item = (&str, &str)> {
        self.headers
            .iter()
            .map(|(name, value)| (name.as_str(), value.as_str()))
    }

    pub(super) fn query(&self) -> &str {
        self.target.split_once('?').map_or("", |(_, query)| query)
    }

    /// Whether the query has the parameter `name`, with or without a value.
    pub(super) fn has_param(&self, name: &str) -> bool {
        self.query()
            .split('&')
            .any(|pair| pair.split_once('=').map_or(pair, |(key, _)| key) == name)
    }
}

struct Rule {
    matches: Box<dyn Fn(&Seen) -> bool + Send + Sync>,
    fault: Fault,
    remaining: usize,
}

struct State {
    upstream: SocketAddr,
    seen: Mutex<Vec<Seen>>,
    rules: Mutex<Vec<Rule>>,
    /// Connections whose request the client did not finish.
    aborted: AtomicUsize,
}

impl State {
    /// The fault for `seen`, if a rule has one left.
    fn take_fault(&self, seen: &Seen) -> Option<Fault> {
        let mut rules = self.rules.lock().unwrap();
        rules
            .iter_mut()
            .find(|rule| rule.remaining > 0 && (rule.matches)(seen))
            .map(|rule| {
                rule.remaining -= 1;
                rule.fault.clone()
            })
    }
}

/// A proxy on loopback that forwards to one upstream address. It stops when
/// dropped.
pub(super) struct Proxy {
    pub(super) addr: SocketAddr,
    state: Arc<State>,
    accepting: JoinHandle<()>,
}

impl Proxy {
    pub(super) async fn start(upstream: SocketAddr) -> Proxy {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let state = Arc::new(State {
            upstream,
            seen: Mutex::new(Vec::new()),
            rules: Mutex::new(Vec::new()),
            aborted: AtomicUsize::new(0),
        });
        let accepting = tokio::spawn(accept(listener, state.clone()));
        Proxy {
            addr,
            state,
            accepting,
        }
    }

    /// Applies `fault` to the next `times` requests that `matches`, on top of
    /// the faults of earlier rules.
    pub(super) fn inject(
        &self,
        matches: impl Fn(&Seen) -> bool + Send + Sync + 'static,
        fault: Fault,
        times: usize,
    ) {
        self.state.rules.lock().unwrap().push(Rule {
            matches: Box::new(matches),
            fault,
            remaining: times,
        });
    }

    /// Drops every rule, spent or not.
    pub(super) fn clear_rules(&self) {
        self.state.rules.lock().unwrap().clear();
    }

    /// Every request received so far, in order of arrival.
    pub(super) fn seen(&self) -> Vec<Seen> {
        self.state.seen.lock().unwrap().clone()
    }

    /// The number of connections on which the client closed before it had sent
    /// a whole request. Such a request is neither recorded nor passed on.
    pub(super) fn aborted(&self) -> usize {
        self.state.aborted.load(Ordering::SeqCst)
    }

    /// The number of requests received so far that `matches`.
    pub(super) fn count(&self, matches: impl Fn(&Seen) -> bool) -> usize {
        self.seen().iter().filter(|seen| matches(seen)).count()
    }
}

impl Drop for Proxy {
    fn drop(&mut self) {
        self.accepting.abort();
    }
}

/// Accepts connections until aborted. The connections end with it.
async fn accept(listener: TcpListener, state: Arc<State>) {
    let mut connections = JoinSet::new();
    while let Ok((stream, _)) = listener.accept().await {
        let state = state.clone();
        connections.spawn(async move {
            let _ = serve(&state, stream).await;
        });
        while connections.try_join_next().is_some() {}
    }
}

async fn serve(state: &State, mut client: TcpStream) -> io::Result<()> {
    let Ok(Some((head, read))) = read_head(&mut client).await else {
        state.aborted.fetch_add(1, Ordering::SeqCst);
        return Ok(());
    };
    let mut seen = Seen::parse(&head);
    let fault = state.take_fault(&seen);
    let body = if matches!(fault, Some(Fault::AnswerEarly(_))) {
        Vec::new()
    } else {
        let Ok(Some(body)) = read_body(&mut client, &head, read).await else {
            state.aborted.fetch_add(1, Ordering::SeqCst);
            return Ok(());
        };
        body
    };
    seen.body.clone_from(&body);
    state.seen.lock().unwrap().push(seen);
    match fault {
        Some(Fault::Reply(reply)) => client.write_all(&reply.to_bytes()).await?,
        Some(Fault::AnswerEarly(reply)) => {
            client.write_all(&reply.to_bytes()).await?;
            return read_slowly(&mut client).await;
        }
        Some(Fault::CutReply(reply)) => {
            let answer = reply.to_bytes();
            client.write_all(&answer[..halfway(&answer)]).await?;
        }
        Some(Fault::Stall) => wait_for_close(&mut client).await?,
        Some(Fault::DropAnswer) => {
            pass(state.upstream, &head, &body).await?;
            return Ok(());
        }
        Some(Fault::CutBody) => {
            let answer = pass(state.upstream, &head, &body).await?;
            client.write_all(&answer[..halfway(&answer)]).await?;
        }
        Some(Fault::StallBody) => {
            let answer = pass(state.upstream, &head, &body).await?;
            client.write_all(&answer[..halfway(&answer)]).await?;
            client.flush().await?;
            wait_for_close(&mut client).await?;
        }
        Some(Fault::Hold(gate)) => {
            gate.notified().await;
            client
                .write_all(&pass(state.upstream, &head, &body).await?)
                .await?
        }
        Some(Fault::HoldReply(gate, reply)) => {
            gate.notified().await;
            client.write_all(&reply.to_bytes()).await?;
        }
        None => {
            client
                .write_all(&pass(state.upstream, &head, &body).await?)
                .await?
        }
    }
    client.shutdown().await
}

/// The length of the head of `answer` and the first half of its body.
fn halfway(answer: &[u8]) -> usize {
    let body_start = find(answer, HEAD_END).map_or(0, |i| i + HEAD_END.len());
    body_start + (answer.len() - body_start) / 2
}

async fn wait_for_close(client: &mut TcpStream) -> io::Result<()> {
    while client.read(&mut [0; 1]).await? > 0 {}
    Ok(())
}

/// Reads what the client sends, 16 KiB every 20 ms, until it closes.
async fn read_slowly(client: &mut TcpStream) -> io::Result<()> {
    let mut chunk = [0; 16 * 1024];
    while client.read(&mut chunk).await? > 0 {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    Ok(())
}

/// Reads the head of a request. Returns it with the bytes after it that came
/// in with it, or `None` when the client closes before the head is complete.
async fn read_head(client: &mut TcpStream) -> io::Result<Option<(Vec<u8>, Vec<u8>)>> {
    let mut buffer = Vec::new();
    let mut chunk = vec![0; 64 * 1024];
    let head_end = loop {
        if let Some(i) = find(&buffer, HEAD_END) {
            break i + HEAD_END.len();
        }
        match client.read(&mut chunk).await? {
            0 => return Ok(None),
            n => buffer.extend_from_slice(&chunk[..n]),
        }
    };
    let read = buffer.split_off(head_end);
    Ok(Some((buffer, read)))
}

/// Reads the body of the request with this `head`, as long as `Content-Length`
/// says. `body` holds what came in after the head. `None` when the client
/// closes before the body is complete.
async fn read_body(
    client: &mut TcpStream,
    head: &[u8],
    mut body: Vec<u8>,
) -> io::Result<Option<Vec<u8>>> {
    let length = String::from_utf8_lossy(head)
        .split("\r\n")
        .filter_map(|line| line.split_once(':'))
        .find(|(name, _)| name.trim().eq_ignore_ascii_case("content-length"))
        .map_or(Ok(0), |(_, value)| value.trim().parse())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "bad Content-Length"))?;
    let mut chunk = vec![0; 64 * 1024];
    while body.len() < length {
        match client.read(&mut chunk).await? {
            0 => return Ok(None),
            n => body.extend_from_slice(&chunk[..n]),
        }
    }
    body.truncate(length);
    Ok(Some(body))
}

/// Sends a request to the upstream and returns its whole answer. The request
/// carries `Connection: close`, so the answer ends when the upstream closes.
async fn pass(upstream: SocketAddr, head: &[u8], body: &[u8]) -> io::Result<Vec<u8>> {
    let mut stream = TcpStream::connect(upstream).await?;
    stream.write_all(&close_after(head)).await?;
    stream.write_all(body).await?;
    let mut answer = Vec::new();
    tokio::time::timeout(Duration::from_secs(60), stream.read_to_end(&mut answer))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "the upstream did not close"))??;
    Ok(close_after(&answer))
}

/// A message with `Connection: close` as its only `Connection` header.
fn close_after(message: &[u8]) -> Vec<u8> {
    let head_end = find(message, HEAD_END).unwrap_or(message.len());
    let head = String::from_utf8_lossy(&message[..head_end]);
    let mut out: Vec<u8> = Vec::with_capacity(message.len() + 20);
    for line in head
        .split("\r\n")
        .filter(|line| !line.to_ascii_lowercase().starts_with("connection:"))
    {
        out.extend_from_slice(line.as_bytes());
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(b"Connection: close\r\n\r\n");
    out.extend_from_slice(message.get(head_end + HEAD_END.len()..).unwrap_or_default());
    out
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

mod tests {
    use super::*;

    #[test]
    fn parses_a_request_head() {
        let head = b"PUT /bucket/a%20b?partNumber=1&uploadId=x&flag HTTP/1.1\r\nHost: h\r\nX-Amz-Date: d\r\n\r\n";
        let seen = Seen::parse(head);
        assert_eq!(seen.method, "PUT");
        assert_eq!(seen.query(), "partNumber=1&uploadId=x&flag");
        assert_eq!(seen.header("x-amz-date"), Some("d"));
        assert_eq!(seen.header("missing"), None);
        assert!(seen.has_param("uploadId") && seen.has_param("flag"));
        assert!(!seen.has_param("upload") && !seen.has_param("x"));
    }
}
