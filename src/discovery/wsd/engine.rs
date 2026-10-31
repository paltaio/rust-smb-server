//! The target service without sockets: datagrams in, replies out.

use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use tokio::time::Instant;
use uuid::Uuid;

use super::msg::{self, Header, Kind, Sequence};
use crate::discovery::Device;

/// Longest datagram read: DPWS lets receivers reject longer ones.
pub(super) const MAX_DATAGRAM: usize = 4096;

/// Longest random wait before a Hello or a ProbeMatches, in milliseconds.
const APP_MAX_DELAY_MS: u64 = 500;

/// Copies of a multicast and of a unicast message: SOAP-over-UDP's
/// example transmission algorithm, as in the 2004 draft that Windows
/// follows.
pub(super) const MULTICAST_COPIES: usize = 4;
pub(super) const UNICAST_COPIES: usize = 2;

/// Requests remembered per interface to answer each MessageID once.
const SEEN_PER_INTERFACE: usize = 64;
const SEEN_FOR: Duration = Duration::from_secs(10);

/// Most datagrams read a second from one address.
const REQUESTS_PER_SOURCE: u32 = 50;
/// Most replies a second to one address, and to all of them.
const REPLIES_PER_SOURCE: u32 = 10;
const REPLIES_OVERALL: u32 = 100;
const RATE_WINDOW: Duration = Duration::from_secs(1);
/// Most addresses whose replies are counted at once. Past it, requests
/// from new addresses go unanswered until a window ends.
const MAX_SOURCES: usize = 256;

/// One interface and address family the server answers on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Link {
    pub(super) index: u32,
    /// The address replies come from, and the metadata endpoint's.
    pub(super) addr: IpAddr,
    /// The networks of the interface's addresses in that family, as
    /// address and prefix length.
    pub(super) networks: Vec<(IpAddr, u8)>,
}

impl Link {
    /// Whether `ip` is on one of the link's networks, or a link-local
    /// address.
    pub(super) fn on_link(&self, ip: IpAddr) -> bool {
        match ip.to_canonical() {
            IpAddr::V4(v4) => {
                v4.is_link_local()
                    || self.networks.iter().any(|&(net, len)| match net {
                        IpAddr::V4(net) => same_prefix(net.to_bits(), v4.to_bits(), len),
                        IpAddr::V6(_) => false,
                    })
            }
            IpAddr::V6(v6) => {
                v6.is_unicast_link_local()
                    || self.networks.iter().any(|&(net, len)| match net {
                        IpAddr::V6(net) => same_prefix(net.to_bits(), v6.to_bits(), len),
                        IpAddr::V4(_) => false,
                    })
            }
        }
    }
}

/// Whether `a` and `b` agree in their first `len` bits. A zero length
/// matches nothing, so that no default route makes every address local.
fn same_prefix<T>(a: T, b: T, len: u8) -> bool
where
    T: std::ops::BitXor<Output = T> + std::ops::Shr<u32, Output = T> + PartialEq + From<u8>,
{
    let bits = u32::try_from(std::mem::size_of::<T>() * 8).unwrap_or(u32::MAX);
    let len = u32::from(len);
    len != 0 && len <= bits && (a ^ b) >> (bits - len) == T::from(0)
}

/// A reply to send to the sender of a request.
#[derive(Debug)]
pub(super) struct Reply {
    pub(super) to: SocketAddr,
    pub(super) message: Vec<u8>,
    /// Sent after a random wait of up to 500 ms.
    pub(super) delayed: bool,
}

/// What was counted in one window: for one sender, the datagrams read
/// from it and the replies sent to it; for all senders, the replies.
#[derive(Debug, Clone, Copy)]
struct Window {
    start: Instant,
    requests: u32,
    replies: u32,
}

impl Window {
    fn new(now: Instant) -> Self {
        Self {
            start: now,
            requests: 0,
            replies: 0,
        }
    }

    fn ended(&self, now: Instant) -> bool {
        now.duration_since(self.start) >= RATE_WINDOW
    }

    /// The window, started again when it ended.
    fn current(&mut self, now: Instant) -> &mut Self {
        if self.ended(now) {
            *self = Self::new(now);
        }
        self
    }
}

/// The state of a target service: its sequence and what it answered.
pub(super) struct Engine {
    device: Arc<Device>,
    instance_id: u64,
    sequence_id: Uuid,
    metadata_version: u32,
    next_message: u64,
    /// MessageIDs answered, per interface index.
    seen: HashMap<u32, VecDeque<(String, Instant)>>,
    sources: HashMap<IpAddr, Window>,
    overall: Window,
}

impl Engine {
    /// A service that started at `instance_id`, in seconds since the Unix
    /// epoch, numbering its messages in `sequence_id`. The start time is
    /// also the metadata version: metadata only changes with a restart,
    /// and the version must not go down across restarts.
    pub(super) fn new(
        device: Arc<Device>,
        instance_id: u64,
        sequence_id: Uuid,
        now: Instant,
    ) -> Self {
        Self {
            device,
            instance_id,
            sequence_id,
            metadata_version: u32::try_from(instance_id).unwrap_or(u32::MAX),
            next_message: 1,
            seen: HashMap::new(),
            sources: HashMap::new(),
            overall: Window::new(now),
        }
    }

    fn header<'a>(&mut self, relates_to: Option<&'a str>) -> Header<'a> {
        let message_number = self.next_message;
        self.next_message += 1;
        Header {
            message_id: Uuid::new_v4(),
            sequence: Sequence {
                instance_id: self.instance_id,
                sequence_id: self.sequence_id,
                message_number,
            },
            relates_to,
            metadata_version: self.metadata_version,
        }
    }

    /// A Hello for the server at `xaddr`.
    pub(super) fn hello(&mut self, xaddr: &str) -> Vec<u8> {
        let header = self.header(None);
        msg::hello(&self.device, xaddr, &header).into_bytes()
    }

    pub(super) fn bye(&mut self) -> Vec<u8> {
        let header = self.header(None);
        msg::bye(&self.device, &header).into_bytes()
    }

    /// The current window of sender `ip`, or `None` when [`MAX_SOURCES`]
    /// other senders are being counted.
    fn source(&mut self, now: Instant, ip: IpAddr) -> Option<&mut Window> {
        if !self.sources.contains_key(&ip) && self.sources.len() >= MAX_SOURCES {
            self.sources.retain(|_, window| !window.ended(now));
            if self.sources.len() >= MAX_SOURCES {
                return None;
            }
        }
        let window = self.sources.entry(ip).or_insert_with(|| Window::new(now));
        Some(window.current(now))
    }

    /// Counts a datagram from `ip` about to be read, or returns false when
    /// the sender sent [`REQUESTS_PER_SOURCE`] in the window.
    fn admit(&mut self, now: Instant, ip: IpAddr) -> bool {
        let Some(source) = self.source(now, ip) else {
            return false;
        };
        if source.requests >= REQUESTS_PER_SOURCE {
            return false;
        }
        source.requests += 1;
        true
    }

    /// The header of a reply to request `message_id` from `ip` on
    /// interface `index`, or `None` when the request was answered there in
    /// the last [`SEEN_FOR`] or a rate limit is reached. The request is
    /// recorded as answered only when it is answered.
    fn reply_header<'a>(
        &mut self,
        now: Instant,
        index: u32,
        ip: IpAddr,
        message_id: &'a str,
    ) -> Option<Header<'a>> {
        let seen = self.seen.entry(index).or_default();
        while seen
            .front()
            .is_some_and(|(_, at)| now.duration_since(*at) >= SEEN_FOR)
        {
            seen.pop_front();
        }
        if seen.iter().any(|(id, _)| id == message_id) {
            return None;
        }
        let source = self.source(now, ip)?;
        if source.replies >= REPLIES_PER_SOURCE {
            return None;
        }
        let overall = self.overall.current(now);
        if overall.replies >= REPLIES_OVERALL {
            return None;
        }
        overall.replies += 1;
        if let Some(source) = self.sources.get_mut(&ip) {
            source.replies += 1;
        }
        let seen = self.seen.entry(index).or_default();
        if seen.len() >= SEEN_PER_INTERFACE {
            seen.pop_front();
        }
        seen.push_back((message_id.to_string(), now));
        Some(self.header(Some(message_id)))
    }

    /// Drops the MessageIDs remembered for interface `index`.
    pub(super) fn forget(&mut self, index: u32) {
        self.seen.remove(&index);
    }
}

/// `engine`, locked; a panic while it was held leaves nothing half done.
pub(super) fn lock(engine: &Mutex<Engine>) -> MutexGuard<'_, Engine> {
    engine.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Answers `datagram` from `from`, received on `link`, where the metadata
/// endpoint is `xaddr`. Requests that are malformed, come from off the
/// link, exceed the sender's budget, do not match, repeat an answered
/// MessageID or exceed the rate limits get no reply. The datagram is read
/// without holding `engine`.
pub(super) fn handle(
    engine: &Mutex<Engine>,
    now: Instant,
    link: &Link,
    xaddr: &str,
    from: SocketAddr,
    datagram: &[u8],
) -> Option<Reply> {
    let ip = from.ip().to_canonical();
    if datagram.len() > MAX_DATAGRAM
        || from.port() == 0
        || ip.is_unspecified()
        || ip.is_multicast()
        || !link.on_link(ip)
    {
        return None;
    }
    let device = {
        let mut engine = lock(engine);
        if !engine.admit(now, ip) {
            return None;
        }
        engine.device.clone()
    };
    let request = msg::read_request(datagram)?;
    let matched = match &request.kind {
        Kind::Probe { types, scopes } => msg::matches(types, scopes),
        Kind::Resolve { address } => msg::is_endpoint(address, device.endpoint),
    };
    if !matched {
        return None;
    }
    let header = lock(engine).reply_header(now, link.index, ip, &request.message_id)?;
    let (message, delayed) = match request.kind {
        Kind::Probe { .. } => (msg::probe_matches(&device, xaddr, &header), true),
        Kind::Resolve { .. } => (msg::resolve_matches(&device, xaddr, &header), false),
    };
    Some(Reply {
        to: from,
        message: message.into_bytes(),
        delayed,
    })
}

/// The waits between the copies of a message sent `copies` times: first
/// `first`, a random 50 to 250 ms, then doubling up to 500 ms.
pub(super) fn repeat_delays(copies: usize, first: Duration) -> Vec<Duration> {
    const UPPER: Duration = Duration::from_millis(500);
    let mut delay = first.min(UPPER);
    (1..copies)
        .map(|_| {
            let this = delay;
            delay = (delay * 2).min(UPPER);
            this
        })
        .collect()
}

/// A random first wait for [`repeat_delays`].
pub(super) fn first_repeat_delay() -> Duration {
    Duration::from_millis(50 + random_below(201))
}

/// A random wait of up to 500 ms.
pub(super) fn app_delay() -> Duration {
    Duration::from_millis(random_below(APP_MAX_DELAY_MS + 1))
}

fn random_below(n: u64) -> u64 {
    let mut bytes = [0; 8];
    let _ = crate::utils::fill_random(&mut bytes);
    u64::from_le_bytes(bytes) % n
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::discovery::wsd::msg::tests::{elements, text};
    use crate::discovery::wsd::samples;
    use crate::discovery::wsd::xml::{WSA, WSD};

    const XADDR: &str = "http://192.168.1.10:5357/3f2b8c1e-7a4d-8e5f-9b6c-2d1e0f3a4b5c";

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn from(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    fn v4_link(index: u32) -> Link {
        Link {
            index,
            addr: ip("192.168.1.10"),
            networks: vec![(ip("192.168.1.10"), 24)],
        }
    }

    fn v6_link(index: u32) -> Link {
        Link {
            index,
            addr: ip("fe80::1"),
            networks: vec![(ip("fe80::1"), 64), (ip("2001:db8::10"), 64)],
        }
    }

    /// An engine behind its lock, as the receive loops share it.
    struct Shared(Mutex<Engine>);

    impl Shared {
        fn handle(
            &mut self,
            now: Instant,
            link: &Link,
            xaddr: &str,
            from: SocketAddr,
            datagram: &[u8],
        ) -> Option<Reply> {
            handle(&self.0, now, link, xaddr, from, datagram)
        }

        fn hello(&mut self, xaddr: &str) -> Vec<u8> {
            lock(&self.0).hello(xaddr)
        }

        fn bye(&mut self) -> Vec<u8> {
            lock(&self.0).bye()
        }

        fn forget(&mut self, index: u32) {
            lock(&self.0).forget(index);
        }

        fn sources(&self) -> usize {
            lock(&self.0).sources.len()
        }
    }

    fn engine(now: Instant) -> Shared {
        let device = Arc::new(samples::device());
        Shared(Mutex::new(Engine::new(
            device,
            1_700_000_000,
            Uuid::from_u128(9),
            now,
        )))
    }

    /// A Windows Probe with MessageID `n`.
    fn probe(n: u32) -> Vec<u8> {
        samples::PROBE
            .replace(
                samples::PROBE_ID,
                &format!("urn:uuid:{}", Uuid::from_u128(n.into())),
            )
            .into_bytes()
    }

    fn number(message: &[u8]) -> u64 {
        let elements = elements(std::str::from_utf8(message).unwrap());
        let sequence = elements.iter().find(|e| e.local == "AppSequence").unwrap();
        sequence.attributes[2].1.parse().unwrap()
    }

    #[test]
    fn windows_requests_are_answered_with_their_reply() {
        let now = Instant::now();
        let mut engine = engine(now);
        let link = v4_link(2);
        let windows = from("192.168.1.30:50000");

        let reply = engine
            .handle(now, &link, XADDR, windows, samples::PROBE.as_bytes())
            .expect("ProbeMatches");
        assert_eq!(reply.to, windows);
        assert!(reply.delayed);
        let message = elements(std::str::from_utf8(&reply.message).unwrap());
        assert_eq!(
            text(&message, WSA, "Action"),
            "http://schemas.xmlsoap.org/ws/2005/04/discovery/ProbeMatches"
        );
        assert_eq!(text(&message, WSA, "RelatesTo"), samples::PROBE_ID);
        assert_eq!(text(&message, WSD, "XAddrs"), XADDR);
        assert_eq!(number(&reply.message), 1);

        let reply = engine
            .handle(now, &link, XADDR, windows, samples::RESOLVE.as_bytes())
            .expect("ResolveMatches");
        assert!(!reply.delayed);
        let message = elements(std::str::from_utf8(&reply.message).unwrap());
        assert_eq!(text(&message, WSA, "RelatesTo"), samples::RESOLVE_ID);
        assert_eq!(number(&reply.message), 2);

        let other = samples::RESOLVE.replacen("3f2b8c1e", "00000000", 1);
        assert!(
            engine
                .handle(now, &link, XADDR, windows, other.as_bytes())
                .is_none()
        );
        let printer = samples::PROBE.replacen("wsdp:Device", "wsdp:Printer", 1);
        assert!(
            engine
                .handle(now, &link, XADDR, windows, printer.as_bytes())
                .is_none()
        );
    }

    #[test]
    fn announcements_number_on_from_replies() {
        let now = Instant::now();
        let mut engine = engine(now);
        assert_eq!(number(&engine.hello(XADDR)), 1);
        let reply = engine
            .handle(now, &v4_link(2), XADDR, from("192.168.1.5:3702"), &probe(1))
            .unwrap();
        assert_eq!(number(&reply.message), 2);
        let bye = engine.bye();
        assert_eq!(number(&bye), 3);
        let bye = elements(std::str::from_utf8(&bye).unwrap());
        let sequence = bye.iter().find(|e| e.local == "AppSequence").unwrap();
        assert_eq!(sequence.attributes[0].1, "1700000000");
        assert_eq!(
            sequence.attributes[1].1,
            format!("urn:uuid:{}", Uuid::from_u128(9))
        );
    }

    #[test]
    fn a_message_id_is_answered_once_per_interface() {
        let now = Instant::now();
        let mut engine = engine(now);
        let v4 = from("192.168.1.30:50000");
        let v6 = from("[fe80::20%2]:50001");
        // Windows sends the same Probe over both families.
        assert!(
            engine
                .handle(now, &v6_link(2), XADDR, v6, &probe(1))
                .is_some()
        );
        assert!(
            engine
                .handle(now, &v4_link(2), XADDR, v4, &probe(1))
                .is_none()
        );
        assert!(
            engine
                .handle(now, &v4_link(3), XADDR, v4, &probe(1))
                .is_some()
        );
        let later = now + Duration::from_millis(9_900);
        assert!(
            engine
                .handle(later, &v4_link(2), XADDR, v4, &probe(1))
                .is_none()
        );
        let later = now + SEEN_FOR;
        assert!(
            engine
                .handle(later, &v4_link(2), XADDR, v4, &probe(1))
                .is_some()
        );
        engine.forget(3);
        assert!(
            engine
                .handle(later, &v4_link(3), XADDR, v4, &probe(1))
                .is_some()
        );
    }

    #[test]
    fn only_senders_on_the_link_are_answered() {
        let on = |net: &str, len| Link {
            networks: vec![(ip(net), len)],
            ..v4_link(2)
        };
        let now = Instant::now();
        let mut engine = engine(now);
        let table = [
            (v4_link(2), "192.168.1.20:5000", true),
            (v4_link(2), "[::ffff:192.168.1.21]:5000", true),
            (v4_link(2), "169.254.7.7:5000", true),
            (v4_link(2), "192.168.2.20:5000", false),
            (v4_link(2), "192.168.1.22:0", false),
            (v6_link(2), "[fe80::5%2]:5000", true),
            (v6_link(2), "[2001:db8::5]:5000", true),
            (v6_link(2), "[2001:db8:1::5]:5000", false),
            // Networks that contain the sender, which is still refused.
            (on("0.0.0.0", 8), "0.0.0.0:5000", false),
            (on("224.0.0.0", 4), "239.255.255.250:3702", false),
            (on("ff00::", 8), "[ff02::c]:3702", false),
        ];
        for (n, (link, sender, answered)) in table.into_iter().enumerate() {
            let reply = engine.handle(now, &link, XADDR, from(sender), &probe(n as u32));
            assert_eq!(reply.is_some(), answered, "{sender}");
        }
        let any = Link {
            networks: vec![(ip("0.0.0.0"), 0)],
            ..v4_link(2)
        };
        assert!(
            engine
                .handle(now, &any, XADDR, from("198.51.100.7:5000"), &probe(99))
                .is_none()
        );
    }

    #[test]
    fn replies_are_rate_limited_per_sender_and_overall() {
        let now = Instant::now();
        let mut engine = engine(now);
        let link = Link {
            networks: vec![(ip("10.0.0.1"), 8)],
            ..v4_link(2)
        };
        let sender = from("10.0.0.5:5000");
        let answered = (0..20)
            .filter(|&n| {
                engine
                    .handle(now, &link, XADDR, sender, &probe(n))
                    .is_some()
            })
            .count();
        assert_eq!(answered, REPLIES_PER_SOURCE as usize);
        let later = now + RATE_WINDOW;
        assert!(
            engine
                .handle(later, &link, XADDR, sender, &probe(100))
                .is_some()
        );

        let mut engine = self::engine(now);
        let answered = (0..300u32)
            .filter(|&n| {
                let sender = SocketAddr::from(([10, 0, (n / 250) as u8, (n % 250) as u8], 5000));
                engine
                    .handle(now, &link, XADDR, sender, &probe(n))
                    .is_some()
            })
            .count();
        assert_eq!(answered, REPLIES_OVERALL as usize);
    }

    #[test]
    fn senders_counted_at_once_are_bounded() {
        let now = Instant::now();
        let mut engine = engine(now);
        let link = Link {
            networks: vec![(ip("10.0.0.1"), 8)],
            ..v4_link(2)
        };
        let sender = |n: u32| SocketAddr::from(([10, 1, (n / 250) as u8, (n % 250) as u8], 5000));
        for n in 0..MAX_SOURCES as u32 {
            assert!(engine.handle(now, &link, XADDR, sender(n), b"<x").is_none());
        }
        assert!(engine.sources() <= MAX_SOURCES);
        // A new sender waits until the senders' windows end.
        let new = sender(1000);
        assert!(engine.handle(now, &link, XADDR, new, &probe(1)).is_none());
        let later = now + RATE_WINDOW;
        assert!(engine.handle(later, &link, XADDR, new, &probe(2)).is_some());
    }

    #[test]
    fn a_rate_limited_request_is_answered_when_repeated() {
        let now = Instant::now();
        let mut engine = engine(now);
        let link = v4_link(2);
        let sender = from("192.168.1.5:5000");
        for n in 0..REPLIES_PER_SOURCE {
            assert!(
                engine
                    .handle(now, &link, XADDR, sender, &probe(n))
                    .is_some()
            );
        }
        assert!(
            engine
                .handle(now, &link, XADDR, sender, &probe(100))
                .is_none()
        );
        let later = now + RATE_WINDOW;
        assert!(
            engine
                .handle(later, &link, XADDR, sender, &probe(100))
                .is_some()
        );
    }

    #[test]
    fn a_sender_gets_a_budget_of_datagrams_read() {
        let now = Instant::now();
        let mut engine = engine(now);
        let link = v4_link(2);
        let sender = from("192.168.1.5:5000");
        for _ in 0..REQUESTS_PER_SOURCE {
            assert!(engine.handle(now, &link, XADDR, sender, b"<x").is_none());
        }
        assert!(
            engine
                .handle(now, &link, XADDR, sender, &probe(1))
                .is_none()
        );
        let other = from("192.168.1.6:5000");
        assert!(engine.handle(now, &link, XADDR, other, &probe(1)).is_some());
        let later = now + RATE_WINDOW;
        assert!(
            engine
                .handle(later, &link, XADDR, sender, &probe(2))
                .is_some()
        );
    }

    #[test]
    fn the_metadata_version_is_the_start_time() {
        let now = Instant::now();
        let mut engine = engine(now);
        let hello = engine.hello(XADDR);
        let hello = elements(std::str::from_utf8(&hello).unwrap());
        assert_eq!(text(&hello, WSD, "MetadataVersion"), "1700000000");
        let later = Engine::new(
            Arc::new(samples::device()),
            u64::from(u32::MAX) + 1,
            Uuid::nil(),
            now,
        );
        assert_eq!(later.metadata_version, u32::MAX);
    }

    #[test]
    fn datagrams_over_4096_bytes_are_dropped() {
        let now = Instant::now();
        let mut engine = engine(now);
        let link = v4_link(2);
        let sender = from("192.168.1.5:5000");
        let mut datagram = probe(1);
        datagram.resize(MAX_DATAGRAM, b' ');
        assert!(
            engine
                .handle(now, &link, XADDR, sender, &datagram)
                .is_some()
        );
        let mut datagram = probe(2);
        datagram.resize(MAX_DATAGRAM + 1, b' ');
        assert!(
            engine
                .handle(now, &link, XADDR, sender, &datagram)
                .is_none()
        );
    }

    #[test]
    fn copies_follow_the_soap_over_udp_schedule() {
        let ms = Duration::from_millis;
        assert_eq!(
            repeat_delays(MULTICAST_COPIES, ms(50)),
            [ms(50), ms(100), ms(200)]
        );
        assert_eq!(
            repeat_delays(MULTICAST_COPIES, ms(250)),
            [ms(250), ms(500), ms(500)]
        );
        assert_eq!(repeat_delays(UNICAST_COPIES, ms(120)), [ms(120)]);
        assert_eq!(repeat_delays(1, ms(120)), []);
        for _ in 0..100 {
            assert!((ms(50)..=ms(250)).contains(&first_repeat_delay()));
            assert!(app_delay() <= ms(500));
        }
    }
}
