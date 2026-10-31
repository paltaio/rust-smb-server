//! Sockets: one handler per interface and address family, each answering
//! on UDP port 3702 and serving metadata over HTTP.

use std::collections::{HashMap, HashSet};
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6};
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::{Semaphore, watch};
use tokio::task::JoinSet;
use tokio::time::{Instant, MissedTickBehavior};
use tracing::{debug, info, warn};
use uuid::Uuid;

use super::engine::{self, Engine, Link, MAX_DATAGRAM, MULTICAST_COPIES, UNICAST_COPIES};
use super::{http, until_stopped};
use crate::discovery::target::Scope;
use crate::discovery::{Device, Stop};

const PORT: u16 = 3702;
const GROUP_V4: Ipv4Addr = Ipv4Addr::new(239, 255, 255, 250);
const GROUP_V6: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0xc);
/// Port of the metadata endpoint unless taken.
const HTTP_PORT: u16 = 5357;
/// How often the interfaces are read again.
const POLL: Duration = Duration::from_secs(5);

/// An address of an interface.
#[derive(Debug, Clone)]
pub(super) struct IfAddr {
    pub(super) name: String,
    pub(super) index: u32,
    pub(super) ip: IpAddr,
    pub(super) prefix_len: u8,
    pub(super) up: bool,
    pub(super) loopback: bool,
    pub(super) point_to_point: bool,
}

/// The addresses of the host's interfaces, or `None` when they cannot be
/// read.
fn interfaces() -> Option<Vec<IfAddr>> {
    let list = match if_addrs::get_if_addrs() {
        Ok(list) => list,
        Err(e) => {
            debug!(error = %e, "cannot read the interfaces");
            return None;
        }
    };
    let addrs = list
        .into_iter()
        .filter_map(|intf| {
            let prefix_len = match &intf.addr {
                if_addrs::IfAddr::V4(addr) => addr.prefixlen,
                if_addrs::IfAddr::V6(addr) => addr.prefixlen,
            };
            Some(IfAddr {
                index: intf.index?,
                ip: intf.ip(),
                prefix_len,
                up: intf.is_oper_up(),
                loopback: intf.is_loopback(),
                point_to_point: intf.is_p2p(),
                name: intf.name,
            })
        })
        .collect();
    Some(addrs)
}

/// Whether the interface named `name` is a VPN tunnel, a container
/// network or one of Apple's peer-to-peer links, none of which reach
/// Windows computers on the LAN.
fn is_virtual(name: &str) -> bool {
    [
        "tun", "utun", "wg", "docker", "br-", "veth", "cni", "flannel", "cali", "awdl", "llw",
        "anpi",
    ]
    .iter()
    .any(|prefix| name.starts_with(prefix))
}

/// The links to answer on for a listener with `scope`: one per interface
/// and family, on interfaces that are up and neither loopback,
/// point-to-point nor virtual, from an address the listener accepts. Over
/// IPv6, a link-local address goes first.
pub(super) fn links(addrs: &[IfAddr], scope: Scope) -> Vec<Link> {
    // The interface list marks addresses as loopback by their value, so
    // the link-local address of a loopback interface, fe80::1 on lo0 on
    // macOS, is known by the interface's other addresses.
    let loopback: HashSet<u32> = addrs
        .iter()
        .filter(|a| a.loopback)
        .map(|a| a.index)
        .collect();
    let mut links: Vec<Link> = Vec::new();
    let usable = addrs.iter().filter(|a| {
        a.up && !loopback.contains(&a.index)
            && !a.point_to_point
            && a.index != 0
            && !is_virtual(&a.name)
            && scope.admits(a.ip, a.loopback)
    });
    for a in usable {
        let v6 = a.ip.is_ipv6();
        let link_local = matches!(a.ip, IpAddr::V6(ip) if ip.is_unicast_link_local());
        if let Some(link) = links.iter_mut().find(|l| key(l) == (a.index, v6)) {
            if link_local && !matches!(link.addr, IpAddr::V6(ip) if ip.is_unicast_link_local()) {
                link.addr = a.ip;
            }
            continue;
        }
        let networks = addrs
            .iter()
            .filter(|b| b.index == a.index && b.ip.is_ipv6() == v6)
            .map(|b| (b.ip, b.prefix_len))
            .collect();
        links.push(Link {
            index: a.index,
            addr: a.ip,
            networks,
        });
    }
    links
}

/// A handler's interface index and whether it is the IPv6 one.
type Key = (u32, bool);

fn key(link: &Link) -> Key {
    (link.index, link.addr.is_ipv6())
}

/// What to do to the running handlers so that they serve the wanted
/// links.
#[derive(Debug, Default, PartialEq, Eq)]
pub(super) struct Changes {
    /// Handlers to stop: their link is gone or its address changed.
    pub(super) stop: Vec<Key>,
    /// Handlers whose address stays and whose networks changed.
    pub(super) update: Vec<Link>,
    /// Links to start a handler on, after the stopped ones closed their
    /// sockets.
    pub(super) start: Vec<Link>,
}

/// The changes that turn handlers on `current` links into handlers on
/// `wanted` links.
pub(super) fn changes<'a>(
    current: impl IntoIterator<Item = &'a Link>,
    wanted: Vec<Link>,
) -> Changes {
    let mut changes = Changes::default();
    let mut kept = HashSet::new();
    for link in current {
        match wanted.iter().find(|w| key(w) == key(link)) {
            Some(want) if want.addr == link.addr => {
                kept.insert(key(link));
                if want.networks != link.networks {
                    changes.update.push(want.clone());
                }
            }
            _ => changes.stop.push(key(link)),
        }
    }
    changes.start = wanted
        .into_iter()
        .filter(|link| !kept.contains(&key(link)))
        .collect();
    changes
}

/// The metadata URL of `endpoint` at `addr` and `port`.
pub(super) fn xaddr(addr: IpAddr, port: u16, endpoint: Uuid) -> String {
    match addr {
        IpAddr::V4(addr) => format!("http://{addr}:{port}/{endpoint}"),
        IpAddr::V6(addr) => format!("http://[{addr}]:{port}/{endpoint}"),
    }
}

/// What the handlers share.
struct Shared {
    engine: Mutex<Engine>,
    device: Arc<Device>,
    /// Connections to the metadata endpoints.
    slots: Arc<Semaphore>,
    /// Whether macOS refused a send, which is logged as a warning once.
    #[cfg_attr(not(target_vendor = "apple"), allow(dead_code))]
    refused: AtomicBool,
}

impl Shared {
    fn new(device: Device, now: Instant) -> Self {
        let instance_id = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |since| since.as_secs());
        let device = Arc::new(device);
        Self {
            engine: Mutex::new(Engine::new(
                device.clone(),
                instance_id,
                Uuid::new_v4(),
                now,
            )),
            device,
            slots: Arc::new(Semaphore::new(http::MAX_CONNECTIONS)),
            refused: AtomicBool::new(false),
        }
    }

    /// Logs a message to `to` that could not be sent.
    fn send_failed(&self, to: SocketAddr, e: &io::Error) {
        // Running as a non-root user, macOS refused these sends with
        // EHOSTUNREACH; running as root worked.
        #[cfg(target_vendor = "apple")]
        if e.raw_os_error() == Some(libc::EHOSTUNREACH)
            && !self
                .refused
                .swap(true, std::sync::atomic::Ordering::Relaxed)
        {
            warn!(
                error = %e,
                "macOS refused to send a WS-Discovery message, so Windows may not list the \
                 server; run the server as root to announce it to Windows"
            );
            return;
        }
        debug!(%to, error = %e, "cannot send a WS-Discovery message");
    }
}

/// Announces `device` to Windows on the interfaces `scope` admits until
/// `stop` resolves, then sends Bye.
pub(crate) async fn run(device: Device, scope: Scope, mut stop: Stop) {
    let shared = Arc::new(Shared::new(device, Instant::now()));
    info!(
        name = %shared.device.info.computer,
        workgroup = %shared.device.info.workgroup,
        endpoint = %shared.device.endpoint,
        "announcing the server to Windows over WS-Discovery"
    );
    let mut handlers: HashMap<Key, Handler> = HashMap::new();
    // Links whose handler failed to start, so that each failure is
    // logged as a warning once.
    let mut failed: HashSet<(u32, IpAddr)> = HashSet::new();
    let mut warned_none = false;
    let mut poll = tokio::time::interval(POLL);
    poll.set_missed_tick_behavior(MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            _ = &mut stop => break,
            _ = poll.tick() => {
                let Some(addrs) = interfaces() else { continue };
                let wanted = links(&addrs, scope);
                if wanted.is_empty() && !warned_none {
                    warn!(
                        "no interface that is up, not loopback, not point-to-point and not virtual \
                         has an address the listener accepts; the server is announced to Windows \
                         once one has"
                    );
                    warned_none = true;
                }
                update(&mut handlers, wanted, &shared, &mut failed).await;
            }
        }
    }
    finish(handlers.into_values().collect(), &shared).await;
}

/// Brings `handlers` to the `wanted` links.
async fn update(
    handlers: &mut HashMap<Key, Handler>,
    wanted: Vec<Link>,
    shared: &Arc<Shared>,
    failed: &mut HashSet<(u32, IpAddr)>,
) {
    let current: Vec<Arc<Link>> = handlers.values().map(|h| h.link.borrow().clone()).collect();
    let changes = changes(current.iter().map(|link| &**link), wanted);
    for stopped in &changes.stop {
        if let Some(mut handler) = handlers.remove(stopped) {
            let addr = handler.link.borrow().addr;
            debug!(%addr, "WS-Discovery stopped on a changed or removed address");
            handler.stop().await;
        }
        if !changes.start.iter().any(|link| key(link) == *stopped) {
            engine::lock(&shared.engine).forget(stopped.0);
        }
    }
    for link in changes.update {
        if let Some(handler) = handlers.get(&key(&link)) {
            handler.link.send_replace(Arc::new(link));
        }
    }
    for link in changes.start {
        let addr = link.addr;
        let started = key(&link);
        let index = link.index;
        match Handler::start(link, shared).await {
            Ok(handler) => {
                debug!(%addr, "WS-Discovery started");
                failed.remove(&(index, addr));
                handlers.insert(started, handler);
            }
            Err(e) if failed.insert((index, addr)) => {
                warn!(%addr, error = %e, "cannot answer WS-Discovery on this address");
            }
            Err(e) => debug!(%addr, error = %e, "cannot answer WS-Discovery on this address"),
        }
    }
}

/// Stops every handler, then sends Bye on each link, so that no reply or
/// Hello follows a Bye.
async fn finish(mut handlers: Vec<Handler>, shared: &Arc<Shared>) {
    for handler in &handlers {
        handler.stop.send_replace(true);
    }
    for handler in &mut handlers {
        handler.stop().await;
    }
    let mut byes = JoinSet::new();
    for handler in &handlers {
        let bye = engine::lock(&shared.engine).bye();
        let send = handler.send.clone();
        let group = handler.group;
        let shared = shared.clone();
        byes.spawn(async move { send_copies(&send, group, &bye, MULTICAST_COPIES, &shared).await });
    }
    while byes.join_next().await.is_some() {}
}

/// The sockets of a handler.
struct Sockets {
    recv: UdpSocket,
    send: UdpSocket,
    http: TcpListener,
}

/// Answers on one link. Dropping it aborts its tasks.
struct Handler {
    /// The link, with the networks it has now.
    link: watch::Sender<Arc<Link>>,
    send: Arc<UdpSocket>,
    /// Where multicast messages go on the link.
    group: SocketAddr,
    stop: watch::Sender<bool>,
    tasks: JoinSet<()>,
}

impl Handler {
    /// Opens the sockets for `link`, starts answering on them, and sends
    /// Hello after a random wait.
    async fn start(link: Link, shared: &Arc<Shared>) -> Result<Self, HandlerError> {
        let recv = recv_socket(&link).map_err(HandlerError::Group)?;
        let send = send_socket(&link).map_err(HandlerError::Port)?;
        let http = http_listener(&link).await.map_err(HandlerError::Http)?;
        let port = http.local_addr().map_err(HandlerError::Http)?.port();
        if port != HTTP_PORT {
            warn!(
                addr = %link.addr,
                port,
                "TCP port 5357 is in use; the metadata is served on another port, which firewall \
                 rules for 5357 do not cover"
            );
        }
        let group = match link.addr {
            IpAddr::V4(_) => SocketAddr::from((GROUP_V4, PORT)),
            IpAddr::V6(_) => SocketAddrV6::new(GROUP_V6, PORT, 0, link.index).into(),
        };
        let sockets = Sockets { recv, send, http };
        Ok(Self::with_sockets(link, sockets, port, group, shared))
    }

    /// Answers on `sockets`, with the metadata endpoint on `port`, sending
    /// multicast messages to `group`.
    fn with_sockets(
        link: Link,
        sockets: Sockets,
        port: u16,
        group: SocketAddr,
        shared: &Arc<Shared>,
    ) -> Self {
        let xaddr = xaddr(link.addr, port, shared.device.endpoint);
        let (link, _) = watch::channel(Arc::new(link));
        let (stop, _) = watch::channel(false);
        let send = Arc::new(sockets.send);
        let mut tasks = JoinSet::new();
        tasks.spawn(hello(
            send.clone(),
            group,
            xaddr.clone(),
            shared.clone(),
            stop.subscribe(),
        ));
        tasks.spawn(receive(
            sockets.recv,
            send.clone(),
            link.subscribe(),
            xaddr,
            shared.clone(),
            stop.subscribe(),
        ));
        tasks.spawn(http::serve(
            sockets.http,
            link.subscribe(),
            shared.device.clone(),
            shared.slots.clone(),
            stop.subscribe(),
        ));
        Self {
            link,
            send,
            group,
            stop,
            tasks,
        }
    }

    /// Stops answering and waits until it has: every socket but the one
    /// Bye goes out on is closed, and no reply or Hello is pending.
    async fn stop(&mut self) {
        self.stop.send_replace(true);
        while self.tasks.join_next().await.is_some() {}
    }
}

#[derive(Debug)]
enum HandlerError {
    Group(io::Error),
    Port(io::Error),
    Http(io::Error),
}

impl std::fmt::Display for HandlerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HandlerError::Group(e) => write!(f, "cannot listen on the WS-Discovery group: {e}"),
            HandlerError::Port(e) if e.kind() == io::ErrorKind::AddrInUse => write!(
                f,
                "UDP port 3702 on this address is in use by another program, such as another \
                 WS-Discovery responder"
            ),
            HandlerError::Port(e) => write!(f, "cannot open UDP port 3702: {e}"),
            HandlerError::Http(e) => write!(f, "cannot open the metadata endpoint: {e}"),
        }
    }
}

/// Sends Hello to `group` after a random wait, unless stopped first.
async fn hello(
    send: Arc<UdpSocket>,
    group: SocketAddr,
    xaddr: String,
    shared: Arc<Shared>,
    mut stop: watch::Receiver<bool>,
) {
    tokio::select! {
        () = until_stopped(&mut stop) => {}
        () = async {
            tokio::time::sleep(engine::app_delay()).await;
            let hello = engine::lock(&shared.engine).hello(&xaddr);
            send_copies(&send, group, &hello, MULTICAST_COPIES, &shared).await;
        } => {}
    }
}

/// Answers the requests that arrive on `recv` from `send`, until stopped.
/// Replies not yet sent are dropped then.
async fn receive(
    recv: UdpSocket,
    send: Arc<UdpSocket>,
    link: watch::Receiver<Arc<Link>>,
    xaddr: String,
    shared: Arc<Shared>,
    mut stop: watch::Receiver<bool>,
) {
    // One byte more than the longest datagram read, to tell longer ones.
    let mut buf = vec![0; MAX_DATAGRAM + 1];
    let mut replies = JoinSet::new();
    loop {
        while replies.try_join_next().is_some() {}
        let received = tokio::select! {
            () = until_stopped(&mut stop) => break,
            received = recv.recv_from(&mut buf) => received,
        };
        let (n, from) = match received {
            Ok(received) => received,
            Err(e) => {
                debug!(error = %e, "cannot receive WS-Discovery requests");
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        let current = link.borrow().clone();
        let reply = engine::handle(
            &shared.engine,
            Instant::now(),
            &current,
            &xaddr,
            from,
            &buf[..n],
        );
        if let Some(reply) = reply {
            let send = send.clone();
            let shared = shared.clone();
            replies.spawn(async move {
                if reply.delayed {
                    tokio::time::sleep(engine::app_delay()).await;
                }
                send_copies(&send, reply.to, &reply.message, UNICAST_COPIES, &shared).await;
            });
        }
    }
    replies.shutdown().await;
}

/// Sends `message` to `to` `copies` times, with the same MessageID.
async fn send_copies(
    socket: &UdpSocket,
    to: SocketAddr,
    message: &[u8],
    copies: usize,
    shared: &Shared,
) {
    let send = || async {
        if let Err(e) = socket.send_to(message, to).await {
            shared.send_failed(to, &e);
        }
    };
    send().await;
    for delay in engine::repeat_delays(copies, engine::first_repeat_delay()) {
        tokio::time::sleep(delay).await;
        send().await;
    }
}

/// Shares the group's port with the receive sockets of other links and
/// processes. Linux shares it through SO_REUSEADDR alone; SO_REUSEPORT
/// there would also require the same user.
fn share_port(socket: &Socket) -> io::Result<()> {
    socket.set_reuse_address(true)?;
    #[cfg(not(any(
        target_os = "linux",
        target_os = "android",
        target_os = "solaris",
        target_os = "illumos",
        target_os = "cygwin",
        target_os = "nuttx",
        target_os = "wasi"
    )))]
    socket.set_reuse_port(true)?;
    Ok(())
}

/// A socket that receives the multicast requests that arrive on `link`
/// only: bound to the group address, joined on the link's interface.
fn recv_socket(link: &Link) -> io::Result<UdpSocket> {
    let socket = match link.addr {
        IpAddr::V4(addr) => {
            let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
            share_port(&socket)?;
            // Otherwise Linux also delivers what arrives on interfaces
            // that other sockets joined the group on.
            #[cfg(target_os = "linux")]
            socket.set_multicast_all_v4(false)?;
            socket.bind(&SocketAddr::from((GROUP_V4, PORT)).into())?;
            socket.join_multicast_v4(&GROUP_V4, &addr)?;
            socket
        }
        IpAddr::V6(_) => {
            let socket = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
            socket.set_only_v6(true)?;
            share_port(&socket)?;
            // Kernels before 4.20 lack the option; the scope ID below
            // keeps the socket to its interface there too.
            #[cfg(target_os = "linux")]
            if let Err(e) = socket.set_multicast_all_v6(false)
                && e.raw_os_error() != Some(libc::ENOPROTOOPT)
            {
                return Err(e);
            }
            // The scope ID binds the socket to the interface.
            socket.bind(&SocketAddrV6::new(GROUP_V6, PORT, 0, link.index).into())?;
            socket.join_multicast_v6(&GROUP_V6, link.index)?;
            socket
        }
    };
    socket.set_nonblocking(true)?;
    UdpSocket::from_std(socket.into())
}

/// The socket replies and multicast messages leave from: bound to the
/// link's address on port 3702, the port Windows expects replies from,
/// sending multicast on the link only.
fn send_socket(link: &Link) -> io::Result<UdpSocket> {
    let socket = match link.addr {
        IpAddr::V4(addr) => {
            let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
            socket.bind(&SocketAddr::from((addr, PORT)).into())?;
            socket.set_multicast_if_v4(&addr)?;
            socket.set_multicast_ttl_v4(1)?;
            socket.set_multicast_loop_v4(false)?;
            socket
        }
        IpAddr::V6(addr) => {
            let socket = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
            socket.set_only_v6(true)?;
            socket.bind(&SocketAddrV6::new(addr, PORT, 0, scope_id(addr, link.index)).into())?;
            socket.set_multicast_if_v6(link.index)?;
            socket.set_multicast_hops_v6(1)?;
            socket.set_multicast_loop_v6(false)?;
            socket
        }
    };
    socket.set_nonblocking(true)?;
    UdpSocket::from_std(socket.into())
}

/// The metadata endpoint's listener on the link's address, on port 5357
/// or, when another program has it, on a free port.
async fn http_listener(link: &Link) -> io::Result<TcpListener> {
    let at = |port| -> SocketAddr {
        match link.addr {
            IpAddr::V4(addr) => (addr, port).into(),
            IpAddr::V6(addr) => SocketAddrV6::new(addr, port, 0, scope_id(addr, link.index)).into(),
        }
    };
    match TcpListener::bind(at(HTTP_PORT)).await {
        Err(e) if e.kind() == io::ErrorKind::AddrInUse => TcpListener::bind(at(0)).await,
        bound => bound,
    }
}

/// The scope ID to bind `addr` with: the interface for a link-local
/// address.
fn scope_id(addr: Ipv6Addr, index: u32) -> u32 {
    if addr.is_unicast_link_local() {
        index
    } else {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn addr(name: &str, index: u32, cidr: &str) -> IfAddr {
        let (ip, len) = cidr.split_once('/').unwrap();
        IfAddr {
            name: name.to_string(),
            index,
            ip: ip.parse().unwrap(),
            prefix_len: len.parse().unwrap(),
            up: true,
            loopback: name == "lo",
            point_to_point: false,
        }
    }

    fn host() -> Vec<IfAddr> {
        vec![
            addr("lo", 1, "127.0.0.1/8"),
            addr("lo", 1, "::1/128"),
            IfAddr {
                loopback: false,
                ..addr("lo", 1, "fe80::1/64")
            },
            addr("eth0", 2, "192.168.1.10/24"),
            addr("eth0", 2, "2001:db8::10/64"),
            addr("eth0", 2, "fe80::10/64"),
            addr("eth0", 2, "192.168.7.10/24"),
            IfAddr {
                point_to_point: true,
                ..addr("ppp0", 3, "10.64.0.2/32")
            },
            addr("utun4", 4, "fe80::4/64"),
            addr("wg0", 5, "10.9.0.2/24"),
            IfAddr {
                up: false,
                ..addr("eth1", 6, "10.0.0.5/8")
            },
            addr("eth2", 7, "172.16.0.2/16"),
            addr("docker0", 8, "172.17.0.1/16"),
            addr("br-0a1b2c3d4e5f", 9, "172.18.0.1/16"),
            addr("veth1234567", 10, "fe80::10:1/64"),
            addr("awdl0", 11, "fe80::11:1/64"),
        ]
    }

    fn eth0_v4() -> Link {
        Link {
            index: 2,
            addr: ip("192.168.1.10"),
            networks: vec![(ip("192.168.1.10"), 24), (ip("192.168.7.10"), 24)],
        }
    }

    fn eth0_v6(addr: &str) -> Link {
        Link {
            index: 2,
            addr: ip(addr),
            networks: vec![(ip("2001:db8::10"), 64), (ip("fe80::10"), 64)],
        }
    }

    fn eth2() -> Link {
        Link {
            index: 7,
            addr: ip("172.16.0.2"),
            networks: vec![(ip("172.16.0.2"), 16)],
        }
    }

    #[test]
    fn links_follow_the_listen_address() {
        let host = host();
        assert_eq!(links(&host, Scope::V4), [eth0_v4(), eth2()]);
        assert_eq!(
            links(&host, Scope::V6 { dual_stack: true }),
            [eth0_v4(), eth0_v6("fe80::10"), eth2()]
        );
        assert_eq!(
            links(&host, Scope::V6 { dual_stack: false }),
            [eth0_v6("fe80::10")]
        );
        assert_eq!(
            links(&host, Scope::Addr(ip("192.168.7.10"))),
            [Link {
                addr: ip("192.168.7.10"),
                ..eth0_v4()
            }]
        );
        assert_eq!(
            links(&host, Scope::Addr(ip("2001:db8::10"))),
            [eth0_v6("2001:db8::10")]
        );
        assert_eq!(links(&host, Scope::Addr(ip("10.0.0.5"))), []);
        assert_eq!(links(&host, Scope::Addr(ip("10.9.0.2"))), []);
    }

    #[test]
    fn metadata_urls_bracket_ipv6_addresses() {
        let endpoint = Uuid::from_u128(1);
        assert_eq!(
            xaddr(ip("192.168.1.10"), 5357, endpoint),
            "http://192.168.1.10:5357/00000000-0000-0000-0000-000000000001"
        );
        assert_eq!(
            xaddr(ip("fe80::10"), 40000, endpoint),
            "http://[fe80::10]:40000/00000000-0000-0000-0000-000000000001"
        );
    }

    #[test]
    fn changes_keep_handlers_whose_address_stays() {
        let v4 = eth0_v4();
        let v6 = eth0_v6("fe80::10");
        // Same links: nothing to do.
        assert_eq!(
            changes([&v4, &v6], vec![v4.clone(), v6.clone()]),
            Changes::default()
        );
        // A global address comes and goes: the networks change in place.
        let fewer = Link {
            networks: vec![(ip("fe80::10"), 64)],
            ..v6.clone()
        };
        assert_eq!(
            changes([&v4, &v6], vec![v4.clone(), fewer.clone()]),
            Changes {
                update: vec![fewer],
                ..Changes::default()
            }
        );
        // The address of a link changes: stop first, then start.
        let moved = Link {
            addr: ip("192.168.7.10"),
            ..v4.clone()
        };
        assert_eq!(
            changes([&v4, &v6], vec![moved.clone(), v6.clone()]),
            Changes {
                stop: vec![(2, false)],
                start: vec![moved],
                ..Changes::default()
            }
        );
        // A link goes away and another appears.
        assert_eq!(
            changes([&v4, &v6], vec![v6.clone(), eth2()]),
            Changes {
                stop: vec![(2, false)],
                start: vec![eth2()],
                ..Changes::default()
            }
        );
        assert_eq!(
            changes([], vec![v4.clone()]),
            Changes {
                start: vec![v4],
                ..Changes::default()
            }
        );
    }

    /// A handler on loopback sockets, with `group` standing in for the
    /// multicast group.
    struct Loopback {
        handler: Handler,
        shared: Arc<Shared>,
        recv: SocketAddr,
        send: SocketAddr,
        http: SocketAddr,
    }

    async fn loopback_handler(group: SocketAddr) -> Loopback {
        let link = Link {
            index: 1,
            addr: ip("127.0.0.1"),
            networks: vec![(ip("127.0.0.1"), 8)],
        };
        let shared = Arc::new(Shared::new(
            crate::discovery::wsd::samples::device(),
            Instant::now(),
        ));
        let recv = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let send = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let http = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addrs = (
            recv.local_addr().unwrap(),
            send.local_addr().unwrap(),
            http.local_addr().unwrap(),
        );
        let sockets = Sockets { recv, send, http };
        let handler = Handler::with_sockets(link, sockets, addrs.2.port(), group, &shared);
        Loopback {
            handler,
            shared,
            recv: addrs.0,
            send: addrs.1,
            http: addrs.2,
        }
    }

    /// The Action of a message, after its last slash.
    fn action(message: &[u8]) -> String {
        let text = std::str::from_utf8(message).unwrap();
        let start = text.find("<wsa:Action>").unwrap() + "<wsa:Action>".len();
        let end = text[start..].find('<').unwrap();
        text[start..start + end]
            .rsplit('/')
            .next()
            .unwrap()
            .to_string()
    }

    /// The Actions of the datagrams `client` receives until it has been
    /// quiet for `quiet`.
    async fn received(client: &UdpSocket, quiet: Duration) -> Vec<String> {
        let mut buf = vec![0; 8192];
        let mut actions = Vec::new();
        while let Ok(Ok(n)) = tokio::time::timeout(quiet, client.recv(&mut buf)).await {
            actions.push(action(&buf[..n]));
        }
        actions
    }

    #[tokio::test]
    async fn bye_follows_every_other_message() {
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let lo = loopback_handler(client.local_addr().unwrap()).await;
        let actions = received(&client, Duration::from_millis(1500)).await;
        assert_eq!(actions, ["Hello"; MULTICAST_COPIES]);

        let probe = crate::discovery::wsd::samples::PROBE.as_bytes();
        client.send_to(probe, lo.recv).await.unwrap();
        let actions = received(&client, Duration::from_millis(1500)).await;
        assert_eq!(actions, ["ProbeMatches"; UNICAST_COPIES]);

        // Probes whose replies wait for their random delay when the
        // server stops.
        for n in 0..5u128 {
            let id = format!("urn:uuid:{}", Uuid::from_u128(n));
            let probe = crate::discovery::wsd::samples::PROBE
                .replace(crate::discovery::wsd::samples::PROBE_ID, &id);
            client.send_to(probe.as_bytes(), lo.recv).await.unwrap();
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
        finish(vec![lo.handler], &lo.shared).await;
        let actions = received(&client, Duration::from_millis(1000)).await;
        let first_bye = actions.iter().position(|a| a == "Bye").expect("Bye");
        assert!(
            actions[first_bye..].iter().all(|a| a == "Bye"),
            "{actions:?}"
        );
        assert_eq!(actions[first_bye..].len(), MULTICAST_COPIES);

        // Every socket is closed once the handlers are gone.
        UdpSocket::bind(lo.recv).await.expect("receive port");
        UdpSocket::bind(lo.send).await.expect("send port");
        TcpListener::bind(lo.http).await.expect("metadata port");
    }
}
