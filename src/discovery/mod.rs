//! Network discovery: announcing the server over mDNS and DNS-SD, and
//! to Windows over WS-Discovery.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;
use tracing::{Instrument, debug, info, warn};
use uuid::Uuid;

use crate::builder::BuildError;

#[cfg(target_os = "linux")]
mod avahi;
#[cfg(target_vendor = "apple")]
mod dns_sd;
#[cfg(windows)]
mod dnsapi;
#[cfg(all(unix, not(target_vendor = "apple")))]
mod responder;
pub(crate) mod target;
#[cfg(unix)]
pub(crate) mod wsd;

use target::{Scope, WsSkip};

/// Most renames tried in a row when the name is taken.
#[cfg_attr(any(target_vendor = "apple", not(unix)), allow(dead_code))]
const MAX_RENAMES: usize = 16;

/// Announces the server on the local network through multicast DNS and
/// DNS service discovery (RFC 6762, RFC 6763). Clients that browse
/// DNS-SD, such as the Finder, GNOME Files and Dolphin, list it. Pass it
/// to [`SmbServerBuilder::discovery`](crate::SmbServerBuilder::discovery).
///
/// While [`SmbServer::serve`](crate::SmbServer::serve) runs, the server is
/// announced as `<name>._smb._tcp.local` with the port it listens on and
/// an empty TXT record. With a [`model`](Self::model),
/// `<name>._device-info._tcp.local` carries TXT `model=<model>` as well.
/// When `serve` stops, the records are withdrawn before it returns,
/// waiting at most 2 seconds for that.
///
/// On Linux, the server registers with Avahi when avahi-daemon is on the
/// system D-Bus, registers again when avahi-daemon restarts, and moves to
/// Avahi when avahi-daemon reaches the bus after `serve` started. The SRV
/// record then points at Avahi's host name, which Avahi announces with
/// the host's addresses on the interfaces it uses, sending AAAA records
/// over IPv4 too in its default configuration. The listen address picks
/// where the service records go: over IPv4 for `0.0.0.0`, over IPv6 for
/// an IPv6-only `[::]`, over both for a dual-stack `[::]`, and on the
/// address's interface for any other address. Once the server uses Avahi,
/// it is not announced while avahi-daemon is gone, until it returns.
///
/// Without Avahi, and on Unix systems other than Apple's, the server
/// answers mDNS queries itself on UDP port 5353. The SRV record points at
/// `<host>.local`, where `<host>` is the first label of the host name,
/// announced with the addresses the listener accepts connections on: IPv4
/// for `0.0.0.0`; IPv6 for `[::]`, and IPv4 too when that socket also
/// accepts IPv4; the one address for any other listen address. Loopback,
/// point-to-point and down interfaces are left out. A name that contains a
/// dot is not announced. When another program holds UDP port 5353, the
/// server is not announced.
///
/// On Apple platforms, the server registers with mDNSResponder, which
/// renames it on a conflict and withdraws the records when the server
/// stops or exits. The SRV record points at the host name, which
/// mDNSResponder announces with the host's IPv4 and IPv6 addresses,
/// whatever addresses the listener accepts. A wildcard listen address
/// registers the service on every interface, any other address on that
/// address's interface only. When mDNSResponder restarts, the server
/// registers again.
///
/// On Windows, the server registers with the DNS client service, which
/// picks a new name when the name is taken, and withdraws the records
/// when the server stops or its process exits. The SRV record points at
/// the computer's DNS host name, which the DNS client announces with the
/// host's IPv4 and IPv6 addresses, whatever addresses the listener
/// accepts; a listen address other than a wildcard registers the service
/// on that address's interface only. The device-info record carries port
/// 9. A name that contains a dot is not announced. A restart of the DNS
/// Client service drops the registration until the server is restarted.
///
/// On other platforms nothing is announced over mDNS.
///
/// On hosts other than Windows, a server listening on port 445 is also
/// announced to Windows, which lists computers in its Network folder
/// through WS-Discovery and opens them on port 445. The server answers
/// probes on UDP port 3702, sends Hello when it starts or gains an address
/// and Bye when it stops, and serves its metadata over HTTP on TCP port
/// 5357, or on a free port, with a warning, when another program has 5357.
/// Windows lists it under its NetBIOS name, in workgroup
/// [`workgroup`](Self::workgroup), and opens it by resolving that name, so
/// the server is announced to Windows only when its NetBIOS name is the
/// first label of the host name, ignoring case; otherwise a warning says to
/// set [`netbios_name`](crate::SmbServerBuilder::netbios_name) to the host
/// name. The NetBIOS name must also be 1 to 15 characters without control
/// characters or any of `"/\[]:|<>+=;,?*`. Listen on `[::]:445`: Windows
/// may resolve the name to an IPv6 address too and then connect over IPv6
/// alone, so it lists a server that listens on IPv4 only but cannot open
/// it, and such a server logs a warning. The server answers on each
/// interface that is up, has an address the listener accepts, and is not
/// loopback, point-to-point, a VPN tunnel
/// (`tun*`, `utun*`, `wg*`), a container network (`docker*`, `br-*`,
/// `veth*`, `cni*`, `flannel*`, `cali*`) or one of Apple's peer-to-peer
/// links (`awdl*`, `llw*`, `anpi*`). It answers senders with a link-local
/// address or an address on one of that interface's networks, and follows
/// interface changes within 5 seconds. Its endpoint address is derived
/// from [`server_guid`](crate::SmbServerBuilder::server_guid) when that is
/// set, otherwise from the host name and the NetBIOS name, and from the
/// port, so it stays the same across restarts. On macOS, run the server as
/// root for WS-Discovery: as a non-root user, macOS may refuse to send its
/// messages, which is logged as a warning, or not deliver the probes to
/// it, and Windows then does not list the server. On Windows, which
/// announces the computer itself, and on other ports, nothing is announced
/// over WS-Discovery.
///
/// Each of these cases, and any failure to announce, is logged; `serve`
/// runs on either way.
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct Discovery {
    name: Option<String>,
    model: Option<String>,
    ws_discovery: Option<bool>,
    workgroup: Option<String>,
    manufacturer: Option<String>,
    model_name: Option<String>,
    firmware_version: Option<String>,
}

impl Discovery {
    /// Discovery under the default name, without a model.
    pub fn new() -> Self {
        Self::default()
    }

    /// Instance name: the name file managers list the server under. 1 to
    /// 63 bytes of UTF-8 without control characters, used as given, so
    /// pass it in Unicode normalization form C. Defaults to the NetBIOS
    /// name in upper case. On Apple platforms with neither a name nor a
    /// model set, the server is registered under the computer name
    /// instead, and macOS announces the Mac's own model for it. When
    /// another service on the network has the name, the server is renamed
    /// with a number added, and the new name is logged. On Windows, and
    /// with the built-in responder, a name that contains a dot is not
    /// announced.
    pub fn name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    /// Model code announced in `<name>._device-info._tcp.local`. The
    /// Finder picks the icon it shows for the server by this code. 1 to
    /// 249 printable ASCII characters. Not announced unless set.
    pub fn model(mut self, model: impl Into<String>) -> Self {
        self.model = Some(model.into());
        self
    }

    /// Whether to announce the server to Windows over WS-Discovery. By
    /// default it is announced when it listens on port 445 on a host other
    /// than Windows, and the reason is logged when it is not. With `true`,
    /// [`build`](crate::SmbServerBuilder::build) fails when the listen
    /// port is set to one other than 445 or the NetBIOS name is not one
    /// Windows accepts, and a skipped announcement is logged as a warning.
    pub fn ws_discovery(mut self, enabled: bool) -> Self {
        self.ws_discovery = Some(enabled);
        self
    }

    /// Workgroup Windows lists the server in. 1 to 15 characters without
    /// control characters or any of `"/\[]:|<>+=;,?*`, sent in upper
    /// case. Defaults to `WORKGROUP`.
    pub fn workgroup(mut self, workgroup: impl Into<String>) -> Self {
        self.workgroup = Some(workgroup.into());
        self
    }

    /// Manufacturer Windows shows in the server's properties. 1 to 255
    /// characters without control characters. Defaults to `smb-server`.
    pub fn manufacturer(mut self, manufacturer: impl Into<String>) -> Self {
        self.manufacturer = Some(manufacturer.into());
        self
    }

    /// Model name Windows shows in the server's properties, apart from
    /// the [`model`](Self::model) code the Finder reads. 1 to 255
    /// characters without control characters. Defaults to `smb-server`.
    pub fn model_name(mut self, model_name: impl Into<String>) -> Self {
        self.model_name = Some(model_name.into());
        self
    }

    /// Firmware version Windows shows in the server's properties. 1 to
    /// 255 characters without control characters. Defaults to the version
    /// of this crate.
    pub fn firmware_version(mut self, version: impl Into<String>) -> Self {
        self.firmware_version = Some(version.into());
        self
    }

    /// Checks the options against the listen address and fills in the
    /// defaults.
    pub(crate) fn settings(
        self,
        listen: SocketAddr,
        netbios_name: &str,
        server_guid: Option<Uuid>,
    ) -> Result<Settings, BuildError> {
        if listen.ip().to_canonical().is_loopback() {
            return Err(BuildError::DiscoveryOnLoopback(listen));
        }
        if self.ws_discovery == Some(true) && !matches!(listen.port(), 0 | target::SMB_PORT) {
            return Err(BuildError::WsDiscoveryPort(listen.port()));
        }
        let default_name = self.name.is_none();
        let name = self.name.unwrap_or_else(|| netbios_name.to_uppercase());
        if !target::valid_name(&name) {
            return Err(BuildError::DiscoveryName(name));
        }
        if let Some(model) = self.model.as_ref().filter(|m| !target::valid_model(m)) {
            return Err(BuildError::DiscoveryModel(model.clone()));
        }
        let workgroup = self
            .workgroup
            .unwrap_or_else(|| DEFAULT_WORKGROUP.to_string());
        if !target::valid_netbios_name(&workgroup.to_uppercase()) {
            return Err(BuildError::DiscoveryWorkgroup(workgroup));
        }
        let computer = netbios_name.to_uppercase();
        if self.ws_discovery == Some(true) && !target::valid_netbios_name(&computer) {
            return Err(BuildError::WsDiscoveryNetbiosName(netbios_name.to_string()));
        }
        let field = |setting: &'static str, value: Option<String>, default: &str| match value {
            Some(value) if !target::valid_field(&value) => {
                Err(BuildError::DiscoveryMetadata { setting, value })
            }
            value => Ok(value.unwrap_or_else(|| default.to_string())),
        };
        let info = DeviceInfo {
            computer,
            workgroup: workgroup.to_uppercase(),
            manufacturer: field("manufacturer", self.manufacturer, env!("CARGO_PKG_NAME"))?,
            model_name: field("model_name", self.model_name, env!("CARGO_PKG_NAME"))?,
            firmware_version: field(
                "firmware_version",
                self.firmware_version,
                env!("CARGO_PKG_VERSION"),
            )?,
        };
        Ok(Settings {
            name,
            default_name,
            model: self.model,
            ws_discovery: self.ws_discovery,
            server_guid,
            info,
        })
    }
}

/// Workgroup announced unless set: the name Windows gives a new
/// workgroup.
const DEFAULT_WORKGROUP: &str = "WORKGROUP";

/// [`Discovery`] as checked by the builder.
#[derive(Debug, Clone)]
pub(crate) struct Settings {
    pub(crate) name: String,
    /// `name` is the default, not one set through [`Discovery::name`].
    pub(crate) default_name: bool,
    pub(crate) model: Option<String>,
    /// Set through [`Discovery::ws_discovery`].
    pub(crate) ws_discovery: Option<bool>,
    /// Set through [`SmbServerBuilder::server_guid`](crate::SmbServerBuilder::server_guid).
    pub(crate) server_guid: Option<Uuid>,
    pub(crate) info: DeviceInfo,
}

/// What Windows shows for the server, from its WS-Discovery metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(not(unix), allow(dead_code))]
pub(crate) struct DeviceInfo {
    /// NetBIOS name, in upper case.
    pub(crate) computer: String,
    /// In upper case.
    pub(crate) workgroup: String,
    pub(crate) manufacturer: String,
    pub(crate) model_name: String,
    pub(crate) firmware_version: String,
}

/// The server as a WS-Discovery device.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(not(unix), allow(dead_code))]
pub(crate) struct Device {
    /// Endpoint address, sent as `urn:uuid:<endpoint>`.
    pub(crate) endpoint: Uuid,
    pub(crate) info: DeviceInfo,
}

/// What a backend announces.
#[derive(Debug, Clone)]
#[cfg_attr(any(target_vendor = "apple", not(unix)), allow(dead_code))]
pub(crate) struct Service {
    pub(crate) name: String,
    /// `name` is the default, not one set through [`Discovery::name`].
    #[cfg_attr(not(target_vendor = "apple"), allow(dead_code))]
    pub(crate) default_name: bool,
    pub(crate) model: Option<String>,
    pub(crate) port: u16,
    pub(crate) scope: Scope,
    /// First label of the host name, the SRV target when the server
    /// answers mDNS itself.
    pub(crate) host: String,
    /// Announced over WS-Discovery when set.
    pub(crate) device: Option<Device>,
}

/// Resolves when the backend is to withdraw the service.
pub(crate) type Stop = oneshot::Receiver<()>;

/// A way to announce the service.
#[async_trait]
pub(crate) trait Backend: Send + Sync {
    /// Announces `service` until `stop` resolves, then withdraws it.
    /// Returns early when it cannot announce.
    async fn run(&self, service: Service, stop: Stop);
}

/// Avahi on Linux when it runs, otherwise the built-in responder where
/// there is one, and WS-Discovery beside it.
pub(crate) struct System;

#[async_trait]
impl Backend for System {
    async fn run(&self, mut service: Service, stop: Stop) {
        let device = service.device.take();
        let scope = service.scope;
        let (mdns_stop, mdns_stopped) = oneshot::channel();
        let (wsd_stop, wsd_stopped) = oneshot::channel::<()>();
        tokio::join!(
            async move {
                let _ = stop.await;
                drop((mdns_stop, wsd_stop));
            },
            mdns(service, mdns_stopped),
            async move {
                #[cfg(unix)]
                if let Some(device) = device {
                    wsd::run(device, scope, wsd_stopped).await;
                }
                #[cfg(not(unix))]
                drop((device, scope, wsd_stopped));
            },
        );
    }
}

/// Announces `service` over mDNS until `stop` resolves.
async fn mdns(service: Service, stop: Stop) {
    #[cfg(target_os = "linux")]
    if let Some(bus) = avahi::Bus::connect().await {
        return bus.run(service, stop).await;
    }
    #[cfg(all(unix, not(target_vendor = "apple")))]
    responder::run(service, async {
        let _ = stop.await;
        responder::Leave::Withdraw
    })
    .await;
    #[cfg(target_vendor = "apple")]
    dns_sd::run(service, stop).await;
    #[cfg(windows)]
    dnsapi::run(service, stop).await;
    #[cfg(not(any(unix, windows)))]
    {
        drop((service, stop));
        warn!("network discovery is not supported on this platform; the server is not announced");
    }
}

/// Longest wait for a backend to withdraw the service when `serve` stops.
const STOP_TIMEOUT: Duration = Duration::from_secs(2);

/// A backend announcing the server, from `serve` until [`Announcer::stop`].
/// Dropping it cancels the backend.
pub(crate) struct Announcer {
    stop: Option<oneshot::Sender<()>>,
    task: JoinHandle<()>,
}

impl Announcer {
    /// Starts `backend` on the address `listener` is bound to.
    pub(crate) fn start(
        settings: &Settings,
        listener: &TcpListener,
        backend: Arc<dyn Backend>,
    ) -> Option<Self> {
        let local = match listener.local_addr() {
            Ok(local) => local,
            Err(e) => {
                warn!(error = %e, "no listen address to announce; the server is not announced");
                return None;
            }
        };
        let v6_only =
            local.is_ipv6() && socket2::SockRef::from(listener).only_v6().unwrap_or(false);
        let host = host_label().unwrap_or_else(|| "smbserver".to_string());
        let service = Service {
            name: settings.name.clone(),
            default_name: settings.default_name,
            model: settings.model.clone(),
            port: local.port(),
            scope: Scope::new(local.ip(), v6_only),
            device: ws_device(
                settings,
                local.port(),
                &host,
                Scope::new(local.ip(), v6_only),
            ),
            host,
        };
        let (stop, stopped) = oneshot::channel();
        let task =
            tokio::spawn(async move { backend.run(service, stopped).await }.in_current_span());
        Some(Self {
            stop: Some(stop),
            task,
        })
    }

    /// Has the backend withdraw the service, and waits for it, at most
    /// [`STOP_TIMEOUT`].
    pub(crate) async fn stop(mut self) {
        self.stop.take();
        if tokio::time::timeout(STOP_TIMEOUT, &mut self.task)
            .await
            .is_err()
        {
            warn!(timeout = ?STOP_TIMEOUT, "network discovery did not stop in time");
        }
    }
}

impl Drop for Announcer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// The device to announce over WS-Discovery for a server on `port` on
/// host `host`, listening on `scope`, or `None`, with the reason logged,
/// when WS-Discovery does not run.
pub(crate) fn ws_device(
    settings: &Settings,
    port: u16,
    host: &str,
    scope: Scope,
) -> Option<Device> {
    let computer = &settings.info.computer;
    let skip =
        target::ws_discovery_skip(settings.ws_discovery, port, computer, host, cfg!(windows));
    let reason = match skip {
        None => {
            if matches!(scope, Scope::V4 | Scope::Addr(std::net::IpAddr::V4(_))) {
                warn!(
                    "the listener accepts IPv4 only: Windows may resolve the server's name to \
                     an IPv6 address too and then connect over IPv6 alone, so it lists the \
                     server but cannot open it; listen on [::]:445 instead"
                );
            }
            return Some(Device {
                endpoint: target::endpoint_uuid(settings.server_guid, host, computer, port),
                info: settings.info.clone(),
            });
        }
        Some(WsSkip::Off) => {
            debug!("WS-Discovery is off");
            return None;
        }
        Some(WsSkip::Windows) => "Windows announces the computer itself",
        Some(WsSkip::Port) => "Windows opens servers it finds that way on port 445 only",
        Some(WsSkip::Host) => {
            warn!(
                name = %computer,
                %host,
                "the server is not announced over WS-Discovery: Windows opens it by its NetBIOS \
                 name, which reaches this host only when it is the host name; set netbios_name \
                 to the host name"
            );
            return None;
        }
        Some(WsSkip::Name) => {
            warn!(
                name = %computer,
                "the server is not announced over WS-Discovery: the NetBIOS name must be 1 to 15 \
                 characters without control characters or any of \"/\\[]:|<>+=;,?*"
            );
            return None;
        }
    };
    if settings.ws_discovery == Some(true) {
        warn!(
            port,
            "the server is not announced over WS-Discovery: {reason}"
        );
    } else {
        info!(
            port,
            "the server is not announced over WS-Discovery: {reason}"
        );
    }
    None
}

/// First label of the host name.
fn host_label() -> Option<String> {
    let host = crate::builder::host_name()?;
    let label = host.split('.').next()?;
    (!label.is_empty()).then(|| label.to_string())
}
