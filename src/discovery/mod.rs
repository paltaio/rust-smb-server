//! Network discovery: announcing the server over mDNS and DNS-SD.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;
use tracing::{Instrument, warn};

use crate::builder::BuildError;

#[cfg(target_os = "linux")]
mod avahi;
#[cfg(target_vendor = "apple")]
mod dns_sd;
#[cfg(all(unix, not(target_vendor = "apple")))]
mod responder;
pub(crate) mod target;

use target::Scope;

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
/// On Windows nothing is announced. Each of these cases, and any failure
/// to announce, is logged; `serve` runs on either way.
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct Discovery {
    name: Option<String>,
    model: Option<String>,
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
    /// with a number added, and the new name is logged. With the built-in
    /// responder, a name that contains a dot is not announced.
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

    /// Checks the options against the listen address and fills in the
    /// default name.
    pub(crate) fn settings(
        self,
        listen: SocketAddr,
        netbios_name: &str,
    ) -> Result<Settings, BuildError> {
        if listen.ip().to_canonical().is_loopback() {
            return Err(BuildError::DiscoveryOnLoopback(listen));
        }
        let default_name = self.name.is_none();
        let name = self.name.unwrap_or_else(|| netbios_name.to_uppercase());
        if !target::valid_name(&name) {
            return Err(BuildError::DiscoveryName(name));
        }
        if let Some(model) = self.model.as_ref().filter(|m| !target::valid_model(m)) {
            return Err(BuildError::DiscoveryModel(model.clone()));
        }
        Ok(Settings {
            name,
            default_name,
            model: self.model,
        })
    }
}

/// [`Discovery`] as checked by the builder.
#[derive(Debug, Clone)]
pub(crate) struct Settings {
    pub(crate) name: String,
    /// `name` is the default, not one set through [`Discovery::name`].
    pub(crate) default_name: bool,
    pub(crate) model: Option<String>,
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
/// there is one.
pub(crate) struct System;

#[async_trait]
impl Backend for System {
    async fn run(&self, service: Service, stop: Stop) {
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
        #[cfg(not(unix))]
        {
            drop((service, stop));
            warn!(
                "network discovery is not supported on this platform; the server is not announced"
            );
        }
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
        let service = Service {
            name: settings.name.clone(),
            default_name: settings.default_name,
            model: settings.model.clone(),
            port: local.port(),
            scope: Scope::new(local.ip(), v6_only),
            host: host_label().unwrap_or_else(|| "smbserver".to_string()),
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
            warn!("network discovery did not stop within 2 seconds");
        }
    }
}

impl Drop for Announcer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// First label of the host name.
fn host_label() -> Option<String> {
    let host = crate::builder::host_name()?;
    let label = host.split('.').next()?;
    (!label.is_empty()).then(|| label.to_string())
}
