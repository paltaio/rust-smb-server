//! The built-in mDNS responder, for hosts that run none.

use std::collections::HashMap;
use std::future::Future;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, UdpSocket};
use std::time::Duration;

use mdns_sd::{DaemonEvent, IfKind, IfPredicate, ServiceDaemon, ServiceInfo};
use tracing::{debug, info, warn};

use super::target::{Scope, numbered_name};
use super::{MAX_RENAMES, Service};

const MDNS_PORT: u16 = 5353;
const SMB_TYPE: &str = "_smb._tcp.local.";
const DEVICE_INFO_TYPE: &str = "_device-info._tcp.local.";

/// Wait after unregistering, in which the responder repeats its goodbyes.
const GOODBYE_REPEAT: Duration = Duration::from_millis(150);

/// Time after registering by which the responder announces the server
/// when its sockets work: probing takes under a second.
const ANNOUNCE_DEADLINE: Duration = Duration::from_secs(5);

/// How the responder stops.
pub(super) enum Leave {
    /// Withdraws the records with goodbyes.
    Withdraw,
    /// Sends nothing: another responder is taking over the same records,
    /// and goodbyes would also withdraw the host's addresses, which that
    /// responder announces too.
    HandOver,
}

/// Announces `service` until `leave` resolves, unless its name contains a
/// dot or UDP port 5353 is unusable.
pub(super) async fn run(service: Service, leave: impl Future<Output = Leave> + Send) {
    if !answerable(&service.name) {
        warn!(
            name = %service.name,
            "the name contains a dot, which the built-in mDNS responder cannot answer for; \
             the server is not announced"
        );
        return;
    }
    match probe_port() {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::AddrInUse => {
            warn!(
                "UDP port 5353 is in use, by another mDNS responder such as systemd-resolved with \
                 MulticastDNS enabled or avahi-daemon outside D-Bus, or by another server in this \
                 process; the server is not announced"
            );
            return;
        }
        Err(e) => {
            warn!(error = %e, "cannot open UDP port 5353; the server is not announced");
            return;
        }
    }
    let daemon = match ServiceDaemon::new() {
        Ok(daemon) => Responder(daemon),
        Err(e) => {
            warn!(error = %e, "cannot start the mDNS responder; the server is not announced");
            return;
        }
    };
    let monitor = match daemon.0.monitor() {
        Ok(monitor) => monitor,
        Err(e) => {
            warn!(error = %e, "cannot start the mDNS responder; the server is not announced");
            return;
        }
    };
    info!(name = %service.name, "announcing the server over mDNS");
    if !has_usable_interface(service.scope) {
        warn!(
            "no interface that is up, not loopback and not point-to-point has an address the \
             listener accepts; the server is announced once one has"
        );
    }

    let scope = service.scope;
    // The responder itself leaves out down and point-to-point interfaces.
    let interfaces = IfKind::Predicate(IfPredicate::new(move |intf| {
        scope.admits(intf.ip(), intf.is_loopback())
    }));
    let mut records = Records {
        daemon: &daemon.0,
        host: format!("{}.local.", service.host),
        interfaces: interfaces.clone(),
        service: &service,
        names: Vec::new(),
    };
    let started = daemon
        .0
        .disable_interface(IfKind::All)
        .and_then(|()| daemon.0.enable_interface(interfaces));
    if let Err(e) = started.and_then(|()| records.register(&service.name)) {
        warn!(error = %e, "cannot announce the server");
        return;
    }

    let mut name = service.name.clone();
    // The number in the last name given, and the renames since the server
    // was last announced.
    let mut number = 1;
    let mut renames = 0;
    let mut announced = false;
    let mut warned = false;
    let deadline = tokio::time::sleep(ANNOUNCE_DEADLINE);
    tokio::pin!(deadline, leave);
    let how = loop {
        tokio::select! {
            how = &mut leave => break how,
            () = &mut deadline, if !announced && !warned && !records.names.is_empty() => {
                warn!(
                    "the mDNS responder has announced nothing; check that multicast on UDP port \
                     5353 works on the listener's interfaces"
                );
                warned = true;
            }
            event = monitor.recv_async() => match event {
                // mdns-sd renames a conflicting record on its own, on one
                // interface, without escaping or shortening the name.
                // Rename both records together instead.
                Ok(DaemonEvent::NameChange(change)) if records.owns(&change.original) => {
                    records.unregister();
                    renames += 1;
                    if renames > MAX_RENAMES {
                        warn!(name = %service.name, "no free name found; the server is not announced");
                        continue;
                    }
                    number += 1;
                    name = numbered_name(&service.name, number);
                    info!(%name, "renamed after a name conflict");
                    if let Err(e) = records.register(&name) {
                        warn!(error = %e, "cannot announce the server");
                    }
                    announced = false;
                    warned = false;
                    deadline.as_mut().reset(tokio::time::Instant::now() + ANNOUNCE_DEADLINE);
                }
                Ok(DaemonEvent::NameChange(change)) if is_service_name(&change.original) => {
                    debug!(from = %change.original, to = %change.new_name, "superseded rename");
                }
                Ok(DaemonEvent::NameChange(change)) => {
                    info!(from = %change.original, to = %change.new_name, "renamed after a name conflict");
                }
                Ok(DaemonEvent::Announce(fullname, _)) if records.is_smb(&fullname) => {
                    renames = 0;
                    if !announced {
                        info!(%name, "announced");
                        announced = true;
                    }
                }
                Ok(DaemonEvent::Error(e)) => warn!(error = %e, "mDNS responder error"),
                Ok(_) => {}
                Err(_) => {
                    warn!("the mDNS responder stopped; the server is no longer announced");
                    leave.await;
                    return;
                }
            },
        }
    };

    match how {
        Leave::Withdraw => {
            for fullname in std::mem::take(&mut records.names) {
                if let Ok(done) = daemon.0.unregister(&fullname) {
                    let _ = done.recv_async().await;
                }
            }
            tokio::time::sleep(GOODBYE_REPEAT).await;
        }
        // With no interface left, shutting down sends nothing.
        Leave::HandOver => {
            let _ = daemon.0.disable_interface(IfKind::All);
        }
    }
    if let Ok(done) = daemon.0.shutdown() {
        let _ = done.recv_async().await;
    }
}

/// Whether the responder can answer queries for instance name `name`:
/// mdns-sd matches incoming names against its escaped form of a name with
/// a dot, so it would answer no query for the records.
fn answerable(name: &str) -> bool {
    !name.contains('.')
}

/// Shuts the responder down when dropped, which sends one goodbye per
/// record.
struct Responder(ServiceDaemon);

impl Drop for Responder {
    fn drop(&mut self) {
        let _ = self.0.shutdown();
    }
}

/// The server's records, registered under one instance name.
struct Records<'a> {
    daemon: &'a ServiceDaemon,
    host: String,
    interfaces: IfKind,
    service: &'a Service,
    /// Full names of the registered records, as the responder writes them.
    names: Vec<String>,
}

impl Records<'_> {
    fn register(&mut self, name: &str) -> mdns_sd::Result<()> {
        let info = |ty: &str, port: u16, txt: HashMap<String, String>| {
            ServiceInfo::new(ty, name, &self.host, (), port, txt).map(|mut info| {
                info.set_interfaces(vec![self.interfaces.clone()]);
                info.enable_addr_auto()
            })
        };
        let mut infos = vec![info(SMB_TYPE, self.service.port, HashMap::new())?];
        if let Some(model) = &self.service.model {
            let txt = HashMap::from([("model".to_string(), model.clone())]);
            infos.push(info(DEVICE_INFO_TYPE, 0, txt)?);
        }
        for info in infos {
            let fullname = info.get_fullname().to_string();
            self.daemon.register(info)?;
            self.names.push(fullname);
        }
        Ok(())
    }

    fn unregister(&mut self) {
        for fullname in self.names.drain(..) {
            let _ = self.daemon.unregister(&fullname);
        }
    }

    fn owns(&self, fullname: &str) -> bool {
        self.names.iter().any(|n| n.eq_ignore_ascii_case(fullname))
    }

    /// Whether `fullname` is the registered `_smb._tcp` record.
    fn is_smb(&self, fullname: &str) -> bool {
        self.names
            .first()
            .is_some_and(|n| n.eq_ignore_ascii_case(fullname))
    }
}

/// Whether `fullname` is an `_smb._tcp` or `_device-info._tcp` record.
fn is_service_name(fullname: &str) -> bool {
    ends_with_ignore_case(fullname, SMB_TYPE) || ends_with_ignore_case(fullname, DEVICE_INFO_TYPE)
}

fn ends_with_ignore_case(s: &str, suffix: &str) -> bool {
    s.len() >= suffix.len()
        && s.is_char_boundary(s.len() - suffix.len())
        && s[s.len() - suffix.len()..].eq_ignore_ascii_case(suffix)
}

/// Binds UDP port 5353 without sharing it, on IPv4 and on IPv6. Fails with
/// AddrInUse when another program holds it, which would receive the
/// unicast queries meant for this responder, or with the first error when
/// neither family can bind.
fn probe_port() -> io::Result<()> {
    let bind = |ip: IpAddr| UdpSocket::bind((ip, MDNS_PORT)).map(drop);
    let v4 = bind(Ipv4Addr::UNSPECIFIED.into());
    let v6 = bind(Ipv6Addr::UNSPECIFIED.into());
    match (v4, v6) {
        (Err(e), _) | (_, Err(e)) if e.kind() == io::ErrorKind::AddrInUse => Err(e),
        (Err(e), Err(_)) => Err(e),
        _ => Ok(()),
    }
}

/// Whether an interface the responder works on has an address in `scope`.
fn has_usable_interface(scope: Scope) -> bool {
    if_addrs::get_if_addrs().is_ok_and(|interfaces| {
        interfaces.iter().any(|intf| {
            intf.is_oper_up() && !intf.is_p2p() && scope.admits(intf.ip(), intf.is_loopback())
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_name_with_a_dot_is_not_announced() {
        assert!(answerable("My NAS"));
        assert!(!answerable("My.NAS"));
    }

    #[test]
    fn service_names_are_recognized_in_any_case() {
        assert!(is_service_name("FILES._smb._tcp.local."));
        assert!(is_service_name("files._SMB._TCP.LOCAL."));
        assert!(is_service_name("FILES (2)._device-info._tcp.local."));
        assert!(!is_service_name("host-2.local."));
        assert!(!is_service_name("\u{e9}"));
    }
}
