//! Names checked at build time, and the addresses announced for a listener.

#![cfg_attr(any(target_vendor = "apple", not(unix)), allow(dead_code))]

use std::net::IpAddr;

use sha2::{Digest, Sha256};
use tracing::info;
use uuid::Uuid;

/// Longest instance name, in bytes: one DNS label.
const MAX_NAME_BYTES: usize = 63;

/// Longest model, so that `model=<model>` fits one TXT string.
const MAX_MODEL_BYTES: usize = 255 - "model=".len();

/// Longest NetBIOS name, in characters.
const MAX_NETBIOS_CHARS: usize = 15;

/// Characters a NetBIOS name cannot hold.
const NETBIOS_RESERVED: &[char] = &[
    '"', '/', '\\', '[', ']', ':', '|', '<', '>', '+', '=', ';', ',', '?', '*',
];

/// Longest device metadata field, in characters: DPWS limits fields to
/// fewer than 256.
const MAX_FIELD_CHARS: usize = 255;

/// The only port Windows opens a computer it found over WS-Discovery on.
pub(crate) const SMB_PORT: u16 = 445;

/// Whether `name` can be an instance name: 1 to 63 bytes without control
/// characters (RFC 6763 4.1.1).
pub(crate) fn valid_name(name: &str) -> bool {
    (1..=MAX_NAME_BYTES).contains(&name.len()) && !name.chars().any(char::is_control)
}

/// Whether `model` can be announced as `model=<model>`: 1 to 249
/// printable ASCII characters.
pub(crate) fn valid_model(model: &str) -> bool {
    (1..=MAX_MODEL_BYTES).contains(&model.len())
        && model.bytes().all(|b| (0x20..=0x7e).contains(&b))
}

/// Whether `name` can be a NetBIOS computer or workgroup name: 1 to 15
/// characters without control characters or any of `"/\[]:|<>+=;,?*`.
pub(crate) fn valid_netbios_name(name: &str) -> bool {
    (1..=MAX_NETBIOS_CHARS).contains(&name.chars().count())
        && !name
            .chars()
            .any(|c| c.is_control() || NETBIOS_RESERVED.contains(&c))
}

/// Whether `value` fits a device metadata field: 1 to 255 characters
/// without control characters.
pub(crate) fn valid_field(value: &str) -> bool {
    (1..=MAX_FIELD_CHARS).contains(&value.chars().count()) && !value.chars().any(char::is_control)
}

/// Why WS-Discovery does not run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WsSkip {
    /// Turned off through the builder.
    Off,
    /// Windows announces the computer itself.
    Windows,
    /// The server listens on a port other than 445.
    Port,
    /// The NetBIOS name is not one [`valid_netbios_name`] accepts.
    Name,
    /// The NetBIOS name is not the host name, so Windows cannot resolve
    /// it to this host.
    Host,
}

/// Why WS-Discovery does not run for a server listening on `port` under
/// NetBIOS name `name` on host `host`, the first label of the host name,
/// or `None` when it runs. `enabled` is `None` unless set explicitly.
pub(crate) fn ws_discovery_skip(
    enabled: Option<bool>,
    port: u16,
    name: &str,
    host: &str,
    windows: bool,
) -> Option<WsSkip> {
    if enabled == Some(false) {
        Some(WsSkip::Off)
    } else if windows {
        Some(WsSkip::Windows)
    } else if port != SMB_PORT {
        Some(WsSkip::Port)
    } else if !valid_netbios_name(name) {
        Some(WsSkip::Name)
    } else if !name.eq_ignore_ascii_case(host) {
        Some(WsSkip::Host)
    } else {
        None
    }
}

/// The WS-Discovery endpoint of a server on `port`: a version 8 UUID from
/// SHA-256 over the server GUID when one was set, otherwise over the host
/// label and the NetBIOS name, so that it stays the same across restarts.
pub(crate) fn endpoint_uuid(server_guid: Option<Uuid>, host: &str, name: &str, port: u16) -> Uuid {
    let mut hash = Sha256::new();
    hash.update(b"smb-server ws-discovery endpoint\0");
    match server_guid {
        Some(guid) => {
            hash.update([1]);
            hash.update(guid.as_bytes());
        }
        None => {
            hash.update([2]);
            hash.update(host.to_ascii_lowercase().as_bytes());
            hash.update([0]);
            hash.update(name.to_uppercase().as_bytes());
        }
    }
    hash.update(port.to_be_bytes());
    let digest = hash.finalize();
    let mut bytes = [0; 16];
    bytes.copy_from_slice(&digest[..16]);
    Uuid::new_v8(bytes)
}

/// The interface index to register on: 0, every interface, for a
/// wildcard listener, otherwise the interface of the address as
/// `index_of` finds it, or `None` without one.
#[cfg_attr(not(any(target_vendor = "apple", windows)), allow(dead_code))]
pub(crate) fn interface_index(
    scope: Scope,
    index_of: impl Fn(IpAddr) -> Option<u32>,
) -> Option<u32> {
    match scope {
        Scope::V4 | Scope::V6 { .. } => Some(0),
        Scope::Addr(ip) => index_of(ip).filter(|&index| index != 0),
    }
}

/// Index of the interface that has `ip`.
#[cfg_attr(
    not(any(target_os = "linux", target_vendor = "apple", windows)),
    allow(dead_code)
)]
pub(crate) fn if_index_of(ip: IpAddr) -> Option<u32> {
    if_addrs::get_if_addrs()
        .ok()?
        .into_iter()
        .find(|intf| intf.ip() == ip)?
        .index
}

/// `name` with ` (n)` appended, shortened on a character boundary to fit
/// one DNS label.
pub(crate) fn numbered_name(name: &str, n: usize) -> String {
    let suffix = format!(" ({n})");
    let mut cut = name.len().min(MAX_NAME_BYTES - suffix.len());
    while !name.is_char_boundary(cut) {
        cut -= 1;
    }
    format!("{}{suffix}", name[..cut].trim_end())
}

/// The names a system responder registered the service under.
#[derive(Debug, Default)]
#[cfg_attr(not(any(target_vendor = "apple", windows)), allow(dead_code))]
pub(crate) struct Names {
    /// The name asked for, `None` for the system's default name.
    pub(crate) requested: Option<String>,
    pub(crate) current: Option<String>,
}

#[cfg_attr(not(any(target_vendor = "apple", windows)), allow(dead_code))]
impl Names {
    /// Takes note of a registration under `name`, and returns whether the
    /// name changed, so that the device-info record must follow.
    pub(crate) fn registered(&mut self, name: &str) -> bool {
        match (&self.current, &self.requested) {
            (Some(current), _) if current == name => return false,
            (Some(from), _) | (None, Some(from)) if from != name => {
                info!(%from, to = %name, "registered under a new name");
            }
            _ => info!(%name, "announced"),
        }
        self.current = Some(name.to_string());
        true
    }
}

/// The addresses a listener accepts connections on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Scope {
    /// Every IPv4 address.
    V4,
    /// Every IPv6 address, and every IPv4 address too on a dual-stack
    /// socket.
    V6 { dual_stack: bool },
    /// One address.
    Addr(IpAddr),
}

impl Scope {
    /// The scope of a listener bound to `ip`, whose socket has IPV6_V6ONLY
    /// set when `v6_only`.
    pub(crate) fn new(ip: IpAddr, v6_only: bool) -> Self {
        match ip.to_canonical() {
            IpAddr::V4(v4) if v4.is_unspecified() => Scope::V4,
            IpAddr::V6(v6) if v6.is_unspecified() => Scope::V6 {
                dual_stack: !v6_only,
            },
            ip => Scope::Addr(ip),
        }
    }

    /// Whether `ip`, an address of an interface that is a loopback
    /// interface when `loopback`, is announced. Loopback interfaces are
    /// left out unless the listener is bound to that one address.
    pub(crate) fn admits(self, ip: IpAddr, loopback: bool) -> bool {
        let ip = ip.to_canonical();
        match self {
            Scope::Addr(addr) => ip == addr,
            _ if loopback || ip.is_loopback() => false,
            Scope::V4 => ip.is_ipv4(),
            Scope::V6 { dual_stack } => ip.is_ipv6() || dual_stack,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_are_one_label_without_control_characters() {
        // Decomposed and precomposed forms both pass as given.
        for name in [
            "a",
            "a".repeat(63).as_str(),
            "\u{e9}".repeat(31).as_str(),
            "Cafe\u{301}",
            "Caf\u{e9}",
            "My NAS (2)",
        ] {
            assert!(valid_name(name), "{name:?}");
        }
        for name in [
            "",
            "a".repeat(64).as_str(),
            "\u{e9}".repeat(32).as_str(),
            "a\nb",
        ] {
            assert!(!valid_name(name), "{name:?}");
        }
    }

    #[test]
    fn models_fit_one_txt_string_of_printable_ascii() {
        for model in [
            "x",
            "MacPro7,1@ECOLOR=226,226,224",
            "m".repeat(249).as_str(),
        ] {
            assert!(valid_model(model), "{model:?}");
        }
        for model in ["", "m".repeat(250).as_str(), "Caf\u{e9}", "a\tb", "\u{7f}"] {
            assert!(!valid_model(model), "{model:?}");
        }
    }

    #[test]
    fn netbios_names_are_short_without_separators() {
        for workgroup in [
            "WORKGROUP",
            "W",
            "HOME-NET_2",
            "W".repeat(15).as_str(),
            "\u{c9}QUIPE",
        ] {
            assert!(valid_netbios_name(workgroup), "{workgroup:?}");
        }
        for workgroup in [
            "",
            "W".repeat(16).as_str(),
            "A/B",
            "A\\B",
            "A:B",
            "A*",
            "A\tB",
        ] {
            assert!(!valid_netbios_name(workgroup), "{workgroup:?}");
        }
    }

    #[test]
    fn metadata_fields_are_short_and_printable() {
        for value in [
            "smb-server",
            "0.7.0",
            "x".repeat(255).as_str(),
            "\u{e9}".repeat(255).as_str(),
        ] {
            assert!(valid_field(value), "{value:?}");
        }
        for value in ["", "x".repeat(256).as_str(), "a\nb", "\u{7f}"] {
            assert!(!valid_field(value), "{value:?}");
        }
    }

    #[test]
    fn ws_discovery_runs_on_port_445_off_windows() {
        let skip =
            |enabled, port, name, windows| ws_discovery_skip(enabled, port, name, "files", windows);
        assert_eq!(skip(None, 445, "FILES", false), None);
        assert_eq!(skip(Some(true), 445, "FILES", false), None);
        assert_eq!(skip(Some(false), 445, "FILES", false), Some(WsSkip::Off));
        assert_eq!(skip(None, 4445, "FILES", false), Some(WsSkip::Port));
        assert_eq!(skip(Some(true), 0, "FILES", false), Some(WsSkip::Port));
        assert_eq!(skip(None, 445, "A/B", false), Some(WsSkip::Name));
        assert_eq!(skip(None, 445, "files", false), None);
        assert_eq!(skip(None, 445, "MEDIA", false), Some(WsSkip::Host));
        assert_eq!(skip(Some(true), 445, "MEDIA", false), Some(WsSkip::Host));
        assert_eq!(
            ws_discovery_skip(None, 445, "NAS-HOST", "nas-host-with-a-long-name", false),
            Some(WsSkip::Host)
        );
        assert_eq!(skip(None, 445, "FILES", true), Some(WsSkip::Windows));
    }

    #[test]
    fn endpoints_are_stable_and_distinct() {
        let uuid = |s: &str| s.parse::<Uuid>().unwrap();
        let by_host = endpoint_uuid(None, "nas-host", "NAS-HOST", 445);
        assert_eq!(by_host, uuid("ee90cc1b-3b1a-8eb6-97bd-0680fdfe52a4"));
        assert_eq!(endpoint_uuid(None, "NAS-Host", "nas-host", 445), by_host);
        // Two servers on one host under different names or ports.
        assert_ne!(endpoint_uuid(None, "nas-host", "FILES", 445), by_host);
        assert_ne!(endpoint_uuid(None, "nas-host", "NAS-HOST", 4445), by_host);
        let guid = Uuid::from_u128(1);
        let by_guid = endpoint_uuid(Some(guid), "nas-host", "NAS-HOST", 445);
        assert_ne!(by_guid, by_host);
        assert_eq!(endpoint_uuid(Some(guid), "", "", 445), by_guid);
    }

    #[test]
    fn the_interface_follows_the_listen_address() {
        let ip = |s: &str| s.parse::<IpAddr>().unwrap();
        let index_of = |addr: IpAddr| (addr == ip("192.168.1.10")).then_some(4);
        assert_eq!(interface_index(Scope::V4, index_of), Some(0));
        assert_eq!(
            interface_index(Scope::V6 { dual_stack: false }, index_of),
            Some(0)
        );
        assert_eq!(
            interface_index(Scope::Addr(ip("192.168.1.10")), index_of),
            Some(4)
        );
        assert_eq!(interface_index(Scope::Addr(ip("10.0.0.1")), index_of), None);
        assert_eq!(
            interface_index(Scope::Addr(ip("10.0.0.1")), |_| Some(0)),
            None
        );
    }

    #[test]
    fn numbered_names_fit_one_label() {
        assert_eq!(numbered_name("FILES", 2), "FILES (2)");
        assert_eq!(numbered_name("a.b\\c", 3), "a.b\\c (3)");
        let long = "n".repeat(63);
        assert_eq!(numbered_name(&long, 2), format!("{} (2)", "n".repeat(59)));
        assert_eq!(numbered_name(&long, 10), format!("{} (10)", "n".repeat(58)));
        // U+00E9 takes two bytes: the cut falls before a whole character.
        let accented = "\u{e9}".repeat(31);
        let renamed = numbered_name(&accented, 2);
        assert_eq!(renamed, format!("{} (2)", "\u{e9}".repeat(29)));
        // A space before the cut is dropped, not doubled.
        let spaced = format!("{} b", "a".repeat(58));
        assert_eq!(numbered_name(&spaced, 2), format!("{} (2)", "a".repeat(58)));
        for n in [2, 9, 10, 99, 100] {
            for name in [long.as_str(), accented.as_str(), spaced.as_str(), "x"] {
                assert!(valid_name(&numbered_name(name, n)), "{name:?} {n}");
            }
        }
    }

    #[test]
    fn the_device_info_record_follows_renames() {
        let mut names = Names::default();
        assert!(names.registered("mac-host"));
        assert!(!names.registered("mac-host"));
        let mut names = Names {
            requested: Some("FILES".to_string()),
            current: None,
        };
        assert!(names.registered("FILES"));
        assert!(!names.registered("FILES"));
        assert!(names.registered("FILES (2)"));
        assert!(!names.registered("FILES (2)"));
        let mut names = Names {
            requested: Some("FILES".to_string()),
            current: None,
        };
        assert!(names.registered("FILES (2)"));
    }

    #[test]
    fn the_scope_follows_the_listen_address() {
        let ip = |s: &str| s.parse::<IpAddr>().unwrap();
        assert_eq!(Scope::new(ip("0.0.0.0"), false), Scope::V4);
        assert_eq!(Scope::new(ip("::"), false), Scope::V6 { dual_stack: true });
        assert_eq!(Scope::new(ip("::"), true), Scope::V6 { dual_stack: false });
        assert_eq!(Scope::new(ip("::ffff:0.0.0.0"), false), Scope::V4);
        assert_eq!(
            Scope::new(ip("10.0.0.5"), false),
            Scope::Addr(ip("10.0.0.5"))
        );
        assert_eq!(
            Scope::new(ip("::ffff:10.0.0.5"), true),
            Scope::Addr(ip("10.0.0.5"))
        );
        assert_eq!(Scope::new(ip("fe80::1"), true), Scope::Addr(ip("fe80::1")));
    }

    #[test]
    fn addresses_are_admitted_by_family_loopback_and_address() {
        let ip = |s: &str| s.parse::<IpAddr>().unwrap();
        let v4 = ip("192.168.1.10");
        let v6 = ip("fe80::10");
        let dual = Scope::V6 { dual_stack: true };
        let v6_only = Scope::V6 { dual_stack: false };

        let table: [(Scope, IpAddr, bool, bool); 11] = [
            (Scope::V4, v4, false, true),
            (Scope::V4, v6, false, false),
            (Scope::V4, ip("127.0.0.1"), true, false),
            (Scope::V4, ip("127.0.0.2"), false, false),
            (dual, v4, false, true),
            (dual, v6, false, true),
            (dual, ip("::1"), true, false),
            (v6_only, v4, false, false),
            (v6_only, v6, false, true),
            (Scope::Addr(v4), v4, false, true),
            (Scope::Addr(v4), ip("192.168.1.11"), false, false),
        ];
        for (scope, addr, loopback, admitted) in table {
            assert_eq!(
                scope.admits(addr, loopback),
                admitted,
                "{scope:?} {addr} {loopback}"
            );
        }
    }
}
