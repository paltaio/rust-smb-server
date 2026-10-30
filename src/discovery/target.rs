//! Names checked at build time, and the addresses announced for a listener.

#![cfg_attr(any(target_vendor = "apple", not(unix)), allow(dead_code))]

use std::net::IpAddr;

use tracing::info;

/// Longest instance name, in bytes: one DNS label.
const MAX_NAME_BYTES: usize = 63;

/// Longest model, so that `model=<model>` fits one TXT string.
const MAX_MODEL_BYTES: usize = 255 - "model=".len();

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
            "a\0",
            "\u{7f}",
            "\u{85}x",
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
        let global = ip("2001:db8::10");
        let dual = Scope::V6 { dual_stack: true };
        let v6_only = Scope::V6 { dual_stack: false };

        let table: [(Scope, IpAddr, bool, bool); 12] = [
            (Scope::V4, v4, false, true),
            (Scope::V4, v6, false, false),
            (Scope::V4, ip("127.0.0.1"), true, false),
            (Scope::V4, ip("127.0.0.2"), false, false),
            (dual, v4, false, true),
            (dual, v6, false, true),
            (dual, global, false, true),
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
