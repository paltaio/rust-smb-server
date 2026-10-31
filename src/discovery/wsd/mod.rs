//! WS-Discovery: the server as a computer in the Windows Network folder,
//! a DPWS device that Windows finds over UDP and whose metadata it reads
//! over HTTP (MS-PBSD).

mod engine;
mod http;
mod msg;
mod net;
#[cfg(test)]
mod samples;
mod xml;

pub(crate) use net::run;

/// Resolves once `stop` turns true or its sender is gone.
async fn until_stopped(stop: &mut tokio::sync::watch::Receiver<bool>) {
    let _ = stop.wait_for(|stopped| *stopped).await;
}

/// What `fuzzing::wsd_datagram` runs; its documentation describes `data`.
#[cfg(fuzzing)]
pub(crate) fn fuzz_datagram(data: &[u8]) {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

    let Some((&pick, rest)) = data.split_first() else {
        return;
    };
    let v6 = pick & 1 == 1;
    let len = if v6 { 16 } else { 4 };
    let Some((addr, rest)) = rest.split_at_checked(len + 2) else {
        return;
    };
    let port = u16::from_be_bytes([addr[len], addr[len + 1]]);
    let from = if v6 {
        let bytes: [u8; 16] = addr[..16].try_into().expect("16 bytes");
        SocketAddr::new(Ipv6Addr::from(bytes).into(), port)
    } else {
        let bytes: [u8; 4] = addr[..4].try_into().expect("4 bytes");
        SocketAddr::new(Ipv4Addr::from(bytes).into(), port)
    };
    let link = if v6 {
        engine::Link {
            index: 1,
            addr: IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1)),
            networks: vec![(
                IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
                64,
            )],
        }
    } else {
        engine::Link {
            index: 1,
            addr: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)),
            networks: vec![(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)), 24)],
        }
    };
    let device = std::sync::Arc::new(fuzz_device());
    let xaddr = net::xaddr(link.addr, 5357, device.endpoint);
    let now = tokio::time::Instant::now();
    let engine = std::sync::Mutex::new(engine::Engine::new(device, 1, uuid::Uuid::nil(), now));
    if let Some(reply) = engine::handle(&engine, now, &link, &xaddr, from, rest) {
        assert!(link.on_link(from.ip()));
        assert_eq!(reply.to, from);
        assert!(reply.message.len() <= engine::MAX_DATAGRAM);
        let text = std::str::from_utf8(&reply.message).expect("UTF-8");
        assert!(xml::parse(text).is_ok());
    }
}

/// Answers `data` as a whole request to the metadata endpoint.
#[cfg(fuzzing)]
pub(crate) fn fuzz_http(data: &[u8]) {
    let response = http::respond(data, &fuzz_device());
    assert!(response.starts_with(b"HTTP/1.1 "));
}

#[cfg(fuzzing)]
fn fuzz_device() -> crate::discovery::Device {
    crate::discovery::Device {
        endpoint: uuid::Uuid::from_u128(0x6ba7_b810_9dad_81d1_80b4_00c0_4fd4_30c8),
        info: crate::discovery::DeviceInfo {
            computer: "FUZZ<&>".to_string(),
            workgroup: "WORKGROUP".to_string(),
            manufacturer: "smb-server".to_string(),
            model_name: "smb-server".to_string(),
            firmware_version: "0.0.0".to_string(),
        },
    }
}
