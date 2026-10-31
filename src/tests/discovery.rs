use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::sync::Notify;
use tokio::time::Instant;

use uuid::Uuid;

use crate::discovery::target::Scope;
use crate::discovery::target::endpoint_uuid;
use crate::discovery::{Backend, DeviceInfo, Service, Stop, ws_device};
use crate::{BuildError, Discovery, SmbServer};

/// A dual-stack listener.
const V6: Scope = Scope::V6 { dual_stack: true };

#[derive(Clone, Copy)]
enum Behavior {
    /// Announces until told to stop.
    Announce,
    /// Gives up at once.
    Fail,
    /// Never returns.
    Hang,
}

#[derive(Debug, PartialEq)]
enum Event {
    Started { name: String, port: u16 },
    Stopped,
}

/// Records what `serve` asks of it.
struct Fake {
    behavior: Behavior,
    events: Mutex<Vec<Event>>,
    started: Notify,
    stopped: Notify,
}

impl Fake {
    fn new(behavior: Behavior) -> Arc<Self> {
        Arc::new(Self {
            behavior,
            events: Mutex::new(Vec::new()),
            started: Notify::new(),
            stopped: Notify::new(),
        })
    }

    fn events(&self) -> Vec<Event> {
        std::mem::take(&mut *self.events.lock().unwrap())
    }
}

#[async_trait]
impl Backend for Fake {
    async fn run(&self, service: Service, stop: Stop) {
        self.events.lock().unwrap().push(Event::Started {
            name: service.name,
            port: service.port,
        });
        self.started.notify_one();
        match self.behavior {
            Behavior::Announce => {
                let _ = stop.await;
                self.events.lock().unwrap().push(Event::Stopped);
                self.stopped.notify_one();
            }
            Behavior::Fail => {}
            Behavior::Hang => std::future::pending().await,
        }
    }
}

fn announced(listen: &str, discovery: Discovery) -> Result<SmbServer, BuildError> {
    SmbServer::builder()
        .listen(listen.parse().unwrap())
        .netbios_name("files")
        .discovery(discovery)
        .build()
}

async fn serving(fake: &Arc<Fake>) -> (SmbServer, u16) {
    let server = announced("0.0.0.0:0", Discovery::new())
        .expect("build")
        .with_discovery_backend(fake.clone());
    let port = server.bind().await.expect("bind").port();
    (server, port)
}

#[tokio::test]
async fn serve_announces_the_bound_port_and_withdraws_before_returning() {
    let fake = Fake::new(Behavior::Announce);
    let (server, port) = serving(&fake).await;
    let shutdown = server.shutdown_handle();
    let serving = tokio::spawn(server.serve());
    fake.started.notified().await;
    assert_eq!(
        fake.events(),
        [Event::Started {
            name: "FILES".to_string(),
            port
        }]
    );

    shutdown.shutdown();
    serving.await.expect("join").expect("serve");
    assert_eq!(fake.events(), [Event::Stopped]);
}

#[tokio::test]
async fn nothing_is_announced_when_shutdown_comes_first() {
    let fake = Fake::new(Behavior::Announce);
    let (server, _) = serving(&fake).await;
    server.shutdown();
    server.serve().await.expect("serve");
    assert_eq!(fake.events(), []);
}

#[tokio::test]
async fn a_failed_announcement_leaves_the_server_serving() {
    let fake = Fake::new(Behavior::Fail);
    let (server, port) = serving(&fake).await;
    let shutdown = server.shutdown_handle();
    let serving = tokio::spawn(server.serve());
    fake.started.notified().await;

    let peer = SocketAddr::from(([127, 0, 0, 1], port));
    let stream = TcpStream::connect(peer).await.expect("connect");
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(!serving.is_finished());
    drop(stream);

    shutdown.shutdown();
    serving.await.expect("join").expect("serve");
    assert_eq!(fake.events().len(), 1);
}

#[tokio::test]
async fn the_withdrawal_runs_while_connections_drain() {
    let fake = Fake::new(Behavior::Announce);
    let (server, port) = serving(&fake).await;
    let shutdown = server.shutdown_handle();
    let serving = tokio::spawn(server.serve());
    fake.started.notified().await;

    // A frame that has started to arrive keeps its connection open after
    // the shutdown, until the rest arrives or the client goes.
    let peer = SocketAddr::from(([127, 0, 0, 1], port));
    let mut stream = TcpStream::connect(peer).await.expect("connect");
    stream.write_all(&[0, 0, 0, 64, 0xfe]).await.expect("write");
    tokio::time::sleep(Duration::from_millis(100)).await;
    shutdown.shutdown();
    tokio::time::timeout(Duration::from_secs(5), fake.stopped.notified())
        .await
        .expect("withdrawn");
    assert!(!serving.is_finished());

    drop(stream);
    serving.await.expect("join").expect("serve");
    assert_eq!(fake.events().last(), Some(&Event::Stopped));
}

#[tokio::test(start_paused = true)]
async fn serve_waits_at_most_two_seconds_for_the_withdrawal() {
    let fake = Fake::new(Behavior::Hang);
    let (server, _) = serving(&fake).await;
    let shutdown = server.shutdown_handle();
    let serving = tokio::spawn(server.serve());
    fake.started.notified().await;

    let start = Instant::now();
    shutdown.shutdown();
    tokio::time::timeout(Duration::from_secs(10), serving)
        .await
        .expect("serve returned")
        .expect("join")
        .expect("serve");
    let waited = start.elapsed();
    assert!(waited >= Duration::from_secs(2), "{waited:?}");
    assert!(waited < Duration::from_millis(2100), "{waited:?}");
}

#[test]
fn loopback_listen_addresses_cannot_be_announced() {
    for listen in [
        "127.0.0.1:445",
        "127.1.2.3:0",
        "[::1]:445",
        "[::ffff:127.0.0.1]:445",
    ] {
        assert!(
            matches!(
                announced(listen, Discovery::new()),
                Err(BuildError::DiscoveryOnLoopback(addr)) if addr == listen.parse().unwrap()
            ),
            "{listen}"
        );
    }
    for listen in [
        "0.0.0.0:445",
        "[::]:0",
        "192.168.1.10:4445",
        "[fe80::1]:445",
    ] {
        assert!(announced(listen, Discovery::new()).is_ok(), "{listen}");
    }
}

#[test]
fn names_and_models_are_checked_at_build() {
    assert!(matches!(
        announced("0.0.0.0:0", Discovery::new().name("a\tb")),
        Err(BuildError::DiscoveryName(n)) if n == "a\tb"
    ));
    assert!(matches!(
        announced("0.0.0.0:0", Discovery::new().model("Caf\u{e9}")),
        Err(BuildError::DiscoveryModel(m)) if m == "Caf\u{e9}"
    ));
    let server = announced(
        "0.0.0.0:0",
        Discovery::new().name("Media Server").model("Xserve3,1"),
    )
    .expect("build");
    let settings = server.state().config.discovery.clone().expect("discovery");
    assert_eq!(settings.name, "Media Server");
    assert!(!settings.default_name);
    assert_eq!(settings.model.as_deref(), Some("Xserve3,1"));
}

#[test]
fn the_name_defaults_to_the_netbios_name_in_upper_case() {
    let server = announced("0.0.0.0:0", Discovery::new()).expect("build");
    let settings = server.state().config.discovery.clone().expect("discovery");
    assert_eq!(settings.name, "FILES");
    assert!(settings.default_name);
    assert_eq!(settings.model, None);

    let server = SmbServer::builder()
        .listen("0.0.0.0:0".parse().unwrap())
        .netbios_name("")
        .discovery(Discovery::new())
        .build();
    assert!(matches!(server, Err(BuildError::DiscoveryName(n)) if n.is_empty()));
}

#[test]
fn ws_discovery_options_are_checked_at_build() {
    assert!(matches!(
        announced("0.0.0.0:0", Discovery::new().workgroup("A/B")),
        Err(BuildError::DiscoveryWorkgroup(w)) if w == "A/B"
    ));
    assert!(matches!(
        announced("0.0.0.0:0", Discovery::new().firmware_version("1\n2")),
        Err(BuildError::DiscoveryMetadata { setting: "firmware_version", value }) if value == "1\n2"
    ));
    assert!(matches!(
        announced("0.0.0.0:4445", Discovery::new().ws_discovery(true)),
        Err(BuildError::WsDiscoveryPort(4445))
    ));
    assert!(announced("0.0.0.0:4445", Discovery::new()).is_ok());
    assert!(announced("0.0.0.0:0", Discovery::new().ws_discovery(true)).is_ok());

    let build = |discovery| {
        SmbServer::builder()
            .listen("0.0.0.0:445".parse().unwrap())
            .netbios_name("a/b")
            .discovery(discovery)
            .build()
    };
    assert!(matches!(
        build(Discovery::new().name("Files").ws_discovery(true)),
        Err(BuildError::WsDiscoveryNetbiosName(n)) if n == "a/b"
    ));
    // Without ws_discovery(true), WS-Discovery is skipped at run time.
    let server = build(Discovery::new().name("Files")).expect("build");
    let settings = server.state().config.discovery.clone().expect("discovery");
    assert_eq!(ws_device(&settings, 445, "a/b", V6), None);
}

#[test]
fn ws_discovery_metadata_has_defaults_and_overrides() {
    let server = announced("0.0.0.0:445", Discovery::new().name("Media")).expect("build");
    let settings = server.state().config.discovery.clone().expect("discovery");
    assert_eq!(
        settings.info,
        DeviceInfo {
            computer: "FILES".to_string(),
            workgroup: "WORKGROUP".to_string(),
            manufacturer: "smb-server".to_string(),
            model_name: "smb-server".to_string(),
            firmware_version: env!("CARGO_PKG_VERSION").to_string(),
        }
    );
    assert_eq!(settings.ws_discovery, None);
    assert_eq!(settings.server_guid, None);

    let guid = Uuid::from_u128(0x6ba7_b810_9dad_11d1_80b4_00c0_4fd4_30c8);
    let server = SmbServer::builder()
        .listen("0.0.0.0:445".parse().unwrap())
        .netbios_name("files")
        .server_guid(guid)
        .discovery(
            Discovery::new()
                .workgroup("home")
                .manufacturer("Acme")
                .model_name("NAS 2")
                .firmware_version("2.1"),
        )
        .build()
        .expect("build");
    let settings = server.state().config.discovery.clone().expect("discovery");
    assert_eq!(settings.info.workgroup, "HOME");
    assert_eq!(settings.info.manufacturer, "Acme");
    assert_eq!(settings.info.model_name, "NAS 2");
    assert_eq!(settings.info.firmware_version, "2.1");
    assert_eq!(settings.server_guid, Some(guid));
}

#[test]
fn ws_device_carries_the_settings_and_endpoint() {
    let server = announced("0.0.0.0:0", Discovery::new()).expect("build");
    let settings = server.state().config.discovery.clone().expect("discovery");
    let device = ws_device(&settings, 445, "files", V6);
    if cfg!(windows) {
        assert_eq!(device, None);
        return;
    }
    let device = device.expect("device");
    assert_eq!(device.endpoint, endpoint_uuid(None, "files", "FILES", 445));
    assert_eq!(device.info, settings.info);

    let guid = Uuid::from_u128(1);
    let server = SmbServer::builder()
        .listen("0.0.0.0:445".parse().unwrap())
        .netbios_name("files")
        .server_guid(guid)
        .discovery(Discovery::new())
        .build()
        .expect("build");
    let settings = server.state().config.discovery.clone().expect("discovery");
    let device = ws_device(&settings, 445, "files", V6).expect("device");
    assert_eq!(device.endpoint, endpoint_uuid(Some(guid), "", "", 445));
}
