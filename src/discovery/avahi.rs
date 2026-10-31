//! Registration with avahi-daemon over the system D-Bus.

use std::net::IpAddr;
use std::pin::Pin;
use std::time::Duration;

use tokio::sync::oneshot;
use tokio::time::Instant;
use tracing::{debug, info, warn};
use zbus::export::futures_core::Stream;
use zbus::export::serde::Serialize;
use zbus::message::Type;
use zbus::{Connection, DynamicType, MatchRule, Message, MessageStream, OwnedObjectPath};

use super::responder::{self, Leave};
use super::target::{Scope, if_index_of};
use super::{MAX_RENAMES, Service, Stop};

const BUS: &str = "org.freedesktop.DBus";
const AVAHI: &str = "org.freedesktop.Avahi";
const SERVER: &str = "org.freedesktop.Avahi.Server";
const ENTRY_GROUP: &str = "org.freedesktop.Avahi.EntryGroup";
const COLLISION_ERROR: &str = "org.freedesktop.Avahi.CollisionError";

// From avahi-common/defs.h.
const IF_UNSPEC: i32 = -1;
const PROTO_UNSPEC: i32 = -1;
const PROTO_INET: i32 = 0;
const PROTO_INET6: i32 = 1;
const SERVER_REGISTERING: i32 = 1;
const SERVER_RUNNING: i32 = 2;
const SERVER_COLLISION: i32 = 3;
const GROUP_ESTABLISHED: i32 = 2;
const GROUP_COLLISION: i32 = 3;
const GROUP_FAILURE: i32 = 4;

/// Longest wait for an answer from the bus or from Avahi.
const CALL_TIMEOUT: Duration = Duration::from_secs(5);

/// Most GetState calls in a row that may fail before the server waits for
/// a state change instead. The wait before a retry doubles from
/// [`STATE_RETRY`].
const MAX_STATE_QUERIES: u32 = 5;
const STATE_RETRY: Duration = Duration::from_millis(500);

/// A connection to the system bus, watching avahi-daemon's bus name.
pub(super) struct Bus {
    conn: Connection,
    /// Avahi's unique bus name, empty while it is not on the bus.
    owner: String,
    /// NameOwnerChanged of Avahi's bus name.
    owners: MessageStream,
    /// StateChanged of the Avahi server and of entry groups.
    states: MessageStream,
}

impl Bus {
    /// Connects to the system bus, or returns `None` when there is none.
    pub(super) async fn connect() -> Option<Self> {
        match tokio::time::timeout(CALL_TIMEOUT, Self::try_connect()).await {
            Ok(Ok(bus)) => Some(bus),
            Ok(Err(e)) => {
                debug!(error = %e, "no system bus");
                None
            }
            Err(_) => {
                debug!("no answer from the system bus");
                None
            }
        }
    }

    async fn try_connect() -> zbus::Result<Self> {
        let conn = zbus::connection::Builder::system()
            .method_timeout(CALL_TIMEOUT)
            .build()
            .await?;
        // Subscribe first, so that no change after the owner lookup is
        // missed.
        let owners = MatchRule::builder()
            .msg_type(Type::Signal)
            .sender(BUS)
            .interface(BUS)
            .member("NameOwnerChanged")
            .add_arg(AVAHI)
            .build()?;
        let owners = MessageStream::for_match_rule(owners, &conn, None).await?;
        let states = MatchRule::builder()
            .msg_type(Type::Signal)
            .sender(AVAHI)
            .member("StateChanged")
            .build()?;
        let states = MessageStream::for_match_rule(states, &conn, None).await?;
        // GetNameOwner does not start a daemon that is installed but
        // stopped, as a call to Avahi itself would through bus activation.
        let owner = match conn
            .call_method(
                Some(BUS),
                "/org/freedesktop/DBus",
                Some(BUS),
                "GetNameOwner",
                &(AVAHI,),
            )
            .await
        {
            Ok(reply) => reply.body().deserialize::<String>()?,
            // The bus answers with an error while the name has no owner.
            Err(zbus::Error::MethodError(..) | zbus::Error::FDO(_)) => String::new(),
            Err(e) => return Err(e),
        };
        Ok(Self {
            conn,
            owner,
            owners,
            states,
        })
    }

    /// Announces `service` through Avahi until `stop` resolves. While Avahi
    /// is not on the bus at first, the built-in responder announces it, up
    /// to the moment Avahi arrives.
    pub(super) async fn run(mut self, service: Service, mut stop: Stop) {
        if self.owner.is_empty() {
            debug!("avahi-daemon is not on the system bus");
            if !self.answer_until_avahi(&service, &mut stop).await {
                return;
            }
            info!("avahi-daemon is on the system bus; handing the announcement over to it");
        }
        let Some((interface, protocol)) = scope_args(service.scope, if_index_of) else {
            warn!("the listen address is on no interface; the server is not announced");
            return;
        };
        info!(name = %service.name, "announcing the server through Avahi");
        let mut group = Group {
            conn: self.conn.clone(),
            interface,
            protocol,
            machine: Machine::new(service.name.clone()),
            service,
        };
        let mut query = StateQuery::default();
        self.query_state(&mut group, &mut query).await;

        let stopped = loop {
            let retry = query.due;
            tokio::select! {
                _ = &mut stop => break true,
                () = sleep_until(retry), if retry.is_some() => {
                    self.query_state(&mut group, &mut query).await;
                }
                msg = next(&mut self.owners) => {
                    let Some(msg) = msg else { break false };
                    let Some(owner) = new_owner(&msg) else { continue };
                    self.owner = owner;
                    group.machine.owner_changed();
                    query = StateQuery::default();
                    if self.owner.is_empty() {
                        warn!("avahi-daemon left the system bus; the server is announced again when it returns");
                        continue;
                    }
                    info!("avahi-daemon is back; announcing the server again");
                    self.query_state(&mut group, &mut query).await;
                }
                msg = next(&mut self.states) => {
                    let Some(msg) = msg else { break false };
                    let header = msg.header();
                    if self.owner.is_empty()
                        || header.sender().map(|s| s.as_str()) != Some(self.owner.as_str())
                    {
                        continue;
                    }
                    let Ok((state, error)) = msg.body().deserialize::<(i32, String)>() else {
                        continue;
                    };
                    let interface = header.interface().map(|i| i.as_str());
                    let path = header.path().map(|p| p.as_str());
                    let step = if interface == Some(SERVER) {
                        query = StateQuery::default();
                        group.machine.server_state(state)
                    } else if interface == Some(ENTRY_GROUP)
                        && path.is_some()
                        && path == group.machine.path.as_deref()
                    {
                        group.machine.group_state(state, &error)
                    } else {
                        Step::Nothing
                    };
                    group.apply(step).await;
                }
            }
        };

        if stopped {
            group.free().await;
        } else {
            warn!("lost the connection to the system bus; the server is no longer announced");
            let _ = stop.await;
        }
    }

    /// Runs the built-in responder until `stop` resolves, returning false,
    /// or until Avahi appears on the bus, returning true.
    async fn answer_until_avahi(&mut self, service: &Service, stop: &mut Stop) -> bool {
        let (leave, left) = oneshot::channel();
        let answering = responder::run(service.clone(), async {
            left.await.unwrap_or(Leave::Withdraw)
        });
        tokio::pin!(answering);
        let mut done = false;
        let how = loop {
            tokio::select! {
                () = &mut answering, if !done => done = true,
                _ = &mut *stop => break Leave::Withdraw,
                msg = next(&mut self.owners) => {
                    let Some(msg) = msg else {
                        // Without the bus, Avahi cannot be followed: keep
                        // answering until told to stop.
                        if !done {
                            tokio::select! {
                                () = &mut answering => {}
                                _ = &mut *stop => {
                                    let _ = leave.send(Leave::Withdraw);
                                    answering.await;
                                }
                            }
                        }
                        return false;
                    };
                    match new_owner(&msg) {
                        Some(owner) if !owner.is_empty() => {
                            self.owner = owner;
                            break Leave::HandOver;
                        }
                        _ => {}
                    }
                }
            }
        };
        let handing_over = matches!(how, Leave::HandOver);
        let _ = leave.send(how);
        if !done {
            answering.await;
        }
        handing_over
    }

    /// Asks Avahi for its state and acts on it. A failed call is retried
    /// later, since Avahi sends no state change while it stays running.
    async fn query_state(&self, group: &mut Group, query: &mut StateQuery) {
        query.due = None;
        let state = call(&self.conn, "/", SERVER, "GetState", &())
            .await
            .and_then(|reply| reply.body().deserialize::<i32>());
        match state {
            Ok(state) => {
                query.failures = 0;
                let step = group.machine.server_state(state);
                group.apply(step).await;
            }
            Err(e) => {
                query.failures += 1;
                if query.failures < MAX_STATE_QUERIES {
                    debug!(error = %e, "no state from avahi-daemon; asking again");
                    query.due = Some(Instant::now() + STATE_RETRY * 2u32.pow(query.failures - 1));
                } else {
                    warn!(error = %e, "no state from avahi-daemon; the server is announced once avahi-daemon reports a change");
                }
            }
        }
    }
}

/// Failed GetState calls in a row, and when the next one is due.
#[derive(Debug, Default)]
struct StateQuery {
    failures: u32,
    due: Option<Instant>,
}

/// Sleeps until `due`, or forever without one.
async fn sleep_until(due: Option<Instant>) {
    match due {
        Some(due) => tokio::time::sleep_until(due).await,
        None => std::future::pending().await,
    }
}

/// What the server's entry group needs next.
#[derive(Debug, PartialEq, Eq)]
enum Step {
    Nothing,
    /// Create the group if there is none, add the records and commit them.
    Register,
    /// Withdraw the records and keep the group.
    Reset,
    /// Withdraw the records and ask Avahi for another name.
    Rename,
}

/// The state of the server's registration, apart from the bus.
#[derive(Debug)]
struct Machine {
    /// The configured name.
    base: String,
    /// The name registered.
    name: String,
    /// The entry group, once Avahi created it.
    path: Option<String>,
    /// The records are added and committed.
    committed: bool,
    /// Renames since the records were last established.
    renames: usize,
}

impl Machine {
    fn new(name: String) -> Self {
        Self {
            name: name.clone(),
            base: name,
            path: None,
            committed: false,
            renames: 0,
        }
    }

    fn server_state(&mut self, state: i32) -> Step {
        match state {
            SERVER_RUNNING if !self.committed && self.renames <= MAX_RENAMES => Step::Register,
            // The host name is not established: Avahi asks for the
            // records to be withdrawn until it is.
            SERVER_REGISTERING | SERVER_COLLISION if self.committed => {
                self.committed = false;
                Step::Reset
            }
            _ => Step::Nothing,
        }
    }

    fn group_state(&mut self, state: i32, error: &str) -> Step {
        match state {
            GROUP_ESTABLISHED => {
                self.renames = 0;
                info!(name = %self.name, "announced");
                Step::Nothing
            }
            GROUP_COLLISION => self.collision(),
            GROUP_FAILURE => {
                self.committed = false;
                warn!(%error, "avahi-daemon withdrew the server's records");
                Step::Nothing
            }
            _ => Step::Nothing,
        }
    }

    /// The name is taken, on the network or by another registration on
    /// this host.
    fn collision(&mut self) -> Step {
        self.committed = false;
        self.renames += 1;
        if self.renames <= MAX_RENAMES {
            return Step::Rename;
        }
        if self.renames == MAX_RENAMES + 1 {
            warn!(name = %self.base, "no free name found; the server is not announced");
        }
        Step::Reset
    }

    fn renamed(&mut self, name: String) -> Step {
        info!(from = %self.name, to = %name, "renamed after a name conflict");
        self.name = name;
        Step::Register
    }

    /// Avahi left the bus or came back: its entry groups went with it.
    fn owner_changed(&mut self) {
        self.name = self.base.clone();
        self.path = None;
        self.committed = false;
        self.renames = 0;
    }
}

/// The entry group holding the server's records.
struct Group {
    conn: Connection,
    service: Service,
    interface: i32,
    protocol: i32,
    machine: Machine,
}

impl Group {
    async fn apply(&mut self, mut step: Step) {
        loop {
            step = match step {
                Step::Nothing => return,
                Step::Reset => {
                    self.reset().await;
                    return;
                }
                Step::Register => match self.add_and_commit().await {
                    Ok(()) => {
                        self.machine.committed = true;
                        return;
                    }
                    Err(zbus::Error::MethodError(name, _, _))
                        if name.as_str() == COLLISION_ERROR =>
                    {
                        self.machine.collision()
                    }
                    Err(e) => {
                        warn!(error = %e, "avahi-daemon refused the server's records; the server is not announced");
                        self.machine.committed = false;
                        Step::Reset
                    }
                },
                Step::Rename => {
                    self.reset().await;
                    match self.alternative_name().await {
                        Ok(name) => self.machine.renamed(name),
                        Err(e) => {
                            warn!(error = %e, "no other name from avahi-daemon; the server is not announced");
                            return;
                        }
                    }
                }
            };
        }
    }

    async fn add_and_commit(&mut self) -> zbus::Result<()> {
        let path = match &self.machine.path {
            Some(path) => path.clone(),
            None => {
                let path = call(&self.conn, "/", SERVER, "EntryGroupNew", &())
                    .await?
                    .body()
                    .deserialize::<OwnedObjectPath>()?
                    .as_str()
                    .to_string();
                self.machine.path = Some(path.clone());
                path
            }
        };
        let (interface, protocol) = (self.interface, self.protocol);
        let name = self.machine.name.as_str();
        let add = |ty: &'static str, port: u16, txt: Vec<Vec<u8>>| {
            (interface, protocol, 0u32, name, ty, "", "", port, txt)
        };
        let smb = add("_smb._tcp", self.service.port, Vec::new());
        call(&self.conn, &path, ENTRY_GROUP, "AddService", &smb).await?;
        if let Some(model) = &self.service.model {
            let txt = vec![format!("model={model}").into_bytes()];
            let info = add("_device-info._tcp", 0, txt);
            call(&self.conn, &path, ENTRY_GROUP, "AddService", &info).await?;
        }
        call(&self.conn, &path, ENTRY_GROUP, "Commit", &()).await?;
        Ok(())
    }

    async fn alternative_name(&self) -> zbus::Result<String> {
        let name = (self.machine.name.as_str(),);
        call(&self.conn, "/", SERVER, "GetAlternativeServiceName", &name)
            .await?
            .body()
            .deserialize::<String>()
    }

    /// Withdraws the records and keeps the group.
    async fn reset(&mut self) {
        if let Some(path) = &self.machine.path
            && let Err(e) = call(&self.conn, path, ENTRY_GROUP, "Reset", &()).await
        {
            debug!(error = %e, "cannot reset the entry group");
        }
    }

    /// Withdraws the records and frees the group.
    async fn free(&mut self) {
        if let Some(path) = self.machine.path.take()
            && let Err(e) = call(&self.conn, &path, ENTRY_GROUP, "Free", &()).await
        {
            debug!(error = %e, "cannot free the entry group");
        }
    }
}

async fn call<B>(
    conn: &Connection,
    path: &str,
    interface: &str,
    method: &str,
    body: &B,
) -> zbus::Result<Message>
where
    B: Serialize + DynamicType,
{
    conn.call_method(Some(AVAHI), path, Some(interface), method, body)
        .await
}

/// The next message of `stream`, or `None` once the connection is gone.
async fn next(stream: &mut MessageStream) -> Option<Message> {
    loop {
        match std::future::poll_fn(|cx| Pin::new(&mut *stream).poll_next(cx)).await? {
            Ok(msg) => return Some(msg),
            Err(e) => debug!(error = %e, "unreadable D-Bus message"),
        }
    }
}

/// The new owner in a NameOwnerChanged signal, empty when the name was
/// released.
fn new_owner(msg: &Message) -> Option<String> {
    let (_, _, owner) = msg.body().deserialize::<(String, String, String)>().ok()?;
    Some(owner)
}

/// The interface and protocol arguments of AddService for `scope`.
fn scope_args(scope: Scope, index_of: impl Fn(IpAddr) -> Option<u32>) -> Option<(i32, i32)> {
    let family = |ip: IpAddr| {
        if ip.is_ipv4() {
            PROTO_INET
        } else {
            PROTO_INET6
        }
    };
    match scope {
        Scope::V4 => Some((IF_UNSPEC, PROTO_INET)),
        Scope::V6 { dual_stack: true } => Some((IF_UNSPEC, PROTO_UNSPEC)),
        Scope::V6 { dual_stack: false } => Some((IF_UNSPEC, PROTO_INET6)),
        Scope::Addr(ip) => {
            let index = i32::try_from(index_of(ip)?).ok()?;
            Some((index, family(ip)))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_scope_picks_interface_and_protocol() {
        let ip = |s: &str| s.parse::<IpAddr>().unwrap();
        let index_of =
            |addr: IpAddr| (addr == ip("192.168.1.10") || addr == ip("fe80::1")).then_some(3);
        assert_eq!(
            scope_args(Scope::V4, index_of),
            Some((IF_UNSPEC, PROTO_INET))
        );
        assert_eq!(
            scope_args(Scope::V6 { dual_stack: true }, index_of),
            Some((IF_UNSPEC, PROTO_UNSPEC))
        );
        assert_eq!(
            scope_args(Scope::V6 { dual_stack: false }, index_of),
            Some((IF_UNSPEC, PROTO_INET6))
        );
        assert_eq!(
            scope_args(Scope::Addr(ip("192.168.1.10")), index_of),
            Some((3, PROTO_INET))
        );
        assert_eq!(
            scope_args(Scope::Addr(ip("fe80::1")), index_of),
            Some((3, PROTO_INET6))
        );
        assert_eq!(scope_args(Scope::Addr(ip("10.0.0.1")), index_of), None);
    }

    /// A machine whose records are committed in the group at `/g/1`.
    fn committed() -> Machine {
        let mut machine = Machine::new("FILES".to_string());
        assert_eq!(machine.server_state(SERVER_RUNNING), Step::Register);
        machine.path = Some("/g/1".to_string());
        machine.committed = true;
        machine
    }

    #[test]
    fn records_are_registered_once_the_server_runs() {
        let mut machine = Machine::new("FILES".to_string());
        assert_eq!(machine.server_state(SERVER_REGISTERING), Step::Nothing);
        assert_eq!(machine.server_state(SERVER_RUNNING), Step::Register);
        let mut machine = committed();
        assert_eq!(machine.server_state(SERVER_RUNNING), Step::Nothing);
    }

    #[test]
    fn a_collision_renames_and_registers_again() {
        let mut machine = committed();
        assert_eq!(machine.group_state(GROUP_COLLISION, ""), Step::Rename);
        assert!(!machine.committed);
        assert_eq!(machine.renamed("FILES #2".to_string()), Step::Register);
        assert_eq!(machine.name, "FILES #2");
        assert_eq!(machine.path.as_deref(), Some("/g/1"));
        assert_eq!(machine.group_state(GROUP_ESTABLISHED, ""), Step::Nothing);
        assert_eq!(machine.renames, 0);
    }

    #[test]
    fn a_new_avahi_gets_the_records_again_in_a_new_group() {
        let mut machine = committed();
        machine.collision();
        machine.renamed("FILES #2".to_string());
        machine.committed = true;
        machine.owner_changed();
        assert_eq!(machine.path, None);
        assert_eq!(machine.name, "FILES");
        assert!(!machine.committed);
        assert_eq!(machine.server_state(SERVER_RUNNING), Step::Register);
    }

    #[test]
    fn records_are_withdrawn_while_the_host_name_is_not_established() {
        for state in [SERVER_REGISTERING, SERVER_COLLISION] {
            let mut machine = committed();
            assert_eq!(machine.server_state(state), Step::Reset);
            assert!(!machine.committed);
            assert_eq!(machine.server_state(state), Step::Nothing);
            assert_eq!(machine.server_state(SERVER_RUNNING), Step::Register);
        }
    }

    #[test]
    fn renames_stop_at_the_cap() {
        let mut machine = committed();
        for _ in 0..MAX_RENAMES {
            assert_eq!(machine.collision(), Step::Rename);
        }
        assert_eq!(machine.collision(), Step::Reset);
        assert_eq!(machine.collision(), Step::Reset);
        assert_eq!(machine.server_state(SERVER_RUNNING), Step::Nothing);
        machine.owner_changed();
        assert_eq!(machine.server_state(SERVER_RUNNING), Step::Register);
    }

    #[test]
    fn a_failure_leaves_the_records_withdrawn() {
        let mut machine = committed();
        assert_eq!(machine.group_state(GROUP_FAILURE, "error"), Step::Nothing);
        assert!(!machine.committed);
        assert_eq!(machine.server_state(SERVER_RUNNING), Step::Register);
    }
}
