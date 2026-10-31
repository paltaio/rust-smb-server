//! Registration with mDNSResponder through the dns_sd API of libSystem.

use std::ffi::{CStr, CString, c_char, c_void};
use std::os::fd::{AsRawFd, RawFd};
use std::ptr;
use std::time::Duration;

use tokio::io::Interest;
use tokio::io::unix::AsyncFd;
use tracing::{debug, info, warn};

use super::target::{Names, if_index_of, interface_index};
use super::{Service, Stop};

/// The parts of `dns_sd.h` the server uses.
mod ffi {
    use std::ffi::{c_char, c_int, c_void};

    #[repr(C)]
    pub(super) struct ServiceOpaque {
        _private: [u8; 0],
    }

    #[repr(C)]
    pub(super) struct RecordOpaque {
        _private: [u8; 0],
    }

    pub(super) type ServiceRef = *mut ServiceOpaque;
    pub(super) type RecordRef = *mut RecordOpaque;

    pub(super) type RegisterReply = extern "C" fn(
        sd: ServiceRef,
        flags: u32,
        error: i32,
        name: *const c_char,
        regtype: *const c_char,
        domain: *const c_char,
        context: *mut c_void,
    );

    pub(super) type RegisterRecordReply = extern "C" fn(
        sd: ServiceRef,
        record: RecordRef,
        flags: u32,
        error: i32,
        context: *mut c_void,
    );

    unsafe extern "C" {
        pub(super) fn DNSServiceCreateConnection(sd: *mut ServiceRef) -> i32;
        pub(super) fn DNSServiceRegister(
            sd: *mut ServiceRef,
            flags: u32,
            interface: u32,
            name: *const c_char,
            regtype: *const c_char,
            domain: *const c_char,
            host: *const c_char,
            port: u16,
            txt_len: u16,
            txt: *const c_void,
            callback: Option<RegisterReply>,
            context: *mut c_void,
        ) -> i32;
        pub(super) fn DNSServiceRegisterRecord(
            sd: ServiceRef,
            record: *mut RecordRef,
            flags: u32,
            interface: u32,
            fullname: *const c_char,
            rrtype: u16,
            rrclass: u16,
            rdlen: u16,
            rdata: *const c_void,
            ttl: u32,
            callback: Option<RegisterRecordReply>,
            context: *mut c_void,
        ) -> i32;
        pub(super) fn DNSServiceRemoveRecord(sd: ServiceRef, record: RecordRef, flags: u32) -> i32;
        pub(super) fn DNSServiceConstructFullName(
            full_name: *mut c_char,
            service: *const c_char,
            regtype: *const c_char,
            domain: *const c_char,
        ) -> i32;
        pub(super) fn DNSServiceRefSockFD(sd: ServiceRef) -> c_int;
        pub(super) fn DNSServiceProcessResult(sd: ServiceRef) -> i32;
        pub(super) fn DNSServiceRefDeallocate(sd: ServiceRef);
    }
}

const NO_ERROR: i32 = 0;
const ERR_BAD_PARAM: i32 = -65540;
const ERR_NAME_CONFLICT: i32 = -65548;
const ERR_SERVICE_NOT_RUNNING: i32 = -65563;
const ERR_DEFUNCT_CONNECTION: i32 = -65569;

const FLAG_ADD: u32 = 0x2;
const FLAG_UNIQUE: u32 = 0x20;
const FLAG_SHARE_CONNECTION: u32 = 0x4000;

const TYPE_TXT: u16 = 16;
const CLASS_IN: u16 = 1;
/// Size of the buffer DNSServiceConstructFullName writes to.
const MAX_DOMAIN_NAME: usize = 1009;

const SMB_TYPE: &CStr = c"_smb._tcp";
const DEVICE_INFO_TYPE: &CStr = c"_device-info._tcp";
const LOCAL: &CStr = c"local.";
/// TTL of the device-info TXT record, as mDNSResponder gives its own.
const DEVICE_INFO_TTL: u32 = 4500;

/// First and longest wait before connecting to mDNSResponder again.
const RETRY_FIRST: Duration = Duration::from_secs(1);
const RETRY_MAX: Duration = Duration::from_secs(30);

/// Announces `service` through mDNSResponder until `stop` resolves,
/// registering again whenever mDNSResponder restarts.
pub(super) async fn run(service: Service, mut stop: Stop) {
    let Some(interface) = interface_index(service.scope, if_index_of) else {
        warn!("the listen address is on no interface; the server is not announced");
        return;
    };
    let name = match registered_name(&service).map(CString::new).transpose() {
        Ok(name) => name,
        Err(_) => {
            warn!("the name holds a NUL; the server is not announced");
            return;
        }
    };
    match &name {
        Some(name) => {
            info!(name = %name.to_string_lossy(), "announcing the server through mDNSResponder")
        }
        None => info!("announcing the server through mDNSResponder under the computer name"),
    }

    let mut backoff = Backoff::default();
    loop {
        let opened = tokio::select! {
            _ = &mut stop => return,
            opened = Link::open(name.clone(), service.port, interface) => opened,
        };
        let (ended, link) = match opened {
            Ok(link) => drive(link, &service, interface, &mut backoff, &mut stop).await,
            Err(failure) => (Ended::from(failure), None),
        };
        if let Some(link) = link {
            link.close().await;
        }
        match ended {
            Ended::Stopped => return,
            Ended::DaemonGone => {
                if !backoff.warned {
                    warn!("mDNSResponder is not running; the server is announced once it is");
                    backoff.warned = true;
                }
                tokio::select! {
                    _ = &mut stop => return,
                    () = tokio::time::sleep(backoff.next()) => {}
                }
            }
            Ended::Failed => {
                let _ = stop.await;
                return;
            }
        }
    }
}

/// Waits between attempts to reach mDNSResponder, doubling from
/// [`RETRY_FIRST`] up to [`RETRY_MAX`].
#[derive(Debug)]
struct Backoff {
    delay: Duration,
    /// The wait has been logged since the last registration.
    warned: bool,
}

impl Default for Backoff {
    fn default() -> Self {
        Self {
            delay: RETRY_FIRST,
            warned: false,
        }
    }
}

impl Backoff {
    fn next(&mut self) -> Duration {
        let delay = self.delay;
        self.delay = (delay * 2).min(RETRY_MAX);
        delay
    }

    fn reset(&mut self) {
        *self = Self::default();
    }
}

enum Failure {
    NotRunning,
    Other(String),
}

impl From<i32> for Failure {
    fn from(code: i32) -> Self {
        if matches!(code, ERR_SERVICE_NOT_RUNNING | ERR_DEFUNCT_CONNECTION) {
            Failure::NotRunning
        } else {
            Failure::Other(describe(code))
        }
    }
}

enum Ended {
    Stopped,
    DaemonGone,
    Failed,
}

impl From<Failure> for Ended {
    fn from(failure: Failure) -> Self {
        match failure {
            Failure::NotRunning => Ended::DaemonGone,
            Failure::Other(e) => {
                warn!(error = %e, "mDNSResponder refused the server; the server is not announced");
                Ended::Failed
            }
        }
    }
}

/// Reads mDNSResponder's replies until `stop` resolves or the connection
/// fails, and returns the connection when it is still open.
async fn drive(
    mut link: Link,
    service: &Service,
    interface: u32,
    backoff: &mut Backoff,
    stop: &mut Stop,
) -> (Ended, Option<Link>) {
    let mut names = Names {
        requested: registered_name(service).map(str::to_string),
        current: None,
    };
    loop {
        tokio::select! {
            _ = &mut *stop => return (Ended::Stopped, Some(link)),
            ready = link.socket.readable() => match ready {
                Ok(mut guard) => guard.clear_ready(),
                Err(e) => {
                    warn!(error = %e, "cannot wait for mDNSResponder; the server is no longer announced");
                    return (Ended::Failed, Some(link));
                }
            },
        }
        // Readiness is cleared first, so a reply arriving from here on
        // wakes the next wait.
        while readable_now(link.socket.get_ref().0) {
            // Data is waiting, so this reads it without waiting for
            // mDNSResponder.
            // SAFETY: `link.conn.main` is a live connection.
            let code = unsafe { ffi::DNSServiceProcessResult(link.conn.main) };
            if code != NO_ERROR {
                let ended = match Failure::from(code) {
                    Failure::NotRunning => Ended::DaemonGone,
                    Failure::Other(e) => {
                        warn!(error = %e, "lost the connection to mDNSResponder; the server is no longer announced");
                        Ended::Failed
                    }
                };
                return (ended, Some(link));
            }
        }
        for event in link.conn.take_events() {
            let call: Box<dyn FnOnce(&mut Connection) + Send> = match event {
                Event::Registered(name) => {
                    backoff.reset();
                    if !names.registered(&name) {
                        continue;
                    }
                    let Some(model) = service.model.clone() else {
                        continue;
                    };
                    Box::new(move |conn| {
                        if let Err(code) = conn.register_device_info(&name, &model, interface) {
                            warn!(error = %describe(code), "cannot announce the model");
                        }
                    })
                }
                Event::Lost(name) => {
                    debug!(%name, "name lost; mDNSResponder picks another");
                    continue;
                }
                Event::Failed(code) => match Failure::from(code) {
                    Failure::NotRunning => return (Ended::DaemonGone, Some(link)),
                    Failure::Other(e) => {
                        warn!(error = %e, "mDNSResponder could not register the server");
                        continue;
                    }
                },
                Event::RecordFailed(record, code) => {
                    // A replaced record was removed, and its reference
                    // freed, when its successor was registered.
                    if !link.conn.record.failed(record) {
                        debug!(error = %describe(code), "a replaced model record failed");
                        continue;
                    }
                    match code {
                        ERR_NAME_CONFLICT => warn!(
                            "another host has a model record under the server's name; the model is not announced"
                        ),
                        _ => warn!(error = %describe(code), "cannot announce the model"),
                    }
                    Box::new(move |conn| conn.remove_record(record))
                }
            };
            // A connection left behind in a call is closed when the call
            // returns.
            link = tokio::select! {
                _ = &mut *stop => return (Ended::Stopped, None),
                called = link.call(call) => match called {
                    Ok(link) => link,
                    Err(failure) => return (Ended::from(failure), None),
                },
            };
        }
    }
}

/// A connection with its socket registered with tokio.
struct Link {
    /// Declared first, so that it leaves the reactor before the
    /// connection closes the socket.
    socket: AsyncFd<Socket>,
    conn: Connection,
}

impl Link {
    /// Connects and registers the service, off the async worker.
    async fn open(name: Option<CString>, port: u16, interface: u32) -> Result<Self, Failure> {
        let opened =
            tokio::task::spawn_blocking(move || Connection::open(name.as_deref(), port, interface))
                .await;
        match opened {
            Ok(conn) => Link::watch(conn?),
            Err(e) => Err(Failure::Other(e.to_string())),
        }
    }

    fn watch(conn: Connection) -> Result<Self, Failure> {
        // SAFETY: `conn.main` is a live connection.
        let fd = unsafe { ffi::DNSServiceRefSockFD(conn.main) };
        if fd < 0 {
            return Err(Failure::Other("no socket to mDNSResponder".to_string()));
        }
        // The replacement, AsyncFd::register_with_interest, needs tokio
        // 1.53.3 or 1.51.6. The socket stays open while the AsyncFd lives:
        // every path that lets the connection go drops the AsyncFd first.
        #[allow(deprecated)]
        let socket = AsyncFd::with_interest(Socket(fd), Interest::READABLE)
            .map_err(|e| Failure::Other(e.to_string()))?;
        Ok(Link { conn, socket })
    }

    /// Runs `call` on the connection off the async worker: dns_sd waits
    /// for mDNSResponder's answer to every request it sends.
    async fn call(self, call: Box<dyn FnOnce(&mut Connection) + Send>) -> Result<Self, Failure> {
        let Link { mut conn, socket } = self;
        // The socket leaves the reactor before the connection leaves this
        // task, after which it may be closed at any time.
        drop(socket);
        let span = tracing::Span::current();
        let called = tokio::task::spawn_blocking(move || {
            let _entered = span.enter();
            call(&mut conn);
            conn
        })
        .await;
        match called {
            Ok(conn) => Link::watch(conn),
            Err(e) => Err(Failure::Other(e.to_string())),
        }
    }

    /// Closes the connection off the async worker, which deregisters the
    /// records; mDNSResponder sends the goodbyes.
    async fn close(self) {
        let Link { conn, socket } = self;
        drop(socket);
        let _ = tokio::task::spawn_blocking(move || drop(conn)).await;
    }
}

/// What a dns_sd callback reported.
#[derive(Debug, PartialEq)]
enum Event {
    /// The service is registered under this name.
    Registered(String),
    /// The service lost this name; mDNSResponder picks another.
    Lost(String),
    Failed(i32),
    RecordFailed(Record, i32),
}

/// A record registered on a connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Record(ffi::RecordRef);

// SAFETY: a record reference is only handed back to dns_sd together with
// the connection it belongs to, which is used from one thread at a time.
unsafe impl Send for Record {}

/// The device-info record in place, if any.
#[derive(Debug, Default)]
struct DeviceInfo(Option<Record>);

impl DeviceInfo {
    /// Takes note that `record` failed, and returns whether it was the
    /// record in place.
    fn failed(&mut self, record: Record) -> bool {
        let current = self.0 == Some(record);
        if current {
            self.0 = None;
        }
        current
    }
}

/// A connection to mDNSResponder holding the server's records.
struct Connection {
    main: ffi::ServiceRef,
    record: DeviceInfo,
    /// Filled by the callbacks, from `Box::into_raw`.
    events: *mut Vec<Event>,
}

// SAFETY: the dns_sd references are not tied to the thread that created
// them. The connection owns them alone and is only used through
// `&mut self`, so they are never used from two threads at once.
unsafe impl Send for Connection {}

impl Connection {
    fn open(name: Option<&CStr>, port: u16, interface: u32) -> Result<Self, Failure> {
        let mut conn = Connection {
            main: ptr::null_mut(),
            record: DeviceInfo::default(),
            events: Box::into_raw(Box::default()),
        };
        // SAFETY: `conn.main` is valid for writes; on success it holds a
        // reference that `Drop` deallocates.
        check(unsafe { ffi::DNSServiceCreateConnection(&mut conn.main) })?;
        let mut registration = conn.main;
        // SAFETY: `registration` holds the connection, as
        // FLAG_SHARE_CONNECTION requires. The strings are NUL-terminated
        // and dns_sd copies them. `conn.events` stays valid until the
        // connection is deallocated, after which no callback runs.
        check(unsafe {
            ffi::DNSServiceRegister(
                &mut registration,
                FLAG_SHARE_CONNECTION,
                interface,
                name.map_or(ptr::null(), CStr::as_ptr),
                SMB_TYPE.as_ptr(),
                ptr::null(),
                ptr::null(),
                port.to_be(),
                0,
                ptr::null(),
                Some(on_register),
                conn.events.cast(),
            )
        })?;
        Ok(conn)
    }

    fn take_events(&mut self) -> Vec<Event> {
        // SAFETY: `self.events` came from `Box::into_raw` and lives as long
        // as the connection; no callback runs outside
        // DNSServiceProcessResult.
        std::mem::take(unsafe { &mut *self.events })
    }

    /// Registers the device-info TXT record under `name`, in place of the
    /// one under the previous name.
    fn register_device_info(&mut self, name: &str, model: &str, interface: u32) -> Result<(), i32> {
        if let Some(old) = self.record.0.take() {
            self.remove_record(old);
        }
        let name = CString::new(name).map_err(|_| ERR_BAD_PARAM)?;
        let mut fullname = [0 as c_char; MAX_DOMAIN_NAME];
        // SAFETY: `fullname` holds the MAX_DOMAIN_NAME bytes the function
        // may write; the other arguments are NUL-terminated.
        check_code(unsafe {
            ffi::DNSServiceConstructFullName(
                fullname.as_mut_ptr(),
                name.as_ptr(),
                DEVICE_INFO_TYPE.as_ptr(),
                LOCAL.as_ptr(),
            )
        })?;
        let rdata = txt_rdata(model);
        let mut record = ptr::null_mut();
        // SAFETY: `self.main` is a live connection; `fullname` is
        // NUL-terminated and `rdata` holds `rdata.len()` bytes, both
        // copied by dns_sd. `self.events` outlives the record, as for
        // DNSServiceRegister.
        check_code(unsafe {
            ffi::DNSServiceRegisterRecord(
                self.main,
                &mut record,
                FLAG_UNIQUE,
                interface,
                fullname.as_ptr(),
                TYPE_TXT,
                CLASS_IN,
                rdata.len() as u16,
                rdata.as_ptr().cast(),
                DEVICE_INFO_TTL,
                Some(on_register_record),
                self.events.cast(),
            )
        })?;
        self.record.0 = Some(Record(record));
        Ok(())
    }

    /// Removes `record` from the connection.
    fn remove_record(&mut self, record: Record) {
        // SAFETY: `self.main` is a live connection and `record` was
        // registered on it; dns_sd ignores a reference that is no longer
        // on the connection's list.
        let code = unsafe { ffi::DNSServiceRemoveRecord(self.main, record.0, 0) };
        if code != NO_ERROR {
            debug!(error = %describe(code), "cannot remove a model record");
        }
    }
}

impl Drop for Connection {
    fn drop(&mut self) {
        if !self.main.is_null() {
            // SAFETY: `self.main` is a live connection, deallocated once
            // here; this also deregisters the service and the record.
            unsafe { ffi::DNSServiceRefDeallocate(self.main) };
        }
        // SAFETY: `self.events` came from `Box::into_raw`, and with the
        // connection gone no callback can reach it.
        drop(unsafe { Box::from_raw(self.events) });
    }
}

/// The socket of a connection, owned and closed by dns_sd.
struct Socket(RawFd);

impl AsRawFd for Socket {
    fn as_raw_fd(&self) -> RawFd {
        self.0
    }
}

/// Whether `fd` has data to read now.
fn readable_now(fd: RawFd) -> bool {
    let mut poll = libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: `poll` is one valid pollfd, and a zero timeout returns at
    // once.
    let n = unsafe { libc::poll(&mut poll, 1, 0) };
    n > 0 && poll.revents != 0
}

extern "C" fn on_register(
    _sd: ffi::ServiceRef,
    flags: u32,
    error: i32,
    name: *const c_char,
    _regtype: *const c_char,
    _domain: *const c_char,
    context: *mut c_void,
) {
    let event = if error != NO_ERROR {
        Event::Failed(error)
    } else {
        // SAFETY: on success `name` is a NUL-terminated string valid for
        // the duration of the callback.
        let name = unsafe { CStr::from_ptr(name) }
            .to_string_lossy()
            .into_owned();
        if flags & FLAG_ADD != 0 {
            Event::Registered(name)
        } else {
            Event::Lost(name)
        }
    };
    // SAFETY: `context` is the connection's event queue, valid while the
    // connection is, and only touched here during DNSServiceProcessResult.
    unsafe { (*context.cast::<Vec<Event>>()).push(event) };
}

extern "C" fn on_register_record(
    _sd: ffi::ServiceRef,
    record: ffi::RecordRef,
    _flags: u32,
    error: i32,
    context: *mut c_void,
) {
    if error != NO_ERROR {
        let event = Event::RecordFailed(Record(record), error);
        // SAFETY: as in `on_register`.
        unsafe { (*context.cast::<Vec<Event>>()).push(event) };
    }
}

fn check(code: i32) -> Result<(), Failure> {
    check_code(code).map_err(Failure::from)
}

fn check_code(code: i32) -> Result<(), i32> {
    if code == NO_ERROR { Ok(()) } else { Err(code) }
}

/// The name to register, or `None` for the computer name: the default
/// name without a model lets mDNSResponder add the Mac's own model.
fn registered_name(service: &Service) -> Option<&str> {
    (!(service.default_name && service.model.is_none())).then_some(service.name.as_str())
}

/// TXT rdata holding the one string `model=<model>`.
fn txt_rdata(model: &str) -> Vec<u8> {
    let entry = format!("model={model}");
    let mut rdata = Vec::with_capacity(entry.len() + 1);
    rdata.push(entry.len() as u8);
    rdata.extend_from_slice(entry.as_bytes());
    rdata
}

/// A dns_sd error code as in `dns_sd.h`.
fn describe(code: i32) -> String {
    let name = match code {
        -65537 => "Unknown",
        -65538 => "NoSuchName",
        -65539 => "NoMemory",
        ERR_BAD_PARAM => "BadParam",
        -65541 => "BadReference",
        -65542 => "BadState",
        -65543 => "BadFlags",
        -65544 => "Unsupported",
        -65545 => "NotInitialized",
        -65547 => "AlreadyRegistered",
        ERR_NAME_CONFLICT => "NameConflict",
        -65549 => "Invalid",
        -65551 => "Incompatible",
        -65552 => "BadInterfaceIndex",
        -65553 => "Refused",
        ERR_SERVICE_NOT_RUNNING => "ServiceNotRunning",
        ERR_DEFUNCT_CONNECTION => "DefunctConnection",
        -65570 => "PolicyDenied",
        -65571 => "NotPermitted",
        _ => return format!("dns_sd error {code}"),
    };
    format!("kDNSServiceErr_{name} ({code})")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::discovery::target::Scope;

    fn service(default_name: bool, model: Option<&str>) -> Service {
        Service {
            name: "FILES".to_string(),
            default_name,
            model: model.map(str::to_string),
            port: 445,
            scope: Scope::V4,
            host: "host".to_string(),
            device: None,
        }
    }

    #[test]
    fn the_computer_name_is_used_without_a_name_or_a_model() {
        assert_eq!(registered_name(&service(true, None)), None);
        assert_eq!(
            registered_name(&service(true, Some("Xserve3,1"))),
            Some("FILES")
        );
        assert_eq!(registered_name(&service(false, None)), Some("FILES"));
        assert_eq!(
            registered_name(&service(false, Some("Xserve3,1"))),
            Some("FILES")
        );
    }

    #[test]
    fn the_model_is_one_txt_string() {
        assert_eq!(txt_rdata("Xserve3,1"), b"\x0fmodel=Xserve3,1");
        let long = "m".repeat(249);
        let rdata = txt_rdata(&long);
        assert_eq!(rdata.len(), 256);
        assert_eq!(rdata[0], 255);
    }

    #[test]
    fn errors_are_named() {
        assert_eq!(describe(-1), "dns_sd error -1");
        assert!(matches!(Failure::from(-65563), Failure::NotRunning));
        assert!(matches!(Failure::from(-65569), Failure::NotRunning));
        assert!(matches!(Failure::from(-65540), Failure::Other(_)));
    }

    #[test]
    fn callbacks_queue_events() {
        let mut events = Vec::new();
        let context = (&mut events as *mut Vec<Event>).cast();
        on_register(
            ptr::null_mut(),
            FLAG_ADD,
            NO_ERROR,
            c"FILES".as_ptr(),
            ptr::null(),
            ptr::null(),
            context,
        );
        on_register(
            ptr::null_mut(),
            0,
            NO_ERROR,
            c"FILES".as_ptr(),
            ptr::null(),
            ptr::null(),
            context,
        );
        on_register(
            ptr::null_mut(),
            0,
            ERR_SERVICE_NOT_RUNNING,
            ptr::null(),
            ptr::null(),
            ptr::null(),
            context,
        );
        let record = record_at(8);
        on_register_record(ptr::null_mut(), record.0, 0, NO_ERROR, context);
        on_register_record(ptr::null_mut(), record.0, 0, ERR_NAME_CONFLICT, context);
        assert_eq!(
            events,
            [
                Event::Registered("FILES".to_string()),
                Event::Lost("FILES".to_string()),
                Event::Failed(ERR_SERVICE_NOT_RUNNING),
                Event::RecordFailed(record, ERR_NAME_CONFLICT),
            ]
        );
    }

    /// A record reference for matching only, never passed to dns_sd.
    fn record_at(address: usize) -> Record {
        Record(ptr::without_provenance_mut(address))
    }

    #[test]
    fn only_a_failure_of_the_record_in_place_clears_it() {
        let (old, new) = (record_at(8), record_at(16));
        let mut info = DeviceInfo(Some(new));
        assert!(!info.failed(old));
        assert_eq!(info.0, Some(new));
        assert!(info.failed(new));
        assert_eq!(info.0, None);
        assert!(!info.failed(new));
    }

    #[test]
    fn retries_back_off_up_to_the_cap_until_reset() {
        let mut backoff = Backoff::default();
        let delays: Vec<u64> = (0..7).map(|_| backoff.next().as_secs()).collect();
        assert_eq!(delays, [1, 2, 4, 8, 16, 30, 30]);
        backoff.warned = true;
        backoff.reset();
        assert_eq!(backoff.next(), RETRY_FIRST);
        assert!(!backoff.warned);
    }
}
