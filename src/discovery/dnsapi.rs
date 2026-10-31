//! Registration with the Windows DNS client (Dnscache) through
//! DnsServiceRegister.

use std::collections::BTreeMap;
use std::ffi::c_void;
use std::ptr;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use tokio::sync::mpsc;
use tracing::{debug, warn};
use windows_sys::Win32::Foundation::{
    DNS_REQUEST_PENDING, ERROR_INTERNAL_ERROR, ERROR_INVALID_PARAMETER, ERROR_SUCCESS,
};
use windows_sys::Win32::NetworkManagement::Dns::{
    DNS_QUERY_REQUEST_VERSION1, DNS_SERVICE_CANCEL, DNS_SERVICE_INSTANCE,
    DNS_SERVICE_REGISTER_REQUEST, DnsServiceConstructInstance, DnsServiceDeRegister,
    DnsServiceFreeInstance, DnsServiceRegister, DnsServiceRegisterCancel,
};
use windows_sys::Win32::System::SystemInformation::{ComputerNameDnsHostname, GetComputerNameExW};

use super::target::{Names, if_index_of, interface_index};
use super::{Service, Stop};

const SMB_TYPE: &str = "._smb._tcp.local";
const DEVICE_INFO_TYPE: &str = "._device-info._tcp.local";
/// Port of the device-info record, which no client connects to:
/// DnsServiceConstructInstance refuses port 0.
const DEVICE_INFO_PORT: u16 = 9;

/// Announces `service` through the DNS client until `stop` resolves.
pub(super) async fn run(service: Service, mut stop: Stop) {
    // The DNS client splits the instance name at every dot, escaped or
    // not, and browsers never list the result.
    if service.name.contains('.') {
        warn!(
            name = %service.name,
            "the name contains a dot, which the Windows DNS client cannot announce; the server is not announced"
        );
        return;
    }
    let Some(interface) = interface_index(service.scope, if_index_of) else {
        warn!("the listen address is on no interface; the server is not announced");
        return;
    };
    let host = format!(
        "{}.local",
        dns_host_name().unwrap_or_else(|| service.host.clone())
    );
    tracing::info!(name = %service.name, "announcing the server through the Windows DNS client");

    let smb = Spec {
        instance: format!("{}{SMB_TYPE}", service.name),
        host: host.clone(),
        port: service.port,
        properties: Vec::new(),
        interface,
    };
    // Not raced with `stop`: a registration made is withdrawn below.
    let mut smb = match Registration::start(smb).await {
        Ok(registration) => registration,
        Err(status) => {
            warn!(error = %describe(status), "the DNS client refused the server; the server is not announced");
            return;
        }
    };
    let mut info: Option<Registration> = None;
    // Device-info records withdrawn after a rename, whose withdrawal may
    // not have completed.
    let mut retired: Vec<Registration> = Vec::new();
    let mut names = Names {
        requested: Some(service.name.clone()),
        current: None,
    };

    loop {
        tokio::select! {
            _ = &mut stop => break,
            Some(done) = smb.completions.recv(), if !smb.registered => {
                if done.status != ERROR_SUCCESS {
                    warn!(error = %describe(done.status), "the DNS client could not register the server");
                    smb.finish();
                    break;
                }
                smb.registered(done.instance);
                let name = done
                    .name
                    .as_deref()
                    .and_then(|full| instance_label(full, SMB_TYPE))
                    .unwrap_or(&service.name)
                    .to_string();
                if !names.registered(&name) {
                    continue;
                }
                let Some(model) = &service.model else {
                    continue;
                };
                if let Some(old) = info.take() {
                    match retire(old, &mut stop).await {
                        Some(old) => retired.push(old),
                        None => break,
                    }
                }
                let spec = Spec {
                    instance: format!("{name}{DEVICE_INFO_TYPE}"),
                    host: host.clone(),
                    port: DEVICE_INFO_PORT,
                    properties: vec![("model".to_string(), model.clone())],
                    interface,
                };
                info = match Registration::start(spec).await {
                    Ok(registration) => Some(registration),
                    Err(status) => {
                        warn!(error = %describe(status), "cannot announce the model");
                        None
                    }
                };
            }
            Some(done) = next_completion(&mut info) => {
                let Some(registration) = info.as_mut() else {
                    continue;
                };
                if done.status != ERROR_SUCCESS {
                    registration.finish();
                    warn!(error = %describe(done.status), "cannot announce the model");
                    info = None;
                    continue;
                }
                registration.registered(done.instance);
                // The DNS client renames each record on its own; clients
                // pair the two by name.
                let label = done.name.as_deref().and_then(|full| instance_label(full, DEVICE_INFO_TYPE));
                if label.is_some() && label != names.current.as_deref() {
                    warn!("another host has a model record under the server's name; the model is not announced");
                    if let Some(old) = info.take() {
                        match retire(old, &mut stop).await {
                            Some(old) => retired.push(old),
                            None => break,
                        }
                    }
                }
            }
        }
    }

    // Every withdrawal is requested before any is waited for.
    let mut stopping = vec![smb.stop_request().await];
    if let Some(info) = info {
        stopping.push(info.stop_request().await);
    }
    for registration in stopping.into_iter().chain(retired) {
        registration.wait().await;
    }
}

/// Requests the withdrawal of `old`, and returns it to be waited for, or
/// `None` when `stop` resolved first, which ends the announcement. The
/// request is made either way: the withdrawal is polled first, which hands
/// it to a blocking thread.
async fn retire(old: Registration, stop: &mut Stop) -> Option<Registration> {
    let retiring = old.stop_request();
    tokio::pin!(retiring);
    tokio::select! {
        biased;
        old = &mut retiring => Some(old),
        _ = &mut *stop => None,
    }
}

/// The next completion of `registration`, while it is pending.
async fn next_completion(registration: &mut Option<Registration>) -> Option<Completion> {
    match registration {
        Some(registration) if !registration.registered => registration.completions.recv().await,
        _ => std::future::pending().await,
    }
}

/// What to register.
#[derive(Debug, Clone)]
struct Spec {
    /// Full instance name, `<name>.<type>.local`.
    instance: String,
    /// Target host, `<host>.local`.
    host: String,
    port: u16,
    properties: Vec<(String, String)>,
    /// Interface index, 0 for every interface.
    interface: u32,
}

/// A DnsServiceRegister or DnsServiceDeRegister completion.
#[derive(Debug, PartialEq)]
struct Completion {
    status: u32,
    /// The registered instance's full name.
    name: Option<String>,
    /// The instance as registered, under the name the DNS client chose.
    instance: Option<Instance>,
}

/// An instance the DNS client allocated, freed when dropped.
#[derive(Debug, PartialEq)]
struct Instance(*mut DNS_SERVICE_INSTANCE);

// SAFETY: the instance is plain memory owned by this value alone.
unsafe impl Send for Instance {}

impl Drop for Instance {
    fn drop(&mut self) {
        // SAFETY: the instance came from the DNS client, which leaves it to
        // the caller to free, once.
        unsafe { DnsServiceFreeInstance(self.0) };
    }
}

/// Where completion callbacks deliver, by the id passed as their context.
/// A callback for an id no longer in the map is dropped.
static WAITING: Mutex<BTreeMap<usize, mpsc::UnboundedSender<Completion>>> =
    Mutex::new(BTreeMap::new());
static NEXT_ID: AtomicUsize = AtomicUsize::new(1);

/// An id in [`WAITING`], removed when dropped.
struct Waiting(usize);

impl Waiting {
    fn new() -> (Self, mpsc::UnboundedReceiver<Completion>) {
        let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = mpsc::unbounded_channel();
        WAITING
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(id, tx);
        (Self(id), rx)
    }
}

impl Drop for Waiting {
    fn drop(&mut self) {
        WAITING
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&self.0);
    }
}

/// The memory a registration lends to the DNS client: the request, its
/// instance and the strings behind it.
struct Request {
    request: DNS_SERVICE_REGISTER_REQUEST,
    cancel: DNS_SERVICE_CANCEL,
    instance: *mut DNS_SERVICE_INSTANCE,
    /// The instance as registered, which DnsServiceDeRegister needs to
    /// withdraw a renamed service.
    registered: Option<Instance>,
    _strings: Vec<Vec<u16>>,
    /// The DNS client is done with this memory, which may be freed.
    finished: bool,
}

// SAFETY: the pointers in a request point at memory it owns or that the
// DNS client allocated for it, none tied to a thread; the request is only
// used by one thread at a time.
unsafe impl Send for Request {}

impl Drop for Request {
    fn drop(&mut self) {
        // SAFETY: `self.instance` came from DnsServiceConstructInstance and
        // is freed once. A request is dropped only once finished: `Lent`
        // leaks an unfinished one.
        unsafe { DnsServiceFreeInstance(self.instance) };
    }
}

/// A request lent to the DNS client. Dropped before the DNS client is done
/// with it, on any path, it is leaked rather than freed under it.
struct Lent(Option<Box<Request>>);

impl Drop for Lent {
    fn drop(&mut self) {
        if let Some(request) = self.0.take()
            && !request.finished
        {
            Box::leak(request);
        }
    }
}

/// Longest wait for a cancelled registration to call back, so that a
/// registration that completed anyway is withdrawn.
const CANCEL_WAIT: Duration = Duration::from_secs(1);

/// One service registered with the DNS client.
struct Registration {
    lent: Lent,
    _waiting: Waiting,
    completions: mpsc::UnboundedReceiver<Completion>,
    /// The registration completed successfully.
    registered: bool,
    /// DnsServiceDeRegister took the withdrawal, and will call back.
    withdrawing: bool,
}

impl Registration {
    /// Asks the DNS client to register `spec`, off the async worker.
    async fn start(spec: Spec) -> Result<Self, u32> {
        let (waiting, completions) = Waiting::new();
        let id = waiting.0;
        let started = tokio::task::spawn_blocking(move || register(&spec, id)).await;
        let lent = match started {
            Ok(Ok(lent)) => lent,
            Ok(Err(status)) => return Err(status),
            Err(_) => return Err(ERROR_INTERNAL_ERROR),
        };
        Ok(Self {
            lent,
            _waiting: waiting,
            completions,
            registered: false,
            withdrawing: false,
        })
    }

    /// Takes note of a successful registration of `instance`.
    fn registered(&mut self, instance: Option<Instance>) {
        self.registered = true;
        if let Some(request) = &mut self.lent.0 {
            request.registered = instance;
        }
    }

    /// Takes in a completion of the registration.
    fn completed(&mut self, done: Completion) {
        if done.status == ERROR_SUCCESS {
            self.registered(done.instance);
        } else {
            self.finish();
        }
    }

    /// Takes note that the DNS client is done with the request.
    fn finish(&mut self) {
        if let Some(request) = &mut self.lent.0 {
            request.finished = true;
        }
    }

    /// Whether the DNS client is done with the request, or it is gone.
    fn finished(&self) -> bool {
        self.lent.0.as_ref().is_none_or(|request| request.finished)
    }

    /// Asks the DNS client to withdraw the service, off the async worker.
    /// A registration still pending is cancelled; if it completes anyway,
    /// it is withdrawn.
    async fn stop_request(mut self) -> Self {
        if self.finished() {
            return self;
        }
        if !self.registered
            && let Ok(done) = self.completions.try_recv()
        {
            self.completed(done);
        }
        if !self.registered && !self.finished() {
            let status;
            (self, status) = self.call(Call::Cancel).await;
            debug!(error = %describe(status), "registration cancelled");
            // Whether or not the cancel took, the registration may have
            // completed meanwhile: a completion queued or arriving now
            // decides whether it needs withdrawing.
            if let Ok(Some(done)) = tokio::time::timeout(CANCEL_WAIT, self.completions.recv()).await
            {
                debug!(error = %describe(done.status), "cancelled registration completed");
                self.completed(done);
            }
        }
        if self.registered && !self.finished() {
            let status;
            (self, status) = self.call(Call::DeRegister).await;
            if status == DNS_REQUEST_PENDING as u32 {
                self.withdrawing = true;
            } else {
                warn!(error = %describe(status), "the DNS client did not take the withdrawal");
            }
        }
        self
    }

    /// Calls the DNS client off the async worker. If the call outlives the
    /// task, the request goes with it, and is leaked unless finished.
    async fn call(mut self, call: Call) -> (Self, u32) {
        let mut lent = std::mem::replace(&mut self.lent, Lent(None));
        let done = tokio::task::spawn_blocking(move || {
            let Some(request) = &mut lent.0 else {
                return (lent, ERROR_INTERNAL_ERROR);
            };
            let status = match call {
                Call::Cancel => {
                    // SAFETY: `request.cancel` is the handle passed to
                    // DnsServiceRegister, kept alive.
                    unsafe { DnsServiceRegisterCancel(&request.cancel) }
                }
                Call::DeRegister => {
                    if let Some(instance) = &request.registered {
                        request.request.pServiceInstance = instance.0;
                    }
                    // SAFETY: `request.request` is the request the service
                    // was registered with, kept alive, now pointing at the
                    // instance as registered, which `request` also keeps
                    // alive.
                    unsafe { DnsServiceDeRegister(&request.request, ptr::null_mut()) }
                }
            };
            (lent, status)
        })
        .await;
        match done {
            Ok((lent, status)) => {
                self.lent = lent;
                (self, status)
            }
            Err(_) => (self, ERROR_INTERNAL_ERROR),
        }
    }

    /// Waits for a requested withdrawal to complete. Cancelled by the
    /// caller's time limit, or without a withdrawal the DNS client took,
    /// it leaves the request to the DNS client, which may still hold it.
    async fn wait(mut self) {
        if self.withdrawing
            && !self.finished()
            && let Some(done) = self.completions.recv().await
        {
            if done.status == ERROR_SUCCESS {
                debug!("withdrawn");
            } else {
                warn!(error = %describe(done.status), "the DNS client did not withdraw the server");
            }
            self.finish();
        }
    }
}

/// A call on a registration that waits for the DNS client.
#[derive(Debug, Clone, Copy)]
enum Call {
    Cancel,
    DeRegister,
}

/// Builds the request for `spec` and calls DnsServiceRegister. Returns the
/// request, which must outlive the registration, or the error status.
fn register(spec: &Spec, id: usize) -> Result<Lent, u32> {
    let strings = instance_strings(spec);
    let (keys, values) = property_pointers(&strings);
    // SAFETY: the strings are NUL-terminated UTF-16, `keys` and `values`
    // hold `properties.len()` pointers each, and null addresses are
    // allowed; the function copies what it keeps.
    let instance = unsafe {
        DnsServiceConstructInstance(
            strings[0].as_ptr(),
            strings[1].as_ptr(),
            ptr::null(),
            ptr::null(),
            spec.port,
            0,
            0,
            spec.properties.len() as u32,
            keys.as_ptr(),
            values.as_ptr(),
        )
    };
    if instance.is_null() {
        return Err(ERROR_INVALID_PARAMETER);
    }
    let mut request = Box::new(Request {
        request: DNS_SERVICE_REGISTER_REQUEST {
            Version: DNS_QUERY_REQUEST_VERSION1,
            InterfaceIndex: spec.interface,
            pServiceInstance: instance,
            pRegisterCompletionCallback: Some(on_complete),
            pQueryContext: ptr::without_provenance_mut(id),
            hCredentials: ptr::null_mut(),
            unicastEnabled: 0,
        },
        cancel: DNS_SERVICE_CANCEL {
            reserved: ptr::null_mut(),
        },
        instance,
        registered: None,
        _strings: strings,
        finished: false,
    });
    // SAFETY: the request is boxed and stays at this address until the
    // DNS client is done with it, and so does the cancel handle; the
    // callback only reads the context as an id.
    let status = unsafe { DnsServiceRegister(&request.request, &mut request.cancel) };
    // Success is documented as DNS_REQUEST_PENDING; ERROR_SUCCESS is taken
    // the same way, since the DNS client may still hold the request.
    if status == DNS_REQUEST_PENDING as u32 || status == ERROR_SUCCESS {
        Ok(Lent(Some(request)))
    } else {
        request.finished = true;
        Err(status)
    }
}

/// The instance name, the host name, then each property's key and value,
/// as NUL-terminated UTF-16.
fn instance_strings(spec: &Spec) -> Vec<Vec<u16>> {
    let mut strings = vec![wide(&spec.instance), wide(&spec.host)];
    for (key, value) in &spec.properties {
        strings.push(wide(key));
        strings.push(wide(value));
    }
    strings
}

/// Pointers to the property keys and values in `strings`, as laid out by
/// [`instance_strings`].
fn property_pointers(strings: &[Vec<u16>]) -> (Vec<*const u16>, Vec<*const u16>) {
    let pointers = |first| {
        strings
            .iter()
            .skip(first)
            .step_by(2)
            .map(|s| s.as_ptr())
            .collect()
    };
    (pointers(2), pointers(3))
}

unsafe extern "system" fn on_complete(
    status: u32,
    context: *const c_void,
    instance: *const DNS_SERVICE_INSTANCE,
) {
    let (name, instance) = if instance.is_null() {
        (None, None)
    } else {
        // SAFETY: a non-null `instance` is a valid DNS_SERVICE_INSTANCE
        // whose instance name is NUL-terminated UTF-16 or null, and it is
        // ours to free, which `Instance` does.
        let name = unsafe {
            let name = (*instance).pszInstanceName;
            (!name.is_null()).then(|| from_wide(name))
        };
        (name, Some(Instance(instance.cast_mut())))
    };
    let waiting = WAITING.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(tx) = waiting.get(&context.addr()) {
        let _ = tx.send(Completion {
            status,
            name,
            instance,
        });
    }
}

/// Reads a NUL-terminated UTF-16 string.
///
/// # Safety
///
/// `s` points at a NUL-terminated UTF-16 string.
unsafe fn from_wide(s: *const u16) -> String {
    let mut len = 0;
    // SAFETY: the string is NUL-terminated, so every unit up to the NUL is
    // readable.
    while unsafe { *s.add(len) } != 0 {
        len += 1;
    }
    // SAFETY: the `len` units before the NUL are readable.
    String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(s, len) })
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// The host's DNS host name, the one the DNS client answers for in
/// `.local`.
fn dns_host_name() -> Option<String> {
    let mut buf = [0u16; 256];
    let mut len = buf.len() as u32;
    // SAFETY: `buf` holds `len` units, as the function is told.
    let ok = unsafe { GetComputerNameExW(ComputerNameDnsHostname, buf.as_mut_ptr(), &mut len) };
    (ok != 0 && len > 0).then(|| String::from_utf16_lossy(&buf[..len as usize]))
}

/// The instance label of `full`, a name of the type ending in `suffix`,
/// in any case and with or without the final dot.
fn instance_label<'a>(full: &'a str, suffix: &str) -> Option<&'a str> {
    let full = full.strip_suffix('.').unwrap_or(full);
    let at = full.len().checked_sub(suffix.len())?;
    (full.is_char_boundary(at) && full[at..].eq_ignore_ascii_case(suffix) && at > 0)
        .then(|| &full[..at])
}

fn describe(status: u32) -> String {
    format!("Windows error {status}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn instance_labels_are_read_from_full_names() {
        assert_eq!(
            instance_label("FILES._smb._tcp.local", SMB_TYPE),
            Some("FILES")
        );
        assert_eq!(
            instance_label("FILES (2)._SMB._TCP.LOCAL.", SMB_TYPE),
            Some("FILES (2)")
        );
        assert_eq!(instance_label("._smb._tcp.local", SMB_TYPE), None);
        assert_eq!(
            instance_label("FILES._device-info._tcp.local", SMB_TYPE),
            None
        );
        assert_eq!(instance_label("local", SMB_TYPE), None);
    }

    #[test]
    fn properties_pair_keys_with_values() {
        let mut spec = Spec {
            instance: format!("FILES{SMB_TYPE}"),
            host: "HOST.local".to_string(),
            port: 445,
            properties: Vec::new(),
            interface: 0,
        };
        let strings = instance_strings(&spec);
        let (keys, values) = property_pointers(&strings);
        assert_eq!(strings.len(), 2);
        assert!(keys.is_empty() && values.is_empty());

        spec.properties = vec![("model".to_string(), "Xserve3,1".to_string())];
        let strings = instance_strings(&spec);
        let (keys, values) = property_pointers(&strings);
        // SAFETY: the pointers point at the NUL-terminated `strings`.
        let read = |p: &[*const u16]| {
            p.iter()
                .map(|&s| unsafe { from_wide(s) })
                .collect::<Vec<_>>()
        };
        assert_eq!(read(&keys), ["model"]);
        assert_eq!(read(&values), ["Xserve3,1"]);
    }

    #[test]
    fn completions_reach_only_their_waiter() {
        let (waiting, mut rx) = Waiting::new();
        let context = ptr::without_provenance::<c_void>(waiting.0);
        // SAFETY: a null instance carries no name; the context is an id.
        unsafe { on_complete(0, context, ptr::null()) };
        assert_eq!(
            rx.try_recv().ok(),
            Some(Completion {
                status: 0,
                name: None,
                instance: None,
            })
        );
        drop(waiting);
        // An id no longer waiting is ignored.
        // SAFETY: as above.
        unsafe { on_complete(5, context, ptr::null()) };
        assert!(rx.try_recv().is_err());
    }
}
