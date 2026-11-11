//! A Versity Gateway on loopback, started once per test binary and shared by
//! its tests.
//!
//! The gateway runs under a helper process: this test binary, started again
//! to run [`run_helper`]. The test binary keeps the helper's stdin open. When
//! that pipe closes, whether the test binary returned, failed or was killed,
//! the helper stops the gateway and removes its directories.

use std::ffi::OsStr;
use std::io::{self, Read as _, Write as _};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::thread;
use std::time::{Duration, Instant};

/// Region the gateway answers for.
pub(crate) const REGION: &str = "us-east-1";

/// Path of the gateway binary; `versitygw` on `PATH` when unset.
const BINARY_VAR: &str = "SMB_TEST_VERSITYGW";

/// Settings the helper reads from its environment.
const HELPER_BINARY: &str = "SMB_TEST_GATEWAY_BINARY";
const HELPER_ADDR: &str = "SMB_TEST_GATEWAY_ADDR";
const HELPER_ACCESS: &str = "SMB_TEST_GATEWAY_ACCESS";
const HELPER_SECRET: &str = "SMB_TEST_GATEWAY_SECRET";

/// Exit code of the helper when it cannot start the gateway binary.
const SPAWN_FAILED: i32 = 17;

const HEALTH_PATH: &str = "/health";
const START_TIMEOUT: Duration = Duration::from_secs(30);
const START_ATTEMPTS: usize = 3;
const POLL_INTERVAL: Duration = Duration::from_millis(50);
/// Wait after the first health answer before checking the helper is still
/// running. If the gateway could not bind its port, it exits and the answer
/// came from whatever else holds that port.
const SETTLE: Duration = Duration::from_millis(500);

static GATEWAY: OnceLock<Result<Gateway, String>> = OnceLock::new();

/// A running gateway and its generated credentials.
pub(crate) struct Gateway {
    /// Address the gateway listens on; its endpoint is `http://` and this.
    pub(crate) addr: SocketAddr,
    #[expect(dead_code, reason = "used by the S3 backend tests")]
    pub(crate) access_key: String,
    #[expect(dead_code, reason = "used by the S3 backend tests")]
    pub(crate) secret_key: String,
    next_bucket: AtomicU32,
    /// Holds the stdin pipe whose closing stops the gateway.
    _helper: Child,
}

impl Gateway {
    /// A bucket name no earlier call returned. The bucket does not exist yet.
    #[expect(dead_code, reason = "used by the S3 backend tests")]
    pub(crate) fn bucket_name(&self) -> String {
        let n = self.next_bucket.fetch_add(1, Ordering::Relaxed);
        format!("smb-test-{n}")
    }
}

/// The gateway of this test binary, started by the first caller. Panics with
/// the reason when it cannot start, so each test that needs it fails.
pub(crate) fn gateway() -> &'static Gateway {
    GATEWAY
        .get_or_init(start)
        .as_ref()
        .unwrap_or_else(|reason| panic!("{reason}"))
}

enum Failure {
    /// The helper exited before the gateway answered, as when the port was
    /// taken. Carries its output.
    Exited(String),
    Fatal(String),
}

fn start() -> Result<Gateway, String> {
    let binary = std::env::var_os(BINARY_VAR)
        .filter(|path| !path.is_empty())
        .unwrap_or_else(|| "versitygw".into());
    let access_key = credential("test", 8)?;
    let secret_key = credential("", 20)?;
    let mut output = String::new();
    for _ in 0..START_ATTEMPTS {
        let addr = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .and_then(|listener| listener.local_addr())
            .map_err(|e| format!("no free port on 127.0.0.1: {e}"))?;
        match launch(&binary, addr, &access_key, &secret_key) {
            Ok(helper) => {
                return Ok(Gateway {
                    addr,
                    access_key,
                    secret_key,
                    next_bucket: AtomicU32::new(0),
                    _helper: helper,
                });
            }
            Err(Failure::Exited(out)) => output = out,
            Err(Failure::Fatal(reason)) => return Err(reason),
        }
    }
    Err(format!(
        "versitygw exited {START_ATTEMPTS} times before it answered {HEALTH_PATH}:\n{output}"
    ))
}

fn credential(prefix: &str, bytes: usize) -> Result<String, String> {
    let mut raw = vec![0; bytes];
    crate::utils::fill_random(&mut raw).map_err(|e| format!("no random bytes: {e}"))?;
    Ok(format!("{prefix}{}", hex::encode(raw)))
}

/// Starts the helper and waits until the gateway answers its health path.
fn launch(
    binary: &OsStr,
    addr: SocketAddr,
    access_key: &str,
    secret_key: &str,
) -> Result<Child, Failure> {
    let exe = std::env::current_exe()
        .map_err(|e| Failure::Fatal(format!("cannot find the test binary: {e}")))?;
    let mut helper = Command::new(exe)
        .args(["--ignored", "--exact", "--nocapture", &helper_test_name()])
        .env(HELPER_BINARY, binary)
        .env(HELPER_ADDR, addr.to_string())
        .env(HELPER_ACCESS, access_key)
        .env(HELPER_SECRET, secret_key)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| Failure::Fatal(format!("cannot start the helper process: {e}")))?;
    let deadline = Instant::now() + START_TIMEOUT;
    loop {
        if let Some(status) = exit_status(&mut helper)? {
            return Err(failure(helper, status));
        }
        if healthy(addr) {
            thread::sleep(SETTLE);
            return match exit_status(&mut helper)? {
                None => Ok(helper),
                Some(status) => Err(failure(helper, status)),
            };
        }
        if Instant::now() >= deadline {
            return Err(Failure::Fatal(format!(
                "versitygw at {addr} did not answer {HEALTH_PATH} within {START_TIMEOUT:?}:\n{}",
                output(helper)
            )));
        }
        thread::sleep(POLL_INTERVAL);
    }
}

fn exit_status(helper: &mut Child) -> Result<Option<ExitStatus>, Failure> {
    helper
        .try_wait()
        .map_err(|e| Failure::Fatal(format!("cannot poll the helper process: {e}")))
}

/// What an exited helper's status means: a gateway that would not start is
/// final, any other exit may be a port that was taken.
fn failure(helper: Child, status: ExitStatus) -> Failure {
    let output = output(helper);
    if status.code() == Some(SPAWN_FAILED) {
        Failure::Fatal(output)
    } else {
        Failure::Exited(output)
    }
}

/// The helper's stderr, which carries the gateway's output. Closes its stdin
/// first, so a helper that is still running stops the gateway.
fn output(helper: Child) -> String {
    match helper.wait_with_output() {
        Ok(out) => String::from_utf8_lossy(&out.stderr).into_owned(),
        Err(e) => format!("no output: {e}"),
    }
}

/// Whether a GET of the health path returns status 200.
fn healthy(addr: SocketAddr) -> bool {
    const TIMEOUT: Duration = Duration::from_secs(2);
    const STATUS: &[u8] = b"HTTP/1.1 200";
    let probe = || -> io::Result<bool> {
        let mut stream = TcpStream::connect_timeout(&addr, TIMEOUT)?;
        stream.set_read_timeout(Some(TIMEOUT))?;
        stream.set_write_timeout(Some(TIMEOUT))?;
        let request =
            format!("GET {HEALTH_PATH} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n");
        stream.write_all(request.as_bytes())?;
        let mut status = [0; STATUS.len()];
        stream.read_exact(&mut status)?;
        Ok(status == STATUS)
    };
    probe().unwrap_or(false)
}

/// libtest names a test by its path below the crate root.
fn helper_test_name() -> String {
    let module = module_path!().split_once("::").map_or("", |(_, path)| path);
    format!("{module}::run_helper")
}

/// Runs the gateway until it exits or stdin closes, then stops it, copies its
/// output to stderr and removes its directories. Exits with [`SPAWN_FAILED`]
/// when the gateway binary cannot be started. Does nothing unless started by
/// [`launch`].
#[test]
#[ignore = "entry point of the gateway helper process"]
fn run_helper() {
    let Some(binary) = std::env::var_os(HELPER_BINARY) else {
        return;
    };
    if let Err(message) = serve(&binary) {
        eprintln!("{message}");
        std::process::exit(SPAWN_FAILED);
    }
}

fn serve(binary: &OsStr) -> Result<(), String> {
    let setting = |name| std::env::var(name).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("root");
    let sidecar = dir.path().join("sidecar");
    let log = dir.path().join("gateway.log");
    std::fs::create_dir(&root).unwrap();
    std::fs::create_dir(&sidecar).unwrap();
    let log_file = std::fs::File::create(&log).unwrap();
    let mut command = Command::new(binary);
    // The gateway reads these as settings (TLS, accounts, admin port, logs).
    for (name, _) in std::env::vars_os() {
        let upper = name.to_string_lossy().to_ascii_uppercase();
        if upper.starts_with("VGW_") || upper.starts_with("ROOT_") {
            command.env_remove(&name);
        }
    }
    let mut gateway = command
        .args(["-a", &setting(HELPER_ACCESS), "-s", &setting(HELPER_SECRET)])
        .args(["-p", &setting(HELPER_ADDR), "-r", REGION])
        .args(["--health", HEALTH_PATH, "-q", "posix", "--sidecar"])
        .arg(&sidecar)
        .arg(&root)
        .stdin(Stdio::null())
        .stdout(log_file.try_clone().unwrap())
        .stderr(log_file)
        .spawn()
        .map_err(|e| {
            format!(
                "cannot start {}: {e} (set {BINARY_VAR} to its path or add it to PATH)",
                binary.to_string_lossy()
            )
        })?;

    let (closed, stdin_closed) = mpsc::channel();
    thread::spawn(move || {
        let _ = io::copy(&mut io::stdin(), &mut io::sink());
        let _ = closed.send(());
    });
    while gateway.try_wait().unwrap().is_none() {
        if stdin_closed.recv_timeout(Duration::from_millis(100)) != Err(RecvTimeoutError::Timeout) {
            let _ = gateway.kill();
            let _ = gateway.wait();
        }
    }
    let _ = io::stderr().write_all(&std::fs::read(&log).unwrap_or_default());
    Ok(())
}

#[test]
fn gateway_starts() {
    gateway();
}
