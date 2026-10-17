use std::fs;
use std::io::{Read, Seek, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use base64::Engine;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::config::{self, ServiceConfig};
use crate::execution_lock::ExecutionLock;
use crate::paths::write_private_atomic;
use crate::status::PersistedState;

pub const PROTOCOL_VERSION: u32 = 1;
const MAX_REQUEST_BYTES: usize = 2_000_000;
const MAX_CONTROL_CONNECTIONS: usize = 32;
const CONTROL_IO_TIMEOUT: Duration = Duration::from_secs(5);
static DOCUMENT_SAVE_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

struct CrossProcessSaveLock(fs::File);

impl CrossProcessSaveLock {
    fn acquire(repo: &Path) -> Result<Self> {
        use std::os::fd::AsRawFd;
        use std::os::unix::fs::OpenOptionsExt;
        let key = scope_key(repo);
        let path = PathBuf::from(format!("/tmp/scriptd-config-save-{key}.lock"));
        let file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .mode(0o666)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)?;
        let metadata = file.metadata()?;
        if !metadata.file_type().is_file() {
            bail!("configuration save lock is not a regular file");
        }
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let uid = unsafe { libc::geteuid() };
        if metadata.uid() != uid && metadata.uid() != 0 {
            bail!("configuration save lock has an unexpected owner");
        }
        if metadata.uid() == uid {
            file.set_permissions(fs::Permissions::from_mode(0o666))?;
        } else if metadata.mode() & 0o006 == 0 {
            bail!("configuration save lock is not writable by the bridge and service users");
        }
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok(Self(file))
    }
}

impl Drop for CrossProcessSaveLock {
    fn drop(&mut self) {
        use std::os::fd::AsRawFd;
        unsafe { libc::flock(self.0.as_raw_fd(), libc::LOCK_UN) };
    }
}

pub type SharedBroker = Arc<std::sync::Mutex<crate::broker::Broker>>;

pub fn empty_broker() -> SharedBroker {
    Arc::new(std::sync::Mutex::new(crate::broker::Broker::new(
        crate::broker::Policy::default(),
    )))
}

#[derive(Debug, Clone)]
pub struct ControlPaths {
    pub repo: PathBuf,
    pub state_dir: PathBuf,
    pub socket: PathBuf,
    pub jobs: PathBuf,
    pub jobs_lock: PathBuf,
    pub approved_sources: PathBuf,
    pub broker_audit: PathBuf,
    pub reload: PathBuf,
    pub status: PathBuf,
}

pub fn paths_for(repo: &Path, state_dir: &Path) -> ControlPaths {
    let key = scope_key(repo);
    let uid = unsafe { libc::geteuid() };
    paths_for_uid(repo, state_dir, uid, key)
}

/// Paths used by the unprivileged browser bridge to contact the root service.
/// Session and draft data stay in the browser user's state directory; only the
/// service socket is resolved in the service's UID namespace.
pub fn browser_paths_for(repo: &Path, state_dir: &Path, service_uid: u32) -> ControlPaths {
    let key = scope_key(repo);
    paths_for_uid(repo, state_dir, service_uid, key)
}

pub fn broker_socket_path(repo: &Path, client_uid: u32) -> PathBuf {
    PathBuf::from(format!(
        "/tmp/scriptd-broker-{client_uid}-{}.sock",
        scope_key(repo)
    ))
}

pub fn broker_activation_status(repo: &Path) -> Result<()> {
    crate::broker::validate_activation_evidence(
        repo,
        Path::new("/Library/Application Support/scriptd/broker-activation.json"),
        Path::new("/usr/local/libexec/scriptd-broker"),
    )
}

fn paths_for_uid(repo: &Path, state_dir: &Path, socket_uid: u32, key: String) -> ControlPaths {
    ControlPaths {
        repo: repo.to_path_buf(),
        state_dir: state_dir.to_path_buf(),
        // sockaddr_un.sun_path is only 104 bytes on macOS. State directories
        // can be deeply nested (notably in isolated test homes), so keep the
        // socket itself under /tmp while retaining per-user and per-repo scope.
        socket: PathBuf::from(format!("/tmp/scriptd-{socket_uid}-{key}.sock")),
        jobs: state_dir.join(format!("jobs-{key}.json")),
        jobs_lock: state_dir.join(format!("jobs-{key}.lock")),
        approved_sources: PathBuf::from(
            "/Library/Application Support/scriptd/approved-cask-sources.txt",
        ),
        broker_audit: state_dir.join(format!("broker-audit-{key}.json")),
        reload: state_dir.join(format!("reload-{key}.request")),
        status: state_dir.join(format!("control-{key}.status.json")),
    }
}

pub fn execution_lock_path(repo: &Path, state_dir: &Path) -> PathBuf {
    state_dir.join(format!("execution-{}.lock", scope_key(repo)))
}

pub fn digest(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let hash = hasher.finalize();
    let mut hex = String::with_capacity(hash.len() * 2);
    for byte in hash {
        hex.push(HEX[(byte >> 4) as usize] as char);
        hex.push(HEX[(byte & 0x0f) as usize] as char);
    }
    format!("sha256:{hex}")
}

const HEX: &[u8; 16] = b"0123456789abcdef";

fn scope_key(repo: &Path) -> String {
    let canonical = repo.canonicalize().unwrap_or_else(|_| repo.to_path_buf());
    digest(canonical.to_string_lossy().as_bytes())[7..23].to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Request {
    pub v: u32,
    pub id: String,
    pub op: String,
    pub repo: String,
    #[serde(default)]
    pub document: Option<String>,
    #[serde(default)]
    pub module: Option<String>,
    #[serde(default)]
    pub yaml: Option<String>,
    #[serde(default)]
    pub base_digest: Option<String>,
    #[serde(default)]
    pub request_id: Option<String>,
    #[serde(default)]
    pub bypass: bool,
    #[serde(default)]
    pub action: Option<String>,
    #[serde(default)]
    pub max_lines: Option<usize>,
    #[serde(default)]
    pub severity: Option<String>,
    #[serde(default)]
    pub query: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct BrokerExecPayload {
    args: Vec<String>,
    cwd: String,
    env: Vec<(String, String)>,
    stdin: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Response {
    pub v: u32,
    pub id: String,
    pub ok: bool,
    pub state: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub apply: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config_digest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reload_error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub snapshot: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub logs: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub draft_yaml: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Job {
    pub id: String,
    pub module: String,
    pub state: String,
    pub bypass: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct JobFile {
    jobs: Vec<Job>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct ControlStatus {
    loaded_digest: Option<String>,
    reload_error: Option<String>,
    #[serde(default)]
    restart_required: bool,
}

#[derive(Debug)]
pub struct ServerHandle {
    stop: Arc<AtomicBool>,
    socket: PathBuf,
    thread: Option<JoinHandle<()>>,
}

impl Drop for ServerHandle {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        let _ = UnixStream::connect(&self.socket);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
        let _ = fs::remove_file(&self.socket);
    }
}

pub fn spawn_server(
    paths: ControlPaths,
    expected_uid: u32,
    broker: SharedBroker,
) -> Result<ServerHandle> {
    fs::create_dir_all(&paths.state_dir)?;
    if paths.socket.exists() {
        match UnixStream::connect(&paths.socket) {
            Ok(stream) => {
                let _ = stream.shutdown(std::net::Shutdown::Both);
                bail!(
                    "control socket is already served at {}",
                    paths.socket.display()
                );
            }
            Err(_) => {
                let _ = fs::remove_file(&paths.socket);
            }
        }
    }
    let listener = UnixListener::bind(&paths.socket)
        .with_context(|| format!("bind {}", paths.socket.display()))?;
    fs::set_permissions(&paths.socket, fs::Permissions::from_mode(0o600))?;
    if unsafe { libc::geteuid() } == 0 && expected_uid != 0 {
        use std::os::unix::ffi::OsStrExt;
        let path = std::ffi::CString::new(paths.socket.as_os_str().as_bytes())?;
        let result = unsafe { libc::chown(path.as_ptr(), expected_uid, !0 as libc::gid_t) };
        if result != 0 {
            return Err(std::io::Error::last_os_error())
                .context("assign control socket to the authenticated console user");
        }
    }
    listener.set_nonblocking(false)?;
    let stop = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&stop);
    let socket = paths.socket.clone();
    let thread = std::thread::Builder::new()
        .name("scriptd-control".to_string())
        .spawn(move || serve(listener, paths, expected_uid, broker, flag))?;
    Ok(ServerHandle {
        stop,
        socket,
        thread: Some(thread),
    })
}

fn serve(
    listener: UnixListener,
    paths: ControlPaths,
    expected_uid: u32,
    broker: SharedBroker,
    stop: Arc<AtomicBool>,
) {
    let active = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    while !stop.load(Ordering::Relaxed) {
        let stream = match listener.accept() {
            Ok((stream, _)) => stream,
            Err(_) => continue,
        };
        if stop.load(Ordering::Relaxed) {
            break;
        }
        if active.fetch_add(1, Ordering::AcqRel) >= MAX_CONTROL_CONNECTIONS {
            active.fetch_sub(1, Ordering::AcqRel);
            let mut stream = stream;
            let _ = write_response(&mut stream, &rejected("unknown", "control server is busy"));
            continue;
        }
        let paths = paths.clone();
        let request_broker = Arc::clone(&broker);
        let connection_active = Arc::clone(&active);
        if std::thread::Builder::new()
            .name("scriptd-control-request".to_string())
            .spawn(move || {
                let _active = ActiveConnection(connection_active);
                let mut stream = stream;
                let _ = stream.set_read_timeout(Some(CONTROL_IO_TIMEOUT));
                let _ = stream.set_write_timeout(Some(CONTROL_IO_TIMEOUT));
                let peer_ok = peer_uid(&stream).ok() == Some(expected_uid);
                let response = match read_request(&mut stream) {
                    Ok(request) => dispatch_with_broker(
                        &paths,
                        request,
                        peer_ok,
                        peer_pid(&stream).unwrap_or(0),
                        &request_broker,
                    ),
                    Err(error) => rejected("unknown", &error.to_string()),
                };
                let _ = write_response(&mut stream, &response);
            })
            .is_err()
        {
            active.fetch_sub(1, Ordering::AcqRel);
        }
    }
}

struct ActiveConnection(Arc<std::sync::atomic::AtomicUsize>);

impl Drop for ActiveConnection {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

pub fn spawn_broker_server(
    repo: PathBuf,
    socket: PathBuf,
    expected_uid: u32,
    broker: SharedBroker,
) -> Result<ServerHandle> {
    if socket.exists() {
        use std::os::unix::fs::{FileTypeExt, MetadataExt};
        let metadata = fs::symlink_metadata(&socket)
            .with_context(|| format!("inspect existing broker socket {}", socket.display()))?;
        if !metadata.file_type().is_socket()
            || (metadata.uid() != 0 && metadata.uid() != expected_uid)
        {
            bail!("existing broker socket path is not a protected socket file");
        }
        match UnixStream::connect(&socket) {
            Ok(stream) => {
                let _ = stream.shutdown(std::net::Shutdown::Both);
                bail!("privilege broker is already served at {}", socket.display());
            }
            Err(_) => fs::remove_file(&socket)
                .with_context(|| format!("remove stale broker socket {}", socket.display()))?,
        }
    }
    let listener = UnixListener::bind(&socket)
        .with_context(|| format!("bind privilege broker socket {}", socket.display()))?;
    fs::set_permissions(&socket, fs::Permissions::from_mode(0o600))?;
    if expected_uid != 0 {
        use std::os::unix::ffi::OsStrExt;
        let path = std::ffi::CString::new(socket.as_os_str().as_bytes())?;
        let result = unsafe { libc::chown(path.as_ptr(), expected_uid, !0 as libc::gid_t) };
        if result != 0 {
            return Err(std::io::Error::last_os_error())
                .context("assign broker socket to the authenticated console user");
        }
    }
    let stop = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&stop);
    let server_socket = socket.clone();
    let thread = std::thread::Builder::new()
        .name("scriptd-privilege-broker".to_string())
        .spawn(move || serve_broker(listener, repo, expected_uid, broker, flag))?;
    Ok(ServerHandle {
        stop,
        socket: server_socket,
        thread: Some(thread),
    })
}

fn serve_broker(
    listener: UnixListener,
    repo: PathBuf,
    expected_uid: u32,
    broker: SharedBroker,
    stop: Arc<AtomicBool>,
) {
    let active = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    while !stop.load(Ordering::Relaxed) {
        let (stream, _) = match listener.accept() {
            Ok(connection) => connection,
            Err(_) => continue,
        };
        if stop.load(Ordering::Relaxed) {
            break;
        }
        if active.fetch_add(1, Ordering::AcqRel) >= MAX_CONTROL_CONNECTIONS {
            active.fetch_sub(1, Ordering::AcqRel);
            let mut stream = stream;
            let _ = write_response(&mut stream, &rejected("unknown", "broker is busy"));
            continue;
        }
        let repo = repo.clone();
        let request_broker = Arc::clone(&broker);
        let connection_active = Arc::clone(&active);
        if std::thread::Builder::new()
            .name("scriptd-privilege-request".to_string())
            .spawn(move || {
                let _active = ActiveConnection(connection_active);
                let mut stream = stream;
                let _ = stream.set_read_timeout(Some(CONTROL_IO_TIMEOUT));
                let _ = stream.set_write_timeout(Some(CONTROL_IO_TIMEOUT));
                let peer_ok = peer_uid(&stream).ok() == Some(expected_uid);
                let caller_pid = peer_pid(&stream).unwrap_or(0);
                let response = match read_request(&mut stream) {
                    Ok(request) => {
                        let maintenance_service_pid = if peer_ok
                            && matches!(
                                request.op.as_str(),
                                "broker_open" | "broker_launch" | "broker_complete"
                            ) {
                            launchd_service_pid(expected_uid)
                                .and_then(|pid| {
                                    authenticate_peer_execution(&stream, pid)?;
                                    Ok(pid)
                                })
                                .ok()
                        } else {
                            None
                        };
                        dispatch_broker_request(
                            &repo,
                            request,
                            peer_ok,
                            caller_pid,
                            expected_uid,
                            maintenance_service_pid,
                            &request_broker,
                        )
                    }
                    Err(error) => rejected("unknown", &error.to_string()),
                };
                let _ = write_response(&mut stream, &response);
            })
            .is_err()
        {
            active.fetch_sub(1, Ordering::AcqRel);
        }
    }
}

fn launchd_service_pid(uid: u32) -> Result<u32> {
    // The expected label is installed into the root-owned broker LaunchDaemon
    // when setup runs. Reading it from the mutable repository would let an
    // unrelated same-UID process change service.yaml and nominate itself.
    let label = std::env::var("SCRIPTD_SERVICE_LABEL")
        .context("root broker has no installed maintenance service identity")?;
    validate_service_label(&label)?;
    launchd_service_pid_with(
        Path::new("/bin/launchctl"),
        uid,
        &label,
        Path::new("/usr/local/libexec/scriptd-broker"),
    )
}

fn validate_service_label(label: &str) -> Result<()> {
    if label.is_empty()
        || !label
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
    {
        bail!("installed maintenance service label is invalid");
    }
    Ok(())
}

fn launchd_service_pid_with(
    program: &Path,
    uid: u32,
    label: &str,
    executable: &Path,
) -> Result<u32> {
    let domain = format!("gui/{uid}/{label}");
    let output = std::process::Command::new(program)
        .args(["print", &domain])
        .output()
        .with_context(|| format!("query launchd service identity {domain}"))?;
    if !output.status.success() {
        bail!("launchd did not confirm the maintenance service {domain}");
    }
    let pid = parse_launchd_service_pid(&String::from_utf8_lossy(&output.stdout))
        .filter(|pid| process_alive(*pid as i32))
        .context("launchd did not report a live maintenance service process")?;
    authenticate_service_executable(pid, executable)?;
    Ok(pid)
}

fn authenticate_service_executable(pid: u32, executable: &Path) -> Result<()> {
    use std::os::unix::fs::MetadataExt;

    // The GUI launchd domain is user controlled. Only the helper's installed
    // binary, with an entirely protected path, can authenticate its service.
    if !executable.is_absolute() {
        bail!("maintenance service executable must have an absolute protected path");
    }
    for path in executable.ancestors() {
        let metadata = fs::symlink_metadata(path)?;
        if metadata.uid() != 0
            || metadata.mode() & 0o022 != 0
            || (path == executable && !metadata.is_file())
            || (path != executable && !metadata.is_dir())
        {
            bail!("maintenance service executable installation is not protected");
        }
    }
    #[cfg(target_os = "macos")]
    {
        use std::os::unix::ffi::OsStrExt;
        let pid = i32::try_from(pid).context("invalid maintenance service PID")?;
        let mut buffer = [0u8; libc::PROC_PIDPATHINFO_MAXSIZE as usize];
        let count =
            unsafe { libc::proc_pidpath(pid, buffer.as_mut_ptr().cast(), buffer.len() as u32) };
        if count <= 0 {
            return Err(std::io::Error::last_os_error())
                .context("read maintenance service executable identity");
        }
        let end = buffer
            .iter()
            .position(|byte| *byte == 0)
            .unwrap_or(buffer.len());
        if Path::new(std::ffi::OsStr::from_bytes(&buffer[..end])) != executable {
            bail!("launchd maintenance service executable is not the installed trusted binary");
        }
        // XNU cs_blobs.h / codesign.h: require active hardened-runtime and
        // library-validation enforcement, rejecting debug/injection allowances.
        // Root ownership alone does not prevent same-UID code injection.
        extern "C" {
            fn csops(
                pid: libc::pid_t,
                ops: libc::c_uint,
                data: *mut libc::c_void,
                size: usize,
            ) -> libc::c_int;
        }
        let mut flags = 0u32;
        let result = unsafe {
            csops(
                pid,
                0,
                (&mut flags as *mut u32).cast(),
                std::mem::size_of_val(&flags),
            )
        };
        if result != 0 || !service_code_flags_are_protected(flags) {
            bail!("maintenance service lacks enforced hardened code identity; elevation is unavailable");
        }
        // Bind the running code to the helper's own installed generation, not
        // just today's contents at a pathname (or a caller-provided signature).
        let mut service_hash = [0u8; 20];
        let mut helper_hash = [0u8; 20];
        for (process, hash) in [
            (pid, &mut service_hash),
            (unsafe { libc::getpid() }, &mut helper_hash),
        ] {
            if unsafe { csops(process, 5, hash.as_mut_ptr().cast(), hash.len()) } != 0 {
                return Err(std::io::Error::last_os_error())
                    .context("read installed maintenance service code signature");
            }
        }
        if service_hash == [0; 20] || service_hash != helper_hash {
            bail!("maintenance service code does not match the installed helper generation");
        }
        Ok(())
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = pid;
        bail!("maintenance service executable authentication requires macOS");
    }
}

fn authenticate_peer_execution(stream: &UnixStream, pid: u32) -> Result<()> {
    #[cfg(target_os = "macos")]
    {
        use std::os::fd::AsRawFd;
        let mut token = [0u32; 8];
        let mut size = std::mem::size_of_val(&token) as libc::socklen_t;
        let result = unsafe {
            libc::getsockopt(
                stream.as_raw_fd(),
                libc::SOL_LOCAL,
                libc::LOCAL_PEERTOKEN,
                token.as_mut_ptr().cast(),
                &mut size,
            )
        };
        if result != 0 || size as usize != std::mem::size_of_val(&token) {
            bail!("maintenance service peer audit identity is unavailable");
        }
        authenticate_execution_token(pid, &mut token)
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = (stream, pid);
        bail!("maintenance service peer authentication requires macOS");
    }
}

#[cfg(target_os = "macos")]
fn authenticate_execution_token(pid: u32, token: &mut [u32; 8]) -> Result<()> {
    extern "C" {
        fn csops_audittoken(
            pid: libc::pid_t,
            ops: libc::c_uint,
            data: *mut libc::c_void,
            size: usize,
            token: *mut libc::c_void,
        ) -> libc::c_int;
    }
    let pid = i32::try_from(pid).context("invalid maintenance service PID")?;
    let mut flags = 0u32;
    // The kernel compares the socket's original PID/version against the current
    // execution. Connecting before exec or reusing a PID cannot inherit trust.
    let result = unsafe {
        csops_audittoken(
            pid,
            0,
            (&mut flags as *mut u32).cast(),
            std::mem::size_of_val(&flags),
            token.as_mut_ptr().cast(),
        )
    };
    if result != 0 {
        bail!("maintenance service peer execution changed after connection");
    }
    Ok(())
}

#[cfg(any(target_os = "macos", test))]
fn service_code_flags_are_protected(flags: u32) -> bool {
    const CS_VALID: u32 = 0x00000001;
    const CS_KILL: u32 = 0x00000200;
    const CS_REQUIRE_LV: u32 = 0x00002000;
    const CS_RUNTIME: u32 = 0x00010000;
    const CS_GET_TASK_ALLOW: u32 = 0x00000004;
    const CS_INVALID_ALLOWED: u32 = 0x00000020;
    const CS_DEBUGGED: u32 = 0x10000000;
    const REQUIRED: u32 = CS_VALID | CS_KILL | CS_REQUIRE_LV | CS_RUNTIME;
    const FORBIDDEN: u32 = CS_GET_TASK_ALLOW | CS_INVALID_ALLOWED | CS_DEBUGGED;
    flags & REQUIRED == REQUIRED && flags & FORBIDDEN == 0
}

fn parse_launchd_service_pid(output: &str) -> Option<u32> {
    let mut running = false;
    let mut pid = None;
    let mut depth: usize = 0;
    for line in output.lines() {
        let line = line.trim();
        if line.ends_with("= {") {
            depth += 1;
            continue;
        }
        if line == "}" {
            depth = depth.saturating_sub(1);
            continue;
        }
        if depth > 1 {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        match key.trim() {
            "state" => running = value.trim() == "running",
            "pid" => pid = value.trim().parse::<u32>().ok().filter(|pid| *pid != 0),
            _ => {}
        }
    }
    running.then_some(pid).flatten()
}

fn maintenance_service_matches(caller_pid: u32, service_pid: Option<u32>) -> bool {
    caller_pid != 0 && service_pid == Some(caller_pid)
}

fn run_helper_launched_homebrew_worker(
    sudo: &Path,
    homebrew_bin: &Path,
    repo: &Path,
    client_uid: u32,
    cask: &str,
    job_id: &str,
    token: &str,
    owner_pid: u32,
    broker: &SharedBroker,
) -> Result<crate::broker::ExecOutput> {
    const BRIDGE_PATH: &str = "/Library/Application Support/scriptd/privilege_bridge.rb";
    const CLIENT_PATH: &str = "/usr/local/libexec/scriptd-broker";
    const START_GATE: &str = "IFS= read -r _ || exit 1\nexec \"$@\"";

    let repo = repo
        .to_str()
        .context("scriptd repository path is not valid UTF-8")?;
    let homebrew = homebrew_bin
        .to_str()
        .context("Homebrew executable path is not valid UTF-8")?;
    let ruby_warnings = format!("-r{BRIDGE_PATH}");
    let mut command = std::process::Command::new(sudo);
    command
        .env_clear()
        .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
        .args(["-n", "-u"])
        .arg(format!("#{client_uid}"))
        .args(["-H", "--", "/usr/bin/env"])
        .arg(format!("HOMEBREW_NO_AUTO_UPDATE=1"))
        .arg("HOMEBREW_DEVELOPER=1")
        .arg("HOMEBREW_SCRIPTD_TEMP_DEVELOPER=1")
        .arg(format!("HOMEBREW_RUBY_WARNINGS={ruby_warnings}"))
        .arg(format!("HOMEBREW_SCRIPTD_PRIVILEGE_CLIENT={CLIENT_PATH}"))
        .arg(format!("HOMEBREW_SCRIPTD_PRIVILEGE_JOB={job_id}"))
        .arg(format!("HOMEBREW_SCRIPTD_PRIVILEGE_TOKEN={token}"))
        .arg(format!("SCRIPTD_ROOT_DIR={repo}"))
        .args(["/bin/sh", "-c", START_GATE, "scriptd-homebrew-worker"])
        .arg(homebrew)
        .args(["upgrade", "--cask", "--no-quit", cask])
        .current_dir(repo)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = command
        .spawn()
        .context("launch the normal-user Homebrew worker")?;
    let worker_pid = child.id();
    let binding = broker
        .lock()
        .map_err(|_| anyhow::anyhow!("broker state is unavailable"))
        .and_then(|mut broker| broker.bind_worker_from(job_id, token, owner_pid, worker_pid));
    if let Err(error) = binding {
        let _ = child.kill();
        let _ = child.wait();
        return Err(error).context("bind the helper-launched Homebrew worker");
    }
    let release = child
        .stdin
        .take()
        .context("Homebrew worker start gate has no input pipe")
        .and_then(|mut stdin| {
            stdin
                .write_all(b"run\n")
                .context("release the authenticated Homebrew worker")
        });
    if let Err(error) = release {
        let _ = child.kill();
        let _ = child.wait();
        return Err(error);
    }
    let output = child
        .wait_with_output()
        .context("wait for helper-launched Homebrew worker")?;
    Ok(crate::broker::ExecOutput {
        status: output.status.code().unwrap_or(1),
        stdout: output.stdout,
        stderr: output.stderr,
    })
}

pub fn run_broker_service(repo: PathBuf) -> Result<()> {
    if unsafe { libc::geteuid() } != 0 {
        bail!("the privilege broker service must run as root");
    }
    let expected_uid = crate::credentials::console_uid()?;
    broker_activation_status(&repo)?;
    let support = PathBuf::from("/Library/Application Support/scriptd");
    let policy = crate::broker::Policy::load_root_owned(
        &support.join("approved-cask-sources.txt"),
        0,
        expected_uid,
    )?;
    if policy.approved_sources.is_empty() {
        bail!("privilege broker requires at least one approved Homebrew source");
    }
    fs::create_dir_all(&support)?;
    let broker = Arc::new(std::sync::Mutex::new(crate::broker::Broker::with_audit(
        policy,
        support.join("broker-audit.json"),
    )));
    let _server = spawn_broker_server(
        repo.clone(),
        broker_socket_path(&repo, expected_uid),
        expected_uid,
        broker,
    )?;
    loop {
        std::thread::park();
    }
}

pub fn transact(socket: &Path, request: &Request) -> Result<Response> {
    transact_with_timeout(socket, request, CONTROL_IO_TIMEOUT)
}

pub fn transact_with_timeout(
    socket: &Path,
    request: &Request,
    timeout: Duration,
) -> Result<Response> {
    let mut stream =
        UnixStream::connect(socket).with_context(|| format!("connect {}", socket.display()))?;
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;
    let line = serde_json::to_string(request)?;
    stream.write_all(line.as_bytes())?;
    stream.write_all(b"\n")?;
    let raw = read_line(&mut stream)?;
    Ok(serde_json::from_str(&raw)?)
}

pub fn dispatch(paths: &ControlPaths, request: Request, peer_ok: bool) -> Response {
    dispatch_with_broker(paths, request, peer_ok, 0, &empty_broker())
}

fn dispatch_with_broker(
    paths: &ControlPaths,
    request: Request,
    peer_ok: bool,
    caller_pid: u32,
    _broker: &SharedBroker,
) -> Response {
    if !peer_ok {
        return rejected(&request.id, "peer user was not accepted");
    }
    if request.v != PROTOCOL_VERSION {
        return rejected(&request.id, "unsupported control protocol version");
    }
    let requested = PathBuf::from(&request.repo);
    let requested = requested.canonicalize().unwrap_or(requested);
    let expected = paths
        .repo
        .canonicalize()
        .unwrap_or_else(|_| paths.repo.clone());
    if requested != expected {
        return rejected(&request.id, "repository identity was not accepted");
    }
    match request.op.as_str() {
        "snapshot" => snapshot_response(paths, &request.id),
        "validate" => validate_request(paths, &request),
        "trigger_draft" => trigger_draft(paths, &request),
        "save" => save(paths, &request),
        "reload" => {
            let digest = file_digest(&paths.repo.join("service.yaml")).ok();
            let _ = request_reload(paths, digest.as_deref().unwrap_or(""));
            accepted(
                &request.id,
                "accepted",
                digest,
                Some("reload requested".to_string()),
            )
        }
        "run" => enqueue_run(paths, &request),
        "logs" => logs(paths, &request),
        "broker_exec" => broker_exec(&request, caller_pid, _broker),
        other => rejected(&request.id, &format!("unknown control operation {other}")),
    }
}

fn snapshot_response(paths: &ControlPaths, id: &str) -> Response {
    match build_snapshot(paths) {
        Ok((digest, snapshot)) => Response {
            v: PROTOCOL_VERSION,
            id: id.to_string(),
            ok: true,
            state: "completed".to_string(),
            apply: None,
            config_digest: Some(digest),
            reload_error: None,
            message: None,
            snapshot: Some(snapshot),
            logs: None,
            draft_yaml: None,
        },
        Err(error) => rejected(id, &error.to_string()),
    }
}

pub fn build_snapshot(paths: &ControlPaths) -> Result<(String, Value)> {
    let service_path = paths.repo.join("service.yaml");
    let digest = file_digest(&service_path).unwrap_or_else(|_| digest(b""));
    let config = config::read_service_config(&paths.repo).ok();
    let state = read_state(&paths.state_dir.join("state.json"), &paths.repo);
    let status = read_control_status(&paths.status);
    let mut modules = Vec::new();
    for id in ["mbrew", "mcpu", "mwifi", "miwatch"] {
        modules.push(module_snapshot(
            &paths.repo,
            &paths.state_dir,
            id,
            config.as_ref(),
            state.as_ref(),
            &paths.broker_audit,
        ));
    }
    let running = state
        .as_ref()
        .and_then(|value| process_alive(value.supervisor.pid).then_some(value.supervisor.pid));
    let service_yaml = fs::read_to_string(&service_path).unwrap_or_default();
    let snapshot = serde_json::json!({
        "service": {
            "label": config.as_ref().map(|value| value.label.clone()).unwrap_or_default(),
            "settings": config.as_ref().map(|value| serde_json::json!({
                "label": value.label.clone(),
                "log_dir": value.log_dir.clone(),
                "watch": value.watch,
                "self_update_check_hours": value.self_update_check_hours,
            })).unwrap_or(Value::Null),
            "running": running.is_some(),
            "pid": running,
            "loaded_digest": status.loaded_digest,
            "reload_error": status.reload_error,
            "restart_required": status.restart_required,
        },
        "config_digest": digest,
        "service_yaml": service_yaml,
        "modules": modules,
        "jobs": read_jobs(&paths.jobs),
        "broker_audit": fs::read_to_string(&paths.broker_audit)
            .ok()
            .and_then(|raw| serde_json::from_str::<Value>(&raw).ok())
            .unwrap_or(Value::Null),
    });
    Ok((digest, snapshot))
}

fn module_snapshot(
    repo: &Path,
    state_dir: &Path,
    id: &str,
    config: Option<&ServiceConfig>,
    state: Option<&PersistedState>,
    broker_audit: &Path,
) -> Value {
    let entry = config.and_then(|config| config.modules.get(id));
    let runtime = state.and_then(|state| state.modules.get(id));
    let manifest = config::read_module_manifest(id, repo).ok();
    let name = manifest
        .as_ref()
        .map(|parsed| parsed.manifest.display_name.clone())
        .unwrap_or_else(|| fallback_name(id).to_string());
    let settings = fs::read_to_string(repo.join("modules").join(id).join("module.yaml"))
        .ok()
        .and_then(|raw| serde_yaml::from_str::<serde_yaml::Value>(&raw).ok())
        .and_then(|value| value.get("settings").cloned())
        .and_then(|value| serde_json::to_value(value).ok())
        .unwrap_or(Value::Null);
    let module_yaml =
        fs::read_to_string(repo.join("modules").join(id).join("module.yaml")).unwrap_or_default();
    let triggers = entry
        .map(|entry| serde_json::to_value(&entry.triggers).unwrap_or(Value::Null))
        .unwrap_or(Value::Null);
    let trigger_state = state
        .map(|state| {
            state
                .triggers
                .iter()
                .filter(|(key, _)| key.starts_with(&format!("{id}.")))
                .map(|(key, value)| {
                    (
                        key.clone(),
                        serde_json::to_value(value).unwrap_or(Value::Null),
                    )
                })
                .collect::<serde_json::Map<String, Value>>()
        })
        .unwrap_or_default();
    serde_json::json!({
        "id": id,
        "name": name,
        "enabled": entry.map(|entry| entry.enabled).unwrap_or(false),
        "present": manifest.is_some(),
        "valid": manifest.is_some() && config.is_some(),
        "status": runtime.map(|value| value.status.clone()).unwrap_or_else(|| "unknown".to_string()),
        "health": runtime.and_then(|value| value.health.clone()).unwrap_or(Value::Null),
        "message": runtime.map(|value| value.message.clone()).unwrap_or_default(),
        "last_run_at": runtime.and_then(|value| value.last_run_at.clone()),
        "next_run_at": runtime.and_then(|value| value.next_run_at.clone()),
        "last_error": runtime.and_then(|value| value.last_error.clone()),
        "module_status": runtime.and_then(|value| value.module_status.clone()).unwrap_or(Value::Null),
        "outcomes": module_outcomes(state_dir, id),
        "privilege_helper": (id == "mbrew").then(|| broker_readiness(repo, broker_audit)),
        "settings": settings,
        "module_yaml": module_yaml,
        "module_digest": digest(module_yaml.as_bytes()),
        "triggers": triggers,
        "trigger_state": trigger_state,
    })
}

fn broker_readiness(repo: &Path, audit_path: &Path) -> String {
    let client = Path::new("/usr/local/libexec/scriptd-broker");
    let bridge = Path::new("/Library/Application Support/scriptd/privilege_bridge.rb");
    let policy = Path::new("/Library/Application Support/scriptd/approved-cask-sources.txt");
    let daemon = Path::new("/Library/LaunchDaemons/com.astronlab.scriptd.broker.plist");
    if crate::broker::validate_root_owned_file(client, 0).is_err() {
        return "Root-owned broker client is not installed".to_string();
    }
    if crate::broker::read_root_owned_file(bridge, 0).is_err() {
        return "Root-owned Homebrew bridge is not installed".to_string();
    }
    if crate::broker::validate_root_owned_file(daemon, 0).is_err() {
        return "Root-owned privilege broker service is not installed".to_string();
    }
    match crate::broker::Policy::load_root_owned(
        policy,
        0,
        crate::credentials::console_uid().unwrap_or(0),
    ) {
        Ok(loaded) if loaded.approved_sources.is_empty() => {
            "No trusted Homebrew sources are configured".to_string()
        }
        Ok(_) if !audit_path.parent().is_some_and(|path| path.is_dir()) => {
            "Broker audit storage is unavailable".to_string()
        }
        Ok(_) if !repo.exists() => "Scriptd repository is unavailable".to_string(),
        Ok(_) => match broker_activation_status(repo) {
            Err(error) => format!("Inactive: privilege activation gate is closed ({error})"),
            Ok(()) => {
                let uid = crate::credentials::console_uid().unwrap_or(0);
                match UnixStream::connect(broker_socket_path(repo, uid)) {
                    Ok(_) => "Inactive: Homebrew runner compatibility has not been verified".to_string(),
                    Err(_) => "Installed but inactive: run 'scriptd broker activate' after the isolated macOS acceptance gate passes".to_string(),
                }
            }
        },
        Err(error) => format!("Approved-source policy is unavailable: {error}"),
    }
}

fn module_outcomes(state_dir: &Path, id: &str) -> Value {
    if id != "mbrew" {
        return Value::Null;
    }
    fs::read_to_string(state_dir.join("mbrew-outcomes.json"))
        .ok()
        .and_then(|raw| serde_json::from_str(&raw).ok())
        .unwrap_or(Value::Null)
}

fn read_jobs(path: &Path) -> Vec<Job> {
    let Ok(raw) = fs::read_to_string(path) else {
        return Vec::new();
    };
    serde_json::from_str::<JobFile>(&raw)
        .map(|file| file.jobs)
        .unwrap_or_default()
}

fn fallback_name(id: &str) -> &'static str {
    match id {
        "mbrew" => "Brew Manager",
        "mcpu" => "CPU Monitor",
        "mwifi" => "Wi-Fi Monitor",
        "miwatch" => "Router Watch",
        _ => "Module",
    }
}

fn save(paths: &ControlPaths, request: &Request) -> Response {
    let _save_guard = match DOCUMENT_SAVE_LOCK.lock() {
        Ok(guard) => guard,
        Err(_) => return rejected(&request.id, "configuration save lock is unavailable"),
    };
    let _cross_process_guard = match CrossProcessSaveLock::acquire(&paths.repo) {
        Ok(guard) => guard,
        Err(error) => {
            return rejected(
                &request.id,
                &format!("configuration save lock failed: {error}"),
            )
        }
    };
    let Some(document) = request.document.as_deref() else {
        return rejected(&request.id, "save requires a document");
    };
    let Some(yaml) = request.yaml.as_deref() else {
        return rejected(&request.id, "save requires yaml");
    };
    let Some(base) = request.base_digest.as_deref() else {
        return rejected(&request.id, "save requires the loaded digest");
    };
    let target = match document {
        "service" => paths.repo.join("service.yaml"),
        "module" => {
            let Some(module) = request.module.as_deref() else {
                return rejected(&request.id, "module save requires a module id");
            };
            if !matches!(module, "mbrew" | "mcpu" | "mwifi" | "miwatch") {
                return rejected(&request.id, "module id is not supported");
            }
            paths.repo.join("modules").join(module).join("module.yaml")
        }
        other => return rejected(&request.id, &format!("unknown document {other}")),
    };
    if let Err(error) = ensure_document_target_is_local(&paths.repo, &target) {
        return rejected(&request.id, &error.to_string());
    }
    let current = fs::read(&target).unwrap_or_default();
    let current_digest = digest(&current);
    if current_digest != base {
        return rejected(&request.id, "the file changed after the draft was opened");
    }
    if let Err(error) = validate_document(&paths.repo, document, request.module.as_deref(), yaml) {
        return rejected(&request.id, &error.to_string());
    }
    let restart = document == "service" && settings_require_restart(&current, yaml.as_bytes());
    if let Err(error) = write_private_atomic(&target, yaml.as_bytes()) {
        return rejected(&request.id, &error.to_string());
    }
    let new_digest = digest(yaml.as_bytes());
    if restart {
        if let Err(error) = set_restart_required(paths, true) {
            return rejected(
                &request.id,
                &format!("configuration saved but restart state could not be recorded: {error}"),
            );
        }
    }
    let reload_error = request_reload(paths, &new_digest).err().map(|error| {
        format!("configuration was saved but the service reload request failed: {error}")
    });
    Response {
        v: PROTOCOL_VERSION,
        id: request.id.clone(),
        ok: true,
        state: "completed".to_string(),
        apply: Some(if restart {
            "restart_required".to_string()
        } else {
            "saved".to_string()
        }),
        config_digest: Some(new_digest),
        reload_error: reload_error.clone(),
        message: reload_error,
        snapshot: None,
        logs: None,
        draft_yaml: None,
    }
}

fn ensure_document_target_is_local(repo: &Path, target: &Path) -> Result<()> {
    let root = repo.canonicalize().context("resolve repository root")?;
    let relative = target
        .strip_prefix(repo)
        .context("configuration target is outside the repository")?;
    let mut cursor = root.clone();
    let components = relative.components().collect::<Vec<_>>();
    for component in components.iter().take(components.len().saturating_sub(1)) {
        cursor.push(component);
        let metadata = fs::symlink_metadata(&cursor)
            .with_context(|| format!("inspect configuration path {}", cursor.display()))?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            bail!("configuration path contains an unsupported link or non-directory");
        }
    }
    let metadata = fs::symlink_metadata(target)
        .with_context(|| format!("inspect configuration file {}", target.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        bail!("configuration file must be a regular file, not a link");
    }
    let parent = target
        .parent()
        .context("configuration target has no parent directory")?
        .canonicalize()
        .context("resolve configuration directory")?;
    if !parent.starts_with(&root) {
        bail!("configuration target resolves outside the repository");
    }
    Ok(())
}

fn validate_request(paths: &ControlPaths, request: &Request) -> Response {
    let (Some(document), Some(yaml)) = (request.document.as_deref(), request.yaml.as_deref())
    else {
        return rejected(&request.id, "validate requires a document and yaml");
    };
    if document == "module"
        && !matches!(
            request.module.as_deref(),
            Some("mbrew" | "mcpu" | "mwifi" | "miwatch")
        )
    {
        return rejected(&request.id, "module id is not supported");
    }
    match validate_document(
        paths.repo.as_path(),
        document,
        request.module.as_deref(),
        yaml,
    ) {
        Ok(()) => {
            let parsed: serde_yaml::Value = match serde_yaml::from_str(yaml) {
                Ok(parsed) => parsed,
                Err(error) => return rejected(&request.id, &error.to_string()),
            };
            let settings = if document == "module" {
                parsed
                    .get("settings")
                    .cloned()
                    .unwrap_or(serde_yaml::Value::Null)
            } else {
                parsed
                    .get("service")
                    .cloned()
                    .unwrap_or(serde_yaml::Value::Null)
            };
            Response {
                v: PROTOCOL_VERSION,
                id: request.id.clone(),
                ok: true,
                state: "validated".to_string(),
                apply: None,
                config_digest: Some(digest(yaml.as_bytes())),
                reload_error: None,
                message: Some("configuration is valid".to_string()),
                snapshot: Some(serde_json::json!({
                    "settings": serde_json::to_value(settings).unwrap_or(Value::Null)
                })),
                logs: None,
                draft_yaml: None,
            }
        }
        Err(error) => rejected(&request.id, &error.to_string()),
    }
}

fn validate_document(repo: &Path, document: &str, module: Option<&str>, yaml: &str) -> Result<()> {
    match document {
        "service" => {
            serde_yaml::from_str::<ServiceConfig>(yaml).context("service.yaml is invalid")?;
            Ok(())
        }
        "module" => {
            let id = module.context("module id is required")?;
            static VALIDATION_ID: std::sync::atomic::AtomicU64 =
                std::sync::atomic::AtomicU64::new(0);
            let temp = loop {
                let candidate = std::env::temp_dir().join(format!(
                    "scriptd-validate-{}-{}-{}",
                    std::process::id(),
                    scope_key(repo),
                    VALIDATION_ID.fetch_add(1, Ordering::Relaxed)
                ));
                match fs::create_dir(&candidate) {
                    Ok(()) => break candidate,
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                    Err(error) => return Err(error.into()),
                }
            };
            let dir = temp.join("modules").join(id);
            fs::create_dir_all(&dir)?;
            fs::write(dir.join("module.yaml"), yaml)?;
            let result = config::read_module_manifest(id, &temp);
            let _ = fs::remove_dir_all(&temp);
            result.map(|_| ())
        }
        other => bail!("unknown document {other}"),
    }
}

fn trigger_draft(paths: &ControlPaths, request: &Request) -> Response {
    let Some(module) = request.module.as_deref() else {
        return rejected(&request.id, "trigger draft requires a module id");
    };
    if !matches!(module, "mbrew" | "mcpu" | "mwifi" | "miwatch") {
        return rejected(&request.id, "module id is not supported");
    }
    let Some(base_digest) = request.base_digest.as_deref() else {
        return rejected(
            &request.id,
            "trigger draft requires the service document digest",
        );
    };
    let Some(trigger_json) = request.yaml.as_deref() else {
        return rejected(&request.id, "trigger draft requires a trigger object");
    };
    let path = paths.repo.join("service.yaml");
    let current = match fs::read(&path) {
        Ok(bytes) => bytes,
        Err(error) => return rejected(&request.id, &error.to_string()),
    };
    if digest(&current) != base_digest {
        return rejected(
            &request.id,
            "the service document changed after trigger editing began",
        );
    }
    let parsed: Value = match serde_json::from_str(trigger_json) {
        Ok(value) => value,
        Err(error) => {
            return rejected(
                &request.id,
                &format!("trigger object is invalid JSON: {error}"),
            );
        }
    };
    let envelope = parsed.get("__scriptd_trigger_draft");
    let trigger_value = envelope
        .and_then(|value| value.get("triggers"))
        .unwrap_or(&parsed);
    let draft_yaml = envelope
        .and_then(|value| value.get("draft_yaml"))
        .and_then(Value::as_str);
    let mut document: serde_yaml::Value = match draft_yaml {
        Some(yaml) => match serde_yaml::from_str(yaml) {
            Ok(value) => value,
            Err(error) => {
                return rejected(
                    &request.id,
                    &format!("service draft is invalid YAML: {error}"),
                );
            }
        },
        None => match serde_yaml::from_slice(&current) {
            Ok(value) => value,
            Err(error) => {
                return rejected(&request.id, &format!("service.yaml is invalid: {error}"));
            }
        },
    };
    let triggers: serde_yaml::Value = match serde_yaml::to_value(trigger_value) {
        Ok(value) => value,
        Err(error) => {
            return rejected(&request.id, &format!("trigger object is invalid: {error}"));
        }
    };
    let key = |value: &str| serde_yaml::Value::String(value.to_string());
    let Some(modules) = document
        .as_mapping_mut()
        .and_then(|root| root.get_mut(key("modules")))
        .and_then(serde_yaml::Value::as_mapping_mut)
    else {
        return rejected(&request.id, "service.yaml has no modules mapping");
    };
    let Some(module_config) = modules
        .get_mut(key(module))
        .and_then(serde_yaml::Value::as_mapping_mut)
    else {
        return rejected(&request.id, "module is not configured in service.yaml");
    };
    module_config.insert(key("triggers"), triggers);
    let yaml = match serde_yaml::to_string(&document) {
        Ok(yaml) => yaml,
        Err(error) => {
            return rejected(
                &request.id,
                &format!("could not render trigger draft: {error}"),
            );
        }
    };
    if let Err(error) = validate_document(&paths.repo, "service", None, &yaml) {
        return rejected(&request.id, &error.to_string());
    }
    Response {
        v: PROTOCOL_VERSION,
        id: request.id.clone(),
        ok: true,
        state: "draft".to_string(),
        apply: None,
        config_digest: Some(base_digest.to_string()),
        reload_error: None,
        message: Some(
            "trigger draft validated; the selected service document has not been saved".to_string(),
        ),
        snapshot: None,
        logs: None,
        draft_yaml: Some(yaml),
    }
}

fn settings_require_restart(current: &[u8], next: &[u8]) -> bool {
    let Ok(current) = serde_yaml::from_slice::<ServiceConfig>(current) else {
        return false;
    };
    let Ok(next) = serde_yaml::from_slice::<ServiceConfig>(next) else {
        return false;
    };
    current.label != next.label || current.control_center != next.control_center
}

fn enqueue_run(paths: &ControlPaths, request: &Request) -> Response {
    if !request.bypass {
        return rejected(
            &request.id,
            "manual execution requires confirmation that global trigger conditions are bypassed",
        );
    }
    let Some(module) = request.module.clone() else {
        return rejected(&request.id, "run requires a module");
    };
    if crate::modules::BuiltInModule::kind_from_id(&module).is_err() {
        return rejected(&request.id, "module is not compiled into this build");
    }
    match request.action.as_deref() {
        None => {}
        Some("retry_pending") if module == "mbrew" => {}
        Some("reboot") if module == "miwatch" => {}
        Some(_) => return rejected(&request.id, "action is not supported for this module"),
    }
    let request_id = request
        .request_id
        .clone()
        .unwrap_or_else(|| request.id.clone());
    let result = with_jobs(&paths.jobs_lock, &paths.jobs, |jobs| {
        if let Some(existing) = jobs.iter().find(|job| job.id == request_id) {
            let same = existing.module == module
                && existing.action == request.action
                && existing.bypass == request.bypass;
            if !same {
                return Err("conflicting reuse of request id".to_string());
            }
            return Ok(existing.clone());
        }
        let job = Job {
            id: request_id,
            module,
            state: "queued".to_string(),
            bypass: true,
            action: request.action.clone(),
            message: None,
        };
        jobs.push(job.clone());
        Ok(job)
    });
    match result {
        Ok(Ok(job)) => Response {
            v: PROTOCOL_VERSION,
            id: request.id.clone(),
            ok: true,
            state: job.state,
            apply: None,
            config_digest: file_digest(&paths.repo.join("service.yaml")).ok(),
            reload_error: None,
            message: Some(format!("request {}", job.id)),
            snapshot: None,
            logs: None,
            draft_yaml: None,
        },
        Ok(Err(message)) => rejected(&request.id, &message),
        Err(error) => rejected(&request.id, &error.to_string()),
    }
}

pub fn claim_queued(paths: &ControlPaths) -> Result<Vec<Job>> {
    with_jobs(&paths.jobs_lock, &paths.jobs, |jobs| {
        let mut claimed = Vec::new();
        if let Some(job) = jobs.iter_mut().find(|job| job.state == "queued") {
            job.state = "running".to_string();
            claimed.push(job.clone());
        }
        claimed
    })
}

pub fn finish_job(
    paths: &ControlPaths,
    id: &str,
    state: &str,
    message: Option<String>,
) -> Result<()> {
    with_jobs(&paths.jobs_lock, &paths.jobs, |jobs| {
        if let Some(job) = jobs.iter_mut().find(|job| job.id == id) {
            job.state = state.to_string();
            job.message = message;
        }
    })
    .map(|_| ())
}

pub fn recover_interrupted(paths: &ControlPaths) -> Result<()> {
    with_jobs(&paths.jobs_lock, &paths.jobs, |jobs| {
        for job in jobs.iter_mut() {
            if job.state == "running" {
                job.state = "interrupted".to_string();
                job.message =
                    Some("interrupted before completion; not replayed automatically".to_string());
            }
        }
    })
    .map(|_| ())
}

fn with_jobs<T>(
    lock_path: &Path,
    jobs_path: &Path,
    mutate: impl FnOnce(&mut Vec<Job>) -> T,
) -> Result<T> {
    let _lock = ExecutionLock::acquire(lock_path)?;
    let mut file = if jobs_path.exists() {
        let raw = fs::read_to_string(jobs_path)?;
        if raw.trim().is_empty() {
            JobFile::default()
        } else {
            serde_json::from_str(&raw)?
        }
    } else {
        JobFile::default()
    };
    let value = mutate(&mut file.jobs);
    write_private_atomic(jobs_path, serde_json::to_string_pretty(&file)?.as_bytes())?;
    Ok(value)
}

fn logs(paths: &ControlPaths, request: &Request) -> Response {
    let Some(module) = request.module.as_deref() else {
        return rejected(&request.id, "logs require a module");
    };
    if !matches!(module, "service" | "mbrew" | "mcpu" | "mwifi" | "miwatch") {
        return rejected(&request.id, "log source is not supported");
    }
    let log_dir = config::read_service_config(&paths.repo)
        .map(|config| config.expanded_log_dir())
        .unwrap_or_else(|_| paths.state_dir.clone());
    let max_lines = request.max_lines.unwrap_or(200).clamp(1, 1000);
    let severity = request.severity.as_deref().unwrap_or("all");
    let query = request.query.as_deref().unwrap_or("");
    let mut lines = if module == "service" {
        read_log_lines(&log_dir.join("scriptd.log"), max_lines)
    } else {
        let mut lines = read_log_lines(&log_dir.join(format!("{module}.log")), max_lines);
        lines.extend(read_log_lines(
            &log_dir.join(format!("{module}.err")),
            max_lines,
        ));
        lines
    };
    lines.retain(|line| {
        severity_matches(line, severity) && (query.is_empty() || line.contains(query))
    });
    if lines.len() > max_lines {
        lines = lines.split_off(lines.len() - max_lines);
    }
    Response {
        v: PROTOCOL_VERSION,
        id: request.id.clone(),
        ok: true,
        state: "completed".to_string(),
        apply: None,
        config_digest: None,
        reload_error: None,
        message: None,
        snapshot: None,
        logs: Some(lines.join("\n")),
        draft_yaml: None,
    }
}

fn read_log_lines(path: &Path, max_lines: usize) -> Vec<String> {
    const CHUNK_SIZE: usize = 8192;
    const MAX_LINE_BYTES: usize = 16 * 1024;
    let Ok(mut file) = fs::File::open(path) else {
        return Vec::new();
    };
    let Ok(mut position) = file.seek(std::io::SeekFrom::End(0)) else {
        return Vec::new();
    };
    let mut reverse_lines = Vec::with_capacity(max_lines.min(1000));
    let mut reverse_line = Vec::new();
    let mut chunk = vec![0; CHUNK_SIZE];
    let max_scan = max_lines.saturating_mul(MAX_LINE_BYTES);
    let mut scanned = 0;
    while position > 0 && reverse_lines.len() < max_lines && scanned < max_scan {
        let length = (position.min(CHUNK_SIZE as u64) as usize).min(max_scan - scanned);
        let start = position - length as u64;
        if file.seek(std::io::SeekFrom::Start(start)).is_err()
            || file.read_exact(&mut chunk[..length]).is_err()
        {
            return Vec::new();
        }
        for byte in chunk[..length].iter().rev().copied() {
            if byte == b'\n' {
                if !reverse_line.is_empty() {
                    reverse_line.reverse();
                    reverse_lines.push(String::from_utf8_lossy(&reverse_line).into_owned());
                    reverse_line.clear();
                    if reverse_lines.len() >= max_lines {
                        break;
                    }
                }
            } else {
                if reverse_line.len() < MAX_LINE_BYTES {
                    reverse_line.push(byte);
                }
            }
        }
        position = start;
        scanned += length;
    }
    if reverse_lines.len() < max_lines && !reverse_line.is_empty() {
        reverse_line.reverse();
        reverse_lines.push(String::from_utf8_lossy(&reverse_line).into_owned());
    }
    reverse_lines.reverse();
    reverse_lines
}

fn severity_matches(line: &str, severity: &str) -> bool {
    let level = if line.contains("[ERROR]") {
        "error"
    } else if line.contains("[WARN]") {
        "warn"
    } else if line.contains("[INFO]") {
        "info"
    } else {
        "info"
    };
    match severity {
        "all" => true,
        "error" => level == "error",
        "warn" => level == "warn",
        "info" => level == "info",
        _ => false,
    }
}

pub fn request_reload(paths: &ControlPaths, digest: &str) -> Result<()> {
    write_private_atomic(&paths.reload, digest.as_bytes())
}

pub fn pending_reload(paths: &ControlPaths) -> Result<Option<String>> {
    if !paths.reload.exists() {
        return Ok(None);
    }
    let value = fs::read_to_string(&paths.reload)?;
    let _ = fs::remove_file(&paths.reload);
    Ok(Some(value))
}

pub fn write_status(
    paths: &ControlPaths,
    loaded_digest: Option<String>,
    reload_error: Option<String>,
) -> Result<()> {
    let restart_required = read_control_status(&paths.status).restart_required;
    let status = ControlStatus {
        loaded_digest,
        reload_error,
        restart_required,
    };
    write_private_atomic(
        &paths.status,
        serde_json::to_string_pretty(&status)?.as_bytes(),
    )
}

pub fn set_restart_required(paths: &ControlPaths, restart_required: bool) -> Result<()> {
    let mut status = read_control_status(&paths.status);
    status.restart_required = restart_required;
    write_private_atomic(
        &paths.status,
        serde_json::to_string_pretty(&status)?.as_bytes(),
    )
}

pub fn loaded_digest(paths: &ControlPaths) -> Option<String> {
    read_control_status(&paths.status).loaded_digest
}

fn read_control_status(path: &Path) -> ControlStatus {
    fs::read_to_string(path)
        .ok()
        .and_then(|raw| serde_json::from_str(&raw).ok())
        .unwrap_or_default()
}

fn read_state(path: &Path, repo: &Path) -> Option<PersistedState> {
    let raw = fs::read_to_string(path).ok()?;
    let state: PersistedState = serde_json::from_str(&raw).ok()?;
    let state_root = PathBuf::from(&state.root_dir);
    let expected = repo.canonicalize().unwrap_or_else(|_| repo.to_path_buf());
    let actual = state_root.canonicalize().unwrap_or(state_root);
    (actual == expected).then_some(state)
}

fn process_alive(pid: i32) -> bool {
    if pid <= 0 {
        return false;
    }
    unsafe { libc::kill(pid, 0) == 0 }
}

fn file_digest(path: &Path) -> Result<String> {
    Ok(digest(&fs::read(path).unwrap_or_default()))
}

fn accepted(id: &str, state: &str, digest: Option<String>, message: Option<String>) -> Response {
    Response {
        v: PROTOCOL_VERSION,
        id: id.to_string(),
        ok: true,
        state: state.to_string(),
        apply: None,
        config_digest: digest,
        reload_error: None,
        message,
        snapshot: None,
        logs: None,
        draft_yaml: None,
    }
}

fn rejected(id: &str, message: &str) -> Response {
    Response {
        v: PROTOCOL_VERSION,
        id: id.to_string(),
        ok: false,
        state: "rejected".to_string(),
        apply: None,
        config_digest: None,
        reload_error: None,
        message: Some(message.to_string()),
        snapshot: None,
        logs: None,
        draft_yaml: None,
    }
}

fn dispatch_broker_request(
    repo: &Path,
    request: Request,
    peer_ok: bool,
    caller_pid: u32,
    client_uid: u32,
    maintenance_service_pid: Option<u32>,
    broker: &SharedBroker,
) -> Response {
    if request.v != PROTOCOL_VERSION {
        return rejected(&request.id, "unsupported broker protocol version");
    }
    if !peer_ok {
        return rejected(&request.id, "broker peer user was not accepted");
    }
    let requested_repo = PathBuf::from(&request.repo)
        .canonicalize()
        .unwrap_or_else(|_| PathBuf::from(&request.repo));
    let expected_repo = repo.canonicalize().unwrap_or_else(|_| repo.to_path_buf());
    if requested_repo != expected_repo {
        return rejected(&request.id, "broker repository identity was not accepted");
    }
    match request.op.as_str() {
        "broker_open" => {
            if !maintenance_service_matches(caller_pid, maintenance_service_pid) {
                return rejected(
                    &request.id,
                    "broker maintenance service identity was not accepted",
                );
            }
            if let Err(error) = broker_activation_status(repo) {
                return rejected(
                    &request.id,
                    &format!("privilege broker is inactive: {error}"),
                );
            }
            let (Some(cask), Some(requested_brew)) =
                (request.module.as_deref(), request.document.as_deref())
            else {
                return rejected(&request.id, "broker job request is incomplete");
            };
            let configured = match config::read_module_manifest("mbrew", repo) {
                Ok(parsed) => match parsed.settings {
                    crate::config::ModuleSettings::Mbrew(settings) => {
                        settings.homebrew_bin().to_string()
                    }
                    _ => return rejected(&request.id, "Homebrew configuration is unavailable"),
                },
                Err(error) => {
                    return rejected(
                        &request.id,
                        &format!("Homebrew configuration is invalid: {error}"),
                    );
                }
            };
            if requested_brew != configured {
                return rejected(
                    &request.id,
                    "Homebrew executable does not match the module configuration",
                );
            }
            let current_console_uid = match crate::credentials::console_uid() {
                Ok(uid) => uid,
                Err(error) => return rejected(&request.id, &error.to_string()),
            };
            if current_console_uid != client_uid {
                return rejected(
                    &request.id,
                    "broker console user changed after the service was authenticated",
                );
            }
            let info_json = match crate::broker::query_cask_info_as_user(
                Path::new(&configured),
                client_uid,
                cask,
            ) {
                Ok(info) => info,
                Err(error) => return rejected(&request.id, &error.to_string()),
            };
            let grant = match broker.lock() {
                Ok(mut broker) => broker.open_cask_job_from(
                    client_uid,
                    caller_pid,
                    cask,
                    &info_json,
                    Duration::from_secs(15 * 60),
                ),
                Err(_) => return rejected(&request.id, "broker state is unavailable"),
            };
            match grant {
                Ok(grant) => Response {
                    v: PROTOCOL_VERSION,
                    id: request.id,
                    ok: true,
                    state: "accepted".to_string(),
                    apply: None,
                    config_digest: None,
                    reload_error: None,
                    message: Some("authenticated Homebrew maintenance job accepted".to_string()),
                    snapshot: Some(serde_json::json!({
                        "job_id": grant.job_id,
                        "token": grant.token,
                    })),
                    logs: None,
                    draft_yaml: None,
                },
                Err(error) => rejected(&request.id, &error.to_string()),
            }
        }
        "broker_launch" => {
            if !maintenance_service_matches(caller_pid, maintenance_service_pid) {
                return rejected(
                    &request.id,
                    "broker maintenance service identity was not accepted",
                );
            }
            if let Err(error) = broker_activation_status(repo) {
                return rejected(
                    &request.id,
                    &format!("privilege broker is inactive: {error}"),
                );
            }
            let (Some(job_id), Some(token)) =
                (request.module.as_deref(), request.request_id.as_deref())
            else {
                return rejected(&request.id, "broker worker launch request is incomplete");
            };
            let current_console_uid = match crate::credentials::console_uid() {
                Ok(uid) => uid,
                Err(error) => return rejected(&request.id, &error.to_string()),
            };
            if current_console_uid != client_uid {
                return rejected(
                    &request.id,
                    "broker console user changed after the service was authenticated",
                );
            }
            let configured = match config::read_module_manifest("mbrew", repo) {
                Ok(parsed) => match parsed.settings {
                    crate::config::ModuleSettings::Mbrew(settings) => {
                        settings.homebrew_bin().to_string()
                    }
                    _ => return rejected(&request.id, "Homebrew configuration is unavailable"),
                },
                Err(error) => {
                    return rejected(
                        &request.id,
                        &format!("Homebrew configuration is invalid: {error}"),
                    );
                }
            };
            let cask = match broker
                .lock()
                .map_err(|_| anyhow::anyhow!("broker state is unavailable"))
                .and_then(|broker| broker.pending_job_cask_from(job_id, token, caller_pid))
            {
                Ok(cask) => cask,
                Err(error) => return rejected(&request.id, &error.to_string()),
            };
            let info_json = match crate::broker::query_cask_info_as_user(
                Path::new(&configured),
                client_uid,
                &cask,
            ) {
                Ok(info) => info,
                Err(error) => return rejected(&request.id, &error.to_string()),
            };
            let bridge = match crate::broker::read_root_owned_file(
                Path::new("/Library/Application Support/scriptd/privilege_bridge.rb"),
                0,
            ) {
                Ok(bridge) => bridge,
                Err(error) => return rejected(&request.id, &error.to_string()),
            };
            if !bridge.contains("def sudo_prefix") {
                return rejected(
                    &request.id,
                    "installed Homebrew privilege bridge is incompatible",
                );
            }
            let homebrew = Path::new(&configured);
            let Some(prefix) = homebrew.parent().and_then(Path::parent) else {
                return rejected(&request.id, "Homebrew executable has no configured prefix");
            };
            let runner = match fs::read_to_string(prefix.join("Library/Homebrew/system_command.rb"))
            {
                Ok(runner) => runner,
                Err(error) => {
                    return rejected(
                        &request.id,
                        &format!("could not read Homebrew's SystemCommand runner: {error}"),
                    );
                }
            };
            if !crate::broker::bridge_compatible(&runner) {
                return rejected(
                    &request.id,
                    "Homebrew privilege bridge compatibility is not verified",
                );
            }
            let reserved_cask = match broker
                .lock()
                .map_err(|_| anyhow::anyhow!("broker state is unavailable"))
                .and_then(|mut broker| {
                    broker.reserve_worker_launch_from(job_id, token, caller_pid, &info_json)
                }) {
                Ok(cask) => cask,
                Err(error) => return rejected(&request.id, &error.to_string()),
            };
            if reserved_cask != cask {
                let _ = broker
                    .lock()
                    .map(|mut broker| broker.complete_from(job_id, token, caller_pid));
                return rejected(
                    &request.id,
                    "broker job cask identity changed before launch",
                );
            }
            let result = run_helper_launched_homebrew_worker(
                Path::new("/usr/bin/sudo"),
                homebrew,
                repo,
                client_uid,
                &cask,
                job_id,
                token,
                caller_pid,
                broker,
            );
            let completed = broker
                .lock()
                .map_err(|_| anyhow::anyhow!("broker state is unavailable"))
                .and_then(|mut broker| broker.complete_from(job_id, token, caller_pid));
            match result {
                Ok(output) => {
                    if let Err(error) = completed {
                        return rejected(&request.id, &error.to_string());
                    }
                    Response {
                        v: PROTOCOL_VERSION,
                        id: request.id,
                        ok: true,
                        state: "completed".to_string(),
                        apply: None,
                        config_digest: None,
                        reload_error: None,
                        message: Some(format!(
                            "Homebrew worker exited with status {}",
                            output.status
                        )),
                        snapshot: Some(serde_json::json!({
                            "status": output.status,
                            "stdout": base64::engine::general_purpose::STANDARD.encode(output.stdout),
                            "stderr": base64::engine::general_purpose::STANDARD.encode(output.stderr),
                        })),
                        logs: None,
                        draft_yaml: None,
                    }
                }
                Err(error) => {
                    let message = match completed {
                        Ok(()) => error.to_string(),
                        Err(completion_error) => {
                            format!(
                                "{error}; broker job completion also failed: {completion_error}"
                            )
                        }
                    };
                    rejected(&request.id, &message)
                }
            }
        }
        "broker_complete" => {
            if !maintenance_service_matches(caller_pid, maintenance_service_pid) {
                return rejected(
                    &request.id,
                    "broker maintenance service identity was not accepted",
                );
            }
            let (Some(job_id), Some(token)) =
                (request.module.as_deref(), request.request_id.as_deref())
            else {
                return rejected(&request.id, "broker completion request is incomplete");
            };
            match broker
                .lock()
                .map_err(|_| anyhow::anyhow!("broker state is unavailable"))
                .and_then(|mut broker| broker.complete_from(job_id, token, caller_pid))
            {
                Ok(()) => accepted(
                    &request.id,
                    "completed",
                    None,
                    Some("broker job completed".to_string()),
                ),
                Err(error) => rejected(&request.id, &error.to_string()),
            }
        }
        "broker_exec" => broker_exec(&request, caller_pid, broker),
        other => rejected(
            &request.id,
            &format!("unsupported broker operation {other}"),
        ),
    }
}

fn broker_exec(request: &Request, caller_pid: u32, broker: &SharedBroker) -> Response {
    let (Some(job_id), Some(token), Some(command_id), Some(program), Some(raw_payload)) = (
        request.module.as_deref(),
        request.request_id.as_deref(),
        request.action.as_deref(),
        request.document.as_deref(),
        request.yaml.as_deref(),
    ) else {
        return rejected(&request.id, "broker execution request is incomplete");
    };
    let payload: BrokerExecPayload = match serde_json::from_str(raw_payload) {
        Ok(payload) => payload,
        Err(error) => return rejected(&request.id, &format!("invalid broker payload: {error}")),
    };
    if payload.args.len() > 4096 || payload.env.len() > 512 {
        return rejected(
            &request.id,
            "broker payload exceeds argument or environment limits",
        );
    }
    let stdin = match base64::engine::general_purpose::STANDARD.decode(payload.stdin) {
        Ok(bytes) => bytes,
        Err(error) => return rejected(&request.id, &format!("invalid broker stdin: {error}")),
    };
    let mut broker_state = match broker.lock() {
        Ok(broker) => broker,
        Err(_) => return rejected(&request.id, "broker state is unavailable"),
    };
    let worker_pid = match broker_state.bound_worker_pid(job_id, token) {
        Ok(pid) => pid,
        Err(error) => return rejected(&request.id, &error.to_string()),
    };
    if !process_descends_from(caller_pid, worker_pid) {
        return rejected(
            &request.id,
            "broker client is outside the bound Homebrew worker tree",
        );
    }
    if let Err(error) = broker_state.authorize_exec(job_id, token, worker_pid, command_id) {
        return rejected(&request.id, &error.to_string());
    }
    drop(broker_state);
    let output = match crate::broker::run_forwarded(
        Path::new(program),
        &payload.args,
        Path::new(&payload.cwd),
        &payload.env,
        &stdin,
    ) {
        Ok(output) => output,
        Err(error) => return rejected(&request.id, &error.to_string()),
    };
    Response {
        v: PROTOCOL_VERSION,
        id: request.id.clone(),
        ok: true,
        state: "completed".to_string(),
        apply: None,
        config_digest: None,
        reload_error: None,
        message: Some(format!(
            "privileged command exited with status {}",
            output.status
        )),
        snapshot: Some(serde_json::json!({
            "status": output.status,
            "stdout": base64::engine::general_purpose::STANDARD.encode(output.stdout),
            "stderr": base64::engine::general_purpose::STANDARD.encode(output.stderr),
        })),
        logs: None,
        draft_yaml: None,
    }
}

fn process_descends_from(mut pid: u32, ancestor: u32) -> bool {
    if pid == 0 || ancestor == 0 || pid == ancestor {
        return false;
    }
    for _ in 0..32 {
        if pid == ancestor {
            return true;
        }
        let output = match std::process::Command::new("/bin/ps")
            .args(["-o", "ppid=", "-p", &pid.to_string()])
            .output()
        {
            Ok(output) if output.status.success() => output,
            _ => return false,
        };
        let parent = String::from_utf8_lossy(&output.stdout)
            .trim()
            .parse::<u32>();
        let Ok(parent) = parent else {
            return false;
        };
        if parent == 0 || parent == pid {
            return false;
        }
        pid = parent;
    }
    false
}

fn peer_pid(stream: &UnixStream) -> Result<u32> {
    #[cfg(target_os = "macos")]
    {
        use std::os::fd::AsRawFd;
        let mut pid: libc::pid_t = 0;
        let mut length = std::mem::size_of_val(&pid) as libc::socklen_t;
        let result = unsafe {
            libc::getsockopt(
                stream.as_raw_fd(),
                libc::SOL_LOCAL,
                libc::LOCAL_PEERPID,
                (&mut pid as *mut libc::pid_t).cast(),
                &mut length,
            )
        };
        if result != 0 || pid <= 0 {
            return Err(std::io::Error::last_os_error()).context("read control peer process");
        }
        return Ok(pid as u32);
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = stream;
        bail!("broker peer-process authentication is supported only on macOS")
    }
}

fn read_request(stream: &mut UnixStream) -> Result<Request> {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
    let raw = read_line(stream)?;
    Ok(serde_json::from_str(&raw)?)
}

fn write_response(stream: &mut UnixStream, response: &Response) -> Result<()> {
    let _ = stream.set_write_timeout(Some(Duration::from_secs(5)));
    let line = serde_json::to_string(response)?;
    stream.write_all(line.as_bytes())?;
    stream.write_all(b"\n")?;
    Ok(())
}

fn read_line(stream: &mut UnixStream) -> Result<String> {
    let mut buffer = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        let read = stream.read(&mut byte)?;
        if read == 0 || byte[0] == b'\n' {
            break;
        }
        if buffer.len() >= MAX_REQUEST_BYTES {
            bail!("control request exceeds {MAX_REQUEST_BYTES} bytes");
        }
        buffer.push(byte[0]);
    }
    Ok(String::from_utf8(buffer)?)
}

fn peer_uid(stream: &UnixStream) -> Result<u32> {
    use std::os::unix::io::AsRawFd;
    let mut uid = 0;
    let mut gid = 0;
    let rc = unsafe { libc::getpeereid(stream.as_raw_fd(), &mut uid, &mut gid) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error()).context("read peer user");
    }
    Ok(uid)
}

use std::os::unix::fs::PermissionsExt;

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> (tempfile::TempDir, tempfile::TempDir, ControlPaths) {
        let repo = tempfile::tempdir().expect("repo");
        let state = tempfile::tempdir().expect("state");
        fs::write(
            repo.path().join("service.yaml"),
            "version: 1\nservice:\n  label: com.example.scriptd\n  log_dir: ~/Library/Logs/scriptd\n  watch: true\n  self_update_check_hours: 12\nmodules:\n  mbrew:\n    enabled: true\n    triggers:\n      maintenance:\n        fire: { mode: every_match }\n        when:\n          schedule:\n            daily_at: \"00:00\"\n            timezone: Asia/Dhaka\n",
        )
        .expect("service");
        fs::create_dir_all(repo.path().join("modules/mbrew")).expect("module dir");
        fs::write(
            repo.path().join("modules/mbrew/module.yaml"),
            "version: 1\nmodule:\n  id: mbrew\n  display_name: Brew Manager\n  mode: task\nsettings:\n  askpass_path: ~/Library/Application Support/scriptd/mbrew/brew_askpass.sh\n  homebrew_bin: /opt/homebrew/bin/brew\n  sudoers_path: /etc/sudoers.d/homebrew\n  sudoers_timeout_path: /etc/sudoers.d/homebrew_timeout\n  sudo_timeout_hours: 2\n",
        )
        .expect("module");
        let paths = paths_for(repo.path(), state.path());
        (repo, state, paths)
    }

    #[test]
    fn control_socket_path_fits_macos_unix_socket_limit() {
        let (_repo, _state, paths) = fixture();
        assert!(paths.socket.as_os_str().len() < 104);
        assert_eq!(paths.socket.parent(), Some(Path::new("/tmp")));
    }

    #[test]
    fn browser_bridge_targets_root_service_socket_but_keeps_user_state() {
        let repo = tempfile::tempdir().expect("repo");
        let state = tempfile::tempdir().expect("browser user state");
        let paths = browser_paths_for(repo.path(), state.path(), 0);
        assert!(paths
            .socket
            .to_string_lossy()
            .starts_with("/tmp/scriptd-0-"));
        assert_eq!(paths.state_dir, state.path());
        assert_eq!(paths.repo, repo.path());
    }

    #[test]
    fn browser_client_reaches_service_socket_from_its_own_state_directory() {
        let (_repo, _service_state, service_paths) = fixture();
        let browser_state = tempfile::tempdir().expect("browser state");
        let browser_paths = browser_paths_for(&service_paths.repo, browser_state.path(), unsafe {
            libc::geteuid()
        });
        assert_ne!(browser_paths.state_dir, service_paths.state_dir);
        assert_eq!(browser_paths.socket, service_paths.socket);

        let expected_uid = unsafe { libc::geteuid() };
        let server = spawn_server(service_paths.clone(), expected_uid, empty_broker())
            .expect("service server");
        let response = transact(
            &browser_paths.socket,
            &Request {
                v: PROTOCOL_VERSION,
                id: "browser-service-snapshot".to_string(),
                op: "snapshot".to_string(),
                repo: service_paths.repo.to_string_lossy().to_string(),
                document: None,
                module: None,
                yaml: None,
                base_digest: None,
                request_id: None,
                bypass: false,
                action: None,
                max_lines: None,
                severity: None,
                query: None,
            },
        )
        .expect("service response");
        assert!(response.ok);
        drop(server);
    }

    #[test]
    fn incomplete_control_client_does_not_block_service_snapshots() {
        let (_repo, _state, paths) = fixture();
        let server = spawn_server(paths.clone(), unsafe { libc::geteuid() }, empty_broker())
            .expect("service server");
        let mut stalled = UnixStream::connect(&paths.socket).expect("stalled client");
        stalled.write_all(b"{\"v\":1").expect("partial request");

        let request = Request {
            v: PROTOCOL_VERSION,
            id: "responsive-snapshot".to_string(),
            op: "snapshot".to_string(),
            repo: paths.repo.to_string_lossy().to_string(),
            document: None,
            module: None,
            yaml: None,
            base_digest: None,
            request_id: None,
            bypass: false,
            action: None,
            max_lines: None,
            severity: None,
            query: None,
        };
        let started = std::time::Instant::now();
        let response = transact(&paths.socket, &request).expect("snapshot response");
        assert!(response.ok);
        assert!(started.elapsed() < Duration::from_secs(1));

        drop(stalled);
        drop(server);
    }

    #[test]
    fn broker_control_forwards_only_a_bound_jobs_command_once() {
        use base64::Engine;
        use std::collections::BTreeSet;
        use std::time::Duration;

        let (_repo, _state, paths) = fixture();
        let policy = crate::broker::Policy {
            owner_uid: 42,
            approved_sources: BTreeSet::from(["homebrew/cask".to_string()]),
        };
        let verified = crate::broker::verify_installed_cask(
            "demo",
            r#"{"casks":[{"token":"demo","tap":"homebrew/cask","installed":"1.0","pinned":false}]}"#,
            &policy,
        )
        .expect("verified cask");
        let broker = Arc::new(std::sync::Mutex::new(crate::broker::Broker::new(policy)));
        let grant = broker
            .lock()
            .expect("broker lock")
            .open_job(crate::broker::OpenRequest {
                caller_uid: 42,
                cask: verified,
                ttl: Duration::from_secs(60),
            })
            .expect("open job");
        broker
            .lock()
            .expect("broker lock")
            .bind_worker(&grant.job_id, &grant.token, std::process::id())
            .expect("bind worker");
        let payload = serde_json::json!({
            "args": [],
            "cwd": "/tmp",
            "env": [],
            "stdin": base64::engine::general_purpose::STANDARD.encode(b"broker-stdin"),
        });
        let request = Request {
            v: PROTOCOL_VERSION,
            id: "broker-exec".to_string(),
            op: "broker_exec".to_string(),
            repo: paths.repo.to_string_lossy().into_owned(),
            document: Some("/bin/cat".to_string()),
            module: Some(grant.job_id.clone()),
            yaml: Some(payload.to_string()),
            base_digest: None,
            request_id: Some(grant.token.clone()),
            bypass: false,
            action: Some("command-once".to_string()),
            max_lines: None,
            severity: None,
            query: None,
        };
        let mut caller = std::process::Command::new("/bin/sleep")
            .arg("5")
            .spawn()
            .expect("spawn helper worker descendant");
        let caller_pid = caller.id();
        let response = dispatch_with_broker(&paths, request.clone(), true, caller_pid, &broker);
        assert!(response.ok, "{:?}", response.message);
        assert_eq!(
            response.snapshot.as_ref().unwrap()["stdout"],
            base64::engine::general_purpose::STANDARD.encode(b"broker-stdin")
        );
        let replay = dispatch_with_broker(&paths, request, true, caller_pid, &broker);
        assert!(!replay.ok);
        assert!(replay.message.unwrap().contains("replay"));
        let _ = caller.kill();
        let _ = caller.wait();
    }

    #[test]
    fn broker_dispatch_rejects_a_peer_with_the_wrong_user_identity() {
        let repo = tempfile::tempdir().expect("repository");
        let response = dispatch_broker_request(
            repo.path(),
            Request {
                v: PROTOCOL_VERSION,
                id: "untrusted-broker-peer".to_string(),
                op: "broker_open".to_string(),
                repo: repo.path().to_string_lossy().into_owned(),
                document: None,
                module: None,
                yaml: None,
                base_digest: None,
                request_id: None,
                bypass: false,
                action: None,
                max_lines: None,
                severity: None,
                query: None,
            },
            false,
            0,
            42,
            None,
            &empty_broker(),
        );
        assert!(!response.ok);
        assert!(response
            .message
            .expect("peer rejection reason")
            .contains("peer user"));
    }

    #[test]
    fn launchd_service_identity_uses_only_its_reported_live_pid() {
        assert_eq!(
            parse_launchd_service_pid("state = running\npid = 4242\nlast exit code = 0\n"),
            Some(4242)
        );
        assert_eq!(
            parse_launchd_service_pid("state = waiting\npid = 123\n"),
            None
        );
        assert_eq!(
            parse_launchd_service_pid("state = waiting\npid = 0\n"),
            None
        );
        assert_eq!(
            parse_launchd_service_pid("state = running\nlast exit code = 0\n"),
            None
        );
        assert_eq!(
            parse_launchd_service_pid("gui/501/test = {\nstate = running\npid = 4242\nresource coalition = {\nstate = active\npid = 17\n}\n}\n"),
            Some(4242)
        );
        assert!(maintenance_service_matches(4242, Some(4242)));
        assert!(!maintenance_service_matches(4242, Some(17)));
        assert!(!maintenance_service_matches(4242, None));
    }

    struct TestProcess(std::process::Child);

    impl TestProcess {
        fn spawn(program: &str, args: &[&str]) -> Result<Self> {
            Ok(Self(
                std::process::Command::new(program).args(args).spawn()?,
            ))
        }
    }

    impl Drop for TestProcess {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn replacement_gui_service_with_correct_label_cannot_authenticate() -> Result<()> {
        let root = tempfile::tempdir()?;
        let replacement = TestProcess::spawn("/bin/sleep", &["60"])?;
        let launchctl = root.path().join("launchctl");
        let uid = unsafe { libc::geteuid() };
        let label = "com.example.scriptd";
        fs::write(&launchctl, format!(
            "#!/bin/sh\n[ \"$1\" = print ] && [ \"$2\" = gui/{uid}/{label} ] || exit 1\nprintf 'state = running\\npid = {}\\n'\n",
            replacement.0.id()
        ))?;
        fs::set_permissions(&launchctl, fs::Permissions::from_mode(0o700))?;
        let error = launchd_service_pid_with(&launchctl, uid, label, Path::new("/usr/bin/true"))
            .expect_err("a matching label must not authenticate the replacement executable");
        assert!(error
            .to_string()
            .contains("not the installed trusted binary"));
        Ok(())
    }

    #[test]
    #[cfg(target_os = "macos")]
    #[ignore = "requires an isolated ephemeral service in a macOS GUI launchd domain"]
    fn live_replacement_user_domain_service_cannot_authenticate() -> Result<()> {
        struct EphemeralService(String);
        impl Drop for EphemeralService {
            fn drop(&mut self) {
                let _ = std::process::Command::new("/bin/launchctl")
                    .args(["bootout", &self.0])
                    .output();
            }
        }
        let root = tempfile::tempdir()?;
        let uid = unsafe { libc::geteuid() };
        let label = format!(
            "com.astronlab.scriptd.test-replacement.{}",
            std::process::id()
        );
        let domain = format!("gui/{uid}");
        let plist = root.path().join("replacement.plist");
        fs::write(&plist, format!(
            "<?xml version=\"1.0\"?><plist version=\"1.0\"><dict>\n<key>Label</key><string>{label}</string>\n<key>ProgramArguments</key><array><string>/bin/sleep</string><string>60</string></array>\n<key>RunAtLoad</key><true/></dict></plist>"
        ))?;
        let status = std::process::Command::new("/bin/launchctl")
            .args(["bootstrap", &domain])
            .arg(&plist)
            .status()?;
        anyhow::ensure!(status.success(), "bootstrap isolated replacement service");
        let _cleanup = EphemeralService(format!("{domain}/{label}"));
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        loop {
            let output = std::process::Command::new("/bin/launchctl")
                .args(["print", &_cleanup.0])
                .output()?;
            if output.status.success()
                && parse_launchd_service_pid(&String::from_utf8_lossy(&output.stdout)).is_some()
            {
                break;
            }
            anyhow::ensure!(
                std::time::Instant::now() < deadline,
                "replacement service did not start"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
        let error = launchd_service_pid_with(
            Path::new("/bin/launchctl"),
            uid,
            &label,
            Path::new("/usr/bin/true"),
        )
        .expect_err("the correct live label must not authenticate an unauthorized executable");
        assert!(error
            .to_string()
            .contains("not the installed trusted binary"));
        Ok(())
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn maintenance_service_rejects_a_stale_peer_execution_token() -> Result<()> {
        use std::os::fd::AsRawFd;
        let (stream, _peer) = UnixStream::pair()?;
        authenticate_peer_execution(&stream, std::process::id())?;
        let mut token = [0u32; 8];
        let mut size = std::mem::size_of_val(&token) as libc::socklen_t;
        let result = unsafe {
            libc::getsockopt(
                stream.as_raw_fd(),
                libc::SOL_LOCAL,
                libc::LOCAL_PEERTOKEN,
                token.as_mut_ptr().cast(),
                &mut size,
            )
        };
        assert_eq!(result, 0);
        token[7] = token[7].wrapping_add(1);
        assert!(authenticate_execution_token(std::process::id(), &mut token).is_err());
        Ok(())
    }

    #[test]
    fn maintenance_service_requires_hardened_non_debuggable_code() {
        let required = 0x00000001 | 0x00000200 | 0x00002000 | 0x00010000;
        assert!(service_code_flags_are_protected(required));
        for bit in [0x00000001, 0x00000200, 0x00002000, 0x00010000] {
            assert!(!service_code_flags_are_protected(required & !bit));
        }
        for bit in [0x00000004, 0x00000020, 0x10000000] {
            assert!(!service_code_flags_are_protected(required | bit));
        }
    }

    #[test]
    fn installed_service_label_is_safe_for_launchd_lookup() {
        assert!(validate_service_label("com.omar.scriptd").is_ok());
        assert!(validate_service_label("").is_err());
        assert!(validate_service_label("../scriptd").is_err());
        assert!(validate_service_label("com.test; id").is_err());
    }

    #[test]
    fn same_uid_process_cannot_open_a_broker_job_without_launchd_service_identity() {
        let (_repo, _state, paths) = fixture();
        let caller_pid = std::process::id();
        let response = dispatch_broker_request(
            &paths.repo,
            Request {
                v: PROTOCOL_VERSION,
                id: "same-user-untrusted-open".to_string(),
                op: "broker_open".to_string(),
                repo: paths.repo.to_string_lossy().into_owned(),
                document: Some("/opt/homebrew/bin/brew".to_string()),
                module: Some("demo".to_string()),
                yaml: None,
                base_digest: None,
                request_id: None,
                bypass: false,
                action: None,
                max_lines: None,
                severity: None,
                query: None,
            },
            true,
            caller_pid,
            unsafe { libc::geteuid() },
            None,
            &empty_broker(),
        );
        assert!(!response.ok);
        assert!(response
            .message
            .expect("service identity rejection")
            .contains("maintenance service identity"));
    }

    #[test]
    fn untrusted_request_cannot_bind_or_execute_as_the_worker() {
        use base64::Engine;
        use std::collections::BTreeSet;
        use std::time::Duration;

        let (_repo, _state, paths) = fixture();
        let caller_pid = std::process::id();
        let uid = unsafe { libc::geteuid() };
        let policy = crate::broker::Policy {
            owner_uid: uid,
            approved_sources: BTreeSet::from(["homebrew/cask".to_string()]),
        };
        let verified = crate::broker::verify_installed_cask(
            "demo",
            r#"{"casks":[{"token":"demo","tap":"homebrew/cask","installed":"1.0","pinned":false}]}"#,
            &policy,
        )
        .expect("verified cask");
        let broker = Arc::new(std::sync::Mutex::new(crate::broker::Broker::new(policy)));
        let grant = broker
            .lock()
            .expect("broker lock")
            .open_job_from(
                crate::broker::OpenRequest {
                    caller_uid: uid,
                    cask: verified,
                    ttl: Duration::from_secs(60),
                },
                caller_pid,
            )
            .expect("open job");
        let bind = dispatch_broker_request(
            &paths.repo,
            Request {
                v: PROTOCOL_VERSION,
                id: "caller-selected-worker".to_string(),
                op: "broker_bind".to_string(),
                repo: paths.repo.to_string_lossy().into_owned(),
                document: Some(caller_pid.to_string()),
                module: Some(grant.job_id.clone()),
                yaml: None,
                base_digest: None,
                request_id: Some(grant.token.clone()),
                bypass: false,
                action: None,
                max_lines: None,
                severity: None,
                query: None,
            },
            true,
            caller_pid,
            uid,
            Some(caller_pid),
            &broker,
        );
        assert!(!bind.ok);
        assert!(bind
            .message
            .expect("unsupported bind rejection")
            .contains("unsupported broker operation"));

        let worker = std::process::Command::new("/bin/sleep")
            .arg("5")
            .spawn()
            .expect("spawn unrelated worker");
        broker
            .lock()
            .expect("broker lock")
            .reserve_worker_launch_from(
                &grant.job_id,
                &grant.token,
                caller_pid,
                r#"{"casks":[{"token":"demo","tap":"homebrew/cask","installed":"1.0","pinned":false}]}"#,
            )
            .expect("reserve helper launch");
        broker
            .lock()
            .expect("broker lock")
            .bind_worker_from(&grant.job_id, &grant.token, caller_pid, worker.id())
            .expect("bind helper worker");
        let exec = dispatch_broker_request(
            &paths.repo,
            Request {
                v: PROTOCOL_VERSION,
                id: "service-outside-worker".to_string(),
                op: "broker_exec".to_string(),
                repo: paths.repo.to_string_lossy().into_owned(),
                document: Some("/bin/id".to_string()),
                module: Some(grant.job_id),
                yaml: Some(
                    serde_json::json!({
                        "args": [],
                        "cwd": "/tmp",
                        "env": [],
                        "stdin": base64::engine::general_purpose::STANDARD.encode(b"")
                    })
                    .to_string(),
                ),
                base_digest: None,
                request_id: Some(grant.token),
                bypass: false,
                action: Some("untrusted-exec".to_string()),
                max_lines: None,
                severity: None,
                query: None,
            },
            true,
            caller_pid,
            uid,
            Some(caller_pid),
            &broker,
        );
        let mut worker = worker;
        let _ = worker.kill();
        let _ = worker.wait();
        assert!(!exec.ok);
        assert!(exec
            .message
            .expect("worker tree rejection")
            .contains("outside the bound Homebrew worker tree"));
    }

    #[test]
    fn broker_launches_homebrew_as_a_bound_normal_user_worker() -> anyhow::Result<()> {
        use std::collections::BTreeSet;
        use std::time::Duration;

        let root = tempfile::tempdir()?;
        let sudo = root.path().join("sudo");
        let brew = root.path().join("brew");
        let sudo_script = "#!/bin/sh\nwhile [ \"$#\" -gt 0 ]; do\n  if [ \"$1\" = \"--\" ]; then shift; break; fi\n  shift\ndone\nexec \"$@\"\n";
        let brew_script =
            "#!/bin/sh\nprintf '%s|%s|%s\\n' \"$HOMEBREW_SCRIPTD_PRIVILEGE_JOB\" \"$*\" \"$PWD\"\n";
        fs::write(&sudo, sudo_script)?;
        fs::write(&brew, brew_script)?;
        fs::set_permissions(&sudo, fs::Permissions::from_mode(0o755))?;
        fs::set_permissions(&brew, fs::Permissions::from_mode(0o755))?;

        let uid = unsafe { libc::geteuid() };
        let owner = TestProcess::spawn("/bin/sleep", &["60"])?;
        let owner_pid = owner.0.id();
        let policy = crate::broker::Policy {
            owner_uid: uid,
            approved_sources: BTreeSet::from(["homebrew/cask".to_string()]),
        };
        let verified = crate::broker::verify_installed_cask(
            "demo",
            r#"{"casks":[{"token":"demo","tap":"homebrew/cask","installed":"1.0","pinned":false}]}"#,
            &policy,
        )?;
        let broker = Arc::new(std::sync::Mutex::new(crate::broker::Broker::new(policy)));
        let grant = broker.lock().expect("broker lock").open_job_from(
            crate::broker::OpenRequest {
                caller_uid: uid,
                cask: verified,
                ttl: Duration::from_secs(60),
            },
            owner_pid,
        )?;
        broker.lock().expect("broker lock").reserve_worker_launch_from(
            &grant.job_id,
            &grant.token,
            owner_pid,
            r#"{"casks":[{"token":"demo","tap":"homebrew/cask","installed":"1.0","pinned":false}]}"#,
        )?;
        let output = run_helper_launched_homebrew_worker(
            &sudo,
            &brew,
            root.path(),
            uid,
            "demo",
            &grant.job_id,
            &grant.token,
            owner_pid,
            &broker,
        )?;
        assert_eq!(output.status, 0);
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(stdout.contains(&grant.job_id));
        assert!(stdout.contains("upgrade --cask --no-quit demo"));
        assert!(stdout.contains(&root.path().to_string_lossy().to_string()));
        let bound = broker
            .lock()
            .expect("broker lock")
            .bound_worker_pid(&grant.job_id, &grant.token)?;
        assert_ne!(bound, owner_pid);
        Ok(())
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn broker_socket_checks_peer_user_repository_and_worker_process() {
        use base64::Engine;
        use std::collections::BTreeSet;
        use std::time::Duration;

        let repo = tempfile::tempdir().expect("repo");
        let uid = unsafe { libc::geteuid() };
        let policy = crate::broker::Policy {
            owner_uid: uid,
            approved_sources: BTreeSet::from(["homebrew/cask".to_string()]),
        };
        let verified = crate::broker::verify_installed_cask(
            "demo",
            r#"{"casks":[{"token":"demo","tap":"homebrew/cask","installed":"1.0","pinned":false}]}"#,
            &policy,
        )
        .expect("verified cask");
        let broker = Arc::new(std::sync::Mutex::new(crate::broker::Broker::new(policy)));
        let service_pid = 42;
        let worker_pid = std::process::id();
        let grant = broker
            .lock()
            .expect("broker lock")
            .open_job_from(
                crate::broker::OpenRequest {
                    caller_uid: uid,
                    cask: verified,
                    ttl: Duration::from_secs(60),
                },
                service_pid,
            )
            .expect("open job");
        broker
            .lock()
            .expect("broker lock")
            .reserve_worker_launch_from(
                &grant.job_id,
                &grant.token,
                service_pid,
                r#"{"casks":[{"token":"demo","tap":"homebrew/cask","installed":"1.0","pinned":false}]}"#,
            )
            .expect("reserve worker");
        broker
            .lock()
            .expect("broker lock")
            .bind_worker_from(&grant.job_id, &grant.token, service_pid, worker_pid)
            .expect("bind worker");
        let socket = repo.path().join("broker.sock");
        let server = spawn_broker_server(repo.path().to_path_buf(), socket.clone(), uid, broker)
            .expect("broker server");
        let payload = serde_json::json!({
            "args": [],
            "cwd": "/tmp",
            "env": [],
            "stdin": base64::engine::general_purpose::STANDARD.encode(b"root broker"),
        });
        let request = Request {
            v: PROTOCOL_VERSION,
            id: "broker-socket-exec".to_string(),
            op: "broker_exec".to_string(),
            repo: repo.path().to_string_lossy().into_owned(),
            document: Some("/bin/cat".to_string()),
            module: Some(grant.job_id),
            yaml: Some(payload.to_string()),
            base_digest: None,
            request_id: Some(grant.token),
            bypass: false,
            action: Some("broker-socket-command".to_string()),
            max_lines: None,
            severity: None,
            query: None,
        };
        let response = transact(&socket, &request).expect("broker response");
        assert!(!response.ok, "the service process is not the helper worker");
        assert!(response
            .message
            .expect("worker identity rejection")
            .contains("outside the bound Homebrew worker tree"));
        let mut wrong_repo = request.clone();
        wrong_repo.id = "wrong-repository".to_string();
        wrong_repo.repo = "/tmp/other-scriptd-repository".to_string();
        let rejected = transact(&socket, &wrong_repo).expect("rejection response");
        assert!(!rejected.ok);
        assert!(rejected.message.unwrap().contains("repository identity"));
        drop(server);
    }

    #[test]
    fn broker_exec_does_not_hold_shared_state_lock_while_child_runs() {
        let (_repo, _state, paths) = fixture();
        let policy = crate::broker::Policy {
            owner_uid: 42,
            approved_sources: std::collections::BTreeSet::from(["homebrew/cask".to_string()]),
        };
        let verified = crate::broker::verify_installed_cask(
            "demo",
            r#"{"casks":[{"token":"demo","tap":"homebrew/cask","installed":"1.0","pinned":false}]}"#,
            &policy,
        )
        .expect("verified cask");
        let broker = Arc::new(std::sync::Mutex::new(crate::broker::Broker::new(policy)));
        let grant = broker
            .lock()
            .expect("broker lock")
            .open_job(crate::broker::OpenRequest {
                caller_uid: 42,
                cask: verified,
                ttl: Duration::from_secs(60),
            })
            .expect("open job");
        broker
            .lock()
            .expect("broker lock")
            .bind_worker(&grant.job_id, &grant.token, std::process::id())
            .expect("bind worker");
        let request = Request {
            v: PROTOCOL_VERSION,
            id: "broker-slow-child".to_string(),
            op: "broker_exec".to_string(),
            repo: paths.repo.to_string_lossy().into_owned(),
            document: Some("/bin/sleep".to_string()),
            module: Some(grant.job_id),
            yaml: Some(
                serde_json::json!({
                    "args": ["1"],
                    "cwd": "/tmp",
                    "env": [],
                    "stdin": ""
                })
                .to_string(),
            ),
            base_digest: None,
            request_id: Some(grant.token),
            bypass: false,
            action: Some("slow-child".to_string()),
            max_lines: None,
            severity: None,
            query: None,
        };
        let mut caller = std::process::Command::new("/bin/sleep")
            .arg("5")
            .spawn()
            .expect("spawn helper worker descendant");
        let caller_pid = caller.id();
        let call_paths = paths.clone();
        let call_broker = Arc::clone(&broker);
        let child = std::thread::spawn(move || {
            dispatch_with_broker(&call_paths, request, true, caller_pid, &call_broker)
        });
        std::thread::sleep(Duration::from_millis(100));
        assert!(
            broker.try_lock().is_ok(),
            "child execution held broker state lock"
        );
        assert!(child.join().expect("broker child thread").ok);
        let _ = caller.kill();
        let _ = caller.wait();
    }

    #[test]
    fn module_sidebar_keeps_installed_modules_visible_when_service_yaml_is_invalid() {
        let (_repo, _state, paths) = fixture();
        let config = config::read_service_config(&paths.repo).expect("valid fixture config");
        let valid = module_snapshot(
            &paths.repo,
            &paths.state_dir,
            "mbrew",
            Some(&config),
            None,
            &paths.broker_audit,
        );
        assert_eq!(valid["present"], true);
        assert_eq!(valid["valid"], true);
        assert_eq!(valid["enabled"], true);

        fs::write(paths.repo.join("service.yaml"), "modules: [broken").expect("invalid config");
        let invalid = module_snapshot(
            &paths.repo,
            &paths.state_dir,
            "mbrew",
            None,
            None,
            &paths.broker_audit,
        );
        assert_eq!(invalid["present"], true);
        assert_eq!(invalid["valid"], false);
        assert_eq!(invalid["enabled"], false);
    }

    #[test]
    fn logs_reject_unrecognized_paths_and_match_severity_exactly() {
        let (_repo, _state, paths) = fixture();
        let request = Request {
            v: PROTOCOL_VERSION,
            id: "logs-traversal".to_string(),
            op: "logs".to_string(),
            repo: paths.repo.to_string_lossy().to_string(),
            document: None,
            module: Some("../../private".to_string()),
            yaml: None,
            base_digest: None,
            request_id: None,
            bypass: false,
            action: None,
            max_lines: Some(10),
            severity: None,
            query: None,
        };
        assert!(!logs(&paths, &request).ok);
        assert!(severity_matches("[ERROR] failed", "warn") == false);
        assert!(severity_matches("[WARN] deferred", "warn"));
        assert!(!severity_matches("[WARN] deferred", "info"));
    }

    #[test]
    fn module_save_rejects_unrecognized_document_paths() {
        let (_repo, _state, paths) = fixture();
        let response = dispatch(
            &paths,
            Request {
                v: PROTOCOL_VERSION,
                id: "traversal".to_string(),
                op: "save".to_string(),
                repo: paths.repo.to_string_lossy().to_string(),
                document: Some("module".to_string()),
                module: Some("../../service".to_string()),
                yaml: Some("version: 1".to_string()),
                base_digest: Some("anything".to_string()),
                request_id: None,
                bypass: false,
                action: None,
                max_lines: None,
                severity: None,
                query: None,
            },
            true,
        );
        assert!(!response.ok);
        assert!(response.message.unwrap().contains("module id"));
    }

    #[test]
    fn validate_checks_service_yaml_without_writing_it() {
        let (_repo, _state, paths) = fixture();
        let yaml = fs::read_to_string(paths.repo.join("service.yaml")).expect("service yaml");
        let response = dispatch(
            &paths,
            Request {
                v: PROTOCOL_VERSION,
                id: "validate-service".to_string(),
                op: "validate".to_string(),
                repo: paths.repo.to_string_lossy().to_string(),
                document: Some("service".to_string()),
                module: None,
                yaml: Some(yaml.clone()),
                base_digest: None,
                request_id: None,
                bypass: false,
                action: None,
                max_lines: None,
                severity: None,
                query: None,
            },
            true,
        );
        assert!(response.ok);
        assert_eq!(response.state, "validated");
        assert_eq!(
            fs::read_to_string(paths.repo.join("service.yaml")).expect("service yaml"),
            yaml
        );
    }

    #[test]
    fn trigger_draft_validates_and_merges_one_module_without_writing() {
        let (_repo, _state, paths) = fixture();
        let source = fs::read(paths.repo.join("service.yaml")).expect("service document");
        let response = dispatch(
            &paths,
            Request {
                v: PROTOCOL_VERSION,
                id: "trigger-draft".to_string(),
                op: "trigger_draft".to_string(),
                repo: paths.repo.to_string_lossy().to_string(),
                document: None,
                module: Some("mbrew".to_string()),
                yaml: Some(r#"{"maintenance":{"fire":{"mode":"every_match"},"when":{"schedule":{"daily_at":"00:00","timezone":"Asia/Dhaka"}}}}"#.to_string()),
                base_digest: Some(digest(&source)),
                request_id: None,
                bypass: false,
                action: None,
                max_lines: None,
                severity: None,
                query: None,
            },
            true,
        );
        assert!(response.ok, "{:?}", response.message);
        let draft = response.draft_yaml.expect("merged service draft");
        assert!(draft.contains("com.example.scriptd"));
        assert!(draft.contains("Asia/Dhaka"));
        assert_eq!(fs::read(paths.repo.join("service.yaml")).unwrap(), source);
    }

    #[test]
    fn save_rejects_external_conflict_and_keeps_the_file() {
        let (_repo, _state, paths) = fixture();
        let original = fs::read_to_string(paths.repo.join("service.yaml")).expect("read");
        let request = Request {
            v: 1,
            id: "save-1".to_string(),
            op: "save".to_string(),
            repo: paths.repo.to_string_lossy().to_string(),
            document: Some("service".to_string()),
            module: None,
            yaml: Some(original.replace("com.example.scriptd", "com.example.other")),
            base_digest: Some("sha256:not-the-file".to_string()),
            request_id: None,
            bypass: false,
            action: None,
            max_lines: None,
            severity: None,
            query: None,
        };
        let response = dispatch(&paths, request, true);
        assert!(!response.ok);
        assert!(response.message.unwrap().contains("changed"));
        let after = fs::read_to_string(paths.repo.join("service.yaml")).expect("read");
        assert!(after.contains("com.example.scriptd"));
    }

    #[test]
    fn save_reports_reload_request_failure_without_claiming_application() {
        let (_repo, state, mut paths) = fixture();
        let original = fs::read_to_string(paths.repo.join("service.yaml")).expect("read");
        let next = original.replace("com.example.scriptd", "com.example.other");
        let not_a_directory = state.path().join("not-a-directory");
        fs::write(&not_a_directory, b"block").expect("write blocker");
        paths.reload = not_a_directory.join("reload.request");
        let response = dispatch(
            &paths,
            Request {
                v: PROTOCOL_VERSION,
                id: "save-reload-failure".to_string(),
                op: "save".to_string(),
                repo: paths.repo.to_string_lossy().to_string(),
                document: Some("service".to_string()),
                module: None,
                yaml: Some(next.clone()),
                base_digest: Some(digest(original.as_bytes())),
                request_id: None,
                bypass: false,
                action: None,
                max_lines: None,
                severity: None,
                query: None,
            },
            true,
        );
        assert!(response.ok);
        assert_eq!(response.apply.as_deref(), Some("restart_required"));
        assert!(response
            .reload_error
            .as_deref()
            .unwrap()
            .contains("saved but"));
        assert_eq!(
            fs::read_to_string(paths.repo.join("service.yaml")).unwrap(),
            next
        );
    }

    #[test]
    fn save_rejects_module_document_symlinks_outside_the_repository() {
        let (_repo, _state, paths) = fixture();
        let module_file = paths.repo.join("modules/mbrew/module.yaml");
        let outside = tempfile::NamedTempFile::new().expect("outside file");
        fs::write(outside.path(), b"outside sentinel").expect("write sentinel");
        fs::remove_file(&module_file).expect("remove module document");
        std::os::unix::fs::symlink(outside.path(), &module_file).expect("symlink module document");
        let response = dispatch(
            &paths,
            Request {
                v: PROTOCOL_VERSION,
                id: "symlink-save".to_string(),
                op: "save".to_string(),
                repo: paths.repo.to_string_lossy().to_string(),
                document: Some("module".to_string()),
                module: Some("mbrew".to_string()),
                yaml: Some("version: 1".to_string()),
                base_digest: Some(digest(b"outside sentinel")),
                request_id: None,
                bypass: false,
                action: None,
                max_lines: None,
                severity: None,
                query: None,
            },
            true,
        );
        assert!(!response.ok);
        assert!(response.message.unwrap().contains("regular file"));
        assert_eq!(
            fs::read(outside.path()).expect("sentinel remains"),
            b"outside sentinel"
        );
    }

    #[test]
    fn duplicate_run_requests_do_not_create_a_second_job() {
        let (_repo, _state, paths) = fixture();
        let request = Request {
            v: 1,
            id: "run-1".to_string(),
            op: "run".to_string(),
            repo: paths.repo.to_string_lossy().to_string(),
            document: None,
            module: Some("mbrew".to_string()),
            yaml: None,
            base_digest: None,
            request_id: Some("same-request".to_string()),
            bypass: true,
            action: None,
            max_lines: None,
            severity: None,
            query: None,
        };
        let first = dispatch(&paths, request.clone(), true);
        let second = dispatch(&paths, request, true);
        assert_eq!(first.state, "queued");
        assert_eq!(second.state, "queued");
        let claimed = claim_queued(&paths).expect("claim");
        assert_eq!(claimed.len(), 1);
        assert!(claim_queued(&paths).expect("second claim").is_empty());
        finish_job(&paths, "same-request", "completed", None).expect("finish");
        let third = dispatch(
            &paths,
            Request {
                id: "run-2".to_string(),
                ..request_base(&paths, "same-request")
            },
            true,
        );
        assert_eq!(third.state, "completed");
    }

    fn request_base(paths: &ControlPaths, request_id: &str) -> Request {
        Request {
            v: 1,
            id: "run-again".to_string(),
            op: "run".to_string(),
            repo: paths.repo.to_string_lossy().to_string(),
            document: None,
            module: Some("mbrew".to_string()),
            yaml: None,
            base_digest: None,
            request_id: Some(request_id.to_string()),
            bypass: true,
            action: None,
            max_lines: None,
            severity: None,
            query: None,
        }
    }

    #[test]
    fn unexpected_peer_is_rejected() {
        let (_repo, _state, paths) = fixture();
        let expected = if unsafe { libc::geteuid() } == 0 {
            1
        } else {
            0
        };
        let server = spawn_server(paths.clone(), expected, empty_broker()).expect("server");
        let response = transact(
            &server.socket,
            &Request {
                v: 1,
                id: "peer".to_string(),
                op: "snapshot".to_string(),
                repo: paths.repo.to_string_lossy().to_string(),
                document: None,
                module: None,
                yaml: None,
                base_digest: None,
                request_id: None,
                bypass: false,
                action: None,
                max_lines: None,
                severity: None,
                query: None,
            },
        )
        .expect("response");
        assert!(!response.ok);
        assert!(response.message.unwrap().contains("peer"));
    }

    #[test]
    fn repository_mismatch_is_rejected() {
        let (_repo, _state, paths) = fixture();
        let response = dispatch(
            &paths,
            Request {
                v: 1,
                id: "repo".to_string(),
                op: "snapshot".to_string(),
                repo: "/tmp".to_string(),
                document: None,
                module: None,
                yaml: None,
                base_digest: None,
                request_id: None,
                bypass: false,
                action: None,
                max_lines: None,
                severity: None,
                query: None,
            },
            true,
        );
        assert!(!response.ok);
        assert!(response.message.unwrap().contains("repository"));
    }
}
