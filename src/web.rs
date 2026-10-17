use std::fs;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::response::sse::{Event, Sse};
use axum::routing::{get, post};
use axum::{Json, Router};
use futures_util::stream;
use serde::Deserialize;
use serde_json::{Value, json};
use tokio::net::TcpListener;
use tokio::sync::{Notify, watch};

use crate::control::{self, ControlPaths};
use crate::paths::{self, write_private_atomic};

const INDEX: &str = include_str!("../assets/web/index.html");

/// Default loopback port for the control center, chosen as a memorable short number.
pub const DEFAULT_BROWSER_PORT: u16 = 15921;
const STYLES: &str = include_str!("../assets/web/styles.css");
const APP: &str = include_str!("../assets/web/app.js");
const PREACT: &str = include_str!("../assets/web/vendor/preact.module.js");
const HTM: &str = include_str!("../assets/web/vendor/htm.module.js");

pub fn stdin_is_interactive() -> bool {
    unsafe { libc::isatty(0) == 1 }
}

pub fn stdout_is_interactive() -> bool {
    unsafe { libc::isatty(1) == 1 }
}

pub fn should_open_browser(argument_count: usize, stdin_tty: bool, stdout_tty: bool) -> bool {
    argument_count == 0 && stdin_tty && stdout_tty
}

pub fn host_allowed(value: &str, port: u16) -> bool {
    value == format!("127.0.0.1:{port}")
}

pub fn origin_allowed(value: Option<&str>, port: u16) -> bool {
    matches!(value, Some(origin) if origin == format!("http://127.0.0.1:{port}"))
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct BrowserSession {
    pid: u32,
    port: u16,
    token: String,
}

struct AppState {
    token: String,
    port: u16,
    paths: ControlPaths,
    connections: AtomicUsize,
    last_disconnect: Mutex<Instant>,
    shutdown: Notify,
    stopping: watch::Sender<bool>,
}

struct ConnectionGuard(Arc<AppState>);

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        self.0.connections.fetch_sub(1, Ordering::SeqCst);
        if let Ok(mut slot) = self.0.last_disconnect.lock() {
            *slot = Instant::now();
        }
    }
}

fn shutdown_due(connections: usize, last_disconnect: Instant, now: Instant) -> bool {
    connections == 0 && now.saturating_duration_since(last_disconnect) >= Duration::from_secs(600)
}

/// Ports tried in order for the control center. The first free port wins.
const BROWSER_PORT_CANDIDATES: [u16; 4] = [
    DEFAULT_BROWSER_PORT,
    DEFAULT_BROWSER_PORT + 1,
    DEFAULT_BROWSER_PORT + 2,
    0,
];
const BRIDGE_DRAIN_TIMEOUT: Duration = Duration::from_secs(5);

/// Overrides the preferred control center port when set to a valid value.
fn preferred_browser_port() -> u16 {
    std::env::var("SCRIPTD_BROWSER_PORT")
        .ok()
        .and_then(|value| value.trim().parse::<u16>().ok())
        .filter(|port| *port != 0)
        .unwrap_or(DEFAULT_BROWSER_PORT)
}

/// Binds the first free port from the candidate list.
///
/// The preferred port never displaces an existing listener: a taken candidate
/// is skipped so another bridge or unrelated process keeps serving on it.
async fn bind_browser_listener_from(preferred: Option<u16>) -> Result<TcpListener> {
    let mut candidates = BROWSER_PORT_CANDIDATES.to_vec();
    candidates[0] = preferred.unwrap_or(BROWSER_PORT_CANDIDATES[0]);
    let mut last_error = None;
    for port in candidates {
        match TcpListener::bind(("127.0.0.1", port)).await {
            Ok(listener) => return Ok(listener),
            Err(error) => last_error = Some(error),
        }
    }
    match last_error {
        Some(error) => Err(error.into()),
        None => anyhow::bail!("no browser port candidates configured"),
    }
}

fn session_path(paths: &ControlPaths) -> PathBuf {
    let name = paths
        .socket
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("control.sock")
        .replace("control-", "web-")
        .replace(".sock", ".json");
    paths.state_dir.join(name)
}

fn draft_path(paths: &ControlPaths) -> PathBuf {
    session_path(paths).with_extension("drafts.json")
}

fn random_token() -> Result<String> {
    let mut bytes = [0u8; 32];
    fs::File::open("/dev/urandom")
        .context("open random source")?
        .read_exact(&mut bytes)?;
    Ok(control::digest(&bytes))
}

fn process_alive(pid: u32) -> bool {
    pid > 0 && unsafe { libc::kill(pid as i32, 0) == 0 }
}

fn read_session(paths: &ControlPaths) -> Option<BrowserSession> {
    let raw = fs::read_to_string(session_path(paths)).ok()?;
    serde_json::from_str(&raw).ok()
}

fn reusable_url(paths: &ControlPaths) -> Option<String> {
    let session = read_session(paths)?;
    if !process_alive(session.pid) {
        let _ = fs::remove_file(session_path(paths));
        return None;
    }
    TcpStream::connect_timeout(
        &format!("127.0.0.1:{}", session.port).parse().ok()?,
        Duration::from_millis(200),
    )
    .ok()?;
    Some(format!(
        "http://127.0.0.1:{}/?session={}",
        session.port, session.token
    ))
}

fn open_url(url: &str) -> Result<()> {
    let status = Command::new("open")
        .arg(url)
        .status()
        .context("open the default browser")?;
    if status.success() {
        Ok(())
    } else {
        anyhow::bail!("the browser could not be opened")
    }
}

pub fn open_control_center(root: &Path, log_dir: &Path) -> Result<()> {
    let paths = control::browser_paths_for(root, &paths::resolve_state_dir(), 0);
    if let Some(url) = reusable_url(&paths) {
        return open_url(&url);
    }
    spawn_bridge(
        &std::env::current_exe().context("resolve scriptd executable")?,
        root,
        log_dir,
    )?;
    for _ in 0..50 {
        if let Some(url) = reusable_url(&paths) {
            return open_url(&url);
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    anyhow::bail!("browser bridge did not become ready")
}

/// Starts a detached browser bridge process for `root`, reusing one that already answers.
pub fn spawn_bridge(exe: &Path, root: &Path, log_dir: &Path) -> Result<()> {
    spawn_bridge_process(exe, root, log_dir).map(|_| ())
}

/// Owns a service control-center bridge hosted on a thread in the supervisor process.
pub struct ServiceBridge {
    state: Arc<AppState>,
    worker: Option<std::thread::JoinHandle<Result<()>>>,
}

impl std::fmt::Debug for ServiceBridge {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ServiceBridge")
            .field(
                "worker_running",
                &self
                    .worker
                    .as_ref()
                    .is_some_and(|worker| !worker.is_finished()),
            )
            .finish()
    }
}

struct BridgeReady {
    state: Arc<AppState>,
}

impl ServiceBridge {
    pub fn stop(&mut self) -> Result<()> {
        self.state.stopping.send_replace(true);
        self.state.shutdown.notify_one();
        // The server forces any remaining connections closed after its bounded
        // graceful-drain window. Join only after it has removed the session and
        // released the instance lock; never report a detached worker as stopped.
        let deadline = Instant::now() + BRIDGE_DRAIN_TIMEOUT + Duration::from_secs(2);
        if let Some(worker) = self.worker.as_ref() {
            while !worker.is_finished() && Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(10));
            }
            if !worker.is_finished() {
                anyhow::bail!("service browser bridge did not stop before the drain deadline");
            }
            if let Some(worker) = self.worker.take() {
                worker
                    .join()
                    .map_err(|_| anyhow::anyhow!("service browser bridge thread panicked"))??;
            }
        }
        Ok(())
    }
}

impl Drop for ServiceBridge {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

/// Starts the persistent control center inside a service-owned thread in the
/// supervisor process, reusing the current browser session when possible.
pub fn start_service_bridge(root: &Path) -> Result<ServiceBridge> {
    let paths = control::browser_paths_for(root, &paths::resolve_state_dir(), 0);
    start_service_bridge_with(paths, Some(preferred_browser_port()))
}

fn stop_existing_bridge(paths: &ControlPaths) -> Result<()> {
    let Some(session) = read_session(paths) else {
        return Ok(());
    };
    if reusable_url(paths).is_none() {
        return Ok(());
    }

    // Only an authenticated response from the session file can request shutdown.
    // Never signal a PID from disk: it could have been reused by an unrelated process.
    request_bridge_shutdown(&session)?;
    let listener = std::net::SocketAddr::from(([127, 0, 0, 1], session.port));
    let stopped = (0..50).any(|_| {
        let session_gone = read_session(paths).is_none();
        let owner_gone = session.pid == std::process::id() || !process_alive(session.pid);
        let listener_closed = TcpStream::connect_timeout(&listener, Duration::from_millis(100)).is_err();
        if session_gone && owner_gone && listener_closed {
            return true;
        }
        std::thread::sleep(Duration::from_millis(100));
        false
    });
    if !stopped {
        anyhow::bail!("existing browser bridge did not stop after authenticated shutdown");
    }
    Ok(())
}

fn start_service_bridge_with(
    paths: ControlPaths,
    preferred_port: Option<u16>,
) -> Result<ServiceBridge> {
    stop_existing_bridge(&paths)?;
    let (ready_sender, ready_receiver) = std::sync::mpsc::sync_channel(1);
    let error_sender = ready_sender.clone();
    let worker = std::thread::Builder::new()
        .name("scriptd-browser-bridge".to_string())
        .spawn(move || {
            let result = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .context("build in-process browser runtime")
                .and_then(|runtime| {
                    runtime.block_on(serve(
                        paths,
                        true,
                        preferred_port,
                        Some(ready_sender),
                    ))
                });
            if let Err(error) = &result {
                let _ = error_sender.try_send(Err(error.to_string()));
            }
            result
        })?;

    match ready_receiver.recv_timeout(Duration::from_secs(5)) {
        Ok(Ok(ready)) => Ok(ServiceBridge {
            state: ready.state,
            worker: Some(worker),
        }),
        Ok(Err(error)) => {
            let _ = worker.join();
            anyhow::bail!("start in-process browser bridge: {error}");
        }
        Err(error) => {
            drop(ready_receiver);
            for _ in 0..20 {
                if worker.is_finished() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(25));
            }
            if worker.is_finished() {
                let _ = worker.join();
            }
            anyhow::bail!("in-process browser bridge did not become ready: {error}");
        }
    }
}

fn request_bridge_shutdown(session: &BrowserSession) -> Result<()> {
    let address = std::net::SocketAddr::from(([127, 0, 0, 1], session.port));
    let mut stream = TcpStream::connect_timeout(&address, Duration::from_millis(500))
        .context("connect to existing browser bridge")?;
    stream.set_read_timeout(Some(Duration::from_secs(1)))?;
    write!(
        stream,
        "POST /api/shutdown HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nX-Scriptd-Session: {}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        session.port, session.token
    )
    .context("request authenticated browser bridge shutdown")?;
    let mut response = String::new();
    stream
        .read_to_string(&mut response)
        .context("read browser bridge shutdown response")?;
    let status = response.lines().next().unwrap_or_default();
    if !status.starts_with("HTTP/1.1 202 ") && !status.starts_with("HTTP/2 202") {
        anyhow::bail!("existing listener did not authenticate browser bridge shutdown");
    }
    Ok(())
}

fn spawn_bridge_process(exe: &Path, root: &Path, log_dir: &Path) -> Result<Child> {
    let paths = control::browser_paths_for(root, &paths::resolve_state_dir(), 0);
    if reusable_url(&paths).is_some() {
        anyhow::bail!("browser bridge is already running");
    }
    let mut command = Command::new(exe);
    command
        .env("SCRIPTD_BROWSER_BRIDGE", "1")
        .env("SCRIPTD_ROOT_DIR", root)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let log_path = log_dir.join("browser-bridge.log");
    if let Ok(file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)
    {
        command.stdout(Stdio::from(file.try_clone().context("clone log file")?));
        command.stderr(Stdio::from(file));
    }
    unsafe {
        command.pre_exec(|| {
            libc::setsid();
            Ok(())
        });
    }
    command.spawn().context("start browser bridge")
}

pub fn serve_bridge() -> Result<()> {
    let root = paths::resolve_repo_root();
    let paths = control::browser_paths_for(&root, &paths::resolve_state_dir(), 0);
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("build browser runtime")?;
    runtime.block_on(serve(paths, false, Some(preferred_browser_port()), None))
}

async fn serve(
    paths: ControlPaths,
    persistent: bool,
    preferred_port: Option<u16>,
    ready: Option<std::sync::mpsc::SyncSender<std::result::Result<BridgeReady, String>>>,
) -> Result<()> {
    fs::create_dir_all(&paths.state_dir)?;
    let _instance_lock = BridgeInstanceLock::acquire(&session_path(&paths).with_extension("lock"))?;
    let listener = bind_browser_listener_from(preferred_port)
        .await
        .context("bind browser bridge")?;
    let port = listener.local_addr()?.port();
    let token = random_token()?;
    let (stopping, _) = watch::channel(false);
    let state = Arc::new(AppState {
        token: token.clone(),
        port,
        paths: paths.clone(),
        connections: AtomicUsize::new(0),
        last_disconnect: Mutex::new(Instant::now()),
        shutdown: Notify::new(),
        stopping,
    });
    let session = BrowserSession {
        pid: std::process::id(),
        port,
        token,
    };
    write_private_atomic(
        &session_path(&paths),
        serde_json::to_string(&session)?.as_bytes(),
    )?;
    if let Some(ready) = ready {
        if ready
            .send(Ok(BridgeReady {
                state: Arc::clone(&state),
            }))
            .is_err()
        {
            state.stopping.send_replace(true);
            state.shutdown.notify_one();
        }
    }
    let shutdown = state.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(5)).await;
            let connections = shutdown.connections.load(Ordering::SeqCst);
            let expired = shutdown
                .last_disconnect
                .lock()
                .map(|slot| shutdown_due(connections, *slot, Instant::now()))
                .unwrap_or(false);
            if expired && !persistent {
                shutdown.stopping.send_replace(true);
                shutdown.shutdown.notify_one();
                break;
            }
        }
    });
    let router = Router::new()
        .route("/", get(index))
        .route("/styles.css", get(styles))
        .route("/app.js", get(script))
        .route("/vendor/preact.module.js", get(preact))
        .route("/vendor/htm.module.js", get(htm))
        .route("/api/snapshot", get(snapshot))
        .route("/api/shutdown", post(shutdown_bridge))
        .route("/api/logs", get(logs))
        .route("/api/validate", post(validate))
        .route("/api/trigger-draft", post(trigger_draft))
        .route("/api/save", post(save))
        .route("/api/run", post(run_action))
        .route("/api/drafts", get(read_drafts).post(write_drafts))
        .route("/events", get(events))
        .with_state(state.clone());
    let shutdown = state.clone();
    let server = axum::serve(listener, router).with_graceful_shutdown(async move {
        shutdown.shutdown.notified().await;
    });
    let forced_shutdown = state.clone();
    let result = tokio::select! {
        result = server => result,
        _ = async move {
            let mut stopping = forced_shutdown.stopping.subscribe();
            if !*stopping.borrow() {
                let _ = stopping.changed().await;
            }
            tokio::time::sleep(BRIDGE_DRAIN_TIMEOUT).await;
        } => Ok(()),
    };
    let _ = fs::remove_file(session_path(&paths));
    result.context("browser bridge stopped")
}

struct BridgeInstanceLock(std::fs::File);

impl BridgeInstanceLock {
    fn acquire(path: &Path) -> Result<Self> {
        use std::os::fd::AsRawFd;

        let file = std::fs::OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .mode(0o600)
            .open(path)
            .with_context(|| format!("open browser bridge lock {}", path.display()))?;
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            anyhow::bail!("a browser bridge is already starting or running");
        }
        Ok(Self(file))
    }
}

impl Drop for BridgeInstanceLock {
    fn drop(&mut self) {
        use std::os::fd::AsRawFd;
        let _ = unsafe { libc::flock(self.0.as_raw_fd(), libc::LOCK_UN) };
    }
}

fn header<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name).and_then(|value| value.to_str().ok())
}

fn authorized(state: &AppState, headers: &HeaderMap, query_token: Option<&str>) -> bool {
    let supplied = header(headers, "x-scriptd-session").or(query_token);
    supplied == Some(state.token.as_str())
        && host_allowed(header(headers, "host").unwrap_or(""), state.port)
}

async fn shutdown_bridge(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if !authorized(&state, &headers, None) {
        return reject(StatusCode::UNAUTHORIZED, "session was not accepted");
    }
    state.stopping.send_replace(true);
    state.shutdown.notify_one();
    (StatusCode::ACCEPTED, Json(json!({ "ok": true })))
}

fn reject(status: StatusCode, message: &str) -> (StatusCode, Json<Value>) {
    (status, Json(json!({ "ok": false, "message": message })))
}

fn control_request(paths: &ControlPaths, id: &str, op: &str) -> control::Request {
    control::Request {
        v: control::PROTOCOL_VERSION,
        id: id.to_string(),
        op: op.to_string(),
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
    }
}

async fn service_snapshot(paths: &ControlPaths) -> Result<(String, Value)> {
    let paths = paths.clone();
    tokio::task::spawn_blocking(move || {
        let request = control_request(&paths, "browser-snapshot", "snapshot");
        for socket in service_socket_candidates(&paths) {
            if let Ok(response) = control::transact(&socket, &request) {
                if response.ok {
                    if let Some(mut snapshot) = response.snapshot {
                        snapshot["service"]["control_connected"] = json!(true);
                        return Ok((response.config_digest.unwrap_or_default(), snapshot));
                    }
                }
            }
        }
        let (digest, mut snapshot) = control::build_snapshot(&paths)?;
        snapshot["service"]["control_connected"] = json!(false);
        Ok((digest, snapshot))
    })
    .await
    .context("read service snapshot")?
}

async fn dispatch_control(
    paths: &ControlPaths,
    request: control::Request,
    offline_ok: bool,
) -> Result<control::Response> {
    let paths = paths.clone();
    tokio::task::spawn_blocking(move || {
        let mut last_error = None;
        for socket in service_socket_candidates(&paths) {
            match control::transact(&socket, &request) {
                Ok(response) => return Ok(response),
                Err(error) => last_error = Some(error),
            }
        }
        if offline_ok {
            Ok(control::dispatch(&paths, request, true))
        } else {
            Err(last_error.unwrap_or_else(|| anyhow::anyhow!("no service endpoint is available")))
        }
    })
    .await
    .context("dispatch service control request")?
}

fn service_socket_candidates(paths: &ControlPaths) -> Vec<PathBuf> {
    let mut sockets = vec![paths.socket.clone()];
    let current_uid = unsafe { libc::geteuid() };
    if let Some(name) = paths.socket.file_name().and_then(|name| name.to_str()) {
        if let Some(suffix) = name.strip_prefix("scriptd-0-") {
            let user_socket = PathBuf::from(format!("/tmp/scriptd-{current_uid}-{suffix}"));
            if current_uid != 0 && user_socket != paths.socket {
                sockets.push(user_socket);
            }
        }
    }
    sockets
}

async fn index(State(state): State<Arc<AppState>>, headers: HeaderMap) -> impl IntoResponse {
    if !host_allowed(header(&headers, "host").unwrap_or(""), state.port) {
        return reject(StatusCode::FORBIDDEN, "host was not accepted").into_response();
    }
    (
        [
            ("content-type", "text/html; charset=utf-8"),
            (
                "content-security-policy",
                "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'",
            ),
            ("referrer-policy", "no-referrer"),
            ("x-content-type-options", "nosniff"),
            ("cache-control", "no-store"),
        ],
        INDEX,
    )
        .into_response()
}

async fn styles(State(state): State<Arc<AppState>>, headers: HeaderMap) -> impl IntoResponse {
    if !host_allowed(header(&headers, "host").unwrap_or(""), state.port) {
        return reject(StatusCode::FORBIDDEN, "host was not accepted").into_response();
    }
    ([("content-type", "text/css; charset=utf-8")], STYLES).into_response()
}

async fn script(State(state): State<Arc<AppState>>, headers: HeaderMap) -> impl IntoResponse {
    if !host_allowed(header(&headers, "host").unwrap_or(""), state.port) {
        return reject(StatusCode::FORBIDDEN, "host was not accepted").into_response();
    }
    ([("content-type", "text/javascript; charset=utf-8")], APP).into_response()
}

async fn preact(State(state): State<Arc<AppState>>, headers: HeaderMap) -> impl IntoResponse {
    if !host_allowed(header(&headers, "host").unwrap_or(""), state.port) {
        return reject(StatusCode::FORBIDDEN, "host was not accepted").into_response();
    }
    ([("content-type", "text/javascript; charset=utf-8")], PREACT).into_response()
}

async fn htm(State(state): State<Arc<AppState>>, headers: HeaderMap) -> impl IntoResponse {
    if !host_allowed(header(&headers, "host").unwrap_or(""), state.port) {
        return reject(StatusCode::FORBIDDEN, "host was not accepted").into_response();
    }
    ([("content-type", "text/javascript; charset=utf-8")], HTM).into_response()
}

#[derive(Deserialize)]
struct TokenQuery {
    session: Option<String>,
}

async fn snapshot(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(query): Query<TokenQuery>,
) -> impl IntoResponse {
    if !authorized(&state, &headers, query.session.as_deref()) {
        return reject(StatusCode::UNAUTHORIZED, "session was not accepted").into_response();
    }
    match service_snapshot(&state.paths).await {
        Ok((digest, snapshot)) => {
            Json(json!({ "ok": true, "config_digest": digest, "snapshot": snapshot }))
                .into_response()
        }
        Err(error) => reject(StatusCode::BAD_GATEWAY, &error.to_string()).into_response(),
    }
}

#[derive(Deserialize)]
struct LogQuery {
    session: Option<String>,
    module: String,
    severity: Option<String>,
    query: Option<String>,
}

async fn logs(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(query): Query<LogQuery>,
) -> impl IntoResponse {
    if !authorized(&state, &headers, query.session.as_deref()) {
        return reject(StatusCode::UNAUTHORIZED, "session was not accepted").into_response();
    }
    let mut request = control_request(&state.paths, "logs", "logs");
    request.module = Some(query.module);
    request.max_lines = Some(400);
    request.severity = query.severity;
    request.query = query.query;
    match dispatch_control(&state.paths, request, true).await {
        Ok(response) => {
            Json(serde_json::to_value(response).unwrap_or(json!({ "ok": false }))).into_response()
        }
        Err(error) => reject(StatusCode::BAD_GATEWAY, &error.to_string()).into_response(),
    }
}

#[derive(Deserialize)]
#[allow(dead_code)]
struct SaveBody {
    document: String,
    module: Option<String>,
    yaml: String,
    base_digest: String,
}

#[derive(Deserialize)]
struct TriggerDraftBody {
    module: String,
    triggers: Value,
    base_digest: String,
    #[serde(default)]
    draft_yaml: Option<String>,
}

async fn trigger_draft(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<TriggerDraftBody>,
) -> impl IntoResponse {
    if !mutating_allowed(&state, &headers) {
        return reject(StatusCode::FORBIDDEN, "origin or session was not accepted").into_response();
    }
    let mut request = control_request(&state.paths, "trigger-draft", "trigger_draft");
    request.module = Some(body.module);
    request.yaml = match serde_json::to_string(&serde_json::json!({
        "__scriptd_trigger_draft": {
            "triggers": body.triggers,
            "draft_yaml": body.draft_yaml,
        }
    })) {
        Ok(value) => Some(value),
        Err(error) => return reject(StatusCode::BAD_REQUEST, &error.to_string()).into_response(),
    };
    request.base_digest = Some(body.base_digest);
    match dispatch_control(&state.paths, request, true).await {
        Ok(response) => {
            Json(serde_json::to_value(response).unwrap_or(json!({ "ok": false }))).into_response()
        }
        Err(error) => reject(StatusCode::BAD_GATEWAY, &error.to_string()).into_response(),
    }
}

async fn save(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<SaveBody>,
) -> impl IntoResponse {
    if !mutating_allowed(&state, &headers) {
        return reject(StatusCode::FORBIDDEN, "origin or session was not accepted").into_response();
    }
    let mut request = control_request(&state.paths, "save", "save");
    request.document = Some(body.document);
    request.module = body.module;
    request.yaml = Some(body.yaml);
    request.base_digest = Some(body.base_digest);
    match dispatch_control(&state.paths, request, true).await {
        Ok(response) => {
            Json(serde_json::to_value(response).unwrap_or(json!({ "ok": false }))).into_response()
        }
        Err(error) => reject(StatusCode::BAD_GATEWAY, &error.to_string()).into_response(),
    }
}

async fn validate(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<SaveBody>,
) -> impl IntoResponse {
    if !mutating_allowed(&state, &headers) {
        return reject(StatusCode::FORBIDDEN, "origin or session was not accepted").into_response();
    }
    let mut request = control_request(&state.paths, "validate", "validate");
    request.document = Some(body.document);
    request.module = body.module;
    request.yaml = Some(body.yaml);
    match dispatch_control(&state.paths, request, true).await {
        Ok(response) => {
            Json(serde_json::to_value(response).unwrap_or(json!({ "ok": false }))).into_response()
        }
        Err(error) => reject(StatusCode::BAD_GATEWAY, &error.to_string()).into_response(),
    }
}

#[derive(Deserialize)]
#[allow(dead_code)]
struct RunBody {
    module: String,
    action: Option<String>,
    confirm: String,
    request_id: String,
}

async fn run_action(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<RunBody>,
) -> impl IntoResponse {
    if !mutating_allowed(&state, &headers) {
        return reject(StatusCode::FORBIDDEN, "origin or session was not accepted").into_response();
    }
    let reboot = body.module == "miwatch" && body.action.as_deref() == Some("reboot");
    if body.module == "miwatch" && !reboot {
        return reject(
            StatusCode::BAD_REQUEST,
            "Router Watch manual execution requires the explicit reboot action",
        )
        .into_response();
    }
    if body.action.as_deref() == Some("reboot") && body.module != "miwatch" {
        return reject(
            StatusCode::BAD_REQUEST,
            "reboot is only supported by Router Watch",
        )
        .into_response();
    }
    let expected = if reboot {
        "reboot-router"
    } else {
        "bypass-global-triggers"
    };
    if body.confirm != expected {
        return reject(StatusCode::BAD_REQUEST, "confirmation did not match").into_response();
    }
    let running = service_snapshot(&state.paths)
        .await
        .map(|(_, snapshot)| snapshot["service"]["running"] == true)
        .unwrap_or(false);
    if !running {
        return reject(
            StatusCode::CONFLICT,
            "The scriptd service must be running. Opening this window does not start it.",
        )
        .into_response();
    }
    let mut request = control_request(&state.paths, &body.request_id, "run");
    request.module = Some(body.module);
    request.request_id = Some(body.request_id);
    request.bypass = true;
    request.action = body.action;
    match dispatch_control(&state.paths, request, false).await {
        Ok(response) => {
            Json(serde_json::to_value(response).unwrap_or(json!({ "ok": false }))).into_response()
        }
        Err(error) => reject(
            StatusCode::CONFLICT,
            &format!("service control is unavailable: {error}"),
        )
        .into_response(),
    }
}

fn mutating_allowed(state: &AppState, headers: &HeaderMap) -> bool {
    authorized(state, headers, None) && origin_allowed(header(headers, "origin"), state.port)
}

async fn read_drafts(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(query): Query<TokenQuery>,
) -> impl IntoResponse {
    if !authorized(&state, &headers, query.session.as_deref()) {
        return reject(StatusCode::UNAUTHORIZED, "session was not accepted").into_response();
    }
    let value = fs::read_to_string(draft_path(&state.paths))
        .ok()
        .and_then(|raw| serde_json::from_str(&raw).ok())
        .unwrap_or_else(|| json!({}));
    Json(json!({ "ok": true, "drafts": value })).into_response()
}

async fn write_drafts(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> impl IntoResponse {
    if !mutating_allowed(&state, &headers) {
        return reject(StatusCode::FORBIDDEN, "origin or session was not accepted").into_response();
    }
    match serde_json::to_vec_pretty(&body) {
        Ok(bytes) => match write_private_atomic(&draft_path(&state.paths), &bytes) {
            Ok(()) => Json(json!({ "ok": true })).into_response(),
            Err(error) => {
                reject(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()).into_response()
            }
        },
        Err(error) => reject(StatusCode::BAD_REQUEST, &error.to_string()).into_response(),
    }
}

async fn events(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(query): Query<TokenQuery>,
) -> impl IntoResponse {
    if !authorized(&state, &headers, query.session.as_deref()) {
        return reject(StatusCode::UNAUTHORIZED, "session was not accepted").into_response();
    }
    state.connections.fetch_add(1, Ordering::SeqCst);
    let guard = ConnectionGuard(state.clone());
    let stopping = state.stopping.subscribe();
    let stream = stream::unfold((state, guard, stopping), |(state, guard, mut stopping)| async move {
        tokio::select! {
            changed = stopping.changed() => {
                if changed.is_err() || *stopping.borrow() {
                    return None;
                }
            }
            _ = tokio::time::sleep(Duration::from_secs(2)) => {}
        }
        if *stopping.borrow() {
            return None;
        }
        let data = service_snapshot(&state.paths)
            .await
            .map(|(_, snapshot)| snapshot.to_string())
            .unwrap_or_else(|error| {
                json!({ "ok": false, "message": error.to_string() }).to_string()
            });
        let event = Event::default().event("snapshot").data(data);
        Some((Ok::<Event, std::convert::Infallible>(event), (state, guard, stopping)))
    });
    Sse::new(stream).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn browser_opens_only_for_a_fully_interactive_bare_launch() {
        assert!(should_open_browser(0, true, true));
        assert!(!should_open_browser(0, false, true));
        assert!(!should_open_browser(0, true, false));
        assert!(!should_open_browser(2, true, true));
    }

    #[test]
    fn host_and_origin_must_match_the_loopback_port() {
        assert!(host_allowed("127.0.0.1:43123", 43123));
        assert!(!host_allowed("localhost:43123", 43123));
        assert!(origin_allowed(Some("http://127.0.0.1:43123"), 43123));
        assert!(!origin_allowed(Some("http://localhost:43123"), 43123));
        assert!(!origin_allowed(None, 43123));
    }

    #[tokio::test]
    async fn browser_port_falls_back_when_a_port_is_already_taken() {
        // The test must not depend on the production port being free, so it
        // reserves candidates itself and exercises the fallback against them.
        let occupied =
            std::net::TcpListener::bind(("127.0.0.1", 0)).expect("reserve the preferred candidate");
        let taken = occupied.local_addr().expect("reserved address").port();
        let listener = bind_browser_listener_from(Some(taken))
            .await
            .expect("bind without displacing the reserved port");
        let port = listener.local_addr().expect("bound address").port();
        assert_ne!(port, taken, "a taken port must not be reused");
        assert_eq!(
            occupied.local_addr().expect("reserved address").port(),
            taken,
            "the existing listener must keep its port"
        );
    }

    #[test]
    fn stale_session_listener_is_never_signalled_as_a_process() {
        let listener =
            std::net::TcpListener::bind(("127.0.0.1", 0)).expect("bind fixture listener");
        let port = listener.local_addr().expect("fixture address").port();
        let responder = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept shutdown request");
            let mut request = [0u8; 1024];
            let _ = stream.read(&mut request).expect("read request");
            stream
                .write_all(
                    b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                )
                .expect("write unrelated listener response");
        });
        let session = BrowserSession {
            pid: std::process::id(),
            port,
            token: "stale-token".to_string(),
        };

        assert!(request_bridge_shutdown(&session).is_err());
        assert!(
            process_alive(session.pid),
            "the unrelated PID must remain alive"
        );
        responder.join().expect("fixture responder");
    }

    #[test]
    fn only_one_browser_bridge_instance_can_hold_a_repository_lock() {
        let dir = tempfile::tempdir().expect("temporary state directory");
        let lock_path = dir.path().join("bridge.lock");
        let first = BridgeInstanceLock::acquire(&lock_path).expect("first bridge lock");
        assert!(BridgeInstanceLock::acquire(&lock_path).is_err());
        drop(first);
        assert!(BridgeInstanceLock::acquire(&lock_path).is_ok());
    }

    #[test]
    fn service_bridge_runs_in_the_supervisor_process_and_stops_cleanly() {
        let dir = tempfile::tempdir().expect("temporary state directory");
        let paths = control::paths_for(dir.path(), dir.path());
        let mut bridge = start_service_bridge_with(paths.clone(), Some(0))
            .expect("start in-process service bridge");
        let session = read_session(&paths).expect("service bridge session");
        assert_eq!(session.pid, std::process::id());
        let address = std::net::SocketAddr::from(([127, 0, 0, 1], session.port));
        assert!(
            TcpStream::connect_timeout(&address, Duration::from_millis(300)).is_ok(),
            "the supervisor process must own a live bridge listener"
        );

        bridge.stop().expect("stop in-process service bridge");
        assert!(read_session(&paths).is_none());
        assert!(TcpStream::connect_timeout(&address, Duration::from_millis(100)).is_err());
    }
    #[test]
    fn bridge_stop_stays_bounded_while_a_request_is_incomplete() {
        let dir = tempfile::tempdir().expect("temporary state directory");
        let paths = control::paths_for(dir.path(), dir.path());
        let mut mine = start_service_bridge_with(paths.clone(), Some(0))
            .expect("start in-process service bridge");
        let session = read_session(&paths).expect("service bridge session");
        let address = std::net::SocketAddr::from(([127, 0, 0, 1], session.port));
        // An incomplete request holds the graceful drain open, so stopping must
        // remain bounded instead of blocking service shutdown indefinitely.
        let mut stalled = TcpStream::connect_timeout(&address, Duration::from_millis(300))
            .expect("connect to the service bridge");
        write!(
            &mut stalled,
            "POST /api/drafts HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nContent-Length: 100\r\n\r\n{{",
            session.port
        )
        .expect("send an incomplete request");

        let started = Instant::now();
        mine.stop()
            .expect("stop the service bridge with a stalled request");
        let elapsed = started.elapsed();

        // Stopping must close the stalled connection and release all bridge
        // resources before returning successfully.
        assert!(TcpStream::connect_timeout(&address, Duration::from_millis(200)).is_err());
        assert!(
            elapsed < Duration::from_secs(20),
            "stopping must not wait indefinitely: {elapsed:?}"
        );
        assert!(read_session(&paths).is_none());

        let mut restarted = start_service_bridge_with(paths.clone(), Some(0))
            .expect("restart while the prior client socket remains open");
        restarted
            .stop()
            .expect("stop restarted bridge while prior client socket remains open");
        assert!(read_session(&paths).is_none());
        drop(stalled);
    }

    #[test]
    fn bridge_grace_expires_only_ten_minutes_after_the_last_disconnection() {
        let disconnected = Instant::now();
        assert!(!shutdown_due(
            0,
            disconnected,
            disconnected + Duration::from_secs(599)
        ));
        assert!(shutdown_due(
            0,
            disconnected,
            disconnected + Duration::from_secs(600)
        ));
        assert!(!shutdown_due(
            1,
            disconnected,
            disconnected + Duration::from_secs(900)
        ));
    }

    #[test]
    fn closing_one_of_multiple_tabs_does_not_start_the_idle_grace() {
        let dir = tempfile::tempdir().expect("temporary state directory");
        let paths = control::paths_for(dir.path(), dir.path());
        let state = Arc::new(AppState {
            token: "test".to_string(),
            port: 43123,
            paths,
            connections: AtomicUsize::new(2),
            last_disconnect: Mutex::new(Instant::now()),
            shutdown: Notify::new(),
            stopping: watch::channel(false).0,
        });
        let first = ConnectionGuard(state.clone());
        drop(first);
        assert_eq!(state.connections.load(Ordering::SeqCst), 1);
        assert!(!shutdown_due(
            1,
            Instant::now() - Duration::from_secs(900),
            Instant::now()
        ));
        let last = ConnectionGuard(state.clone());
        drop(last);
        assert_eq!(state.connections.load(Ordering::SeqCst), 0);
        let disconnected = *state.last_disconnect.lock().unwrap();
        assert!(!shutdown_due(0, disconnected, Instant::now()));
    }
}
