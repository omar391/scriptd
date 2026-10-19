use std::fs;

use std::net::TcpStream;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::net::TcpListener;

use anyhow::{Context, Result};
use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::sse::{Event, Sse};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use futures_util::stream;
use serde::Deserialize;
use serde_json::{json, Value};
use tokio::sync::{watch, Notify};

use crate::access::{self, AccessController, AccessState};
use crate::control::{self, ControlPaths};
use crate::grants::GrantsStore;
use crate::paths::{self, write_private_atomic};

const INDEX: &str = include_str!("../assets/web/index.html");

/// Default loopback port for the control center, chosen as a memorable short number.
pub const DEFAULT_BROWSER_PORT: u16 = 15921;
const BRIDGE_DRAIN_TIMEOUT: Duration = Duration::from_secs(5);
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

struct AppState {
    port: u16,
    paths: ControlPaths,
    connections: AtomicUsize,
    last_disconnect: Mutex<Instant>,
    shutdown: Notify,
    stopping: watch::Sender<bool>,
    access: AccessController,
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

fn detached_shutdown_due(
    persistent: bool,
    connections: usize,
    last_disconnect: Instant,
    now: Instant,
) -> bool {
    !persistent && shutdown_due(connections, last_disconnect, now)
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
    spawn_bridge(
        &std::env::current_exe().context("resolve scriptd executable")?,
        root,
        log_dir,
    )?;
    for _ in 0..50 {
        if let Ok(_) = TcpStream::connect_timeout(
            &format!("127.0.0.1:{}", DEFAULT_BROWSER_PORT)
                .parse()
                .ok()
                .unwrap(),
            Duration::from_millis(100),
        ) {
            return open_url(&format!("http://127.0.0.1:{}", DEFAULT_BROWSER_PORT));
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
    start_service_bridge_with(paths, Some(DEFAULT_BROWSER_PORT))
}

fn start_service_bridge_with(
    paths: ControlPaths,
    preferred_port: Option<u16>,
) -> Result<ServiceBridge> {
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
                    runtime.block_on(serve(paths, true, preferred_port, Some(ready_sender)))
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

fn spawn_bridge_process(exe: &Path, root: &Path, log_dir: &Path) -> Result<Child> {
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
    runtime.block_on(serve(paths, false, Some(DEFAULT_BROWSER_PORT), None))
}

async fn serve(
    paths: ControlPaths,
    persistent: bool,
    preferred_port: Option<u16>,
    ready: Option<std::sync::mpsc::SyncSender<std::result::Result<BridgeReady, String>>>,
) -> Result<()> {
    fs::create_dir_all(&paths.state_dir)?;
    let _instance_lock = BridgeInstanceLock::acquire(&paths.state_dir.join("browser-bridge.lock"))?;
    let listener = TcpListener::bind(("127.0.0.1", preferred_port.unwrap_or(DEFAULT_BROWSER_PORT)))
        .await
        .context("bind browser listener")?;
    let port = listener.local_addr()?.port();
    let grants = GrantsStore::load(&paths).context("load browser grants")?;
    let access = AccessController::new(grants);
    let (stopping, _) = watch::channel(false);
    let state = Arc::new(AppState {
        port,
        paths: paths.clone(),
        connections: AtomicUsize::new(0),
        last_disconnect: Mutex::new(Instant::now()),
        shutdown: Notify::new(),
        stopping,
        access,
    });
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
                .map(|slot| detached_shutdown_due(persistent, connections, *slot, Instant::now()))
                .unwrap_or(false);
            if expired {
                shutdown.stopping.send_replace(true);
                shutdown.shutdown.notify_one();
                break;
            }
        }
    });
    let router = bridge_router(state.clone());
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
    // Persist the grants store on shutdown
    if let Err(error) = state.access.snapshot().save(&state.paths) {
        eprintln!("Failed to save browser grants: {}", error);
    }
    result.context("browser bridge stopped")
}

fn bridge_router(state: Arc<AppState>) -> Router {
    Router::new()
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
        .route("/api/access", get(access_status))
        .route("/api/access/request", post(access_request))
        .route("/api/access/poll", post(access_poll))
        .route("/api/access/revoke", post(access_revoke))
        .route("/api/access/list", get(access_list))
        .route("/events", get(events))
        .with_state(state)
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

/// True when the request came from this loopback address and an approved
/// browser grant. Every authenticated endpoint checks the Host header so a
/// DNS-rebinding or cross-origin request is rejected before credentials matter.
fn authorized(state: &AppState, headers: &HeaderMap) -> bool {
    host_allowed(header(headers, "host").unwrap_or(""), state.port)
        && state.access.verifies(headers)
}

async fn shutdown_bridge(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if !authorized(&state, &headers) {
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

/// Reports the browser's access state and a short identifier if pending.
async fn access_status(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if !host_allowed(header(&headers, "host").unwrap_or(""), state.port) {
        return reject(StatusCode::FORBIDDEN, "host was not accepted").into_response();
    }
    let access_state = state.access.state_for(&headers);
    let pending = if access_state == AccessState::Pending {
        state.access.pending_identifier()
    } else {
        None
    };
    let mut response = Json(json!({
        "ok": true,
        "state": access_state.as_str(),
        "pending_identifier": pending,
    }))
    .into_response();
    response.headers_mut().insert(
        "cache-control",
        axum::http::HeaderValue::from_static("no-store"),
    );
    response
}

async fn access_request(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<crate::access::AccessRequestBody>,
) -> impl IntoResponse {
    if !host_allowed(header(&headers, "host").unwrap_or(""), state.port) {
        return reject(StatusCode::FORBIDDEN, "host was not accepted").into_response();
    }
    if !origin_allowed(header(&headers, "origin"), state.port) {
        return reject(StatusCode::FORBIDDEN, "origin was not accepted").into_response();
    }
    if state.access.verifies(&headers) {
        return reject(StatusCode::CONFLICT, "this browser already has access").into_response();
    }
    let label = if body.label.trim().is_empty() {
        "Browser on this Mac".to_string()
    } else {
        body.label.trim().chars().take(80).collect()
    };
    let ticket = match state.access.open_request(&label) {
        Ok(ticket) => ticket,
        Err(message) => {
            return reject(StatusCode::TOO_MANY_REQUESTS, &message).into_response();
        }
    };
    // Hand the claim back immediately and open the native prompt behind the
    // request. Blocking the response on an OS dialog would strand this tab on
    // an open HTTP request, so polling is the path that delivers the decision.
    let pending_state = Arc::clone(&state);
    let identifier = ticket.identifier.clone();
    let claim = ticket.claim.clone();
    tokio::spawn(async move {
        let decision = crate::approval::request_approval(
            "Scriptd access request",
            &format!(
                "Allow this browser to manage Scriptd?

Identifier: {}
Label: {}",
                identifier, label
            ),
            crate::access::REQUEST_TIMEOUT,
        )
        .await;
        match decision {
            Ok(crate::approval::ApprovalDecision::Allowed) => {
                if let Err(error) = pending_state.access.resolve_claim(&claim, true) {
                    pending_state.access.cancel_claim(&claim);
                    eprintln!("Failed to record a browser approval: {error}");
                    return;
                }
                if let Err(error) = pending_state.access.snapshot().save(&pending_state.paths) {
                    pending_state.access.cancel_claim(&claim);
                    eprintln!("Failed to persist a browser approval: {error}");
                }
            }
            Ok(crate::approval::ApprovalDecision::Denied) => {
                let _ = pending_state.access.resolve_claim(&claim, false);
            }
            Ok(crate::approval::ApprovalDecision::Unavailable) | Err(_) => {
                pending_state.access.cancel_claim(&claim);
            }
        }
    });
    let mut response = Json(json!({
        "ok": true,
        "state": access::AccessState::Pending.as_str(),
        "identifier": ticket.identifier,
        "claim": ticket.claim,
    }))
    .into_response();
    response.headers_mut().insert(
        "cache-control",
        axum::http::HeaderValue::from_static("no-store"),
    );
    response
}
async fn access_poll(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<crate::access::AccessPollBody>,
) -> impl IntoResponse {
    if !host_allowed(header(&headers, "host").unwrap_or(""), state.port) {
        return reject(StatusCode::FORBIDDEN, "host was not accepted").into_response();
    }
    let outcome = state.access.poll(&body.claim);
    let mut response = match outcome {
        access::PollOutcome::Waiting => Json(json!({
            "ok": true,
            "state": access::AccessState::Pending.as_str(),
        }))
        .into_response(),
        access::PollOutcome::Allowed(credential) => Json(json!({
            "ok": true,
            "state": access::AccessState::Authorized.as_str(),
            "grant": credential,
        }))
        .into_response(),
        access::PollOutcome::Expired => Json(json!({
            "ok": false,
            "state": access::AccessState::Unauthorized.as_str(),
            "message": "the request expired or was never opened by this tab",
        }))
        .into_response(),
    };
    response.headers_mut().insert(
        "cache-control",
        axum::http::HeaderValue::from_static("no-store"),
    );
    response
}

async fn access_revoke(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<crate::access::AccessRevokeBody>,
) -> impl IntoResponse {
    if !authorized(&state, &headers) || !origin_allowed(header(&headers, "origin"), state.port) {
        return reject(StatusCode::FORBIDDEN, "origin or grant was not accepted").into_response();
    }
    if !state.access.revoke(&body.id) {
        return reject(
            StatusCode::NOT_FOUND,
            "no browser profile matches that identity",
        )
        .into_response();
    }
    if let Err(error) = state.access.snapshot().save(&state.paths) {
        return reject(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("persist the revoked grants: {error}"),
        )
        .into_response();
    }
    Json(json!({ "ok": true })).into_response()
}

async fn access_list(State(state): State<Arc<AppState>>, headers: HeaderMap) -> impl IntoResponse {
    if !authorized(&state, &headers) {
        return reject(StatusCode::UNAUTHORIZED, "grant was not accepted").into_response();
    }
    let profiles = state
        .access
        .list()
        .into_iter()
        .map(|(id, label, issued_at)| json!({ "id": id, "label": label, "issued_at": issued_at }))
        .collect::<Vec<_>>();
    Json(json!({ "ok": true, "profiles": profiles })).into_response()
}

async fn snapshot(State(state): State<Arc<AppState>>, headers: HeaderMap) -> impl IntoResponse {
    if !authorized(&state, &headers) {
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
    module: String,
    severity: Option<String>,
    query: Option<String>,
}

async fn logs(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(query): Query<LogQuery>,
) -> impl IntoResponse {
    if !authorized(&state, &headers) {
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
    authorized(state, headers) && origin_allowed(header(headers, "origin"), state.port)
}

async fn read_drafts(State(state): State<Arc<AppState>>, headers: HeaderMap) -> impl IntoResponse {
    if !authorized(&state, &headers) {
        return reject(StatusCode::UNAUTHORIZED, "session was not accepted").into_response();
    }
    let value = fs::read_to_string(state.paths.state_dir.join("drafts.json"))
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
        Ok(bytes) => match write_private_atomic(&state.paths.state_dir.join("drafts.json"), &bytes)
        {
            Ok(()) => Json(json!({ "ok": true })).into_response(),
            Err(error) => {
                reject(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()).into_response()
            }
        },
        Err(error) => reject(StatusCode::BAD_REQUEST, &error.to_string()).into_response(),
    }
}

async fn events(State(state): State<Arc<AppState>>, headers: HeaderMap) -> impl IntoResponse {
    if !authorized(&state, &headers) {
        return reject(StatusCode::UNAUTHORIZED, "session was not accepted").into_response();
    }
    state.connections.fetch_add(1, Ordering::SeqCst);
    let guard = ConnectionGuard(state.clone());
    let stopping = state.stopping.subscribe();
    let stream_headers = headers.clone();
    let stream = stream::unfold(
        (state, guard, stopping, stream_headers),
        |(state, guard, mut stopping, headers)| async move {
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
            // A revoked profile loses an already-open stream on its next poll.
            if !authorized(&state, &headers) {
                return None;
            }
            let data = service_snapshot(&state.paths)
                .await
                .map(|(_, snapshot)| snapshot.to_string())
                .unwrap_or_else(|error| {
                    json!({ "ok": false, "message": error.to_string() }).to_string()
                });
            let event = Event::default().event("snapshot").data(data);
            Some((
                Ok::<Event, std::convert::Infallible>(event),
                (state, guard, stopping, headers),
            ))
        },
    );
    Sse::new(stream).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    use axum::http::HeaderValue;

    fn test_paths() -> (tempfile::TempDir, ControlPaths) {
        let dir = tempfile::tempdir().expect("temporary state directory");
        let paths = control::paths_for(dir.path(), dir.path());
        let cloned = paths.clone();
        (dir, cloned)
    }

    /// An isolated AppState whose grant store is empty and never persisted to
    /// the real service state directory.
    fn test_state(port: u16) -> Arc<AppState> {
        let (dir, paths) = test_paths();
        std::mem::forget(dir);
        let grants = GrantsStore::load(&paths).expect("empty grants store");
        Arc::new(AppState {
            port,
            paths,
            connections: AtomicUsize::new(0),
            last_disconnect: Mutex::new(Instant::now()),
            shutdown: Notify::new(),
            stopping: watch::channel(false).0,
            access: AccessController::new(grants),
        })
    }

    fn loopback_host(port: u16) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            "host",
            HeaderValue::from_str(&format!("127.0.0.1:{port}")).expect("host header"),
        );
        headers
    }

    fn headers_with_grant(port: u16, grant: &str) -> HeaderMap {
        let mut headers = loopback_host(port);
        headers.insert(
            crate::access::GRANT_HEADER,
            HeaderValue::from_str(grant).expect("grant header"),
        );
        headers
    }

    async fn http_get(port: u16, path: &str, header: Option<(&str, &str)>) -> String {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .expect("connect to test bridge");
        let extra_header = header
            .map(|(name, value)| format!("{name}: {value}\r\n"))
            .unwrap_or_default();
        let request = format!(
            "GET {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n{extra_header}Connection: close\r\n\r\n"
        );
        stream
            .write_all(request.as_bytes())
            .await
            .expect("write HTTP request");
        let mut response = Vec::new();
        stream
            .read_to_end(&mut response)
            .await
            .expect("read HTTP response");
        String::from_utf8(response).expect("HTTP response is UTF-8")
    }

    async fn http_post(port: u16, path: &str, body: &str, header: Option<(&str, &str)>) -> String {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .expect("connect to test bridge");
        let mut extra = String::new();
        if let Some((name, value)) = header {
            extra.push_str(&format!("{name}: {value}\r\n"));
        }
        let request = format!(
            "POST {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n{extra}Connection: close\r\n\r\n{body}",
            body.len()
        );
        stream
            .write_all(request.as_bytes())
            .await
            .expect("write HTTP request");
        let mut response = Vec::new();
        stream
            .read_to_end(&mut response)
            .await
            .expect("read HTTP response");
        String::from_utf8(response).expect("HTTP response is UTF-8")
    }

    /// Serves the real bridge router on an ephemeral port and returns the port
    /// plus the shutdown signal. The join handle is leaked so the test ends by
    /// sending on the channel.
    async fn spawn_test_bridge(
        state: &mut Arc<AppState>,
    ) -> (u16, tokio::sync::oneshot::Sender<()>) {
        let listener = TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("bind test bridge");
        let port = listener.local_addr().expect("test bridge address").port();
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
        Arc::get_mut(state)
            .expect("test bridge state has one owner before serving")
            .port = port;
        let state = Arc::clone(state);
        let server = tokio::spawn(async move {
            axum::serve(listener, bridge_router(state))
                .with_graceful_shutdown(async move {
                    let _ = shutdown_rx.await;
                })
                .await
        });
        std::mem::forget(server);
        (port, shutdown_tx)
    }

    #[tokio::test]
    async fn unauthorized_browser_is_told_it_needs_authorization() {
        // A grant-less browser must read "authorization required", never a
        // misleading service-offline state.
        let mut state = test_state(0);
        let (port, shutdown_tx) = spawn_test_bridge(&mut state).await;

        let body = http_get(port, "/api/access", None).await;
        assert!(body.starts_with("HTTP/1.1 200"), "{body}");
        assert!(body.contains("\"state\":\"unauthorized\""), "{body}");
        assert!(body.contains("\"pending_identifier\":null"), "{body}");
        let _ = shutdown_tx.send(());
    }

    #[tokio::test]
    async fn snapshot_and_events_reject_a_missing_grant() {
        // Authenticated endpoints must refuse a grant-less request instead of
        // answering as if the browser were approved.
        let mut state = test_state(0);
        let (port, shutdown_tx) = spawn_test_bridge(&mut state).await;

        assert!(
            "HTTP/1.1 401" == &http_get(port, "/api/snapshot", None).await[..12],
            "the snapshot requires a grant"
        );
        assert!(
            "HTTP/1.1 401" == &http_get(port, "/events", None).await[..12],
            "the live stream requires a grant"
        );
        let _ = shutdown_tx.send(());
    }

    #[tokio::test]
    async fn an_approved_reaches_the_snapshot_stream_and_settings() {
        // The full path a real browser takes: open a request, approve it,
        // receive the credential through the private claim, then use it for the
        // snapshot, the live stream and the browser access settings.
        let mut state = test_state(0);
        let (port, shutdown_tx) = spawn_test_bridge(&mut state).await;

        let ticket = state
            .access
            .open_request("Test browser")
            .expect("open request");
        assert!(!ticket.identifier.is_empty());
        assert!(!ticket.claim.is_empty());
        state
            .access
            .resolve_claim(&ticket.claim, true)
            .expect("approve request");
        let grant = match state.access.poll(&ticket.claim) {
            access::PollOutcome::Allowed(credential) => credential,
            _ => panic!("an approved request must deliver its grant"),
        };
        state
            .access
            .snapshot()
            .save(&state.paths)
            .expect("save grants");

        let snapshot = http_get(port, "/api/snapshot", Some((access::GRANT_HEADER, &grant))).await;
        assert!(snapshot.starts_with("HTTP/1.1 200"), "{snapshot}");

        let profiles = http_get(
            port,
            "/api/access/list",
            Some((access::GRANT_HEADER, &grant)),
        )
        .await;
        assert!(profiles.starts_with("HTTP/1.1 200"), "{profiles}");

        // A different credential is refused.
        let wrong = http_get(
            port,
            "/api/snapshot",
            Some((access::GRANT_HEADER, "not-a-credential")),
        )
        .await;
        assert!(wrong.starts_with("HTTP/1.1 401"), "{wrong}");

        // Revoking the profile withdraws access immediately.
        let (revoke_id, _, _) = state.access.list()[0].clone();
        assert!(
            state.access.revoke(&revoke_id),
            "revocation must remove the grant"
        );
        let revoked = http_get(port, "/api/snapshot", Some((access::GRANT_HEADER, &grant))).await;
        assert!(revoked.starts_with("HTTP/1.1 401"), "{revoked}");
        let _ = shutdown_tx.send(());
    }

    #[tokio::test]
    async fn an_approval_claim_reaches_only_the_tab_that_opened_the_request() {
        // Approval is delivered through a private claim, so a forged or
        // replayed claim from another tab learns nothing.
        let mut state = test_state(0);
        let (port, shutdown_tx) = spawn_test_bridge(&mut state).await;

        let ticket = state
            .access
            .open_request("First tab")
            .expect("first request");
        // A second tab cannot open another prompt while one is pending.
        assert!(
            state.access.open_request("Second tab").is_err(),
            "only one native prompt may exist at a time"
        );

        let forged = http_post(
            port,
            "/api/access/poll",
            &serde_json::json!({ "claim": "forged" }).to_string(),
            None,
        )
        .await;
        assert!(forged.starts_with("HTTP/1.1 200"), "{forged}");
        assert!(
            forged.contains("\"state\":\"unauthorized\""),
            "a forged claim must never see the approval"
        );

        state
            .access
            .resolve_claim(&ticket.claim, true)
            .expect("approve");
        let delivered = http_post(
            port,
            "/api/access/poll",
            &serde_json::json!({ "claim": ticket.claim }).to_string(),
            None,
        )
        .await;
        assert!(delivered.contains("\"grant\":"), "{delivered}");

        // A dropped response can replay the settled approval briefly.
        let replayed = http_post(
            port,
            "/api/access/poll",
            &serde_json::json!({ "claim": ticket.claim }).to_string(),
            None,
        )
        .await;
        assert!(replayed.contains("\"grant\":"), "{replayed}");
        let _ = shutdown_tx.send(());
    }

    #[tokio::test]
    async fn a_request_naming_another_host_is_refused_before_access_logic() {
        // Strict Host checks keep foreign origins out even when they reach the
        // loopback listener.
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let mut state = test_state(0);
        let (port, shutdown_tx) = spawn_test_bridge(&mut state).await;
        let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .expect("connect to test bridge");
        stream
            .write_all(
                b"GET /api/access HTTP/1.1\r\nHost: 127.0.0.1:9999\r\nConnection: close\r\n\r\n",
            )
            .await
            .expect("write request");
        let mut response = Vec::new();
        stream
            .read_to_end(&mut response)
            .await
            .expect("read response");
        let text = String::from_utf8(response).expect("UTF-8 response");
        assert!(text.starts_with("HTTP/1.1 403"), "{text}");
        let _ = shutdown_tx.send(());
    }

    #[tokio::test]
    async fn a_declined_request_starts_a_cooldown_and_can_be_retried() {
        // A declared prompt must not be immediately repeatable, and once it has
        // been consumed the tab reads unauthorized again.
        let state = test_state(0);
        let ticket = state.access.open_request("Declined").expect("open request");
        assert_eq!(
            state.access.poll(&ticket.claim),
            access::PollOutcome::Waiting
        );
        state
            .access
            .resolve_claim(&ticket.claim, false)
            .expect("deny request");
        assert!(
            state.access.open_request("Declined again").is_err(),
            "a denial places the controller in a cooldown"
        );
        assert_eq!(
            state.access.poll(&ticket.claim),
            access::PollOutcome::Expired,
            "the denied request leaves nothing to poll"
        );
    }

    #[tokio::test]
    async fn cancelling_a_pending_request_on_shutdown() {
        // Service shutdown must cancel the pending prompt so the user is not
        // left with a stale popup after the bridge has stopped.
        let state = test_state(0);
        let ticket = state
            .access
            .open_request("Cancelled")
            .expect("open request");
        assert!(state.access.pending_identifier().is_some());
        state.access.cancel_claim(&ticket.claim);
        assert!(state.access.pending_identifier().is_none());
        assert_eq!(
            state.access.poll(&ticket.claim),
            access::PollOutcome::Expired
        );
    }

    #[tokio::test]
    async fn revoking_one_profile_leaves_the_others_authorized() {
        // Per-profile revocation must not disturb other browsers.
        let state = test_state(0);
        let first = state.access.open_request("One").expect("first");
        state
            .access
            .resolve_claim(&first.claim, true)
            .expect("approve first");
        let first_grant = match state.access.poll(&first.claim) {
            access::PollOutcome::Allowed(credential) => credential,
            _ => panic!("the first approval must deliver a grant"),
        };
        assert_eq!(
            state.access.state_for(&headers_with_grant(0, &first_grant)),
            access::AccessState::Authorized
        );

        let second = state.access.open_request("Two").expect("second");
        state
            .access
            .resolve_claim(&second.claim, true)
            .expect("approve second");
        let second_grant = match state.access.poll(&second.claim) {
            access::PollOutcome::Allowed(credential) => credential,
            _ => panic!("the second approval must deliver a grant"),
        };

        let (revoke_id, _, _) = state
            .access
            .list()
            .into_iter()
            .find(|(_, label, _)| label == "One")
            .expect("the first grant has its unique label");
        assert!(state.access.revoke(&revoke_id));
        assert_eq!(state.access.list().len(), 1, "one profile remains");
        let revoked = state.access.state_for(&headers_with_grant(0, &first_grant));
        assert_eq!(revoked, access::AccessState::Unauthorized);
        let survivor = state
            .access
            .state_for(&headers_with_grant(0, &second_grant));
        assert_eq!(survivor, access::AccessState::Authorized);
    }

    #[test]
    fn only_the_exact_loopback_page_origin_is_allowed() {
        // A credential must never travel to any other host or port.
        assert!(host_allowed("127.0.0.1:15921", 15921));
        assert!(!host_allowed("localhost:15921", 15921));
        assert!(!host_allowed("", 15921));
        assert!(!host_allowed("attacker.example", 15921));
        assert!(!host_allowed("127.0.0.1:15922", 15921));
        assert!(origin_allowed(Some("http://127.0.0.1:15921"), 15921));
        assert!(!origin_allowed(Some("http://localhost:15921"), 15921));
        assert!(!origin_allowed(None, 15921));
        assert!(!origin_allowed(Some("https://evil.example"), 15921));
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
        // The supervisor owns the bridge: the same process hosts the listener,
        // and stopping it releases the port without any helper process.

        let dir = tempfile::tempdir().expect("temporary state directory");
        let paths = control::paths_for(dir.path(), dir.path());
        let mut bridge =
            start_service_bridge_with(paths, Some(0)).expect("start in-process service bridge");
        let port = bridge.state.port;
        let connecting = TcpStream::connect_timeout(
            &std::net::SocketAddr::from(([127, 0, 0, 1], port)),
            Duration::from_millis(200),
        );
        assert!(
            connecting.is_ok(),
            "the supervisor process must own a live bridge listener"
        );
        drop(connecting);

        bridge.stop().expect("stop in-process service bridge");
        let refused = TcpStream::connect_timeout(
            &std::net::SocketAddr::from(([127, 0, 0, 1], port)),
            Duration::from_millis(200),
        );
        assert!(
            refused.is_err(),
            "stopping the bridge must release the loopback listener"
        );
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
    fn detached_bridge_waits_for_idle_grace_regardless_of_supervisor_pid_files() {
        let directory = tempfile::tempdir().expect("temporary state directory");
        let lock_path = directory.path().join("scriptd.lock");
        let now = Instant::now();

        // A running supervisor may have control_center disabled, and a stale
        // PID may be reused. Neither file state proves a replacement listener
        // has taken ownership, so an active dashboard keeps its bridge.
        std::fs::write(&lock_path, std::process::id().to_string()).expect("write live PID");
        assert!(!detached_shutdown_due(
            false,
            1,
            now - Duration::from_secs(900),
            now
        ));
        std::fs::write(&lock_path, "999999999").expect("write stale PID");
        assert!(!detached_shutdown_due(
            false,
            1,
            now - Duration::from_secs(900),
            now
        ));
        assert!(detached_shutdown_due(
            false,
            0,
            now - Duration::from_secs(600),
            now
        ));
        assert!(!detached_shutdown_due(
            true,
            0,
            now - Duration::from_secs(900),
            now
        ));
    }

    #[test]
    fn browser_opens_only_for_a_fully_interactive_bare_launch() {
        assert!(should_open_browser(0, true, true));
        assert!(!should_open_browser(0, false, true));
        assert!(!should_open_browser(0, true, false));
        assert!(!should_open_browser(2, true, true));
    }

    #[test]
    fn closing_one_of_multiple_tabs_does_not_start_the_idle_grace() {
        let dir = tempfile::tempdir().expect("temporary state directory");
        let grants = GrantsStore::load(&control::paths_for(dir.path(), dir.path()))
            .expect("empty grants store");
        let state = Arc::new(AppState {
            port: 43123,
            paths: control::paths_for(dir.path(), dir.path()),
            connections: AtomicUsize::new(2),
            last_disconnect: Mutex::new(Instant::now()),
            shutdown: Notify::new(),
            stopping: watch::channel(false).0,
            access: AccessController::new(grants),
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
