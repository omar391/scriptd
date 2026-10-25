#![cfg(target_os = "macos")]

use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use scriptd_bridge_protocol::{
    Capability, CapabilityReport, Operation, OperationReceipt, OperationRequest, OperationState,
    OperationStatusRequest, PairingReceipt, PairingRequest, PairingStatus, PROTOCOL_VERSION,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const BRIDGE_BINARY: &str = "/usr/local/libexec/scriptd-bridge";
const INSTALLATION_RECEIPT: &str = "/Library/Application Support/scriptd/bridge-installation.json";
const STATE_FILE: &str = "/Library/Application Support/scriptd/bridge-state.json";
const SOCKET_DIRECTORY: &str = "/var/run/scriptd";
const MAX_REQUEST_BYTES: usize = 64 * 1024;
const MAX_STATE_BYTES: usize = 16 * 1024 * 1024;
const MAX_RECEIPTS: usize = 4096;
const IO_TIMEOUT: Duration = Duration::from_secs(15);

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    v: u32,
    id: String,
    op: String,
    #[serde(default)]
    repo: String,
    #[serde(default)]
    module: Option<String>,
    #[serde(default)]
    yaml: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Response {
    v: u32,
    id: String,
    ok: bool,
    state: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    snapshot: Option<serde_json::Value>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Identity {
    team_identifier: String,
    bundle_identifier: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Pairing {
    team_identifier: String,
    bundle_identifier: String,
    active: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct OperationRecord {
    identity: Identity,
    request: OperationRequest,
    receipt: OperationReceipt,
}

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct State {
    schema: String,
    pairings: BTreeMap<String, Pairing>,
    #[serde(default)]
    pairing_authorizations: BTreeMap<String, Identity>,
    operations: BTreeMap<String, OperationRecord>,
}

impl State {
    fn load(path: &Path) -> Result<Self> {
        let state = match read_root_file(path) {
            Ok(bytes) => serde_json::from_slice(&bytes).context("parse protected bridge state")?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Self {
                schema: "scriptd-bridge-state/v1".to_string(),
                ..Self::default()
            },
            Err(error) => return Err(error).context("read protected bridge state"),
        };
        if state.schema != "scriptd-bridge-state/v1" {
            bail!("unsupported protected bridge state schema");
        }
        let mut state = state;
        state.mark_interrupted_unknown();
        Ok(state)
    }

    fn mark_interrupted_unknown(&mut self) {
        for record in self.operations.values_mut() {
            if matches!(
                record.receipt.state,
                OperationState::Accepted | OperationState::Running
            ) {
                record.receipt.state = OperationState::Unknown;
                record.receipt.message = Some(
                    "bridge restarted before recording the operation outcome; it was not replayed"
                        .to_string(),
                );
            }
        }
    }

    fn save(&self, path: &Path) -> Result<()> {
        let bytes = serde_json::to_vec(self)?;
        write_root_atomic(path, &bytes)
    }

    fn require_pairing(&self, identity: &Identity) -> Result<()> {
        let pairing = self
            .pairings
            .get(&identity.bundle_identifier)
            .context("this app is not paired with the bridge")?;
        if !pairing.active || pairing.team_identifier != identity.team_identifier {
            bail!("the active pairing does not match this app's signing identity");
        }
        Ok(())
    }

    fn pair(
        &mut self,
        identity: &Identity,
        request: PairingRequest,
        path: &Path,
    ) -> Result<PairingReceipt> {
        self.pair_with(identity, request, |state| state.save(path))
    }

    fn pair_with(
        &mut self,
        identity: &Identity,
        request: PairingRequest,
        mut persist: impl FnMut(&State) -> Result<()>,
    ) -> Result<PairingReceipt> {
        validate_identity(identity)?;
        if request.protocol_version != PROTOCOL_VERSION
            || request.bundle_identifier != identity.bundle_identifier
        {
            bail!("pairing request does not match the authenticated app or protocol");
        }
        if let Some(existing) = self.pairings.get(&identity.bundle_identifier) {
            if existing.active {
                if existing.team_identifier != identity.team_identifier {
                    bail!(
                        "replacing the paired signer requires revoking the existing pairing first"
                    );
                }
                return Ok(PairingReceipt {
                    signing_identity: identity.team_identifier.clone(),
                    bundle_identifier: identity.bundle_identifier.clone(),
                    protocol_version: PROTOCOL_VERSION,
                    active: true,
                });
            }
        }
        if self.pairing_authorizations.get(&identity.bundle_identifier) != Some(identity) {
            bail!("a protected administrator approval is required before pairing");
        }
        let pairing = Pairing {
            team_identifier: identity.team_identifier.clone(),
            bundle_identifier: identity.bundle_identifier.clone(),
            active: true,
        };
        let previous = self
            .pairings
            .insert(identity.bundle_identifier.clone(), pairing);
        self.pairing_authorizations
            .remove(&identity.bundle_identifier);
        if let Err(error) = persist(self) {
            if let Some(previous) = previous {
                self.pairings
                    .insert(identity.bundle_identifier.clone(), previous);
            } else {
                self.pairings.remove(&identity.bundle_identifier);
            }
            self.pairing_authorizations
                .insert(identity.bundle_identifier.clone(), identity.clone());
            return Err(error).context("persist pairing before acknowledging it");
        }
        Ok(PairingReceipt {
            signing_identity: identity.team_identifier.clone(),
            bundle_identifier: identity.bundle_identifier.clone(),
            protocol_version: PROTOCOL_VERSION,
            active: true,
        })
    }

    fn authorize_pairing(&mut self, identity: &Identity, path: &Path) -> Result<()> {
        self.authorize_pairing_with(identity, |state| state.save(path))
    }

    fn authorize_pairing_with(
        &mut self,
        identity: &Identity,
        mut persist: impl FnMut(&State) -> Result<()>,
    ) -> Result<()> {
        validate_identity(identity)?;
        if self
            .pairings
            .get(&identity.bundle_identifier)
            .is_some_and(|pairing| pairing.active)
        {
            bail!("revoke the active pairing before approving a different pairing");
        }
        let previous = self
            .pairing_authorizations
            .insert(identity.bundle_identifier.clone(), identity.clone());
        if let Err(error) = persist(self) {
            if let Some(previous) = previous {
                self.pairing_authorizations
                    .insert(identity.bundle_identifier.clone(), previous);
            } else {
                self.pairing_authorizations
                    .remove(&identity.bundle_identifier);
            }
            return Err(error).context("persist protected pairing approval");
        }
        Ok(())
    }

    fn submit(
        &mut self,
        identity: &Identity,
        request: OperationRequest,
        path: &Path,
    ) -> Result<OperationReceipt> {
        self.submit_with(identity, request, |state| state.save(path), execute)
    }

    fn submit_with(
        &mut self,
        identity: &Identity,
        request: OperationRequest,
        mut persist: impl FnMut(&State) -> Result<()>,
        execute_operation: impl FnOnce(&Operation) -> Result<()>,
    ) -> Result<OperationReceipt> {
        request
            .validate()
            .map_err(|error| anyhow::anyhow!("invalid bridge operation: {error}"))?;
        self.require_pairing(identity)?;
        let id = request.operation_id.as_str().to_string();
        if let Some(existing) = self.operations.get(&id) {
            if existing.identity != *identity || existing.request != request {
                bail!("operation ID is already bound to a different request or app");
            }
            return Ok(existing.receipt.clone());
        }
        if self.operations.len() >= MAX_RECEIPTS {
            bail!("bridge receipt storage is full; refusing new operations");
        }
        let mut record = OperationRecord {
            identity: identity.clone(),
            request: request.clone(),
            receipt: OperationReceipt {
                protocol_version: PROTOCOL_VERSION,
                operation_id: request.operation_id.clone(),
                state: OperationState::Accepted,
                message: None,
            },
        };
        self.operations.insert(id.clone(), record.clone());
        if let Err(error) = persist(self) {
            self.operations.remove(&id);
            return Err(error).context("persist operation acceptance before acknowledging");
        }

        record.receipt.state = OperationState::Running;
        self.operations.insert(id.clone(), record.clone());
        if let Err(error) = persist(self) {
            record.receipt.state = OperationState::Unknown;
            record.receipt.message = Some("operation was accepted but not started".into());
            self.operations.insert(id, record);
            return Err(error).context("persist running operation before execution");
        }

        match execute_operation(&request.operation) {
            Ok(()) => {
                record.receipt.state = OperationState::Succeeded;
                record.receipt.message = Some("operation completed".to_string());
            }
            Err(error) => {
                record.receipt.state = OperationState::Failed;
                record.receipt.message = Some(format!("operation failed: {error:#}"));
            }
        }
        self.operations.insert(id.clone(), record.clone());
        if let Err(error) = persist(self) {
            record.receipt.state = OperationState::Unknown;
            record.receipt.message = Some("operation ran but its result could not be saved".into());
            self.operations.insert(id, record);
            return Err(error).context("persist operation outcome");
        }
        Ok(record.receipt)
    }

    fn status(
        &self,
        identity: &Identity,
        request: OperationStatusRequest,
    ) -> Result<OperationReceipt> {
        request
            .validate()
            .map_err(|error| anyhow::anyhow!("invalid bridge status request: {error}"))?;
        match self.operations.get(request.operation_id.as_str()) {
            Some(record) if record.identity == *identity => Ok(record.receipt.clone()),
            Some(_) => bail!("operation receipt belongs to a different app"),
            None => Ok(OperationReceipt {
                protocol_version: PROTOCOL_VERSION,
                operation_id: request.operation_id,
                state: OperationState::Unknown,
                message: Some("no operation with this ID is recorded".to_string()),
            }),
        }
    }

    fn unpair(&mut self, identity: &Identity, path: &Path) -> Result<()> {
        self.unpair_with(identity, |state| state.save(path))
    }

    fn unpair_with(
        &mut self,
        identity: &Identity,
        mut persist: impl FnMut(&State) -> Result<()>,
    ) -> Result<()> {
        let pairing = self
            .pairings
            .get_mut(&identity.bundle_identifier)
            .context("no pairing exists for this app")?;
        if pairing.team_identifier != identity.team_identifier {
            bail!("only the paired signing identity may revoke this pairing");
        }
        pairing.active = false;
        persist(self)
    }
}

fn validate_identity(identity: &Identity) -> Result<()> {
    let valid_team = !identity.team_identifier.is_empty()
        && identity.team_identifier.len() <= 64
        && identity
            .team_identifier
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric());
    let valid_bundle = !identity.bundle_identifier.is_empty()
        && identity.bundle_identifier.len() <= 255
        && identity
            .bundle_identifier
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-'));
    if !valid_team || !valid_bundle {
        bail!("pairing identity is invalid");
    }
    Ok(())
}

fn respond(
    id: &str,
    ok: bool,
    state: &str,
    message: Option<String>,
    snapshot: Option<serde_json::Value>,
) -> Response {
    Response {
        v: PROTOCOL_VERSION,
        id: id.to_string(),
        ok,
        state: state.to_string(),
        message,
        snapshot,
    }
}

fn handle(
    request: Request,
    identity: Option<Identity>,
    admin_authorized: bool,
    state: &mut State,
    state_path: &Path,
) -> Response {
    if request.v != PROTOCOL_VERSION {
        return respond(
            &request.id,
            false,
            "rejected",
            Some("unsupported bridge protocol version".into()),
            None,
        );
    }
    match request.op.as_str() {
        "capabilities" => respond(
            &request.id,
            true,
            "completed",
            None,
            Some(
                serde_json::to_value(CapabilityReport {
                    protocol_version: PROTOCOL_VERSION,
                    capabilities: vec![Capability::WifiNetworkChange],
                })
                .unwrap_or(serde_json::Value::Null),
            ),
        ),
        "pair" => {
            let Some(identity) = identity.as_ref() else {
                return respond(
                    &request.id,
                    false,
                    "rejected",
                    Some("app signature is not verified".into()),
                    None,
                );
            };
            let Some(payload) = request.yaml.as_deref() else {
                return respond(
                    &request.id,
                    false,
                    "rejected",
                    Some("pairing request is incomplete".into()),
                    None,
                );
            };
            let pairing: PairingRequest = match serde_json::from_str(payload) {
                Ok(value) => value,
                Err(error) => {
                    return respond(
                        &request.id,
                        false,
                        "rejected",
                        Some(format!("invalid pairing request: {error}")),
                        None,
                    )
                }
            };
            match state.pair(identity, pairing, state_path) {
                Ok(receipt) => respond(
                    &request.id,
                    true,
                    "completed",
                    None,
                    Some(serde_json::to_value(receipt).unwrap_or(serde_json::Value::Null)),
                ),
                Err(error) => respond(
                    &request.id,
                    false,
                    "rejected",
                    Some(error.to_string()),
                    None,
                ),
            }
        }
        "authorize_pairing" => {
            if !admin_authorized {
                return respond(
                    &request.id,
                    false,
                    "rejected",
                    Some("pairing approval requires administrator authorization".into()),
                    None,
                );
            }
            let Some(payload) = request.yaml.as_deref() else {
                return respond(
                    &request.id,
                    false,
                    "rejected",
                    Some("pairing approval request is incomplete".into()),
                    None,
                );
            };
            let identity: Identity = match serde_json::from_str(payload) {
                Ok(value) => value,
                Err(error) => {
                    return respond(
                        &request.id,
                        false,
                        "rejected",
                        Some(format!("invalid pairing approval: {error}")),
                        None,
                    )
                }
            };
            match state.authorize_pairing(&identity, state_path) {
                Ok(()) => respond(
                    &request.id,
                    true,
                    "completed",
                    Some("one pairing approval recorded".into()),
                    None,
                ),
                Err(error) => respond(
                    &request.id,
                    false,
                    "rejected",
                    Some(error.to_string()),
                    None,
                ),
            }
        }
        "pairing_status" => {
            let Some(identity) = identity.as_ref() else {
                return respond(
                    &request.id,
                    false,
                    "rejected",
                    Some("app signature is not verified".into()),
                    None,
                );
            };
            if request.module.as_deref() != Some(identity.bundle_identifier.as_str()) {
                return respond(
                    &request.id,
                    false,
                    "rejected",
                    Some("pairing status is limited to the authenticated app".into()),
                    None,
                );
            }
            let active = state
                .pairings
                .get(&identity.bundle_identifier)
                .is_some_and(|pairing| {
                    pairing.active && pairing.team_identifier == identity.team_identifier
                });
            let status = PairingStatus {
                protocol_version: PROTOCOL_VERSION,
                bundle_identifier: identity.bundle_identifier.clone(),
                active,
            };
            respond(
                &request.id,
                true,
                "completed",
                None,
                Some(serde_json::to_value(status).unwrap_or(serde_json::Value::Null)),
            )
        }
        "unpair" => {
            let Some(identity) = identity.as_ref() else {
                return respond(
                    &request.id,
                    false,
                    "rejected",
                    Some("app signature is not verified".into()),
                    None,
                );
            };
            if request.module.as_deref() != Some(identity.bundle_identifier.as_str()) {
                return respond(
                    &request.id,
                    false,
                    "rejected",
                    Some("an app may revoke only its own pairing".into()),
                    None,
                );
            }
            match state.unpair(identity, state_path) {
                Ok(()) => respond(
                    &request.id,
                    true,
                    "completed",
                    Some("pairing revoked".into()),
                    None,
                ),
                Err(error) => respond(
                    &request.id,
                    false,
                    "rejected",
                    Some(error.to_string()),
                    None,
                ),
            }
        }
        "operation" => {
            let Some(identity) = identity.as_ref() else {
                return respond(
                    &request.id,
                    false,
                    "rejected",
                    Some("app signature is not verified".into()),
                    None,
                );
            };
            let Some(payload) = request.yaml.as_deref() else {
                return respond(
                    &request.id,
                    false,
                    "rejected",
                    Some("operation request is incomplete".into()),
                    None,
                );
            };
            let operation: OperationRequest = match serde_json::from_str(payload) {
                Ok(value) => value,
                Err(error) => {
                    return respond(
                        &request.id,
                        false,
                        "rejected",
                        Some(format!("invalid operation request: {error}")),
                        None,
                    )
                }
            };
            match state.submit(identity, operation, state_path) {
                Ok(receipt) => operation_response(&request.id, receipt),
                Err(error) => respond(
                    &request.id,
                    false,
                    "rejected",
                    Some(error.to_string()),
                    None,
                ),
            }
        }
        "operation_status" => {
            let Some(identity) = identity.as_ref() else {
                return respond(
                    &request.id,
                    false,
                    "rejected",
                    Some("app signature is not verified".into()),
                    None,
                );
            };
            let Some(payload) = request.yaml.as_deref() else {
                return respond(
                    &request.id,
                    false,
                    "rejected",
                    Some("operation status request is incomplete".into()),
                    None,
                );
            };
            let status: OperationStatusRequest = match serde_json::from_str(payload) {
                Ok(value) => value,
                Err(error) => {
                    return respond(
                        &request.id,
                        false,
                        "rejected",
                        Some(format!("invalid status request: {error}")),
                        None,
                    )
                }
            };
            match state.status(identity, status) {
                Ok(receipt) => operation_response(&request.id, receipt),
                Err(error) => respond(
                    &request.id,
                    false,
                    "rejected",
                    Some(error.to_string()),
                    None,
                ),
            }
        }
        _ => respond(
            &request.id,
            false,
            "rejected",
            Some("unsupported bridge operation".into()),
            None,
        ),
    }
}

fn operation_response(id: &str, receipt: OperationReceipt) -> Response {
    let state = match receipt.state {
        OperationState::Accepted => "accepted",
        OperationState::Running => "running",
        OperationState::Succeeded => "completed",
        OperationState::Failed => "failed",
        OperationState::Unavailable => "unavailable",
        OperationState::Unknown => "unknown",
    };
    respond(
        id,
        true,
        state,
        receipt.message.clone(),
        Some(serde_json::to_value(receipt).unwrap_or(serde_json::Value::Null)),
    )
}

fn execute(operation: &Operation) -> Result<()> {
    match operation {
        Operation::SetWifiNetwork { ssid } => {
            let ports = Command::new("/usr/sbin/networksetup")
                .arg("-listallhardwareports")
                .output()
                .context("read Wi-Fi hardware device")?;
            if !ports.status.success() {
                bail!("networksetup could not enumerate hardware ports");
            }
            let mut device = None;
            let mut in_wifi = false;
            for line in String::from_utf8_lossy(&ports.stdout).lines() {
                if let Some(value) = line.trim().strip_prefix("Hardware Port:") {
                    in_wifi = matches!(value.trim(), "Wi-Fi" | "AirPort");
                } else if in_wifi {
                    if let Some(value) = line.trim().strip_prefix("Device:") {
                        device = Some(value.trim().to_string());
                        break;
                    }
                }
            }
            let device = device.context("no Wi-Fi hardware device was found")?;
            if device.is_empty()
                || device.len() > 32
                || !device
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
            {
                bail!("Wi-Fi hardware device name is invalid");
            }
            let result = Command::new("/usr/sbin/networksetup")
                .args(["-setairportnetwork", device.as_str(), ssid])
                .output()
                .context("ask macOS to join the requested Wi-Fi network")?;
            if !result.status.success() {
                bail!("networksetup failed with status {}", result.status);
            }
            Ok(())
        }
    }
}

fn configure_accepted_stream(stream: &UnixStream) -> Result<()> {
    stream
        .set_nonblocking(false)
        .context("restore blocking mode on accepted bridge stream")?;
    stream
        .set_read_timeout(Some(IO_TIMEOUT))
        .context("set bridge client read timeout")?;
    stream
        .set_write_timeout(Some(IO_TIMEOUT))
        .context("set bridge client write timeout")?;
    Ok(())
}

fn serve() -> Result<()> {
    if unsafe { libc::geteuid() } != 0 {
        bail!("the bridge service must run as root");
    }
    verify_installation()?;
    let socket_directory = Path::new(SOCKET_DIRECTORY);
    fs::create_dir_all(socket_directory).context("create protected bridge socket directory")?;
    let directory_metadata = fs::symlink_metadata(socket_directory)?;
    if !directory_metadata.is_dir()
        || directory_metadata.uid() != 0
        || directory_metadata.mode() & 0o022 != 0
    {
        bail!("bridge socket directory must be protected and root-owned");
    }
    let state_path = PathBuf::from(STATE_FILE);
    let mut state = State::load(&state_path)?;
    let mut active = None;
    loop {
        let uid = match console_uid() {
            Ok(uid) => uid,
            Err(error) => {
                if let Some(previous) = active.take() {
                    remove_console_listener(previous)?;
                }
                eprintln!("console user is unavailable; bridge socket is closed: {error:#}");
                std::thread::sleep(Duration::from_millis(500));
                continue;
            }
        };
        if !matches!(active.as_ref(), Some(listener) if listener.uid == uid) {
            if let Err(error) =
                replace_console_listener(&mut active, socket_directory, uid, chown_socket)
            {
                eprintln!("could not bind bridge for console user {uid}: {error:#}");
                std::thread::sleep(Duration::from_millis(500));
                continue;
            }
        }
        let Some(listener) = active.as_ref() else {
            std::thread::sleep(Duration::from_millis(500));
            continue;
        };
        match listener.listener.accept() {
            Ok((mut stream, _)) => {
                if let Err(error) = configure_accepted_stream(&stream) {
                    eprintln!("could not configure accepted bridge stream: {error:#}");
                    continue;
                }
                let expected_uid = listener.uid;
                let response = match read_request(&stream, expected_uid) {
                    Ok((request, identity, admin_authorized))
                        if console_uid().ok() == Some(expected_uid) =>
                    {
                        handle(request, identity, admin_authorized, &mut state, &state_path)
                    }
                    Ok(_) => respond(
                        "unknown",
                        false,
                        "rejected",
                        Some("console user changed while the request was pending".to_string()),
                        None,
                    ),
                    Err(error) => {
                        respond("unknown", false, "rejected", Some(error.to_string()), None)
                    }
                };
                let _ = write_response(&mut stream, &response);
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(250));
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error).context("accept bridge client"),
        }
    }
}

fn read_request(
    stream: &UnixStream,
    expected_uid: u32,
) -> Result<(Request, Option<Identity>, bool)> {
    let uid = peer_uid(stream)?;
    let pid = peer_pid(stream)?;
    let mut stream = stream;
    let mut bytes = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        let read = stream.read(&mut byte)?;
        if read == 0 || byte[0] == b'\n' {
            break;
        }
        if bytes.len() >= MAX_REQUEST_BYTES {
            bail!("bridge request exceeds the size limit");
        }
        bytes.push(byte[0]);
    }
    let request: Request = serde_json::from_slice(&bytes).context("parse bridge request")?;
    if request.op == "authorize_pairing" {
        if uid != 0 {
            bail!("pairing approval requires a root-owned bridge client");
        }
        let client_identity = authenticate_peer(pid)?;
        let bridge_identity = authenticate_peer_identity_path(Path::new(BRIDGE_BINARY))?;
        if client_identity != bridge_identity {
            bail!("pairing approval must come from the installed bridge executable");
        }
        return Ok((request, None, true));
    }
    if uid != expected_uid {
        bail!("bridge peer user was not accepted");
    }
    let identity = if matches!(
        request.op.as_str(),
        "pair" | "pairing_status" | "unpair" | "operation" | "operation_status"
    ) {
        Some(authenticate_peer(pid)?)
    } else {
        None
    };
    Ok((request, identity, false))
}

fn peer_uid(stream: &UnixStream) -> Result<u32> {
    use std::os::fd::AsRawFd;
    let (mut uid, mut gid) = (0, 0);
    if unsafe { libc::getpeereid(stream.as_raw_fd(), &mut uid, &mut gid) } != 0 {
        return Err(std::io::Error::last_os_error()).context("read bridge peer user");
    }
    Ok(uid)
}

fn peer_pid(stream: &UnixStream) -> Result<u32> {
    use std::os::fd::AsRawFd;
    let mut pid: libc::pid_t = 0;
    let mut length = std::mem::size_of_val(&pid) as libc::socklen_t;
    if unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_LOCAL,
            libc::LOCAL_PEERPID,
            (&mut pid as *mut libc::pid_t).cast(),
            &mut length,
        )
    } != 0
        || pid <= 0
    {
        return Err(std::io::Error::last_os_error()).context("read bridge peer process");
    }
    Ok(pid as u32)
}

fn authenticate_peer(pid: u32) -> Result<Identity> {
    const PROC_PIDPATHINFO_MAXSIZE: u32 = 4096;
    extern "C" {
        fn proc_pidpath(
            pid: libc::c_int,
            buffer: *mut libc::c_void,
            buffersize: u32,
        ) -> libc::c_int;
        fn csops(
            pid: libc::pid_t,
            ops: libc::c_uint,
            data: *mut libc::c_void,
            size: usize,
        ) -> libc::c_int;
    }
    let mut path_bytes = vec![0_u8; PROC_PIDPATHINFO_MAXSIZE as usize];
    let length = unsafe {
        proc_pidpath(
            pid as libc::c_int,
            path_bytes.as_mut_ptr().cast(),
            PROC_PIDPATHINFO_MAXSIZE,
        )
    };
    if length <= 0 {
        return Err(std::io::Error::last_os_error()).context("resolve bridge peer executable");
    }
    path_bytes.truncate(length as usize);
    let executable = PathBuf::from(
        String::from_utf8(path_bytes).context("bridge peer executable path is not UTF-8")?,
    );
    let verify = Command::new("/usr/bin/codesign")
        .args(["--verify", "--strict", "--all-architectures", "--"])
        .arg(&executable)
        .output()
        .context("verify bridge peer code signature")?;
    if !verify.status.success() {
        bail!("bridge peer code signature is invalid");
    }
    let details = Command::new("/usr/bin/codesign")
        .args(["-dv", "--verbose=4", "--"])
        .arg(&executable)
        .output()
        .context("read bridge peer signing identity")?;
    if !details.status.success() {
        bail!("bridge peer signing identity is unavailable");
    }
    let details = String::from_utf8_lossy(&details.stderr);
    let mut identifier = None;
    let mut team = None;
    let mut signature = None;
    let mut cdhash = None;
    for line in details.lines() {
        if let Some(value) = line.strip_prefix("Identifier=") {
            identifier = Some(value.trim().to_string());
        }
        if let Some(value) = line.strip_prefix("TeamIdentifier=") {
            team = Some(value.trim().to_string());
        }
        if let Some(value) = line.strip_prefix("Signature=") {
            signature = Some(value.trim().to_string());
        }
        if let Some(value) = line.strip_prefix("CDHash=") {
            cdhash = Some(value.trim().to_ascii_lowercase());
        }
    }
    let team = team
        .filter(|value| !value.is_empty() && value != "not set")
        .context("bridge peer must have a distribution signer")?;
    if signature.as_deref() == Some("adhoc") {
        bail!("ad-hoc signed apps cannot pair with the bridge");
    }
    let cdhash = cdhash.context("bridge peer signature has no code-directory hash")?;
    let mut running_hash = [0_u8; 20];
    if unsafe {
        csops(
            pid as libc::pid_t,
            5,
            running_hash.as_mut_ptr().cast(),
            running_hash.len(),
        )
    } != 0
    {
        return Err(std::io::Error::last_os_error())
            .context("read bridge peer code-directory hash");
    }
    if hex::encode(running_hash) != cdhash {
        bail!("bridge peer executable changed during identity verification");
    }
    Ok(Identity {
        team_identifier: team,
        bundle_identifier: identifier.context("bridge peer has no bundle identifier")?,
    })
}

fn read_root_file(path: &Path) -> std::io::Result<Vec<u8>> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.uid() != 0 || metadata.mode() & 0o077 != 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "bridge state must be a protected root-owned file",
        ));
    }
    if metadata.len() > MAX_STATE_BYTES as u64 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "bridge state exceeds the maximum supported size",
        ));
    }
    let mut bytes = Vec::new();
    file.take(MAX_STATE_BYTES as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > MAX_STATE_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "bridge state exceeds the maximum supported size",
        ));
    }
    Ok(bytes)
}

fn write_root_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path.parent().context("bridge state has no parent")?;
    let metadata = fs::symlink_metadata(parent)?;
    if !metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
        bail!("bridge state directory must be protected and root-owned");
    }
    let temporary = path.with_extension(format!("{}.tmp", std::process::id()));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temporary)?;
    let result = (|| -> Result<()> {
        file.write_all(bytes)?;
        file.sync_all()?;
        fs::rename(&temporary, path)?;
        File::open(parent)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(temporary);
    }
    result
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct InstallationReceipt {
    schema: String,
    protocol_version: u32,
    binary_sha256: String,
    team_identifier: String,
    bundle_identifier: String,
}

fn digest(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

fn verify_installation() -> Result<()> {
    let receipt_bytes = read_root_file(Path::new(INSTALLATION_RECEIPT))
        .context("read bridge installation receipt")?;
    let receipt: InstallationReceipt = serde_json::from_slice(&receipt_bytes)?;
    let binary = Path::new(BRIDGE_BINARY);
    let binary_bytes = fs::read(binary)?;
    let identity = authenticate_peer_identity_path(binary)?;
    if receipt.schema != "scriptd-bridge-installation/v1"
        || receipt.protocol_version != PROTOCOL_VERSION
        || receipt.binary_sha256 != digest(&binary_bytes)
        || receipt.team_identifier != identity.team_identifier
        || receipt.bundle_identifier != identity.bundle_identifier
    {
        bail!("bridge installation receipt does not match the installed binary");
    }
    Ok(())
}

fn authenticate_peer_identity_path(executable: &Path) -> Result<Identity> {
    let verify = Command::new("/usr/bin/codesign")
        .args(["--verify", "--strict", "--all-architectures", "--"])
        .arg(executable)
        .output()?;
    if !verify.status.success() {
        bail!("installed bridge code signature is invalid");
    }
    let details = Command::new("/usr/bin/codesign")
        .args(["-dv", "--verbose=4", "--"])
        .arg(executable)
        .output()?;
    if !details.status.success() {
        bail!("installed bridge signing identity is unavailable");
    }
    let details = String::from_utf8_lossy(&details.stderr);
    let mut identifier = None;
    let mut team = None;
    for line in details.lines() {
        if let Some(value) = line.strip_prefix("Identifier=") {
            identifier = Some(value.trim().to_string());
        }
        if let Some(value) = line.strip_prefix("TeamIdentifier=") {
            team = Some(value.trim().to_string());
        }
    }
    Ok(Identity {
        team_identifier: team
            .filter(|value| value != "not set")
            .context("installed bridge has no distribution signer")?,
        bundle_identifier: identifier.context("installed bridge has no bundle identifier")?,
    })
}

fn write_installation_receipt() -> Result<()> {
    if unsafe { libc::geteuid() } != 0 {
        bail!("writing the bridge installation receipt requires administrator privileges");
    }
    let binary_path = Path::new(BRIDGE_BINARY);
    let metadata = fs::symlink_metadata(binary_path)?;
    if !metadata.is_file() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
        bail!("installed bridge executable must be protected and root-owned");
    }
    let parent = Path::new(INSTALLATION_RECEIPT)
        .parent()
        .context("bridge receipt directory missing")?;
    let parent_metadata = fs::symlink_metadata(parent)?;
    if !parent_metadata.is_dir()
        || parent_metadata.uid() != 0
        || parent_metadata.mode() & 0o022 != 0
    {
        bail!("bridge receipt directory must be protected and root-owned");
    }
    let identity = authenticate_peer_identity_path(binary_path)?;
    let receipt = InstallationReceipt {
        schema: "scriptd-bridge-installation/v1".to_string(),
        protocol_version: PROTOCOL_VERSION,
        binary_sha256: digest(&fs::read(binary_path)?),
        team_identifier: identity.team_identifier,
        bundle_identifier: identity.bundle_identifier,
    };
    write_root_atomic(
        Path::new(INSTALLATION_RECEIPT),
        &serde_json::to_vec(&receipt)?,
    )
}

fn console_uid() -> Result<u32> {
    let output = Command::new("/usr/bin/stat")
        .args(["-f", "%u", "/dev/console"])
        .output()?;
    if !output.status.success() {
        bail!("could not resolve the logged-in console user");
    }
    parse_console_uid(&String::from_utf8_lossy(&output.stdout))
}

fn parse_console_uid(value: &str) -> Result<u32> {
    value
        .trim()
        .parse()
        .context("console user ID is not a valid number")
}

struct ConsoleListener {
    uid: u32,
    path: PathBuf,
    listener: UnixListener,
}

fn socket_path(directory: &Path, uid: u32) -> PathBuf {
    directory.join(format!("scriptd-broker-{uid}.sock"))
}

fn chown_socket(path: &Path, uid: u32) -> Result<()> {
    let socket_c = std::ffi::CString::new(path.as_os_str().as_encoded_bytes())?;
    if unsafe { libc::chown(socket_c.as_ptr(), uid, !0 as libc::gid_t) } != 0 {
        return Err(std::io::Error::last_os_error())
            .context("assign bridge socket to console user");
    }
    Ok(())
}

fn bind_console_listener(
    directory: &Path,
    uid: u32,
    assign_owner: impl FnOnce(&Path, u32) -> Result<()>,
) -> Result<ConsoleListener> {
    let socket = socket_path(directory, uid);
    match fs::symlink_metadata(&socket) {
        Ok(metadata) => {
            if !metadata.file_type().is_socket() || (metadata.uid() != 0 && metadata.uid() != uid) {
                bail!("existing bridge socket path is not a protected socket");
            }
            if UnixStream::connect(&socket).is_ok() {
                bail!("bridge is already running");
            }
            fs::remove_file(&socket).context("remove stale bridge socket")?;
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error).context("inspect bridge socket path"),
    }
    let listener =
        UnixListener::bind(&socket).with_context(|| format!("bind {}", socket.display()))?;
    fs::set_permissions(&socket, fs::Permissions::from_mode(0o600))?;
    assign_owner(&socket, uid)?;
    listener.set_nonblocking(true)?;
    Ok(ConsoleListener {
        uid,
        path: socket,
        listener,
    })
}

fn remove_console_listener(listener: ConsoleListener) -> Result<()> {
    let ConsoleListener {
        uid,
        path,
        listener,
    } = listener;
    drop(listener);
    match fs::symlink_metadata(&path) {
        Ok(metadata)
            if metadata.file_type().is_socket()
                && (metadata.uid() == 0 || metadata.uid() == uid) =>
        {
            fs::remove_file(path).context("remove previous console-user bridge socket")
        }
        Ok(_) => bail!("bridge socket changed type or owner during user transition"),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).context("inspect previous console-user bridge socket"),
    }
}

fn replace_console_listener(
    active: &mut Option<ConsoleListener>,
    directory: &Path,
    uid: u32,
    assign_owner: impl Fn(&Path, u32) -> Result<()>,
) -> Result<()> {
    if active.as_ref().is_some_and(|listener| listener.uid == uid) {
        return Ok(());
    }
    if let Some(previous) = active.take() {
        remove_console_listener(previous)?;
    }
    *active = Some(bind_console_listener(directory, uid, assign_owner)?);
    Ok(())
}

fn write_response(stream: &mut UnixStream, response: &Response) -> Result<()> {
    let mut bytes = serde_json::to_vec(response)?;
    bytes.push(b'\n');
    stream.write_all(&bytes)?;
    Ok(())
}

fn main() -> Result<()> {
    let mut args = std::env::args();
    let _program = args.next();
    match args.next().as_deref() {
        Some("serve") => serve(),
        Some("write-installation-receipt") => write_installation_receipt(),
        Some("authorize-pairing") => {
            let team_identifier = args.next().context("missing team identifier")?;
            let bundle_identifier = args.next().context("missing bundle identifier")?;
            if args.next().is_some() {
                bail!("too many authorize-pairing arguments");
            }
            authorize_pairing_command(team_identifier, bundle_identifier)
        }
        _ => {
            eprintln!("usage: scriptd-bridge serve|write-installation-receipt|authorize-pairing <team-identifier> <bundle-identifier>");
            std::process::exit(2);
        }
    }
}

fn authorize_pairing_command(team_identifier: String, bundle_identifier: String) -> Result<()> {
    if unsafe { libc::geteuid() } != 0 {
        bail!("pairing approval requires administrator privileges");
    }
    let identity = Identity {
        team_identifier,
        bundle_identifier,
    };
    validate_identity(&identity)?;
    let uid = console_uid()?;
    let socket = socket_path(Path::new(SOCKET_DIRECTORY), uid);
    let mut stream = UnixStream::connect(&socket)
        .with_context(|| format!("connect to bridge at {}", socket.display()))?;
    stream.set_read_timeout(Some(IO_TIMEOUT))?;
    stream.set_write_timeout(Some(IO_TIMEOUT))?;
    let request = Request {
        v: PROTOCOL_VERSION,
        id: format!("authorize-{}", std::process::id()),
        op: "authorize_pairing".to_string(),
        repo: String::new(),
        module: None,
        yaml: Some(serde_json::to_string(&identity)?),
    };
    let mut bytes = serde_json::to_vec(&request)?;
    bytes.push(b'\n');
    stream.write_all(&bytes)?;
    let mut response_bytes = Vec::new();
    let mut byte = [0_u8; 1];
    loop {
        let count = stream.read(&mut byte)?;
        if count == 0 || byte[0] == b'\n' {
            break;
        }
        if response_bytes.len() >= MAX_REQUEST_BYTES {
            bail!("bridge approval response exceeds the size limit");
        }
        response_bytes.push(byte[0]);
    }
    let response: Response =
        serde_json::from_slice(&response_bytes).context("parse bridge approval response")?;
    if !response.ok || response.state != "completed" {
        bail!(
            "bridge rejected pairing approval: {}",
            response.message.unwrap_or_else(|| response.state.clone())
        );
    }
    println!(
        "{} for {} signed by {}",
        response
            .message
            .unwrap_or_else(|| "pairing approval recorded".to_string()),
        identity.bundle_identifier,
        identity.team_identifier,
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity() -> Identity {
        Identity {
            team_identifier: "TEAM123456".to_string(),
            bundle_identifier: "com.example.scriptd".to_string(),
        }
    }

    fn paired_state(active: bool) -> State {
        let identity = identity();
        State {
            schema: "scriptd-bridge-state/v1".to_string(),
            pairings: BTreeMap::from([(
                identity.bundle_identifier.clone(),
                Pairing {
                    team_identifier: identity.team_identifier,
                    bundle_identifier: identity.bundle_identifier,
                    active,
                },
            )]),
            ..State::default()
        }
    }

    fn operation_request(id: &str) -> OperationRequest {
        OperationRequest {
            protocol_version: PROTOCOL_VERSION,
            operation_id: scriptd_bridge_protocol::OperationId::new(id)
                .expect("valid operation ID"),
            operation: Operation::SetWifiNetwork {
                ssid: "Saved network".to_string(),
            },
        }
    }

    #[test]
    fn pairing_uses_authenticated_signer_and_refuses_silent_replacement() {
        let identity = identity();
        let mut state = State {
            schema: "scriptd-bridge-state/v1".to_string(),
            ..State::default()
        };
        let request = PairingRequest {
            bundle_identifier: identity.bundle_identifier.clone(),
            protocol_version: PROTOCOL_VERSION,
        };
        assert!(state
            .pair_with(&identity, request.clone(), |_| Ok(()))
            .is_err());
        state
            .authorize_pairing_with(&identity, |_| Ok(()))
            .expect("record protected administrator approval");
        let replacement = Identity {
            team_identifier: "OTHERTEAM".to_string(),
            bundle_identifier: identity.bundle_identifier.clone(),
        };
        assert!(state
            .pair_with(&replacement, request.clone(), |_| Ok(()))
            .is_err());
        let receipt = state
            .pair_with(&identity, request.clone(), |_| Ok(()))
            .expect("pair signed app");
        assert!(receipt.active);
        assert_eq!(receipt.signing_identity, identity.team_identifier);
        assert!(!state
            .pairing_authorizations
            .contains_key(&identity.bundle_identifier));
        assert!(state.pair_with(&replacement, request, |_| Ok(())).is_err());
        assert_eq!(
            state.pairings[&identity.bundle_identifier].team_identifier,
            identity.team_identifier
        );
    }

    #[test]
    fn revoked_pairing_requires_a_new_approval_before_reactivation() {
        let identity = identity();
        let request = PairingRequest {
            bundle_identifier: identity.bundle_identifier.clone(),
            protocol_version: PROTOCOL_VERSION,
        };
        let mut state = State::default();
        state
            .authorize_pairing_with(&identity, |_| Ok(()))
            .expect("approve initial pairing");
        state
            .pair_with(&identity, request.clone(), |_| Ok(()))
            .expect("activate approved pairing");
        state
            .unpair_with(&identity, |_| Ok(()))
            .expect("revoke pairing");

        assert!(state
            .pair_with(&identity, request.clone(), |_| Ok(()))
            .is_err());
        let unrelated = Identity {
            team_identifier: "OTHERTEAM".to_string(),
            bundle_identifier: identity.bundle_identifier.clone(),
        };
        assert!(state
            .pair_with(&unrelated, request.clone(), |_| Ok(()))
            .is_err());

        state
            .authorize_pairing_with(&identity, |_| Ok(()))
            .expect("renew approval after revocation");
        assert!(
            state
                .pair_with(&identity, request, |_| Ok(()))
                .expect("reactivate with renewed approval")
                .active
        );
    }

    #[test]
    fn older_persisted_state_defaults_to_no_pairing_approvals() {
        let state: State = serde_json::from_str(
            r#"{"schema":"scriptd-bridge-state/v1","pairings":{},"operations":{}}"#,
        )
        .expect("load state written before approval support");
        assert!(state.pairing_authorizations.is_empty());
    }

    #[test]
    fn pairing_approval_rejects_requests_without_root_authorization() {
        let identity = identity();
        let request = Request {
            v: PROTOCOL_VERSION,
            id: "approve".to_string(),
            op: "authorize_pairing".to_string(),
            repo: String::new(),
            module: None,
            yaml: Some(serde_json::to_string(&identity).expect("serialize identity")),
        };
        let rejected = handle(
            request,
            None,
            false,
            &mut State::default(),
            Path::new("unused"),
        );
        assert!(!rejected.ok);
    }

    #[test]
    fn console_listener_rebinds_when_the_active_user_changes() {
        let directory = tempfile::tempdir().expect("create isolated socket directory");
        let first_uid = unsafe { libc::geteuid() };
        let second_uid = if first_uid == 65_535 {
            65_534
        } else {
            first_uid + 1
        };
        let mut active = None;
        replace_console_listener(&mut active, directory.path(), first_uid, |_, _| Ok(()))
            .expect("bind initial console-user socket");
        let first_path = active.as_ref().expect("initial listener").path.clone();
        assert!(first_path.exists());

        replace_console_listener(&mut active, directory.path(), second_uid, |_, _| Ok(()))
            .expect("replace socket after user transition");
        let listener = active.as_ref().expect("replacement listener");
        assert_eq!(listener.uid, second_uid);
        assert!(!first_path.exists());
        assert!(listener.path.exists());
        let _client = UnixStream::connect(&listener.path).expect("connect to new user socket");
        let _accepted = listener
            .listener
            .accept()
            .expect("accept from new user socket");
    }

    #[test]
    fn accepted_console_stream_reads_delayed_fragmented_requests() {
        let directory = tempfile::tempdir().expect("create isolated socket directory");
        let expected_uid = unsafe { libc::geteuid() };
        let listener = bind_console_listener(directory.path(), expected_uid, |_, _| Ok(()))
            .expect("bind isolated console-user socket");
        let mut client = UnixStream::connect(&listener.path).expect("connect isolated client");
        let (accepted, _) = listener.listener.accept().expect("accept isolated client");
        configure_accepted_stream(&accepted).expect("configure accepted client stream");

        let request = format!(
            r#"{{"v":{},"id":"delayed-fragmented","op":"capabilities"}}"#,
            PROTOCOL_VERSION
        );
        let split = request.len() / 2;
        let first = request[..split].to_string();
        let second = format!("{}\n", &request[split..]);
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let writer = std::thread::spawn(move || -> std::io::Result<()> {
            ready_tx.send(()).expect("signal delayed writer startup");
            std::thread::sleep(Duration::from_millis(75));
            client.write_all(first.as_bytes())?;
            std::thread::sleep(Duration::from_millis(75));
            client.write_all(second.as_bytes())?;
            Ok(())
        });
        ready_rx.recv().expect("wait for delayed writer startup");

        let received = read_request(&accepted, expected_uid);
        writer
            .join()
            .expect("request writer thread should not panic")
            .expect("write request fragments");
        let (request, _, _) = received.expect("read delayed fragmented request");
        assert_eq!(request.id, "delayed-fragmented");
    }

    #[test]
    fn startup_without_a_logged_in_user_binds_the_root_socket() {
        let directory = tempfile::tempdir().expect("create isolated socket directory");
        assert_eq!(
            parse_console_uid("0\n").expect("parse pre-login console UID"),
            0
        );
        let listener = bind_console_listener(directory.path(), 0, |_, _| Ok(()))
            .expect("bind root-only endpoint before login");
        assert_eq!(listener.uid, 0);
        assert_eq!(listener.path, socket_path(directory.path(), 0));
        assert_eq!(
            fs::metadata(&listener.path)
                .expect("read isolated socket permissions")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        drop(listener.listener);
        fs::remove_file(listener.path).expect("remove isolated pre-login socket");
    }

    #[test]
    fn revocation_is_durable_before_new_work_is_rejected() {
        let identity = identity();
        let mut state = paired_state(true);
        state
            .unpair_with(&identity, |_| Ok(()))
            .expect("revoke pairing");
        assert!(state.require_pairing(&identity).is_err());
        assert!(!state.pairings[&identity.bundle_identifier].active);
    }

    #[test]
    fn capabilities_expose_only_the_typed_wifi_operation() {
        let response = handle(
            Request {
                v: PROTOCOL_VERSION,
                id: "capabilities".to_string(),
                op: "capabilities".to_string(),
                repo: String::new(),
                module: None,
                yaml: None,
            },
            None,
            false,
            &mut State::default(),
            Path::new("unused"),
        );
        assert!(response.ok);
        let report: CapabilityReport =
            serde_json::from_value(response.snapshot.unwrap()).expect("decode capability report");
        assert_eq!(report.capabilities, vec![Capability::WifiNetworkChange]);
    }

    #[test]
    fn duplicate_operation_ids_never_execute_the_privileged_action_twice() {
        let identity = identity();
        let request = operation_request("wifi-once");
        let mut state = paired_state(true);
        let executions = std::cell::Cell::new(0);
        let persist = |_: &State| Ok(());
        let first = state
            .submit_with(&identity, request.clone(), persist, |_| {
                executions.set(executions.get() + 1);
                Ok(())
            })
            .expect("first operation");
        let second = state
            .submit_with(
                &identity,
                request,
                |_: &State| Ok(()),
                |_| {
                    executions.set(executions.get() + 1);
                    Ok(())
                },
            )
            .expect("same operation ID returns its existing receipt");
        assert_eq!(executions.get(), 1);
        assert_eq!(first, second);
        assert_eq!(first.state, OperationState::Succeeded);
    }

    #[test]
    fn revocation_blocks_new_operations_but_keeps_old_receipts_readable() {
        let identity = identity();
        let request = operation_request("wifi-accepted");
        let mut state = paired_state(false);
        let receipt = OperationReceipt {
            protocol_version: PROTOCOL_VERSION,
            operation_id: request.operation_id.clone(),
            state: OperationState::Unknown,
            message: Some("reconcile only".to_string()),
        };
        state.operations.insert(
            request.operation_id.as_str().to_string(),
            OperationRecord {
                identity: identity.clone(),
                request: request.clone(),
                receipt: receipt.clone(),
            },
        );
        assert!(state
            .submit_with(
                &identity,
                operation_request("wifi-new"),
                |_: &State| Ok(()),
                |_| Ok(())
            )
            .is_err());
        let reconciled = state
            .status(
                &identity,
                OperationStatusRequest {
                    protocol_version: PROTOCOL_VERSION,
                    operation_id: request.operation_id,
                },
            )
            .expect("existing operation remains readable");
        assert_eq!(reconciled, receipt);
    }

    #[test]
    fn restart_marks_in_flight_receipts_unknown_without_replay() {
        let identity = identity();
        let request = operation_request("wifi-interrupted");
        let mut state = paired_state(true);
        state.operations.insert(
            request.operation_id.as_str().to_string(),
            OperationRecord {
                identity: identity.clone(),
                request: request.clone(),
                receipt: OperationReceipt {
                    protocol_version: PROTOCOL_VERSION,
                    operation_id: request.operation_id.clone(),
                    state: OperationState::Running,
                    message: None,
                },
            },
        );
        state.mark_interrupted_unknown();
        let receipt = state
            .status(
                &identity,
                OperationStatusRequest {
                    protocol_version: PROTOCOL_VERSION,
                    operation_id: request.operation_id,
                },
            )
            .expect("unknown operation remains reconcilable");
        assert_eq!(receipt.state, OperationState::Unknown);
        assert!(receipt.message.unwrap().contains("not replayed"));
    }

    #[test]
    fn protocol_version_mismatch_is_rejected_before_dispatch() {
        let response = handle(
            Request {
                v: PROTOCOL_VERSION - 1,
                id: "old-client".to_string(),
                op: "capabilities".to_string(),
                repo: String::new(),
                module: None,
                yaml: None,
            },
            None,
            false,
            &mut State::default(),
            Path::new("unused"),
        );
        assert!(!response.ok);
        assert!(response.message.unwrap().contains("unsupported"));
    }
}
