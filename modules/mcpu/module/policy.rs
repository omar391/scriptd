use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use super::process::{Candidate, ProcessIdentity, UiHelperIdentity};

const POLICY_VERSION: u32 = 1;
const MAX_POLICY_BYTES: u64 = 4 * 1024 * 1024;
pub(super) const DEFAULT_TIMER_MINUTES: u64 = 30;
pub(super) const MAX_TIMER_MINUTES: u64 = 525_600;
pub(super) const MAX_PENDING_REQUESTS: usize = 64;

#[cfg(target_os = "macos")]
const EMBEDDED_UI_EXECUTABLE: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/McpuEnrollment"));

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Approval {
    pub canonical_path: String,
    pub fingerprint: String,
    pub timer_minutes: u64,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PendingRequest {
    pub request_id: String,
    pub identity: ProcessIdentity,
    pub name: String,
    pub cpu_percent: f32,
    pub memory_bytes: u64,
    pub reason: String,
    pub observed_at: String,
    pub default_timer_minutes: u64,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "lowercase")]
pub(super) enum Decision {
    Add,
    Exclude,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct DecisionResponse {
    pub request_id: String,
    pub canonical_path: String,
    pub fingerprint: String,
    pub decision: Decision,
    pub timer_minutes: Option<u64>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct UiAcknowledgement {
    pub request_id: String,
    pub canonical_path: String,
    pub fingerprint: String,
    pub decision: Option<Decision>,
    pub timer_minutes: Option<u64>,
    pub accepted: bool,
    pub message: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct UiHeartbeat {
    pub request_id: String,
    pub pid: u32,
    pub unix_millis: i64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct UiOwner {
    pub request_id: String,
    pub identity: UiHelperIdentity,
    pub last_heartbeat_unix_millis: i64,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PolicyFile {
    pub schema_version: u32,
    pub approvals: BTreeMap<String, Approval>,
    pub exclusions: BTreeSet<String>,
    pub pending: BTreeMap<String, PendingRequest>,
    #[serde(default)]
    pub completed: BTreeMap<String, DecisionResponse>,
}

impl Default for PolicyFile {
    fn default() -> Self {
        Self {
            schema_version: POLICY_VERSION,
            approvals: BTreeMap::new(),
            exclusions: BTreeSet::new(),
            pending: BTreeMap::new(),
            completed: BTreeMap::new(),
        }
    }
}

impl PolicyFile {
    pub fn validate(&self) -> Result<()> {
        if self.schema_version != POLICY_VERSION {
            anyhow::bail!("unsupported mcpu policy version {}", self.schema_version);
        }
        for (path, approval) in &self.approvals {
            if path != &approval.canonical_path
                || !Path::new(path).is_absolute()
                || approval.fingerprint.len() != 64
                || !approval
                    .fingerprint
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit())
                || approval.timer_minutes == 0
                || approval.timer_minutes > MAX_TIMER_MINUTES
                || approval.timer_minutes.checked_mul(60).is_none()
            {
                anyhow::bail!("mcpu policy contains an invalid approval");
            }
        }
        if self
            .exclusions
            .iter()
            .any(|path| !Path::new(path).is_absolute())
        {
            anyhow::bail!("mcpu policy contains an invalid exclusion");
        }
        if self.pending.len() > MAX_PENDING_REQUESTS || self.completed.len() > MAX_PENDING_REQUESTS
        {
            anyhow::bail!("mcpu policy exceeds its enrollment queue limit");
        }
        for (request_id, request) in &self.pending {
            if request_id != &request.request_id
                || self.completed.contains_key(request_id)
                || !is_request_id(request_id)
                || request.identity.pid <= 1
                || request.identity.pid_version == 0
                || request.identity.start_seconds == 0
                || request.identity.start_microseconds >= 1_000_000
                || !Path::new(&request.identity.executable).is_absolute()
                || !is_fingerprint(&request.identity.fingerprint)
                || request.identity.code_directory_hash.len() != 40
                || !request
                    .identity
                    .code_directory_hash
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit())
                || !request.cpu_percent.is_finite()
                || request.cpu_percent <= 50.0
                || request.default_timer_minutes != DEFAULT_TIMER_MINUTES
                || request.name.trim().is_empty()
                || request.reason.trim().is_empty()
            {
                anyhow::bail!("mcpu policy contains an invalid pending request");
            }
        }
        for (request_id, response) in &self.completed {
            let durable_decision_exists = match response.decision {
                Decision::Add => {
                    self.exclusions.contains(&response.canonical_path)
                        || self
                            .approvals
                            .get(&response.canonical_path)
                            .is_some_and(|approval| {
                                approval.fingerprint == response.fingerprint
                                    && Some(approval.timer_minutes) == response.timer_minutes
                            })
                }
                Decision::Exclude => self.exclusions.contains(&response.canonical_path),
            };
            if request_id != &response.request_id
                || !is_request_id(request_id)
                || !Path::new(&response.canonical_path).is_absolute()
                || !is_fingerprint(&response.fingerprint)
                || response.timer_minutes.is_some_and(|minutes| {
                    minutes == 0 || minutes > MAX_TIMER_MINUTES || minutes.checked_mul(60).is_none()
                })
                || (response.decision == Decision::Add && response.timer_minutes.is_none())
                || (response.decision == Decision::Exclude && response.timer_minutes.is_some())
                || !durable_decision_exists
            {
                anyhow::bail!("mcpu policy contains an invalid completion receipt");
            }
        }
        Ok(())
    }

    pub fn is_excluded(&self, canonical_path: &str) -> bool {
        self.exclusions.contains(canonical_path)
    }

    pub fn approval_for(&self, identity: &ProcessIdentity) -> Option<&Approval> {
        if self.is_excluded(&identity.executable) {
            return None;
        }
        self.approvals
            .get(&identity.executable)
            .filter(|approval| approval.fingerprint == identity.fingerprint)
    }

    pub fn has_pending(&self, identity: &ProcessIdentity) -> bool {
        self.pending.values().any(|pending| {
            pending.identity.executable == identity.executable
                && pending.identity.fingerprint == identity.fingerprint
        })
    }

    pub fn content_digest(&self) -> Result<String> {
        let bytes = serde_json::to_vec(self)?;
        let mut hasher = Sha256::new();
        hasher.update(bytes);
        Ok(format!("{:x}", hasher.finalize()))
    }
}

pub(super) struct PolicyStore {
    root: PathBuf,
}

impl PolicyStore {
    pub fn new(root: PathBuf) -> Self {
        Self { root }
    }

    pub fn system_default() -> Self {
        Self::new(crate::paths::resolve_state_dir().join("mcpu"))
    }

    pub fn lock(&self) -> Result<PolicyLock<'_>> {
        ensure_private_directory(&self.root)?;
        let path = self.root.join("policy.lock");
        let file = open_private_lock_file(&path)?;
        lock_file(&file, true).context("lock mcpu policy without blocking the supervisor")?;
        Ok(PolicyLock { store: self, file })
    }

    pub fn request_path(&self, request_id: &str) -> PathBuf {
        self.root
            .join("requests")
            .join(format!("{request_id}.json"))
    }

    pub fn response_path(&self, request_id: &str) -> PathBuf {
        self.root
            .join("responses")
            .join(format!("{request_id}.json"))
    }

    pub fn prepare_response_directory(&self) -> Result<()> {
        ensure_private_directory(&self.root.join("responses"))
    }

    pub fn ui_lock_path(&self) -> PathBuf {
        self.root.join("ui.lock")
    }

    pub fn ui_heartbeat_path(&self) -> PathBuf {
        self.root.join("ui-heartbeat.json")
    }

    fn ui_owner_path(&self) -> PathBuf {
        self.root.join("ui-owner.json")
    }

    pub fn acknowledgement_path(&self, request_id: &str) -> PathBuf {
        self.root
            .join("acknowledgements")
            .join(format!("{request_id}.json"))
    }

    pub fn ui_executable_path(&self) -> PathBuf {
        self.root
            .join("CPU Tool Enrollment.app/Contents/MacOS/McpuEnrollment")
    }

    pub fn prepare_ui_executable(&self) -> Result<PathBuf> {
        #[cfg(target_os = "macos")]
        {
            self.prepare_macos_ui_executable()
        }
        #[cfg(not(target_os = "macos"))]
        {
            anyhow::bail!("the native enrollment UI is supported only on macOS")
        }
    }

    #[cfg(target_os = "macos")]
    fn prepare_macos_ui_executable(&self) -> Result<PathBuf> {
        use std::os::unix::fs::PermissionsExt;

        const APP_INFO: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleExecutable</key><string>McpuEnrollment</string>
<key>CFBundleIdentifier</key><string>com.scriptd.cpu-tool-enrollment</string>
<key>CFBundleName</key><string>CPU Tool Enrollment</string>
<key>CFBundlePackageType</key><string>APPL</string>
<key>CFBundleVersion</key><string>1</string>
<key>NSPrincipalClass</key><string>NSApplication</string>
<key>NSHighResolutionCapable</key><true/>
</dict></plist>
"#;

        ensure_private_directory(&self.root)?;
        let source_digest = digest_hex(EMBEDDED_UI_EXECUTABLE);
        let executable = self.ui_executable_path();
        let app = executable
            .ancestors()
            .nth(3)
            .context("native enrollment app path is invalid")?
            .to_path_buf();
        let digest_path = self.root.join("ui-source.sha256");
        if ensure_private_file(&digest_path).is_ok()
            && fs::read_to_string(&digest_path).ok().as_deref() == Some(source_digest.as_str())
            && private_ui_executable_is_valid(&app, &executable)
        {
            return Ok(executable);
        }

        let temporary = self.root.join(format!(
            ".ui-build-{}-{}",
            std::process::id(),
            &source_digest[..12]
        ));
        if temporary.exists() {
            fs::remove_dir_all(&temporary).context("remove incomplete native UI build")?;
        }
        ensure_private_directory(&temporary)?;
        let contents = temporary.join("Contents");
        let macos = contents.join("MacOS");
        ensure_private_directory(&contents)?;
        ensure_private_directory(&macos)?;
        let temporary_executable = macos.join("McpuEnrollment");
        fs::write(&temporary_executable, EMBEDDED_UI_EXECUTABLE)
            .context("install embedded native enrollment executable")?;
        fs::set_permissions(&temporary_executable, fs::Permissions::from_mode(0o500))
            .context("restrict native enrollment executable permissions")?;
        let info_path = contents.join("Info.plist");
        crate::paths::write_private_atomic(&info_path, APP_INFO.as_bytes())
            .context("write native enrollment app metadata")?;
        sync_directory(&macos)?;
        sync_directory(&contents)?;
        sync_directory(&temporary)?;

        let backup = self.root.join(format!(".ui-backup-{}", std::process::id()));
        if backup.exists() {
            fs::remove_dir_all(&backup).context("remove previous native UI backup")?;
        }
        if app.exists() {
            fs::rename(&app, &backup).context("move previous native enrollment app")?;
        }
        if let Err(error) = fs::rename(&temporary, &app) {
            if backup.exists() && !app.exists() {
                let _ = fs::rename(&backup, &app);
            }
            let _ = fs::remove_dir_all(&temporary);
            return Err(error).context("install native enrollment app");
        }
        if backup.exists() {
            fs::remove_dir_all(&backup).context("remove previous native enrollment app")?;
        }
        crate::paths::write_private_atomic(&digest_path, source_digest.as_bytes())
            .context("persist native enrollment source fingerprint")?;
        if !private_ui_executable_is_valid(&app, &executable) {
            anyhow::bail!("installed native enrollment executable failed its safety check");
        }
        sync_directory(&self.root)?;
        Ok(executable)
    }

    pub fn ensure_request(&self, request: &PendingRequest) -> Result<PathBuf> {
        ensure_private_directory(&self.root.join("requests"))?;
        let path = self.request_path(&request.request_id);
        let bytes = serde_json::to_vec(request)?;
        crate::paths::write_private_atomic(&path, &bytes)
            .with_context(|| format!("persist mcpu prompt {}", request.request_id))?;
        let saved: PendingRequest = read_json_bounded::<PendingRequest>(&path)?;
        if saved != *request {
            anyhow::bail!("mcpu prompt read-back did not match");
        }
        Ok(path)
    }

    pub fn read_response(&self, request_id: &str) -> Result<Option<DecisionResponse>> {
        ensure_private_directory(&self.root.join("responses"))?;
        let path = self.response_path(request_id);
        match read_json_bounded::<DecisionResponse>(&path) {
            Ok(response) => Ok(Some(response)),
            Err(error)
                if error
                    .downcast_ref::<std::io::Error>()
                    .is_some_and(|io| io.kind() == ErrorKind::NotFound) =>
            {
                Ok(None)
            }
            Err(error) => Err(error).with_context(|| format!("read mcpu UI response {request_id}")),
        }
    }

    pub fn read_ui_heartbeat(&self) -> Result<Option<UiHeartbeat>> {
        match read_optional_json::<UiHeartbeat>(&self.ui_heartbeat_path())? {
            Some(heartbeat)
                if is_request_id(&heartbeat.request_id)
                    && heartbeat.pid > 1
                    && heartbeat.unix_millis > 0 =>
            {
                Ok(Some(heartbeat))
            }
            Some(_) => anyhow::bail!("mcpu UI heartbeat is invalid"),
            None => Ok(None),
        }
    }

    pub fn read_ui_owner(&self) -> Result<Option<UiOwner>> {
        match read_optional_json::<UiOwner>(&self.ui_owner_path())? {
            Some(owner)
                if is_request_id(&owner.request_id)
                    && owner.identity.pid > 1
                    && owner.identity.pid_version > 0
                    && owner.identity.start_seconds > 0
                    && owner.identity.start_microseconds < 1_000_000
                    && owner.identity.user_id == unsafe { libc::getuid() } as u32
                    && Path::new(&owner.identity.executable).is_absolute()
                    && owner.last_heartbeat_unix_millis > 0 =>
            {
                Ok(Some(owner))
            }
            Some(_) => anyhow::bail!("mcpu UI owner record is invalid"),
            None => Ok(None),
        }
    }

    pub fn save_ui_owner(&self, owner: &UiOwner) -> Result<()> {
        let path = self.ui_owner_path();
        let bytes = serde_json::to_vec(owner)?;
        crate::paths::write_private_atomic(&path, &bytes)
            .context("persist mcpu UI owner identity")?;
        let saved: UiOwner = read_json_bounded(&path)?;
        if saved != *owner {
            anyhow::bail!("mcpu UI owner read-back did not match");
        }
        Ok(())
    }

    pub fn clear_ui_health(&self) -> Result<()> {
        for path in [self.ui_heartbeat_path(), self.ui_owner_path()] {
            match fs::remove_file(&path) {
                Ok(()) => {}
                Err(error) if error.kind() == ErrorKind::NotFound => {}
                Err(error) => {
                    return Err(error).with_context(|| format!("remove {}", path.display()));
                }
            }
        }
        Ok(())
    }

    pub fn write_acknowledgement(&self, response: &DecisionResponse) -> Result<()> {
        self.write_ui_acknowledgement(&UiAcknowledgement {
            request_id: response.request_id.clone(),
            canonical_path: response.canonical_path.clone(),
            fingerprint: response.fingerprint.clone(),
            decision: Some(response.decision),
            timer_minutes: response.timer_minutes,
            accepted: true,
            message: None,
        })
    }

    pub fn write_rejection_acknowledgement(
        &self,
        request: &PendingRequest,
        message: &str,
    ) -> Result<()> {
        self.write_ui_acknowledgement(&UiAcknowledgement {
            request_id: request.request_id.clone(),
            canonical_path: request.identity.executable.clone(),
            fingerprint: request.identity.fingerprint.clone(),
            decision: None,
            timer_minutes: None,
            accepted: false,
            message: Some(message.to_string()),
        })
    }

    fn write_ui_acknowledgement(&self, acknowledgement: &UiAcknowledgement) -> Result<()> {
        let accepted_choice_is_valid = match acknowledgement.decision {
            Some(Decision::Add) => acknowledgement.timer_minutes.is_some_and(|minutes| {
                minutes > 0 && minutes <= MAX_TIMER_MINUTES && minutes.checked_mul(60).is_some()
            }),
            Some(Decision::Exclude) => acknowledgement.timer_minutes.is_none(),
            None => false,
        };
        if !is_request_id(&acknowledgement.request_id)
            || !Path::new(&acknowledgement.canonical_path).is_absolute()
            || !is_fingerprint(&acknowledgement.fingerprint)
            || (acknowledgement.accepted
                && (!accepted_choice_is_valid || acknowledgement.message.is_some()))
            || (!acknowledgement.accepted
                && (acknowledgement.decision.is_some()
                    || acknowledgement.timer_minutes.is_some()
                    || acknowledgement.message.as_deref().is_none_or(str::is_empty)))
        {
            anyhow::bail!("mcpu UI acknowledgement is invalid");
        }
        ensure_private_directory(&self.root.join("acknowledgements"))?;
        let path = self.acknowledgement_path(&acknowledgement.request_id);
        let bytes = serde_json::to_vec(acknowledgement)?;
        crate::paths::write_private_atomic(&path, &bytes)
            .context("persist mcpu UI choice acknowledgement")?;
        let saved: UiAcknowledgement = read_json_bounded(&path)?;
        if saved != *acknowledgement {
            anyhow::bail!("mcpu UI acknowledgement read-back did not match");
        }
        Ok(())
    }

    pub fn remove_acknowledgement(&self, request_id: &str) -> Result<()> {
        let path = self.acknowledgement_path(request_id);
        match fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == ErrorKind::NotFound => Ok(()),
            Err(error) => {
                Err(error).with_context(|| format!("remove mcpu acknowledgement {request_id}"))
            }
        }
    }

    pub fn remove_response(&self, request_id: &str) -> Result<()> {
        let path = self.response_path(request_id);
        match fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == ErrorKind::NotFound => Ok(()),
            Err(error) => {
                Err(error).with_context(|| format!("remove mcpu UI response {request_id}"))
            }
        }
    }

    pub fn remove_request(&self, request_id: &str) {
        let _ = fs::remove_file(self.request_path(request_id));
    }
}

#[cfg(target_os = "macos")]
fn digest_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

#[cfg(target_os = "macos")]
fn private_ui_executable_is_valid(app: &Path, executable: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;

    let expected_uid = unsafe { libc::getuid() };
    let Ok(canonical) = executable.canonicalize() else {
        return false;
    };
    let Some(canonical_app) = canonical.ancestors().nth(3) else {
        return false;
    };
    if app.canonicalize().ok().as_deref() != Some(canonical_app) {
        return false;
    }
    let valid_directory = |path: &Path| {
        fs::symlink_metadata(path).is_ok_and(|metadata| {
            metadata.is_dir()
                && !metadata.file_type().is_symlink()
                && metadata.uid() == expected_uid
                && metadata.mode() & 0o077 == 0
        })
    };
    let contents = canonical_app.join("Contents");
    let macos = contents.join("MacOS");
    let valid_executable = fs::symlink_metadata(&canonical).is_ok_and(|metadata| {
        metadata.is_file()
            && !metadata.file_type().is_symlink()
            && metadata.uid() == expected_uid
            && metadata.mode() & 0o077 == 0
            && metadata.mode() & 0o100 != 0
    });
    valid_directory(canonical_app)
        && valid_directory(&contents)
        && valid_directory(&macos)
        && valid_executable
}

#[cfg(not(target_os = "macos"))]
fn private_ui_executable_is_valid(_app: &Path, _executable: &Path) -> bool {
    false
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> Result<()> {
    use std::os::fd::AsRawFd;

    let directory =
        File::open(path).with_context(|| format!("open directory {}", path.display()))?;
    if unsafe { libc::fsync(directory.as_raw_fd()) } != 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("sync directory {}", path.display()));
    }
    Ok(())
}

#[cfg(not(unix))]
fn sync_directory(_path: &Path) -> Result<()> {
    Ok(())
}

pub(super) struct PolicyLock<'a> {
    store: &'a PolicyStore,
    file: File,
}

impl PolicyLock<'_> {
    pub fn load(&self) -> Result<PolicyFile> {
        let path = self.store.root.join("policy.json");
        match read_json_bounded::<PolicyFile>(&path) {
            Ok(policy) => {
                policy.validate()?;
                Ok(policy)
            }
            Err(error)
                if error
                    .downcast_ref::<std::io::Error>()
                    .is_some_and(|io| io.kind() == ErrorKind::NotFound) =>
            {
                Ok(PolicyFile::default())
            }
            Err(error) => {
                Err(error).with_context(|| format!("read mcpu policy {}", path.display()))
            }
        }
    }

    pub fn save(&self, policy: &PolicyFile) -> Result<()> {
        policy.validate()?;
        let path = self.store.root.join("policy.json");
        let bytes = serde_json::to_vec(policy)?;
        crate::paths::write_private_atomic(&path, &bytes)
            .with_context(|| format!("write mcpu policy {}", path.display()))?;
        let saved: PolicyFile = read_json_bounded::<PolicyFile>(&path)?;
        saved.validate()?;
        if saved != *policy {
            anyhow::bail!("mcpu policy read-back did not match");
        }
        ensure_private_file(&path)?;
        Ok(())
    }

    pub fn store(&self) -> &PolicyStore {
        self.store
    }
}

impl Drop for PolicyLock<'_> {
    fn drop(&mut self) {
        unlock_file(&self.file);
    }
}

pub(super) fn new_pending(candidate: &Candidate, observed_at: String) -> Result<PendingRequest> {
    let seed = serde_json::to_vec(&(
        &candidate.identity,
        &candidate.name,
        &observed_at,
        std::process::id(),
    ))?;
    let mut hasher = Sha256::new();
    hasher.update(seed);
    let request_id = format!("{:x}", hasher.finalize());
    Ok(PendingRequest {
        request_id,
        identity: candidate.identity.clone(),
        name: candidate.name.clone(),
        cpu_percent: candidate.cpu_percent,
        memory_bytes: candidate.memory_bytes,
        reason: candidate.reason.clone(),
        observed_at,
        default_timer_minutes: DEFAULT_TIMER_MINUTES,
    })
}

pub(super) fn apply_response(
    policy: &mut PolicyFile,
    response: &DecisionResponse,
) -> Result<DecisionApply> {
    let Some(request) = policy.pending.get(&response.request_id) else {
        return Ok(DecisionApply::Stale);
    };
    if request.identity.executable != response.canonical_path
        || request.identity.fingerprint != response.fingerprint
    {
        return Ok(DecisionApply::Stale);
    }

    match response.decision {
        Decision::Add => {
            let minutes = response
                .timer_minutes
                .context("Add requires a valid timer in minutes")?;
            if minutes == 0 || minutes > MAX_TIMER_MINUTES || minutes.checked_mul(60).is_none() {
                anyhow::bail!("timer must be between 1 and {MAX_TIMER_MINUTES} minutes");
            }
            if policy.is_excluded(&response.canonical_path) {
                policy.pending.remove(&response.request_id);
                policy
                    .completed
                    .insert(response.request_id.clone(), response.clone());
                return Ok(DecisionApply::ExcludedAlready);
            }
            policy.approvals.insert(
                response.canonical_path.clone(),
                Approval {
                    canonical_path: response.canonical_path.clone(),
                    fingerprint: response.fingerprint.clone(),
                    timer_minutes: minutes,
                },
            );
            policy.pending.remove(&response.request_id);
            policy
                .completed
                .insert(response.request_id.clone(), response.clone());
            Ok(DecisionApply::Added { minutes })
        }
        Decision::Exclude => {
            policy.exclusions.insert(response.canonical_path.clone());
            policy.approvals.remove(&response.canonical_path);
            policy
                .pending
                .retain(|_, pending| pending.identity.executable != response.canonical_path);
            policy
                .completed
                .insert(response.request_id.clone(), response.clone());
            Ok(DecisionApply::Excluded)
        }
    }
}

pub(super) fn flush_completed(
    store: &PolicyStore,
    policy_lock: &PolicyLock<'_>,
    policy: &mut PolicyFile,
) -> Result<()> {
    if policy.completed.is_empty() {
        return Ok(());
    }
    let completed = policy.completed.values().cloned().collect::<Vec<_>>();
    for response in &completed {
        store.write_acknowledgement(response)?;
    }
    let previous_completed = policy.completed.clone();
    policy.completed.clear();
    if let Err(error) = policy_lock.save(policy) {
        policy.completed = previous_completed;
        return Err(error);
    }
    for response in completed {
        store.remove_response(&response.request_id)?;
        store.remove_request(&response.request_id);
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum DecisionApply {
    Added { minutes: u64 },
    Excluded,
    ExcludedAlready,
    Stale,
}

pub(super) fn try_ui_lock(path: &Path) -> Result<bool> {
    ensure_private_directory(
        path.parent()
            .context("mcpu UI lock has no parent directory")?,
    )?;
    let file = open_private_lock_file(path)?;
    match lock_file(&file, true) {
        Ok(()) => {
            unlock_file(&file);
            Ok(false)
        }
        Err(error) if is_would_block(&error) => Ok(true),
        Err(error) => Err(error).context("probe mcpu UI lock"),
    }
}

fn read_json_bounded<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<T> {
    let metadata = fs::metadata(path).with_context(|| format!("inspect {}", path.display()))?;
    if metadata.len() > MAX_POLICY_BYTES {
        anyhow::bail!("{} exceeds the mcpu state size limit", path.display());
    }
    ensure_private_file(path)?;
    let bytes = fs::read(path).with_context(|| format!("read {}", path.display()))?;
    serde_json::from_slice(&bytes).with_context(|| format!("parse {}", path.display()))
}

fn read_optional_json<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<Option<T>> {
    match read_json_bounded(path) {
        Ok(value) => Ok(Some(value)),
        Err(error)
            if error
                .downcast_ref::<std::io::Error>()
                .is_some_and(|io| io.kind() == ErrorKind::NotFound) =>
        {
            Ok(None)
        }
        Err(error) => Err(error),
    }
}

fn is_request_id(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn is_fingerprint(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn ensure_private_directory(path: &Path) -> Result<()> {
    fs::create_dir_all(path).with_context(|| format!("create {}", path.display()))?;
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("inspect directory {}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        anyhow::bail!("mcpu state directory is not a real directory");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let current_uid = unsafe { libc::getuid() };
        if metadata.uid() != current_uid {
            anyhow::bail!("mcpu state directory is owned by another user");
        }
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

fn ensure_private_file(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("inspect private file {}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        anyhow::bail!("mcpu state file is not a regular file");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let current_uid = unsafe { libc::getuid() };
        if metadata.uid() != current_uid {
            anyhow::bail!("mcpu state file is owned by another user");
        }
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

fn open_private_lock_file(path: &Path) -> Result<File> {
    let mut options = OpenOptions::new();
    options.create(true).read(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options
            .mode(0o600)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    }
    let file = options
        .open(path)
        .with_context(|| format!("open lock {}", path.display()))?;
    ensure_private_file(path)?;
    Ok(file)
}

#[cfg(unix)]
fn lock_file(file: &File, nonblocking: bool) -> std::io::Result<()> {
    use std::os::fd::AsRawFd;
    let operation = libc::LOCK_EX | if nonblocking { libc::LOCK_NB } else { 0 };
    let result = unsafe { libc::flock(file.as_raw_fd(), operation) };
    if result == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[cfg(unix)]
fn unlock_file(file: &File) {
    use std::os::fd::AsRawFd;
    let _ = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_UN) };
}

#[cfg(not(unix))]
fn lock_file(_file: &File, _nonblocking: bool) -> std::io::Result<()> {
    Err(std::io::Error::new(
        ErrorKind::Unsupported,
        "file locks are unavailable",
    ))
}

#[cfg(not(unix))]
fn unlock_file(_file: &File) {}

fn is_would_block(error: &std::io::Error) -> bool {
    error.kind() == ErrorKind::WouldBlock
}

#[cfg(test)]
#[path = "policy_tests.rs"]
mod tests;
