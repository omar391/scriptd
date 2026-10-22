use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, SystemTime};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone)]
pub struct Policy {
    pub owner_uid: u32,
    pub approved_sources: BTreeSet<String>,
}

impl Policy {
    pub fn load_root_owned(path: &Path, file_owner_uid: u32, caller_uid: u32) -> Result<Self> {
        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)
            .with_context(|| format!("open approved Homebrew source policy {}", path.display()))?;
        let metadata = file.metadata()?;
        if !metadata.is_file() || metadata.uid() != file_owner_uid || metadata.mode() & 0o022 != 0 {
            bail!(
                "approved Homebrew source policy must be a non-writable regular file owned by UID {file_owner_uid}"
            );
        }
        let mut contents = String::new();
        file.read_to_string(&mut contents)?;
        let mut approved_sources = BTreeSet::new();
        for (index, line) in contents.lines().enumerate() {
            let source = line.trim();
            if source.is_empty() || source.starts_with('#') {
                continue;
            }
            let mut parts = source.split('/');
            let owner = parts.next().unwrap_or_default();
            let repository = parts.next().unwrap_or_default();
            let valid_component = |value: &str| {
                !value.is_empty()
                    && value.bytes().all(|byte| {
                        byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.')
                    })
            };
            if parts.next().is_some() || !valid_component(owner) || !valid_component(repository) {
                bail!(
                    "invalid approved source at {}:{}",
                    path.display(),
                    index + 1
                );
            }
            approved_sources.insert(source.to_string());
        }
        Ok(Self {
            owner_uid: caller_uid,
            approved_sources,
        })
    }
}

pub fn read_root_owned_file(path: &Path, owner_uid: u32) -> Result<String> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .with_context(|| format!("open root-owned file {}", path.display()))?;
    validate_open_root_owned_file(&file, path, owner_uid)?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;
    Ok(contents)
}

fn read_private_root_owned_file(path: &Path, owner_uid: u32) -> Result<String> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .with_context(|| format!("open private broker state {}", path.display()))?;
    validate_open_root_owned_file(&file, path, owner_uid)?;
    if file.metadata()?.mode() & 0o077 != 0 {
        bail!(
            "{} must not be readable or writable by group or other users",
            path.display()
        );
    }
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;
    Ok(contents)
}

pub fn validate_root_owned_file(path: &Path, owner_uid: u32) -> Result<()> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .with_context(|| format!("open root-owned file {}", path.display()))?;
    validate_open_root_owned_file(&file, path, owner_uid)
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ActivationEvidence {
    schema: String,
    generation: String,
    broker_binary_digest: String,
    authenticated_landing: AuthenticatedLandingEvidence,
    isolated_acceptance: IsolatedAcceptanceEvidence,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthenticatedLandingEvidence {
    schema: String,
    candidate_commit: String,
    landed_commit: String,
    review_reference: String,
    landing_reference: String,
    review_passed: bool,
    landed: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct IsolatedAcceptanceEvidence {
    app_cask: String,
    package_cask: String,
    script_cask: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AcceptanceRecord {
    schema: String,
    platform: String,
    isolated: bool,
    passed: bool,
    cask_type: String,
    procedure: String,
    result: String,
}

/// Require a protected, generation-bound decision before the root broker can
/// create or serve privileged jobs. The acceptance digests refer to evidence
/// captured by the isolated macOS acceptance run.
pub fn validate_activation_evidence(
    repo: &Path,
    activation_path: &Path,
    client_path: &Path,
) -> Result<()> {
    if crate::paths::is_linked_worktree(repo) {
        bail!("privilege broker activation requires the primary repository checkout");
    }
    let repo = repo.to_string_lossy();
    let status = Command::new("git")
        .arg("-C")
        .arg(repo.as_ref())
        .args(["status", "--porcelain"])
        .output()
        .context("check the landed scriptd generation")?;
    if !status.status.success() || !status.stdout.is_empty() {
        bail!("privilege broker activation requires a clean landed generation");
    }
    let generation = Command::new("git")
        .arg("-C")
        .arg(repo.as_ref())
        .args(["rev-parse", "HEAD"])
        .output()
        .context("read the landed scriptd generation")?;
    if !generation.status.success() {
        bail!("could not identify the landed scriptd generation");
    }
    let generation = String::from_utf8_lossy(&generation.stdout)
        .trim()
        .to_string();
    let activation = read_root_owned_file(activation_path, 0)
        .context("protected privilege activation evidence is unavailable")?;
    let evidence: ActivationEvidence =
        serde_json::from_str(&activation).context("parse privilege activation evidence")?;
    if evidence.schema != "scriptd-privilege-activation/v1" {
        bail!("privilege activation evidence has an unsupported schema");
    }
    if evidence.generation != generation {
        bail!("privilege activation evidence is for a different landed generation");
    }
    validate_landing_evidence(&evidence.authenticated_landing, &generation)?;
    let binary = std::fs::read(client_path)
        .with_context(|| format!("read installed broker binary {}", client_path.display()))?;
    if evidence.broker_binary_digest != crate::control::digest(&binary) {
        bail!("privilege activation evidence is for a different broker binary");
    }
    validate_acceptance_record(
        activation_path,
        "app-cask.json",
        "app",
        &evidence.isolated_acceptance.app_cask,
    )?;
    validate_acceptance_record(
        activation_path,
        "package-cask.json",
        "package",
        &evidence.isolated_acceptance.package_cask,
    )?;
    validate_acceptance_record(
        activation_path,
        "script-cask.json",
        "script",
        &evidence.isolated_acceptance.script_cask,
    )?;
    Ok(())
}

fn validate_landing_evidence(
    evidence: &AuthenticatedLandingEvidence,
    generation: &str,
) -> Result<()> {
    if evidence.schema != "scriptd-authenticated-landing/v1"
        || evidence.candidate_commit != generation
        || evidence.landed_commit != generation
        || evidence.review_reference.trim().is_empty()
        || evidence.landing_reference.trim().is_empty()
        || !evidence.review_passed
        || !evidence.landed
    {
        bail!("privilege activation evidence does not attest to the reviewed landed generation");
    }
    Ok(())
}

fn validate_acceptance_record(
    activation_path: &Path,
    file_name: &str,
    expected_type: &str,
    expected_digest: &str,
) -> Result<()> {
    if !is_sha256_digest(expected_digest) {
        bail!("privilege activation evidence is missing an isolated cask acceptance digest");
    }
    let path = activation_path
        .parent()
        .context("privilege activation evidence has no parent")?
        .join("acceptance")
        .join(file_name);
    let record = read_root_owned_file(&path, 0)
        .with_context(|| format!("read isolated {expected_type} cask acceptance evidence"))?;
    if crate::control::digest(record.as_bytes()) != expected_digest {
        bail!("isolated {expected_type} cask acceptance evidence digest does not match");
    }
    let record: AcceptanceRecord =
        serde_json::from_str(&record).context("parse isolated cask acceptance evidence")?;
    if record.schema != "scriptd-privileged-acceptance-evidence/v1"
        || record.platform != "macOS"
        || !record.isolated
        || !record.passed
        || record.cask_type != expected_type
        || record.procedure.trim().is_empty()
        || record.result.trim().is_empty()
    {
        bail!("isolated {expected_type} cask acceptance evidence is incomplete or did not pass");
    }
    Ok(())
}

fn is_sha256_digest(value: &str) -> bool {
    value
        .strip_prefix("sha256:")
        .is_some_and(|hex| hex.len() == 64 && hex.bytes().all(|byte| byte.is_ascii_hexdigit()))
}

pub fn query_cask_info_as_user(
    homebrew_bin: &Path,
    caller_uid: u32,
    token: &str,
) -> Result<String> {
    if token.is_empty()
        || token.starts_with('-')
        || !token.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'.' | b'_' | b'-' | b'@')
        })
    {
        bail!("Homebrew cask token is invalid");
    }
    if !homebrew_bin.is_absolute() || !homebrew_bin.is_file() {
        bail!("configured Homebrew executable is unavailable");
    }
    let output = Command::new("/usr/bin/sudo")
        .args(["-n", "-u"])
        .arg(format!("#{caller_uid}"))
        .args(["-H", "--"])
        .arg(homebrew_bin)
        .args(["info", "--cask", "--json=v2", token])
        .output()
        .context("query installed cask metadata as the Homebrew user")?;
    if !output.status.success() {
        bail!(
            "Homebrew cask metadata query failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    String::from_utf8(output.stdout).context("Homebrew cask metadata was not UTF-8")
}

fn validate_open_root_owned_file(file: &File, path: &Path, owner_uid: u32) -> Result<()> {
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.uid() != owner_uid || metadata.mode() & 0o022 != 0 {
        bail!(
            "{} must be a non-writable regular file owned by UID {owner_uid}",
            path.display()
        );
    }
    Ok(())
}

#[derive(Debug, Clone)]
pub struct VerifiedCask {
    token: String,
    source: String,
}

#[derive(Debug, Clone)]
pub struct OpenRequest {
    pub caller_uid: u32,
    pub cask: VerifiedCask,
    pub ttl: Duration,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Grant {
    pub job_id: String,
    pub token: String,
}

#[derive(Debug, Clone)]
struct Job {
    cask: String,
    source: String,
    client_bundle_identifier: Option<String>,
    client_signing_identity: Option<String>,
    token: String,
    owner_pid: u32,
    worker_pid: Option<u32>,
    launch_reserved: bool,
    expires_at: SystemTime,
    completed: bool,
    seen_commands: HashSet<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecOutput {
    pub status: i32,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct JobAudit {
    pub job_id: String,
    #[serde(default)]
    pub client_bundle_identifier: Option<String>,
    #[serde(default)]
    pub client_signing_identity: Option<String>,
    pub cask: String,
    pub source: String,
    pub completed: bool,
    pub worker_bound: bool,
    pub command_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct PairingAudit {
    transition: String,
    signing_identity: String,
    bundle_identifier: String,
    authorizing_principal: String,
    occurred_at_unix_seconds: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ClientSubmission {
    handle: String,
    job_id: String,
    module: String,
    action: Option<String>,
    bundle_identifier: String,
    signing_identity: String,
    #[serde(default)]
    status: ClientSubmissionStatus,
    #[serde(default)]
    run_handle: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum ClientSubmissionStatus {
    #[default]
    Issued,
    Dispatched,
    Completed,
    Interrupted,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
struct BrokerAudit {
    schema: String,
    jobs: Vec<JobAudit>,
    pairings: Vec<Pairing>,
    pairing_events: Vec<PairingAudit>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(default)]
struct ClientSubmissionStore {
    schema: String,
    submissions: Vec<ClientSubmission>,
}

#[derive(Debug, Default)]
pub struct Broker {
    policy: Policy,
    audit_path: Option<std::path::PathBuf>,
    client_submissions_path: Option<std::path::PathBuf>,
    jobs: BTreeMap<String, Job>,
    historical_jobs: Vec<JobAudit>,
    spent_tokens: HashSet<String>,
    pairings: BTreeMap<String, Pairing>,
    pairing_events: Vec<PairingAudit>,
    client_submissions: BTreeMap<String, ClientSubmission>,
}

/// A client that the bridge has agreed to work with.
///
/// Pairing binds the bridge to one code-signing identity so a later client
/// running as a different signer is not silently trusted. Revoking a pairing
/// blocks new jobs; jobs that were already accepted still report their
/// results.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Pairing {
    /// The code-signing identity the client presented.
    pub signing_identity: String,
    /// The client application's bundle identifier.
    pub bundle_identifier: String,
    /// The protocol version the client speaks.
    pub protocol_version: u32,
    /// Whether the pairing is currently active.
    pub active: bool,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            owner_uid: 0,
            approved_sources: BTreeSet::new(),
        }
    }
}

pub fn verify_installed_cask(
    token: &str,
    info_json: &str,
    policy: &Policy,
) -> Result<VerifiedCask> {
    if token.trim().is_empty() || token.trim() != token {
        bail!("Homebrew cask token is invalid");
    }
    let document: serde_json::Value =
        serde_json::from_str(info_json).context("parse Homebrew cask metadata")?;
    let casks = document
        .get("casks")
        .and_then(serde_json::Value::as_array)
        .context("Homebrew cask metadata has no casks array")?;
    let cask = casks
        .iter()
        .find(|cask| cask.get("token").and_then(serde_json::Value::as_str) == Some(token))
        .context("Homebrew metadata did not identify the requested cask")?;
    let installed = cask
        .get("installed")
        .and_then(serde_json::Value::as_str)
        .is_some_and(|version| !version.trim().is_empty());
    if !installed {
        bail!("broker jobs require a cask Homebrew reports as installed");
    }
    if cask.get("pinned").and_then(serde_json::Value::as_bool) == Some(true) {
        bail!("pinned casks cannot receive broker jobs");
    }
    let source = cask
        .get("tap")
        .and_then(serde_json::Value::as_str)
        .context("Homebrew metadata has no cask source")?;
    if !policy.approved_sources.contains(source) {
        bail!("cask source {source} is not approved");
    }
    Ok(VerifiedCask {
        token: token.to_string(),
        source: source.to_string(),
    })
}

impl Broker {
    pub fn new(policy: Policy) -> Self {
        Self {
            policy,
            ..Self::default()
        }
    }

    pub fn with_audit(policy: Policy, audit_path: std::path::PathBuf) -> Self {
        let client_submissions_path = audit_path.with_file_name("broker-client-submissions.json");
        Self {
            policy,
            audit_path: Some(audit_path),
            client_submissions_path: Some(client_submissions_path),
            ..Self::default()
        }
    }

    pub fn load_with_audit(policy: Policy, audit_path: std::path::PathBuf) -> Result<Self> {
        Self::load_with_audit_owner(policy, audit_path, 0)
    }

    pub fn load_with_audit_owner(
        policy: Policy,
        audit_path: std::path::PathBuf,
        owner_uid: u32,
    ) -> Result<Self> {
        let mut broker = Self::with_audit(policy, audit_path.clone());
        match crate::broker::read_root_owned_file(&audit_path, owner_uid) {
            Ok(contents) => {
                let value: serde_json::Value = serde_json::from_str(&contents)
                    .context("parse durable broker state and pairing audit")?;
                let legacy_audit = value.is_array();
                let persisted = if legacy_audit {
                    BrokerAudit {
                        jobs: serde_json::from_value(value)
                            .context("parse legacy broker job audit")?,
                        ..BrokerAudit::default()
                    }
                } else {
                    serde_json::from_value::<BrokerAudit>(value)
                        .context("parse durable broker state and pairing audit")?
                };
                if !legacy_audit && persisted.schema != "scriptd-broker-audit/v1" {
                    bail!("durable broker state has an unsupported schema");
                }
                for pairing in &persisted.pairings {
                    if pairing.signing_identity.trim().is_empty()
                        || pairing.signing_identity.trim() != pairing.signing_identity
                        || pairing.bundle_identifier.trim().is_empty()
                        || pairing.bundle_identifier.trim() != pairing.bundle_identifier
                        || pairing.protocol_version != crate::control::PROTOCOL_VERSION
                    {
                        bail!("durable broker state contains an invalid client pairing");
                    }
                    if broker
                        .pairings
                        .insert(pairing.bundle_identifier.clone(), pairing.clone())
                        .is_some()
                    {
                        bail!("durable broker state contains duplicate client pairings");
                    }
                }
                broker.historical_jobs = persisted.jobs;
                broker.pairing_events = persisted.pairing_events;
            }
            Err(_error) if !audit_path.exists() => {}
            Err(error) => return Err(error).context("load durable broker state"),
        }
        if unsafe { libc::geteuid() } == owner_uid {
            if let Some(submissions_path) = broker.client_submissions_path.as_deref() {
                match read_private_root_owned_file(submissions_path, owner_uid) {
                    Ok(contents) => {
                        let mut persisted: ClientSubmissionStore = serde_json::from_str(&contents)
                            .context("parse protected client submission handles")?;
                        let legacy = persisted.schema == "scriptd-client-submissions/v1";
                        if !legacy && persisted.schema != "scriptd-client-submissions/v2" {
                            bail!("protected client submission store has an unsupported schema");
                        }
                        let mut submission_job_ids = HashSet::new();
                        let mut interrupted_active_run = false;
                        for mut submission in persisted.submissions.drain(..) {
                            let stored_run_handle_is_valid =
                                submission.status != ClientSubmissionStatus::Dispatched
                                    || submission
                                        .run_handle
                                        .as_deref()
                                        .is_some_and(is_capability_handle);
                            if !stored_run_handle_is_valid {
                                bail!("protected client submission store contains an invalid run handle");
                            }
                            if legacy || submission.status == ClientSubmissionStatus::Dispatched {
                                if submission.status == ClientSubmissionStatus::Dispatched {
                                    interrupted_active_run = true;
                                }
                                submission.status = ClientSubmissionStatus::Interrupted;
                                submission.run_handle = None;
                            }
                            let run_handle_is_valid = match submission.status {
                                ClientSubmissionStatus::Dispatched => submission
                                    .run_handle
                                    .as_deref()
                                    .is_some_and(is_capability_handle),
                                ClientSubmissionStatus::Issued
                                | ClientSubmissionStatus::Completed
                                | ClientSubmissionStatus::Interrupted => {
                                    submission.run_handle.is_none()
                                }
                            };
                            if !is_capability_handle(&submission.handle)
                                || submission.job_id.trim().is_empty()
                                || submission.job_id.trim() != submission.job_id
                                || submission.module != "mbrew"
                                || submission.bundle_identifier.trim().is_empty()
                                || submission.bundle_identifier.trim()
                                    != submission.bundle_identifier
                                || submission.signing_identity.trim().is_empty()
                                || submission.signing_identity.trim() != submission.signing_identity
                                || !run_handle_is_valid
                                || !submission_job_ids.insert(submission.job_id.clone())
                                || broker
                                    .client_submissions
                                    .insert(submission.handle.clone(), submission)
                                    .is_some()
                            {
                                bail!(
                                    "protected client submission store contains an invalid handle"
                                );
                            }
                        }
                        if legacy || interrupted_active_run {
                            broker.persist_client_submissions().context(
                                "persist interrupted client submissions before accepting work",
                            )?;
                        }
                    }
                    Err(_error) if !submissions_path.exists() => {}
                    Err(error) => return Err(error).context("load protected client submissions"),
                }
            }
        }
        Ok(broker)
    }

    /// Records a pairing for a client identity.
    ///
    /// Pairing is keyed by bundle identifier and bound to its verified signer.
    /// An active signer cannot be silently replaced; the old pairing must be
    /// explicitly revoked first.
    #[cfg(test)]
    pub fn pair(&mut self, pairing: Pairing) -> Result<Pairing> {
        let authenticated_signer = pairing.signing_identity.clone();
        let principal = format!(
            "{} ({})",
            pairing.signing_identity, pairing.bundle_identifier
        );
        self.pair_authorized(pairing, &authenticated_signer, &principal)
    }

    pub fn pair_authorized(
        &mut self,
        pairing: Pairing,
        authenticated_signing_identity: &str,
        authorizing_principal: &str,
    ) -> Result<Pairing> {
        if pairing.signing_identity.trim().is_empty()
            || pairing.signing_identity.trim() != pairing.signing_identity
        {
            bail!("pairing requires a code-signing identity");
        }
        if pairing.bundle_identifier.trim().is_empty()
            || pairing.bundle_identifier.trim() != pairing.bundle_identifier
        {
            bail!("pairing requires a bundle identifier");
        }
        if pairing.protocol_version != crate::control::PROTOCOL_VERSION {
            bail!("pairing protocol version is not supported");
        }
        if pairing.signing_identity != authenticated_signing_identity {
            bail!("pairing signer does not match the authenticated client");
        }
        if let Some(existing) = self.pairings.get(&pairing.bundle_identifier) {
            if existing.active && existing.signing_identity != authenticated_signing_identity {
                bail!("signer replacement requires the enrolled signer or an administrator");
            }
        }
        let previous = self
            .pairings
            .insert(pairing.bundle_identifier.clone(), pairing.clone());
        self.pairing_events.push(PairingAudit {
            transition: match previous.as_ref() {
                None => "paired",
                Some(existing) if existing.signing_identity != pairing.signing_identity => {
                    "replaced"
                }
                Some(_) => "reaffirmed",
            }
            .to_string(),
            signing_identity: pairing.signing_identity.clone(),
            bundle_identifier: pairing.bundle_identifier.clone(),
            authorizing_principal: authorizing_principal.to_string(),
            occurred_at_unix_seconds: unix_timestamp(),
        });
        if let Err(error) = self.persist_audit() {
            self.pairing_events.pop();
            if let Some(previous) = previous {
                self.pairings
                    .insert(pairing.bundle_identifier.clone(), previous);
            } else {
                self.pairings.remove(&pairing.bundle_identifier);
            }
            return Err(error).context("persist pairing before acknowledging enrollment");
        }
        Ok(pairing)
    }

    /// Revokes a pairing.
    ///
    /// Revocation blocks new work from that client. Jobs the bridge already
    /// accepted still report their results.
    #[cfg(test)]
    pub fn unpair(&mut self, bundle_identifier: &str) -> Result<()> {
        let Some(pairing) = self.pairings.get(bundle_identifier).cloned() else {
            bail!("no pairing exists for this client");
        };
        let principal = format!(
            "{} ({})",
            pairing.signing_identity, pairing.bundle_identifier
        );
        self.unpair_authorized(bundle_identifier, &pairing.signing_identity, &principal)
    }

    pub fn unpair_authorized(
        &mut self,
        bundle_identifier: &str,
        authenticated_signing_identity: &str,
        authorizing_principal: &str,
    ) -> Result<()> {
        let Some(pairing) = self.pairings.get(bundle_identifier).cloned() else {
            bail!("no pairing exists for this client");
        };
        if pairing.signing_identity != authenticated_signing_identity {
            bail!("authenticated signer does not match the enrolled pairing");
        }
        if !pairing.active {
            bail!("client pairing is already revoked");
        }
        self.pairings
            .get_mut(bundle_identifier)
            .expect("pairing checked above")
            .active = false;
        self.pairing_events.push(PairingAudit {
            transition: "revoked".to_string(),
            signing_identity: pairing.signing_identity.clone(),
            bundle_identifier: pairing.bundle_identifier.clone(),
            authorizing_principal: authorizing_principal.to_string(),
            occurred_at_unix_seconds: unix_timestamp(),
        });
        if let Err(error) = self.persist_audit() {
            self.pairing_events.pop();
            self.pairings.insert(bundle_identifier.to_string(), pairing);
            return Err(error).context("persist revocation before acknowledging it");
        }
        Ok(())
    }

    /// Issues a durable opaque handle for one authenticated queued submission.
    ///
    /// The handle is returned to the trusted service and stored in its
    /// user-owned queue. The corresponding client identity remains in the
    /// broker's protected audit store, where queue edits cannot change it.
    pub fn issue_client_submission_handle(
        &mut self,
        client: &Pairing,
        job_id: &str,
        module: &str,
        action: Option<&str>,
    ) -> Result<String> {
        self.require_active_pairing(&client.bundle_identifier, &client.signing_identity)?;
        if job_id.trim().is_empty() || job_id.trim() != job_id || module != "mbrew" {
            bail!("client submission requires a valid queued job id");
        }
        if action.is_some_and(|action| action != "retry_pending") {
            bail!("client submission action is not supported");
        }
        if let Some(existing) = self
            .client_submissions
            .values()
            .find(|submission| submission.job_id == job_id)
        {
            if existing.bundle_identifier == client.bundle_identifier
                && existing.signing_identity == client.signing_identity
                && existing.module == module
                && existing.action.as_deref() == action
                && existing.status == ClientSubmissionStatus::Issued
            {
                return Ok(existing.handle.clone());
            }
            bail!("queued job id is already authorized or has been consumed");
        }

        let handle = random_hex()?;
        let submission = ClientSubmission {
            handle: handle.clone(),
            job_id: job_id.to_string(),
            module: module.to_string(),
            action: action.map(str::to_string),
            bundle_identifier: client.bundle_identifier.clone(),
            signing_identity: client.signing_identity.clone(),
            status: ClientSubmissionStatus::Issued,
            run_handle: None,
        };
        self.client_submissions.insert(handle.clone(), submission);
        if let Err(error) = self.persist_client_submissions() {
            self.client_submissions.remove(&handle);
            return Err(error).context("persist client submission before accepting it");
        }
        Ok(handle)
    }

    /// Claims a queued submission for one run and persists the dispatch before
    /// returning the run-scoped capability used by its cask operations.
    pub fn begin_client_submission_run(
        &mut self,
        handle: &str,
        job_id: &str,
        module: &str,
        action: Option<&str>,
    ) -> Result<String> {
        let submission = self
            .client_submissions
            .get(handle)
            .context("unknown authenticated client submission handle")?;
        if submission.job_id != job_id
            || submission.module != module
            || submission.action.as_deref() != action
        {
            bail!("authenticated client handle does not match the queued job");
        }
        let Some(pairing) = self.pairings.get(&submission.bundle_identifier) else {
            bail!("authenticated client submission has no enrolled pairing");
        };
        if !pairing.active || pairing.signing_identity != submission.signing_identity {
            bail!("authenticated client submission pairing is inactive or has changed");
        }
        if submission.status != ClientSubmissionStatus::Issued {
            bail!("authenticated client submission has already been dispatched or consumed");
        }

        let run_handle = random_hex()?;
        {
            let submission = self
                .client_submissions
                .get_mut(handle)
                .expect("submission was validated above");
            submission.status = ClientSubmissionStatus::Dispatched;
            submission.run_handle = Some(run_handle.clone());
        }
        if let Err(error) = self.persist_client_submissions() {
            if let Some(submission) = self.client_submissions.get_mut(handle) {
                submission.status = ClientSubmissionStatus::Interrupted;
                submission.run_handle = None;
            }
            return Err(error).context("persist client submission dispatch before authorizing work");
        }
        Ok(run_handle)
    }

    /// Resolves an in-flight run capability to the identity recorded at
    /// submission time. Multiple cask operations can use it until the run is
    /// completed, interrupted, or the broker restarts.
    pub fn resolve_client_submission_run(
        &self,
        run_handle: &str,
        job_id: &str,
        module: &str,
        action: Option<&str>,
    ) -> Result<Pairing> {
        let submission = self
            .client_submissions
            .values()
            .find(|submission| {
                submission.status == ClientSubmissionStatus::Dispatched
                    && submission.run_handle.as_deref() == Some(run_handle)
            })
            .context("unknown or inactive client submission run")?;
        if submission.job_id != job_id
            || submission.module != module
            || submission.action.as_deref() != action
        {
            bail!("authenticated client run does not match the queued job");
        }
        let Some(pairing) = self.pairings.get(&submission.bundle_identifier) else {
            bail!("authenticated client submission has no enrolled pairing");
        };
        if !pairing.active || pairing.signing_identity != submission.signing_identity {
            bail!("authenticated client submission pairing is inactive or has changed");
        }
        Ok(pairing.clone())
    }

    /// Marks a submission run terminal. The state remains spent even if the
    /// durable write fails, and a restart also converts any persisted active
    /// run into an interrupted one.
    pub fn finish_client_submission_run(
        &mut self,
        run_handle: &str,
        job_id: &str,
        module: &str,
        action: Option<&str>,
        completed: bool,
    ) -> Result<()> {
        let handle = self
            .client_submissions
            .values()
            .find(|submission| {
                submission.status == ClientSubmissionStatus::Dispatched
                    && submission.run_handle.as_deref() == Some(run_handle)
                    && submission.job_id == job_id
                    && submission.module == module
                    && submission.action.as_deref() == action
            })
            .map(|submission| submission.handle.clone())
            .context("unknown or mismatched client submission run")?;
        let submission = self
            .client_submissions
            .get_mut(&handle)
            .expect("run submission was found above");
        submission.status = if completed {
            ClientSubmissionStatus::Completed
        } else {
            ClientSubmissionStatus::Interrupted
        };
        submission.run_handle = None;
        self.persist_client_submissions()
            .context("persist client submission terminal state")
    }

    /// Reports the pairing recorded for a client, if any.
    #[cfg(test)]
    pub fn pairing(&self, bundle_identifier: &str) -> Option<&Pairing> {
        self.pairings.get(bundle_identifier)
    }

    /// Reports whether a client currently holds an active pairing.
    #[cfg(test)]
    pub fn is_paired(&self, bundle_identifier: &str) -> bool {
        self.pairings
            .get(bundle_identifier)
            .is_some_and(|pairing| pairing.active)
    }

    #[cfg(test)]
    pub fn open_job(&mut self, request: OpenRequest) -> Result<Grant> {
        self.open_job_from(request, 0)
    }

    #[cfg(test)]
    pub fn open_job_from(&mut self, request: OpenRequest, owner_pid: u32) -> Result<Grant> {
        self.open_job_from_client(request, owner_pid, None, None)
    }

    fn open_job_from_client(
        &mut self,
        request: OpenRequest,
        owner_pid: u32,
        client_bundle_identifier: Option<&str>,
        client_signing_identity: Option<&str>,
    ) -> Result<Grant> {
        if request.caller_uid != self.policy.owner_uid {
            bail!("broker caller is not the enrolled user");
        }
        if request.ttl < Duration::from_secs(1) || request.ttl > Duration::from_secs(15 * 60) {
            bail!("broker job expiry must be between one second and fifteen minutes");
        }
        let job_id = random_hex()?;
        let token = random_hex()?;
        self.jobs.insert(
            job_id.clone(),
            Job {
                cask: request.cask.token,
                source: request.cask.source,
                client_bundle_identifier: client_bundle_identifier.map(str::to_string),
                client_signing_identity: client_signing_identity.map(str::to_string),
                token: token.clone(),
                owner_pid,
                worker_pid: None,
                launch_reserved: false,
                expires_at: SystemTime::now() + request.ttl,
                completed: false,
                seen_commands: HashSet::new(),
            },
        );
        if let Err(error) = self.persist_audit() {
            self.jobs.remove(&job_id);
            return Err(error).context("persist broker job before accepting it");
        }
        Ok(Grant { job_id, token })
    }

    pub fn open_cask_job_from(
        &mut self,
        caller_uid: u32,
        owner_pid: u32,
        client: &Pairing,
        token: &str,
        info_json: &str,
        ttl: Duration,
    ) -> Result<Grant> {
        self.require_active_pairing(&client.bundle_identifier, &client.signing_identity)?;
        let cask = verify_installed_cask(token, info_json, &self.policy)?;
        self.open_job_from_client(
            OpenRequest {
                caller_uid,
                cask,
                ttl,
            },
            owner_pid,
            Some(&client.bundle_identifier),
            Some(&client.signing_identity),
        )
    }

    /// Requires that a client holds an active pairing before new work runs.
    ///
    /// A revoked pairing blocks new jobs. Jobs that were already accepted
    /// keep their own state, so an in-flight job still reports its result.
    fn require_active_pairing(
        &self,
        bundle_identifier: &str,
        signing_identity: &str,
    ) -> Result<()> {
        let Some(pairing) = self.pairings.get(bundle_identifier) else {
            bail!("requesting client has no pairing; pair this client before requesting work");
        };
        if !pairing.active || pairing.signing_identity != signing_identity {
            bail!("requesting client pairing is inactive or its signer does not match");
        }
        Ok(())
    }

    pub fn pending_job_cask_from(
        &self,
        job_id: &str,
        token: &str,
        owner_pid: u32,
    ) -> Result<String> {
        let job = self.jobs.get(job_id).context("unknown broker job")?;
        if job.token != token || job.completed || self.spent_tokens.contains(token) {
            bail!("broker job token was rejected");
        }
        if job.owner_pid != owner_pid {
            bail!("broker job owner process was rejected");
        }
        if SystemTime::now() >= job.expires_at {
            bail!("broker job expired");
        }
        if job.launch_reserved || job.worker_pid.is_some() {
            bail!("broker job worker launch is already reserved");
        }
        Ok(job.cask.clone())
    }

    pub fn reserve_worker_launch_from(
        &mut self,
        job_id: &str,
        token: &str,
        owner_pid: u32,
        info_json: &str,
    ) -> Result<String> {
        let job = self.jobs.get(job_id).context("unknown broker job")?;
        if job.token != token || job.completed || self.spent_tokens.contains(token) {
            bail!("broker job token was rejected");
        }
        if job.owner_pid != owner_pid {
            bail!("broker job owner process was rejected");
        }
        if SystemTime::now() >= job.expires_at {
            bail!("broker job expired");
        }
        if job.launch_reserved || job.worker_pid.is_some() {
            bail!("broker job worker launch is already reserved");
        }
        let verified = verify_installed_cask(&job.cask, info_json, &self.policy)?;
        if verified.source != job.source {
            bail!("broker cask source changed after job acceptance");
        }
        let cask = job.cask.clone();
        self.jobs
            .get_mut(job_id)
            .context("unknown broker job")?
            .launch_reserved = true;
        if let Err(error) = self.persist_audit() {
            if let Some(job) = self.jobs.get_mut(job_id) {
                job.launch_reserved = false;
            }
            return Err(error).context("persist broker worker launch reservation");
        }
        Ok(cask)
    }

    #[cfg(test)]
    pub fn bind_worker(&mut self, job_id: &str, token: &str, worker_pid: u32) -> Result<()> {
        if let Some(job) = self.jobs.get_mut(job_id) {
            job.launch_reserved = true;
        }
        self.bind_worker_from(job_id, token, 0, worker_pid)
    }

    pub fn bind_worker_from(
        &mut self,
        job_id: &str,
        token: &str,
        owner_pid: u32,
        worker_pid: u32,
    ) -> Result<()> {
        let job = self.jobs.get_mut(job_id).context("unknown broker job")?;
        if job.token != token || job.completed || self.spent_tokens.contains(token) {
            bail!("broker job token was rejected");
        }
        if job.owner_pid != owner_pid {
            bail!("broker job owner process was rejected");
        }
        if !job.launch_reserved
            || worker_pid == 0
            || worker_pid == owner_pid
            || job.worker_pid.is_some()
        {
            bail!("broker job worker binding is unreserved, invalid, self-bound, or already set");
        }
        job.worker_pid = Some(worker_pid);
        self.persist_audit()
            .context("persist broker worker binding before execution")?;
        Ok(())
    }

    pub fn bound_worker_pid(&self, job_id: &str, token: &str) -> Result<u32> {
        let job = self.jobs.get(job_id).context("unknown broker job")?;
        if job.token != token || job.completed || self.spent_tokens.contains(token) {
            bail!("broker job token was rejected");
        }
        if SystemTime::now() >= job.expires_at {
            bail!("broker job expired");
        }
        job.worker_pid
            .context("broker job has no bound Homebrew worker")
    }

    pub fn authorize_exec(
        &mut self,
        job_id: &str,
        token: &str,
        worker_pid: u32,
        command_id: &str,
    ) -> Result<()> {
        let job = self.jobs.get(job_id).context("unknown broker job")?;
        if job.completed || self.spent_tokens.contains(token) {
            bail!("broker job capability was already used");
        }
        if job.token != token {
            bail!("broker job token was rejected");
        }
        if job.worker_pid != Some(worker_pid) {
            bail!("privileged channel is limited to the job worker");
        }
        if SystemTime::now() >= job.expires_at {
            bail!("broker job expired");
        }
        if command_id.is_empty() {
            bail!("broker command id is required");
        }
        if job.seen_commands.contains(command_id) {
            bail!("broker command replay was rejected");
        }
        let job = self.jobs.get_mut(job_id).context("unknown broker job")?;
        job.seen_commands.insert(command_id.to_string());
        self.persist_audit()
            .context("persist broker command acceptance before execution")?;
        Ok(())
    }

    #[cfg(test)]
    fn exec(
        &mut self,
        job_id: &str,
        token: &str,
        worker_pid: u32,
        command_id: &str,
        program: &Path,
        args: &[String],
        cwd: &Path,
        env: &[(String, String)],
        stdin: &[u8],
    ) -> Result<ExecOutput> {
        self.authorize_exec(job_id, token, worker_pid, command_id)?;
        run_forwarded(program, args, cwd, env, stdin)
    }

    #[cfg(test)]
    pub fn complete(&mut self, job_id: &str, token: &str) -> Result<()> {
        self.complete_from(job_id, token, 0)
    }

    pub fn complete_from(&mut self, job_id: &str, token: &str, owner_pid: u32) -> Result<()> {
        let job = self.jobs.get_mut(job_id).context("unknown broker job")?;
        if job.token != token || job.completed || self.spent_tokens.contains(token) {
            bail!("broker job token was rejected");
        }
        if job.owner_pid != owner_pid {
            bail!("broker job owner process was rejected");
        }
        job.completed = true;
        self.spent_tokens.insert(token.to_string());
        self.persist_audit()
            .context("persist broker job completion")?;
        Ok(())
    }

    pub fn audit(&self) -> Vec<JobAudit> {
        let mut records = self.historical_jobs.clone();
        records.extend(
            self.jobs
                .iter()
                .map(|(job_id, job)| JobAudit {
                    job_id: job_id.clone(),
                    client_bundle_identifier: job.client_bundle_identifier.clone(),
                    client_signing_identity: job.client_signing_identity.clone(),
                    cask: job.cask.clone(),
                    source: job.source.clone(),
                    completed: job.completed,
                    worker_bound: job.worker_pid.is_some(),
                    command_count: job.seen_commands.len(),
                })
                .collect::<Vec<_>>(),
        );
        records
    }

    fn persist_audit(&self) -> Result<()> {
        let Some(path) = self.audit_path.as_deref() else {
            return Ok(());
        };
        let persisted = BrokerAudit {
            schema: "scriptd-broker-audit/v1".to_string(),
            jobs: self.audit(),
            pairings: self.pairings.values().cloned().collect(),
            pairing_events: self.pairing_events.clone(),
        };
        write_shared_audit(path, serde_json::to_string_pretty(&persisted)?.as_bytes())
    }

    fn persist_client_submissions(&self) -> Result<()> {
        let Some(path) = self.client_submissions_path.as_deref() else {
            return Ok(());
        };
        let persisted = ClientSubmissionStore {
            schema: "scriptd-client-submissions/v2".to_string(),
            submissions: self.client_submissions.values().cloned().collect(),
        };
        write_private_shared_state(path, serde_json::to_string_pretty(&persisted)?.as_bytes())
    }
}

fn random_hex() -> Result<String> {
    let mut bytes = [0u8; 32];
    File::open("/dev/urandom")
        .context("open cryptographic random source")?
        .read_exact(&mut bytes)?;
    let mut result = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        write!(&mut result, "{byte:02x}").expect("writing to a string cannot fail");
    }
    Ok(result)
}

fn is_capability_handle(handle: &str) -> bool {
    handle.len() == 64 && handle.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn unix_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn write_shared_audit(path: &Path, contents: &[u8]) -> Result<()> {
    let parent = path.parent().context("broker audit path has no parent")?;
    let name = path
        .file_name()
        .context("broker audit path has no filename")?
        .to_string_lossy();
    let temporary = parent.join(format!(".{name}.{}.tmp", random_hex()?));
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o644)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&temporary)?;
        file.write_all(contents)?;
        file.sync_all()?;
        drop(file);
        std::fs::rename(&temporary, path)?;
        File::open(parent)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }
    result
}

fn write_private_shared_state(path: &Path, contents: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .context("private broker state path has no parent")?;
    let name = path
        .file_name()
        .context("private broker state path has no filename")?
        .to_string_lossy();
    let temporary = parent.join(format!(".{name}.{}.tmp", random_hex()?));
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&temporary)?;
        file.write_all(contents)?;
        file.sync_all()?;
        drop(file);
        std::fs::rename(&temporary, path)?;
        File::open(parent)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }
    result
}

pub fn bridge_compatible(system_command_source: &str) -> bool {
    // A method-name match does not establish the semantics this bridge relies
    // on. Until an exact supported runner fingerprint is configured, defer
    // privilege instead of granting a job to an unverified implementation.
    let _ = system_command_source;
    false
}

pub(crate) fn run_forwarded(
    program: &Path,
    args: &[String],
    cwd: &Path,
    env: &[(String, String)],
    stdin: &[u8],
) -> Result<ExecOutput> {
    let mut command = Command::new(program);
    command
        .args(args)
        .current_dir(cwd)
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (key, value) in env {
        command.env(key, value);
    }
    let mut child = command
        .spawn()
        .with_context(|| format!("spawn {}", program.display()))?;
    let input = stdin.to_vec();
    let stdin_pipe = child.stdin.take();
    let writer = std::thread::spawn(move || {
        if let Some(mut pipe) = stdin_pipe {
            pipe.write_all(&input)
        } else {
            Ok(())
        }
    });
    let output = child.wait_with_output()?;
    writer
        .join()
        .map_err(|_| anyhow::anyhow!("stdin forwarding thread panicked"))??;
    Ok(ExecOutput {
        status: output.status.code().unwrap_or(1),
        stdout: output.stdout,
        stderr: output.stderr,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn policy() -> Policy {
        Policy {
            owner_uid: 42,
            approved_sources: BTreeSet::from(["homebrew/cask".to_string()]),
        }
    }

    #[test]
    fn activation_landing_evidence_requires_review_and_the_exact_landed_commit() {
        let generation = "commit-123";
        let evidence = AuthenticatedLandingEvidence {
            schema: "scriptd-authenticated-landing/v1".to_string(),
            candidate_commit: generation.to_string(),
            landed_commit: generation.to_string(),
            review_reference: "pull/42/review".to_string(),
            landing_reference: "pull/42/merge".to_string(),
            review_passed: true,
            landed: true,
        };
        assert!(validate_landing_evidence(&evidence, generation).is_ok());

        let mut unreviewed = evidence;
        unreviewed.review_passed = false;
        assert!(validate_landing_evidence(&unreviewed, generation).is_err());
        unreviewed.review_passed = true;
        unreviewed.landed_commit = "different-commit".to_string();
        assert!(validate_landing_evidence(&unreviewed, generation).is_err());
    }

    #[test]
    fn root_owned_policy_rejects_symlinks_writable_files_and_invalid_sources() {
        let dir = tempfile::tempdir().expect("policy dir");
        let policy_path = dir.path().join("approved-sources");
        std::fs::write(&policy_path, "homebrew/cask\ntrusted/private-tap\n").expect("write policy");
        let uid = unsafe { libc::geteuid() };
        std::fs::set_permissions(&policy_path, std::fs::Permissions::from_mode(0o600))
            .expect("secure policy");
        let loaded = Policy::load_root_owned(&policy_path, uid, 42).expect("load policy");
        assert_eq!(loaded.owner_uid, 42);
        assert_eq!(loaded.approved_sources.len(), 2);

        std::fs::set_permissions(&policy_path, std::fs::Permissions::from_mode(0o666))
            .expect("make policy writable");
        assert!(Policy::load_root_owned(&policy_path, uid, 42).is_err());

        std::fs::set_permissions(&policy_path, std::fs::Permissions::from_mode(0o600))
            .expect("secure policy again");
        std::fs::write(&policy_path, "homebrew/cask/extra\n").expect("invalid source");
        assert!(Policy::load_root_owned(&policy_path, uid, 42).is_err());

        let symlink = dir.path().join("symlink");
        std::os::unix::fs::symlink(&policy_path, &symlink).expect("policy symlink");
        assert!(Policy::load_root_owned(&symlink, uid, 42).is_err());
    }

    fn request() -> OpenRequest {
        OpenRequest {
            caller_uid: 42,
            cask: verified_cask(),
            ttl: Duration::from_secs(60),
        }
    }

    fn verified_cask() -> VerifiedCask {
        verify_installed_cask(
            "anydesk",
            r#"{"casks":[{"token":"anydesk","tap":"homebrew/cask","installed":"9.7.0","pinned":false}]}"#,
            &policy(),
        )
        .expect("verified cask")
    }

    fn open_with_worker(broker: &mut Broker, request: OpenRequest) -> Grant {
        let grant = broker.open_job(request).expect("open");
        broker
            .bind_worker(&grant.job_id, &grant.token, 7)
            .expect("bind worker");
        grant
    }

    #[test]
    fn broker_job_is_bound_to_its_opening_service_process() {
        let mut broker = Broker::new(policy());
        let grant = broker.open_job_from(request(), 100).expect("open job");
        assert!(broker
            .bind_worker_from(&grant.job_id, &grant.token, 101, 102)
            .is_err());
        broker
            .reserve_worker_launch_from(
                &grant.job_id,
                &grant.token,
                100,
                r#"{"casks":[{"token":"anydesk","tap":"homebrew/cask","installed":"9.7.0","pinned":false}]}"#,
            )
            .expect("reserve worker launch");
        broker
            .bind_worker_from(&grant.job_id, &grant.token, 100, 102)
            .expect("bind worker from owning service");
        assert!(broker
            .complete_from(&grant.job_id, &grant.token, 101)
            .is_err());
        broker
            .complete_from(&grant.job_id, &grant.token, 100)
            .expect("complete from owning service");
    }

    #[test]
    fn a_revoked_pairing_blocks_new_jobs_but_keeps_an_accepted_job_usable() {
        let mut broker = Broker::new(policy());
        let signer_a = "Developer ID Application: Client A (TEAM-A)";
        let client_a = Pairing {
            signing_identity: signer_a.to_string(),
            bundle_identifier: "com.example.client-a".to_string(),
            protocol_version: crate::control::PROTOCOL_VERSION,
            active: true,
        };
        broker.pair(client_a.clone()).expect("pair client A");
        broker
            .pair(Pairing {
                signing_identity: "Developer ID Application: Client B (TEAM-B)".to_string(),
                bundle_identifier: "com.example.client-b".to_string(),
                protocol_version: crate::control::PROTOCOL_VERSION,
                active: true,
            })
            .expect("pair client B");

        // A job accepted while the pairing was active keeps its own state.
        let grant = broker
            .open_cask_job_from(
                42,
                100,
                &client_a,
                "anydesk",
                r#"{"casks":[{"token":"anydesk","tap":"homebrew/cask","installed":"9.7.0","pinned":false}]}"#,
                Duration::from_secs(60),
            )
            .expect("open job for client A");
        let accepted_audit = broker.audit();
        assert_eq!(
            accepted_audit[0].client_bundle_identifier.as_deref(),
            Some("com.example.client-a")
        );
        assert_eq!(
            accepted_audit[0].client_signing_identity.as_deref(),
            Some(signer_a)
        );

        broker
            .unpair("com.example.client-a")
            .expect("revoke client A");
        assert!(!broker.is_paired("com.example.client-a"));
        assert!(broker.is_paired("com.example.client-b"));

        let error = broker
            .open_cask_job_from(
                42,
                100,
                &client_a,
                "anydesk",
                r#"{"casks":[{"token":"anydesk","tap":"homebrew/cask","installed":"9.7.0","pinned":false}]}"#,
                Duration::from_secs(60),
            )
            .expect_err("a revoked pairing blocks new work");
        assert!(error.to_string().contains("inactive"));

        // The job accepted before the revocation still completes.
        broker
            .complete_from(&grant.job_id, &grant.token, 100)
            .expect("an accepted job still reports its result");
    }

    #[test]
    fn a_client_without_a_pairing_cannot_open_new_work() {
        let mut broker = Broker::new(policy());
        let error = broker
            .open_cask_job_from(
                42,
                100,
                &Pairing {
                    signing_identity: "Developer ID Application: Example (TEAM)".to_string(),
                    bundle_identifier: "com.example.unpaired".to_string(),
                    protocol_version: crate::control::PROTOCOL_VERSION,
                    active: true,
                },
                "anydesk",
                r#"{"casks":[{"token":"anydesk","tap":"homebrew/cask","installed":"9.7.0","pinned":false}]}"#,
                Duration::from_secs(60),
            )
            .expect_err("an unpaired client cannot open work");
        assert!(error.to_string().contains("no pairing"));
    }

    #[test]
    fn broker_rejects_self_binding_the_service_as_its_worker() {
        let mut broker = Broker::new(policy());
        let owner_pid = 4242;
        let grant = broker
            .open_job_from(request(), owner_pid)
            .expect("open job");
        let error = broker
            .bind_worker_from(&grant.job_id, &grant.token, owner_pid, owner_pid)
            .expect_err("service cannot bind itself as its worker");
        assert!(error.to_string().contains("self-bound"));
    }

    #[test]
    fn worker_launch_revalidates_the_installed_cask_and_source() {
        let mut broker = Broker::new(policy());
        let grant = broker.open_job_from(request(), 100).expect("open job");
        let info = r#"{"casks":[{"token":"anydesk","tap":"homebrew/cask","installed":"9.8.0","pinned":false}]}"#;
        assert_eq!(
            broker
                .reserve_worker_launch_from(&grant.job_id, &grant.token, 100, info)
                .expect("reserve launch"),
            "anydesk"
        );
        assert!(broker
            .pending_job_cask_from(&grant.job_id, &grant.token, 100)
            .is_err());
        let mut unreserved = Broker::new(policy());
        let second = unreserved
            .open_job_from(request(), 100)
            .expect("open second job");
        let changed_source = r#"{"casks":[{"token":"anydesk","tap":"other/cask","installed":"9.8.0","pinned":false}]}"#;
        assert!(unreserved
            .reserve_worker_launch_from(&second.job_id, &second.token, 100, changed_source)
            .is_err());
    }

    #[test]
    fn rejects_unapproved_source_wrong_worker_expiry_and_replay() {
        let mut broker = Broker::new(policy());
        assert!(verify_installed_cask(
            "anydesk",
            r#"{"casks":[{"token":"anydesk","tap":"evil/tap","installed":"9.7.0"}]}"#,
            &policy()
        )
        .is_err());

        let grant = open_with_worker(&mut broker, request());
        let dir = tempfile::tempdir().expect("dir");
        let first = broker
            .exec(
                &grant.job_id,
                &grant.token,
                7,
                "cmd-1",
                Path::new("/bin/cat"),
                &[],
                dir.path(),
                &[("SCRIPTD_BROKER_TEST".to_string(), "1".to_string())],
                b"hello-stdin",
            )
            .expect("exec");
        assert_eq!(first.status, 0);
        assert_eq!(first.stdout, b"hello-stdin");
        assert!(broker
            .exec(
                &grant.job_id,
                &grant.token,
                8,
                "cmd-2",
                Path::new("/bin/cat"),
                &[],
                dir.path(),
                &[],
                b"",
            )
            .is_err());
        assert!(broker
            .exec(
                &grant.job_id,
                &grant.token,
                7,
                "cmd-1",
                Path::new("/bin/cat"),
                &[],
                dir.path(),
                &[],
                b"",
            )
            .is_err());

        let mut expired = Broker::new(policy());
        let mut opening = request();
        opening.ttl = Duration::from_secs(0);
        assert!(expired.open_job(opening).is_err());
        let mut opening = request();
        opening.ttl = Duration::from_secs(1);
        let expired_grant = open_with_worker(&mut expired, opening);
        assert_ne!(grant.job_id, expired_grant.job_id);
        assert_ne!(grant.token, expired_grant.token);
        std::thread::sleep(Duration::from_millis(1010));
        assert!(expired
            .exec(
                &expired_grant.job_id,
                &expired_grant.token,
                7,
                "cmd-9",
                Path::new("/bin/cat"),
                &[],
                dir.path(),
                &[],
                b"",
            )
            .is_err());

        broker
            .complete(&grant.job_id, &grant.token)
            .expect("complete");
        assert!(broker.complete(&grant.job_id, &grant.token).is_err());
        assert!(broker
            .exec(
                &grant.job_id,
                &grant.token,
                7,
                "cmd-3",
                Path::new("/bin/cat"),
                &[],
                dir.path(),
                &[],
                b"",
            )
            .is_err());
    }

    #[test]
    fn installed_cask_verification_rejects_unknown_uninstalled_pinned_and_untrusted_casks() {
        let policy = policy();
        assert!(verify_installed_cask("other", r#"{"casks":[]}"#, &policy).is_err());
        assert!(verify_installed_cask(
            "anydesk",
            r#"{"casks":[{"token":"anydesk","tap":"homebrew/cask","installed":null}]}"#,
            &policy
        )
        .is_err());
        assert!(verify_installed_cask(
            "anydesk",
            r#"{"casks":[{"token":"anydesk","tap":"homebrew/cask","installed":"9.7.0","pinned":true}]}"#,
            &policy
        )
        .is_err());
        assert!(verify_installed_cask(
            "anydesk",
            r#"{"casks":[{"token":"anydesk","tap":"evil/tap","installed":"9.7.0"}]}"#,
            &policy
        )
        .is_err());
    }

    #[test]
    fn broker_audit_omits_capabilities_and_records_job_provenance() {
        let mut broker = Broker::new(policy());
        let grant = open_with_worker(&mut broker, request());
        let audit = broker.audit();
        assert_eq!(audit.len(), 1);
        assert_eq!(audit[0].job_id, grant.job_id);
        assert_eq!(audit[0].cask, "anydesk");
        assert_eq!(audit[0].source, "homebrew/cask");
        assert!(audit[0].worker_bound);
        assert_eq!(audit[0].command_count, 0);
        assert!(!format!("{audit:?}").contains(&grant.token));
    }

    #[test]
    fn broker_audit_is_persisted_without_capability_tokens() {
        let dir = tempfile::tempdir().expect("audit directory");
        let path = dir.path().join("broker-audit.json");
        let mut broker = Broker::with_audit(policy(), path.clone());
        let grant = open_with_worker(&mut broker, request());
        broker
            .complete(&grant.job_id, &grant.token)
            .expect("complete job");
        let contents = std::fs::read_to_string(path).expect("persisted audit");
        assert!(contents.contains("anydesk"));
        assert!(contents.contains("homebrew/cask"));
        assert!(contents.contains("\"completed\": true"));
        assert!(!contents.contains(&grant.token));
    }

    #[test]
    fn client_submission_handles_are_private_durable_and_bound_to_the_queued_job() {
        use std::os::unix::fs::MetadataExt;

        let dir = tempfile::tempdir().expect("broker state directory");
        let audit_path = dir.path().join("broker-audit.json");
        let submissions_path = dir.path().join("broker-client-submissions.json");
        let client = Pairing {
            signing_identity: "Developer ID Application: Client (TEAM)".to_string(),
            bundle_identifier: "com.example.client".to_string(),
            protocol_version: crate::control::PROTOCOL_VERSION,
            active: true,
        };
        let mut broker = Broker::with_audit(policy(), audit_path.clone());
        broker.pair(client.clone()).expect("enroll client");
        let handle = broker
            .issue_client_submission_handle(
                &client,
                "queued-request",
                "mbrew",
                Some("retry_pending"),
            )
            .expect("authorize queued work");
        assert_eq!(
            broker
                .issue_client_submission_handle(
                    &client,
                    "queued-request",
                    "mbrew",
                    Some("retry_pending"),
                )
                .expect("idempotent authorization"),
            handle
        );
        assert!(broker
            .begin_client_submission_run(
                &handle,
                "edited-request",
                "mbrew",
                Some("retry_pending"),
            )
            .is_err());
        let run_handle = broker
            .begin_client_submission_run(
                &handle,
                "queued-request",
                "mbrew",
                Some("retry_pending"),
            )
            .expect("claim the submission run");
        assert!(broker
            .begin_client_submission_run(
                &handle,
                "queued-request",
                "mbrew",
                Some("retry_pending"),
            )
            .is_err());
        for _ in 0..2 {
            assert_eq!(
                broker
                    .resolve_client_submission_run(
                        &run_handle,
                        "queued-request",
                        "mbrew",
                        Some("retry_pending"),
                    )
                    .expect("same accepted run can open another cask operation"),
                client
            );
        }

        let public_audit = std::fs::read_to_string(&audit_path).expect("public broker audit");
        assert!(!public_audit.contains(&handle));
        assert!(!public_audit.contains(&run_handle));
        let private_state =
            std::fs::read_to_string(&submissions_path).expect("private handle store");
        assert!(private_state.contains(&handle));
        assert!(private_state.contains(&run_handle));
        let mode = std::fs::metadata(&submissions_path)
            .expect("private handle store metadata")
            .mode();
        assert_eq!(
            mode & 0o077,
            0,
            "untrusted users cannot read the handle store"
        );

        drop(broker);
        let mut loaded =
            Broker::load_with_audit_owner(policy(), audit_path, unsafe { libc::geteuid() })
                .expect("reload protected client handles");
        assert!(loaded
            .begin_client_submission_run(
                &handle,
                "queued-request",
                "mbrew",
                Some("retry_pending"),
            )
            .is_err(), "a broker restart must not reopen an interrupted run");
        assert!(loaded
            .resolve_client_submission_run(
                &run_handle,
                "queued-request",
                "mbrew",
                Some("retry_pending"),
            )
            .is_err(), "the prior run capability is invalid after restart");
    }

    #[test]
    fn completed_and_interrupted_submissions_stay_spent_after_restart() {
        let dir = tempfile::tempdir().expect("broker state directory");
        let audit_path = dir.path().join("broker-audit.json");
        let client = Pairing {
            signing_identity: "Developer ID Application: Client (TEAM)".to_string(),
            bundle_identifier: "com.example.client".to_string(),
            protocol_version: crate::control::PROTOCOL_VERSION,
            active: true,
        };
        let mut broker = Broker::with_audit(policy(), audit_path.clone());
        broker.pair(client.clone()).expect("enroll client");

        let mut spent = Vec::new();
        for (job_id, completed) in [("completed-job", true), ("interrupted-job", false)] {
            let handle = broker
                .issue_client_submission_handle(&client, job_id, "mbrew", None)
                .expect("issue client submission");
            let run_handle = broker
                .begin_client_submission_run(&handle, job_id, "mbrew", None)
                .expect("dispatch submission");
            broker
                .finish_client_submission_run(
                    &run_handle,
                    job_id,
                    "mbrew",
                    None,
                    completed,
                )
                .expect("persist terminal submission state");
            assert!(broker
                .begin_client_submission_run(&handle, job_id, "mbrew", None)
                .is_err(), "a terminal submission cannot be dispatched again");
            spent.push((handle, run_handle, job_id));
        }

        drop(broker);
        let mut restarted = Broker::load_with_audit_owner(
            policy(),
            audit_path,
            unsafe { libc::geteuid() },
        )
        .expect("reload durable submission states");
        for (handle, run_handle, job_id) in spent {
            assert!(restarted
                .begin_client_submission_run(&handle, job_id, "mbrew", None)
                .is_err(), "requeueing a spent job must not dispatch it again");
            assert!(restarted
                .resolve_client_submission_run(&run_handle, job_id, "mbrew", None)
                .is_err(), "terminal run capabilities must not open new work");
        }
    }

    #[test]
    fn pairing_state_and_transitions_are_durable_and_audit_failure_fails_closed() {
        let dir = tempfile::tempdir().expect("audit directory");
        let path = dir.path().join("broker-audit.json");
        let mut broker = Broker::with_audit(policy(), path.clone());
        let pairing = Pairing {
            signing_identity: "Developer ID Application: Client (TEAM)".to_string(),
            bundle_identifier: "com.example.client".to_string(),
            protocol_version: crate::control::PROTOCOL_VERSION,
            active: true,
        };
        broker.pair(pairing.clone()).expect("persist enrollment");
        broker
            .unpair(&pairing.bundle_identifier)
            .expect("persist revocation");

        let loaded =
            Broker::load_with_audit_owner(policy(), path.clone(), unsafe { libc::geteuid() })
                .expect("reload durable pairing state");
        assert!(!loaded.is_paired(&pairing.bundle_identifier));
        assert_eq!(loaded.pairing_events.len(), 2);
        assert_eq!(loaded.pairing_events[0].transition, "paired");
        assert_eq!(loaded.pairing_events[1].transition, "revoked");
        assert_eq!(
            loaded.pairing_events[0].authorizing_principal,
            "Developer ID Application: Client (TEAM) (com.example.client)"
        );

        let blocked_path = dir.path().join("missing").join("audit.json");
        let mut blocked = Broker::with_audit(policy(), blocked_path);
        assert!(blocked.pair(pairing.clone()).is_err());
        assert!(!blocked.is_paired(&pairing.bundle_identifier));

        let mut revoke_blocked = Broker::new(policy());
        revoke_blocked
            .pair(pairing.clone())
            .expect("in-memory enrollment");
        revoke_blocked.audit_path = Some(dir.path().join("absent").join("revoke.json"));
        assert!(revoke_blocked.unpair(&pairing.bundle_identifier).is_err());
        assert!(revoke_blocked.is_paired(&pairing.bundle_identifier));
    }

    #[test]
    fn signer_replacement_requires_an_explicit_revocation_and_is_audited() {
        let dir = tempfile::tempdir().expect("audit directory");
        let path = dir.path().join("broker-audit.json");
        let mut broker = Broker::with_audit(policy(), path);
        let client = Pairing {
            signing_identity: "Developer ID Application: Old (TEAM)".to_string(),
            bundle_identifier: "com.example.client".to_string(),
            protocol_version: crate::control::PROTOCOL_VERSION,
            active: true,
        };
        broker.pair(client.clone()).expect("enroll first signer");
        let impostor = Pairing {
            signing_identity: "Developer ID Application: New (TEAM)".to_string(),
            bundle_identifier: client.bundle_identifier.clone(),
            protocol_version: client.protocol_version,
            active: true,
        };
        assert!(broker
            .pair_authorized(
                impostor.clone(),
                &impostor.signing_identity,
                "Developer ID Application: New (TEAM) (com.example.client)",
            )
            .is_err());
        assert!(broker
            .unpair_authorized(
                &client.bundle_identifier,
                &impostor.signing_identity,
                "Developer ID Application: New (TEAM) (com.example.client)",
            )
            .is_err());
        assert_eq!(
            broker
                .pairing("com.example.client")
                .unwrap()
                .signing_identity,
            "Developer ID Application: Old (TEAM)"
        );
        broker
            .unpair("com.example.client")
            .expect("explicitly revoke old signer");
        broker
            .pair(impostor)
            .expect("enroll replacement signer after revocation");
        assert_eq!(broker.pairing_events[2].transition, "replaced");
    }

    #[test]
    fn preserves_arguments_and_working_directory() {
        let mut broker = Broker::new(policy());
        let grant = open_with_worker(&mut broker, request());
        let dir = tempfile::tempdir().expect("dir");
        std::fs::write(dir.path().join("note.txt"), b"from-cwd").expect("fixture");
        let output = broker
            .exec(
                &grant.job_id,
                &grant.token,
                7,
                "read-note",
                Path::new("/bin/cat"),
                &["note.txt".to_string()],
                dir.path(),
                &[],
                b"",
            )
            .expect("exec");
        assert_eq!(output.status, 0);
        assert_eq!(output.stdout, b"from-cwd");
    }

    #[test]
    fn forwards_large_stdin_while_draining_child_output() {
        let mut broker = Broker::new(policy());
        let grant = open_with_worker(&mut broker, request());
        let dir = tempfile::tempdir().expect("dir");
        let input = vec![b'x'; 1024 * 1024];
        let output = broker
            .exec(
                &grant.job_id,
                &grant.token,
                7,
                "large-stdin",
                Path::new("/bin/cat"),
                &[],
                dir.path(),
                &[],
                &input,
            )
            .expect("exec");
        assert_eq!(output.status, 0);
        assert_eq!(output.stdout, input);
    }

    #[test]
    fn a_failed_privileged_command_id_cannot_be_replayed() {
        let mut broker = Broker::new(policy());
        let grant = open_with_worker(&mut broker, request());
        let dir = tempfile::tempdir().expect("dir");
        assert!(broker
            .exec(
                &grant.job_id,
                &grant.token,
                7,
                "one-shot",
                Path::new("/path/that/does/not/exist"),
                &[],
                dir.path(),
                &[],
                b"",
            )
            .is_err());
        assert!(broker
            .exec(
                &grant.job_id,
                &grant.token,
                7,
                "one-shot",
                Path::new("/bin/cat"),
                &[],
                dir.path(),
                &[],
                b"replay",
            )
            .is_err());
    }

    #[test]
    fn incompatible_homebrew_runner_is_visible() {
        assert!(!bridge_compatible("def sudo_prefix\n"));
        assert!(!bridge_compatible("def command_prefix\n"));
    }
}
