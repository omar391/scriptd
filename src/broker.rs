use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
#[cfg(test)]
use std::os::unix::fs::PermissionsExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, SystemTime};

use anyhow::{bail, Context, Result};
use serde::Deserialize;

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
    if repo.join(".git").is_file() {
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
    pub cask: String,
    pub source: String,
    pub completed: bool,
    pub worker_bound: bool,
    pub command_count: usize,
}

#[derive(Debug, Default)]
pub struct Broker {
    policy: Policy,
    audit_path: Option<std::path::PathBuf>,
    jobs: BTreeMap<String, Job>,
    spent_tokens: HashSet<String>,
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
        Self {
            policy,
            audit_path: Some(audit_path),
            ..Self::default()
        }
    }

    #[cfg(test)]
    pub fn open_job(&mut self, request: OpenRequest) -> Result<Grant> {
        self.open_job_from(request, 0)
    }

    pub fn open_job_from(&mut self, request: OpenRequest, owner_pid: u32) -> Result<Grant> {
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
        token: &str,
        info_json: &str,
        ttl: Duration,
    ) -> Result<Grant> {
        let cask = verify_installed_cask(token, info_json, &self.policy)?;
        self.open_job_from(
            OpenRequest {
                caller_uid,
                cask,
                ttl,
            },
            owner_pid,
        )
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
        self.jobs
            .iter()
            .map(|(job_id, job)| JobAudit {
                job_id: job_id.clone(),
                cask: job.cask.clone(),
                source: job.source.clone(),
                completed: job.completed,
                worker_bound: job.worker_pid.is_some(),
                command_count: job.seen_commands.len(),
            })
            .collect()
    }

    fn persist_audit(&self) -> Result<()> {
        let Some(path) = self.audit_path.as_deref() else {
            return Ok(());
        };
        crate::paths::write_private_atomic(
            path,
            serde_json::to_string_pretty(&self.audit())?.as_bytes(),
        )
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
