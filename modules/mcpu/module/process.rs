use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Component, Path};
use std::process::Command;
use std::time::{Duration, Instant, SystemTime};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sysinfo::{Pid, ProcessesToUpdate, System};

pub(super) const CPU_THRESHOLD: f32 = 50.0;
pub(super) const MAX_SAMPLE_GAP: Duration = Duration::from_secs(90);
const MAX_ANCESTRY_DEPTH: usize = 64;
const NO_TTY_DEVICE: u32 = u32::MAX;
const PROC_FLAG_SLEADER: u32 = 0x20;
const PROC_FLAG_CTTY: u32 = 0x40;
const PROC_FLAG_CONTROLT: u32 = 0x80;
const PROC_TTY_FLAGS: u32 = PROC_FLAG_CTTY | PROC_FLAG_CONTROLT;

fn has_verified_no_controlling_terminal(
    tty_device: u32,
    tty_process_group: u32,
    flags: u32,
) -> bool {
    tty_device == NO_TTY_DEVICE && tty_process_group == 0 && flags & PROC_TTY_FLAGS == 0
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub(super) struct ProcessIdentity {
    pub pid: u32,
    pub pid_version: u32,
    pub start_seconds: u64,
    pub start_microseconds: u64,
    pub executable: String,
    pub user_id: u32,
    pub fingerprint: String,
    pub code_directory_hash: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub(super) struct UiHelperIdentity {
    pub pid: u32,
    pub pid_version: u32,
    pub start_seconds: u64,
    pub start_microseconds: u64,
    pub user_id: u32,
    pub executable: String,
}

#[derive(Clone, Debug)]
pub(super) struct Candidate {
    pub identity: ProcessIdentity,
    pub name: String,
    pub cpu_percent: f32,
    pub memory_bytes: u64,
    pub reason: String,
    pub ownership: OwnershipKind,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum OwnershipKind {
    Orphaned,
    LaunchdOwned,
    ActiveOwner,
}

struct OwnershipAssessment {
    kind: OwnershipKind,
    reason: String,
}

#[derive(Debug)]
pub(super) struct Snapshot {
    pub at: Instant,
    pub wall_at: SystemTime,
    pub warmed: bool,
    pub discontinuity: bool,
    pub candidates: Vec<Candidate>,
    pub protected_high_cpu: u64,
    pub protection_error: Option<String>,
}

#[derive(Debug)]
struct SampleClock {
    monotonic: Instant,
    wall: SystemTime,
}

fn sample_clock_discontinuous(monotonic_elapsed: Duration, wall_elapsed: Duration) -> bool {
    let skew = wall_elapsed.abs_diff(monotonic_elapsed);
    monotonic_elapsed > MAX_SAMPLE_GAP || skew > Duration::from_secs(3)
}

pub(super) struct CpuSampler {
    system: System,
    previous: Option<SampleClock>,
}

impl Default for CpuSampler {
    fn default() -> Self {
        Self {
            system: System::new_all(),
            previous: None,
        }
    }
}

impl CpuSampler {
    pub fn reset(&mut self) {
        self.system = System::new_all();
        self.previous = None;
    }

    pub fn sample(&mut self, exclude_apps: &[String], configured_threshold: f32) -> Snapshot {
        self.sample_with_service_query(exclude_apps, configured_threshold, launchd_service_pids)
    }

    fn sample_with_service_query<F>(
        &mut self,
        exclude_apps: &[String],
        configured_threshold: f32,
        query_service_pids: F,
    ) -> Snapshot
    where
        F: FnOnce() -> Result<HashSet<u32>>,
    {
        let now = Instant::now();
        let wall_now = SystemTime::now();
        let previous = self.previous.take();
        let discontinuity = previous.as_ref().is_some_and(|clock| {
            let monotonic = now.saturating_duration_since(clock.monotonic);
            let wall = wall_now
                .duration_since(clock.wall)
                .unwrap_or_else(|error| error.duration());
            sample_clock_discontinuous(monotonic, wall)
        });
        let warmed = previous.is_some() && !discontinuity;
        if discontinuity {
            self.system = System::new_all();
        }
        self.system.refresh_processes(ProcessesToUpdate::All, true);
        self.previous = Some(SampleClock {
            monotonic: now,
            wall: wall_now,
        });

        if !warmed {
            return Snapshot {
                at: now,
                wall_at: wall_now,
                warmed: false,
                discontinuity,
                candidates: Vec::new(),
                protected_high_cpu: 0,
                protection_error: None,
            };
        }

        let mut candidates = Vec::new();
        let mut protected_high_cpu = 0;
        let processes = self
            .system
            .processes()
            .iter()
            .filter(|(_, process)| process.cpu_usage() > configured_threshold.max(CPU_THRESHOLD))
            .filter_map(|(pid, process)| {
                if exclude_apps.iter().any(|excluded| {
                    excluded.eq_ignore_ascii_case(&process.name().to_string_lossy())
                }) {
                    protected_high_cpu += 1;
                    None
                } else {
                    Some((*pid, process))
                }
            })
            .collect::<Vec<_>>();

        if processes.is_empty() {
            return Snapshot {
                at: now,
                wall_at: wall_now,
                warmed: true,
                discontinuity: false,
                candidates,
                protected_high_cpu,
                protection_error: None,
            };
        }

        let service_pids = match query_service_pids() {
            Ok(pids) => pids,
            Err(error) => {
                return Snapshot {
                    at: now,
                    wall_at: wall_now,
                    warmed: true,
                    discontinuity: false,
                    candidates: Vec::new(),
                    protected_high_cpu,
                    protection_error: Some(error.to_string()),
                };
            }
        };

        for (pid, process) in processes {
            match classify_process(&self.system, pid.as_u32(), process, &service_pids) {
                Ok(candidate) => candidates.push(candidate),
                Err(_) => protected_high_cpu += 1,
            }
        }

        Snapshot {
            at: now,
            wall_at: wall_now,
            warmed: true,
            discontinuity: false,
            candidates,
            protected_high_cpu,
            protection_error: None,
        }
    }
}

pub(super) fn verify_current_identity(
    expected: &ProcessIdentity,
    exclude_apps: &[String],
) -> std::result::Result<(), CleanupCheckError> {
    verify_current_identity_inner(expected, exclude_apps, || {}, || {}, || {})
}

#[derive(Debug)]
pub(super) enum CleanupCheckError {
    Shared(anyhow::Error),
    Candidate(anyhow::Error),
}

fn verify_current_identity_inner<F, G, H>(
    expected: &ProcessIdentity,
    exclude_apps: &[String],
    after_executable_verification: F,
    after_initial_process_group_snapshot: G,
    after_final_process_group_snapshot: H,
) -> std::result::Result<(), CleanupCheckError>
where
    F: FnOnce(),
    G: FnOnce(),
    H: FnOnce(),
{
    let mut system = System::new_all();
    system.refresh_processes(ProcessesToUpdate::All, true);
    let service_pids = launchd_service_pids().map_err(CleanupCheckError::Shared)?;
    let process = system
        .process(Pid::from_u32(expected.pid))
        .context("process exited before signal")
        .map_err(CleanupCheckError::Candidate)?;
    let current = classify_process(&system, expected.pid, process, &service_pids)
        .map_err(|error| CleanupCheckError::Candidate(anyhow::Error::msg(error)))?;
    if current.identity != *expected {
        return Err(CleanupCheckError::Candidate(anyhow::anyhow!(
            "process identity or executable fingerprint changed"
        )));
    }
    if exclude_apps
        .iter()
        .any(|excluded| excluded.eq_ignore_ascii_case(&current.name))
    {
        return Err(CleanupCheckError::Candidate(anyhow::anyhow!(
            "process is explicitly excluded by name"
        )));
    }

    // Tests use this boundary to model a process acquiring a child while code
    // signature verification is in progress.
    after_executable_verification();

    // Code-signature verification can invoke external tooling. Refresh process
    // and service evidence after that work, then avoid another expensive
    // executable verification before the final child check.
    system.refresh_processes(ProcessesToUpdate::All, true);
    let service_pids = launchd_service_pids().map_err(CleanupCheckError::Shared)?;
    let process = system
        .process(Pid::from_u32(expected.pid))
        .context("process exited during immediate cleanup verification")
        .map_err(CleanupCheckError::Candidate)?;
    let fresh_info = process_info(expected.pid).map_err(CleanupCheckError::Candidate)?;
    if fresh_info.pid_version != expected.pid_version
        || fresh_info.start_seconds != expected.start_seconds
        || fresh_info.start_microseconds != expected.start_microseconds
        || fresh_info.user_id != expected.user_id
        || process.start_time() != expected.start_seconds
        || process
            .exe()
            .and_then(|path| path.canonicalize().ok())
            .is_none_or(|path| path.to_string_lossy() != expected.executable)
    {
        return Err(CleanupCheckError::Candidate(anyhow::anyhow!(
            "process identity or executable changed during cleanup verification"
        )));
    }
    if exclude_apps
        .iter()
        .any(|excluded| excluded.eq_ignore_ascii_case(&process.name().to_string_lossy()))
    {
        return Err(CleanupCheckError::Candidate(anyhow::anyhow!(
            "process became explicitly excluded by name"
        )));
    }
    is_cleanup_eligible_after_process_group_snapshot(
        &mut system,
        expected,
        &service_pids,
        after_initial_process_group_snapshot,
        after_final_process_group_snapshot,
    )?;
    Ok(())
}

fn classify_process(
    system: &System,
    pid: u32,
    process: &sysinfo::Process,
    service_pids: &HashSet<u32>,
) -> std::result::Result<Candidate, String> {
    classify_process_with_evidence(
        system,
        pid,
        process,
        service_pids,
        &LiveProcessOwnershipEvidence,
    )
}

trait ProcessOwnershipEvidence {
    fn process_info(&self, pid: u32) -> std::result::Result<ProcessInfo, String>;

    fn parent_pid(&self, system: &System, pid: u32) -> Option<u32>;

    fn verified_launchd_parent_unique_id(
        &self,
        system: &System,
        service_pids: &HashSet<u32>,
        launchd_pid: u32,
    ) -> Option<u64>;
}

struct LiveProcessOwnershipEvidence;

impl ProcessOwnershipEvidence for LiveProcessOwnershipEvidence {
    fn process_info(&self, pid: u32) -> std::result::Result<ProcessInfo, String> {
        process_info(pid).map_err(|error| error.to_string())
    }

    fn parent_pid(&self, system: &System, pid: u32) -> Option<u32> {
        system
            .process(Pid::from_u32(pid))?
            .parent()
            .map(Pid::as_u32)
    }

    fn verified_launchd_parent_unique_id(
        &self,
        system: &System,
        service_pids: &HashSet<u32>,
        launchd_pid: u32,
    ) -> Option<u64> {
        verified_launchd_parent_unique_id(system, service_pids, launchd_pid)
    }
}

fn classify_process_with_evidence<E: ProcessOwnershipEvidence>(
    system: &System,
    pid: u32,
    process: &sysinfo::Process,
    service_pids: &HashSet<u32>,
    ownership_evidence: &E,
) -> std::result::Result<Candidate, String> {
    let info = ownership_evidence
        .process_info(pid)
        .map_err(|_| "process identity is unavailable".to_string())?;
    if info.pid != pid || info.start_seconds != process.start_time() {
        return Err("process identity changed during sampling".to_string());
    }
    if ownership_evidence.parent_pid(system, pid) != Some(info.parent_pid) {
        return Err("process parent identity is unavailable or inconsistent".to_string());
    }
    let current_uid = unsafe { libc::getuid() };
    if info.user_id != current_uid {
        return Err("process belongs to another user".to_string());
    }

    let executable = process
        .exe()
        .ok_or_else(|| "executable path is unavailable".to_string())?;
    let canonical = executable
        .canonicalize()
        .map_err(|_| "executable path cannot be verified".to_string())?;
    if is_protected_system_path(&canonical) {
        return Err("macOS system executable".to_string());
    }
    if is_inside_app_bundle(&canonical) {
        return Err("desktop application or helper executable".to_string());
    }
    let name = process.name().to_string_lossy().into_owned();
    if is_shared_runtime(&name, &canonical) {
        return Err("shared interpreter, runtime, or build tool".to_string());
    }
    if is_protected_owner_name(&name) {
        return Err("protected system or desktop process".to_string());
    }

    let running_code_hash = code_directory_hash_for_pid(pid)
        .map_err(|_| "running executable code identity is unavailable".to_string())?;
    let verified_file = verified_code_identity_for_file(&canonical)
        .map_err(|_| "on-disk executable code identity is unavailable".to_string())?;
    if running_code_hash != verified_file.code_directory_hash {
        return Err("running executable does not match the on-disk binary".to_string());
    }
    let ownership =
        verify_enrollment_ownership(system, pid, &info, service_pids, ownership_evidence)?;
    Ok(Candidate {
        identity: ProcessIdentity {
            pid,
            pid_version: info.pid_version,
            start_seconds: info.start_seconds,
            start_microseconds: info.start_microseconds,
            executable: canonical.to_string_lossy().into_owned(),
            user_id: info.user_id,
            fingerprint: verified_file.fingerprint,
            code_directory_hash: running_code_hash,
        },
        name,
        cpu_percent: process.cpu_usage(),
        memory_bytes: process.memory(),
        reason: ownership.reason,
        ownership: ownership.kind,
    })
}

fn is_cleanup_eligible(
    system: &mut System,
    expected: &ProcessIdentity,
    service_pids: &HashSet<u32>,
) -> std::result::Result<(), CleanupCheckError> {
    is_cleanup_eligible_after_process_group_snapshot(system, expected, service_pids, || {}, || {})
}

fn is_cleanup_eligible_after_process_group_snapshot<G, H>(
    system: &mut System,
    expected: &ProcessIdentity,
    service_pids: &HashSet<u32>,
    after_initial_process_group_snapshot: G,
    after_final_process_group_snapshot: H,
) -> std::result::Result<(), CleanupCheckError>
where
    G: FnOnce(),
    H: FnOnce(),
{
    let current_uid = unsafe { libc::getuid() };
    let info = process_info(expected.pid).map_err(|error| {
        candidate_cleanup_error(format!("process identity is unavailable: {error}"))
    })?;

    let sampled_process = system
        .process(Pid::from_u32(expected.pid))
        .ok_or_else(|| candidate_cleanup_error("process is absent from the cleanup snapshot"))?;
    if info.pid != expected.pid
        || info.pid_version != expected.pid_version
        || info.start_seconds != expected.start_seconds
        || info.start_microseconds != expected.start_microseconds
        || sampled_process.start_time() != expected.start_seconds
    {
        return Err(candidate_cleanup_error(
            "process generation changed during cleanup checks",
        ));
    }
    if info.user_id != current_uid || info.user_id != expected.user_id {
        return Err(candidate_cleanup_error("process belongs to another user"));
    }
    if system
        .process(Pid::from_u32(expected.pid))
        .and_then(|current| current.parent())
        .map(Pid::as_u32)
        != Some(info.parent_pid)
    {
        return Err(candidate_cleanup_error(
            "process parent changed during cleanup checks",
        ));
    }
    if !has_verified_no_controlling_terminal(info.tty_device, info.tty_process_group, info.flags) {
        return Err(candidate_cleanup_error(
            "process has a controlling terminal",
        ));
    }
    if info.flags & PROC_FLAG_SLEADER != 0 {
        return Err(candidate_cleanup_error("process is a session leader"));
    }
    if info.process_group == expected.pid {
        return Err(candidate_cleanup_error(
            "process is a surviving process-group leader",
        ));
    }
    if service_pids.contains(&expected.pid) {
        return Err(candidate_cleanup_error("process is a registered service"));
    }
    let ownership = verify_enrollment_ownership(
        system,
        expected.pid,
        &info,
        service_pids,
        &LiveProcessOwnershipEvidence,
    )
    .map_err(candidate_cleanup_error)?;
    if ownership.kind != OwnershipKind::Orphaned {
        return Err(candidate_cleanup_error(
            "process no longer has a verified orphaned ownership state",
        ));
    }

    let process_groups = process_group_snapshot().map_err(|error| {
        CleanupCheckError::Shared(error.context("process-group membership is unverifiable"))
    })?;
    verify_singleton_process_group(expected.pid, info.process_group, &process_groups)?;
    after_initial_process_group_snapshot();

    // `ps` is an external process and the process-group snapshot can take long
    // enough for process state to change. Refresh process and service evidence
    // after it, then make the child check the final safety predicate.
    let fresh_service_pids = launchd_service_pids()
        .map_err(|error| CleanupCheckError::Shared(error.context("refresh launchd services")))?;
    system.refresh_processes(ProcessesToUpdate::All, true);
    let fresh_process = system.process(Pid::from_u32(expected.pid)).ok_or_else(|| {
        candidate_cleanup_error("process exited during final cleanup revalidation")
    })?;
    let fresh_info = process_info(expected.pid).map_err(|_| {
        candidate_cleanup_error("process identity is unavailable during final cleanup revalidation")
    })?;
    if fresh_info.pid_version != expected.pid_version
        || fresh_info.start_seconds != expected.start_seconds
        || fresh_info.start_microseconds != expected.start_microseconds
        || fresh_info.user_id != expected.user_id
        || fresh_process.start_time() != expected.start_seconds
        || system
            .process(Pid::from_u32(expected.pid))
            .and_then(|current| current.parent())
            .map(Pid::as_u32)
            != Some(fresh_info.parent_pid)
    {
        return Err(candidate_cleanup_error(
            "process identity changed during final cleanup revalidation",
        ));
    }
    verify_final_process_group(expected.pid, info.process_group, &fresh_info)?;
    if fresh_service_pids.contains(&expected.pid) {
        return Err(candidate_cleanup_error(
            "process became a registered service during cleanup verification",
        ));
    }
    let fresh_ownership = verify_enrollment_ownership(
        system,
        expected.pid,
        &fresh_info,
        &fresh_service_pids,
        &LiveProcessOwnershipEvidence,
    )
    .map_err(candidate_cleanup_error)?;
    if fresh_ownership.kind != OwnershipKind::Orphaned {
        return Err(candidate_cleanup_error(
            "process no longer has a verified orphaned ownership state",
        ));
    }
    if has_direct_child_process(system, expected.pid) {
        return Err(candidate_cleanup_error("process has child workloads"));
    }

    // Service and ownership queries can take long enough for another orphan
    // to join the candidate's group. Take a second, final group snapshot after
    // those queries, then bind it to a fresh process identity before signaling.
    system.refresh_processes(ProcessesToUpdate::All, true);
    if has_direct_child_process(system, expected.pid) {
        return Err(candidate_cleanup_error("process has child workloads"));
    }
    let final_process_groups = process_group_snapshot().map_err(|error| {
        CleanupCheckError::Shared(error.context("final process-group membership is unverifiable"))
    })?;
    after_final_process_group_snapshot();
    let final_info = process_info(expected.pid).map_err(|_| {
        candidate_cleanup_error("process identity is unavailable after final group snapshot")
    })?;
    if final_info.pid != expected.pid
        || final_info.pid_version != expected.pid_version
        || final_info.start_seconds != expected.start_seconds
        || final_info.start_microseconds != expected.start_microseconds
        || final_info.user_id != expected.user_id
        || system
            .process(Pid::from_u32(expected.pid))
            .is_none_or(|current| current.start_time() != expected.start_seconds)
        || system
            .process(Pid::from_u32(expected.pid))
            .and_then(|current| current.parent())
            .map(Pid::as_u32)
            != Some(final_info.parent_pid)
    {
        return Err(candidate_cleanup_error(
            "process identity changed after final group snapshot",
        ));
    }
    verify_final_process_group(expected.pid, info.process_group, &final_info)?;
    verify_singleton_process_group(
        expected.pid,
        final_info.process_group,
        &final_process_groups,
    )?;

    // The final `ps` above is external and can outlast a child-state sample.
    // Refresh the process snapshot after it and keep the leaf predicate last;
    // no external query follows this check before the signal adapter runs.
    system.refresh_processes(ProcessesToUpdate::All, true);
    let final_process = system
        .process(Pid::from_u32(expected.pid))
        .ok_or_else(|| candidate_cleanup_error("process exited during final child revalidation"))?;
    if final_process.start_time() != expected.start_seconds
        || final_process.parent().map(Pid::as_u32) != Some(final_info.parent_pid)
    {
        return Err(candidate_cleanup_error(
            "process identity changed during final child revalidation",
        ));
    }
    if has_direct_child_process(system, expected.pid) {
        return Err(candidate_cleanup_error("process has child workloads"));
    }

    Ok(())
}

fn verify_singleton_process_group(
    expected_pid: u32,
    verified_group: u32,
    process_groups: &HashMap<u32, u32>,
) -> std::result::Result<(), CleanupCheckError> {
    if process_groups.get(&expected_pid) != Some(&verified_group) {
        return Err(candidate_cleanup_error(
            "process group changed during cleanup verification",
        ));
    }
    let members = process_groups
        .iter()
        .filter_map(|(pid, group)| (*group == verified_group).then_some(*pid))
        .collect::<Vec<_>>();
    if members.as_slice() != [expected_pid] {
        return Err(candidate_cleanup_error(
            "process is not alone in its process group",
        ));
    }
    if process_groups.get(&verified_group) == Some(&verified_group) {
        return Err(candidate_cleanup_error(
            "process group still has a surviving group leader",
        ));
    }
    Ok(())
}

fn verify_final_process_group(
    expected_pid: u32,
    verified_group: u32,
    fresh_info: &ProcessInfo,
) -> std::result::Result<(), CleanupCheckError> {
    if fresh_info.pid != expected_pid {
        return Err(candidate_cleanup_error(
            "process identity changed during final process-group verification",
        ));
    }
    if fresh_info.process_group != verified_group {
        return Err(candidate_cleanup_error(
            "process group changed after membership verification",
        ));
    }
    if fresh_info.process_group == expected_pid || fresh_info.flags & PROC_FLAG_SLEADER != 0 {
        return Err(candidate_cleanup_error(
            "process became a session or process-group leader during cleanup verification",
        ));
    }
    if !has_verified_no_controlling_terminal(
        fresh_info.tty_device,
        fresh_info.tty_process_group,
        fresh_info.flags,
    ) {
        return Err(candidate_cleanup_error(
            "process acquired a controlling terminal during cleanup verification",
        ));
    }
    Ok(())
}

fn candidate_cleanup_error(message: impl Into<String>) -> CleanupCheckError {
    CleanupCheckError::Candidate(anyhow::Error::msg(message.into()))
}

fn process_group_snapshot() -> Result<HashMap<u32, u32>> {
    let output = Command::new("/bin/ps")
        .args(["-A", "-o", "pid=,pgid="])
        .output()
        .context("read the current process-group table")?;
    if !output.status.success() {
        anyhow::bail!(
            "ps could not read process groups: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    let mut groups = HashMap::new();
    for line in String::from_utf8_lossy(&output.stdout).lines() {
        let fields = line.split_whitespace().collect::<Vec<_>>();
        if fields.len() != 2 {
            anyhow::bail!("ps returned a malformed process-group row");
        }
        let pid = fields[0]
            .parse::<u32>()
            .context("parse process PID from ps output")?;
        let group = fields[1]
            .parse::<u32>()
            .context("parse process group from ps output")?;
        if pid == 0 || group == 0 || groups.insert(pid, group).is_some() {
            anyhow::bail!("ps returned an invalid or duplicate process-group row");
        }
    }
    if groups.is_empty() {
        anyhow::bail!("ps returned an empty process-group table");
    }
    Ok(groups)
}

fn verify_enrollment_ownership(
    system: &System,
    pid: u32,
    sampled_identity: &ProcessInfo,
    service_pids: &HashSet<u32>,
    ownership_evidence: &impl ProcessOwnershipEvidence,
) -> std::result::Result<OwnershipAssessment, String> {
    let current_uid = unsafe { libc::getuid() };
    let mut current = pid;
    for _ in 0..MAX_ANCESTRY_DEPTH {
        let Some(process) = system.process(Pid::from_u32(current)) else {
            return Err("process ancestry is incomplete".to_string());
        };
        let info = if current == pid {
            sampled_identity.clone()
        } else {
            ownership_evidence
                .process_info(current)
                .map_err(|_| "process ancestry identity is unavailable".to_string())?
        };
        if info.pid != current || info.start_seconds != process.start_time() {
            return Err("process ancestry changed during verification".to_string());
        }
        if current == pid
            && (info.pid_version != sampled_identity.pid_version
                || info.start_microseconds != sampled_identity.start_microseconds
                || info.user_id != sampled_identity.user_id
                || info.parent_pid != sampled_identity.parent_pid
                || info.unique_id != sampled_identity.unique_id
                || info.parent_unique_id != sampled_identity.parent_unique_id
                || info.process_group != sampled_identity.process_group)
        {
            return Err("process identity changed during ancestry verification".to_string());
        }
        if info.user_id != current_uid {
            return Err("process ancestry belongs to another user".to_string());
        }
        if !has_verified_no_controlling_terminal(
            info.tty_device,
            info.tty_process_group,
            info.flags,
        ) {
            return Err("process tree still belongs to a controlling terminal".to_string());
        }
        if service_pids.contains(&current) {
            return Err("process tree is registered with launchd".to_string());
        }
        let name = process.name().to_string_lossy();
        if name.trim().is_empty() || (current != pid && is_protected_owner_name(&name)) {
            return Err("process tree has a protected or unknown owner".to_string());
        }
        let executable = process
            .exe()
            .ok_or_else(|| "process tree executable is unavailable".to_string())?
            .canonicalize()
            .map_err(|_| "process tree executable cannot be verified".to_string())?;
        if is_protected_system_path(&executable)
            || is_inside_app_bundle(&executable)
            || is_shared_runtime(&name, &executable)
        {
            return Err("process tree has a system, desktop, or shared-runtime owner".to_string());
        }

        let parent = ownership_evidence
            .parent_pid(system, current)
            .ok_or_else(|| "process parent is unavailable or unverifiable".to_string())?;
        if info.parent_pid != parent {
            return Err("process ancestry disagrees across identity sources".to_string());
        }
        if parent == 1 {
            let launchd_unique_id = ownership_evidence
                .verified_launchd_parent_unique_id(system, service_pids, parent)
                .ok_or_else(|| "launchd parent identity is unavailable".to_string())?;
            if current != pid {
                return Ok(OwnershipAssessment {
                    kind: OwnershipKind::ActiveOwner,
                    reason: format!("active background owner PID {current} ({name}) remains"),
                });
            }
            let (kind, reason) = if info.parent_unique_id == launchd_unique_id {
                (
                    OwnershipKind::LaunchdOwned,
                    "unregistered process launched by launchd".to_string(),
                )
            } else {
                (
                    OwnershipKind::Orphaned,
                    if info.flags & PROC_FLAG_SLEADER != 0 {
                        "orphaned session leader reparented to launchd".to_string()
                    } else {
                        "orphaned and reparented to launchd".to_string()
                    },
                )
            };
            return Ok(OwnershipAssessment { kind, reason });
        }
        if parent < 1 {
            return Err("process ancestry has an invalid root".to_string());
        }
        let parent_process = system
            .process(Pid::from_u32(parent))
            .ok_or_else(|| "process parent is unavailable from the fresh snapshot".to_string())?;
        let parent_info = ownership_evidence
            .process_info(parent)
            .map_err(|_| "process parent identity is unavailable".to_string())?;
        if parent_info.pid != parent || parent_info.start_seconds != parent_process.start_time() {
            return Err("process parent generation changed during verification".to_string());
        }
        if info.parent_unique_id != parent_info.unique_id {
            return Err("process parent generation does not match the live owner".to_string());
        }
        current = parent;
    }
    Err("process ancestry exceeds the verification limit".to_string())
}

fn verified_launchd_parent_unique_id(
    system: &System,
    service_pids: &HashSet<u32>,
    launchd_pid: u32,
) -> Option<u64> {
    let process = system.process(Pid::from_u32(launchd_pid))?;
    if process.name().to_string_lossy() != "launchd"
        || !is_protected_system_path(&process.exe()?.canonicalize().ok()?)
    {
        return None;
    }
    let launchd_process_unique_id = if launchd_pid == 1 {
        None
    } else {
        Some(process_info(launchd_pid).ok()?.unique_id)
    };
    // Active jobs provide the launchd generation identity even when PID 1 is unreadable.
    for service_pid in service_pids {
        let Ok(service) = process_info(*service_pid) else {
            continue;
        };
        if service.parent_pid != launchd_pid || service.parent_unique_id == 0 {
            continue;
        }
        if launchd_process_unique_id.is_none_or(|unique_id| unique_id == service.parent_unique_id) {
            return Some(service.parent_unique_id);
        }
    }
    None
}

fn has_direct_child_process(system: &System, pid: u32) -> bool {
    system.processes().values().any(|process| {
        process
            .parent()
            .is_some_and(|parent| parent.as_u32() == pid)
    })
}

fn is_protected_owner_name(name: &str) -> bool {
    let value = name.to_ascii_lowercase();
    [
        "terminal",
        "iterm",
        "wezterm",
        "warp",
        "ghostty",
        "alacritty",
        "kitty",
        "cursor",
        "visual studio code",
        "code helper",
        "codex",
        "chatgpt",
        "xcode",
        "textedit",
        "zsh",
        "bash",
        "fish",
        "sh",
        "tmux",
        "screen",
        "sshd",
        "launchd",
        "scriptd",
    ]
    .iter()
    .any(|protected| value == *protected || value.starts_with(&format!("{protected} ")))
}

fn is_shared_runtime(name: &str, path: &Path) -> bool {
    let basename = path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or(name)
        .to_ascii_lowercase();
    let fixed_names = [
        "python",
        "python2",
        "python3",
        "pypy",
        "node",
        "nodejs",
        "bun",
        "deno",
        "ruby",
        "perl",
        "php",
        "java",
        "swift",
        "swift-frontend",
        "osascript",
        "bash",
        "zsh",
        "fish",
        "sh",
        "env",
        "git",
        "cargo",
        "rustc",
        "clang",
        "clang++",
        "gcc",
        "g++",
        "make",
        "ninja",
        "cmake",
        "xcodebuild",
    ];
    fixed_names
        .iter()
        .any(|runtime| basename == *runtime || basename.starts_with(&format!("{runtime}-")))
        || ["python", "pypy", "ruby"]
            .iter()
            .any(|runtime| has_numeric_runtime_suffix(&basename, runtime))
}

fn has_numeric_runtime_suffix(basename: &str, runtime: &str) -> bool {
    let Some(suffix) = basename.strip_prefix(runtime) else {
        return false;
    };
    !suffix.is_empty()
        && suffix
            .bytes()
            .all(|byte| byte.is_ascii_digit() || byte == b'.')
        && suffix.bytes().any(|byte| byte.is_ascii_digit())
}

fn is_inside_app_bundle(path: &Path) -> bool {
    path.components().any(|component| {
        component
            .as_os_str()
            .to_string_lossy()
            .to_ascii_lowercase()
            .ends_with(".app")
    })
}

fn is_protected_system_path(path: &Path) -> bool {
    let components = path.components().collect::<Vec<_>>();
    let Some(Component::RootDir) = components.first() else {
        return true;
    };
    let Some(Component::Normal(first)) = components.get(1) else {
        return true;
    };
    let first = first.to_string_lossy();
    if first == "System" || first == "bin" || first == "sbin" {
        return true;
    }
    if first == "usr" {
        return component_name(components.get(2))
            .is_some_and(|value| matches!(value, "bin" | "sbin" | "libexec"));
    }
    if first == "Library" {
        return component_name(components.get(2)) == Some("Apple");
    }
    false
}

fn component_name<'path>(component: Option<&Component<'path>>) -> Option<&'path str> {
    match component {
        Some(Component::Normal(value)) => value.to_str(),
        _ => None,
    }
}

fn open_executable_file(path: &Path) -> Result<File> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    let file = options.open(path).context("open executable")?;
    let metadata = file.metadata().context("inspect executable")?;
    if !metadata.is_file() {
        anyhow::bail!("executable is not a regular file");
    }
    Ok(file)
}

fn fingerprint_open_file(file: &mut File) -> Result<String> {
    file.seek(SeekFrom::Start(0))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

struct VerifiedCodeIdentity {
    fingerprint: String,
    code_directory_hash: String,
}

#[cfg(target_os = "macos")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ExecutableFileStamp {
    device: u64,
    inode: u64,
    length: u64,
    modified_seconds: i64,
    modified_nanoseconds: i64,
    changed_seconds: i64,
    changed_nanoseconds: i64,
}

#[cfg(target_os = "macos")]
fn executable_file_stamp(metadata: &std::fs::Metadata) -> ExecutableFileStamp {
    use std::os::unix::fs::MetadataExt;

    ExecutableFileStamp {
        device: metadata.dev(),
        inode: metadata.ino(),
        length: metadata.len(),
        modified_seconds: metadata.mtime(),
        modified_nanoseconds: metadata.mtime_nsec(),
        changed_seconds: metadata.ctime(),
        changed_nanoseconds: metadata.ctime_nsec(),
    }
}

#[cfg(target_os = "macos")]
fn code_directory_hash_for_pid(pid: u32) -> Result<String> {
    const CS_OPS_CDHASH: libc::c_uint = 5;
    const CS_CDHASH_LEN: usize = 20;
    let mut hash = [0_u8; CS_CDHASH_LEN];
    let result = unsafe {
        csops(
            pid as libc::pid_t,
            CS_OPS_CDHASH,
            hash.as_mut_ptr().cast(),
            hash.len(),
        )
    };
    if result != 0 {
        anyhow::bail!("csops could not verify the running code signature");
    }
    Ok(hash.iter().map(|byte| format!("{byte:02x}")).collect())
}

#[cfg(target_os = "macos")]
fn verified_code_identity_for_file(path: &Path) -> Result<VerifiedCodeIdentity> {
    let canonical = path.canonicalize().context("canonicalize executable")?;
    let mut file = open_executable_file(&canonical)?;
    let before_metadata = file
        .metadata()
        .context("inspect executable before verification")?;
    let before_stamp = executable_file_stamp(&before_metadata);
    let before_fingerprint = fingerprint_open_file(&mut file)?;

    let verification = Command::new("/usr/bin/codesign")
        .args(["--verify", "--strict", "--all-architectures"])
        .arg(&canonical)
        .output()
        .context("verify executable code signature")?;
    if !verification.status.success() {
        anyhow::bail!(
            "on-disk executable signature verification failed: {}",
            String::from_utf8_lossy(&verification.stderr).trim()
        );
    }

    let output = Command::new("/usr/bin/codesign")
        .args(["-dv", "--verbose=4"])
        .arg(&canonical)
        .output()
        .context("inspect executable code signature")?;
    if !output.status.success() {
        anyhow::bail!("on-disk executable has no verifiable code signature");
    }
    let details = format!(
        "{}\n{}",
        String::from_utf8_lossy(&output.stderr),
        String::from_utf8_lossy(&output.stdout)
    );
    let code_directory_hash = details
        .lines()
        .find_map(|line| line.strip_prefix("CDHash="))
        .map(str::to_ascii_lowercase)
        .filter(|value| value.len() == 40 && value.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .context("codesign did not return a code directory hash")?;

    let after_fingerprint = fingerprint_open_file(&mut file)?;
    let after_metadata = file
        .metadata()
        .context("inspect executable after verification")?;
    let path_metadata = std::fs::metadata(&canonical).context("reinspect executable path")?;
    let after_stamp = executable_file_stamp(&after_metadata);
    let path_stamp = executable_file_stamp(&path_metadata);
    if before_stamp != after_stamp
        || before_fingerprint != after_fingerprint
        || after_stamp != path_stamp
    {
        anyhow::bail!("executable changed while its signature and fingerprint were verified");
    }

    Ok(VerifiedCodeIdentity {
        fingerprint: after_fingerprint,
        code_directory_hash,
    })
}

pub(super) fn capture_ui_helper_identity(
    pid: u32,
    expected_executable: &Path,
) -> Result<UiHelperIdentity> {
    let info = process_info(pid)?;
    if info.user_id != unsafe { libc::getuid() } {
        anyhow::bail!("enrollment helper belongs to another user");
    }
    let mut system = System::new_all();
    system.refresh_processes(ProcessesToUpdate::All, true);
    let process = system
        .process(Pid::from_u32(pid))
        .context("enrollment helper is no longer running")?;
    if process.start_time() != info.start_seconds {
        anyhow::bail!("enrollment helper PID was reused");
    }
    let executable = process
        .exe()
        .context("enrollment helper executable is unknown")?
        .canonicalize()
        .context("canonicalize enrollment helper executable")?;
    let expected_executable = expected_executable
        .canonicalize()
        .context("canonicalize expected enrollment executable")?;
    if executable != expected_executable
        || executable.file_name().and_then(|value| value.to_str()) != Some("McpuEnrollment")
        || !is_private_ui_bundle_executable(&executable)
    {
        anyhow::bail!("heartbeat PID is not the private native enrollment helper");
    }
    Ok(UiHelperIdentity {
        pid,
        pid_version: info.pid_version,
        start_seconds: info.start_seconds,
        start_microseconds: info.start_microseconds,
        user_id: info.user_id,
        executable: executable.to_string_lossy().into_owned(),
    })
}

#[cfg(target_os = "macos")]
fn is_private_ui_bundle_executable(executable: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;

    let uid = unsafe { libc::getuid() };
    let Some(app) = executable.ancestors().nth(3) else {
        return false;
    };
    let contents = app.join("Contents");
    let macos = contents.join("MacOS");
    let secure_directory = |path: &Path| {
        std::fs::symlink_metadata(path).is_ok_and(|metadata| {
            metadata.is_dir()
                && !metadata.file_type().is_symlink()
                && metadata.uid() == uid
                && metadata.mode() & 0o077 == 0
        })
    };
    std::fs::symlink_metadata(executable).is_ok_and(|metadata| {
        metadata.is_file()
            && !metadata.file_type().is_symlink()
            && metadata.uid() == uid
            && metadata.mode() & 0o077 == 0
            && metadata.mode() & 0o100 != 0
    }) && secure_directory(app)
        && secure_directory(&contents)
        && secure_directory(&macos)
}

#[cfg(not(target_os = "macos"))]
fn is_private_ui_bundle_executable(_executable: &Path) -> bool {
    false
}

#[cfg(not(target_os = "macos"))]
fn code_directory_hash_for_pid(_pid: u32) -> Result<String> {
    anyhow::bail!("running code identity is supported only on macOS")
}

#[cfg(not(target_os = "macos"))]
fn verified_code_identity_for_file(_path: &Path) -> Result<VerifiedCodeIdentity> {
    anyhow::bail!("on-disk code identity is supported only on macOS")
}

fn launchd_service_pids() -> Result<HashSet<u32>> {
    let mut pids = HashSet::new();
    let uid = unsafe { libc::getuid() };
    for domain in [
        "system".to_string(),
        format!("user/{uid}"),
        format!("gui/{uid}"),
    ] {
        let output = Command::new("/bin/launchctl")
            .args(["print", &domain])
            .output()
            .with_context(|| format!("query launchd service domain {domain}"))?;
        if !output.status.success() {
            anyhow::bail!(
                "launchd service domain {domain} is unavailable: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            );
        }
        if output.stdout.len() > 2 * 1024 * 1024 {
            anyhow::bail!("launchd service domain {domain} output exceeded its bound");
        }
        let listing = std::str::from_utf8(&output.stdout)
            .with_context(|| format!("decode launchd service domain {domain}"))?;
        pids.extend(service_pids_from_domain_listing(listing)?);
    }
    Ok(pids)
}

fn service_pids_from_domain_listing(listing: &str) -> Result<HashSet<u32>> {
    let mut pids = HashSet::new();
    let mut in_services = false;
    let mut found_services = false;
    for line in listing.lines() {
        let trimmed = line.trim();
        if !in_services {
            if trimmed == "services = {" {
                if found_services {
                    anyhow::bail!("launchd domain contains duplicate service tables");
                }
                found_services = true;
                in_services = true;
            }
            continue;
        }
        if trimmed == "}" {
            in_services = false;
            continue;
        }
        if trimmed.is_empty() {
            anyhow::bail!("launchd service table contains an empty record");
        }
        let mut fields = trimmed.split_whitespace();
        let pid = fields
            .next()
            .and_then(|field| field.parse::<u32>().ok())
            .context("launchd service record has no valid PID")?;
        if fields.next().is_none() || fields.next().is_none() {
            anyhow::bail!("launchd service record is incomplete");
        }
        if pid != 0 {
            pids.insert(pid);
        }
    }
    if !found_services || in_services {
        anyhow::bail!("launchd service table is missing or incomplete");
    }
    Ok(pids)
}

#[cfg(target_os = "macos")]
#[derive(Default)]
#[repr(C)]
struct ProcBsdInfo {
    flags: u32,
    status: u32,
    exit_status: u32,
    pid: u32,
    parent_pid: u32,
    user_id: u32,
    group_id: u32,
    real_user_id: u32,
    real_group_id: u32,
    saved_user_id: u32,
    saved_group_id: u32,
    reserved: u32,
    command: [libc::c_char; 16],
    name: [libc::c_char; 32],
    open_files: u32,
    process_group: u32,
    job_control_count: u32,
    tty_device: u32,
    tty_process_group: u32,
    nice: i32,
    start_seconds: u64,
    start_microseconds: u64,
}

#[cfg(target_os = "macos")]
#[derive(Default)]
#[repr(C)]
struct ProcUniqueIdentifierInfo {
    executable_uuid: [u8; 16],
    unique_id: u64,
    // The kernel preserves the creator's unique ID when a process is reparented.
    parent_unique_id: u64,
    pid_version: i32,
    reserved_2: u32,
    reserved_3: u64,
    reserved_4: u64,
}

#[cfg(target_os = "macos")]
#[derive(Default)]
#[repr(C)]
struct ProcBsdInfoWithUniqueId {
    bsd: ProcBsdInfo,
    unique: ProcUniqueIdentifierInfo,
}

#[cfg(target_os = "macos")]
#[derive(Clone, Default)]
struct ProcessInfo {
    pid: u32,
    pid_version: u32,
    unique_id: u64,
    parent_unique_id: u64,
    parent_pid: u32,
    user_id: u32,
    process_group: u32,
    flags: u32,
    tty_device: u32,
    tty_process_group: u32,
    start_seconds: u64,
    start_microseconds: u64,
}

#[cfg(target_os = "macos")]
#[link(name = "proc")]
extern "C" {
    fn proc_pidinfo(
        pid: libc::c_int,
        flavor: libc::c_int,
        arg: u64,
        buffer: *mut libc::c_void,
        buffersize: libc::c_int,
    ) -> libc::c_int;
}

#[cfg(target_os = "macos")]
#[link(name = "System")]
extern "C" {
    fn csops(
        pid: libc::pid_t,
        operation: libc::c_uint,
        user_address: *mut libc::c_void,
        user_size: libc::size_t,
    ) -> libc::c_int;
}

#[cfg(target_os = "macos")]
fn process_info(pid: u32) -> Result<ProcessInfo> {
    let mut info = ProcBsdInfoWithUniqueId::default();
    // Flavor 18 returns BSD identity and pidversion in one private libproc call.
    // The pidversion is then checked atomically by proc_signal_with_audittoken.
    let copied = unsafe {
        proc_pidinfo(
            pid as libc::c_int,
            18,
            0,
            (&mut info as *mut ProcBsdInfoWithUniqueId).cast(),
            std::mem::size_of::<ProcBsdInfoWithUniqueId>() as libc::c_int,
        )
    };
    if copied != std::mem::size_of::<ProcBsdInfoWithUniqueId>() as libc::c_int
        || info.bsd.pid != pid
        || info.unique.unique_id == 0
        || info.unique.pid_version <= 0
    {
        anyhow::bail!("libproc could not verify PID {pid}");
    }
    Ok(ProcessInfo {
        pid: info.bsd.pid,
        pid_version: info.unique.pid_version as u32,
        unique_id: info.unique.unique_id,
        parent_unique_id: info.unique.parent_unique_id,
        parent_pid: info.bsd.parent_pid,
        user_id: info.bsd.user_id,
        process_group: info.bsd.process_group,
        flags: info.bsd.flags,
        tty_device: info.bsd.tty_device,
        tty_process_group: info.bsd.tty_process_group,
        start_seconds: info.bsd.start_seconds,
        start_microseconds: info.bsd.start_microseconds,
    })
}

#[cfg(not(target_os = "macos"))]
fn process_info(_pid: u32) -> Result<ProcessInfo> {
    anyhow::bail!("process identity is supported only on macOS")
}

#[cfg(not(target_os = "macos"))]
#[derive(Clone, Default)]
struct ProcessInfo {
    pid: u32,
    pid_version: u32,
    unique_id: u64,
    parent_unique_id: u64,
    parent_pid: u32,
    user_id: u32,
    process_group: u32,
    flags: u32,
    tty_device: u32,
    tty_process_group: u32,
    start_seconds: u64,
    start_microseconds: u64,
}

pub(super) fn signal_process_generation(
    pid: u32,
    pid_version: u32,
    signal: i32,
) -> std::io::Result<()> {
    #[cfg(target_os = "macos")]
    {
        use std::ffi::c_void;

        #[repr(C)]
        struct AuditToken {
            values: [u32; 8],
        }

        type SignalWithAuditToken = unsafe extern "C" fn(*mut AuditToken, libc::c_int) -> i32;

        if pid <= 1 || pid_version == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "invalid macOS process generation",
            ));
        }
        let symbol =
            unsafe { libc::dlsym(libc::RTLD_DEFAULT, c"proc_signal_with_audittoken".as_ptr()) };
        if symbol.is_null() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "identity-safe macOS process signaling is unavailable",
            ));
        }
        // SAFETY: libproc exports this function with the declared C ABI; a missing symbol fails closed.
        let signal_with_token: SignalWithAuditToken =
            unsafe { std::mem::transmute::<*mut c_void, _>(symbol) };
        let mut token = AuditToken { values: [0; 8] };
        // XNU's proc_find_audit_token validates these PID and pidversion fields before signaling.
        token.values[5] = pid;
        token.values[7] = pid_version;
        let result = unsafe { signal_with_token(&mut token, signal) };
        if result != 0 {
            return Err(std::io::Error::from_raw_os_error(result));
        }
        Ok(())
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = (pid, pid_version, signal);
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "identity-safe process signaling is supported only on macOS",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn idle_warmed_sample_skips_launchd_service_query() {
        let query_count = AtomicUsize::new(0);
        let mut sampler = CpuSampler::default();
        let _ = sampler.sample_with_service_query(&[], f32::MAX, || {
            query_count.fetch_add(1, Ordering::Relaxed);
            Ok(HashSet::new())
        });

        let snapshot = sampler.sample_with_service_query(&[], f32::MAX, || {
            query_count.fetch_add(1, Ordering::Relaxed);
            Ok(HashSet::new())
        });

        assert!(snapshot.warmed);
        assert!(snapshot.candidates.is_empty());
        assert_eq!(query_count.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn final_process_group_revalidation_rejects_session_changes_after_snapshot() {
        let verified_group = 41;
        let changed_session = ProcessInfo {
            pid: 42,
            process_group: 42,
            flags: PROC_FLAG_SLEADER,
            ..ProcessInfo::default()
        };
        assert!(verify_final_process_group(42, verified_group, &changed_session).is_err());

        let changed_group = ProcessInfo {
            pid: 42,
            process_group: 43,
            ..ProcessInfo::default()
        };
        assert!(verify_final_process_group(42, verified_group, &changed_group).is_err());
    }

    #[cfg(target_os = "macos")]
    #[test]
    #[serial_test::serial]
    fn child_forked_during_executable_verification_prevents_signal() {
        use std::process::{Child, Stdio};

        struct Fixture {
            launcher: Child,
            worker_pid: u32,
            stop_path: std::path::PathBuf,
        }
        impl Drop for Fixture {
            fn drop(&mut self) {
                let _ = std::fs::write(&self.stop_path, b"stop");
                if let Ok(identity) = process_info(self.worker_pid) {
                    let _ = signal_process_generation(
                        self.worker_pid,
                        identity.pid_version,
                        libc::SIGTERM,
                    );
                }
                let _ = self.launcher.wait();
            }
        }

        let temp = tempfile::tempdir().expect("isolated verification-race fixture");
        let source = temp.path().join("verification-race.c");
        let executable = temp.path().join("verification-race");
        let worker_pid_path = temp.path().join("worker.pid");
        let child_pid_path = temp.path().join("child.pid");
        let fork_path = temp.path().join("fork");
        let stop_path = temp.path().join("stop");
        std::fs::write(
            &source,
            br#"#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
static void save_pid(const char *path) {
    FILE *file = fopen(path, "w");
    if (file == NULL) _exit(11);
    fprintf(file, "%d\n", getpid());
    fclose(file);
}
int main(int argc, char **argv) {
    if (argc != 5) return 2;
    if (fork() > 0) return 0;
    if (setsid() < 0) _exit(3);
    if (fork() > 0) return 0;
    save_pid(argv[1]);
    int spawned = 0;
    volatile uint64_t counter = 0;
    for (;;) {
        counter++;
        if ((counter & 0xfffff) == 0) {
            if (access(argv[4], F_OK) == 0) return 0;
            if (!spawned && access(argv[2], F_OK) == 0) {
                pid_t child = fork();
                if (child < 0) _exit(4);
                if (child == 0) {
                    if (setpgid(0, 0) != 0) _exit(5);
                    save_pid(argv[3]);
                    while (access(argv[4], F_OK) != 0) usleep(10000);
                    _exit(0);
                }
                spawned = 1;
            }
        }
    }
}
"#,
        )
        .expect("write synthetic process source");
        let compile = Command::new("/usr/bin/clang")
            .arg(&source)
            .arg("-o")
            .arg(&executable)
            .output()
            .expect("compile synthetic process fixture");
        assert!(
            compile.status.success(),
            "clang failed: {}",
            String::from_utf8_lossy(&compile.stderr)
        );
        let sign = Command::new("/usr/bin/codesign")
            .args(["--force", "--sign", "-"])
            .arg(&executable)
            .output()
            .expect("ad-hoc sign synthetic process fixture");
        assert!(
            sign.status.success(),
            "codesign failed: {}",
            String::from_utf8_lossy(&sign.stderr)
        );

        let mut launcher = Command::new(&executable)
            .arg(&worker_pid_path)
            .arg(&fork_path)
            .arg(&child_pid_path)
            .arg(&stop_path)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("start detached synthetic worker");
        assert!(launcher.wait().expect("reap fixture launcher").success());
        let worker_pid = (0..100)
            .find_map(|_| {
                std::fs::read_to_string(&worker_pid_path)
                    .ok()
                    .and_then(|value| value.trim().parse::<u32>().ok())
                    .or_else(|| {
                        std::thread::sleep(Duration::from_millis(20));
                        None
                    })
            })
            .expect("read detached worker PID");
        let fixture = Fixture {
            launcher,
            worker_pid,
            stop_path: stop_path.clone(),
        };

        let result = (|| -> Result<()> {
            let mut system = System::new_all();
            let mut candidate = None;
            let mut classification_error = None;
            for _ in 0..100 {
                system.refresh_processes(ProcessesToUpdate::All, true);
                if let Some(process) = system.process(Pid::from_u32(worker_pid)) {
                    match classify_process(&system, worker_pid, process, &launchd_service_pids()?) {
                        Ok(found) => {
                            candidate = Some(found);
                            break;
                        }
                        Err(error) => classification_error = Some(error),
                    }
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            let candidate = candidate.context(format!(
                "classify isolated orphaned worker: {classification_error:?}"
            ))?;
            anyhow::ensure!(candidate.ownership == OwnershipKind::Orphaned);
            let signals = std::cell::Cell::new(0);
            let result = super::super::send_signal_with(
                &candidate,
                libc::SIGTERM,
                |identity| {
                    verify_current_identity_inner(
                        identity,
                        &[],
                        || {
                            std::fs::write(&fork_path, b"fork").expect("trigger child creation");
                            for _ in 0..100 {
                                if child_pid_path.exists() {
                                    return;
                                }
                                std::thread::sleep(Duration::from_millis(10));
                            }
                            panic!("synthetic worker did not create its child");
                        },
                        || {},
                        || {},
                    )
                    .map_err(|error| anyhow::anyhow!("{error:?}"))
                },
                |_, _| {
                    signals.set(signals.get() + 1);
                    Ok(())
                },
            );
            anyhow::ensure!(
                result.is_err(),
                "candidate with a new child passed revalidation"
            );
            anyhow::ensure!(signals.get() == 0, "unsafe candidate received a signal");
            Ok(())
        })();
        drop(fixture);
        result.expect("revalidate child relationships after executable verification");
    }

    #[cfg(target_os = "macos")]
    #[test]
    #[serial_test::serial]
    fn child_spawned_during_final_group_snapshot_withholds_signal() {
        use std::process::{Child, Stdio};

        struct Fixture {
            launcher: Child,
            worker_pid: Option<u32>,
            child_pid: Option<u32>,
            stop_path: std::path::PathBuf,
        }
        impl Drop for Fixture {
            fn drop(&mut self) {
                let _ = std::fs::write(&self.stop_path, b"stop");
                for pid in [self.worker_pid, self.child_pid].into_iter().flatten() {
                    if let Ok(identity) = process_info(pid) {
                        let _ = signal_process_generation(pid, identity.pid_version, libc::SIGTERM);
                    }
                }
                let _ = self.launcher.wait();
            }
        }

        let temp = tempfile::tempdir().expect("isolated final-child-check fixture");
        let source = temp.path().join("final-child-check.c");
        let executable = temp.path().join("final-child-check");
        let leader_pid_path = temp.path().join("leader.pid");
        let worker_pid_path = temp.path().join("worker.pid");
        let spawn_child_path = temp.path().join("spawn-child");
        let child_pid_path = temp.path().join("child.pid");
        let stop_path = temp.path().join("stop");
        std::fs::write(
            &source,
            br#"#include <stdio.h>
#include <unistd.h>
static void save_pid(const char *path) {
    FILE *file = fopen(path, "w");
    if (file == NULL) _exit(11);
    fprintf(file, "%d\n", getpid());
    fclose(file);
}
static void wait_for_stop(const char *path) {
    for (;;) {
        if (access(path, F_OK) == 0) _exit(0);
        usleep(10000);
    }
}
int main(int argc, char **argv) {
    if (argc != 6) return 2;
    if (fork() > 0) return 0;
    if (setsid() < 0) _exit(3);
    save_pid(argv[1]);
    if (fork() > 0) return 0;
    save_pid(argv[2]);
    int forked = 0;
    for (;;) {
        if (access(argv[5], F_OK) == 0) return 0;
        if (!forked && access(argv[3], F_OK) == 0) {
            forked = 1;
            pid_t child = fork();
            if (child < 0) _exit(4);
            if (child == 0) {
                if (setpgid(0, 0) < 0) _exit(5);
                save_pid(argv[4]);
                wait_for_stop(argv[5]);
            }
        }
        usleep(10000);
    }
}
"#,
        )
        .expect("write synthetic final-child-check process");
        let compile = Command::new("/usr/bin/clang")
            .args(["-O2", "-o"])
            .arg(&executable)
            .arg(&source)
            .output()
            .expect("compile synthetic final-child-check process");
        assert!(
            compile.status.success(),
            "clang failed: {}",
            String::from_utf8_lossy(&compile.stderr)
        );
        let sign = Command::new("/usr/bin/codesign")
            .args(["--force", "--sign", "-", "--timestamp=none"])
            .arg(&executable)
            .output()
            .expect("sign synthetic final-child-check process");
        assert!(
            sign.status.success(),
            "codesign failed: {}",
            String::from_utf8_lossy(&sign.stderr)
        );

        let launcher = Command::new(&executable)
            .arg(&leader_pid_path)
            .arg(&worker_pid_path)
            .arg(&spawn_child_path)
            .arg(&child_pid_path)
            .arg(&stop_path)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("start synthetic final-child-check fixture");
        let mut fixture = Fixture {
            launcher,
            worker_pid: None,
            child_pid: None,
            stop_path: stop_path.clone(),
        };
        assert!(fixture
            .launcher
            .wait()
            .expect("reap fixture launcher")
            .success());
        let read_pid = |path: &std::path::Path| {
            (0..100).find_map(|_| {
                std::fs::read_to_string(path)
                    .ok()
                    .and_then(|value| value.trim().parse::<u32>().ok())
                    .or_else(|| {
                        std::thread::sleep(Duration::from_millis(20));
                        None
                    })
            })
        };
        let worker_pid = read_pid(&worker_pid_path).expect("read synthetic worker PID");
        fixture.worker_pid = Some(worker_pid);
        let leader_pid = read_pid(&leader_pid_path).expect("read synthetic group leader PID");

        let result = (|| -> Result<()> {
            let mut system = System::new_all();
            let mut candidate = None;
            let mut classification_error = None;
            for _ in 0..100 {
                system.refresh_processes(ProcessesToUpdate::All, true);
                if let Some(process) = system.process(Pid::from_u32(worker_pid)) {
                    match classify_process(&system, worker_pid, process, &launchd_service_pids()?) {
                        Ok(found) => {
                            candidate = Some(found);
                            break;
                        }
                        Err(error) => classification_error = Some(error),
                    }
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            let candidate = candidate.context(format!(
                "classify isolated orphaned worker: {classification_error:?}"
            ))?;
            anyhow::ensure!(candidate.ownership == OwnershipKind::Orphaned);
            let before = process_info(worker_pid)?;
            anyhow::ensure!(before.process_group == leader_pid);
            anyhow::ensure!(before.process_group != worker_pid);
            anyhow::ensure!(before.flags & PROC_FLAG_SLEADER == 0);
            let initial_groups = process_group_snapshot()?;
            verify_singleton_process_group(worker_pid, before.process_group, &initial_groups)
                .map_err(|error| anyhow::anyhow!("initial group is not singleton: {error:?}"))?;

            let signals = std::cell::Cell::new(0);
            let result = super::super::send_signal_with(
                &candidate,
                libc::SIGTERM,
                |identity| {
                    verify_current_identity_inner(
                        identity,
                        &[],
                        || {},
                        || {},
                        || {
                            std::fs::write(&spawn_child_path, b"spawn")
                                .expect("request synthetic child during final group snapshot");
                            for _ in 0..100 {
                                if child_pid_path.exists() {
                                    return;
                                }
                                std::thread::sleep(Duration::from_millis(10));
                            }
                            panic!("synthetic worker did not spawn its separate-group child");
                        },
                    )
                    .map_err(|error| anyhow::anyhow!("{error:?}"))
                },
                |_, _| {
                    signals.set(signals.get() + 1);
                    Ok(())
                },
            );
            let error =
                result.expect_err("candidate with a new child passed final cleanup revalidation");
            anyhow::ensure!(
                format!("{error:#}").contains("process has child workloads"),
                "candidate was rejected for an unrelated reason: {error:#}"
            );
            let child_pid = read_pid(&child_pid_path).context("read spawned child PID")?;
            fixture.child_pid = Some(child_pid);
            let after = process_info(worker_pid)?;
            let child_info = process_info(child_pid)?;
            anyhow::ensure!(after.pid_version == before.pid_version);
            anyhow::ensure!(after.process_group == before.process_group);
            anyhow::ensure!(after.flags & PROC_FLAG_SLEADER == 0);
            anyhow::ensure!(child_info.parent_pid == worker_pid);
            anyhow::ensure!(child_info.process_group == child_pid);
            anyhow::ensure!(child_info.process_group != after.process_group);
            anyhow::ensure!(signals.get() == 0, "unsafe synthetic process was signaled");
            Ok(())
        })();
        drop(fixture);
        result.expect("revalidate child workloads after final process-group query");
    }

    #[cfg(target_os = "macos")]
    #[test]
    #[serial_test::serial]
    fn session_change_after_process_group_snapshot_withholds_signal() {
        use std::process::{Child, Stdio};

        struct Fixture {
            launcher: Child,
            worker_pid: u32,
            stop_path: std::path::PathBuf,
        }
        impl Drop for Fixture {
            fn drop(&mut self) {
                let _ = std::fs::write(&self.stop_path, b"stop");
                if let Ok(identity) = process_info(self.worker_pid) {
                    let _ = signal_process_generation(
                        self.worker_pid,
                        identity.pid_version,
                        libc::SIGTERM,
                    );
                }
                let _ = self.launcher.wait();
            }
        }

        let temp = tempfile::tempdir().expect("isolated session-race fixture");
        let source = temp.path().join("session-race.c");
        let executable = temp.path().join("session-race");
        let leader_pid_path = temp.path().join("leader.pid");
        let worker_pid_path = temp.path().join("worker.pid");
        let change_session_path = temp.path().join("change-session");
        let session_changed_path = temp.path().join("session-changed");
        let stop_path = temp.path().join("stop");
        std::fs::write(
            &source,
            br#"#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
static void save_pid(const char *path) {
    FILE *file = fopen(path, "w");
    if (file == NULL) _exit(11);
    fprintf(file, "%d\n", getpid());
    fclose(file);
}
int main(int argc, char **argv) {
    if (argc != 6) return 2;
    if (fork() > 0) return 0;
    if (setsid() < 0) _exit(3);
    save_pid(argv[1]);
    if (fork() > 0) return 0;
    save_pid(argv[2]);
    for (;;) {
        if (access(argv[5], F_OK) == 0) return 0;
        if (access(argv[3], F_OK) == 0 && access(argv[4], F_OK) != 0) {
            if (setsid() < 0) _exit(4);
            save_pid(argv[4]);
        }
        usleep(10000);
    }
}
"#,
        )
        .expect("write synthetic session-race process");
        let compile = Command::new("/usr/bin/clang")
            .args(["-O2", "-o"])
            .arg(&executable)
            .arg(&source)
            .output()
            .expect("compile synthetic session-race process");
        assert!(
            compile.status.success(),
            "clang failed: {}",
            String::from_utf8_lossy(&compile.stderr)
        );
        let sign = Command::new("/usr/bin/codesign")
            .args(["--force", "--sign", "-", "--timestamp=none"])
            .arg(&executable)
            .output()
            .expect("sign synthetic session-race process");
        assert!(
            sign.status.success(),
            "codesign failed: {}",
            String::from_utf8_lossy(&sign.stderr)
        );

        let mut launcher = Command::new(&executable)
            .arg(&leader_pid_path)
            .arg(&worker_pid_path)
            .arg(&change_session_path)
            .arg(&session_changed_path)
            .arg(&stop_path)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("start synthetic session-race process");
        assert!(launcher.wait().expect("reap fixture launcher").success());
        let worker_pid = (0..100)
            .find_map(|_| {
                std::fs::read_to_string(&worker_pid_path)
                    .ok()
                    .and_then(|value| value.trim().parse::<u32>().ok())
                    .or_else(|| {
                        std::thread::sleep(Duration::from_millis(20));
                        None
                    })
            })
            .expect("read synthetic worker PID");
        let fixture = Fixture {
            launcher,
            worker_pid,
            stop_path,
        };

        let result = (|| -> Result<()> {
            let mut system = System::new_all();
            let mut candidate = None;
            let mut classification_error = None;
            for _ in 0..100 {
                system.refresh_processes(ProcessesToUpdate::All, true);
                if let Some(process) = system.process(Pid::from_u32(worker_pid)) {
                    match classify_process(&system, worker_pid, process, &launchd_service_pids()?) {
                        Ok(found) => {
                            candidate = Some(found);
                            break;
                        }
                        Err(error) => classification_error = Some(error),
                    }
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            let candidate = candidate.context(format!(
                "classify isolated orphaned worker: {classification_error:?}"
            ))?;
            anyhow::ensure!(candidate.ownership == OwnershipKind::Orphaned);
            let before = process_info(worker_pid)?;
            anyhow::ensure!(before.process_group != worker_pid);
            anyhow::ensure!(before.flags & PROC_FLAG_SLEADER == 0);

            let signals = std::cell::Cell::new(0);
            let result = super::super::send_signal_with(
                &candidate,
                libc::SIGTERM,
                |identity| {
                    verify_current_identity_inner(
                        identity,
                        &[],
                        || {},
                        || {
                            std::fs::write(&change_session_path, b"change")
                                .expect("request synthetic session change");
                            for _ in 0..100 {
                                if session_changed_path.exists() {
                                    return;
                                }
                                std::thread::sleep(Duration::from_millis(10));
                            }
                            panic!("synthetic process did not become a session leader");
                        },
                        || {},
                    )
                    .map_err(|error| anyhow::anyhow!("{error:?}"))
                },
                |_, _| {
                    signals.set(signals.get() + 1);
                    Ok(())
                },
            );
            anyhow::ensure!(
                result.is_err(),
                "session change after group snapshot passed cleanup revalidation"
            );
            let after = process_info(worker_pid)?;
            anyhow::ensure!(after.process_group == worker_pid);
            anyhow::ensure!(after.flags & PROC_FLAG_SLEADER != 0);
            anyhow::ensure!(signals.get() == 0, "unsafe synthetic process was signaled");
            Ok(())
        })();
        drop(fixture);
        result.expect("revalidate session and process-group state after its snapshot");
    }

    #[cfg(target_os = "macos")]
    #[test]
    #[serial_test::serial]
    fn process_group_member_joined_after_snapshot_withholds_signal() {
        use std::process::{Child, Stdio};

        struct Fixture {
            launcher: Child,
            worker_pid: Option<u32>,
            peer_pid: Option<u32>,
            stop_path: std::path::PathBuf,
        }
        impl Drop for Fixture {
            fn drop(&mut self) {
                let _ = std::fs::write(&self.stop_path, b"stop");
                for pid in [self.worker_pid, self.peer_pid].into_iter().flatten() {
                    if let Ok(identity) = process_info(pid) {
                        let _ = signal_process_generation(pid, identity.pid_version, libc::SIGTERM);
                    }
                }
                let _ = self.launcher.wait();
            }
        }

        let temp = tempfile::tempdir().expect("isolated process-group-race fixture");
        let source = temp.path().join("process-group-race.c");
        let executable = temp.path().join("process-group-race");
        let leader_pid_path = temp.path().join("leader.pid");
        let worker_pid_path = temp.path().join("worker.pid");
        let peer_pid_path = temp.path().join("peer.pid");
        let join_group_path = temp.path().join("join-group");
        let joined_group_path = temp.path().join("joined-group");
        let stop_path = temp.path().join("stop");
        std::fs::write(
            &source,
            br#"#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
static void save_pid(const char *path) {
    FILE *file = fopen(path, "w");
    if (file == NULL) _exit(11);
    fprintf(file, "%d\n", getpid());
    fclose(file);
}
static void wait_for_stop(const char *path) {
    for (;;) {
        if (access(path, F_OK) == 0) _exit(0);
        usleep(10000);
    }
}
int main(int argc, char **argv) {
    if (argc != 7) return 2;
    if (fork() > 0) return 0;
    if (setsid() < 0) _exit(3);
    save_pid(argv[1]);
    pid_t worker = fork();
    if (worker < 0) _exit(4);
    if (worker == 0) {
        save_pid(argv[2]);
        wait_for_stop(argv[6]);
    }
    pid_t peer = fork();
    if (peer < 0) _exit(5);
    if (peer == 0) {
        if (setpgid(0, 0) < 0) _exit(6);
        save_pid(argv[3]);
        for (;;) {
            if (access(argv[6], F_OK) == 0) _exit(0);
            if (access(argv[4], F_OK) == 0 && access(argv[5], F_OK) != 0) {
                FILE *leader = fopen(argv[1], "r");
                long group = 0;
                if (leader == NULL || fscanf(leader, "%ld", &group) != 1) _exit(7);
                fclose(leader);
                if (setpgid(0, (pid_t)group) < 0) _exit(8);
                FILE *joined = fopen(argv[5], "w");
                if (joined == NULL) _exit(9);
                fputs("joined\n", joined);
                fclose(joined);
            }
            usleep(10000);
        }
    }
    return 0;
}
"#,
        )
        .expect("write synthetic process-group-race process");
        let compile = Command::new("/usr/bin/clang")
            .args(["-O2", "-o"])
            .arg(&executable)
            .arg(&source)
            .output()
            .expect("compile synthetic process-group-race process");
        assert!(
            compile.status.success(),
            "clang failed: {}",
            String::from_utf8_lossy(&compile.stderr)
        );
        let sign = Command::new("/usr/bin/codesign")
            .args(["--force", "--sign", "-", "--timestamp=none"])
            .arg(&executable)
            .output()
            .expect("sign synthetic process-group-race process");
        assert!(
            sign.status.success(),
            "codesign failed: {}",
            String::from_utf8_lossy(&sign.stderr)
        );

        let launcher = Command::new(&executable)
            .arg(&leader_pid_path)
            .arg(&worker_pid_path)
            .arg(&peer_pid_path)
            .arg(&join_group_path)
            .arg(&joined_group_path)
            .arg(&stop_path)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("start synthetic process-group-race fixture");
        let mut fixture = Fixture {
            launcher,
            worker_pid: None,
            peer_pid: None,
            stop_path: stop_path.clone(),
        };
        assert!(fixture
            .launcher
            .wait()
            .expect("reap fixture launcher")
            .success());
        let read_pid = |path: &std::path::Path| {
            (0..100).find_map(|_| {
                std::fs::read_to_string(path)
                    .ok()
                    .and_then(|value| value.trim().parse::<u32>().ok())
                    .or_else(|| {
                        std::thread::sleep(Duration::from_millis(20));
                        None
                    })
            })
        };
        let worker_pid = read_pid(&worker_pid_path).expect("read synthetic worker PID");
        fixture.worker_pid = Some(worker_pid);
        let peer_pid = read_pid(&peer_pid_path).expect("read synthetic peer PID");
        fixture.peer_pid = Some(peer_pid);
        let leader_pid = read_pid(&leader_pid_path).expect("read synthetic session leader PID");

        let result = (|| -> Result<()> {
            let mut system = System::new_all();
            let mut candidate = None;
            let mut classification_error = None;
            for _ in 0..100 {
                system.refresh_processes(ProcessesToUpdate::All, true);
                if let Some(process) = system.process(Pid::from_u32(worker_pid)) {
                    match classify_process(&system, worker_pid, process, &launchd_service_pids()?) {
                        Ok(found) => {
                            candidate = Some(found);
                            break;
                        }
                        Err(error) => classification_error = Some(error),
                    }
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            let candidate = candidate.context(format!(
                "classify isolated orphaned worker: {classification_error:?}"
            ))?;
            anyhow::ensure!(candidate.ownership == OwnershipKind::Orphaned);
            let before = process_info(worker_pid)?;
            let peer_before = process_info(peer_pid)?;
            anyhow::ensure!(before.process_group == leader_pid);
            anyhow::ensure!(before.process_group != worker_pid);
            anyhow::ensure!(before.flags & PROC_FLAG_SLEADER == 0);
            anyhow::ensure!(peer_before.process_group == peer_pid);
            let initial_groups = process_group_snapshot()?;
            anyhow::ensure!(initial_groups.get(&leader_pid) != Some(&leader_pid));
            verify_singleton_process_group(worker_pid, before.process_group, &initial_groups)
                .map_err(|error| anyhow::anyhow!("initial group is not singleton: {error:?}"))?;

            let signals = std::cell::Cell::new(0);
            let result = super::super::send_signal_with(
                &candidate,
                libc::SIGTERM,
                |identity| {
                    verify_current_identity_inner(
                        identity,
                        &[],
                        || {},
                        || {
                            std::fs::write(&join_group_path, b"join")
                                .expect("request synthetic peer to join candidate group");
                            for _ in 0..100 {
                                if joined_group_path.exists() {
                                    return;
                                }
                                std::thread::sleep(Duration::from_millis(10));
                            }
                            panic!("synthetic peer did not join candidate process group");
                        },
                        || {},
                    )
                    .map_err(|error| anyhow::anyhow!("{error:?}"))
                },
                |_, _| {
                    signals.set(signals.get() + 1);
                    Ok(())
                },
            );
            let error = result.expect_err(
                "candidate passed cleanup revalidation after a peer joined its process group",
            );
            anyhow::ensure!(
                format!("{error:#}").contains("process is not alone in its process group"),
                "candidate was rejected for an unrelated reason: {error:#}"
            );
            let after = process_info(worker_pid)?;
            let peer_after = process_info(peer_pid)?;
            anyhow::ensure!(after.process_group == before.process_group);
            anyhow::ensure!(after.pid_version == before.pid_version);
            anyhow::ensure!(after.flags & PROC_FLAG_SLEADER == 0);
            anyhow::ensure!(peer_after.process_group == before.process_group);
            anyhow::ensure!(signals.get() == 0, "unsafe synthetic process was signaled");
            Ok(())
        })();
        drop(fixture);
        result.expect("revalidate process-group membership after launchd queries");
    }

    #[cfg(target_os = "macos")]
    #[test]
    #[serial_test::serial]
    fn orphaned_nonleader_reaches_enrollment_and_passes_approved_cleanup() {
        use super::super::policy::{Decision, DecisionResponse};
        use std::process::{Child, Stdio};

        struct FixtureProcess {
            launcher: Child,
            worker_pid: u32,
            stop_path: std::path::PathBuf,
        }
        impl Drop for FixtureProcess {
            fn drop(&mut self) {
                let _ = std::fs::write(&self.stop_path, b"stop");
                if let Ok(identity) = process_info(self.worker_pid) {
                    let _ = signal_process_generation(
                        self.worker_pid,
                        identity.pid_version,
                        libc::SIGTERM,
                    );
                }
                let _ = self.launcher.wait();
            }
        }

        let temp = tempfile::tempdir().expect("isolated candidate fixture");
        let source = temp.path().join("eligible-cli.c");
        let executable = temp.path().join("eligible-cli");
        let leader_path = temp.path().join("leader.pid");
        let worker_path = temp.path().join("worker.pid");
        let stop_path = temp.path().join("stop");
        std::fs::write(
            &source,
            br#"#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
static void save_pid(const char *path) {
    FILE *file = fopen(path, "w");
    if (file == NULL) _exit(11);
    fprintf(file, "%d\n", getpid());
    fclose(file);
}
int main(int argc, char **argv) {
    if (argc != 4) return 2;
    if (fork() > 0) return 0;
    if (setsid() < 0) _exit(3);
    save_pid(argv[1]);
    pid_t worker = fork();
    if (worker < 0) _exit(4);
    if (worker > 0) _exit(0);
    save_pid(argv[2]);
    volatile uint64_t counter = 0;
    for (;;) {
        counter++;
        if ((counter & 0xfffff) == 0 && access(argv[3], F_OK) == 0) return 0;
    }
}
"#,
        )
        .expect("write isolated CLI fixture");
        let compile = Command::new("/usr/bin/clang")
            .args(["-O2", "-o"])
            .arg(&executable)
            .arg(&source)
            .output()
            .expect("compile isolated CLI fixture");
        assert!(
            compile.status.success(),
            "clang failed: {}",
            String::from_utf8_lossy(&compile.stderr)
        );
        let sign = Command::new("/usr/bin/codesign")
            .args(["--force", "--sign", "-", "--timestamp=none"])
            .arg(&executable)
            .output()
            .expect("sign isolated CLI fixture");
        assert!(
            sign.status.success(),
            "codesign failed: {}",
            String::from_utf8_lossy(&sign.stderr)
        );

        let mut launcher = Command::new(&executable)
            .arg(&leader_path)
            .arg(&worker_path)
            .arg(&stop_path)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("start isolated CLI fixture");
        let launcher_status = launcher.wait().expect("reap isolated launcher");
        assert!(launcher_status.success());
        for _ in 0..100 {
            if leader_path.exists() && worker_path.exists() {
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        let leader_pid = std::fs::read_to_string(&leader_path)
            .expect("read process-group leader PID")
            .trim()
            .parse::<u32>()
            .expect("valid process-group leader PID");
        let worker_pid = std::fs::read_to_string(&worker_path)
            .expect("read orphaned worker PID")
            .trim()
            .parse::<u32>()
            .expect("valid orphaned worker PID");
        let fixture = FixtureProcess {
            launcher,
            worker_pid,
            stop_path,
        };
        let result = (|| -> anyhow::Result<()> {
            let mut system = System::new_all();
            let mut ready = false;
            for _ in 0..12 {
                std::thread::sleep(Duration::from_secs(1));
                system.refresh_processes(ProcessesToUpdate::All, true);
                let orphaned = process_info(worker_pid)
                    .is_ok_and(|info| info.parent_pid == 1 && info.process_group == leader_pid);
                let leader_exited = process_info(leader_pid).is_err();
                let high_cpu = system
                    .process(Pid::from_u32(worker_pid))
                    .is_some_and(|process| process.cpu_usage() > CPU_THRESHOLD);
                if orphaned && leader_exited && high_cpu {
                    ready = true;
                    break;
                }
            }
            anyhow::ensure!(
                ready,
                "synthetic orphan did not reach the PGID != PID fixture state"
            );
            let process = system
                .process(Pid::from_u32(worker_pid))
                .context("find isolated high-CPU CLI")?;
            let service_pids = launchd_service_pids()?;
            let candidate = classify_process(&system, worker_pid, process, &service_pids)
                .map_err(anyhow::Error::msg)?;
            assert!(candidate.cpu_percent > CPU_THRESHOLD);
            assert_eq!(candidate.ownership, OwnershipKind::Orphaned);
            assert_eq!(candidate.identity.pid, worker_pid);
            let identity = process_info(worker_pid)?;
            assert_eq!(identity.process_group, leader_pid);
            assert_ne!(identity.process_group, worker_pid);
            assert_eq!(identity.flags & PROC_FLAG_SLEADER, 0);
            assert!(candidate.reason.contains("reparented to launchd"));
            let mut registered_service_pids = service_pids.clone();
            registered_service_pids.insert(worker_pid);
            anyhow::ensure!(
                is_cleanup_eligible(&mut system, &candidate.identity, &registered_service_pids,)
                    .is_err(),
                "registered service fixture passed cleanup eligibility"
            );

            let now = Instant::now();
            let mut discovery = HashMap::new();
            assert_eq!(
                super::super::observe_candidate(&mut discovery, &candidate, now),
                Duration::ZERO
            );
            assert!(
                super::super::observe_candidate(
                    &mut discovery,
                    &candidate,
                    now + Duration::from_secs(60)
                ) < super::super::DISCOVERY_DURATION
            );
            assert!(
                super::super::observe_candidate(
                    &mut discovery,
                    &candidate,
                    now + super::super::DISCOVERY_DURATION
                ) >= super::super::DISCOVERY_DURATION
            );

            let mut policy = super::super::PolicyFile::default();
            let request = super::super::new_pending(&candidate, chrono::Utc::now().to_rfc3339())?;
            assert!(request.reason.contains("reparented to launchd"));
            policy
                .pending
                .insert(request.request_id.clone(), request.clone());
            let response = DecisionResponse {
                request_id: request.request_id,
                canonical_path: candidate.identity.executable.clone(),
                fingerprint: candidate.identity.fingerprint.clone(),
                decision: Decision::Add,
                timer_minutes: Some(1),
            };
            assert!(matches!(
                super::super::apply_response(&mut policy, &response)?,
                super::super::DecisionApply::Added { minutes: 1 }
            ));
            assert!(policy.approval_for(&candidate.identity).is_some());

            let mut post_approval_tracking = HashMap::new();
            let approval_start = now + super::super::DISCOVERY_DURATION + Duration::from_secs(1);
            let _ = super::super::observe_candidate(
                &mut post_approval_tracking,
                &candidate,
                approval_start,
            );
            let _ = super::super::observe_candidate(
                &mut post_approval_tracking,
                &candidate,
                approval_start + Duration::from_secs(30),
            );
            assert_eq!(
                super::super::cleanup_action(
                    post_approval_tracking.get(&worker_pid),
                    None,
                    Duration::from_secs(60),
                    approval_start + Duration::from_secs(59),
                ),
                None
            );
            assert_eq!(
                super::super::cleanup_action(
                    post_approval_tracking.get(&worker_pid),
                    None,
                    Duration::from_secs(60),
                    approval_start + Duration::from_secs(60),
                ),
                Some(super::super::CleanupAction::Terminate)
            );

            let store = super::super::PolicyStore::new(temp.path().join("policy"));
            let lock = store.lock()?;
            lock.save(&policy)?;
            let persisted = lock.load()?;
            anyhow::ensure!(
                persisted.approval_for(&candidate.identity).is_some(),
                "approval was not durable before cleanup"
            );
            let signals = std::cell::Cell::new(0);
            let result = super::super::send_signal_with_policy_persistence(
                &candidate,
                libc::SIGTERM,
                || lock.save(&persisted),
                |expected| {
                    verify_current_identity(expected, &[])
                        .map_err(|error| anyhow::anyhow!("{error:?}"))
                },
                |identity, signal| {
                    assert_eq!(identity.pid, worker_pid);
                    assert_eq!(signal, libc::SIGTERM);
                    let result =
                        signal_process_generation(identity.pid, identity.pid_version, signal);
                    if result.is_ok() {
                        signals.set(signals.get() + 1);
                    }
                    result
                },
            );
            result?;
            anyhow::ensure!(
                signals.get() == 1,
                "safe orphan did not receive one SIGTERM"
            );
            for _ in 0..50 {
                if process_info(worker_pid).is_err() {
                    return Ok(());
                }
                std::thread::sleep(Duration::from_millis(100));
            }
            anyhow::bail!("synthetic orphan did not exit after its verified SIGTERM");
        })();
        drop(fixture);
        result.expect("enroll and clean up a safe synthetic orphan with PGID != PID");
    }

    #[test]
    fn sample_clock_tolerates_small_read_skew_and_rejects_real_discontinuities() {
        assert!(!sample_clock_discontinuous(
            Duration::from_secs(60),
            Duration::from_secs(60) - Duration::from_micros(50)
        ));
        assert!(!sample_clock_discontinuous(
            Duration::from_secs(60),
            Duration::from_secs(60) + Duration::from_millis(20)
        ));
        assert!(sample_clock_discontinuous(
            Duration::from_secs(60),
            Duration::from_secs(55)
        ));
        assert!(sample_clock_discontinuous(
            Duration::from_secs(91),
            Duration::from_secs(91)
        ));
    }

    #[test]
    fn system_paths_and_shared_runtimes_are_protected() {
        assert!(is_protected_system_path(Path::new("/usr/bin/top")));
        assert!(is_protected_system_path(Path::new("/System/Library/foo")));
        assert!(is_shared_runtime(
            "node",
            Path::new("/opt/homebrew/bin/node")
        ));
        assert!(is_shared_runtime(
            "python3",
            Path::new("/usr/local/bin/python3")
        ));
        for interpreter in ["python3.13", "python3.14", "pypy3", "ruby3.3"] {
            assert!(is_shared_runtime(interpreter, Path::new(interpreter)));
        }
        assert!(!is_shared_runtime(
            "trunk",
            Path::new("/opt/homebrew/bin/trunk")
        ));
    }

    #[test]
    fn desktop_bundle_helpers_are_protected_by_path() {
        assert!(is_inside_app_bundle(Path::new(
            "/Applications/Editor.app/Contents/Helpers/worker"
        )));
        assert!(!is_inside_app_bundle(Path::new("/opt/homebrew/bin/trunk")));
    }

    #[test]
    fn protected_owner_names_include_shells_and_desktop_apps() {
        assert!(is_protected_owner_name("zsh"));
        assert!(is_protected_owner_name("Codex Helper"));
        assert!(!is_protected_owner_name("trunk"));
    }

    #[test]
    fn terminal_absence_requires_the_darwin_nodev_sentinel_and_clear_flags() {
        assert!(has_verified_no_controlling_terminal(u32::MAX, 0, 0));
        assert!(!has_verified_no_controlling_terminal(0, 0, 0));
        assert!(!has_verified_no_controlling_terminal(1, 0, 0));
        assert!(!has_verified_no_controlling_terminal(u32::MAX, 1, 0));
        assert!(!has_verified_no_controlling_terminal(
            u32::MAX,
            0,
            PROC_FLAG_CTTY
        ));
        assert!(!has_verified_no_controlling_terminal(
            u32::MAX,
            0,
            PROC_FLAG_CONTROLT
        ));
        assert!(!has_verified_no_controlling_terminal(u32::MAX, u32::MAX, 0));
    }

    #[test]
    fn launchd_domain_parser_collects_running_service_pids_and_fails_closed() {
        let listing = "domain = {\n\tservices = {\n\t\t123 (pe) com.example.running\n\t\t0 - com.example.stopped\n\t}\n}";
        assert_eq!(
            service_pids_from_domain_listing(listing).expect("valid service listing"),
            HashSet::from([123])
        );
        assert!(service_pids_from_domain_listing("domain = {\n}").is_err());
        assert!(service_pids_from_domain_listing(
            "domain = {\n\tservices = {\n\t\tunknown service\n\t}\n}"
        )
        .is_err());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn current_process_code_hash_matches_its_executable_file() {
        let pid = std::process::id();
        let running = code_directory_hash_for_pid(pid).expect("running code hash");
        let executable = std::env::current_exe().expect("test executable path");
        let on_disk =
            verified_code_identity_for_file(&executable).expect("verified file code identity");
        assert_eq!(running, on_disk.code_directory_hash);
        assert_eq!(on_disk.fingerprint.len(), 64);

        let info = process_info(pid).expect("precise process identity");
        assert_eq!(info.pid, pid);
        assert!(info.start_seconds > 0);
        assert!(info.start_microseconds < 1_000_000);
        assert_eq!(std::mem::size_of::<ProcBsdInfo>(), 136);
        assert_eq!(std::mem::offset_of!(ProcBsdInfo, tty_device), 108);
        assert_eq!(std::mem::offset_of!(ProcBsdInfo, tty_process_group), 112);
        assert_eq!(std::mem::offset_of!(ProcBsdInfo, start_seconds), 120);
        assert_eq!(std::mem::offset_of!(ProcBsdInfo, start_microseconds), 128);
        assert_eq!(std::mem::size_of::<ProcUniqueIdentifierInfo>(), 56);
        assert_eq!(std::mem::offset_of!(ProcBsdInfoWithUniqueId, unique), 136);
        assert_eq!(
            std::mem::offset_of!(ProcUniqueIdentifierInfo, pid_version),
            32
        );
        assert_eq!(std::mem::size_of::<ProcBsdInfoWithUniqueId>(), 192);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn modified_executable_with_retained_code_directory_hash_is_rejected() {
        use std::io::Write;

        let temp = tempfile::tempdir().expect("isolated signed executable directory");
        let source = temp.path().join("signed-fixture.c");
        let executable = temp.path().join("signed-fixture");
        std::fs::write(
            &source,
            b"int main(void) { volatile unsigned long n = 0; for (;;) { n++; } }\n",
        )
        .expect("write isolated executable source");
        let compile = Command::new("/usr/bin/clang")
            .args(["-O2", "-o"])
            .arg(&executable)
            .arg(&source)
            .output()
            .expect("compile isolated executable");
        assert!(
            compile.status.success(),
            "clang failed: {}",
            String::from_utf8_lossy(&compile.stderr)
        );
        let sign = Command::new("/usr/bin/codesign")
            .args(["--force", "--sign", "-", "--timestamp=none"])
            .arg(&executable)
            .output()
            .expect("ad-hoc sign isolated executable");
        assert!(
            sign.status.success(),
            "codesign failed: {}",
            String::from_utf8_lossy(&sign.stderr)
        );

        let original = verified_code_identity_for_file(&executable)
            .expect("verify original signed executable");
        let mut file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&executable)
            .expect("open isolated executable for mutation");
        file.seek(SeekFrom::Start(4096))
            .expect("seek into signed executable code");
        let mut byte = [0_u8; 1];
        file.read_exact(&mut byte)
            .expect("read signed executable code");
        byte[0] ^= 0x01;
        file.seek(SeekFrom::Start(4096))
            .expect("return to signed executable code");
        file.write_all(&byte)
            .expect("modify signed executable code");
        file.sync_all().expect("persist executable modification");

        let displayed = Command::new("/usr/bin/codesign")
            .args(["-dv", "--verbose=4"])
            .arg(&executable)
            .output()
            .expect("display retained code directory metadata");
        assert!(displayed.status.success());
        let details = format!(
            "{}\n{}",
            String::from_utf8_lossy(&displayed.stderr),
            String::from_utf8_lossy(&displayed.stdout)
        );
        assert!(details.lines().any(|line| {
            line.strip_prefix("CDHash=")
                .is_some_and(|hash| hash.eq_ignore_ascii_case(&original.code_directory_hash))
        }));

        let verification = Command::new("/usr/bin/codesign")
            .args(["--verify", "--strict", "--all-architectures"])
            .arg(&executable)
            .output()
            .expect("verify modified executable");
        assert!(!verification.status.success());
        assert!(verified_code_identity_for_file(&executable).is_err());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn pidversion_bound_signal_rejects_a_different_process_generation() {
        use std::os::unix::process::ExitStatusExt;

        let mut child = Command::new("/bin/sleep")
            .arg("30")
            .spawn()
            .expect("start isolated synthetic process");
        let result = (|| -> Result<()> {
            let pid = child.id();
            let identity = process_info(pid)?;
            let wrong_version = identity
                .pid_version
                .checked_add(1)
                .context("synthetic pidversion overflowed")?;
            if signal_process_generation(pid, wrong_version, libc::SIGTERM).is_ok() {
                anyhow::bail!("wrong process generation unexpectedly accepted a signal");
            }
            if child.try_wait()?.is_some() {
                anyhow::bail!("wrong process generation signaled the synthetic child");
            }

            signal_process_generation(pid, identity.pid_version, libc::SIGTERM)?;
            let status = child.wait()?;
            if status.signal() != Some(libc::SIGTERM) {
                anyhow::bail!("synthetic child did not receive SIGTERM");
            }
            Ok(())
        })();

        if child.try_wait().expect("inspect synthetic child").is_none() {
            child.kill().expect("clean up synthetic child");
            child.wait().expect("reap synthetic child");
        }
        result.expect("validate exact-generation process signaling");
    }

    #[cfg(target_os = "macos")]
    #[test]
    #[serial_test::serial]
    fn orphaned_and_active_owner_candidates_reach_enrollment_but_are_not_cleaned() {
        use crate::modules::mcpu::send_signal_with;
        use std::io::Write;

        struct StopOnDrop {
            stop_path: std::path::PathBuf,
            pid_paths: [std::path::PathBuf; 3],
        }
        impl Drop for StopOnDrop {
            fn drop(&mut self) {
                let _ = std::fs::write(&self.stop_path, b"stop");
                let mut identities = Vec::new();
                for path in &self.pid_paths {
                    if let Ok(pid) = std::fs::read_to_string(path).and_then(|value| {
                        value.trim().parse::<u32>().map_err(std::io::Error::other)
                    }) {
                        if let Ok(identity) = process_info(pid) {
                            identities.push((pid, identity.pid_version));
                        }
                    }
                }
                for _ in 0..50 {
                    if identities
                        .iter()
                        .all(|(pid, _)| process_info(*pid).is_err())
                    {
                        return;
                    }
                    std::thread::sleep(Duration::from_millis(100));
                }
                for (pid, pid_version) in identities {
                    let _ = signal_process_generation(pid, pid_version, libc::SIGTERM);
                }
                for _ in 0..50 {
                    if self.pid_paths.iter().all(|path| {
                        std::fs::read_to_string(path)
                            .ok()
                            .and_then(|value| value.trim().parse::<u32>().ok())
                            .is_none_or(|pid| process_info(pid).is_err())
                    }) {
                        return;
                    }
                    std::thread::sleep(Duration::from_millis(100));
                }
            }
        }

        let temp = tempfile::tempdir().expect("isolated CLI tree directory");
        let source = temp.path().join("tree-cli-fixture.c");
        let executable = temp.path().join("tree-cli-fixture");
        let stop_path = temp.path().join("stop");
        let root_path = temp.path().join("root.pid");
        let worker_path = temp.path().join("worker.pid");
        let owner_path = temp.path().join("owner.pid");
        let mut source_file = std::fs::File::create(&source).expect("create fixture source");
        source_file
            .write_all(
                br#"#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/stat.h>
static void save_pid(const char *path) {
    FILE *file = fopen(path, "w");
    if (file == NULL) _exit(11);
    fprintf(file, "%d\n", getpid());
    fclose(file);
}
int main(int argc, char **argv) {
    if (argc != 5) return 2;
    int owner_to_tool[2];
    if (pipe(owner_to_tool) != 0) return 12;
    pid_t owner = fork();
    if (owner < 0) return 13;
    if (owner == 0) {
        close(owner_to_tool[0]);
        save_pid(argv[4]);
        char heartbeat = 'x';
        while (access(argv[1], F_OK) != 0) {
            if (write(owner_to_tool[1], &heartbeat, 1) < 0) _exit(14);
            usleep(20000);
        }
        _exit(0);
    }
    pid_t first = fork();
    if (first < 0) return 3;
    if (first > 0) _exit(0);
    close(owner_to_tool[1]);
    if (setsid() < 0) _exit(4);
    save_pid(argv[2]);
    pid_t worker = fork();
    if (worker < 0) _exit(5);
    if (worker == 0) {
        save_pid(argv[3]);
        fcntl(owner_to_tool[0], F_SETFL, O_NONBLOCK);
    }
    volatile uint64_t counter = 0;
    for (;;) {
        counter++;
        if (worker == 0) {
            char heartbeat[64];
            (void)read(owner_to_tool[0], heartbeat, sizeof(heartbeat));
        }
        if ((counter & 0xfffff) == 0 && access(argv[1], F_OK) == 0) break;
    }
    return 0;
}
"#,
            )
            .expect("write fixture source");
        let compile = Command::new("/usr/bin/clang")
            .args(["-O2", "-o"])
            .arg(&executable)
            .arg(&source)
            .output()
            .expect("compile isolated CLI tree");
        assert!(
            compile.status.success(),
            "clang failed: {}",
            String::from_utf8_lossy(&compile.stderr)
        );
        let sign = Command::new("/usr/bin/codesign")
            .args(["--force", "--sign", "-", "--timestamp=none"])
            .arg(&executable)
            .output()
            .expect("ad-hoc sign isolated CLI tree");
        assert!(
            sign.status.success(),
            "codesign failed: {}",
            String::from_utf8_lossy(&sign.stderr)
        );

        let stop_guard = StopOnDrop {
            stop_path: stop_path.clone(),
            pid_paths: [root_path.clone(), worker_path.clone(), owner_path.clone()],
        };
        let mut launcher = Command::new(&executable)
            .arg(&stop_path)
            .arg(&root_path)
            .arg(&worker_path)
            .arg(&owner_path)
            .spawn()
            .expect("start isolated CLI tree");
        let launcher_status = launcher.wait().expect("reap CLI tree launcher");
        assert!(launcher_status.success());
        for _ in 0..100 {
            if root_path.exists() && worker_path.exists() && owner_path.exists() {
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        let root_pid = std::fs::read_to_string(&root_path)
            .expect("detached tree root PID")
            .trim()
            .parse::<u32>()
            .expect("valid root PID");
        let worker_pid = std::fs::read_to_string(&worker_path)
            .expect("detached worker PID")
            .trim()
            .parse::<u32>()
            .expect("valid worker PID");
        let owner_pid = std::fs::read_to_string(&owner_path)
            .expect("surviving owner PID")
            .trim()
            .parse::<u32>()
            .expect("valid owner PID");
        for _ in 0..100 {
            if process_info(root_pid).is_ok_and(|identity| identity.parent_pid == 1) {
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        let root_identity = process_info(root_pid).expect("verify orphaned tree root");
        let worker_identity = process_info(worker_pid).expect("verify high-CPU tree member");
        let mut service_pids = launchd_service_pids().expect("read launchd test fixture set");
        assert!(
            process_info(owner_pid).is_ok(),
            "the owner must remain alive"
        );
        assert_eq!(root_identity.parent_pid, 1);
        assert_eq!(root_identity.process_group, root_pid);
        assert_eq!(worker_identity.parent_pid, root_pid);
        assert_eq!(worker_identity.process_group, root_pid);
        assert!(
            has_verified_no_controlling_terminal(
                root_identity.tty_device,
                root_identity.tty_process_group,
                root_identity.flags,
            ),
            "detached root terminal metadata: device={} process_group={} flags=0x{:x}",
            root_identity.tty_device,
            root_identity.tty_process_group,
            root_identity.flags
        );
        assert!(
            has_verified_no_controlling_terminal(
                worker_identity.tty_device,
                worker_identity.tty_process_group,
                worker_identity.flags,
            ),
            "detached worker terminal metadata: device={} process_group={} flags=0x{:x}",
            worker_identity.tty_device,
            worker_identity.tty_process_group,
            worker_identity.flags
        );

        let mut sampler = CpuSampler::default();
        let warmup = sampler.sample(&[], CPU_THRESHOLD);
        assert!(!warmup.warmed);
        let mut interval_diagnostics = Vec::new();
        let mut previous_monotonic = warmup.at;
        let mut previous_wall = warmup.wall_at;
        let mut ready_snapshot = None;
        for _ in 0..8 {
            std::thread::sleep(Duration::from_secs(3));
            let snapshot = sampler.sample(&[], CPU_THRESHOLD);
            let monotonic_elapsed = snapshot.at.saturating_duration_since(previous_monotonic);
            let wall_elapsed = snapshot.wall_at.duration_since(previous_wall).map_or_else(
                |error| format!("backward by {:?}", error.duration()),
                |value| format!("{value:?}"),
            );
            interval_diagnostics.push(format!(
                "monotonic={monotonic_elapsed:?} wall={wall_elapsed} warmed={} discontinuity={}",
                snapshot.warmed, snapshot.discontinuity
            ));
            if snapshot.warmed {
                assert!(!snapshot.discontinuity);
                ready_snapshot = Some(snapshot);
                break;
            }
            assert!(snapshot.discontinuity);
            assert!(snapshot.candidates.is_empty());
            previous_monotonic = snapshot.at;
            previous_wall = snapshot.wall_at;
        }
        let snapshot = ready_snapshot.unwrap_or_else(|| {
            panic!("sampler never warmed: {interval_diagnostics:?}");
        });
        let launchd_unique_id =
            verified_launchd_parent_unique_id(&sampler.system, &service_pids, 1)
                .expect("derive launchd identity from a live registered service");
        assert_ne!(
            root_identity.parent_unique_id, launchd_unique_id,
            "the kernel must preserve the exited creator identity after reparenting"
        );
        service_pids.insert(owner_pid);
        let fixture_process = sampler
            .system
            .process(Pid::from_u32(worker_pid))
            .expect("find synthetic CLI tree worker");
        let fixture_cpu = fixture_process.cpu_usage();
        assert!(fixture_cpu > CPU_THRESHOLD);
        assert!(
            snapshot
                .candidates
                .iter()
                .any(|candidate| candidate.identity.pid == worker_pid),
            "verified active-owner workloads can reach enrollment; cpu={fixture_cpu:.1}% protected={} protection_error={:?}",
            snapshot.protected_high_cpu,
            snapshot.protection_error
        );
        let root_process = sampler
            .system
            .process(Pid::from_u32(root_pid))
            .expect("find synthetic parent with a child");
        assert!(root_process.cpu_usage() > CPU_THRESHOLD);
        assert!(has_direct_child_process(&sampler.system, root_pid));
        let root_candidate =
            classify_process(&sampler.system, root_pid, root_process, &service_pids)
                .expect("orphaned process with a child workload reaches enrollment");
        let worker_candidate =
            classify_process(&sampler.system, worker_pid, fixture_process, &service_pids)
                .expect("verified active-owner workload reaches enrollment");
        assert_eq!(root_candidate.ownership, OwnershipKind::Orphaned);
        assert_eq!(worker_candidate.ownership, OwnershipKind::ActiveOwner);

        let sent = std::cell::Cell::new(0);
        for candidate in [root_candidate, worker_candidate] {
            assert!(send_signal_with(
                &candidate,
                libc::SIGTERM,
                |identity| {
                    verify_current_identity(identity, &[])
                        .map_err(|error| anyhow::anyhow!("{error:?}"))
                },
                |_, _| {
                    sent.set(sent.get() + 1);
                    Ok(())
                },
            )
            .is_err());
        }
        assert_eq!(
            sent.get(),
            0,
            "unsafe synthetic processes receive no signal"
        );

        std::fs::write(&stop_path, b"stop").expect("stop isolated CLI tree");
        for _ in 0..50 {
            if process_info(worker_pid).is_err() && process_info(root_pid).is_err() {
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        assert!(
            process_info(worker_pid).is_err(),
            "worker must exit after stop"
        );
        assert!(
            process_info(root_pid).is_err(),
            "tree root must exit after stop"
        );
        drop(stop_guard);
    }
}
