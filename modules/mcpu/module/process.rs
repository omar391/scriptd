use std::collections::HashSet;
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

        let service_pids = match launchd_service_pids() {
            Ok(pids) => pids,
            Err(error) => {
                return Snapshot {
                    at: now,
                    wall_at: wall_now,
                    warmed: true,
                    discontinuity: false,
                    candidates: Vec::new(),
                    protected_high_cpu: 0,
                    protection_error: Some(error.to_string()),
                };
            }
        };

        let mut candidates = Vec::new();
        let mut protected_high_cpu = 0;
        let processes = self
            .system
            .processes()
            .iter()
            .filter(|(_, process)| process.cpu_usage() > configured_threshold.max(CPU_THRESHOLD))
            .map(|(pid, process)| (*pid, process))
            .collect::<Vec<_>>();

        for (pid, process) in processes {
            let name = process.name().to_string_lossy().into_owned();
            if exclude_apps
                .iter()
                .any(|excluded| excluded.eq_ignore_ascii_case(&name))
            {
                protected_high_cpu += 1;
                continue;
            }
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
) -> Result<()> {
    let mut system = System::new_all();
    system.refresh_processes(ProcessesToUpdate::All, true);
    let pid = Pid::from_u32(expected.pid);
    let process = system
        .process(pid)
        .context("process exited before signal")?;
    let service_pids = launchd_service_pids()?;
    let current = classify_process(&system, expected.pid, process, &service_pids)
        .map_err(anyhow::Error::msg)?;
    if current.identity != *expected {
        anyhow::bail!("process identity or executable fingerprint changed");
    }
    if exclude_apps
        .iter()
        .any(|excluded| excluded.eq_ignore_ascii_case(&current.name))
    {
        anyhow::bail!("process is explicitly excluded by name");
    }
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

    verify_process_ownership(system, pid, &info, service_pids, ownership_evidence)?;

    let running_code_hash = code_directory_hash_for_pid(pid)
        .map_err(|_| "running executable code identity is unavailable".to_string())?;
    let verified_file = verified_code_identity_for_file(&canonical)
        .map_err(|_| "on-disk executable code identity is unavailable".to_string())?;
    if running_code_hash != verified_file.code_directory_hash {
        return Err("running executable does not match the on-disk binary".to_string());
    }
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
        reason: "detached CLI process with verified executable identity and no known owner"
            .to_string(),
    })
}

fn verify_process_ownership(
    system: &System,
    pid: u32,
    sampled_identity: &ProcessInfo,
    service_pids: &HashSet<u32>,
    ownership_evidence: &impl ProcessOwnershipEvidence,
) -> std::result::Result<(), String> {
    let current_uid = unsafe { libc::getuid() };
    let process_group = sampled_identity.process_group;
    if has_direct_child_process(system, pid) {
        return Err("process has child workloads and cannot be signaled alone".to_string());
    }
    if system.process(Pid::from_u32(pid)).is_some() {
        let parent_pid = ownership_evidence.parent_pid(system, pid);
        let launchd_unique_id = parent_pid.and_then(|parent_pid| {
            ownership_evidence
                .verified_launchd_parent_unique_id(system, service_pids, parent_pid)
                .map(|unique_id| (parent_pid, unique_id))
        });
        if let Some((launchd_pid, launchd_unique_id)) = launchd_unique_id {
            let process = ownership_evidence.process_info(pid).map_err(|_| {
                "process identity is unavailable during ownership verification".to_string()
            })?;
            if process.pid == sampled_identity.pid
                && process.pid_version == sampled_identity.pid_version
                && process.unique_id == sampled_identity.unique_id
                && process.parent_unique_id == sampled_identity.parent_unique_id
                && process.parent_pid == sampled_identity.parent_pid
                && process.start_seconds == sampled_identity.start_seconds
                && process.start_microseconds == sampled_identity.start_microseconds
                && process.user_id == sampled_identity.user_id
                && process.process_group == sampled_identity.process_group
                && process.flags == sampled_identity.flags
                && has_verified_no_controlling_terminal(
                    process.tty_device,
                    process.tty_process_group,
                    process.flags,
                )
                && is_verified_unmanaged_launchd_child(
                    &process,
                    launchd_pid,
                    launchd_unique_id,
                    service_pids,
                )
            {
                return Ok(());
            }
            return Err(
                "process origin is a service or cannot be distinguished from reparenting"
                    .to_string(),
            );
        }
    }
    let mut current = pid;
    for _ in 0..MAX_ANCESTRY_DEPTH {
        let Some(process) = system.process(Pid::from_u32(current)) else {
            return Err("process ancestry is incomplete".to_string());
        };
        let info = ownership_evidence
            .process_info(current)
            .map_err(|_| "process ancestry identity is unavailable".to_string())?;
        if info.pid != current || info.start_seconds != process.start_time() {
            return Err("process ancestry changed during verification".to_string());
        }
        if current == pid
            && (info.pid_version != sampled_identity.pid_version
                || info.start_microseconds != sampled_identity.start_microseconds
                || info.user_id != sampled_identity.user_id
                || info.parent_pid != sampled_identity.parent_pid
                || info.process_group != sampled_identity.process_group)
        {
            return Err("process identity changed during ancestry verification".to_string());
        }
        if info.user_id != current_uid {
            return Err("process ancestry belongs to another user".to_string());
        }
        if info.process_group != process_group {
            return Err("process ancestry crosses a process-group boundary".to_string());
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
        if name.trim().is_empty() || is_protected_owner_name(&name) {
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
            .ok_or_else(|| "process parent is unavailable".to_string())?;
        if info.parent_pid != parent {
            return Err("process ancestry disagrees across identity sources".to_string());
        }
        if parent == 1 {
            return Err(
                "process ownership is unverifiable after reparenting to launchd".to_string(),
            );
        }
        if parent < 1 {
            return Err("process ancestry has an invalid root".to_string());
        }
        current = parent;
    }
    Err("process ancestry exceeds the verification limit".to_string())
}

fn is_verified_unmanaged_launchd_child(
    process: &ProcessInfo,
    launchd_pid: u32,
    launchd_unique_id: u64,
    service_pids: &HashSet<u32>,
) -> bool {
    process.pid > 1
        && process.parent_pid == launchd_pid
        && process.parent_unique_id == launchd_unique_id
        && process.process_group == process.pid
        && process.flags & PROC_FLAG_SLEADER != 0
        && !service_pids.contains(&process.pid)
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

    #[test]
    fn verified_unmanaged_launchd_child_has_a_reachable_ownership_path() {
        let launchd_unique_id = 100;
        let mut candidate = ProcessInfo {
            pid: 42,
            parent_pid: 1,
            parent_unique_id: launchd_unique_id,
            process_group: 42,
            flags: PROC_FLAG_SLEADER,
            ..ProcessInfo::default()
        };

        assert!(is_verified_unmanaged_launchd_child(
            &candidate,
            1,
            launchd_unique_id,
            &HashSet::new()
        ));

        candidate.parent_unique_id += 1;
        assert!(!is_verified_unmanaged_launchd_child(
            &candidate,
            1,
            launchd_unique_id,
            &HashSet::new()
        ));
        candidate.parent_unique_id = launchd_unique_id;
        assert!(!is_verified_unmanaged_launchd_child(
            &candidate,
            1,
            launchd_unique_id,
            &HashSet::from([candidate.pid])
        ));
        candidate.flags = 0;
        assert!(!is_verified_unmanaged_launchd_child(
            &candidate,
            1,
            launchd_unique_id,
            &HashSet::new()
        ));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn verified_cli_candidate_reaches_enrollment_and_cleanup_revalidation() {
        use super::super::policy::{Decision, DecisionResponse};
        use std::process::{Child, Stdio};

        struct ModeledLaunchdChild {
            pid: u32,
            info: ProcessInfo,
        }
        impl ProcessOwnershipEvidence for ModeledLaunchdChild {
            fn process_info(&self, pid: u32) -> std::result::Result<ProcessInfo, String> {
                if pid == self.pid {
                    return Ok(self.info.clone());
                }
                super::process_info(pid).map_err(|error| error.to_string())
            }

            fn parent_pid(&self, system: &System, pid: u32) -> Option<u32> {
                if pid == self.pid {
                    Some(self.info.parent_pid)
                } else {
                    system
                        .process(Pid::from_u32(pid))?
                        .parent()
                        .map(Pid::as_u32)
                }
            }

            fn verified_launchd_parent_unique_id(
                &self,
                system: &System,
                service_pids: &HashSet<u32>,
                launchd_pid: u32,
            ) -> Option<u64> {
                super::verified_launchd_parent_unique_id(system, service_pids, launchd_pid)
            }
        }

        struct FixtureProcess {
            child: Child,
            stop_path: std::path::PathBuf,
        }
        impl Drop for FixtureProcess {
            fn drop(&mut self) {
                let _ = std::fs::write(&self.stop_path, b"stop");
                if self.child.try_wait().ok().flatten().is_none() {
                    let _ = self.child.kill();
                }
                let _ = self.child.wait();
            }
        }

        let temp = tempfile::tempdir().expect("isolated candidate fixture");
        let source = temp.path().join("eligible-cli.c");
        let executable = temp.path().join("eligible-cli");
        let stop_path = temp.path().join("stop");
        std::fs::write(
            &source,
            b"#include <stdint.h>\n#include <unistd.h>\nint main(int argc, char **argv) { if (setsid() < 0) return 2; volatile uint64_t n = 0; for (;;) { n++; if ((n & 0xfffff) == 0 && access(argv[1], F_OK) == 0) return 0; } }\n",
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

        let child = Command::new(&executable)
            .arg(&stop_path)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("start isolated CLI fixture");
        let fixture = FixtureProcess { child, stop_path };
        let result = (|| -> anyhow::Result<()> {
            let mut system = System::new_all();
            system.refresh_processes(ProcessesToUpdate::All, true);
            let pid = fixture.child.id();
            for _ in 0..5 {
                std::thread::sleep(Duration::from_secs(1));
                system.refresh_processes(ProcessesToUpdate::All, true);
                if system
                    .process(Pid::from_u32(pid))
                    .is_some_and(|process| process.cpu_usage() > CPU_THRESHOLD)
                {
                    break;
                }
            }
            let process = system
                .process(Pid::from_u32(pid))
                .context("find isolated high-CPU CLI")?;
            assert!(process.cpu_usage() > CPU_THRESHOLD);
            let service_pids = launchd_service_pids()?;
            let launchd_unique_id = verified_launchd_parent_unique_id(&system, &service_pids, 1)
                .context("verify launchd generation for the ownership fixture")?;
            // Model libproc's complete view of an unmanaged launchd child; the production
            // ownership verifier still evaluates every field and protection itself.
            let ownership_evidence = ModeledLaunchdChild {
                pid,
                info: ProcessInfo {
                    pid,
                    pid_version: 1,
                    unique_id: u64::from(pid),
                    parent_unique_id: launchd_unique_id,
                    parent_pid: 1,
                    user_id: unsafe { libc::getuid() },
                    process_group: pid,
                    flags: PROC_FLAG_SLEADER,
                    tty_device: NO_TTY_DEVICE,
                    tty_process_group: 0,
                    start_seconds: process.start_time(),
                    start_microseconds: 0,
                },
            };
            let candidate = classify_process_with_evidence(
                &system,
                pid,
                process,
                &service_pids,
                &ownership_evidence,
            )
            .map_err(anyhow::Error::msg)?;
            assert!(candidate.cpu_percent > CPU_THRESHOLD);

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
                    post_approval_tracking.get(&pid),
                    None,
                    Duration::from_secs(60),
                    approval_start + Duration::from_secs(59),
                ),
                None
            );
            assert_eq!(
                super::super::cleanup_action(
                    post_approval_tracking.get(&pid),
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
            let signals = std::cell::Cell::new(0);
            super::super::send_signal_with_policy_persistence(
                &candidate,
                libc::SIGTERM,
                || {
                    anyhow::ensure!(
                        persisted.approval_for(&candidate.identity).is_some(),
                        "approval was not durable before cleanup"
                    );
                    lock.save(&persisted)
                },
                |expected| {
                    let mut current_system = System::new_all();
                    current_system.refresh_processes(ProcessesToUpdate::All, true);
                    let current_process = current_system
                        .process(Pid::from_u32(expected.pid))
                        .context("candidate exited before signal revalidation")?;
                    let current = classify_process_with_evidence(
                        &current_system,
                        expected.pid,
                        current_process,
                        &service_pids,
                        &ownership_evidence,
                    )
                    .map_err(anyhow::Error::msg)?;
                    anyhow::ensure!(
                        current.identity == *expected,
                        "process identity changed before cleanup"
                    );
                    anyhow::ensure!(
                        persisted.approval_for(&current.identity).is_some(),
                        "approval no longer matches the candidate"
                    );
                    Ok(())
                },
                |identity, signal| {
                    assert_eq!(identity.pid, pid);
                    assert_eq!(signal, libc::SIGTERM);
                    signals.set(signals.get() + 1);
                    Ok(())
                },
            )?;
            assert_eq!(signals.get(), 1);
            Ok(())
        })();
        drop(fixture);
        result.expect("exercise isolated candidate enrollment and cleanup flow");
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
    fn detached_work_with_a_surviving_owner_and_children_is_protected() {
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
                .all(|candidate| candidate.identity.pid != worker_pid),
            "a detached workload with a surviving communicating owner must not be enrolled; cpu={fixture_cpu:.1}% protected={} protection_error={:?}",
            snapshot.protected_high_cpu,
            snapshot.protection_error
        );
        let root_process = sampler
            .system
            .process(Pid::from_u32(root_pid))
            .expect("find synthetic parent with a child");
        assert!(root_process.cpu_usage() > CPU_THRESHOLD);
        assert!(has_direct_child_process(&sampler.system, root_pid));
        assert!(classify_process(&sampler.system, root_pid, root_process, &service_pids).is_err());
        assert!(
            classify_process(&sampler.system, worker_pid, fixture_process, &service_pids).is_err()
        );

        let sent = std::cell::Cell::new(0);
        for pid in [root_pid, worker_pid] {
            let info = process_info(pid).expect("read protected fixture identity");
            let candidate = Candidate {
                identity: ProcessIdentity {
                    pid,
                    pid_version: info.pid_version,
                    start_seconds: info.start_seconds,
                    start_microseconds: info.start_microseconds,
                    executable: executable.to_string_lossy().into_owned(),
                    user_id: info.user_id,
                    fingerprint: String::new(),
                    code_directory_hash: String::new(),
                },
                name: "tree-cli-fixture".to_string(),
                cpu_percent: CPU_THRESHOLD + 1.0,
                memory_bytes: 0,
                reason: "isolated test candidate".to_string(),
            };
            assert!(send_signal_with(
                &candidate,
                libc::SIGTERM,
                |identity| verify_current_identity(identity, &[]),
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
            "protected synthetic processes receive no signal"
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
