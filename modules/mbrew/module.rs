use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fs;
use std::io::Write;
use std::path::{Component, Path, PathBuf};
use std::process::Command;

use anyhow::{bail, Context};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::credentials;
use crate::modules::{ModuleContext, ModuleHealth, ModuleLogger, ModuleStatus};

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[schemars(description = "Typed Homebrew maintenance settings.")]
pub(crate) struct MbrewConfig {
    #[serde(rename = "askpass_path")]
    #[schemars(length(min = 1))]
    askpass_path: String,
    #[serde(rename = "homebrew_bin")]
    #[schemars(length(min = 1))]
    homebrew_bin: String,
    #[serde(default, rename = "trusted_taps")]
    #[schemars(inner(length(min = 1)), extend("uniqueItems" = true))]
    trusted_taps: Vec<String>,
    #[serde(rename = "sudoers_path")]
    #[schemars(length(min = 1))]
    sudoers_path: String,
    #[serde(rename = "sudoers_timeout_path")]
    #[schemars(length(min = 1))]
    sudoers_timeout_path: String,
    #[serde(rename = "sudo_timeout_hours")]
    #[schemars(range(min = 1))]
    sudo_timeout_hours: u64,
}

impl Default for MbrewConfig {
    fn default() -> Self {
        Self {
            askpass_path: "~/Library/Application Support/scriptd/mbrew/brew_askpass.sh".to_string(),
            homebrew_bin: "/opt/homebrew/bin/brew".to_string(),
            trusted_taps: Vec::new(),
            sudoers_path: "/etc/sudoers.d/homebrew".to_string(),
            sudoers_timeout_path: "/etc/sudoers.d/homebrew_timeout".to_string(),
            sudo_timeout_hours: 2,
        }
    }
}

impl MbrewConfig {
    pub(crate) fn homebrew_bin(&self) -> &str {
        &self.homebrew_bin
    }
}

#[derive(Debug, Default)]
struct MbrewState {
    last_run_at: Option<String>,
    last_error: Option<String>,
    last_message: Option<String>,
    repaired_casks: Vec<String>,
    deferred_casks: Vec<String>,
    failed_casks: Vec<String>,
}

static STATE: once_cell::sync::Lazy<std::sync::Mutex<MbrewState>> =
    once_cell::sync::Lazy::new(|| std::sync::Mutex::new(MbrewState::default()));

/// Serializes every ledger read-modify-write cycle so a control-center
/// decision can be applied while a maintenance run is recording its outcome.
static LEDGER_LOCK: once_cell::sync::Lazy<std::sync::Mutex<()>> =
    once_cell::sync::Lazy::new(|| std::sync::Mutex::new(()));

/// Holds the in-process ledger lock and an on-disk lock for the lifetime of a
/// ledger transaction. The on-disk lock also serializes access from the
/// control-center bridge when it runs as its own process.
struct LedgerGuard {
    _process: std::sync::MutexGuard<'static, ()>,
    _file: crate::execution_lock::ExecutionLock,
}

fn lock_ledger(state_dir: &Path) -> anyhow::Result<LedgerGuard> {
    let process = LEDGER_LOCK
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    let file = crate::execution_lock::ExecutionLock::acquire(&state_dir.join("mbrew-ledger.lock"))
        .context("acquire the Homebrew outcome ledger lock")?;
    Ok(LedgerGuard {
        _process: process,
        _file: file,
    })
}

fn run_command(
    program: &str,
    args: &[&str],
    input: Option<&str>,
    env: Option<&[(&str, &str)]>,
) -> anyhow::Result<(String, String, i32)> {
    let mut command = Command::new(program);
    command.args(args);
    if let Some(values) = env {
        for (key, value) in values {
            command.env(key, value);
        }
    }
    if let Some(input) = input {
        command
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
        let mut child = command.spawn()?;
        if let Some(mut stdin) = child.stdin.take() {
            stdin.write_all(input.as_bytes())?;
            let _ = stdin.flush();
        }
        let output = child.wait_with_output()?;
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        Ok((
            stdout.into_owned(),
            stderr.into_owned(),
            output.status.code().unwrap_or(1),
        ))
    } else {
        let output = command.output()?;
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        Ok((
            stdout.into_owned(),
            stderr.into_owned(),
            output.status.code().unwrap_or(1),
        ))
    }
}

fn keychain_password() -> anyhow::Result<String> {
    Ok(credentials::admin_password()?.unwrap_or_default())
}

fn homebrew_user_home() -> anyhow::Result<PathBuf> {
    let uid = if unsafe { libc::geteuid() } == 0 {
        credentials::console_uid()?
    } else {
        unsafe { libc::geteuid() }
    };
    if uid == 0 {
        bail!("Homebrew requires a logged-in non-root user");
    }
    credentials::home_dir_for_uid(uid)
}

fn homebrew_path(raw: &str) -> anyhow::Result<PathBuf> {
    if raw == "~" {
        return homebrew_user_home();
    }
    if let Some(suffix) = raw.strip_prefix("~/") {
        return Ok(homebrew_user_home()?.join(suffix));
    }
    Ok(PathBuf::from(raw))
}

/// Name of the tracked askpass helper that ships with the module.
const ASKPASS_SOURCE: &str = "brew_askpass.sh";

/// Repository root that holds the tracked module assets.
fn tracked_root() -> PathBuf {
    std::env::var_os("SCRIPTD_ROOT_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")))
}

/// Locates the tracked askpass helper inside the repository.
///
/// The helper is a repository asset, so the installed copy is always derived
/// from the tracked source rather than generated from inline content.
fn askpass_source_path() -> anyhow::Result<PathBuf> {
    Ok(tracked_root()
        .join("modules")
        .join("mbrew")
        .join(ASKPASS_SOURCE))
}

fn write_askpass(config: &MbrewConfig, logger: &ModuleLogger) -> anyhow::Result<()> {
    let path = homebrew_path(&config.askpass_path)?;
    let source = askpass_source_path()?;
    let script = fs::read(&source)
        .with_context(|| format!("read tracked askpass helper {}", source.display()))?;

    // The installed copy is an installation artifact of the tracked source,
    // never an independently authored file. A copy that already matches the
    // packaged source is left alone; a stale or missing one is refreshed from
    // it, so an upgrade always ships the current helper.
    if path.exists() && fs::read(&path).is_ok_and(|installed| installed == script) {
        return Ok(());
    }
    fs::create_dir_all(path.parent().expect("path has parent"))?;
    crate::paths::write_private_atomic(&path, &script)
        .with_context(|| format!("write askpass helper {}", path.display()))?;
    let _ = Command::new("chmod")
        .args(["+x", &path.to_string_lossy()])
        .status();
    logger.info(&format!("refreshed askpass helper {}", path.display()));
    Ok(())
}

fn ensure_askpass(config: &MbrewConfig, logger: &ModuleLogger) -> anyhow::Result<()> {
    let path = homebrew_path(&config.askpass_path)?;
    if path.exists() {
        return write_askpass(config, logger);
    }
    if unsafe { libc::geteuid() } == 0 {
        bail!("mbrew setup required. run './scriptd.sh config mbrew' as the logged-in user");
    }
    let existing = keychain_password()?;
    if existing.is_empty() {
        bail!("mbrew setup required. run './scriptd.sh config mbrew'");
    }
    write_askpass(config, logger)
}

fn install_privilege_broker(
    config: &MbrewConfig,
    context: &ModuleContext,
    password: &str,
) -> anyhow::Result<()> {
    const SUPPORT_DIR: &str = "/Library/Application Support/scriptd";
    const BRIDGE_PATH: &str = "/Library/Application Support/scriptd/privilege_bridge.rb";
    const POLICY_PATH: &str = "/Library/Application Support/scriptd/approved-cask-sources.txt";
    const CLIENT_PATH: &str = "/usr/local/libexec/scriptd-broker";
    const DAEMON_PLIST: &str = "/Library/LaunchDaemons/com.astronlab.scriptd.broker.plist";

    validate_config(config)?;
    let nonce = format!(
        "{}-{}",
        std::process::id(),
        chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default()
    );
    let bridge_stage = std::env::temp_dir().join(format!("scriptd-bridge-{nonce}"));
    let policy_stage = std::env::temp_dir().join(format!("scriptd-policy-{nonce}"));
    let plist_stage = std::env::temp_dir().join(format!("scriptd-broker-plist-{nonce}"));
    let result = (|| {
        let bridge_source = context.module_dir.join("privilege_bridge.rb");
        let bridge = fs::read(&bridge_source)
            .with_context(|| format!("read generic Homebrew bridge {}", bridge_source.display()))?;
        let current = std::env::current_exe().context("resolve the running scriptd binary")?;
        sign_broker_binary(&current)?;
        let policy = format!("{}\n", config.trusted_taps.join("\n"));
        let service = crate::config::read_service_config(&context.repo_root)
            .context("read service identity for the installed privilege broker")?;
        let plist = broker_daemon_plist(&context.repo_root, &service.label);
        write_staged_private(&bridge_stage, &bridge)?;
        write_staged_private(&policy_stage, policy.as_bytes())?;
        write_staged_private(&plist_stage, plist.as_bytes())?;

        let password = format!("{password}\n");
        for (args, stdin) in [
            (
                vec![
                    "-S",
                    "/usr/bin/install",
                    "-d",
                    "-o",
                    "root",
                    "-g",
                    "wheel",
                    "-m",
                    "755",
                    SUPPORT_DIR,
                ],
                password.as_str(),
            ),
            (
                vec![
                    "-S",
                    "/usr/bin/install",
                    "-d",
                    "-o",
                    "root",
                    "-g",
                    "wheel",
                    "-m",
                    "755",
                    "/usr/local/libexec",
                ],
                password.as_str(),
            ),
            (
                vec![
                    "-S",
                    "/usr/bin/install",
                    "-d",
                    "-o",
                    "root",
                    "-g",
                    "wheel",
                    "-m",
                    "755",
                    "/Library/LaunchDaemons",
                ],
                password.as_str(),
            ),
        ] {
            run_sudo_checked(&args, stdin)?;
        }
        let current = current.to_string_lossy().into_owned();
        let bridge_stage = bridge_stage.to_string_lossy().into_owned();
        let policy_stage = policy_stage.to_string_lossy().into_owned();
        let plist_stage = plist_stage.to_string_lossy().into_owned();
        for args in [
            vec![
                "-S",
                "/usr/bin/install",
                "-o",
                "root",
                "-g",
                "wheel",
                "-m",
                "755",
                &current,
                CLIENT_PATH,
            ],
            vec![
                "-S",
                "/usr/bin/install",
                "-o",
                "root",
                "-g",
                "wheel",
                "-m",
                "644",
                &bridge_stage,
                BRIDGE_PATH,
            ],
            vec![
                "-S",
                "/usr/bin/install",
                "-o",
                "root",
                "-g",
                "wheel",
                "-m",
                "644",
                &policy_stage,
                POLICY_PATH,
            ],
            vec![
                "-S",
                "/usr/bin/install",
                "-o",
                "root",
                "-g",
                "wheel",
                "-m",
                "644",
                &plist_stage,
                DAEMON_PLIST,
            ],
        ] {
            run_sudo_checked(&args, &password)?;
        }
        // Remove the legacy broad Homebrew upgrade grant so privileged work
        // can only flow through an authenticated cask job.
        for path in ["/etc/sudoers.d/homebrew", "/etc/sudoers.d/homebrew_timeout"] {
            run_sudo_checked(&["-S", "/bin/rm", "-f", path], &password)?;
        }
        Ok(())
    })();
    let _ = fs::remove_file(&bridge_stage);
    let _ = fs::remove_file(&policy_stage);
    let _ = fs::remove_file(&plist_stage);
    result
}

fn sign_broker_binary(binary: &Path) -> anyhow::Result<()> {
    let status = Command::new("/usr/bin/codesign")
        .args(["--force", "--sign", "-", "--options", "runtime,library"])
        .arg(binary)
        .status()
        .context(
            "enable the hardened runtime and library validation for the broker and service binary",
        )?;
    if !status.success() {
        bail!("could not enable the hardened runtime for the broker binary");
    }

    let output = Command::new("/usr/bin/codesign")
        .args(["--display", "--verbose=4"])
        .arg(binary)
        .output()
        .context("verify the broker binary code signature")?;
    let details = format!(
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    if !output.status.success()
        || !details
            .lines()
            .any(|line| line.starts_with("CodeDirectory ") && line.contains("runtime)"))
    {
        bail!("broker binary is not signed with the hardened runtime");
    }
    Ok(())
}

fn broker_daemon_plist(repo: &Path, service_label: &str) -> String {
    let repo = xml_escape(&repo.to_string_lossy());
    let service_label = xml_escape(service_label);
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\"><dict>\n<key>Label</key><string>com.astronlab.scriptd.broker</string>\n<key>ProgramArguments</key><array><string>/usr/local/libexec/scriptd-broker</string><string>broker</string><string>serve</string></array>\n<key>RunAtLoad</key><true/>\n<key>EnvironmentVariables</key><dict><key>SCRIPTD_ROOT_DIR</key><string>{repo}</string><key>SCRIPTD_SERVICE_LABEL</key><string>{service_label}</string><key>PATH</key><string>/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin</string></dict>\n<key>StandardOutPath</key><string>/Library/Logs/scriptd-broker.log</string>\n<key>StandardErrorPath</key><string>/Library/Logs/scriptd-broker.log</string>\n</dict></plist>\n"
    )
}

fn xml_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

fn write_staged_private(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn run_sudo_checked(args: &[&str], password: &str) -> anyhow::Result<()> {
    let (stdout, stderr, status) = run_command("/usr/bin/sudo", args, Some(password), None)?;
    if status != 0 {
        bail!(
            "privilege broker setup command failed with status {status}: {}{}",
            stderr.trim(),
            stdout.trim()
        );
    }
    Ok(())
}

fn build_brew_command(
    config: &MbrewConfig,
    args: &[&str],
    effective_uid: u32,
    console_uid: Option<u32>,
) -> anyhow::Result<Command> {
    let askpass_path = homebrew_path(&config.askpass_path)?;
    if effective_uid == 0 {
        let uid = console_uid.context("root-run Homebrew needs a logged-in console user")?;
        if uid == 0 {
            bail!("root-run Homebrew refuses to run as root without a console user");
        }
        let mut command = Command::new("/usr/bin/sudo");
        command
            .args(["-n", "-u"])
            .arg(format!("#{uid}"))
            .args(["-H", "--", "/usr/bin/env"])
            .arg(format!("SUDO_ASKPASS={}", askpass_path.display()))
            .arg(&config.homebrew_bin)
            .args(args);
        Ok(command)
    } else {
        let mut command = Command::new(&config.homebrew_bin);
        command.args(args).env("SUDO_ASKPASS", askpass_path);
        Ok(command)
    }
}

fn command_for_brew(config: &MbrewConfig, args: &[&str]) -> anyhow::Result<(String, String, i32)> {
    let effective_uid = unsafe { libc::geteuid() };
    let console_uid = (effective_uid == 0)
        .then(credentials::console_uid)
        .transpose()?;
    let output = build_brew_command(config, args, effective_uid, console_uid)?
        .output()
        .context("brew command failed to execute")?;
    Ok((
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
        output.status.code().unwrap_or(1),
    ))
}

fn brew_failure(stderr: &str, fallback: &str) -> String {
    if stderr.trim().is_empty() {
        fallback.to_string()
    } else {
        stderr.trim().to_string()
    }
}

fn installed_brew_taps(config: &MbrewConfig) -> anyhow::Result<BTreeSet<String>> {
    let (stdout, stderr, status) = command_for_brew(config, &["tap"])?;
    if status != 0 {
        bail!(
            "brew tap listing failed: {}",
            brew_failure(&stderr, "brew tap failed")
        );
    }
    Ok(stdout
        .lines()
        .map(str::trim)
        .filter(|tap| !tap.is_empty())
        .map(ToString::to_string)
        .collect())
}

fn trust_configured_taps(config: &MbrewConfig, logger: &ModuleLogger) -> anyhow::Result<()> {
    if config.trusted_taps.is_empty() {
        return Ok(());
    }

    let installed = installed_brew_taps(config)?;
    for tap in &config.trusted_taps {
        if !installed.contains(tap) {
            logger.warn(&format!(
                "configured trusted tap {tap} is not installed; skipping trust"
            ));
            continue;
        }

        let (stdout, stderr, status) = command_for_brew(config, &["trust", "--tap", tap])?;
        if status != 0 {
            bail!(
                "brew trust --tap {tap} failed: {}",
                brew_failure(&stderr, "brew trust failed")
            );
        }
        if !stdout.trim().is_empty() {
            logger.info(stdout.trim());
        }
        if !stderr.trim().is_empty() {
            logger.warn(stderr.trim());
        }
    }
    Ok(())
}

fn untrusted_homebrew_entries(output: &str) -> Vec<String> {
    const PREFIX: &str = "Skipping ";
    const SUFFIX: &str = " because it is not trusted";
    let mut entries = Vec::new();

    for line in output.lines() {
        let Some(start) = line.find(PREFIX) else {
            continue;
        };
        let rest = &line[start + PREFIX.len()..];
        let Some(end) = rest.find(SUFFIX) else {
            continue;
        };
        let entry = rest[..end].trim();
        if !entry.is_empty() && !entries.iter().any(|existing| existing == entry) {
            entries.push(entry.to_string());
        }
    }

    entries
}

fn reject_untrusted_homebrew_entries(update_out: &str, update_err: &str) -> anyhow::Result<()> {
    let output = format!("{update_out}\n{update_err}");
    let entries = untrusted_homebrew_entries(&output);
    if entries.is_empty() {
        return Ok(());
    }

    bail!(
        "brew update skipped untrusted entries: {}. Add only reviewed whole taps to mbrew settings.trusted_taps; trust formulae, casks, or commands with the matching brew trust option, then rerun",
        entries.join(", ")
    );
}

pub(crate) fn validate_config(config: &MbrewConfig) -> anyhow::Result<()> {
    for (name, value) in [
        ("askpass_path", config.askpass_path.as_str()),
        ("homebrew_bin", config.homebrew_bin.as_str()),
        ("sudoers_path", config.sudoers_path.as_str()),
        ("sudoers_timeout_path", config.sudoers_timeout_path.as_str()),
    ] {
        crate::paths::validate_config_path(&format!("mbrew {name}"), value, false)?;
    }
    if config.sudo_timeout_hours == 0 {
        anyhow::bail!("mbrew sudo_timeout_hours must be greater than zero");
    }
    for tap in &config.trusted_taps {
        let mut parts = tap.split('/');
        let owner = parts.next().unwrap_or_default();
        let repository = parts.next().unwrap_or_default();
        let valid_component = |value: &str| {
            !value.is_empty()
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        };
        if parts.next().is_some() || !valid_component(owner) || !valid_component(repository) {
            anyhow::bail!("mbrew trusted_taps entries must use owner/repository form: {tap}");
        }
    }
    Ok(())
}

fn update_from_config(context: &ModuleContext) -> anyhow::Result<MbrewConfig> {
    let Some(crate::config::ModuleSettings::Mbrew(config)) = context.settings.as_ref() else {
        anyhow::bail!("mbrew typed settings were not loaded");
    };
    Ok(config.clone())
}

#[derive(Debug, Default, PartialEq, Eq)]
struct BrewMaintenanceOutcome {
    repaired_casks: Vec<String>,
    deferred_casks: Vec<String>,
    failed_casks: Vec<String>,
    retryable_casks: BTreeSet<String>,
    attention_casks: BTreeSet<String>,
    /// Casks the user dismissed: still outstanding, but never re-prompted and
    /// never retried automatically.
    dismissed_casks: BTreeSet<String>,
    /// Casks for which a real `brew upgrade` was actually launched. Only these
    /// count towards the ledger attempt counter.
    attempted_casks: BTreeSet<String>,
    reasons: BTreeMap<String, String>,
    /// The class of blocker that stopped each deferred cask. The class
    /// decides whether retrying can help and which recovery action to offer.
    blockers: BTreeMap<String, CaskBlockerClass>,
    cask_error: Option<String>,
    formula_error: Option<String>,
    cleanup_error: Option<String>,
}

/// Why a cask's maintenance did not complete.
///
/// The class is what the interface shows the user, so each class carries both
/// a stable name and the recovery action that can actually resolve it. A
/// cask that cannot be retried until a human installs something must never
/// advertise itself as retryable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum CaskBlockerClass {
    /// The local Scriptd setup for Homebrew maintenance is incomplete.
    SetupMissing,
    /// The companion automation bridge is not installed or not paired.
    BridgeAbsent,
    /// An application from this cask is running and must be closed first.
    ApplicationRunning,
    /// The cask's running state could not be established.
    ActivityUnverifiable,
    /// The authorization policy denies this operation.
    PolicyDenied,
    /// A real Homebrew upgrade ran and failed.
    UpgradeFailed,
}

impl CaskBlockerClass {
    /// The stable name recorded in the ledger and shown to the interface.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SetupMissing => "setup_missing",
            Self::BridgeAbsent => "bridge_absent",
            Self::ApplicationRunning => "application_running",
            Self::ActivityUnverifiable => "activity_unverifiable",
            Self::PolicyDenied => "policy_denied",
            Self::UpgradeFailed => "upgrade_failed",
        }
    }

    /// Whether retrying the same operation could succeed without the user
    /// changing anything first.
    ///
    /// A missing setup or bridge, a denied policy, and an unverifiable
    /// activity state all need a human action before a retry can work.
    pub fn is_retryable(self) -> bool {
        matches!(self, Self::ApplicationRunning | Self::UpgradeFailed)
    }

    /// The recovery action that can resolve this blocker.
    pub fn recovery_action(self) -> &'static str {
        match self {
            Self::SetupMissing => {
                "Run the Homebrew setup to finish installing the maintenance helper."
            }
            Self::BridgeAbsent => "Install the automation bridge and pair this app with it.",
            Self::ApplicationRunning => "Quit the running app, then retry the upgrade.",
            Self::ActivityUnverifiable => {
                "The app's state could not be read. Retry once the app can be inspected."
            }
            Self::PolicyDenied => {
                "This package source is not approved. Review the trusted sources."
            }
            Self::UpgradeFailed => "The upgrade failed. Review the error, then retry.",
        }
    }
}

#[derive(Debug, Default, PartialEq, Eq)]
struct CaskRuntimeIdentity {
    bundle_ids: BTreeSet<String>,
    app_paths: BTreeSet<String>,
    binary_paths: BTreeSet<String>,
    service_names: BTreeSet<String>,
    package_receipts: BTreeSet<String>,
    observation_incomplete: bool,
}

struct CaskMetadata {
    identity: CaskRuntimeIdentity,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RunningApplication {
    pub(crate) bundle_id: Option<String>,
    pub(crate) path: Option<String>,
}

const RUNNING_APPLICATIONS_SCRIPT: &str = r#"'use strict';

ObjC.import('AppKit');

function value(value) {
  return value ? ObjC.unwrap(value) : null;
}

function run() {
  var applications = $.NSWorkspace.sharedWorkspace.runningApplications.js;
  var result = applications.map(function(app) {
    var bundleUrl = app.bundleURL;
    return {
      bundleId: value(app.bundleIdentifier),
      path: bundleUrl ? value(bundleUrl.path) : null
    };
  });
  return JSON.stringify(result);
}

run();"#;

fn normalize_runtime_path(value: &str) -> Option<String> {
    let value = value.trim();
    if value.is_empty()
        || value.starts_with('~')
        || value.contains('*')
        || value.contains('$')
        || value.contains("{{")
        || value.contains("}}")
        || !Path::new(value).is_absolute()
    {
        return None;
    }

    let mut normalized = PathBuf::new();
    for component in Path::new(value).components() {
        match component {
            Component::RootDir => normalized.push("/"),
            Component::CurDir => {}
            Component::ParentDir => {
                normalized.pop();
            }
            Component::Normal(part) => normalized.push(part),
            Component::Prefix(_) => return None,
        }
    }

    Some(normalized.to_string_lossy().into_owned())
}

fn normalize_app_path(value: &str) -> Option<String> {
    let normalized = normalize_runtime_path(value)?;
    let mut app_path = PathBuf::new();
    for component in Path::new(&normalized).components() {
        app_path.push(component.as_os_str());
        if app_path
            .file_name()
            .is_some_and(|part| part.to_string_lossy().ends_with(".app"))
        {
            return Some(app_path.to_string_lossy().into_owned());
        }
    }
    None
}

fn normalize_artifact_path(value: &str, allow_non_app: bool) -> Option<String> {
    let value = value.trim();
    if value.is_empty()
        || value.starts_with('~')
        || value.contains('*')
        || value.contains('$')
        || value.contains("{{")
        || value.contains("}}")
    {
        return None;
    }

    let path = Path::new(value);
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        if path
            .components()
            .any(|component| matches!(component, Component::ParentDir | Component::Prefix(_)))
        {
            return None;
        }
        Path::new("/Applications").join(path)
    };
    let normalized = normalize_runtime_path(&absolute.to_string_lossy())?;
    if allow_non_app {
        Some(normalized)
    } else {
        normalize_app_path(&normalized)
    }
}

fn collect_artifact_paths(
    value: &serde_json::Value,
    app_paths: &mut BTreeSet<String>,
    allow_non_app: bool,
) {
    match value {
        serde_json::Value::String(value) => {
            if let Some(path) = normalize_artifact_path(value, allow_non_app) {
                app_paths.insert(path);
            }
        }
        serde_json::Value::Array(values) => {
            for value in values {
                collect_artifact_paths(value, app_paths, allow_non_app);
            }
        }
        _ => {}
    }
}

fn insert_bundle_id(value: &str, bundle_ids: &mut BTreeSet<String>) {
    let value = value.trim();
    let valid = !value.is_empty()
        && value.split('.').all(|segment| {
            !segment.is_empty()
                && segment
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        });
    if valid {
        bundle_ids.insert(value.to_string());
    }
}

fn collect_bundle_ids(value: &serde_json::Value, bundle_ids: &mut BTreeSet<String>) {
    match value {
        serde_json::Value::String(value) => insert_bundle_id(value, bundle_ids),
        serde_json::Value::Array(values) => {
            for value in values {
                collect_bundle_ids(value, bundle_ids);
            }
        }
        _ => {}
    }
}

fn collect_signal_bundle_ids(value: &serde_json::Value, bundle_ids: &mut BTreeSet<String>) {
    let serde_json::Value::Array(values) = value else {
        return;
    };
    if let Some(bundle_id) = values.get(1).and_then(serde_json::Value::as_str) {
        insert_bundle_id(bundle_id, bundle_ids);
    }
    for value in values {
        if value.is_array() {
            collect_signal_bundle_ids(value, bundle_ids);
        }
    }
}

fn collect_app_paths(value: &serde_json::Value, app_paths: &mut BTreeSet<String>) {
    match value {
        serde_json::Value::String(value) => {
            if let Some(path) = normalize_app_path(value) {
                app_paths.insert(path);
            }
        }
        serde_json::Value::Array(values) => {
            for value in values {
                collect_app_paths(value, app_paths);
            }
        }
        _ => {}
    }
}

fn collect_cask_runtime_identity(
    value: &serde_json::Value,
    identity: &mut CaskRuntimeIdentity,
    bin_dir: &Path,
) {
    let Some(object) = value.as_object() else {
        if let Some(values) = value.as_array() {
            for value in values {
                collect_cask_runtime_identity(value, identity, bin_dir);
            }
        }
        return;
    };

    if object.contains_key("app") {
        if let Some(target) = object.get("target") {
            collect_artifact_paths(target, &mut identity.app_paths, false);
        } else if let Some(app) = object.get("app") {
            collect_artifact_paths(app, &mut identity.app_paths, false);
        }
    }
    if object.contains_key("suite") {
        if let Some(target) = object.get("target") {
            collect_artifact_paths(target, &mut identity.app_paths, true);
        } else if let Some(suite) = object.get("suite") {
            collect_artifact_paths(suite, &mut identity.app_paths, true);
        }
    }
    if let Some(quit) = object.get("quit") {
        collect_bundle_ids(quit, &mut identity.bundle_ids);
    }
    if let Some(signal) = object.get("signal") {
        collect_signal_bundle_ids(signal, &mut identity.bundle_ids);
    }
    if let Some(delete) = object.get("delete") {
        collect_app_paths(delete, &mut identity.app_paths);
    }
    if object.contains_key("binary") {
        if let Some(binary) = object.get("binary") {
            identity.observation_incomplete |=
                !collect_binary_targets(binary, bin_dir, &mut identity.binary_paths);
        }
    }
    if let Some(service) = object.get("service") {
        identity.observation_incomplete |=
            !collect_service_names(service, &mut identity.service_names);
    }
    if let Some(launchctl) = object.get("launchctl") {
        identity.observation_incomplete |=
            !collect_service_names(launchctl, &mut identity.service_names);
    }
    if let Some(pkgutil) = object.get("pkgutil") {
        identity.observation_incomplete |=
            !collect_package_receipts(pkgutil, &mut identity.package_receipts);
    }
    if object
        .get("type")
        .and_then(serde_json::Value::as_str)
        .is_some_and(|value| value == "terminate_process")
    {
        if let Some(name) = object.get("name") {
            collect_app_paths(name, &mut identity.app_paths);
        }
    }

    for value in object.values() {
        collect_cask_runtime_identity(value, identity, bin_dir);
    }
}

fn cask_runtime_identity(value: &serde_json::Value) -> anyhow::Result<CaskRuntimeIdentity> {
    cask_runtime_identity_with_bin_dir(value, Path::new("/opt/homebrew/bin"))
}

fn homebrew_bin_dir(homebrew_bin: &Path) -> anyhow::Result<PathBuf> {
    let executable = homebrew_bin
        .canonicalize()
        .with_context(|| format!("resolve Homebrew executable {}", homebrew_bin.display()))?;
    executable
        .parent()
        .map(Path::to_path_buf)
        .ok_or_else(|| anyhow::anyhow!("Homebrew executable has no parent directory"))
}

fn cask_runtime_identity_with_bin_dir(
    value: &serde_json::Value,
    bin_dir: &Path,
) -> anyhow::Result<CaskRuntimeIdentity> {
    let artifacts = value
        .get("artifacts")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| anyhow::anyhow!("cask metadata is missing artifacts"))?;
    let mut identity = CaskRuntimeIdentity::default();
    for artifact in artifacts {
        collect_cask_runtime_identity(artifact, &mut identity, bin_dir);
    }
    Ok(identity)
}

fn collect_binary_targets(
    value: &serde_json::Value,
    bin_dir: &Path,
    paths: &mut BTreeSet<String>,
) -> bool {
    match value {
        serde_json::Value::String(value) => {
            let value = Path::new(value.trim());
            if value.as_os_str().is_empty()
                || value.components().any(|component| {
                    matches!(component, Component::ParentDir | Component::Prefix(_))
                })
            {
                return false;
            }
            let path = if value.is_absolute() {
                value.to_path_buf()
            } else {
                bin_dir.join(value)
            };
            let Some(path) = normalize_runtime_path(&path.to_string_lossy()) else {
                return false;
            };
            paths.insert(path);
            true
        }
        serde_json::Value::Array(values) => {
            let mut valid = !values.is_empty();
            for value in values {
                valid &= collect_binary_targets(value, bin_dir, paths);
            }
            valid
        }
        serde_json::Value::Object(object) => {
            if let Some(target) = object.get("target") {
                return collect_binary_targets(target, bin_dir, paths);
            }
            let mut found = false;
            let mut valid = true;
            for value in object
                .values()
                .filter(|value| value.is_array() || value.is_object())
            {
                found = true;
                valid &= collect_binary_targets(value, bin_dir, paths);
            }
            found && valid
        }
        _ => false,
    }
}

fn collect_service_names(value: &serde_json::Value, names: &mut BTreeSet<String>) -> bool {
    match value {
        serde_json::Value::String(value) => {
            let value = value.trim();
            let valid = !value.is_empty()
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'));
            if valid {
                names.insert(value.to_string());
            }
            valid
        }
        serde_json::Value::Array(values) => {
            let mut valid = !values.is_empty();
            for value in values {
                valid &= collect_service_names(value, names);
            }
            valid
        }
        serde_json::Value::Object(object) => {
            if let Some(name) = object.get("name").or_else(|| object.get("service")) {
                collect_service_names(name, names)
            } else {
                false
            }
        }
        _ => false,
    }
}

fn collect_package_receipts(value: &serde_json::Value, receipts: &mut BTreeSet<String>) -> bool {
    match value {
        serde_json::Value::String(value) => {
            let value = value.trim();
            let valid = !value.is_empty()
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'));
            if valid {
                receipts.insert(value.to_string());
            }
            valid
        }
        serde_json::Value::Array(values) => {
            let mut valid = !values.is_empty();
            for value in values {
                valid &= collect_package_receipts(value, receipts);
            }
            valid
        }
        serde_json::Value::Object(object) => {
            let mut valid = !object.is_empty();
            for value in object.values() {
                valid &= collect_package_receipts(value, receipts);
            }
            valid
        }
        _ => false,
    }
}

fn identity_is_known(identity: &CaskRuntimeIdentity) -> bool {
    !identity.observation_incomplete
        && (!identity.bundle_ids.is_empty()
            || !identity.app_paths.is_empty()
            || !identity.binary_paths.is_empty()
            || !identity.service_names.is_empty()
            || !identity.package_receipts.is_empty())
}

fn executable_is_running(paths: &BTreeSet<String>) -> bool {
    if paths.is_empty() {
        return false;
    }
    let mut system = sysinfo::System::new();
    system.refresh_processes(sysinfo::ProcessesToUpdate::All, true);
    let executables = system
        .processes()
        .values()
        .filter_map(|process| process.exe().map(Path::to_path_buf))
        .collect::<Vec<_>>();
    executable_matches(paths, &executables)
}

fn executable_matches(paths: &BTreeSet<String>, executables: &[PathBuf]) -> bool {
    let canonical_targets = paths
        .iter()
        .map(|path| canonical_executable(Path::new(path)))
        .collect::<BTreeSet<_>>();
    executables
        .iter()
        .any(|exe| canonical_targets.contains(&canonical_executable(exe)))
}

fn canonical_executable(path: &Path) -> PathBuf {
    path.canonicalize().unwrap_or_else(|_| path.to_path_buf())
}

fn service_is_running(name: &str) -> anyhow::Result<bool> {
    service_is_running_with(Path::new("/bin/launchctl"), name)
}

fn service_is_running_with(program: &Path, name: &str) -> anyhow::Result<bool> {
    let gui_uid = gui_user_uid()?;
    let mut observed_missing = false;
    for target in [format!("gui/{gui_uid}/{name}"), format!("system/{name}")] {
        let output = std::process::Command::new(program)
            .args(["print", &target])
            .output()
            .with_context(|| format!("launchctl print {target} failed"))?;
        if output.status.success() {
            // A loaded service can be relaunched while Homebrew is replacing its files.
            return Ok(true);
        } else {
            let diagnostic = format!(
                "{}{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            let lower = diagnostic.to_lowercase();
            if lower.contains("could not find service") || lower.contains("service not found") {
                observed_missing = true;
            } else {
                bail!(
                    "could not establish activity for launchd service {target}: {}",
                    diagnostic.trim()
                );
            }
        }
    }
    if observed_missing {
        Ok(false)
    } else {
        bail!("launchctl did not provide a reliable activity result for {name}")
    }
}

fn resolve_package_receipts(
    receipts: &BTreeSet<String>,
) -> anyhow::Result<(BTreeSet<String>, BTreeSet<String>)> {
    resolve_package_receipts_with(receipts, Path::new("/usr/sbin/pkgutil"))
}

/// Resolves the installed files declared by one package receipt.
///
/// The bridge exposes this so a client can learn what a receipt actually
/// installed without reading raw configuration.
pub(crate) fn resolve_package_receipt_paths(receipt: &str) -> anyhow::Result<BTreeSet<String>> {
    let receipts = BTreeSet::from([receipt.to_string()]);
    let (paths, _) = resolve_package_receipts_with(&receipts, Path::new("/usr/sbin/pkgutil"))?;
    Ok(paths)
}

fn resolve_package_receipts_with(
    receipts: &BTreeSet<String>,
    pkgutil: &Path,
) -> anyhow::Result<(BTreeSet<String>, BTreeSet<String>)> {
    resolve_package_receipts_with_tools(receipts, pkgutil, Path::new("/usr/bin/plutil"))
}

fn resolve_package_receipts_with_tools(
    receipts: &BTreeSet<String>,
    pkgutil: &Path,
    plutil: &Path,
) -> anyhow::Result<(BTreeSet<String>, BTreeSet<String>)> {
    let mut paths = BTreeSet::new();
    let mut services = BTreeSet::new();
    let pkgutil = pkgutil
        .to_str()
        .context("pkgutil executable path is not valid UTF-8")?;
    let plutil = plutil
        .to_str()
        .context("plutil executable path is not valid UTF-8")?;

    for receipt in receipts {
        let (info_plist, info_stderr, info_status) =
            run_command(pkgutil, &["--pkg-info-plist", receipt], None, None)
                .with_context(|| format!("query package receipt location for {receipt}"))?;
        if info_status != 0 {
            bail!(
                "could not establish package receipt location for {receipt}: {}",
                info_stderr.trim()
            );
        }
        let (info_json, conversion_stderr, conversion_status) = run_command(
            plutil,
            &["-convert", "json", "-o", "-", "-"],
            Some(&info_plist),
            None,
        )
        .with_context(|| format!("decode package receipt location for {receipt}"))?;
        if conversion_status != 0 {
            bail!(
                "could not decode package receipt location for {receipt}: {}",
                conversion_stderr.trim()
            );
        }
        let info: serde_json::Value = serde_json::from_str(&info_json)
            .with_context(|| format!("parse package receipt location for {receipt}"))?;
        let install_root = package_receipt_install_root(&info, receipt)?;

        let (files, stderr, status) = run_command(pkgutil, &["--files", receipt], None, None)
            .with_context(|| format!("query package receipt files for {receipt}"))?;
        if status != 0 {
            bail!(
                "could not establish installed files for package receipt {receipt}: {}",
                stderr.trim()
            );
        }
        let mut observed_file = false;
        for file in files.lines().map(str::trim).filter(|file| !file.is_empty()) {
            observed_file = true;
            let relative = Path::new(file);
            if relative.is_absolute()
                || relative.components().any(|component| {
                    matches!(
                        component,
                        Component::ParentDir | Component::RootDir | Component::Prefix(_)
                    )
                })
            {
                bail!("package receipt {receipt} returned an unsafe relative path");
            }
            let absolute = install_root.join(relative);
            let Some(normalized) = normalize_runtime_path(&absolute.to_string_lossy()) else {
                bail!("package receipt {receipt} returned an invalid installed path");
            };
            paths.insert(normalized.clone());
            let path = Path::new(&normalized);
            if is_launchd_plist(path) {
                if !path.exists() {
                    bail!(
                        "package receipt {receipt} declares a missing launchd plist at {}",
                        path.display()
                    );
                }
                if let Some(service) = launchd_plist_label(path)? {
                    services.insert(service);
                }
            }
        }
        if !observed_file {
            bail!("package receipt {receipt} returned no installed files");
        }
    }
    Ok((paths, services))
}

fn package_receipt_install_root(
    info: &serde_json::Value,
    receipt: &str,
) -> anyhow::Result<PathBuf> {
    let volume = info
        .get("volume")
        .and_then(serde_json::Value::as_str)
        .context("package receipt has no volume location")?;
    let location = info
        .get("install-location")
        .and_then(serde_json::Value::as_str)
        .context("package receipt has no install location")?;
    let volume = validated_receipt_volume(volume)?;
    let location = validated_receipt_location(location, "install location")?;
    let volume = volume
        .canonicalize()
        .with_context(|| format!("resolve package receipt {receipt} volume"))?;
    if !volume.is_dir() {
        bail!("package receipt {receipt} volume is unavailable");
    }
    // A receipt's install location is relative to its volume. Real receipts
    // report it either with a leading slash ("/Applications") or as a bare
    // relative path ("Applications"), so both spellings resolve to the same
    // directory inside the volume.
    let install_root = volume
        .join(location.strip_prefix("/").unwrap_or(&location))
        .canonicalize()
        .with_context(|| format!("resolve package receipt {receipt} install location"))?;
    if !install_root.is_dir() || !install_root.starts_with(&volume) {
        bail!("package receipt {receipt} install location is unavailable or outside its volume");
    }
    Ok(install_root)
}

/// Validates a receipt's volume.
///
/// A volume is always an absolute path and may be the filesystem root. It
/// must not contain traversal or relative components, because it anchors
/// every path derived from the receipt.
fn validated_receipt_volume(raw: &str) -> anyhow::Result<PathBuf> {
    let path = Path::new(raw);
    if !path.is_absolute()
        || path.components().any(|component| {
            matches!(
                component,
                Component::ParentDir | Component::CurDir | Component::Prefix(_)
            )
        })
    {
        bail!("package receipt volume is not a safe absolute path");
    }
    Ok(path.to_path_buf())
}

fn validated_receipt_location(raw: &str, field: &str) -> anyhow::Result<PathBuf> {
    let path = Path::new(raw);
    if path.components().any(|component| {
        matches!(
            component,
            Component::ParentDir | Component::CurDir | Component::Prefix(_)
        )
    }) {
        bail!("package receipt {field} is not a safe path");
    }
    Ok(path.to_path_buf())
}

fn is_launchd_plist(path: &Path) -> bool {
    path.extension()
        .is_some_and(|extension| extension == "plist")
        && path.components().any(|component| {
            matches!(
                component,
                Component::Normal(name)
                    if name == "LaunchAgents" || name == "LaunchDaemons"
            )
        })
}

fn launchd_plist_label(path: &Path) -> anyhow::Result<Option<String>> {
    let contents = fs::read_to_string(path)
        .with_context(|| format!("read receipt-declared launchd plist {}", path.display()))?;
    let Some(key) = contents.find("<key>Label</key>") else {
        bail!(
            "receipt-declared launchd plist {} has no Label",
            path.display()
        );
    };
    let value = &contents[key + "<key>Label</key>".len()..];
    let Some(start) = value.find("<string>") else {
        bail!(
            "receipt-declared launchd plist {} has an invalid Label",
            path.display()
        );
    };
    let value = &value[start + "<string>".len()..];
    let Some(end) = value.find("</string>") else {
        bail!(
            "receipt-declared launchd plist {} has an invalid Label",
            path.display()
        );
    };
    let label = value[..end].trim();
    if label.is_empty()
        || !label
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
    {
        bail!(
            "receipt-declared launchd plist {} has an invalid Label",
            path.display()
        );
    }
    Ok(Some(label.to_string()))
}

fn gui_user_uid() -> anyhow::Result<u32> {
    let effective_uid = unsafe { libc::geteuid() };
    if effective_uid != 0 {
        return Ok(effective_uid);
    }
    let uid = credentials::console_uid()?;
    if uid == 0 {
        bail!("no logged-in user session is available for service activity checks");
    }
    Ok(uid)
}

fn cask_activity(identity: &CaskRuntimeIdentity) -> anyhow::Result<bool> {
    if identity.observation_incomplete {
        bail!("cask metadata contains an unresolved runtime or uninstall identity");
    }
    let applications = running_applications()?;
    if cask_is_running(identity, &applications) || executable_is_running(&identity.binary_paths) {
        return Ok(true);
    }
    let (receipt_paths, receipt_services) = resolve_package_receipts(&identity.package_receipts)?;
    if executable_is_running(&receipt_paths) {
        return Ok(true);
    }
    for service in identity.service_names.iter().chain(&receipt_services) {
        if service_is_running(service)? {
            return Ok(true);
        }
    }
    Ok(false)
}

fn selectable_cask_names(document: &serde_json::Value) -> Vec<String> {
    let Some(casks) = document.get("casks").and_then(serde_json::Value::as_array) else {
        return Vec::new();
    };
    casks
        .iter()
        .filter_map(|cask| {
            if cask.get("pinned").and_then(serde_json::Value::as_bool) == Some(true) {
                return None;
            }
            if cask
                .get("current_version")
                .and_then(serde_json::Value::as_str)
                == Some("latest")
            {
                return None;
            }
            cask.get("name")
                .or_else(|| cask.get("token"))
                .and_then(serde_json::Value::as_str)
                .map(ToString::to_string)
        })
        .collect()
}

fn listed_casks(output: &str) -> Vec<String> {
    if let Ok(document) = serde_json::from_str::<serde_json::Value>(output.trim()) {
        if document.get("casks").is_some() || document.get("formulae").is_some() {
            return selectable_cask_names(&document);
        }
    }
    output
        .lines()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
        .collect()
}

pub(crate) fn running_applications() -> anyhow::Result<Vec<RunningApplication>> {
    let (stdout, stderr, status) = run_command(
        "osascript",
        &["-l", "JavaScript", "-e", RUNNING_APPLICATIONS_SCRIPT],
        None,
        None,
    )
    .context("running-applications query failed to execute")?;
    if status != 0 {
        bail!(
            "running-applications query failed: {}",
            if stderr.trim().is_empty() {
                "osascript returned a nonzero status"
            } else {
                stderr.trim()
            }
        );
    }

    let applications: Vec<RunningApplication> = serde_json::from_str(stdout.trim())
        .context("running-applications query returned invalid JSON")?;
    Ok(applications
        .into_iter()
        .filter_map(|mut application| {
            application.bundle_id = application
                .bundle_id
                .take()
                .map(|value| value.trim().to_string())
                .filter(|value| !value.is_empty());
            application.path = application.path.as_deref().and_then(normalize_app_path);
            if application.bundle_id.is_none() && application.path.is_none() {
                None
            } else {
                Some(application)
            }
        })
        .collect())
}

fn cask_is_running(identity: &CaskRuntimeIdentity, applications: &[RunningApplication]) -> bool {
    applications.iter().any(|application| {
        application
            .bundle_id
            .as_ref()
            .is_some_and(|bundle_id| identity.bundle_ids.contains(bundle_id))
            || application.path.as_ref().is_some_and(|path| {
                let running_path = canonical_executable(Path::new(path));
                identity.app_paths.iter().any(|app_path| {
                    let target = canonical_executable(Path::new(app_path));
                    running_path == target || running_path.starts_with(target)
                })
            })
    })
}

fn cask_metadata(config: &MbrewConfig, cask: &str) -> anyhow::Result<Option<CaskMetadata>> {
    let (stdout, stderr, status) =
        command_for_brew(config, &["info", "--cask", "--json=v2", cask])?;
    if status != 0 {
        bail!(
            "brew info failed: {}",
            if stderr.trim().is_empty() {
                "brew info returned a nonzero status"
            } else {
                stderr.trim()
            }
        );
    }

    let document: serde_json::Value =
        serde_json::from_str(stdout.trim()).context("brew info returned invalid JSON")?;
    let casks = document
        .get("casks")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| anyhow::anyhow!("brew info metadata is missing casks"))?;
    let metadata = casks
        .iter()
        .find(|value| value.get("token").and_then(serde_json::Value::as_str) == Some(cask))
        .or_else(|| (casks.len() == 1).then(|| &casks[0]))
        .ok_or_else(|| anyhow::anyhow!("brew info metadata did not contain cask {cask}"))?;
    let bin_dir = homebrew_bin_dir(Path::new(&config.homebrew_bin))?;
    let identity = cask_runtime_identity_with_bin_dir(metadata, &bin_dir)?;
    Ok(identity_is_known(&identity).then_some(CaskMetadata { identity }))
}

fn broker_control_call(
    repo: &Path,
    op: &str,
    module: Option<&str>,
    document: Option<&str>,
    request_id: Option<&str>,
    client_handle: Option<&str>,
    action: Option<&str>,
) -> anyhow::Result<crate::control::Response> {
    use std::time::Duration;

    let uid = credentials::console_uid()?;
    let id = format!(
        "broker-{}-{}",
        std::process::id(),
        chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default()
    );
    let request = crate::control::Request {
        v: crate::control::PROTOCOL_VERSION,
        id,
        op: op.to_string(),
        repo: repo.to_string_lossy().into_owned(),
        document: document.map(str::to_string),
        module: module.map(str::to_string),
        yaml: None,
        base_digest: None,
        request_id: request_id.map(str::to_string),
        bypass: false,
        action: action.map(str::to_string),
        max_lines: None,
        severity: None,
        query: None,
        client_identity: None,
        client_handle: client_handle.map(str::to_string),
    };
    let response = crate::control::transact_with_timeout(
        &crate::control::broker_socket_path(repo, uid),
        &request,
        Duration::from_secs(15 * 60 + 10),
    )
    .context("broker control transport error")?;
    if !response.ok {
        bail!(
            "privilege broker rejected the request: {}",
            response.message.as_deref().unwrap_or("no reason provided")
        );
    }
    Ok(response)
}

#[derive(Clone, Copy, Default)]
struct ClientSubmission<'a> {
    run_handle: Option<&'a str>,
    job_id: Option<&'a str>,
    action: Option<&'a str>,
}

fn brokered_cask_upgrade(
    config: &MbrewConfig,
    cask: &str,
    identity: &CaskRuntimeIdentity,
    _broker: &crate::control::SharedBroker,
    submission: ClientSubmission<'_>,
) -> anyhow::Result<BrokerUpgradeResult> {
    let (Some(client_run_handle), Some(client_job_id)) =
        (submission.run_handle, submission.job_id)
    else {
        return Ok(BrokerUpgradeResult::Deferred(
            "an authenticated paired client is required for privileged maintenance".into(),
            CaskBlockerClass::PolicyDenied,
        ));
    };
    let bridge_path = PathBuf::from("/Library/Application Support/scriptd/privilege_bridge.rb");
    let bridge = match crate::broker::read_root_owned_file(&bridge_path, 0) {
        Ok(bridge) => bridge,
        Err(error) => {
            return Ok(BrokerUpgradeResult::Deferred(
                format!("privilege bridge setup is required: {error}"),
                CaskBlockerClass::BridgeAbsent,
            ));
        }
    };
    let repository = std::env::var_os("SCRIPTD_ROOT_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(crate::paths::resolve_repo_root);
    if let Err(error) = crate::control::broker_activation_status(&repository) {
        return Ok(BrokerUpgradeResult::Deferred(
            format!("privilege broker is inactive: {error}"),
            CaskBlockerClass::BridgeAbsent,
        ));
    }
    let command_runner = PathBuf::from(&config.homebrew_bin)
        .parent()
        .context("Homebrew executable has no parent directory")?
        .parent()
        .context("Homebrew prefix could not be resolved")?
        .join("Library/Homebrew/system_command.rb");
    let runner = fs::read_to_string(command_runner)
        .context("could not read Homebrew's SystemCommand runner")?;
    if !crate::broker::bridge_compatible(&runner) || !bridge.contains("def sudo_prefix") {
        return Ok(BrokerUpgradeResult::Deferred(
            "Homebrew privilege bridge compatibility is not verified; elevation is deferred".into(),
            CaskBlockerClass::BridgeAbsent,
        ));
    }

    let client = PathBuf::from("/usr/local/libexec/scriptd-broker");
    if let Err(error) = crate::broker::validate_root_owned_file(&client, 0) {
        return Ok(BrokerUpgradeResult::Deferred(
            format!("root-owned scriptd broker client setup is required: {error}"),
            CaskBlockerClass::SetupMissing,
        ));
    }
    let grant = match broker_control_call(
        &repository,
        "broker_open",
        Some(cask),
        Some(&config.homebrew_bin),
        Some(client_job_id),
        Some(client_run_handle),
        submission.action,
    ) {
        Ok(response) => response
            .snapshot
            .ok_or_else(|| anyhow::anyhow!("privilege broker returned no job grant"))?,
        Err(error) => {
            return Ok(BrokerUpgradeResult::Deferred(
                format!("authenticated privilege broker is unavailable: {error}"),
                CaskBlockerClass::PolicyDenied,
            ));
        }
    };
    let job_id = grant
        .get("job_id")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("privilege broker returned no job id"))?
        .to_string();
    let token = grant
        .get("token")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("privilege broker returned no job capability"))?
        .to_string();
    match cask_activity(identity) {
        Ok(true) => {
            let _ = broker_control_call(
                &repository,
                "broker_complete",
                Some(&job_id),
                None,
                Some(&token),
                None,
                None,
            );
            return Ok(BrokerUpgradeResult::Deferred(
                "an application or helper from this cask became active before the upgrade".into(),
                CaskBlockerClass::ApplicationRunning,
            ));
        }
        Err(error) => {
            let _ = broker_control_call(
                &repository,
                "broker_complete",
                Some(&job_id),
                None,
                Some(&token),
                None,
                None,
            );
            return Ok(BrokerUpgradeResult::Deferred(
                format!("could not reverify cask activity immediately before upgrade: {error}"),
                CaskBlockerClass::ActivityUnverifiable,
            ));
        }
        Ok(false) => {}
    }
    let repository = repository
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("scriptd repository path is not valid UTF-8"))?;
    let response = match broker_control_call(
        Path::new(repository),
        "broker_launch",
        Some(&job_id),
        None,
        Some(&token),
        None,
        None,
    ) {
        Ok(response) => response,
        Err(error) => {
            let failure = broker_launch_error_status(&error);
            if failure == BrokerLaunchFailure::NotStarted {
                let _ = broker_control_call(
                    Path::new(repository),
                    "broker_complete",
                    Some(&job_id),
                    None,
                    Some(&token),
                    None,
                    None,
                );
            }
            return Ok(broker_launch_failure_result(failure, &error));
        }
    };
    // The Homebrew worker was launched, so the upgrade was really attempted
    // even when its result cannot be read back.
    let Some(snapshot) = response.snapshot else {
        return Ok(BrokerUpgradeResult::Failed(
            "privilege broker returned no Homebrew worker result".into(),
        ));
    };
    let Some(status) = snapshot
        .get("status")
        .and_then(serde_json::Value::as_i64)
        .and_then(|status| i32::try_from(status).ok())
    else {
        return Ok(BrokerUpgradeResult::Failed(
            "privilege broker returned an invalid Homebrew worker status".into(),
        ));
    };
    let decode_output = |key: &str| -> anyhow::Result<Vec<u8>> {
        use base64::Engine;
        let Some(encoded) = snapshot.get(key).and_then(serde_json::Value::as_str) else {
            return Ok(Vec::new());
        };
        base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .with_context(|| format!("privilege broker returned invalid {key}"))
    };
    let stdout = String::from_utf8_lossy(&decode_output("stdout").unwrap_or_default()).into_owned();
    let stderr = String::from_utf8_lossy(&decode_output("stderr").unwrap_or_default()).into_owned();
    Ok(BrokerUpgradeResult::Completed((stdout, stderr, status)))
}

/// Preserves the launch boundary when the broker reports an error. Failures
/// before connecting are known not to have launched a worker; other transport
/// failures are ambiguous and need attention without counting an attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BrokerLaunchFailure {
    NotStarted,
    Started,
    Unknown,
}

fn broker_launch_error_status(error: &anyhow::Error) -> BrokerLaunchFailure {
    let text = format!("{error:#}");
    if text.contains("wait for helper-launched Homebrew worker")
        || (text.contains("persist broker job completion")
            && !text.contains("broker job completion also failed"))
    {
        BrokerLaunchFailure::Started
    } else if text.contains(": connect ") && error.chain().any(|cause| cause.is::<std::io::Error>())
    {
        BrokerLaunchFailure::NotStarted
    } else if error
        .chain()
        .any(|cause| cause.to_string().contains("broker control transport error"))
    {
        BrokerLaunchFailure::Unknown
    } else {
        BrokerLaunchFailure::NotStarted
    }
}

fn broker_launch_failure_result(
    failure: BrokerLaunchFailure,
    error: &anyhow::Error,
) -> BrokerUpgradeResult {
    match failure {
        BrokerLaunchFailure::Started => BrokerUpgradeResult::Failed(format!(
            "Homebrew worker launch result was unsuccessful: {error}"
        )),
        BrokerLaunchFailure::Unknown => BrokerUpgradeResult::Unconfirmed(format!(
            "Homebrew worker launch result is unknown: {error}"
        )),
        BrokerLaunchFailure::NotStarted => BrokerUpgradeResult::Deferred(
            format!("helper-launched Homebrew worker was unavailable: {error}"),
            CaskBlockerClass::BridgeAbsent,
        ),
    }
}

enum BrokerUpgradeResult {
    /// The privileged worker ran the upgrade and reported its result. The
    /// upgrade was really attempted, whatever the exit status was.
    Completed((String, String, i32)),
    /// The worker launch is confirmed, but the final result is unavailable.
    Failed(String),
    /// The launch outcome cannot be confirmed. Require an explicit decision
    /// before retrying, but do not count an unconfirmed launch as an attempt.
    Unconfirmed(String),
    /// The upgrade was never launched (bridge missing, broker inactive,
    /// privilege not granted). No upgrade was attempted.
    Deferred(String, CaskBlockerClass),
}

fn push_unique(values: &mut Vec<String>, value: &str) {
    if !values.iter().any(|existing| existing == value) {
        values.push(value.to_string());
    }
}

fn defer_cask(
    outcome: &mut BrewMaintenanceOutcome,
    logger: &ModuleLogger,
    cask: &str,
    reason: &str,
) {
    defer_cask_with_class(
        outcome,
        logger,
        cask,
        reason,
        CaskBlockerClass::ApplicationRunning,
    );
}

/// Defers a cask and records why it was stopped.
///
/// The blocker class decides whether the cask is eligible for an automatic
/// retry, so a cask that needs a human action never claims it is retryable.
fn defer_cask_with_class(
    outcome: &mut BrewMaintenanceOutcome,
    logger: &ModuleLogger,
    cask: &str,
    reason: &str,
    class: CaskBlockerClass,
) {
    push_unique(&mut outcome.deferred_casks, cask);
    if class.is_retryable() {
        outcome.retryable_casks.insert(cask.to_string());
    } else {
        outcome.retryable_casks.remove(cask);
    }
    outcome.reasons.insert(cask.to_string(), reason.to_string());
    outcome.blockers.insert(cask.to_string(), class);
    logger.warn(&format!("Deferring cask {cask}: {reason}"));
}

fn defer_cask_for_attention(
    outcome: &mut BrewMaintenanceOutcome,
    logger: &ModuleLogger,
    cask: &str,
    reason: &str,
) {
    defer_cask_for_attention_with_class(
        outcome,
        logger,
        cask,
        reason,
        CaskBlockerClass::ActivityUnverifiable,
    );
}

/// Defers a cask that needs a human decision before it can proceed.
///
/// The cask stays visible in the ledger, is never retried automatically, and
/// is surfaced as an attention item so the interface can offer the recovery
/// action its blocker class names.
fn defer_cask_for_attention_with_class(
    outcome: &mut BrewMaintenanceOutcome,
    logger: &ModuleLogger,
    cask: &str,
    reason: &str,
    class: CaskBlockerClass,
) {
    defer_cask_with_class(outcome, logger, cask, reason, class);
    outcome.retryable_casks.remove(cask);
    outcome.attention_casks.insert(cask.to_string());
}

fn fail_cask(
    outcome: &mut BrewMaintenanceOutcome,
    logger: &ModuleLogger,
    cask: &str,
    reason: &str,
) {
    push_unique(&mut outcome.failed_casks, cask);
    outcome.reasons.insert(cask.to_string(), reason.to_string());
    outcome
        .blockers
        .insert(cask.to_string(), CaskBlockerClass::UpgradeFailed);
    outcome.attention_casks.insert(cask.to_string());
    logger.error(&format!("Cask {cask} upgrade failed: {reason}"));
}

fn brew_cask_maintenance(
    config: &MbrewConfig,
    logger: &ModuleLogger,
    only: Option<&std::collections::BTreeSet<String>>,
    skip: &std::collections::BTreeSet<String>,
) -> anyhow::Result<BrewMaintenanceOutcome> {
    brew_cask_maintenance_with_broker(config, logger, only, None, skip)
}

fn brew_cask_maintenance_with_broker(
    config: &MbrewConfig,
    logger: &ModuleLogger,
    only: Option<&std::collections::BTreeSet<String>>,
    broker: Option<&crate::control::SharedBroker>,
    skip: &std::collections::BTreeSet<String>,
) -> anyhow::Result<BrewMaintenanceOutcome> {
    brew_cask_maintenance_with_client(
        config,
        logger,
        only,
        broker,
        skip,
        ClientSubmission::default(),
    )
}

fn brew_cask_maintenance_with_client(
    config: &MbrewConfig,
    logger: &ModuleLogger,
    only: Option<&std::collections::BTreeSet<String>>,
    broker: Option<&crate::control::SharedBroker>,
    skip: &std::collections::BTreeSet<String>,
    submission: ClientSubmission<'_>,
) -> anyhow::Result<BrewMaintenanceOutcome> {
    let (outdated_out, outdated_err, outdated_status) = command_for_brew(
        config,
        &["outdated", "--cask", "--greedy-auto-updates", "--json=v2"],
    )?;
    if outdated_status != 0 {
        bail!(
            "brew outdated cask listing failed: {}",
            if outdated_err.trim().is_empty() {
                "brew outdated returned a nonzero status"
            } else {
                outdated_err.trim()
            }
        );
    }

    let mut casks = listed_casks(&outdated_out);
    if let Some(only) = only {
        casks.retain(|cask| only.contains(cask));
    }
    casks.retain(|cask| !skip.contains(cask));
    let mut outcome = BrewMaintenanceOutcome::default();

    for cask in casks {
        let metadata = match cask_metadata(config, &cask) {
            Ok(Some(metadata)) => metadata,
            Ok(None) => {
                defer_cask_for_attention(
                    &mut outcome,
                    logger,
                    &cask,
                    "no trustworthy application identity is present in cask metadata",
                );
                continue;
            }
            Err(error) => {
                defer_cask_for_attention(&mut outcome, logger, &cask, &error.to_string());
                continue;
            }
        };

        if defer_for_activity(&mut outcome, logger, &cask, &metadata.identity) {
            continue;
        }
        let Some(broker) = broker else {
            defer_cask_for_attention_with_class(
                &mut outcome,
                logger,
                &cask,
                "the authenticated scriptd privilege broker is unavailable; cask elevation is not permitted from a direct CLI run",
                CaskBlockerClass::BridgeAbsent,
            );
            continue;
        };
        let upgrade =
            match brokered_cask_upgrade(config, &cask, &metadata.identity, broker, submission) {
                Ok(BrokerUpgradeResult::Completed(output)) => {
                    outcome.attempted_casks.insert(cask.clone());
                    Ok(output)
                }
                Ok(BrokerUpgradeResult::Failed(reason)) => {
                    outcome.attempted_casks.insert(cask.clone());
                    Err(anyhow::anyhow!(reason))
                }
                Ok(BrokerUpgradeResult::Deferred(reason, class)) => {
                    defer_cask_with_class(&mut outcome, logger, &cask, &reason, class);
                    continue;
                }
                Ok(BrokerUpgradeResult::Unconfirmed(reason)) => {
                    defer_cask_for_attention(&mut outcome, logger, &cask, &reason);
                    continue;
                }
                Err(error) => Err(error),
            };
        match upgrade {
            Ok((stdout, stderr, 0)) => {
                push_unique(&mut outcome.repaired_casks, &cask);
                if stdout.trim().is_empty() {
                    logger.info(&format!("Upgraded cask {cask}"));
                } else {
                    logger.info(stdout.trim());
                }
                if !stderr.trim().is_empty() {
                    logger.warn(stderr.trim());
                }
            }
            Ok((_stdout, stderr, status)) => {
                let reason = if stderr.trim().is_empty() {
                    format!("brew upgrade returned status {status}")
                } else {
                    stderr.trim().to_string()
                };
                fail_cask(&mut outcome, logger, &cask, &reason);
            }
            Err(error) => fail_cask(&mut outcome, logger, &cask, &error.to_string()),
        }
    }

    Ok(outcome)
}

fn defer_for_activity(
    outcome: &mut BrewMaintenanceOutcome,
    logger: &ModuleLogger,
    cask: &str,
    identity: &CaskRuntimeIdentity,
) -> bool {
    match cask_activity(identity) {
        Ok(false) => false,
        Ok(true) => {
            defer_cask_with_class(
                outcome,
                logger,
                cask,
                "an application or helper from this cask is running",
                CaskBlockerClass::ApplicationRunning,
            );
            true
        }
        Err(error) => {
            defer_cask_with_class(
                outcome,
                logger,
                cask,
                &format!("could not verify cask activity: {error}"),
                CaskBlockerClass::ActivityUnverifiable,
            );
            true
        }
    }
}

fn run_cleanup(config: &MbrewConfig, logger: &ModuleLogger) -> anyhow::Result<()> {
    let (cleanup_out, cleanup_err, cleanup_status) = command_for_brew(config, &["cleanup"])?;
    if cleanup_status != 0 {
        anyhow::bail!(
            "{}",
            if cleanup_err.trim().is_empty() {
                "brew cleanup returned a nonzero status".to_string()
            } else {
                cleanup_err.trim().to_string()
            }
        );
    }
    if !cleanup_out.trim().is_empty() {
        logger.info(cleanup_out.trim());
    }
    Ok(())
}

fn brew_maintenance(
    config: &MbrewConfig,
    logger: &ModuleLogger,
    action: Option<&str>,
    state_dir: &Path,
) -> anyhow::Result<BrewMaintenanceOutcome> {
    brew_maintenance_with_broker(config, logger, action, None, state_dir)
}

fn brew_maintenance_with_broker(
    config: &MbrewConfig,
    logger: &ModuleLogger,
    action: Option<&str>,
    broker: Option<&crate::control::SharedBroker>,
    state_dir: &Path,
) -> anyhow::Result<BrewMaintenanceOutcome> {
    brew_maintenance_with_client(config, logger, action, broker, state_dir, None, None)
}

fn brew_maintenance_with_client(
    config: &MbrewConfig,
    logger: &ModuleLogger,
    action: Option<&str>,
    broker: Option<&crate::control::SharedBroker>,
    state_dir: &Path,
    client_handle: Option<&str>,
    client_job_id: Option<&str>,
) -> anyhow::Result<BrewMaintenanceOutcome> {
    let submission = ClientSubmission {
        run_handle: client_handle,
        job_id: client_job_id,
        action,
    };
    let (Some(client_handle), Some(client_job_id), Some(_)) =
        (client_handle, client_job_id, broker)
    else {
        return brew_maintenance_with_submission(
            config,
            logger,
            action,
            broker,
            state_dir,
            submission,
        );
    };

    let repository = std::env::var_os("SCRIPTD_ROOT_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(crate::paths::resolve_repo_root);
    let response = broker_control_call(
        &repository,
        "broker_begin_submission",
        Some("mbrew"),
        None,
        Some(client_job_id),
        Some(client_handle),
        action,
    )?;
    let snapshot = response
        .snapshot
        .ok_or_else(|| anyhow::anyhow!("privilege broker returned no submission run"))?;
    let run_handle = snapshot
        .get("run_handle")
        .and_then(serde_json::Value::as_str)
        .context("privilege broker returned no submission run capability")?
        .to_string();
    let submission = ClientSubmission {
        run_handle: Some(&run_handle),
        job_id: Some(client_job_id),
        action,
    };
    let result = brew_maintenance_with_submission(
        config,
        logger,
        action,
        broker,
        state_dir,
        submission,
    );
    let finish_op = if result.is_ok() {
        "broker_finish_submission"
    } else {
        "broker_interrupt_submission"
    };
    let finish_result = broker_control_call(
        &repository,
        finish_op,
        Some("mbrew"),
        None,
        Some(client_job_id),
        Some(&run_handle),
        action,
    );
    match (result, finish_result) {
        (Ok(outcome), Ok(_)) => Ok(outcome),
        (Err(error), Ok(_)) => Err(error),
        (Ok(_), Err(error)) => Err(error).context("persist Homebrew submission completion"),
        (Err(run_error), Err(finish_error)) => Err(anyhow::anyhow!(
            "{run_error}; Homebrew submission interruption could not be recorded: {finish_error}"
        )),
    }
}

fn brew_maintenance_with_submission(
    config: &MbrewConfig,
    logger: &ModuleLogger,
    action: Option<&str>,
    broker: Option<&crate::control::SharedBroker>,
    state_dir: &Path,
    submission: ClientSubmission<'_>,
) -> anyhow::Result<BrewMaintenanceOutcome> {
    if action == Some("retry_pending") {
        let only = retry_candidates(state_dir)?;
        let dismissed = dismissed_casks(state_dir)?;
        let outcome = brew_cask_maintenance_with_client(
            config,
            logger,
            Some(&only),
            broker,
            &dismissed,
            submission,
        )
        .unwrap_or_else(|error| BrewMaintenanceOutcome {
            cask_error: Some(error.to_string()),
            ..BrewMaintenanceOutcome::default()
        });
        record_cask_ledger(state_dir, &outcome, true)?;
        if outcome.cask_error.is_none() {
            clear_resolved_retries(state_dir, &only, &outcome)?;
        }
        if let Some(error) = outcome.cask_error.as_deref() {
            bail!("{error}");
        }
        return Ok(outcome);
    }
    ensure_askpass(config, logger)?;
    trust_configured_taps(config, logger)?;
    let (update_out, update_err, status) = command_for_brew(config, &["update"])?;
    if status != 0 {
        bail!(
            "{}",
            if update_err.trim().is_empty() {
                "brew update failed".to_string()
            } else {
                update_err.trim().to_string()
            }
        );
    }
    if !update_err.trim().is_empty() {
        logger.warn(update_err.trim());
    }
    reject_untrusted_homebrew_entries(&update_out, &update_err)?;
    logger.info(if update_out.trim().is_empty() {
        "brew update completed"
    } else {
        update_out.trim()
    });

    let (formula_out, formula_err, formula_status) =
        command_for_brew(config, &["upgrade", "--formula"])?;
    if !formula_out.trim().is_empty() {
        logger.info(formula_out.trim());
    }
    let mut excluded = dismissed_casks(state_dir)?;
    excluded.extend(attention_casks(state_dir)?);
    let mut outcome =
        brew_cask_maintenance_with_client(config, logger, None, broker, &excluded, submission)
            .unwrap_or_else(|error| BrewMaintenanceOutcome {
                cask_error: Some(error.to_string()),
                ..BrewMaintenanceOutcome::default()
            });
    if formula_status != 0 {
        outcome.formula_error = Some(if formula_err.trim().is_empty() {
            "brew upgrade --formula returned a nonzero status".to_string()
        } else {
            formula_err.trim().to_string()
        });
    }
    if let Err(error) = run_cleanup(config, logger) {
        outcome.cleanup_error = Some(error.to_string());
    }
    record_cask_ledger(state_dir, &outcome, false)?;
    Ok(outcome)
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, Default)]
struct PackageLedger {
    #[serde(default)]
    packages: Vec<PackageRecord>,
    #[serde(default)]
    formula_error: Option<String>,
    #[serde(default)]
    cleanup_error: Option<String>,
    #[serde(default)]
    cask_error: Option<String>,
}
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct PackageRecord {
    name: String,
    state: String,
    reason: Option<String>,
    /// The class of blocker that stopped this cask, when one applies. The
    /// interface uses it to show an accurate state and a recovery action
    /// instead of a misleading generic retry label.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    blocker: Option<String>,
    /// The recovery action that can resolve this cask's blocker.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    recovery: Option<String>,
    /// Number of REAL upgrade attempts (a launched `brew upgrade`) for this
    /// cask. Pure deferrals never increase it.
    attempts: u32,
    retry: bool,
    /// Set when the user dismissed this cask: it stays visible in the ledger
    /// but is never re-prompted and never retried automatically.
    #[serde(default)]
    dismissed: bool,
}
fn ledger_path(state_dir: &Path) -> PathBuf {
    state_dir.join("mbrew-outcomes.json")
}
fn read_ledger(path: &Path) -> anyhow::Result<PackageLedger> {
    match std::fs::read_to_string(path) {
        Ok(raw) => serde_json::from_str(&raw)
            .with_context(|| format!("parse Homebrew outcome ledger at {}", path.display())),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(PackageLedger::default()),
        Err(error) => Err(error)
            .with_context(|| format!("read Homebrew outcome ledger at {}", path.display())),
    }
}
fn load_ledger(state_dir: &Path) -> anyhow::Result<PackageLedger> {
    read_ledger(&ledger_path(state_dir))
}
fn retry_candidates(state_dir: &Path) -> anyhow::Result<std::collections::BTreeSet<String>> {
    Ok(load_ledger(state_dir)?
        .packages
        .into_iter()
        .filter(|record| record.retry && !record.dismissed)
        .map(|record| record.name)
        .collect())
}
fn dismissed_casks(state_dir: &Path) -> anyhow::Result<std::collections::BTreeSet<String>> {
    Ok(load_ledger(state_dir)?
        .packages
        .into_iter()
        .filter(|record| record.dismissed)
        .map(|record| record.name)
        .collect())
}
fn attention_casks(state_dir: &Path) -> anyhow::Result<std::collections::BTreeSet<String>> {
    Ok(load_ledger(state_dir)?
        .packages
        .into_iter()
        .filter(|record| record.state == "attention")
        .map(|record| record.name)
        .collect())
}
fn persist_ledger(path: &Path, ledger: &PackageLedger) -> anyhow::Result<()> {
    let body = serde_json::to_vec_pretty(ledger)?;
    crate::paths::write_private_atomic(path, &body)
        .with_context(|| format!("persist Homebrew outcome ledger at {}", path.display()))
}

fn record_cask_ledger(
    state_dir: &Path,
    outcome: &BrewMaintenanceOutcome,
    pending_retry: bool,
) -> anyhow::Result<()> {
    let _guard = lock_ledger(state_dir)?;
    let mut ledger = load_ledger(state_dir)?;
    if !pending_retry {
        ledger.formula_error = outcome.formula_error.clone();
        ledger.cleanup_error = outcome.cleanup_error.clone();
    }
    ledger.cask_error = outcome.cask_error.clone();
    let updates = outcome
        .repaired_casks
        .iter()
        .map(|name| (name.clone(), "updated".to_string(), false))
        .chain(outcome.deferred_casks.iter().map(|name| {
            let state = if outcome.attention_casks.contains(name) {
                "attention"
            } else {
                "deferred"
            };
            (
                name.clone(),
                state.to_string(),
                outcome.retryable_casks.contains(name),
            )
        }))
        .chain(
            outcome
                .failed_casks
                .iter()
                .map(|name| (name.clone(), "attention".to_string(), false)),
        );
    for (name, state, retry) in updates {
        let previous = ledger
            .packages
            .iter()
            .find(|record| record.name == name)
            .cloned();
        // `attempts` counts REAL upgrade attempts only. A cask that is merely
        // deferred (an app is running, the broker is unavailable, metadata is
        // unusable) never had an upgrade launched for it, so it must not
        // accumulate attempts. A repaired or failed cask did have a real
        // upgrade attempt and therefore counts as one.
        let attempts = if outcome.attempted_casks.contains(&name) {
            previous
                .as_ref()
                .map(|record| record.attempts.saturating_add(1))
                .unwrap_or(1)
        } else {
            previous.as_ref().map(|record| record.attempts).unwrap_or(0)
        };
        let dismissed = previous
            .as_ref()
            .map(|record| record.dismissed)
            .unwrap_or(false)
            || outcome.dismissed_casks.contains(&name);
        ledger.packages.retain(|record| record.name != name);
        ledger.packages.push(PackageRecord {
            reason: outcome.reasons.get(&name).cloned(),
            blocker: outcome
                .blockers
                .get(&name)
                .map(|class| class.as_str().to_string()),
            recovery: outcome
                .blockers
                .get(&name)
                .map(|class| class.recovery_action().to_string()),
            name,
            state,
            attempts,
            retry: retry && !dismissed,
            dismissed,
        });
    }
    persist_ledger(&ledger_path(state_dir), &ledger)
}

fn clear_resolved_retries(
    state_dir: &Path,
    candidates: &std::collections::BTreeSet<String>,
    outcome: &BrewMaintenanceOutcome,
) -> anyhow::Result<()> {
    let _guard = lock_ledger(state_dir)?;
    let observed = outcome
        .repaired_casks
        .iter()
        .chain(&outcome.deferred_casks)
        .chain(&outcome.failed_casks)
        .collect::<BTreeSet<_>>();
    let mut ledger = load_ledger(state_dir)?;
    for record in &mut ledger.packages {
        if candidates.contains(&record.name) && !observed.contains(&record.name) {
            record.state = "current".to_string();
            record.reason = None;
            record.retry = false;
        }
    }
    persist_ledger(&ledger_path(state_dir), &ledger)
}

/// A user decision about a single cask that is waiting for attention.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CaskDecision {
    /// The user approves the work: clear the attention state so the next
    /// maintenance or retry run attempts the cask again.
    Approve,
    /// The user dismisses the cask: keep it visible in the ledger, but never
    /// re-prompt for it and never retry it automatically.
    Dismiss,
    /// The user asks for another attempt: make the cask eligible again.
    Retry,
}

impl CaskDecision {
    /// Parses the decision names accepted by the control center.
    pub fn parse(raw: &str) -> anyhow::Result<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "approve" | "approved" | "allow" => Ok(Self::Approve),
            "dismiss" | "dismissed" | "deny" | "denied" => Ok(Self::Dismiss),
            "retry" | "retry_pending" => Ok(Self::Retry),
            other => anyhow::bail!("unsupported cask decision \"{other}\""),
        }
    }
}

/// Applies a user decision about one cask to the Homebrew outcome ledger.
///
/// The decision is persisted in the ledger file, so it survives a restart of
/// the service. The call is safe to make while a maintenance run is in
/// progress: the ledger read-modify-write cycle is serialized.
pub fn apply_cask_decision(
    state_dir: &Path,
    cask: &str,
    decision: CaskDecision,
) -> anyhow::Result<()> {
    let cask = cask.trim();
    if cask.is_empty() {
        anyhow::bail!("a cask name is required");
    }
    let _guard = lock_ledger(state_dir)?;
    let mut ledger = load_ledger(state_dir)?;
    let Some(record) = ledger
        .packages
        .iter_mut()
        .find(|record| record.name == cask)
    else {
        anyhow::bail!("cask \"{cask}\" is not present in the Homebrew outcome ledger");
    };
    match decision {
        CaskDecision::Approve => {
            // The cask no longer needs a decision: clear the attention state so
            // the next run attempts it again, and let it be retried.
            record.dismissed = false;
            if record.state == "attention" {
                record.state = "deferred".to_string();
            }
            record.retry = true;
        }
        CaskDecision::Dismiss => {
            // The cask stays visible in the ledger, but it is never re-prompted
            // and never retried automatically.
            record.dismissed = true;
            record.retry = false;
            if record.state == "attention" {
                record.state = "dismissed".to_string();
            }
        }
        CaskDecision::Retry => {
            // Re-running is driven by the `retry_pending` action; the hook only
            // has to make the cask eligible again.
            record.dismissed = false;
            record.retry = true;
            if record.state == "attention" {
                record.state = "deferred".to_string();
            }
        }
    }
    persist_ledger(&ledger_path(state_dir), &ledger)
}

pub fn setup(context: &mut ModuleContext) -> anyhow::Result<()> {
    let config = update_from_config(context)?;
    let password = credentials::admin_password_or_prompt()?;
    write_askpass(&config, &context.logger)?;
    install_privilege_broker(&config, context, &password)?;
    context.logger.info("mbrew setup complete");
    println!("mbrew setup complete.");
    Ok(())
}

pub fn run_once(context: &mut ModuleContext) -> anyhow::Result<Option<ModuleStatus>> {
    let config = update_from_config(context)?;
    // Resolve the production state directory once, at the entry point, and
    // thread it down. Tests call the lower level helpers with a temp dir so
    // they never touch the real ledger.
    let state_dir = crate::paths::resolve_state_dir();
    let result = brew_maintenance_with_client(
        &config,
        &context.logger,
        context.action.as_deref(),
        context.broker.as_ref(),
        &state_dir,
        context.client_handle.as_deref(),
        context.client_job_id.as_deref(),
    );
    let mut state = STATE.lock().unwrap_or_else(|error| error.into_inner());

    match result {
        Ok(outcome) => {
            state.last_error = None;
            state.last_run_at = Some(chrono::Utc::now().to_rfc3339());
            let stage_error = outcome
                .formula_error
                .clone()
                .or(outcome.cleanup_error.clone())
                .or(outcome.cask_error.clone());
            state.repaired_casks = outcome.repaired_casks;
            state.deferred_casks = outcome.deferred_casks;
            state.failed_casks = outcome.failed_casks;
            state.last_message = Some(maintenance_message(&state));
            if let Some(error) = stage_error.as_deref() {
                state.last_message = Some(format!(
                    "{}; stage error: {error}",
                    state
                        .last_message
                        .as_deref()
                        .unwrap_or("Homebrew maintenance failed")
                ));
            }
            if !state.failed_casks.is_empty() || stage_error.is_some() {
                let error = state.last_message.clone().unwrap_or_else(|| {
                    "Homebrew maintenance failed for one or more casks".to_string()
                });
                state.last_error = Some(error.clone());
                context.logger.error(&error);
                return Err(anyhow::anyhow!(error));
            }
            Ok(Some(module_status_from_state(&state, "running")))
        }
        Err(error) => {
            state.repaired_casks.clear();
            state.deferred_casks.clear();
            state.failed_casks.clear();
            state.last_error = Some(error.to_string());
            state.last_message = Some(
                state
                    .last_error
                    .clone()
                    .unwrap_or_else(|| "error".to_string()),
            );
            state.last_run_at = Some(chrono::Utc::now().to_rfc3339());
            context.logger.error(error.to_string().as_str());
            Err(error)
        }
    }
}

fn cask_metric(values: &[String]) -> serde_json::Value {
    serde_json::Value::String(if values.is_empty() {
        "none".to_string()
    } else {
        values.join(",")
    })
}

fn module_metrics(state: &MbrewState) -> HashMap<String, serde_json::Value> {
    HashMap::from([
        (
            "repairedCasks".to_string(),
            cask_metric(&state.repaired_casks),
        ),
        (
            "deferredCasks".to_string(),
            cask_metric(&state.deferred_casks),
        ),
        ("failedCasks".to_string(), cask_metric(&state.failed_casks)),
    ])
}

fn maintenance_message(state: &MbrewState) -> String {
    let deferred = if state.deferred_casks.is_empty() {
        "none".to_string()
    } else {
        state.deferred_casks.join(",")
    };
    let failed = if state.failed_casks.is_empty() {
        "none".to_string()
    } else {
        state.failed_casks.join(",")
    };
    let prefix = if state.failed_casks.is_empty() {
        "Homebrew maintenance completed"
    } else {
        "Homebrew maintenance completed with failed casks"
    };
    format!("{prefix} (deferred casks: {deferred}; failed casks: {failed})",)
}

fn module_status_from_state(state: &MbrewState, status: &str) -> ModuleStatus {
    ModuleStatus {
        state: status.to_string(),
        message: state.last_message.clone(),
        started_at: None,
        last_run_at: state.last_run_at.clone(),
        next_run_at: None,
        metrics: Some(module_metrics(state)),
    }
}

pub fn status() -> Option<(ModuleStatus, ModuleHealth)> {
    let state = STATE.lock().unwrap_or_else(|error| error.into_inner());
    if state.last_run_at.is_none() {
        return Some((
            ModuleStatus {
                state: "stopped".to_string(),
                message: Some("not run yet".to_string()),
                started_at: None,
                last_run_at: None,
                next_run_at: None,
                metrics: Some(module_metrics(&state)),
            },
            ModuleHealth {
                ok: true,
                message: Some("brew manager ready".to_string()),
            },
        ));
    }

    let status = if state.last_error.is_none() {
        "running"
    } else {
        "error"
    };
    Some((
        module_status_from_state(&state, status),
        ModuleHealth {
            ok: state.last_error.is_none(),
            message: state
                .last_error
                .clone()
                .or_else(|| Some("brew manager healthy".to_string())),
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::{self, File};
    use std::io::Write;
    use std::path::Path;
    use tempfile::tempdir;

    #[cfg(target_os = "macos")]
    #[test]
    fn broker_open_carries_only_the_queued_client_handle() -> anyhow::Result<()> {
        use std::io::{BufRead, BufReader};
        use std::os::unix::net::UnixListener;

        let repo = tempdir()?;
        let uid = credentials::console_uid()?;
        let listener = UnixListener::bind(crate::control::broker_socket_path(repo.path(), uid))?;
        let broker_thread =
            std::thread::spawn(move || -> anyhow::Result<crate::control::Request> {
                let (mut stream, _) = listener.accept()?;
                let request = {
                    let mut reader = BufReader::new(&mut stream);
                    let mut line = String::new();
                    reader.read_line(&mut line)?;
                    serde_json::from_str::<crate::control::Request>(&line)?
                };
                let response = crate::control::Response {
                    v: crate::control::PROTOCOL_VERSION,
                    id: request.id.clone(),
                    ok: true,
                    state: "accepted".to_string(),
                    apply: None,
                    config_digest: None,
                    reload_error: None,
                    message: None,
                    snapshot: None,
                    logs: None,
                    draft_yaml: None,
                };
                stream.write_all(serde_json::to_string(&response)?.as_bytes())?;
                stream.write_all(b"\n")?;
                Ok(request)
            });
        let response = broker_control_call(
            repo.path(),
            "broker_open",
            Some("anydesk"),
            Some("/opt/homebrew/bin/brew"),
            Some("queue-job-1"),
            Some("opaque-broker-handle"),
            Some("retry_pending"),
        )?;
        assert!(response.ok);
        let forwarded = broker_thread.join().expect("mock broker thread")?;
        assert_eq!(forwarded.op, "broker_open");
        assert_eq!(forwarded.request_id.as_deref(), Some("queue-job-1"));
        assert_eq!(forwarded.client_identity, None);
        assert_eq!(
            forwarded.client_handle.as_deref(),
            Some("opaque-broker-handle")
        );
        assert_eq!(forwarded.action.as_deref(), Some("retry_pending"));
        Ok(())
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn broker_binary_signing_enforces_broker_code_identity() -> anyhow::Result<()> {
        const VERIFY_RUNNING_SIGNATURE: &str = "SCRIPTD_VERIFY_BROKER_CODE_IDENTITY";
        const REQUIRED: u32 = 0x00000001 | 0x00000200 | 0x00002000 | 0x00010000;
        const FORBIDDEN: u32 = 0x00000004 | 0x00000020 | 0x10000000;

        if std::env::var_os(VERIFY_RUNNING_SIGNATURE).is_some() {
            extern "C" {
                fn csops(
                    pid: libc::pid_t,
                    ops: libc::c_uint,
                    data: *mut libc::c_void,
                    size: usize,
                ) -> libc::c_int;
            }
            let mut flags = 0u32;
            // SAFETY: `flags` is a writable u32 buffer of the size passed to csops.
            let result = unsafe {
                csops(
                    0,
                    0,
                    (&mut flags as *mut u32).cast(),
                    std::mem::size_of_val(&flags),
                )
            };
            anyhow::ensure!(result == 0, "could not read running process code flags");
            anyhow::ensure!(
                flags & REQUIRED == REQUIRED && flags & FORBIDDEN == 0,
                "running broker binary does not satisfy the broker code identity predicate: {flags:#010x}"
            );
            return Ok(());
        }

        let root = tempdir()?;
        let binary = root.path().join("scriptd-broker");
        fs::copy(std::env::current_exe()?, &binary)?;

        sign_broker_binary(&binary)?;

        let output = Command::new(&binary)
            .args([
                "--exact",
                "modules::mbrew::tests::broker_binary_signing_enforces_broker_code_identity",
                "--nocapture",
            ])
            .env(VERIFY_RUNNING_SIGNATURE, "1")
            .output()?;
        anyhow::ensure!(
            output.status.success(),
            "signed broker binary failed its running-process identity check: {}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        Ok(())
    }

    fn write_script(path: &Path, body: &str) -> anyhow::Result<()> {
        let mut file = File::create(path)?;
        file.write_all(body.as_bytes())?;
        let _ = std::process::Command::new("chmod")
            .args(["+x", path.to_string_lossy().as_ref()])
            .status();
        Ok(())
    }

    fn with_path_scope<F, R>(scope: &std::path::Path, f: F) -> R
    where
        F: FnOnce() -> R,
    {
        let original = std::env::var("PATH").unwrap_or_default();
        let mut paths = vec![scope.to_path_buf()];
        for entry in std::env::split_paths(&original) {
            paths.push(entry);
        }
        let updated = std::env::join_paths(paths)
            .expect("build PATH")
            .to_string_lossy()
            .to_string();
        std::env::set_var("PATH", &updated);
        let result = f();
        std::env::set_var("PATH", original);
        result
    }

    fn default_config(_home: &Path, homebrew_bin: &Path, askpass: &Path) -> MbrewConfig {
        MbrewConfig {
            homebrew_bin: homebrew_bin.to_string_lossy().to_string(),
            askpass_path: askpass.to_string_lossy().to_string(),
            ..MbrewConfig::default()
        }
    }

    #[test]
    fn broker_daemon_pins_the_installed_service_identity() {
        let plist = broker_daemon_plist(Path::new("/tmp/scriptd"), "com.example.scriptd");
        assert!(
            plist.contains("<key>SCRIPTD_SERVICE_LABEL</key><string>com.example.scriptd</string>")
        );
        let escaped = broker_daemon_plist(Path::new("/tmp/a&b"), "com.example.scriptd");
        assert!(escaped.contains("<string>/tmp/a&amp;b</string>"));
    }

    #[test]
    fn outcome_ledger_persistence_failures_are_reported() -> anyhow::Result<()> {
        let root = tempdir()?;
        let blocked_parent = root.path().join("not-a-directory");
        fs::write(&blocked_parent, "file blocks ledger directory")?;

        let error = persist_ledger(
            &blocked_parent.join("ledger.json"),
            &PackageLedger::default(),
        )
        .expect_err("ledger persistence must fail when its parent is not a directory");
        assert!(error
            .to_string()
            .contains("persist Homebrew outcome ledger"));
        Ok(())
    }

    #[test]
    fn corrupt_outcome_ledger_blocks_retry_without_discarding_state() -> anyhow::Result<()> {
        let root = tempdir()?;
        let path = root.path().join("ledger.json");
        fs::write(&path, "{not valid json")?;

        let error = read_ledger(&path).expect_err("corrupt retry ledger must be surfaced");
        assert!(error.to_string().contains("parse Homebrew outcome ledger"));
        Ok(())
    }

    #[test]
    fn cask_runtime_identity_extracts_exact_bundle_ids_and_app_paths() -> anyhow::Result<()> {
        let metadata = serde_json::json!({
            "artifacts": [
                {
                    "uninstall": [{
                        "quit": ["com.example.Demo"],
                        "signal": ["KILL", "com.example.DemoHelper"],
                        "delete": ["/Applications/Demo.app"]
                    }]
                },
                {"app": ["Demo.app"]},
                {"suite": ["Demo Suite"]},
                {"uninstall": {"launchctl": ["com.example.agent"], "pkgutil": ["com.example.pkg"]}},
                {"postflight_steps": [{"type": "terminate_process", "name": "/Applications/Demo.app"}]}
            ]
        });
        let identity = cask_runtime_identity(&metadata)?;

        assert!(identity.bundle_ids.contains("com.example.Demo"));
        assert!(identity.bundle_ids.contains("com.example.DemoHelper"));
        assert!(identity.service_names.contains("com.example.agent"));
        assert!(identity.package_receipts.contains("com.example.pkg"));
        assert!(identity_is_known(&identity));
        assert!(identity.app_paths.contains("/Applications/Demo Suite"));
        assert_eq!(
            identity.app_paths,
            BTreeSet::from([
                "/Applications/Demo.app".to_string(),
                "/Applications/Demo Suite".to_string()
            ])
        );

        let running = vec![RunningApplication {
            bundle_id: Some("com.example.Demographic".to_string()),
            path: Some("/Applications/Demo.app/Contents/MacOS/Demo".to_string()),
        }];
        assert!(cask_is_running(&identity, &running));
        let suite_running = vec![RunningApplication {
            bundle_id: None,
            path: Some("/Applications/Demo Suite/Demo.app/Contents/MacOS/Demo".to_string()),
        }];
        assert!(cask_is_running(&identity, &suite_running));

        let unrelated = vec![RunningApplication {
            bundle_id: Some("com.example.Demographic".to_string()),
            path: Some("/Applications/Other.app".to_string()),
        }];
        assert!(!cask_is_running(&identity, &unrelated));
        Ok(())
    }

    #[test]
    fn cask_runtime_identity_rejects_malformed_and_opaque_metadata() {
        assert!(cask_runtime_identity(&serde_json::json!({})).is_err());
        let opaque = serde_json::json!({
            "artifacts": [{"pkg": ["Demo.pkg"]}]
        });
        assert_eq!(
            cask_runtime_identity(&opaque).expect("valid opaque metadata"),
            CaskRuntimeIdentity::default()
        );

        let invalid_bundle_ids = serde_json::json!({
            "artifacts": [{
                "uninstall": [{
                    "quit": [
                        "Demo Helper",
                        "${BUNDLE_ID}",
                        "com.example.bad_id",
                        "com.example.good"
                    ]
                }]
            }]
        });
        let identity = cask_runtime_identity(&invalid_bundle_ids).expect("valid metadata");
        assert_eq!(
            identity.bundle_ids,
            BTreeSet::from(["com.example.good".to_string()])
        );

        let unresolved_uninstall = cask_runtime_identity(&serde_json::json!({
            "artifacts": [{
                "app": ["Demo.app"],
                "uninstall": {"launchctl": ["com.example.good", "${SERVICE_LABEL}"]}
            }]
        }))
        .expect("valid metadata with an unresolved service declaration");
        assert!(unresolved_uninstall.observation_incomplete);
        assert!(!identity_is_known(&unresolved_uninstall));
    }

    #[test]
    #[serial_test::serial]
    fn service_activity_checks_console_and_system_launchd_domains() -> anyhow::Result<()> {
        let root = tempdir()?;
        let bin = root.path().join("bin");
        fs::create_dir_all(&bin)?;
        let log = root.path().join("launchctl.log");
        write_script(
            &bin.join("launchctl"),
            "#!/bin/sh\necho \"$2\" >> \"$LAUNCHCTL_TEST_LOG\"\nif [ \"$2\" = \"system/com.example.agent\" ]; then echo 'state = waiting'; exit 0; fi\necho 'Could not find service' >&2\nexit 113\n",
        )?;
        let old_log = std::env::var("LAUNCHCTL_TEST_LOG").ok();
        std::env::set_var("LAUNCHCTL_TEST_LOG", &log);
        let running = service_is_running_with(&bin.join("launchctl"), "com.example.agent");
        if let Some(value) = old_log {
            std::env::set_var("LAUNCHCTL_TEST_LOG", value);
        } else {
            std::env::remove_var("LAUNCHCTL_TEST_LOG");
        }

        assert!(running?);
        let queried = fs::read_to_string(log)?;
        let uid = unsafe { libc::geteuid() };
        assert!(queried.contains(&format!("gui/{uid}/com.example.agent")));
        assert!(queried.contains("system/com.example.agent"));
        Ok(())
    }

    #[test]
    fn failed_launchctl_observation_is_not_treated_as_inactive() -> anyhow::Result<()> {
        let root = tempdir()?;
        let launchctl = root.path().join("launchctl");
        write_script(
            &launchctl,
            "#!/bin/sh\necho 'Operation not permitted' >&2\nexit 1\n",
        )?;

        let error = service_is_running_with(&launchctl, "com.example.agent")
            .expect_err("failed service observation must defer the cask");
        assert!(error.to_string().contains("could not establish activity"));
        Ok(())
    }

    #[test]
    fn binary_activity_matches_resolved_symlink_targets() -> anyhow::Result<()> {
        let root = tempdir()?;
        let target = root.path().join("installed/helper");
        let alias = root.path().join("bin/helper");
        fs::create_dir_all(target.parent().expect("target parent"))?;
        fs::create_dir_all(alias.parent().expect("alias parent"))?;
        fs::write(&target, "helper")?;
        std::os::unix::fs::symlink(&target, &alias)?;

        assert!(executable_matches(
            &BTreeSet::from([alias.to_string_lossy().into_owned()]),
            &[target]
        ));
        Ok(())
    }

    #[test]
    fn binary_targets_resolve_from_the_configured_homebrew_prefix() -> anyhow::Result<()> {
        let root = tempdir()?;
        let brew_bin = root.path().join("opt/homebrew/bin");
        fs::create_dir_all(&brew_bin)?;
        let brew = brew_bin.join("brew");
        fs::write(&brew, "")?;
        let alternate_bin = root.path().join("usr/local/bin");
        fs::create_dir_all(&alternate_bin)?;
        std::os::unix::fs::symlink(&brew, alternate_bin.join("brew"))?;

        let metadata = serde_json::json!({
            "artifacts": [{"binary": [{"target": "demo-helper", "source": "helper"}]}]
        });
        let bin_dir = homebrew_bin_dir(&alternate_bin.join("brew"))?;
        assert_eq!(bin_dir, brew_bin.canonicalize()?);
        let identity = cask_runtime_identity_with_bin_dir(&metadata, &bin_dir)?;
        assert!(identity
            .binary_paths
            .contains(bin_dir.join("demo-helper").to_str().expect("UTF-8 path")));
        assert!(identity_is_known(&identity));
        Ok(())
    }

    #[test]
    #[serial_test::serial]
    fn package_receipt_resolves_relocated_relative_helper_and_service() -> anyhow::Result<()> {
        let root = tempdir()?;
        let volume = root.path().join("mounted-volume");
        let install_root = volume.join("Vendor/Scriptd");
        let plist = install_root.join("Library/LaunchDaemons/com.example.helper.plist");
        let helper = install_root.join("Library/PrivilegedHelperTools/example-helper");
        fs::create_dir_all(plist.parent().expect("plist parent"))?;
        fs::create_dir_all(helper.parent().expect("helper parent"))?;
        fs::write(
            &plist,
            "<?xml version=\"1.0\"?><plist><dict><key>Label</key><string>com.example.helper</string></dict></plist>",
        )?;
        fs::write(&helper, "helper")?;

        let pkgutil = root.path().join("pkgutil");
        write_script(
            &pkgutil,
            "#!/bin/sh\nif [ \"$1\" = \"--pkg-info-plist\" ]; then echo '<plist />'; exit 0; fi\nif [ \"$1\" = \"--files\" ]; then printf '%s\\n' 'Library/LaunchDaemons/com.example.helper.plist' 'Library/PrivilegedHelperTools/example-helper'; exit 0; fi\necho unsupported >&2\nexit 2\n",
        )?;
        fs::write(
            root.path().join("receipt-info.json"),
            serde_json::to_vec(&serde_json::json!({
                "volume": volume.to_string_lossy(),
                "install-location": "/Vendor/Scriptd"
            }))?,
        )?;
        let plutil = root.path().join("plutil");
        write_script(
            &plutil,
            "#!/bin/sh\ncat >/dev/null\ncat \"$(dirname \"$0\")/receipt-info.json\"\n",
        )?;

        let (paths, services) = resolve_package_receipts_with_tools(
            &BTreeSet::from(["com.example.product".to_string()]),
            &pkgutil,
            &plutil,
        )?;
        let helper_path = helper.canonicalize()?.to_string_lossy().into_owned();
        let plist_path = plist.canonicalize()?.to_string_lossy().into_owned();
        assert!(paths.contains(&plist_path));
        assert!(paths.contains(&helper_path));
        assert!(services.contains("com.example.helper"));
        assert!(executable_matches(&paths, &[helper]));
        Ok(())
    }

    #[test]
    fn missing_package_receipt_location_is_unknown_activity() -> anyhow::Result<()> {
        let root = tempdir()?;
        let pkgutil = root.path().join("pkgutil");
        write_script(
            &pkgutil,
            "#!/bin/sh\necho 'receipt metadata unavailable' >&2\nexit 1\n",
        )?;
        let plutil = root.path().join("plutil");
        write_script(&plutil, "#!/bin/sh\ncat >/dev/null\nexit 1\n")?;

        let error = resolve_package_receipts_with_tools(
            &BTreeSet::from(["com.example.product".to_string()]),
            &pkgutil,
            &plutil,
        )
        .expect_err("missing package location must defer the cask");
        assert!(error
            .to_string()
            .contains("could not establish package receipt location"));
        Ok(())
    }

    #[test]
    fn package_receipt_resolves_a_volume_relative_install_location() -> anyhow::Result<()> {
        // A real receipt reports "volume: /" with "install-location:
        // Applications" and relative `pkgutil --files` output.
        let root = tempdir()?;
        let volume = root.path().join("volume");
        let install_root = volume.join("Applications");
        let app = install_root.join("Example.app");
        fs::create_dir_all(&app)?;

        let pkgutil = root.path().join("pkgutil");
        write_script(
            &pkgutil,
            r##"#!/bin/sh
if [ "$1" = "--pkg-info-plist" ]; then echo '<plist />'; exit 0; fi
if [ "$1" = "--files" ]; then printf '%s\n' 'Example.app'; exit 0; fi
echo unsupported >&2
exit 2
"##,
        )?;
        fs::write(
            root.path().join("receipt-info.json"),
            serde_json::to_vec(&serde_json::json!({
                "volume": volume.to_string_lossy(),
                "install-location": "Applications"
            }))?,
        )?;
        let plutil = root.path().join("plutil");
        write_script(
            &plutil,
            r##"#!/bin/sh
cat >/dev/null
cat "$(dirname "$0")/receipt-info.json"
"##,
        )?;

        let (paths, services) = resolve_package_receipts_with_tools(
            &BTreeSet::from(["com.example.product".to_string()]),
            &pkgutil,
            &plutil,
        )?;
        let app_path = app.canonicalize()?.to_string_lossy().into_owned();
        assert!(
            paths.contains(&app_path),
            "a volume-relative install location must resolve inside its volume"
        );
        assert!(services.is_empty());
        Ok(())
    }

    #[test]
    fn package_receipt_resolves_a_slash_prefixed_relative_install_location() -> anyhow::Result<()> {
        let root = tempdir()?;
        let volume = root.path().join("volume");
        let install_root = volume.join("Applications");
        fs::create_dir_all(&install_root)?;

        let pkgutil = root.path().join("pkgutil");
        write_script(
            &pkgutil,
            r##"#!/bin/sh
if [ "$1" = "--pkg-info-plist" ]; then echo '<plist />'; exit 0; fi
if [ "$1" = "--files" ]; then printf '%s\n' 'Example.app'; exit 0; fi
echo unsupported >&2
exit 2
"##,
        )?;
        fs::write(
            root.path().join("receipt-info.json"),
            serde_json::to_vec(&serde_json::json!({
                "volume": volume.to_string_lossy(),
                "install-location": "/Applications"
            }))?,
        )?;
        let plutil = root.path().join("plutil");
        write_script(
            &plutil,
            r##"#!/bin/sh
cat >/dev/null
cat "$(dirname "$0")/receipt-info.json"
"##,
        )?;

        let (paths, _) = resolve_package_receipts_with_tools(
            &BTreeSet::from(["com.example.product".to_string()]),
            &pkgutil,
            &plutil,
        )?;
        assert_eq!(paths.len(), 1);
        Ok(())
    }

    #[test]
    fn package_receipt_rejects_a_traversal_install_location() -> anyhow::Result<()> {
        let root = tempdir()?;
        let volume = root.path().join("volume");
        fs::create_dir_all(&volume)?;

        let pkgutil = root.path().join("pkgutil");
        write_script(
            &pkgutil,
            r##"#!/bin/sh
if [ "$1" = "--pkg-info-plist" ]; then echo '<plist />'; exit 0; fi
echo unsupported >&2
exit 2
"##,
        )?;
        fs::write(
            root.path().join("receipt-info.json"),
            serde_json::to_vec(&serde_json::json!({
                "volume": volume.to_string_lossy(),
                "install-location": "../outside"
            }))?,
        )?;
        let plutil = root.path().join("plutil");
        write_script(
            &plutil,
            r##"#!/bin/sh
cat >/dev/null
cat "$(dirname "$0")/receipt-info.json"
"##,
        )?;

        let error = resolve_package_receipts_with_tools(
            &BTreeSet::from(["com.example.product".to_string()]),
            &pkgutil,
            &plutil,
        )
        .expect_err("a traversal install location must be rejected");
        assert!(error.to_string().contains("not a safe path"));
        Ok(())
    }

    #[test]
    fn package_receipt_rejects_a_relative_volume() -> anyhow::Result<()> {
        let root = tempdir()?;
        let pkgutil = root.path().join("pkgutil");
        write_script(
            &pkgutil,
            r##"#!/bin/sh
if [ "$1" = "--pkg-info-plist" ]; then echo '<plist />'; exit 0; fi
echo unsupported >&2
exit 2
"##,
        )?;
        fs::write(
            root.path().join("receipt-info.json"),
            serde_json::to_vec(&serde_json::json!({
                "volume": "relative/volume",
                "install-location": "Applications"
            }))?,
        )?;
        let plutil = root.path().join("plutil");
        write_script(
            &plutil,
            r##"#!/bin/sh
cat >/dev/null
cat "$(dirname "$0")/receipt-info.json"
"##,
        )?;

        let error = resolve_package_receipts_with_tools(
            &BTreeSet::from(["com.example.product".to_string()]),
            &pkgutil,
            &plutil,
        )
        .expect_err("a relative volume must be rejected");
        assert!(error
            .to_string()
            .contains("volume is not a safe absolute path"));
        Ok(())
    }

    #[test]
    fn missing_package_receipt_files_are_unknown_activity() -> anyhow::Result<()> {
        let root = tempdir()?;
        let volume = root.path().join("volume");
        let install_root = volume.join("Vendor/Scriptd");
        fs::create_dir_all(&install_root)?;
        let pkgutil = root.path().join("pkgutil");
        write_script(
            &pkgutil,
            "#!/bin/sh\nif [ \"$1\" = \"--pkg-info-plist\" ]; then echo '<plist />'; exit 0; fi\necho 'receipt missing' >&2\nexit 1\n",
        )?;
        fs::write(
            root.path().join("receipt-info.json"),
            serde_json::to_vec(&serde_json::json!({
                "volume": volume.to_string_lossy(),
                "install-location": "/Vendor/Scriptd"
            }))?,
        )?;
        let plutil = root.path().join("plutil");
        write_script(
            &plutil,
            "#!/bin/sh\ncat >/dev/null\ncat \"$(dirname \"$0\")/receipt-info.json\"\n",
        )?;

        let error = resolve_package_receipts_with_tools(
            &BTreeSet::from(["com.example.product".to_string()]),
            &pkgutil,
            &plutil,
        )
        .expect_err("failed receipt observation must be surfaced");
        assert!(error
            .to_string()
            .contains("could not establish installed files"));
        Ok(())
    }

    #[test]
    fn cask_outcomes_are_exposed_in_status_metrics_and_message() {
        let state = MbrewState {
            deferred_casks: vec!["running-cask".to_string()],
            failed_casks: vec!["broken-cask".to_string()],
            ..MbrewState::default()
        };
        let metrics = module_metrics(&state);
        assert_eq!(metrics["repairedCasks"], serde_json::json!("none"));
        assert_eq!(metrics["deferredCasks"], serde_json::json!("running-cask"));
        assert_eq!(metrics["failedCasks"], serde_json::json!("broken-cask"));
        assert!(maintenance_message(&state).contains("deferred casks: running-cask"));
        assert!(maintenance_message(&state).contains("failed casks: broken-cask"));
    }

    #[test]
    fn a_blocker_that_needs_a_human_action_is_never_retryable() {
        // A missing bridge, a missing setup, a denied policy, and an
        // unverifiable activity state all need the user to act first, so
        // none of them may advertise themselves as retryable.
        for class in [
            CaskBlockerClass::SetupMissing,
            CaskBlockerClass::BridgeAbsent,
            CaskBlockerClass::ActivityUnverifiable,
            CaskBlockerClass::PolicyDenied,
        ] {
            assert!(
                !class.is_retryable(),
                "{} must not be advertised as retryable",
                class.as_str()
            );
            assert!(
                !class.recovery_action().is_empty(),
                "{} must name a recovery action",
                class.as_str()
            );
        }
    }

    #[test]
    fn a_running_application_and_a_failed_upgrade_stay_retryable() {
        assert!(CaskBlockerClass::ApplicationRunning.is_retryable());
        assert!(CaskBlockerClass::UpgradeFailed.is_retryable());
    }

    #[test]
    fn a_deferred_cask_records_its_blocker_class_and_recovery_action() {
        let mut outcome = BrewMaintenanceOutcome::default();
        let logger = ModuleLogger::new(std::env::temp_dir(), "mbrew", false);
        defer_cask_with_class(
            &mut outcome,
            &logger,
            "bridge-cask",
            "privilege bridge setup is required",
            CaskBlockerClass::BridgeAbsent,
        );

        assert!(outcome.deferred_casks.contains(&"bridge-cask".to_string()));
        assert!(
            !outcome.retryable_casks.contains("bridge-cask"),
            "a missing bridge must not advertise itself as retryable"
        );
        assert_eq!(
            outcome.blockers.get("bridge-cask"),
            Some(&CaskBlockerClass::BridgeAbsent)
        );
        assert_eq!(
            outcome.reasons.get("bridge-cask").map(String::as_str),
            Some("privilege bridge setup is required")
        );
    }

    #[test]
    fn a_blocker_class_has_a_stable_distinct_name() {
        let mut names: Vec<&str> = [
            CaskBlockerClass::SetupMissing,
            CaskBlockerClass::BridgeAbsent,
            CaskBlockerClass::ApplicationRunning,
            CaskBlockerClass::ActivityUnverifiable,
            CaskBlockerClass::PolicyDenied,
            CaskBlockerClass::UpgradeFailed,
        ]
        .iter()
        .map(|class| class.as_str())
        .collect();
        names.sort_unstable();
        let count = names.len();
        names.dedup();
        assert_eq!(names.len(), count, "blocker class names must be distinct");
    }

    #[test]
    fn the_installed_askpass_helper_is_refreshed_from_the_tracked_source() -> anyhow::Result<()> {
        let root = tempdir()?;
        let source = root.path().join("brew_askpass.sh");
        fs::write(&source, "#!/bin/sh\nexit 1\n")?;
        let installed = root.path().join("installed/brew_askpass.sh");
        fs::create_dir_all(installed.parent().expect("installed parent"))?;
        // A stale copy from an earlier version must be replaced.
        fs::write(&installed, "#!/bin/sh\necho stale >&2\n")?;

        let config = MbrewConfig {
            askpass_path: installed.to_string_lossy().into_owned(),
            ..MbrewConfig::default()
        };
        let logger = ModuleLogger::new(root.path().to_path_buf(), "mbrew", false);

        let previous_root = std::env::var_os("SCRIPTD_ROOT_DIR");
        // Point the tracked-asset lookup at a directory that holds the source.
        let asset_root = root.path().join("assets");
        fs::create_dir_all(asset_root.join("modules/mbrew"))?;
        fs::copy(&source, asset_root.join("modules/mbrew/brew_askpass.sh"))?;
        std::env::set_var("SCRIPTD_ROOT_DIR", &asset_root);
        let result = write_askpass(&config, &logger);
        match previous_root {
            Some(value) => std::env::set_var("SCRIPTD_ROOT_DIR", value),
            None => std::env::remove_var("SCRIPTD_ROOT_DIR"),
        }
        result?;

        assert_eq!(
            fs::read(&installed)?,
            fs::read(&source)?,
            "the installed helper must match the tracked source"
        );
        Ok(())
    }

    #[test]
    fn untrusted_homebrew_entries_are_deduplicated() {
        let output = "Warning: Skipping oven-sh/bun because it is not trusted.\nWarning: Skipping oven-sh/bun because it is not trusted.\nWarning: Skipping user/tap/tool because it is not trusted.";
        assert_eq!(
            untrusted_homebrew_entries(output),
            vec!["oven-sh/bun".to_string(), "user/tap/tool".to_string()]
        );
    }

    #[test]
    fn validate_config_rejects_non_tap_trust_targets() {
        let mut config = MbrewConfig::default();
        config.trusted_taps = vec!["not-a-tap".to_string()];
        let error = validate_config(&config).expect_err("invalid tap should be rejected");
        assert!(error.to_string().contains("owner/repository"));
    }

    fn write_trust_brew(
        path: &Path,
        log: &Path,
        update_warning: Option<&str>,
    ) -> anyhow::Result<()> {
        let update = update_warning
            .map(|warning| format!("printf '%s\\n' '{warning}' >&2"))
            .unwrap_or_else(|| "true".to_string());
        write_script(
            path,
            &format!(
                r#"#!/bin/sh
echo "$@" >> "{log}"
if [ "$1" = "tap" ]; then
  printf '%s\n' trusted/tap untrusted/tap
  exit 0
fi
if [ "$1" = "trust" ] && [ "$2" = "--tap" ]; then exit 0; fi
if [ "$1" = "update" ]; then
  {update}
  exit 0
fi
if [ "$1" = "upgrade" ] && [ "$2" = "--formula" ]; then exit 0; fi
if [ "$1" = "outdated" ] && [ "$2" = "--cask" ]; then printf '%s\n' '{{"casks":[]}}'; exit 0; fi
if [ "$1" = "cleanup" ]; then exit 0; fi
echo unsupported-command >&2
exit 1
"#,
                log = log.to_string_lossy(),
                update = update,
            ),
        )
    }

    #[test]
    fn brew_maintenance_trusts_only_configured_installed_taps_before_update() -> anyhow::Result<()>
    {
        let root = tempdir()?;
        let brew = root.path().join("brew");
        let log = root.path().join("brew.log");
        let askpass = root.path().join("askpass.sh");
        write_trust_brew(&brew, &log, None)?;
        fs::write(&askpass, "#!/bin/sh\nexit 1\n")?;
        let mut config = default_config(root.path(), &brew, &askpass);
        config.trusted_taps = vec!["trusted/tap".to_string()];

        brew_maintenance(
            &config,
            &ModuleLogger::new(root.path().to_path_buf(), "mbrew", false),
            None,
            root.path(),
        )?;

        let log = fs::read_to_string(log)?;
        let commands: Vec<&str> = log.lines().collect();
        assert_eq!(commands[0], "tap");
        assert_eq!(commands[1], "trust --tap trusted/tap");
        assert_eq!(commands[2], "update");
        assert!(!log.contains("--force"));
        assert!(!log.contains("trust --tap untrusted/tap"));
        Ok(())
    }

    #[test]
    fn brew_maintenance_rejects_untrusted_update_entries() -> anyhow::Result<()> {
        let root = tempdir()?;
        let brew = root.path().join("brew");
        let log = root.path().join("brew.log");
        let askpass = root.path().join("askpass.sh");
        write_trust_brew(
            &brew,
            &log,
            Some("Warning: Skipping untrusted/tap because it is not trusted."),
        )?;
        fs::write(&askpass, "#!/bin/sh\nexit 1\n")?;
        let config = default_config(root.path(), &brew, &askpass);

        let error = brew_maintenance(
            &config,
            &ModuleLogger::new(root.path().to_path_buf(), "mbrew", false),
            None,
            root.path(),
        )
        .expect_err("untrusted entries must stop maintenance");

        assert!(error.to_string().contains("untrusted/tap"));
        assert!(error.to_string().contains("trusted_taps"));
        let log = fs::read_to_string(log)?;
        assert!(log.contains("update"));
        assert!(!log.contains("upgrade --formula"));
        Ok(())
    }

    fn write_safe_cask_brew(path: &Path, upgrade_status: i32) -> anyhow::Result<()> {
        write_script(
            path,
            &format!(
                r#"#!/bin/sh
echo "$@" >> "$BREW_TEST_LOG"
if [ "$1" = "update" ]; then exit 0; fi
if [ "$1" = "upgrade" ] && [ "$2" = "--formula" ]; then exit 0; fi
if [ "$1" = "outdated" ] && [ "$2" = "--cask" ]; then
  printf '%s\n' '{{"casks":[{{"name":"running-cask","current_version":"2.0"}},{{"name":"closed-cask","current_version":"2.0"}},{{"name":"opaque-cask","current_version":"2.0"}},{{"name":"malformed-cask","current_version":"2.0"}}]}}'
  exit 0
fi
if [ "$1" = "info" ] && [ "$2" = "--cask" ]; then
  case "$4" in
    running-cask)
      printf '%s\n' '{{"casks":[{{"token":"running-cask","artifacts":[{{"app":["Running.app"],"target":"/Applications/Running.app"}}]}}]}}'
      ;;
    closed-cask)
      printf '%s\n' '{{"casks":[{{"token":"closed-cask","artifacts":[{{"app":["Closed.app"],"target":"/Applications/Closed.app"}}]}}]}}'
      ;;
    opaque-cask)
      printf '%s\n' '{{"casks":[{{"token":"opaque-cask","artifacts":[{{"pkg":["Opaque.pkg"]}}]}}]}}'
      ;;
    malformed-cask)
      printf '%s\n' 'not-json'
      ;;
  esac
  exit 0
fi
if [ "$1" = "upgrade" ] && [ "$2" = "--cask" ] && [ "$3" = "--no-quit" ]; then
  if [ "$4" = "running-cask" ]; then
    echo upgraded
    exit 0
  fi
  if [ "$4" = "closed-cask" ]; then
    echo upgraded
    exit {upgrade_status}
  fi
  echo unexpected-cask-upgrade >&2
  exit 1
fi
if [ "$1" = "cleanup" ]; then exit 0; fi
echo unsupported-command >&2
exit 1
"#,
                upgrade_status = upgrade_status
            ),
        )
    }

    fn run_safe_cask_brew_test(
        upgrade_status: i32,
        osascript_body: &str,
    ) -> anyhow::Result<(BrewMaintenanceOutcome, String)> {
        let root = tempdir()?;
        // The ledger lives in a task-local state directory: a unit test must
        // never write the production ledger under ~/Library/Application Support.
        let state_dir = root.path().join("state");
        fs::create_dir_all(&state_dir)?;
        let fake_bin = root.path().join("bin");
        fs::create_dir_all(&fake_bin)?;
        let brew = fake_bin.join("brew");
        let osascript = fake_bin.join("osascript");
        let brew_log = root.path().join("brew.log");
        let askpass = root.path().join("askpass.sh");
        write_safe_cask_brew(&brew, upgrade_status)?;
        write_script(&osascript, osascript_body)?;
        fs::write(&askpass, "#!/bin/sh\nexit 1\n")?;
        let config = default_config(root.path(), &brew, &askpass);
        let previous_log = std::env::var("BREW_TEST_LOG").ok();
        std::env::set_var("BREW_TEST_LOG", &brew_log);
        let result = with_path_scope(&fake_bin, || {
            brew_maintenance(
                &config,
                &ModuleLogger::new(root.path().to_path_buf(), "mbrew", false),
                None,
                &state_dir,
            )
        });
        if let Some(value) = previous_log {
            std::env::set_var("BREW_TEST_LOG", value);
        } else {
            std::env::remove_var("BREW_TEST_LOG");
        }
        Ok((result?, fs::read_to_string(brew_log)?))
    }

    #[test]
    #[serial_test::serial]
    fn pending_retry_only_upgrades_retryable_casks_and_preserves_full_pass_errors(
    ) -> anyhow::Result<()> {
        let root = tempdir()?;
        let home = root.path().join("home");
        let fake_bin = root.path().join("bin");
        fs::create_dir_all(&home)?;
        fs::create_dir_all(&fake_bin)?;
        let brew_log = root.path().join("brew.log");
        let brew = fake_bin.join("brew");
        let askpass = root.path().join("askpass.sh");
        let script = r#"#!/bin/sh
echo "$@" >> "$BREW_TEST_LOG"
if [ "$1" = "outdated" ]; then
  printf '%s\n' '{"casks":[{"name":"pending-cask","current_version":"1.0"},{"name":"attention-cask","current_version":"1.0"}]}'
  exit 0
fi
if [ "$1" = "info" ]; then
  printf '%s\n' '{"casks":[{"token":"pending-cask","artifacts":[{"app":["Pending.app"],"target":"/Applications/Pending.app"}]}]}'
  exit 0
fi
if [ "$1" = "upgrade" ] && [ "$4" = "pending-cask" ]; then exit 0; fi
echo unexpected-command >&2
exit 1
"#;
        write_script(&brew, script)?;
        write_script(
            &fake_bin.join("osascript"),
            "#!/bin/sh\nprintf '%s\\n' '[]'\n",
        )?;
        fs::write(&askpass, "#!/bin/sh\nexit 1\n")?;
        let config = default_config(root.path(), &brew, &askpass);
        let state_dir = home.join("Library/Application Support/scriptd");
        fs::create_dir_all(&state_dir)?;
        let ledger_path = state_dir.join("mbrew-outcomes.json");
        fs::write(
            &ledger_path,
            serde_json::to_vec(&PackageLedger {
                packages: vec![
                    PackageRecord {
                        name: "pending-cask".to_string(),
                        state: "deferred".to_string(),
                        reason: Some("application running".to_string()),
                        blocker: Some("application_running".to_string()),
                        recovery: Some(
                            CaskBlockerClass::ApplicationRunning
                                .recovery_action()
                                .to_string(),
                        ),
                        attempts: 2,
                        retry: true,
                        dismissed: false,
                    },
                    PackageRecord {
                        name: "attention-cask".to_string(),
                        state: "attention".to_string(),
                        reason: Some("metadata unavailable".to_string()),
                        blocker: Some("activity_unverifiable".to_string()),
                        recovery: Some(
                            CaskBlockerClass::ActivityUnverifiable
                                .recovery_action()
                                .to_string(),
                        ),
                        attempts: 1,
                        retry: false,
                        dismissed: false,
                    },
                    PackageRecord {
                        name: "stale-cask".to_string(),
                        state: "deferred".to_string(),
                        reason: Some("application running".to_string()),
                        blocker: Some("application_running".to_string()),
                        recovery: Some(
                            CaskBlockerClass::ApplicationRunning
                                .recovery_action()
                                .to_string(),
                        ),
                        attempts: 3,
                        retry: true,
                        dismissed: false,
                    },
                ],
                formula_error: Some("prior formula warning".to_string()),
                cleanup_error: None,
                cask_error: None,
            })?,
        )?;

        let previous_home = std::env::var("HOME").ok();
        let previous_log = std::env::var("BREW_TEST_LOG").ok();
        std::env::set_var("HOME", &home);
        std::env::set_var("BREW_TEST_LOG", &brew_log);
        let result = with_path_scope(&fake_bin, || {
            brew_maintenance(
                &config,
                &ModuleLogger::new(root.path().to_path_buf(), "mbrew", false),
                Some("retry_pending"),
                &state_dir,
            )
        });
        if let Some(value) = previous_home {
            std::env::set_var("HOME", value);
        } else {
            std::env::remove_var("HOME");
        }
        if let Some(value) = previous_log {
            std::env::set_var("BREW_TEST_LOG", value);
        } else {
            std::env::remove_var("BREW_TEST_LOG");
        }

        let outcome = result?;
        assert!(outcome.repaired_casks.is_empty());
        assert_eq!(outcome.deferred_casks, vec!["pending-cask"]);
        let log = fs::read_to_string(&brew_log)?;
        assert!(!log.contains("upgrade --cask --no-quit pending-cask"));
        assert!(!log.contains("attention-cask"));
        assert!(!log.contains(" update"));
        assert!(!log.contains("upgrade --formula"));
        assert!(!log.contains("cleanup"));

        let ledger: PackageLedger = serde_json::from_slice(&fs::read(ledger_path)?)?;
        assert_eq!(
            ledger.formula_error.as_deref(),
            Some("prior formula warning")
        );
        assert!(ledger
            .packages
            .iter()
            .any(|item| item.name == "pending-cask" && item.state == "attention" && !item.retry));
        assert!(ledger
            .packages
            .iter()
            .any(|item| item.name == "attention-cask" && item.state == "attention" && !item.retry));
        assert!(ledger.packages.iter().any(|item| {
            item.name == "stale-cask"
                && item.state == "current"
                && !item.retry
                && item.reason.is_none()
        }));
        Ok(())
    }

    #[test]
    #[serial_test::serial]
    fn brew_maintenance_defers_running_opaque_and_malformed_casks() -> anyhow::Result<()> {
        let (outcome, log) = run_safe_cask_brew_test(
            0,
            "#!/bin/sh\nprintf '%s\\n' '[{\"bundleId\":\"com.example.running\",\"path\":\"/Applications/Running.app/Contents/MacOS/Running\"}]'\nexit 0\n",
        )?;
        assert!(outcome.repaired_casks.is_empty());
        assert_eq!(outcome.failed_casks, Vec::<String>::new());
        assert_eq!(
            outcome.deferred_casks,
            vec![
                "running-cask".to_string(),
                "closed-cask".to_string(),
                "opaque-cask".to_string(),
                "malformed-cask".to_string()
            ]
        );
        assert!(!log.contains("upgrade --cask --no-quit closed-cask"));
        assert!(!log.contains("--force"));
        assert!(!log.contains("uninstall"));
        assert!(!log.contains("install"));
        assert!(log.contains("cleanup"));
        Ok(())
    }

    #[test]
    #[serial_test::serial]
    fn brew_maintenance_defers_when_running_app_detection_fails() -> anyhow::Result<()> {
        let (outcome, log) = run_safe_cask_brew_test(0, "#!/bin/sh\nexit 1\n")?;
        assert_eq!(
            outcome.deferred_casks,
            vec![
                "running-cask".to_string(),
                "closed-cask".to_string(),
                "opaque-cask".to_string(),
                "malformed-cask".to_string(),
            ]
        );
        assert_eq!(outcome.failed_casks, Vec::<String>::new());
        assert!(!log.contains("upgrade --cask --no-quit"));
        assert!(log.contains("cleanup"));
        Ok(())
    }

    #[test]
    #[serial_test::serial]
    fn brew_maintenance_records_cask_failure_without_repair_commands() -> anyhow::Result<()> {
        let (outcome, log) =
            run_safe_cask_brew_test(1, "#!/bin/sh\nprintf '%s\\n' '[]'\nexit 0\n")?;
        assert_eq!(
            outcome.deferred_casks,
            vec![
                "running-cask".to_string(),
                "closed-cask".to_string(),
                "opaque-cask".to_string(),
                "malformed-cask".to_string()
            ]
        );
        assert!(outcome.failed_casks.is_empty());
        assert!(outcome.deferred_casks.contains(&"closed-cask".to_string()));
        assert!(!log.contains("upgrade --cask --no-quit closed-cask"));
        assert!(!log.contains("--force"));
        assert!(!log.contains("uninstall"));
        assert!(!log.contains("install"));
        assert!(log.contains("cleanup"));
        Ok(())
    }

    #[test]
    #[serial_test::serial]
    fn brew_askpass_is_refreshed_from_tracked_source_during_maintenance() -> anyhow::Result<()> {
        let root = tempdir()?;
        let fake_bin = root.path().join("bin");
        fs::create_dir_all(&fake_bin)?;
        let security = fake_bin.join("security");
        let askpass = root.path().join("brew_askpass.sh");
        write_script(
            &security,
            "#!/bin/sh\nif [ \"$1\" = \"find-generic-password\" ]; then\necho super-secret\nexit 0\nfi\nexit 0\n",
        )?;
        let config = default_config(root.path(), &root.path().join("brew"), &askpass);
        crate::credentials::store_admin_password("super-secret")?;

        let tracked = askpass_source_path()?;
        let tracked_content = fs::read(&tracked)
            .with_context(|| format!("read tracked askpass helper {}", tracked.display()))?;
        let previous_root = std::env::var_os("SCRIPTD_ROOT_DIR");
        std::env::set_var("SCRIPTD_ROOT_DIR", tracked_root());
        with_path_scope(&fake_bin, || -> anyhow::Result<()> {
            fs::write(&askpass, "stale helper")?;
            ensure_askpass(
                &config,
                &ModuleLogger::new(root.path().to_path_buf(), "mbrew", false),
            )
            .expect("stale askpass refreshed");
            assert!(askpass.exists());
            Ok(())
        })?;
        match previous_root {
            Some(value) => std::env::set_var("SCRIPTD_ROOT_DIR", value),
            None => std::env::remove_var("SCRIPTD_ROOT_DIR"),
        }
        let content = fs::read(&askpass)?;
        assert_eq!(
            content, tracked_content,
            "the installed askpass helper must match the tracked repository asset"
        );
        Ok(())
    }

    #[test]
    #[serial_test::serial]
    fn brew_setup_requires_keychain_password_when_missing() -> anyhow::Result<()> {
        let root = tempdir()?;
        let fake_bin = root.path().join("bin");
        fs::create_dir_all(&fake_bin)?;
        let security = fake_bin.join("security");
        write_script(
            &security,
            "#!/bin/sh\nif [ \"$1\" = \"find-generic-password\" ]; then\nexit 1\nfi\nexit 0\n",
        )?;
        let config = default_config(
            root.path(),
            &root.path().join("brew"),
            &root.path().join("askpass.sh"),
        );
        crate::credentials::delete_admin_password()?;

        let result = with_path_scope(&fake_bin, || {
            ensure_askpass(
                &config,
                &ModuleLogger::new(root.path().to_path_buf(), "mbrew", false),
            )
        });
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("mbrew setup required"));
        Ok(())
    }

    #[test]
    #[serial_test::serial]
    fn command_for_brew_includes_askpass_environment() -> anyhow::Result<()> {
        let root = tempdir()?;
        let fake_bin = root.path().join("bin");
        fs::create_dir_all(&fake_bin)?;
        let askpass = root.path().join("askpass.sh");
        fs::write(&askpass, "SECRET=1\n")?;
        let brew = fake_bin.join("brew");
        write_script(&brew, "#!/bin/sh\nprintf \"$SUDO_ASKPASS\"\nexit 0\n")?;
        let config = default_config(root.path(), &brew, &askpass);
        let (stdout, _, code) = command_for_brew(&config, &["--version"])?;
        assert_eq!(code, 0);
        assert_eq!(stdout.trim(), askpass.to_string_lossy());
        Ok(())
    }

    #[test]
    fn root_service_runs_homebrew_as_the_console_user() -> anyhow::Result<()> {
        let root = tempdir()?;
        let brew = root.path().join("brew");
        let askpass = root.path().join("askpass helper.sh");
        let config = default_config(root.path(), &brew, &askpass);

        let command = build_brew_command(&config, &["upgrade", "--formula"], 0, Some(501))?;
        assert_eq!(command.get_program(), "/usr/bin/sudo");
        let args = command
            .get_args()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        let expected = [
            "-n".to_string(),
            "-u".to_string(),
            "#501".to_string(),
            "-H".to_string(),
            "--".to_string(),
            "/usr/bin/env".to_string(),
            format!("SUDO_ASKPASS={}", askpass.display()),
            brew.to_string_lossy().into_owned(),
            "upgrade".to_string(),
            "--formula".to_string(),
        ];
        assert_eq!(args, expected);
        assert!(build_brew_command(&config, &["upgrade"], 0, Some(0)).is_err());
        assert!(build_brew_command(&config, &["upgrade"], 0, None).is_err());
        Ok(())
    }

    fn seed_ledger(state_dir: &Path, packages: Vec<PackageRecord>) -> anyhow::Result<()> {
        fs::create_dir_all(state_dir)?;
        fs::write(
            ledger_path(state_dir),
            serde_json::to_vec(&PackageLedger {
                packages,
                formula_error: None,
                cleanup_error: None,
                cask_error: None,
            })?,
        )?;
        Ok(())
    }

    fn record(name: &str, state: &str, attempts: u32, retry: bool) -> PackageRecord {
        PackageRecord {
            name: name.to_string(),
            state: state.to_string(),
            reason: Some("reason".to_string()),
            blocker: None,
            recovery: None,
            attempts,
            retry,
            dismissed: false,
        }
    }

    #[test]
    fn deferred_casks_do_not_accumulate_upgrade_attempts() -> anyhow::Result<()> {
        let root = tempdir()?;
        let state_dir = root.path().join("state");
        seed_ledger(
            &state_dir,
            vec![record("deferred-cask", "deferred", 4, true)],
        )?;

        // A pure deferral: the cask was never upgraded, so no attempt is made.
        let outcome = BrewMaintenanceOutcome {
            deferred_casks: vec!["deferred-cask".to_string()],
            retryable_casks: BTreeSet::from(["deferred-cask".to_string()]),
            reasons: BTreeMap::from([("deferred-cask".to_string(), "app running".to_string())]),
            ..BrewMaintenanceOutcome::default()
        };
        record_cask_ledger(&state_dir, &outcome, false)?;

        let ledger = load_ledger(&state_dir)?;
        let entry = ledger
            .packages
            .iter()
            .find(|item| item.name == "deferred-cask")
            .expect("deferred cask stays in the ledger");
        assert_eq!(entry.attempts, 4, "a deferral is not an upgrade attempt");
        assert_eq!(entry.state, "deferred");
        assert!(entry.retry);
        Ok(())
    }

    #[test]
    fn repeated_deferrals_never_raise_the_attempt_counter() -> anyhow::Result<()> {
        let root = tempdir()?;
        let state_dir = root.path().join("state");
        seed_ledger(
            &state_dir,
            vec![record("deferred-cask", "deferred", 0, true)],
        )?;

        for _ in 0..5 {
            let outcome = BrewMaintenanceOutcome {
                deferred_casks: vec!["deferred-cask".to_string()],
                retryable_casks: BTreeSet::from(["deferred-cask".to_string()]),
                ..BrewMaintenanceOutcome::default()
            };
            record_cask_ledger(&state_dir, &outcome, false)?;
        }

        let ledger = load_ledger(&state_dir)?;
        let entry = ledger
            .packages
            .iter()
            .find(|item| item.name == "deferred-cask")
            .expect("deferred cask stays in the ledger");
        assert_eq!(entry.attempts, 0);
        Ok(())
    }

    #[test]
    fn a_real_upgrade_attempt_counts_once_and_a_repair_counts_once() -> anyhow::Result<()> {
        let root = tempdir()?;
        let state_dir = root.path().join("state");
        seed_ledger(
            &state_dir,
            vec![record("repaired-cask", "deferred", 2, true)],
        )?;

        let outcome = BrewMaintenanceOutcome {
            repaired_casks: vec!["repaired-cask".to_string()],
            attempted_casks: BTreeSet::from(["repaired-cask".to_string()]),
            ..BrewMaintenanceOutcome::default()
        };
        record_cask_ledger(&state_dir, &outcome, false)?;

        let ledger = load_ledger(&state_dir)?;
        let entry = ledger
            .packages
            .iter()
            .find(|item| item.name == "repaired-cask")
            .expect("repaired cask stays in the ledger");
        assert_eq!(entry.attempts, 3, "a real upgrade attempt counts once");
        assert_eq!(entry.state, "updated");
        Ok(())
    }

    #[test]
    fn a_failed_upgrade_counts_as_one_attempt() -> anyhow::Result<()> {
        let root = tempdir()?;
        let state_dir = root.path().join("state");
        seed_ledger(&state_dir, vec![record("failed-cask", "deferred", 1, true)])?;

        let outcome = BrewMaintenanceOutcome {
            failed_casks: vec!["failed-cask".to_string()],
            attention_casks: BTreeSet::from(["failed-cask".to_string()]),
            attempted_casks: BTreeSet::from(["failed-cask".to_string()]),
            ..BrewMaintenanceOutcome::default()
        };
        record_cask_ledger(&state_dir, &outcome, false)?;

        let ledger = load_ledger(&state_dir)?;
        let entry = ledger
            .packages
            .iter()
            .find(|item| item.name == "failed-cask")
            .expect("failed cask stays in the ledger");
        assert_eq!(entry.attempts, 2);
        assert_eq!(entry.state, "attention");
        assert!(!entry.retry);
        Ok(())
    }

    #[test]
    fn prelaunch_failure_does_not_increment_the_attempt_counter() -> anyhow::Result<()> {
        let root = tempdir()?;
        let state_dir = root.path().join("state");
        seed_ledger(&state_dir, vec![record("failed-cask", "deferred", 3, true)])?;

        let outcome = BrewMaintenanceOutcome {
            failed_casks: vec!["failed-cask".to_string()],
            attention_casks: BTreeSet::from(["failed-cask".to_string()]),
            ..BrewMaintenanceOutcome::default()
        };
        record_cask_ledger(&state_dir, &outcome, false)?;

        let entry = load_ledger(&state_dir)?.packages.remove(0);
        assert_eq!(entry.attempts, 3);
        assert_eq!(entry.state, "attention");
        Ok(())
    }

    #[test]
    fn broker_launch_errors_preserve_confirmed_attempt_boundary() {
        let launched = anyhow::anyhow!("wait for helper-launched Homebrew worker: interrupted");
        assert_eq!(
            broker_launch_error_status(&launched),
            BrokerLaunchFailure::Started
        );
        assert!(matches!(
            broker_launch_failure_result(BrokerLaunchFailure::Started, &launched),
            BrokerUpgradeResult::Failed(_)
        ));
        let completion = anyhow::anyhow!("persist broker job completion: audit file unavailable");
        assert_eq!(
            broker_launch_error_status(&completion),
            BrokerLaunchFailure::Started
        );
        let release = anyhow::anyhow!("release the authenticated Homebrew worker: partial write");
        assert_eq!(
            broker_launch_error_status(&release),
            BrokerLaunchFailure::NotStarted
        );
        let spawn = anyhow::anyhow!("launch the normal-user Homebrew worker: executable missing");
        assert_eq!(
            broker_launch_error_status(&spawn),
            BrokerLaunchFailure::NotStarted
        );
        let bind = anyhow::anyhow!("bind the helper-launched Homebrew worker: rejected");
        assert_eq!(
            broker_launch_error_status(&bind),
            BrokerLaunchFailure::NotStarted
        );
        let compound =
            anyhow::anyhow!("broker job completion also failed: persist broker job completion");
        assert_eq!(
            broker_launch_error_status(&compound),
            BrokerLaunchFailure::NotStarted
        );
        let connection_refused = anyhow::Error::new(std::io::Error::new(
            std::io::ErrorKind::ConnectionRefused,
            "connection refused",
        ))
        .context("connect /tmp/scriptd-broker.sock")
        .context("broker control transport error");
        assert_eq!(
            broker_launch_error_status(&connection_refused),
            BrokerLaunchFailure::NotStarted
        );
        assert!(matches!(
            broker_launch_failure_result(BrokerLaunchFailure::NotStarted, &connection_refused),
            BrokerUpgradeResult::Deferred(_, CaskBlockerClass::BridgeAbsent)
        ));

        let lost_response = anyhow::Error::new(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "broker closed the connection after launching the worker",
        ))
        .context("read broker response")
        .context("broker control transport error");
        assert_eq!(
            broker_launch_error_status(&lost_response),
            BrokerLaunchFailure::Unknown
        );
        assert!(matches!(
            broker_launch_failure_result(
                broker_launch_error_status(&lost_response),
                &lost_response
            ),
            BrokerUpgradeResult::Unconfirmed(_)
        ));
    }

    #[test]
    fn unconfirmed_broker_launch_requires_attention_without_counting_attempt() -> anyhow::Result<()>
    {
        let root = tempdir()?;
        let state_dir = root.path().join("state");
        seed_ledger(
            &state_dir,
            vec![record("uncertain-cask", "deferred", 4, true)],
        )?;
        let logger = ModuleLogger::new(root.path().to_path_buf(), "mbrew", false);
        let error = anyhow::Error::new(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "broker closed the connection after launching the worker",
        ))
        .context("read broker response")
        .context("broker control transport error");
        let result = broker_launch_failure_result(broker_launch_error_status(&error), &error);
        let mut outcome = BrewMaintenanceOutcome::default();
        let BrokerUpgradeResult::Unconfirmed(reason) = result else {
            panic!("a lost broker response must remain unconfirmed");
        };
        defer_cask_for_attention(&mut outcome, &logger, "uncertain-cask", &reason);

        assert!(outcome.attempted_casks.is_empty());
        assert!(!outcome.retryable_casks.contains("uncertain-cask"));
        assert!(outcome.attention_casks.contains("uncertain-cask"));
        record_cask_ledger(&state_dir, &outcome, false)?;
        let entry = load_ledger(&state_dir)?.packages.remove(0);
        assert_eq!(entry.attempts, 4);
        assert_eq!(entry.state, "attention");
        assert!(!entry.retry);
        Ok(())
    }

    #[test]
    fn unresolved_attention_is_excluded_until_a_decision_approves_it() -> anyhow::Result<()> {
        let root = tempdir()?;
        let state_dir = root.path().join("state");
        seed_ledger(
            &state_dir,
            vec![record("attention-cask", "attention", 1, false)],
        )?;

        assert!(attention_casks(&state_dir)?.contains("attention-cask"));
        apply_cask_decision(&state_dir, "attention-cask", CaskDecision::Approve)?;
        assert!(!attention_casks(&state_dir)?.contains("attention-cask"));
        assert!(retry_candidates(&state_dir)?.contains("attention-cask"));
        Ok(())
    }

    #[test]
    fn dismissed_casks_stay_excluded_after_reopening_the_ledger() -> anyhow::Result<()> {
        let root = tempdir()?;
        let state_dir = root.path().join("state");
        seed_ledger(
            &state_dir,
            vec![record("attention-cask", "attention", 1, false)],
        )?;

        apply_cask_decision(&state_dir, "attention-cask", CaskDecision::Dismiss)?;

        let reopened = read_ledger(&ledger_path(&state_dir))?;
        let entry = reopened
            .packages
            .iter()
            .find(|entry| entry.name == "attention-cask")
            .expect("dismissed cask remains in the reopened ledger");
        assert!(entry.dismissed);
        assert!(!entry.retry);
        assert!(!retry_candidates(&state_dir)?.contains("attention-cask"));
        Ok(())
    }

    #[test]
    fn approving_a_cask_clears_attention_and_makes_it_eligible_again() -> anyhow::Result<()> {
        let root = tempdir()?;
        let state_dir = root.path().join("state");
        seed_ledger(
            &state_dir,
            vec![record("attention-cask", "attention", 2, false)],
        )?;

        apply_cask_decision(&state_dir, "attention-cask", CaskDecision::Approve)?;

        let ledger = load_ledger(&state_dir)?;
        let entry = ledger
            .packages
            .iter()
            .find(|item| item.name == "attention-cask")
            .expect("the cask stays visible in the ledger");
        assert_eq!(entry.state, "deferred");
        assert!(entry.retry, "an approved cask is retried by the next run");
        assert!(!entry.dismissed);
        assert_eq!(entry.attempts, 2, "a decision is not an upgrade attempt");
        Ok(())
    }

    #[test]
    fn dismissing_a_cask_keeps_it_visible_but_stops_retry_and_prompting() -> anyhow::Result<()> {
        let root = tempdir()?;
        let state_dir = root.path().join("state");
        seed_ledger(
            &state_dir,
            vec![record("attention-cask", "attention", 1, false)],
        )?;

        apply_cask_decision(&state_dir, "attention-cask", CaskDecision::Dismiss)?;

        let ledger = load_ledger(&state_dir)?;
        let entry = ledger
            .packages
            .iter()
            .find(|item| item.name == "attention-cask")
            .expect("a dismissed cask is still visible in the ledger");
        assert!(entry.dismissed);
        assert!(!entry.retry);
        assert_ne!(
            entry.state, "attention",
            "a dismissed cask is not re-prompted"
        );
        assert!(!retry_candidates(&state_dir)?.contains("attention-cask"));
        assert!(dismissed_casks(&state_dir)?.contains("attention-cask"));
        Ok(())
    }

    #[test]
    fn a_decision_for_an_unknown_cask_is_rejected() -> anyhow::Result<()> {
        let root = tempdir()?;
        let state_dir = root.path().join("state");
        seed_ledger(
            &state_dir,
            vec![record("attention-cask", "attention", 1, false)],
        )?;

        let error = apply_cask_decision(&state_dir, "missing-cask", CaskDecision::Approve)
            .expect_err("an unknown cask must be rejected");
        assert!(error.to_string().contains("missing-cask"));
        assert!(apply_cask_decision(&state_dir, "  ", CaskDecision::Approve).is_err());
        Ok(())
    }

    #[test]
    fn cask_decision_names_are_parsed() -> anyhow::Result<()> {
        assert_eq!(CaskDecision::parse("approve")?, CaskDecision::Approve);
        assert_eq!(CaskDecision::parse("Dismiss")?, CaskDecision::Dismiss);
        assert_eq!(CaskDecision::parse("retry")?, CaskDecision::Retry);
        assert!(CaskDecision::parse("nonsense").is_err());
        Ok(())
    }

    #[test]
    fn unit_tests_never_write_the_production_ledger() -> anyhow::Result<()> {
        // The production ledger must never be a target of a unit test: the
        // module threads an explicit state directory through every ledger
        // call, so the real file is only reachable from the production entry
        // point that resolves the state directory itself.
        let root = tempdir()?;
        let state_dir = root.path().join("state");
        seed_ledger(
            &state_dir,
            vec![record("deferred-cask", "deferred", 0, true)],
        )?;
        let outcome = BrewMaintenanceOutcome {
            deferred_casks: vec!["deferred-cask".to_string()],
            retryable_casks: BTreeSet::from(["deferred-cask".to_string()]),
            ..BrewMaintenanceOutcome::default()
        };
        record_cask_ledger(&state_dir, &outcome, false)?;

        assert!(ledger_path(&state_dir).starts_with(&state_dir));
        assert!(ledger_path(&state_dir).exists());
        Ok(())
    }

    #[test]
    fn a_decision_is_safe_while_a_run_records_its_outcome() -> anyhow::Result<()> {
        let root = tempdir()?;
        let state_dir = root.path().join("state");
        seed_ledger(
            &state_dir,
            vec![record("attention-cask", "attention", 1, false)],
        )?;

        // A decision and a maintenance run both take the ledger lock, so the
        // two read-modify-write cycles never interleave.
        let decision = std::thread::spawn({
            let state_dir = state_dir.clone();
            move || apply_cask_decision(&state_dir, "attention-cask", CaskDecision::Approve)
        });
        let record_outcome = std::thread::spawn({
            let state_dir = state_dir.clone();
            move || {
                let outcome = BrewMaintenanceOutcome {
                    deferred_casks: vec!["other-cask".to_string()],
                    retryable_casks: BTreeSet::from(["other-cask".to_string()]),
                    ..BrewMaintenanceOutcome::default()
                };
                record_cask_ledger(&state_dir, &outcome, false)
            }
        });
        decision.join().expect("decision thread")?;
        record_outcome.join().expect("recording thread")?;

        let ledger = load_ledger(&state_dir)?;
        assert!(ledger
            .packages
            .iter()
            .any(|item| item.name == "attention-cask" && item.state == "deferred"));
        assert!(ledger
            .packages
            .iter()
            .any(|item| item.name == "other-cask" && item.state == "deferred"));
        Ok(())
    }
}
