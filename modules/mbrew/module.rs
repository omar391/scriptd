use std::collections::{BTreeSet, HashMap};
use std::fs;
use std::io::Write;
use std::path::{Component, Path, PathBuf};
use std::process::Command;

use anyhow::{bail, Context};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::credentials;
use crate::modules::{ModuleContext, ModuleHealth, ModuleLogger, ModuleStatus};
use crate::paths::expand_home;

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
            sudoers_path: "/etc/sudoers.d/homebrew".to_string(),
            sudoers_timeout_path: "/etc/sudoers.d/homebrew_timeout".to_string(),
            sudo_timeout_hours: 2,
        }
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
        command.stdin(std::process::Stdio::piped());
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

fn write_askpass(config: &MbrewConfig, logger: &ModuleLogger) -> anyhow::Result<()> {
    let path = expand_home(&config.askpass_path);
    if path.exists() {
        return Ok(());
    }
    fs::create_dir_all(path.parent().expect("path has parent"))?;
    let mut file = fs::File::create(&path)?;
    let script = "#!/bin/bash\n\
echo \"scriptd mbrew sudoers setup is required\" >&2\n\
exit 1\n";
    file.write_all(script.as_bytes())?;
    let _ = Command::new("chmod")
        .args(["+x", &path.to_string_lossy()])
        .status();
    logger.info(&format!("wrote askpass helper {}", path.display()));
    Ok(())
}

fn ensure_askpass(config: &MbrewConfig, logger: &ModuleLogger) -> anyhow::Result<()> {
    let path = expand_home(&config.askpass_path);
    if path.exists() {
        return Ok(());
    }
    let existing = keychain_password()?;
    if existing.is_empty() {
        bail!("mbrew setup required. run './scriptd.sh config mbrew'");
    }
    write_askpass(config, logger)
}

fn configure_sudo(
    config: &MbrewConfig,
    password: &str,
    logger: &ModuleLogger,
) -> anyhow::Result<()> {
    let user = credentials::current_user();
    if user.is_empty() {
        bail!("could not resolve the current user for sudoers setup");
    }
    let rules = format!(
        "{} ALL=(ALL) NOPASSWD: {} upgrade*, {} cleanup\n",
        user, config.homebrew_bin, config.homebrew_bin
    );
    let timeout = format!(
        "Defaults:{} timestamp_timeout={}\n",
        user,
        config.sudo_timeout_hours.saturating_mul(60)
    );

    let rules_path = PathBuf::from(format!("/tmp/mbrew-rules-{}.tmp", std::process::id()));
    let timeout_path = PathBuf::from(format!("/tmp/mbrew-timeout-{}.tmp", std::process::id()));
    fs::write(&rules_path, rules)?;
    fs::write(&timeout_path, timeout)?;
    run_command(
        "sudo",
        &[
            "-S",
            "cp",
            rules_path.to_string_lossy().as_ref(),
            &config.sudoers_path,
        ],
        Some(&format!("{password}\n")),
        None,
    )?;
    run_command(
        "sudo",
        &["-S", "chmod", "440", &config.sudoers_path],
        Some(&format!("{password}\n")),
        None,
    )?;
    run_command(
        "sudo",
        &[
            "-S",
            "cp",
            timeout_path.to_string_lossy().as_ref(),
            &config.sudoers_timeout_path,
        ],
        Some(&format!("{password}\n")),
        None,
    )?;
    run_command(
        "sudo",
        &["-S", "chmod", "440", &config.sudoers_timeout_path],
        Some(&format!("{password}\n")),
        None,
    )?;
    let _ = fs::remove_file(rules_path);
    let _ = fs::remove_file(timeout_path);
    logger.info("configured sudoers for Homebrew maintenance");
    Ok(())
}

fn command_for_brew(config: &MbrewConfig, args: &[&str]) -> anyhow::Result<(String, String, i32)> {
    let askpass_path = expand_home(&config.askpass_path);
    let askpass = askpass_path.to_string_lossy().to_string();
    let env = [("SUDO_ASKPASS", askpass.as_str())];
    let command = run_command(&config.homebrew_bin, args, None, Some(&env))
        .context("brew command failed to execute")?;
    Ok(command)
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
}

#[derive(Debug, Default, PartialEq, Eq)]
struct CaskRuntimeIdentity {
    bundle_ids: BTreeSet<String>,
    app_paths: BTreeSet<String>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
struct RunningApplication {
    bundle_id: Option<String>,
    path: Option<String>,
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

fn collect_cask_runtime_identity(value: &serde_json::Value, identity: &mut CaskRuntimeIdentity) {
    let Some(object) = value.as_object() else {
        if let Some(values) = value.as_array() {
            for value in values {
                collect_cask_runtime_identity(value, identity);
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
        collect_cask_runtime_identity(value, identity);
    }
}

fn cask_runtime_identity(value: &serde_json::Value) -> anyhow::Result<CaskRuntimeIdentity> {
    let artifacts = value
        .get("artifacts")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| anyhow::anyhow!("cask metadata is missing artifacts"))?;
    let mut identity = CaskRuntimeIdentity::default();
    for artifact in artifacts {
        collect_cask_runtime_identity(artifact, &mut identity);
    }
    Ok(identity)
}

fn running_applications() -> anyhow::Result<Vec<RunningApplication>> {
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
                identity.app_paths.iter().any(|app_path| {
                    path == app_path || Path::new(path).starts_with(Path::new(app_path))
                })
            })
    })
}

fn cask_metadata(config: &MbrewConfig, cask: &str) -> anyhow::Result<Option<CaskRuntimeIdentity>> {
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
    let identity = cask_runtime_identity(metadata)?;
    Ok((!identity.bundle_ids.is_empty() || !identity.app_paths.is_empty()).then_some(identity))
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
    push_unique(&mut outcome.deferred_casks, cask);
    logger.warn(&format!("Deferring cask {cask}: {reason}"));
}

fn fail_cask(
    outcome: &mut BrewMaintenanceOutcome,
    logger: &ModuleLogger,
    cask: &str,
    reason: &str,
) {
    push_unique(&mut outcome.failed_casks, cask);
    logger.error(&format!("Cask {cask} upgrade failed: {reason}"));
}

fn brew_cask_maintenance(
    config: &MbrewConfig,
    logger: &ModuleLogger,
) -> anyhow::Result<BrewMaintenanceOutcome> {
    let (outdated_out, outdated_err, outdated_status) =
        command_for_brew(config, &["outdated", "--cask", "--quiet"])?;
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

    let casks: Vec<String> = outdated_out
        .lines()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
        .collect();
    let mut outcome = BrewMaintenanceOutcome::default();

    for cask in casks {
        let identity = match cask_metadata(config, &cask) {
            Ok(Some(identity)) => identity,
            Ok(None) => {
                defer_cask(
                    &mut outcome,
                    logger,
                    &cask,
                    "no trustworthy application identity is present in cask metadata",
                );
                continue;
            }
            Err(error) => {
                defer_cask(&mut outcome, logger, &cask, &error.to_string());
                continue;
            }
        };

        let applications = match running_applications() {
            Ok(applications) => applications,
            Err(error) => {
                defer_cask(
                    &mut outcome,
                    logger,
                    &cask,
                    &format!("could not verify running applications: {error}"),
                );
                continue;
            }
        };
        if cask_is_running(&identity, &applications) {
            defer_cask(
                &mut outcome,
                logger,
                &cask,
                "an application or helper from this cask is running",
            );
            continue;
        }

        // `--no-quit` is defense-in-depth; the identity check above is what
        // keeps Homebrew from replacing a bundle that is actively in use.
        let upgrade = command_for_brew(config, &["upgrade", "--cask", "--no-quit", cask.as_str()]);
        match upgrade {
            Ok((stdout, stderr, 0)) => {
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

fn run_cleanup(config: &MbrewConfig, logger: &ModuleLogger) -> anyhow::Result<()> {
    let (cleanup_out, _cleanup_err, _cleanup_status) = command_for_brew(config, &["cleanup"])?;
    if !cleanup_out.trim().is_empty() {
        logger.info(cleanup_out.trim());
    }
    Ok(())
}

fn brew_maintenance(
    config: &MbrewConfig,
    logger: &ModuleLogger,
) -> anyhow::Result<BrewMaintenanceOutcome> {
    ensure_askpass(config, logger)?;
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
    logger.info(if update_out.trim().is_empty() {
        "brew update completed"
    } else {
        update_out.trim()
    });

    let (formula_out, _formula_err, _formula_status) =
        command_for_brew(config, &["upgrade", "--formula"])?;
    if !formula_out.trim().is_empty() {
        logger.info(formula_out.trim());
    }
    let cask_result = brew_cask_maintenance(config, logger);
    let cleanup_result = run_cleanup(config, logger);
    let outcome = cask_result?;
    cleanup_result?;
    Ok(outcome)
}

pub fn setup(context: &mut ModuleContext) -> anyhow::Result<()> {
    let config = update_from_config(context)?;
    let password = credentials::admin_password_or_prompt()?;
    write_askpass(&config, &context.logger)?;
    configure_sudo(&config, &password, &context.logger)?;
    context.logger.info("mbrew setup complete");
    println!("mbrew setup complete.");
    Ok(())
}

pub fn run_once(context: &mut ModuleContext) -> anyhow::Result<Option<ModuleStatus>> {
    let config = update_from_config(context)?;
    let result = brew_maintenance(&config, &context.logger);
    let mut state = STATE.lock().unwrap_or_else(|error| error.into_inner());

    match result {
        Ok(outcome) => {
            state.last_error = None;
            state.last_run_at = Some(chrono::Utc::now().to_rfc3339());
            state.repaired_casks = outcome.repaired_casks;
            state.deferred_casks = outcome.deferred_casks;
            state.failed_casks = outcome.failed_casks;
            state.last_message = Some(maintenance_message(&state));
            if !state.failed_casks.is_empty() {
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
                {"postflight_steps": [{"type": "terminate_process", "name": "/Applications/Demo.app"}]}
            ]
        });
        let identity = cask_runtime_identity(&metadata)?;

        assert!(identity.bundle_ids.contains("com.example.Demo"));
        assert!(identity.bundle_ids.contains("com.example.DemoHelper"));
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

    fn write_safe_cask_brew(path: &Path, upgrade_status: i32) -> anyhow::Result<()> {
        write_script(
            path,
            &format!(
                r#"#!/bin/sh
echo "$@" >> "$BREW_TEST_LOG"
if [ "$1" = "update" ]; then exit 0; fi
if [ "$1" = "upgrade" ] && [ "$2" = "--formula" ]; then exit 0; fi
if [ "$1" = "outdated" ] && [ "$2" = "--cask" ] && [ "$3" = "--quiet" ]; then
  printf '%s\n' running-cask closed-cask opaque-cask malformed-cask
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
    fn brew_maintenance_defers_running_opaque_and_malformed_casks() -> anyhow::Result<()> {
        let (outcome, log) = run_safe_cask_brew_test(
            0,
            "#!/bin/sh\nprintf '%s\\n' '[{\"bundleId\":\"com.example.running\",\"path\":\"/Applications/Running.app/Contents/MacOS/Running\"}]'\nexit 0\n",
        )?;
        assert_eq!(outcome.repaired_casks, Vec::<String>::new());
        assert_eq!(outcome.failed_casks, Vec::<String>::new());
        assert_eq!(
            outcome.deferred_casks,
            vec![
                "running-cask".to_string(),
                "opaque-cask".to_string(),
                "malformed-cask".to_string()
            ]
        );
        assert!(log.contains("upgrade --cask --no-quit closed-cask"));
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
            vec!["opaque-cask".to_string(), "malformed-cask".to_string()]
        );
        assert_eq!(outcome.failed_casks, vec!["closed-cask".to_string()]);
        assert!(log.contains("upgrade --cask --no-quit closed-cask"));
        assert!(!log.contains("--force"));
        assert!(!log.contains("uninstall"));
        assert!(!log.contains("install"));
        assert!(log.contains("cleanup"));
        Ok(())
    }

    #[test]
    #[serial_test::serial]
    fn brew_askpass_recreated_when_missing() -> anyhow::Result<()> {
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

        with_path_scope(&fake_bin, || {
            assert!(!askpass.exists());
            ensure_askpass(
                &config,
                &ModuleLogger::new(root.path().to_path_buf(), "mbrew", false),
            )
            .expect("askpass written");
            assert!(askpass.exists());
        });
        let content = fs::read_to_string(&askpass)?;
        assert!(content.contains("sudoers setup is required"));
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
        write_script(&brew, "#!/bin/sh\necho \"$SUDO_ASKPASS\"\nexit 0\n")?;
        let config = default_config(root.path(), &brew, &askpass);
        let (stdout, _, code) = command_for_brew(&config, &["--version"])?;
        assert_eq!(code, 0);
        assert_eq!(stdout.trim(), askpass.to_string_lossy());
        Ok(())
    }
}
