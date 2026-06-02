use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::process::Command;

use anyhow::{bail, Context};
use rpassword::read_password;
use serde::{Deserialize, Serialize};

use crate::modules::{ModuleContext, ModuleHealth, ModuleLogger, ModuleStatus};
use crate::paths::expand_home;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct BrewManagerConfig {
    #[serde(rename = "keychain_service")]
    keychain_service: String,
    #[serde(rename = "askpass_path")]
    askpass_path: String,
    #[serde(rename = "legacy_log_dir")]
    legacy_log_dir: String,
    #[serde(rename = "max_log_size_mb")]
    max_log_size_mb: u64,
    #[serde(rename = "max_log_age_days")]
    max_log_age_days: u64,
    #[serde(rename = "max_rotated_logs")]
    max_rotated_logs: u64,
    #[serde(rename = "homebrew_bin")]
    homebrew_bin: String,
    #[serde(rename = "sudoers_path")]
    sudoers_path: String,
    #[serde(rename = "sudoers_timeout_path")]
    sudoers_timeout_path: String,
    #[serde(rename = "sudo_timeout_hours")]
    sudo_timeout_hours: u64,
}

impl Default for BrewManagerConfig {
    fn default() -> Self {
        Self {
            keychain_service: "BrewAutoUpdate".to_string(),
            askpass_path: "~/Library/Application Support/scriptd/brew-manager/brew_askpass.sh"
                .to_string(),
            legacy_log_dir: "~/Library/Logs/Homebrew".to_string(),
            max_log_size_mb: 50,
            max_log_age_days: 30,
            max_rotated_logs: 5,
            homebrew_bin: "/opt/homebrew/bin/brew".to_string(),
            sudoers_path: "/etc/sudoers.d/homebrew".to_string(),
            sudoers_timeout_path: "/etc/sudoers.d/homebrew_timeout".to_string(),
            sudo_timeout_hours: 2,
        }
    }
}

#[derive(Debug, Default)]
struct BrewState {
    last_run_at: Option<String>,
    last_error: Option<String>,
    last_message: Option<String>,
    repaired_casks: Vec<String>,
}

static STATE: once_cell::sync::Lazy<std::sync::Mutex<BrewState>> =
    once_cell::sync::Lazy::new(|| std::sync::Mutex::new(BrewState::default()));

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
            format!("{}{stderr}", stdout),
            stderr.into_owned(),
            output.status.code().unwrap_or(1),
        ))
    } else {
        let output = command.output()?;
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        Ok((
            format!("{}{stderr}", stdout),
            stderr.into_owned(),
            output.status.code().unwrap_or(1),
        ))
    }
}

fn keychain_password(config: &BrewManagerConfig) -> anyhow::Result<String> {
    let (stdout, _stderr, code) = run_command(
        "security",
        &[
            "find-generic-password",
            "-s",
            &config.keychain_service,
            "-a",
            &std::env::var("USER").unwrap_or_default(),
            "-w",
        ],
        None,
        None,
    )?;
    if code != 0 {
        return Ok(String::new());
    }
    Ok(stdout.trim().to_string())
}

fn verify_password(password: &str) -> bool {
    let (_stdout, _stderr, code) = run_command(
        "sudo",
        &["-S", "-k", "-v"],
        Some(&format!("{password}\n")),
        None,
    )
    .unwrap_or_default();
    code == 0
}

fn cleanup_legacy_logs(config: &BrewManagerConfig, logger: &ModuleLogger) {
    let base = expand_home(&config.legacy_log_dir);
    if !base.exists() {
        return;
    }
    rotate_log(
        base.join("autoupdate.log").as_path(),
        config.max_log_size_mb,
        config.max_rotated_logs,
        logger,
    );
    rotate_log(
        base.join("autoupdate.err").as_path(),
        config.max_log_size_mb,
        config.max_rotated_logs,
        logger,
    );
}

fn rotate_log(path: &std::path::Path, max_size_mb: u64, max_rotated: u64, logger: &ModuleLogger) {
    let metadata = fs::metadata(path).ok();
    let size = metadata.map_or(0, |value| value.len());
    let max_bytes = max_size_mb.saturating_mul(1024).saturating_mul(1024);
    if size <= max_bytes {
        return;
    }
    for index in (1..=max_rotated).rev() {
        let source = format!("{}.{}", path.display(), index);
        let target = format!("{}.{}", path.display(), index + 1);
        let _ = fs::rename(source, target);
    }
    let _ = fs::rename(path, format!("{}.1", path.display()));
    let _ = fs::write(path, "");
    logger.info(&format!("rotated legacy log {}", path.display()));
}

fn write_askpass(config: &BrewManagerConfig, logger: &ModuleLogger) -> anyhow::Result<()> {
    let path = expand_home(&config.askpass_path);
    if path.exists() {
        return Ok(());
    }
    fs::create_dir_all(path.parent().expect("path has parent"))?;
    let mut file = fs::File::create(&path)?;
    let script = format!(
        "#!/bin/bash\nsecurity find-generic-password -s \"{}\" -a \"{}\" -w\n",
        config.keychain_service,
        std::env::var("USER").unwrap_or_default()
    );
    file.write_all(script.as_bytes())?;
    let _ = Command::new("chmod")
        .args(["+x", &path.to_string_lossy()])
        .status();
    logger.info(&format!("wrote askpass helper {}", path.display()));
    Ok(())
}

fn ensure_askpass(config: &BrewManagerConfig, logger: &ModuleLogger) -> anyhow::Result<()> {
    let path = expand_home(&config.askpass_path);
    if path.exists() {
        return Ok(());
    }
    let existing = keychain_password(config)?;
    if existing.is_empty() {
        bail!("brew-manager setup required. run './scriptd.sh setup brew-manager'");
    }
    write_askpass(config, logger)
}

fn configure_sudo(
    config: &BrewManagerConfig,
    password: &str,
    logger: &ModuleLogger,
) -> anyhow::Result<()> {
    let rules = format!(
        "{} ALL=(ALL) NOPASSWD: {} upgrade*, {} cleanup\n",
        std::env::var("USER").unwrap_or_default(),
        config.homebrew_bin,
        config.homebrew_bin
    );
    let timeout = format!(
        "Defaults:{} timestamp_timeout={}\n",
        std::env::var("USER").unwrap_or_default(),
        config.sudo_timeout_hours.saturating_mul(60)
    );

    let rules_path = PathBuf::from(format!(
        "/tmp/brew-manager-rules-{}.tmp",
        std::process::id()
    ));
    let timeout_path = PathBuf::from(format!(
        "/tmp/brew-manager-timeout-{}.tmp",
        std::process::id()
    ));
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

fn command_for_brew(
    config: &BrewManagerConfig,
    args: &[&str],
) -> anyhow::Result<(String, String, i32)> {
    let askpass_path = expand_home(&config.askpass_path);
    let askpass = askpass_path.to_string_lossy().to_string();
    let env = [("SUDO_ASKPASS", askpass.as_str())];
    let command = run_command(&config.homebrew_bin, args, None, Some(&env))
        .context("brew command failed to execute")?;
    Ok(command)
}

fn update_from_config(module_dir: &std::path::Path) -> BrewManagerConfig {
    let path = module_dir.join("module.yaml");
    fs::read_to_string(path)
        .ok()
        .and_then(|text| serde_yaml::from_str::<BrewManagerConfig>(&text).ok())
        .unwrap_or_default()
}

fn brew_maintenance(
    config: &BrewManagerConfig,
    logger: &ModuleLogger,
) -> anyhow::Result<Vec<String>> {
    cleanup_legacy_logs(config, logger);
    ensure_askpass(config, logger)?;
    let (_, _, status) = command_for_brew(config, &["update"])?;
    if status != 0 {
        bail!("brew update failed");
    }

    let (formula_out, _formula_err, _formula_status) =
        command_for_brew(config, &["upgrade", "--formula"])?;
    if !formula_out.trim().is_empty() {
        logger.info(formula_out.trim());
    }
    let (_cask_out, _cask_err, cask_status) = command_for_brew(config, &["upgrade", "--cask"])?;
    if cask_status != 0 {
        let (outdated_out, _outdated_err, _status) =
            command_for_brew(config, &["outdated", "--cask", "--quiet"])?;
        let casks: Vec<String> = outdated_out
            .lines()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToString::to_string)
            .collect();

        let mut repaired = Vec::new();
        if casks.is_empty() {
            let _ = command_for_brew(config, &["upgrade", "--cask", "--force"])?;
        } else {
            for cask in casks.iter() {
                let _ = command_for_brew(config, &["upgrade", "--cask", "--force", cask])?;
                let _ = command_for_brew(config, &["uninstall", "--cask", "--force", cask])?;
                let _ = command_for_brew(config, &["install", "--cask", cask])?;
                repaired.push(cask.clone());
            }
        }
        let _ = command_for_brew(config, &["cleanup"])?;
        return Ok(repaired);
    }

    let _ = command_for_brew(config, &["cleanup"])?;
    Ok(Vec::new())
}

pub fn setup(context: &mut ModuleContext) -> anyhow::Result<()> {
    let config = update_from_config(&context.module_dir);
    let existing = keychain_password(&config).unwrap_or_default();
    if !existing.is_empty() && verify_password(&existing) {
        context
            .logger
            .info("brew-manager setup already provisioned");
        return Ok(());
    }

    if !existing.is_empty() {
        let _ = run_command(
            "security",
            &[
                "delete-generic-password",
                "-s",
                &config.keychain_service,
                "-a",
                &std::env::var("USER").unwrap_or_default(),
            ],
            None,
            None,
        );
    }

    for _ in 0..3 {
        context.logger.warn("Enter your sudo password:");
        let password =
            read_password().map_err(|error| anyhow::anyhow!("failed to read password: {error}"))?;
        if !verify_password(&password) {
            context.logger.warn("Password verification failed");
            continue;
        }

        run_command(
            "security",
            &[
                "add-generic-password",
                "-U",
                "-s",
                &config.keychain_service,
                "-a",
                &std::env::var("USER").unwrap_or_default(),
                "-w",
                &password,
            ],
            None,
            None,
        )?;
        write_askpass(&config, &context.logger)?;
        configure_sudo(&config, &password, &context.logger)?;
        return Ok(());
    }

    bail!("could not verify password after 3 attempts");
}

pub fn run_once(context: &mut ModuleContext) -> anyhow::Result<Option<ModuleStatus>> {
    let config = update_from_config(&context.module_dir);
    let result = brew_maintenance(&config, &context.logger);
    let mut state = STATE.lock().unwrap_or_else(|error| error.into_inner());

    match result {
        Ok(repaired) => {
            state.last_error = None;
            state.last_message = Some(format!(
                "Homebrew maintenance completed (repaired={} casks)",
                repaired.len()
            ));
            state.last_run_at = Some(chrono::Utc::now().to_rfc3339());
            state.repaired_casks = repaired;
            Ok(Some(ModuleStatus {
                state: "running".to_string(),
                message: state.last_message.clone(),
                started_at: None,
                last_run_at: state.last_run_at.clone(),
                next_run_at: None,
                metrics: Some(HashMap::from([(
                    "repaired_casks".to_string(),
                    serde_json::Value::String(state.repaired_casks.join(",")),
                )])),
            }))
        }
        Err(error) => {
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
                metrics: Some(HashMap::from([(
                    "repaired_casks".to_string(),
                    serde_json::Value::String("none".to_string()),
                )])),
            },
            ModuleHealth {
                ok: true,
                message: Some("brew manager ready".to_string()),
            },
        ));
    }

    Some((
        ModuleStatus {
            state: if state.last_error.is_none() {
                "running".to_string()
            } else {
                "error".to_string()
            },
            message: state.last_message.clone(),
            started_at: None,
            last_run_at: state.last_run_at.clone(),
            next_run_at: None,
            metrics: Some(HashMap::from([(
                "repaired_casks".to_string(),
                serde_json::Value::String(state.repaired_casks.join(",")),
            )])),
        },
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

    fn default_config(home: &Path, homebrew_bin: &Path, askpass: &Path) -> BrewManagerConfig {
        BrewManagerConfig {
            homebrew_bin: homebrew_bin.to_string_lossy().to_string(),
            askpass_path: askpass.to_string_lossy().to_string(),
            legacy_log_dir: format!("{}/legacy", home.to_string_lossy()),
            ..BrewManagerConfig::default()
        }
    }

    #[test]
    #[serial_test::serial]
    fn brew_maintenance_performs_cask_fallback_repair() -> anyhow::Result<()> {
        let root = tempdir()?;
        let fake_bin = root.path().join("bin");
        fs::create_dir_all(&fake_bin)?;
        let brew = fake_bin.join("brew");
        let security = fake_bin.join("security");
        let brew_log = root.path().join("brew.log");
        write_script(
            &brew,
            r#"#!/bin/sh
echo "$@" >> "$BREW_TEST_LOG"
if [ "$1" = "update" ]; then
  echo updated
  exit 0
fi

if [ "$1" = "upgrade" ] && [ "$2" = "--formula" ]; then
  echo formula-upgrades
  exit 0
fi

if [ "$1" = "upgrade" ] && [ "$2" = "--cask" ] && [ -z "$3" ]; then
  echo bad cask path
  exit 1
fi

if [ "$1" = "outdated" ] && [ "$2" = "--cask" ] && [ "$3" = "--quiet" ]; then
  echo brew-offending-cask
  exit 0
fi

if [ "$1" = "upgrade" ] && [ "$2" = "--cask" ] && [ "$3" = "--force" ] && [ -n "$4" ]; then
  echo forced
  exit 0
fi

if [ "$1" = "uninstall" ] && [ "$2" = "--cask" ] && [ "$3" = "--force" ] && [ -n "$4" ]; then
  echo removed
  exit 0
fi

if [ "$1" = "install" ] && [ "$2" = "--cask" ] && [ -n "$3" ]; then
  echo installed
  exit 0
fi

if [ "$1" = "cleanup" ]; then
  exit 0
fi

echo unsupported command "$@" >&2
exit 1
"#,
        )?;
        write_script(
            &security,
            "#!/bin/sh\nif [ \"$1\" = \"find-generic-password\" ]; then\necho super-secret\nexit 0\nfi\nexit 0\n",
        )?;
        let config = default_config(root.path(), &brew, &root.path().join("askpass.sh"));

        let previous_log = std::env::var("BREW_TEST_LOG").ok();
        std::env::set_var("BREW_TEST_LOG", &brew_log);
        with_path_scope(&fake_bin, || {
            let logger = ModuleLogger::new(root.path().to_path_buf(), "brew-manager");
            let repaired = brew_maintenance(&config, &logger).expect("maintenance");
            assert_eq!(repaired, vec!["brew-offending-cask".to_string()]);
        });
        if let Some(value) = previous_log {
            std::env::set_var("BREW_TEST_LOG", value);
        } else {
            std::env::remove_var("BREW_TEST_LOG");
        }
        let log = fs::read_to_string(&brew_log)?;
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

        with_path_scope(&fake_bin, || {
            assert!(!askpass.exists());
            ensure_askpass(
                &config,
                &ModuleLogger::new(root.path().to_path_buf(), "brew-manager"),
            )
            .expect("askpass written");
            assert!(askpass.exists());
        });
        let content = fs::read_to_string(&askpass)?;
        assert!(content.contains("security find-generic-password"));
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

        let result = with_path_scope(&fake_bin, || {
            ensure_askpass(
                &config,
                &ModuleLogger::new(root.path().to_path_buf(), "brew-manager"),
            )
        });
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("brew-manager setup required"));
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
