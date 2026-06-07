use serde_json::Value;
use serial_test::serial;
use std::fs;
use std::path::Path;
use std::process::Command as SysCommand;
use std::thread;
use std::time::{Duration, Instant};
use tempfile::tempdir;

fn fake_bin_script(path: &Path, body: &str) -> anyhow::Result<()> {
    fs::write(path, body)?;
    let status = SysCommand::new("chmod")
        .args([
            "+x",
            path.to_str().ok_or_else(|| anyhow::anyhow!("bad path"))?,
        ])
        .status()?;
    assert!(status.success());
    Ok(())
}

fn create_fake_launchctl(
    fake_bin: &Path,
    label: &str,
    state_file: &Path,
    log_file: &Path,
    pid: &str,
) -> anyhow::Result<()> {
    let script = fake_bin.join("launchctl");
    let body = format!(
        r#"#!/bin/sh
LAUNCHCTL_STATE_FILE="{state}"
LAUNCHCTL_LOG_FILE="{log}"
LAUNCHCTL_LABEL="{label}"
LAUNCHCTL_PID="{pid}"

echo "$@" >> "$LAUNCHCTL_LOG_FILE"
case "$1" in
  load)
    mkdir -p "$(dirname \"$LAUNCHCTL_STATE_FILE\")"
    touch "$LAUNCHCTL_STATE_FILE"
    ;;
  unload|remove)
    rm -f "$LAUNCHCTL_STATE_FILE"
    ;;
  enable)
    ;;
  list)
    if [ -f "$LAUNCHCTL_STATE_FILE" ]; then
      echo "$LAUNCHCTL_PID 0 $LAUNCHCTL_LABEL"
    fi
    ;;
  *)
    ;;
esac
"#,
        state = state_file.to_string_lossy(),
        log = log_file.to_string_lossy(),
        label = label,
        pid = pid,
    );

    fake_bin_script(&script, &body)?;

    let id = fake_bin.join("id");
    fake_bin_script(&id, "#!/bin/sh\necho 501\n")?;
    Ok(())
}

fn create_fake_brew_stack(fake_bin: &Path, brew_log: &Path) -> anyhow::Result<()> {
    fake_bin_script(
        &fake_bin.join("brew"),
        &format!(
            r#"#!/bin/sh
echo "$@" >> "{log}"
case "$1 $2 $3" in
  "update  ")
    echo updated
    exit 0
    ;;
  "upgrade --formula ")
    echo formula-upgrades
    exit 0
    ;;
  "upgrade --cask ")
    echo cask-upgrades
    exit 0
    ;;
  "cleanup  ")
    echo cleaned
    exit 0
    ;;
esac
echo unsupported brew "$@" >&2
exit 1
"#,
            log = brew_log.to_string_lossy()
        ),
    )?;
    fake_bin_script(
        &fake_bin.join("security"),
        "#!/bin/sh\nif [ \"$1\" = \"find-generic-password\" ]; then\necho super-secret\nexit 0\nfi\nexit 0\n",
    )?;
    fake_bin_script(&fake_bin.join("sudo"), "#!/bin/sh\nexit 0\n")?;
    Ok(())
}

fn create_fake_wifi_stack(fake_bin: &Path, wifi_log: &Path) -> anyhow::Result<()> {
    let current_file = wifi_log.with_extension("current");
    fake_bin_script(
        &fake_bin.join("networksetup"),
        &format!(
            r#"#!/bin/sh
echo "$@" >> "{log}"
if [ ! -f "{current}" ]; then
  echo "Home" > "{current}"
fi
case "$1" in
  -listallhardwareports)
    echo "Hardware Port: Wi-Fi"
    echo "Device: en0"
    exit 0
    ;;
  -getairportnetwork)
    echo "Current Wi-Fi Network: $(cat "{current}")"
    exit 0
    ;;
  -listpreferredwirelessnetworks)
    echo "Preferred networks on en0:"
    echo "Home"
    echo "Office"
    exit 0
    ;;
  -setairportnetwork)
    echo "$3" > "{current}"
    exit 0
    ;;
esac
exit 1
"#,
            log = wifi_log.to_string_lossy(),
            current = current_file.to_string_lossy()
        ),
    )?;
    fake_bin_script(
        &fake_bin.join("ping"),
        "#!/bin/sh\necho '3 packets transmitted, 3 packets received, 0.0% packet loss'\nexit 0\n",
    )?;
    Ok(())
}

fn create_fake_wifi_stack_requiring_password(
    fake_bin: &Path,
    wifi_log: &Path,
) -> anyhow::Result<()> {
    let current_file = wifi_log.with_extension("current");
    fake_bin_script(
        &fake_bin.join("networksetup"),
        &format!(
            r#"#!/bin/sh
echo "$@" >> "{log}"
if [ ! -f "{current}" ]; then
  echo "Home" > "{current}"
fi
case "$1" in
  -listallhardwareports)
    echo "Hardware Port: Wi-Fi"
    echo "Device: en0"
    exit 0
    ;;
  -getairportnetwork)
    echo "Current Wi-Fi Network: $(cat "{current}")"
    exit 0
    ;;
  -listpreferredwirelessnetworks)
    echo "Preferred networks on en0:"
    echo "Home"
    echo "Office"
    exit 0
    ;;
  -setairportnetwork)
    if [ "${{4-}}" = "office-password" ]; then
      echo "$3" > "{current}"
      exit 0
    fi
    echo "Failed to join network $3."
    echo "Error: -3900  The operation couldn't be completed. tmpErr"
    exit 0
    ;;
esac
exit 1
"#,
            log = wifi_log.to_string_lossy(),
            current = current_file.to_string_lossy()
        ),
    )?;
    fake_bin_script(
        &fake_bin.join("ping"),
        "#!/bin/sh\necho '3 packets transmitted, 3 packets received, 0.0% packet loss'\nexit 0\n",
    )?;
    Ok(())
}

fn write_modules(root: &Path) {
    for module in ["mbrew", "mcpu", "mwifi"] {
        let module_dir = root.join("modules").join(module);
        fs::create_dir_all(&module_dir).expect("create module dir");
        fs::write(
            module_dir.join("module.yaml"),
            format!("id: {module}\nmode: interval\ninterval_seconds: 30\n"),
        )
        .expect("write module manifest");
    }
}

fn write_brew_module(root: &Path, homebrew_bin: &Path, askpass_path: &Path) {
    let module_dir = root.join("modules").join("mbrew");
    fs::create_dir_all(&module_dir).expect("create brew module dir");
    fs::write(
        module_dir.join("module.yaml"),
        format!(
            "id: mbrew\nmode: interval\ninterval_seconds: 30\nkeychain_service: BrewAutoUpdate\naskpass_path: {}\nlegacy_log_dir: {}/legacy\nmax_log_size_mb: 50\nmax_log_age_days: 30\nmax_rotated_logs: 5\nhomebrew_bin: {}\nsudoers_path: {}/sudoers-homebrew\nsudoers_timeout_path: {}/sudoers-timeout\nsudo_timeout_hours: 2\n",
            askpass_path.to_string_lossy(),
            root.to_string_lossy(),
            homebrew_bin.to_string_lossy(),
            root.to_string_lossy(),
            root.to_string_lossy()
        ),
    )
    .expect("write brew module yaml");
}

fn write_wifi_module(root: &Path, state_file: &Path) {
    let module_dir = root.join("modules").join("mwifi");
    fs::create_dir_all(&module_dir).expect("create wifi module dir");
    fs::write(
        module_dir.join("module.yaml"),
        format!(
            "id: mwifi\nmode: interval\ninterval_seconds: 30\nmin_dwell: 1\nping_target: 1.1.1.1\nping_count: 3\nping_timeout: 1\nping_high_latency_ms: 250\nhealth_failure_switch_runs: 2\nband_bonus_2g: 0\nband_bonus_5g: 35\nband_bonus_6g: 50\npreference_top_bonus: 30\npreference_rank_decay: 5\ncurrent_sticky_bonus: 25\nrssi_offset: 100\nmin_switch_score_delta: 10\nssids:\n  - Home\n  - Office\nstate_file: {}\nconfig_path: {}\n",
            state_file.to_string_lossy(),
            module_dir.join("module.yaml").to_string_lossy()
        ),
    )
    .expect("write wifi module yaml");
}

fn write_service_yaml(
    root: &Path,
    watch: bool,
    brew_enabled: bool,
    cpu_enabled: bool,
    wifi_enabled: bool,
) {
    fs::create_dir_all(root).unwrap();
    fs::write(
        root.join("service.yaml"),
        format!(
            "label: com.omar.scriptd\nlog_dir: ~/Library/Logs/scriptd\nwatch: {}\nmodules:\n  mbrew:\n    enabled: {}\n  mcpu:\n    enabled: {}\n  mwifi:\n    enabled: {}\n",
            watch,
            brew_enabled,
            cpu_enabled,
            wifi_enabled
        ),
    )
    .unwrap();
}

fn test_credentials_file(home: &Path) -> std::path::PathBuf {
    home.join("scriptd-test-credentials.json")
}

fn write_test_admin_credential(home: &Path, password: &str) {
    let user = std::env::var("USER").unwrap_or_default();
    let mut values = serde_json::Map::new();
    values.insert(
        format!("ScriptdAdmin\n{user}"),
        Value::String(password.to_string()),
    );
    values.insert(
        format!("BrewAutoUpdate\n{user}"),
        Value::String(password.to_string()),
    );
    fs::write(
        test_credentials_file(home),
        serde_json::to_string_pretty(&Value::Object(values)).unwrap(),
    )
    .unwrap();
}

fn run_scriptd(root: &Path, home: &Path, fake_bin: &Path) -> SysCommand {
    let mut cmd = SysCommand::new(env!("CARGO_BIN_EXE_scriptd"));
    let original_path = std::env::var("PATH").unwrap_or_default();
    cmd.env("SCRIPTD_ROOT_DIR", root)
        .env("HOME", home)
        .env(
            "PATH",
            format!("{}:{}", fake_bin.to_string_lossy(), original_path),
        )
        .env("SCRIPTD_CREDENTIALS_FILE", test_credentials_file(home))
        .env("SCRIPTD_ENTRY_SHELL_PATH", root.join("scriptd.sh"));
    cmd
}

#[test]
#[serial]
fn integration_status_is_unreadable_without_state() {
    let root = tempdir().unwrap();
    let home = tempdir().unwrap();
    write_modules(root.path());
    write_service_yaml(root.path(), true, false, false, false);

    let mut cmd = run_scriptd(root.path(), home.path(), root.path());
    let output = cmd.arg("status").output().unwrap();
    assert!(output.status.success());
    let output = String::from_utf8_lossy(&output.stdout);
    assert!(output.contains("state: unreadable"));
}

#[test]
#[serial]
fn integration_status_detects_stale_supervisor_snapshot() {
    let root = tempdir().unwrap();
    let home = tempdir().unwrap();
    let fake_bin = root.path().join("fake_bin");
    fs::create_dir_all(&fake_bin).unwrap();
    let launchctl_state = home.path().join("launchctl-loaded");
    let launchctl_log = home.path().join("launchctl.log");
    create_fake_launchctl(
        &fake_bin,
        "com.omar.scriptd",
        &launchctl_state,
        &launchctl_log,
        "222",
    )
    .unwrap();

    write_modules(root.path());
    write_service_yaml(root.path(), false, true, false, false);

    fs::create_dir_all(home.path().join("Library/Application Support/scriptd")).unwrap();
    fs::write(
        home.path()
            .join("Library/Application Support/scriptd/state.json"),
        format!(
            r#"{{
  "label":"com.omar.scriptd",
  "rootDir":"{}",
  "configPath":"{}",
  "logDir":"/tmp/scriptd-logs",
  "updatedAt":"2020-01-01T00:00:00Z",
  "supervisor":{{"pid":111,"startedAt":"2020-01-01T00:00:00Z","watch":true}},
  "modules":{{}}
}}
"#,
            root.path().to_string_lossy(),
            root.path().join("service.yaml").to_string_lossy()
        ),
    )
    .unwrap();

    let mut cmd = run_scriptd(root.path(), home.path(), &fake_bin);
    let output = cmd.arg("status").output().unwrap();
    assert!(output.status.success());
    let output = String::from_utf8_lossy(&output.stdout);
    assert!(output.contains("state: stale snapshot"));
}

#[test]
#[serial]
fn integration_start_stop_uninstall_root_commands() {
    let root = tempdir().unwrap();
    let home = tempdir().unwrap();
    let fake_bin = root.path().join("fake_bin");
    fs::create_dir_all(&fake_bin).unwrap();
    let launchctl_state = home.path().join("launchctl-loaded");
    let launchctl_log = home.path().join("launchctl.log");
    create_fake_launchctl(
        &fake_bin,
        "com.omar.scriptd",
        &launchctl_state,
        &launchctl_log,
        "777",
    )
    .unwrap();

    write_modules(root.path());
    write_service_yaml(root.path(), false, true, false, false);

    let launch_agents = home
        .path()
        .join("Library/LaunchAgents/com.omar.scriptd.plist");
    let app_executable = home
        .path()
        .join("Library/Application Support/scriptd/Scriptd.app/Contents/MacOS/scriptd");

    let start = run_scriptd(root.path(), home.path(), &fake_bin)
        .arg("start")
        .arg("root")
        .status()
        .unwrap();
    assert!(start.success());

    assert!(launch_agents.exists());
    assert!(app_executable.exists());
    let wrapper = fs::read_to_string(&app_executable).unwrap();
    assert!(wrapper.contains("SCRIPTD_ROOT_DIR"));
    assert!(wrapper.contains(root.path().to_string_lossy().as_ref()));
    assert!(wrapper.contains("exec"));

    let log = fs::read_to_string(&launchctl_log).unwrap_or_default();
    assert!(log.contains("load"));

    let stop = run_scriptd(root.path(), home.path(), &fake_bin)
        .arg("stop")
        .arg("root")
        .status()
        .unwrap();
    assert!(stop.success());
    assert!(!launchctl_state.exists());

    let uninstall = run_scriptd(root.path(), home.path(), &fake_bin)
        .arg("uninstall")
        .arg("root")
        .status()
        .unwrap();
    assert!(uninstall.success());
    assert!(!launch_agents.exists());
    assert!(!app_executable.parent().unwrap().exists());
}

#[test]
#[serial]
fn integration_run_root_rejects_invalid_module() {
    let root = tempdir().unwrap();
    let home = tempdir().unwrap();
    write_modules(root.path());
    write_service_yaml(root.path(), false, false, false, false);

    let output = run_scriptd(root.path(), home.path(), root.path())
        .arg("run")
        .arg("totally-unknown-module")
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("not compiled into this build"),);
}

#[test]
#[serial]
fn integration_run_mbrew_uses_fake_brew_security_and_sudo_boundary() {
    let root = tempdir().unwrap();
    let home = tempdir().unwrap();
    let fake_bin = root.path().join("fake_bin");
    fs::create_dir_all(&fake_bin).unwrap();
    let brew_log = root.path().join("brew.log");
    create_fake_brew_stack(&fake_bin, &brew_log).unwrap();
    write_test_admin_credential(home.path(), "super-secret");
    write_modules(root.path());
    write_brew_module(
        root.path(),
        &fake_bin.join("brew"),
        &root.path().join("brew_askpass.sh"),
    );
    write_service_yaml(root.path(), false, true, false, false);

    let output = run_scriptd(root.path(), home.path(), &fake_bin)
        .arg("run")
        .arg("mbrew")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let log = fs::read_to_string(&brew_log).unwrap();
    assert!(log.contains("update"));
    assert!(log.contains("upgrade --formula"));
    assert!(log.contains("upgrade --cask"));
    assert!(log.contains("cleanup"));
    assert!(root.path().join("brew_askpass.sh").exists());
}

#[test]
#[serial]
fn integration_run_mwifi_uses_fake_networksetup_and_ping_boundary() {
    let root = tempdir().unwrap();
    let home = tempdir().unwrap();
    let fake_bin = root.path().join("fake_bin");
    fs::create_dir_all(&fake_bin).unwrap();
    let wifi_log = root.path().join("wifi.log");
    let wifi_state = root.path().join("mwifi-state.json");
    create_fake_wifi_stack(&fake_bin, &wifi_log).unwrap();
    write_modules(root.path());
    write_wifi_module(root.path(), &wifi_state);
    write_service_yaml(root.path(), false, false, false, true);

    let scan_output = "SSID BSSID RSSI CHANNEL SECURITY\nHome 00:11:22:33:44:55 -90 1 WPA2\nOffice 00:11:22:33:44:66 -20 233 WPA3\n";
    let output = run_scriptd(root.path(), home.path(), &fake_bin)
        .env("SCRIPTD_MWIFI_SCAN_OUTPUT", scan_output)
        .arg("run")
        .arg("mwifi")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let log = fs::read_to_string(&wifi_log).unwrap();
    assert!(log.contains("-listallhardwareports"));
    assert!(log.contains("-getairportnetwork en0"));
    assert!(log.contains("-listpreferredwirelessnetworks en0"));
    assert!(log.contains("-setairportnetwork en0 Office"));

    let state_text = fs::read_to_string(&wifi_state).unwrap();
    let state: Value = serde_json::from_str(&state_text).unwrap();
    assert_eq!(
        state.get("lastSsid").and_then(Value::as_str),
        Some("Office")
    );
}

#[test]
#[serial]
fn integration_run_mwifi_retries_with_password_after_unobserved_zero_exit_join() {
    let root = tempdir().unwrap();
    let home = tempdir().unwrap();
    let fake_bin = root.path().join("fake_bin");
    fs::create_dir_all(&fake_bin).unwrap();
    let wifi_log = root.path().join("mwifi-password.log");
    let wifi_state = root.path().join("mwifi-password-state.json");
    create_fake_wifi_stack_requiring_password(&fake_bin, &wifi_log).unwrap();
    write_modules(root.path());
    write_wifi_module(root.path(), &wifi_state);
    write_service_yaml(root.path(), false, false, false, true);

    let scan_output = "SSID BSSID RSSI CHANNEL SECURITY\nHome 00:11:22:33:44:55 -90 1 WPA2\nOffice 00:11:22:33:44:66 -20 233 WPA3\n";
    let output = run_scriptd(root.path(), home.path(), &fake_bin)
        .env("SCRIPTD_MWIFI_SCAN_OUTPUT", scan_output)
        .env("MWIFI_PASSWORD_OFFICE", "office-password")
        .arg("run")
        .arg("mwifi")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let log = fs::read_to_string(&wifi_log).unwrap();
    assert!(log.contains("-setairportnetwork en0 Office\n"));
    assert!(log.contains("-setairportnetwork en0 Office office-password\n"));

    let state_text = fs::read_to_string(&wifi_state).unwrap();
    let state: Value = serde_json::from_str(&state_text).unwrap();
    assert_eq!(
        state.get("lastSsid").and_then(Value::as_str),
        Some("Office")
    );
}

#[test]
#[serial]
fn integration_run_root_preserves_desired_state_on_shutdown() {
    let root = tempdir().unwrap();
    let home = tempdir().unwrap();
    write_modules(root.path());
    write_service_yaml(root.path(), false, true, false, false);

    let mut cmd = run_scriptd(root.path(), home.path(), root.path());
    cmd.arg("run").arg("root");
    let mut child = cmd.spawn().expect("run root");

    let state_file = home
        .path()
        .join("Library/Application Support/scriptd/state.json");
    let state_deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < state_deadline {
        if state_file.exists() {
            break;
        }
        thread::sleep(Duration::from_millis(50));
    }

    let pid = child.id();
    let _ = SysCommand::new("kill")
        .args(["-TERM", &pid.to_string()])
        .status();

    let mut exited = false;
    let timeout = Instant::now() + Duration::from_secs(5);
    while Instant::now() < timeout {
        if let Ok(Some(_)) = child.try_wait() {
            exited = true;
            break;
        }
        thread::sleep(Duration::from_millis(50));
    }
    if !exited {
        let _ = SysCommand::new("kill")
            .args(["-TERM", &pid.to_string()])
            .status();
    }
    let _ = child.wait();

    assert!(exited);

    let state_text = fs::read_to_string(&state_file).expect("state file");
    let parsed: Value = serde_json::from_str(&state_text).unwrap();
    let modules = parsed.get("modules").and_then(Value::as_object).unwrap();
    let brew = modules.get("mbrew").and_then(Value::as_object).unwrap();
    assert_eq!(
        brew.get("desiredEnabled").and_then(Value::as_bool),
        Some(true)
    );
}

#[test]
#[serial]
fn integration_run_root_reloads_service_yaml_changes() {
    let root = tempdir().unwrap();
    let home = tempdir().unwrap();
    write_modules(root.path());
    write_service_yaml(root.path(), true, false, false, false);

    let mut cmd = run_scriptd(root.path(), home.path(), root.path());
    cmd.arg("run").arg("root");
    let mut child = cmd.spawn().expect("run root");

    thread::sleep(Duration::from_millis(700));

    write_service_yaml(root.path(), true, true, false, false);

    let state_file = home
        .path()
        .join("Library/Application Support/scriptd/state.json");

    let mut observed = false;
    let deadline = Instant::now() + Duration::from_secs(6);
    while Instant::now() < deadline {
        if let Ok(state_text) = fs::read_to_string(&state_file) {
            if let Ok(parsed) = serde_json::from_str::<Value>(&state_text) {
                if let Some(modules) = parsed.get("modules").and_then(Value::as_object) {
                    if let Some(entry) = modules.get("mbrew").and_then(Value::as_object) {
                        if entry.get("desiredEnabled").and_then(Value::as_bool) == Some(true) {
                            observed = true;
                            break;
                        }
                    }
                }
            }
        }
        thread::sleep(Duration::from_millis(150));
    }

    let pid = child.id();
    let _ = SysCommand::new("kill")
        .args(["-TERM", &pid.to_string()])
        .status();
    let _ = child.wait();

    assert!(
        observed,
        "module desire should reload from service.yaml while running"
    );
}
