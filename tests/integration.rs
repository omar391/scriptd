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
    for module in ["mbrew", "mcpu", "mwifi", "miwatch"] {
        let module_dir = root.join("modules").join(module);
        fs::create_dir_all(&module_dir).expect("create module dir");
        let source = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("modules")
            .join(module)
            .join("module.yaml");
        fs::copy(source, module_dir.join("module.yaml")).expect("write module manifest");
    }
}

fn write_brew_module(root: &Path, homebrew_bin: &Path, askpass_path: &Path) {
    let module_dir = root.join("modules").join("mbrew");
    fs::create_dir_all(&module_dir).expect("create brew module dir");
    fs::write(
        module_dir.join("module.yaml"),
        format!(
            "version: 1\nmodule:\n  id: mbrew\n  display_name: Brew Manager\n  mode: task\nsettings:\n  askpass_path: {}\n  homebrew_bin: {}\n  sudoers_path: {}/sudoers-homebrew\n  sudoers_timeout_path: {}/sudoers-timeout\n  sudo_timeout_hours: 2\n",
            askpass_path.to_string_lossy(),
            homebrew_bin.to_string_lossy(),
            root.to_string_lossy(),
            root.to_string_lossy()
        ),
    )
    .expect("write brew module yaml");
}

fn write_wifi_module(root: &Path, state_file: &Path) {
    write_wifi_module_with_repeater_rules(root, state_file, "repeater_rules: []\n");
}

fn write_wifi_module_with_repeater_rules(
    root: &Path,
    state_file: &Path,
    repeater_rules_yaml: &str,
) {
    let module_dir = root.join("modules").join("mwifi");
    fs::create_dir_all(&module_dir).expect("create wifi module dir");
    fs::write(
        module_dir.join("module.yaml"),
        format!(
            "version: 1\nmodule:\n  id: mwifi\n  display_name: Wi-Fi Monitor\n  mode: task\nsettings:\n  min_dwell: 1\n  ping_target: 1.1.1.1\n  ping_count: 3\n  ping_timeout: 1\n  ping_high_latency_ms: 250\n  health_failure_switch_runs: 2\n  band_bonus_2g: 0\n  band_bonus_5g: 35\n  band_bonus_6g: 50\n  preference_top_bonus: 30\n  preference_rank_decay: 5\n  current_sticky_bonus: 25\n  rssi_offset: 100\n  min_switch_score_delta: 10\n  ssids:\n    - Home\n    - Office\n  {}  state_file: {}\n",
            repeater_rules_yaml,
            state_file.to_string_lossy()
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
            "version: 1\nservice:\n  label: com.omar.scriptd\n  log_dir: ~/Library/Logs/scriptd\n  watch: {}\nmodules:\n  mbrew:\n    enabled: {}\n    triggers:\n      maintenance:\n        fire: {{ mode: every_match }}\n        when: {{ schedule: {{ every_hours: 1 }} }}\n  mcpu:\n    enabled: {}\n    triggers:\n      sample:\n        fire: {{ mode: every_match }}\n        when: {{ schedule: {{ every_hours: 1 }} }}\n  mwifi:\n    enabled: {}\n    triggers:\n      sample:\n        fire: {{ mode: every_match }}\n        when: {{ schedule: {{ every_hours: 1 }} }}\n  miwatch:\n    enabled: false\n",
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
  "modules":{{}},
  "triggers":{{
    "mbrew.maintenance":{{
      "target":"mbrew",
      "enabled":true,
      "nextWakeAt":"2026-07-30T12:00:00Z",
      "runtime":{{
        "phase":"matching",
        "match_count":2,
        "last_evaluated_at":"2026-07-30T00:00:00Z"
      }}
    }}
  }}
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
    assert!(output.contains("Triggers:"));
    assert!(output.contains("mbrew.maintenance: target=mbrew"));
    assert!(output.contains("matches=2"));
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
fn integration_run_root_rejects_unknown_trigger_target() {
    let root = tempdir().unwrap();
    let home = tempdir().unwrap();
    write_modules(root.path());
    fs::write(
        root.path().join("service.yaml"),
        "version: 1\nservice: { label: com.omar.scriptd, log_dir: ~/Library/Logs/scriptd }\nmodules:\n  missing:\n    enabled: true\n",
    )
    .unwrap();
    let output = run_scriptd(root.path(), home.path(), root.path())
        .arg("run")
        .arg("root")
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("unknown field"));
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
fn integration_run_mwifi_does_not_attempt_repeater_without_parent() {
    let root = tempdir().unwrap();
    let home = tempdir().unwrap();
    let fake_bin = root.path().join("fake_bin");
    fs::create_dir_all(&fake_bin).unwrap();
    let wifi_log = root.path().join("wifi.log");
    let wifi_state = root.path().join("mwifi-state.json");
    create_fake_wifi_stack(&fake_bin, &wifi_log).unwrap();
    fs::write(wifi_log.with_extension("current"), "Office\n").unwrap();
    write_modules(root.path());
    write_wifi_module_with_repeater_rules(
        root.path(),
        &wifi_state,
        "repeater_rules:\n  - pattern: '^Home-EXT$'\n    parent_ssid: Home\n",
    );
    write_service_yaml(root.path(), false, false, false, true);

    let scan_output = "SSID BSSID RSSI CHANNEL SECURITY\nHome-EXT 00:11:22:33:44:55 -20 233 WPA3\nOffice 00:11:22:33:44:66 -90 1 WPA2\n";
    let output = run_scriptd(root.path(), home.path(), &fake_bin)
        .env("SCRIPTD_MWIFI_SCAN_OUTPUT", scan_output)
        .env("MWIFI_SSIDS", "Office,Home-EXT")
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
    assert!(!log.contains("-setairportnetwork en0 Home-EXT"));
    assert!(!log.contains("-setairportnetwork en0 Office"));
}

#[test]
#[serial]
fn integration_run_mwifi_scans_parent_outside_candidate_allowlist_and_allows_repeater() {
    let root = tempdir().unwrap();
    let home = tempdir().unwrap();
    let fake_bin = root.path().join("fake_bin");
    fs::create_dir_all(&fake_bin).unwrap();
    let wifi_log = root.path().join("wifi.log");
    let wifi_state = root.path().join("mwifi-state.json");
    create_fake_wifi_stack(&fake_bin, &wifi_log).unwrap();
    fs::write(wifi_log.with_extension("current"), "Office\n").unwrap();
    write_modules(root.path());
    write_wifi_module_with_repeater_rules(
        root.path(),
        &wifi_state,
        "repeater_rules:\n  - pattern: '^Home-EXT$'\n    parent_ssid: Home\n",
    );
    write_service_yaml(root.path(), false, false, false, true);

    let scan_output = "SSID BSSID RSSI CHANNEL SECURITY\nHome 00:11:22:33:44:55 -80 1 WPA2\nHome-EXT 00:11:22:33:44:66 -20 233 WPA3\nOffice 00:11:22:33:44:77 -90 1 WPA2\n";
    let output = run_scriptd(root.path(), home.path(), &fake_bin)
        .env("SCRIPTD_MWIFI_SCAN_OUTPUT", scan_output)
        .env("MWIFI_SSIDS", "Office,Home-EXT")
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
    assert!(log.contains("-setairportnetwork en0 Home-EXT"));
    let state_text = fs::read_to_string(&wifi_state).unwrap();
    let state: Value = serde_json::from_str(&state_text).unwrap();
    assert_eq!(
        state.get("lastSsid").and_then(Value::as_str),
        Some("Home-EXT")
    );
}

#[test]
#[serial]
fn integration_run_mwifi_rejects_invalid_repeater_configuration() {
    let root = tempdir().unwrap();
    let home = tempdir().unwrap();
    let fake_bin = root.path().join("fake_bin");
    fs::create_dir_all(&fake_bin).unwrap();
    let wifi_log = root.path().join("wifi.log");
    let wifi_state = root.path().join("mwifi-state.json");
    create_fake_wifi_stack(&fake_bin, &wifi_log).unwrap();
    write_modules(root.path());
    write_wifi_module_with_repeater_rules(
        root.path(),
        &wifi_state,
        "repeater_rules:\n  - pattern: '['\n    parent_ssid: Home\n",
    );
    write_service_yaml(root.path(), false, false, false, true);

    let output = run_scriptd(root.path(), home.path(), &fake_bin)
        .arg("run")
        .arg("mwifi")
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("invalid mwifi repeater_rules[0] pattern"),
        "{stderr}"
    );
}

#[test]
#[serial]
fn integration_run_one_module_does_not_overwrite_supervisor_state() {
    let root = tempdir().unwrap();
    let home = tempdir().unwrap();
    let fake_bin = root.path().join("fake_bin");
    fs::create_dir_all(&fake_bin).unwrap();
    let wifi_log = root.path().join("wifi.log");
    let wifi_state = root.path().join("mwifi-state.json");
    create_fake_wifi_stack(&fake_bin, &wifi_log).unwrap();
    write_modules(root.path());
    write_wifi_module(root.path(), &wifi_state);
    write_service_yaml(root.path(), false, true, false, true);

    let state_file = home
        .path()
        .join("Library/Application Support/scriptd/state.json");
    fs::create_dir_all(state_file.parent().unwrap()).unwrap();
    fs::write(
        &state_file,
        format!(
            r#"{{
  "label":"com.omar.scriptd",
  "rootDir":"{}",
  "configPath":"{}",
  "logDir":"/tmp/scriptd-logs",
  "updatedAt":"2026-06-08T00:00:00Z",
  "supervisor":{{"pid":111,"startedAt":"2026-06-08T00:00:00Z","watch":true}},
  "modules":{{
    "mbrew":{{"desiredEnabled":true,"status":"scheduled","mode":"interval","lastStartedAt":null,"lastRunAt":null,"lastExitAt":null,"nextRunAt":"2026-06-08T12:00:00Z","runs":7,"restarts":0,"message":"next run at 2026-06-08T12:00:00Z","health":null,"moduleStatus":null,"lastError":null}},
    "mwifi":{{"desiredEnabled":true,"status":"scheduled","mode":"interval","lastStartedAt":null,"lastRunAt":null,"lastExitAt":null,"nextRunAt":"2026-06-08T00:05:00Z","runs":3,"restarts":0,"message":"next run at 2026-06-08T00:05:00Z","health":null,"moduleStatus":null,"lastError":null}}
  }}
}}
"#,
            root.path().to_string_lossy(),
            root.path().join("service.yaml").to_string_lossy()
        ),
    )
    .unwrap();
    let before = fs::read_to_string(&state_file).unwrap();

    let scan_output =
        "SSID BSSID RSSI CHANNEL SECURITY\nHome 00:11:22:33:44:55 -90 1 WPA2\nOffice 00:11:22:33:44:66 -20 233 WPA3\n";
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

    let after = fs::read_to_string(&state_file).unwrap();
    assert_eq!(after, before);
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

#[test]
#[serial]
fn integration_invalid_trigger_reload_keeps_last_valid_runtime() {
    let root = tempdir().unwrap();
    let home = tempdir().unwrap();
    write_modules(root.path());
    write_service_yaml(root.path(), true, false, false, false);

    let mut cmd = run_scriptd(root.path(), home.path(), root.path());
    cmd.arg("run").arg("root");
    let mut child = cmd.spawn().expect("run root");
    let state_file = home
        .path()
        .join("Library/Application Support/scriptd/state.json");
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline && !state_file.exists() {
        thread::sleep(Duration::from_millis(50));
    }
    assert!(state_file.exists(), "initial state should be persisted");

    fs::write(
        root.path().join("service.yaml"),
        "version: 1\nservice: { label: com.omar.scriptd, log_dir: ~/Library/Logs/scriptd, watch: true }\nmodules:\n  mbrew:\n    enabled: false\n    triggers:\n      broken:\n        fire: { mode: every_match }\n        when: { all: [] }\n",
    )
    .unwrap();
    thread::sleep(Duration::from_secs(1));

    assert!(
        child.try_wait().unwrap().is_none(),
        "supervisor must stay alive"
    );
    let state: Value = serde_json::from_str(&fs::read_to_string(&state_file).unwrap()).unwrap();
    let triggers = state
        .get("triggers")
        .and_then(Value::as_object)
        .expect("persisted triggers");
    assert!(triggers.contains_key("mbrew.maintenance"));
    assert!(!triggers.contains_key("broken"));

    let _ = SysCommand::new("kill")
        .args(["-TERM", &child.id().to_string()])
        .status();
    let _ = child.wait();
}

#[test]
fn integration_repository_configuration_migrates_all_modules_to_global_triggers() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let service: serde_yaml::Value =
        serde_yaml::from_str(&fs::read_to_string(root.join("service.yaml")).unwrap()).unwrap();
    let modules = service
        .get("modules")
        .and_then(serde_yaml::Value::as_mapping)
        .expect("modules");
    for id in ["mbrew", "mcpu", "mwifi", "miwatch"] {
        assert!(
            modules.contains_key(serde_yaml::Value::String(id.to_string())),
            "missing module {id}"
        );
    }
    let brew = &service["modules"]["mbrew"]["triggers"]["maintenance"];
    let cpu = &service["modules"]["mcpu"]["triggers"]["sample"];
    let wifi = &service["modules"]["mwifi"]["triggers"]["sample"];
    let watchdog = &service["modules"]["miwatch"]["triggers"]["outage"];
    assert_eq!(
        brew["when"]["schedule"]["daily_at"].as_str(),
        Some("00:00")
    );
    assert_eq!(
        brew["when"]["schedule"]["timezone"].as_str(),
        Some("Asia/Dhaka")
    );
    assert_eq!(cpu["when"]["schedule"]["every_minutes"].as_u64(), Some(1));
    assert_eq!(
        wifi["when"]["schedule"]["every_minutes"].as_u64(),
        Some(5)
    );
    assert_eq!(
        watchdog["when"]["all"][0]["schedule"]["every_seconds"].as_u64(),
        Some(30)
    );
    assert_eq!(
        watchdog["when"]["all"][1]["wifi_ssid"]["state"].as_str(),
        Some("unavailable")
    );
    assert_eq!(
        watchdog["when"]["all"][2]["any"][0]["time_window"]["start"].as_str(),
        Some("05:00")
    );
    assert_eq!(
        watchdog["when"]["all"][2]["any"][1]["process_network"]["applications"][0].as_str(),
        Some("Codex")
    );
    assert_eq!(
        watchdog["when"]["all"][2]["any"][1]["process_network"]["at_least_bytes_per_second"]
            .as_u64(),
        Some(1024)
    );
    assert_eq!(
        watchdog["fire"]["after"]["consecutive_matches"].as_u64(),
        Some(3)
    );
    assert_eq!(
        watchdog["fire"]["reset"]["after"]["consecutive_matches"].as_u64(),
        Some(2)
    );
    assert_eq!(
        watchdog["fire"]["reset"]["when"]["wifi_ssid"]["state"].as_str(),
        Some("available")
    );
    for entry in modules.values() {
        assert!(entry.get("settings").is_none());
    }
    for module in ["mbrew", "mcpu", "mwifi", "miwatch"] {
        let manifest: serde_yaml::Value = serde_yaml::from_str(
            &fs::read_to_string(root.join("modules").join(module).join("module.yaml")).unwrap(),
        )
        .unwrap();
        assert_eq!(
            manifest["module"]
                .get("mode")
                .and_then(serde_yaml::Value::as_str),
            Some("task")
        );
        assert!(manifest.get("interval_seconds").is_none());
    }
}
