use std::fmt::Write;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::Result;

use crate::config::ServiceConfig;
use crate::paths::{resolve_launch_agents_dir, resolve_launchd_plist_path, resolve_state_dir};

fn plist_contents(label: &str, executable: &str) -> String {
    let mut buffer = String::new();
    let _ = writeln!(
        buffer,
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>{label}</string>
  <key>ProgramArguments</key>
  <array>
    <string>{executable}</string>
    <string>run</string>
    <string>root</string>
  </array>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
  <key>ProcessType</key>
  <string>Standard</string>
  <key>StandardOutPath</key>
  <string>{out}</string>
  <key>StandardErrorPath</key>
  <string>{err}</string>
  <key>EnvironmentVariables</key>
  <dict>
    <key>PATH</key>
    <string>/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin</string>
  </dict>
</dict>
</plist>"#,
        label = label,
        executable = executable,
        out = resolve_state_dir().join("scriptd.log").to_string_lossy(),
        err = resolve_state_dir().join("scriptd.err").to_string_lossy(),
    );
    buffer
}

fn app_info_plist(label: &str) -> String {
    let mut buffer = String::new();
    let _ = writeln!(
        buffer,
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleDisplayName</key>
  <string>scriptd</string>
  <key>CFBundleExecutable</key>
  <string>scriptd</string>
  <key>CFBundleIconFile</key>
  <string>Scriptd</string>
  <key>CFBundleIconName</key>
  <string>Scriptd</string>
  <key>CFBundleIdentifier</key>
  <string>{label}</string>
  <key>CFBundleName</key>
  <string>scriptd</string>
  <key>CFBundlePackageType</key>
  <string>APPL</string>
  <key>LSBackgroundOnly</key>
  <true/>
</dict>
</plist>"#,
        label = label,
    );
    buffer
}

fn launchd_domain_label(label: &str) -> String {
    let output = Command::new("id").args(["-u"]).output();
    if let Ok(value) = output {
        let uid = String::from_utf8_lossy(&value.stdout).trim().to_string();
        if !uid.is_empty() {
            return format!("gui/{uid}/{label}");
        }
    }
    format!("gui/{label}")
}

fn resolve_state_app_root() -> PathBuf {
    resolve_state_dir().join("Scriptd.app")
}

fn write_scriptd_wrapper(binary_path: &Path, config: &ServiceConfig) -> Result<PathBuf> {
    let app_root = resolve_state_app_root();
    let exec_path = app_root.join("Contents").join("MacOS").join("scriptd");
    fs::create_dir_all(app_root.join("Contents").join("MacOS"))?;
    fs::create_dir_all(app_root.join("Contents").join("Resources"))?;

    let info_path = app_root.join("Contents").join("Info.plist");
    fs::write(&info_path, app_info_plist(&config.label))?;

    let icon_src = Path::new(env!("CARGO_MANIFEST_DIR")).join("assets/Scriptd.icns");
    let icon_dest = app_root
        .join("Contents")
        .join("Resources")
        .join("Scriptd.icns");
    if icon_src.exists() {
        let _ = fs::copy(icon_src, icon_dest)?;
    }

    let script = format!(
        "#!/bin/sh\nexport SCRIPTD_ROOT_DIR=\"{}\"\nexport SCRIPTD_ENTRY_SHELL_PATH=\"{}/scriptd.sh\"\nexec \"{}\" \"$@\"\n",
        config.root_dir.to_string_lossy(),
        config.root_dir.to_string_lossy(),
        binary_path.to_string_lossy(),
    );
    fs::write(&exec_path, script)?;
    let _ = Command::new("chmod")
        .args(["+x", exec_path.to_str().expect("path")])
        .status();
    Ok(exec_path)
}

pub fn write_root_plist(executable: &Path, config: &ServiceConfig) -> Result<PathBuf> {
    fs::create_dir_all(resolve_state_dir())?;
    let wrapper = write_scriptd_wrapper(executable, config)?;
    let plist_path = resolve_launchd_plist_path(&config.label);
    fs::create_dir_all(resolve_launch_agents_dir())?;
    fs::write(
        &plist_path,
        plist_contents(&config.label, &wrapper.to_string_lossy()),
    )?;
    Ok(plist_path)
}

pub fn start_root(config: &ServiceConfig) -> Result<()> {
    let exe = std::env::current_exe()?;
    let plist_path = write_root_plist(&exe, config)?;
    let label = &config.label;

    let _ = run_launchctl(&["unload", plist_path.to_str().unwrap_or_default()], false);
    let _ = run_launchctl(&["enable", &launchd_domain_label(label)], false);
    let _ = run_launchctl(
        &["load", "-w", plist_path.to_str().unwrap_or_default()],
        true,
    );
    println!("Started root launchd item: {label}");
    Ok(())
}

pub fn stop_root(label: &str) -> Result<()> {
    let plist_path = resolve_launchd_plist_path(label);
    let _ = run_launchctl(&["unload", plist_path.to_str().unwrap_or_default()], false);
    println!("Stopped root launchd item: {label}");
    Ok(())
}

pub fn uninstall_root(label: &str) -> Result<()> {
    let plist_path = resolve_launchd_plist_path(label);
    let _ = run_launchctl(&["unload", plist_path.to_str().unwrap_or_default()], false);
    let _ = run_launchctl(&["remove", label], false);
    let _ = fs::remove_file(&plist_path);
    let _ = fs::remove_dir_all(resolve_state_app_root());
    println!("Uninstalled root launchd item: {label}");
    Ok(())
}

pub fn status_loaded(label: &str) -> (bool, Option<u32>, Option<i32>) {
    let output = Command::new("launchctl").args(["list"]).output();
    let output = match output {
        Ok(value) => value,
        Err(_) => return (false, None, None),
    };
    let text = String::from_utf8_lossy(&output.stdout);
    for line in text.lines() {
        let fields: Vec<_> = line.split_whitespace().collect();
        if fields.len() >= 3 && fields[2] == label {
            let pid = fields[0].parse::<u32>().ok();
            let exit = fields[1].parse::<i32>().ok();
            return (true, pid, exit);
        }
    }
    (false, None, None)
}

pub fn run_launchctl(args: &[&str], must_succeed: bool) -> Result<()> {
    let result = Command::new("launchctl").args(args).status();
    if must_succeed {
        let status = result?;
        if !status.success() {
            anyhow::bail!("launchctl {} failed", args.join(" "));
        }
    }
    Ok(())
}
