use std::fmt::Write;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::Result;

use crate::config::ServiceConfig;
use crate::paths::{resolve_launch_agents_dir, resolve_launchd_plist_path, resolve_state_dir};

fn plist_contents(label: &str, executable: &str) -> String {
    let mut buffer = String::new();
    let user = crate::credentials::current_user();
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
    <key>USER</key>
    <string>{user}</string>
    <key>LOGNAME</key>
    <string>{user}</string>
    <key>PATH</key>
    <string>/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin</string>
  </dict>
</dict>
</plist>"#,
        label = label,
        executable = executable,
        user = user,
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
    let output = Command::new("/usr/bin/id").args(["-u"]).output();
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

fn ensure_stable_service_root(root: &Path) -> Result<()> {
    if crate::paths::is_linked_worktree(root) {
        anyhow::bail!(
            "refusing to install scriptd from a linked git worktree; land the change and start it from the primary checkout"
        );
    }
    Ok(())
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

    let script = scriptd_wrapper_script(
        binary_path,
        config,
        binary_path == Path::new("/usr/local/libexec/scriptd-broker"),
    );
    fs::write(&exec_path, script)?;
    let _ = Command::new("chmod")
        .args(["+x", exec_path.to_str().expect("path")])
        .status();
    Ok(exec_path)
}

fn scriptd_wrapper_script(
    binary_path: &Path,
    config: &ServiceConfig,
    protected_helper: bool,
) -> String {
    if protected_helper {
        return format!(
            "#!/bin/sh\nset -eu\nexport SCRIPTD_ROOT_DIR=\"{}\"\nexec \"{}\" \"$@\"\n",
            config.root_dir.to_string_lossy(),
            binary_path.to_string_lossy(),
        );
    }

    format!(
        "#!/bin/sh\nset -eu\nexport SCRIPTD_ROOT_DIR=\"{}\"\nexport SCRIPTD_ENTRY_SHELL_PATH=\"{}/scriptd.sh\"\nrelease_binary_is_stale() {{\n  binary=\"$1\"\n  root=\"$2\"\n  [ -x \"$binary\" ] || return 0\n  [ \"$root/Cargo.toml\" -nt \"$binary\" ] && return 0\n  [ -f \"$root/Cargo.lock\" ] && [ \"$root/Cargo.lock\" -nt \"$binary\" ] && return 0\n  [ -f \"$root/build.rs\" ] && [ \"$root/build.rs\" -nt \"$binary\" ] && return 0\n  if find \"$root/src\" \"$root/modules\" -type f \\( -name '*.rs' -o -name '*.swift' \\) -newer \"$binary\" -print -quit 2>/dev/null | grep -q .; then\n    return 0\n  fi\n  return 1\n}}\nif release_binary_is_stale \"{}\" \"{}\"; then\n  exec \"$SCRIPTD_ENTRY_SHELL_PATH\" \"$@\"\nfi\nexec \"{}\" \"$@\"\n",
        config.root_dir.to_string_lossy(),
        config.root_dir.to_string_lossy(),
        binary_path.to_string_lossy(),
        config.root_dir.to_string_lossy(),
        binary_path.to_string_lossy(),
    )
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
    ensure_stable_service_root(&config.root_dir)?;
    let current = std::env::current_exe()?;
    let helper = Path::new("/usr/local/libexec/scriptd-broker");
    let helper_protected = crate::broker::validate_root_owned_file(helper, 0).is_ok();
    let exe = select_service_executable(&current, helper, helper_protected);
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

fn select_service_executable(current: &Path, helper: &Path, helper_protected: bool) -> PathBuf {
    if helper_protected
        && fs::read(current)
            .ok()
            .zip(fs::read(helper).ok())
            .is_some_and(|(current, helper)| current == helper)
    {
        helper.to_path_buf()
    } else {
        current.to_path_buf()
    }
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

#[cfg(test)]
mod tests {
    use super::{
        ensure_stable_service_root, plist_contents, scriptd_wrapper_script,
        select_service_executable,
    };
    use crate::config::ServiceConfig;
    use crate::credentials::current_user;
    use std::collections::HashMap;
    use std::os::unix::fs::PermissionsExt;
    use std::process::Command;
    use tempfile::tempdir;

    fn test_service_config(root_dir: std::path::PathBuf) -> ServiceConfig {
        ServiceConfig {
            label: "com.example.scriptd".into(),
            log_dir: String::new(),
            watch: false,
            control_center: false,
            self_update_check_hours: 24,
            modules: HashMap::new(),
            triggers: Default::default(),
            path: root_dir.join("config.toml"),
            root_dir: root_dir.clone(),
            state_dir: root_dir.join("state"),
            state_file: root_dir.join("state.json"),
        }
    }

    #[test]
    fn launch_agent_plist_pins_the_current_user() {
        let plist = plist_contents("com.example.scriptd", "/tmp/scriptd");
        let user = current_user();
        assert!(plist.contains(&format!("<key>USER</key>\n    <string>{user}</string>")));
        assert!(plist.contains(&format!("<key>LOGNAME</key>\n    <string>{user}</string>")));
    }

    #[test]
    fn launch_agent_rejects_linked_worktree_roots() {
        let root = tempdir().expect("temp root");
        std::fs::write(
            root.path().join(".git"),
            "gitdir: /tmp/example/.git/worktrees/feature",
        )
        .expect("git marker");
        let error = ensure_stable_service_root(root.path()).expect_err("linked worktree rejected");
        assert!(error.to_string().contains("primary checkout"));
    }

    #[test]
    fn launch_agent_accepts_a_submodule_checkout_root() {
        let root = tempdir().expect("temp root");
        std::fs::write(
            root.path().join(".git"),
            "gitdir: /tmp/example/.git/modules/scriptd",
        )
        .expect("git marker");
        assert!(
            ensure_stable_service_root(root.path()).is_ok(),
            "a submodule checkout is a stable service root"
        );
    }

    #[test]
    fn launch_agent_uses_protected_broker_binary_only_for_the_same_generation() {
        let root = tempdir().expect("temp root");
        let current = root.path().join("current-scriptd");
        let helper = root.path().join("protected-scriptd");
        std::fs::write(&current, b"same signed executable").expect("write current binary");
        std::fs::write(&helper, b"same signed executable").expect("write helper binary");

        assert_eq!(
            select_service_executable(&current, &helper, true),
            helper,
            "the launch agent and broker must execute the same protected code generation"
        );
        assert_eq!(
            select_service_executable(&current, &helper, false),
            current,
            "an unprotected helper path must never become the launch target"
        );

        std::fs::write(&helper, b"different signed executable").expect("replace helper bytes");
        assert_eq!(
            select_service_executable(&current, &helper, true),
            current,
            "a stale protected helper must not be used for a different service generation"
        );
    }

    #[test]
    fn protected_launch_wrapper_ignores_newer_repository_sources() {
        let root = tempdir().expect("temp root");
        let binary = root.path().join("protected-scriptd");
        let source = root.path().join("src").join("newer.rs");
        let marker = root.path().join("launched");
        std::fs::create_dir_all(source.parent().expect("source parent")).expect("source dir");
        std::fs::write(
            &binary,
            format!("#!/bin/sh\nprintf launched > '{}'\n", marker.display()),
        )
        .expect("write helper executable");
        std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o755))
            .expect("make helper executable");
        std::fs::write(&source, "newer repository source").expect("write source");
        let config = test_service_config(root.path().to_path_buf());
        let wrapper = scriptd_wrapper_script(&binary, &config, true);
        let wrapper_path = root.path().join("wrapper.sh");
        std::fs::write(&wrapper_path, wrapper).expect("write wrapper");
        std::fs::set_permissions(&wrapper_path, std::fs::Permissions::from_mode(0o755))
            .expect("make wrapper executable");

        let status = Command::new(&wrapper_path)
            .arg("run")
            .arg("root")
            .status()
            .expect("run wrapper");
        assert!(status.success());
        assert_eq!(
            std::fs::read_to_string(marker).expect("helper marker"),
            "launched"
        );
    }
}
