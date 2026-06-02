use std::env;
use std::path::{Path, PathBuf};

pub fn home_dir() -> PathBuf {
    dirs::home_dir().unwrap_or_else(|| PathBuf::from("/"))
}

pub fn expand_home(raw: &str) -> PathBuf {
    if raw == "~" {
        return home_dir();
    }

    if let Some(suffix) = raw.strip_prefix("~/") {
        return home_dir().join(suffix);
    }

    PathBuf::from(raw)
}

pub fn resolve_repo_root() -> PathBuf {
    if let Ok(root) = env::var("SCRIPTD_ROOT_DIR") {
        return PathBuf::from(root);
    }

    let exe = env::current_exe().ok();
    exe.and_then(|value| value.parent().map(Path::to_path_buf))
        .or_else(|| env::current_dir().ok())
        .unwrap_or_else(|| PathBuf::from("."))
}

pub fn resolve_modules_dir(root: &Path) -> PathBuf {
    root.join("modules")
}

pub fn resolve_service_config_path(root: &Path) -> PathBuf {
    root.join("service.yaml")
}

pub fn resolve_state_dir() -> PathBuf {
    home_dir()
        .join("Library")
        .join("Application Support")
        .join("scriptd")
}

pub fn resolve_state_file() -> PathBuf {
    resolve_state_dir().join("state.json")
}

pub fn resolve_launch_agents_dir() -> PathBuf {
    home_dir().join("Library").join("LaunchAgents")
}

pub fn resolve_launchd_plist_path(label: &str) -> PathBuf {
    resolve_launch_agents_dir().join(format!("{label}.plist"))
}

#[allow(dead_code)]
pub fn resolve_script_path() -> PathBuf {
    if let Ok(path) = env::var("SCRIPTD_ENTRY_SHELL_PATH") {
        return PathBuf::from(path);
    }

    resolve_repo_root().join("scriptd.sh")
}
