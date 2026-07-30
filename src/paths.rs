use std::env;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

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

pub fn validate_config_path(label: &str, raw: &str, allow_empty: bool) -> anyhow::Result<()> {
    if raw.is_empty() && allow_empty {
        return Ok(());
    }
    if raw.trim().is_empty() || raw.trim() != raw {
        anyhow::bail!("{label} must be a non-empty path without surrounding whitespace");
    }
    if raw.contains('\0') {
        anyhow::bail!("{label} must not contain a NUL byte");
    }
    if !expand_home(raw).is_absolute() {
        anyhow::bail!("{label} must be absolute or start with ~/");
    }
    Ok(())
}

pub fn write_private_atomic(path: &Path, contents: &[u8]) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let temporary = path.with_extension(format!("{}-{nonce}.tmp", std::process::id()));
    let result = (|| {
        let mut options = OpenOptions::new();
        options.create_new(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&temporary)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&temporary, std::fs::Permissions::from_mode(0o600))?;
        }
        file.write_all(contents)?;
        file.sync_all()?;
        drop(file);
        std::fs::rename(&temporary, path)?;
        if let Some(parent) = path.parent() {
            std::fs::File::open(parent)?.sync_all()?;
        }
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }
    result
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

#[cfg(test)]
mod tests {
    use super::{validate_config_path, write_private_atomic};

    #[test]
    fn config_paths_are_absolute_or_home_relative() {
        assert!(validate_config_path("path", "/tmp/scriptd", false).is_ok());
        assert!(validate_config_path("path", "~/Library/scriptd", false).is_ok());
        assert!(validate_config_path("path", "", true).is_ok());
        assert!(validate_config_path("path", "relative/scriptd", false).is_err());
        assert!(validate_config_path("path", " /tmp/scriptd", false).is_err());
        assert!(validate_config_path("path", "", false).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn private_atomic_writes_use_restricted_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("state.json");
        write_private_atomic(&path, br#"{"ok":true}"#).expect("write state");

        assert_eq!(
            std::fs::metadata(path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}
