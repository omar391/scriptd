use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use crate::paths::{
    expand_home, resolve_service_config_path, resolve_state_dir, resolve_state_file,
};
use anyhow::Context;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceConfig {
    pub label: String,
    #[serde(rename = "log_dir")]
    pub log_dir: String,
    #[serde(default)]
    pub watch: bool,
    #[serde(default = "default_self_update_check_hours")]
    pub self_update_check_hours: u64,
    #[serde(default)]
    pub modules: HashMap<String, ServiceModuleConfig>,
    #[serde(default)]
    pub triggers: crate::triggers::TriggerMap,

    #[serde(skip)]
    pub path: PathBuf,
    #[serde(skip)]
    pub root_dir: PathBuf,
    #[serde(skip)]
    pub state_dir: PathBuf,
    #[serde(skip)]
    pub state_file: PathBuf,
}

impl ServiceConfig {
    pub fn expanded_log_dir(&self) -> PathBuf {
        expand_home(&self.log_dir)
    }

    pub fn self_update_check_interval(&self) -> std::time::Duration {
        std::time::Duration::from_secs(self.self_update_check_hours.saturating_mul(60 * 60))
    }
}

fn default_self_update_check_hours() -> u64 {
    12
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct ServiceModuleConfig {
    pub enabled: bool,
    #[serde(rename = "schedule", default, skip_serializing_if = "Option::is_none")]
    legacy_schedule: Option<serde_yaml::Value>,
}

#[derive(Debug, Clone)]
pub struct ParsedModule {
    pub manifest: ModuleManifest,
    pub dir: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleManifest {
    pub id: String,
    #[serde(rename = "display_name")]
    pub display_name: Option<String>,
    pub mode: String,
    #[serde(rename = "interval_seconds", default)]
    legacy_interval_seconds: Option<u64>,
}

pub fn read_service_config(root: &Path) -> anyhow::Result<ServiceConfig> {
    let path = resolve_service_config_path(root);
    let text = fs::read_to_string(&path)?;
    let mut config: ServiceConfig = serde_yaml::from_str(&text)?;
    config.path = path;
    config.root_dir = root.to_path_buf();
    config.state_dir = resolve_state_dir();
    config.state_file = resolve_state_file();
    for (module_id, module) in &config.modules {
        if module.legacy_schedule.is_some() {
            anyhow::bail!(
                "legacy modules.{module_id}.schedule is no longer supported; define a top-level trigger"
            );
        }
    }
    for (trigger_id, trigger) in &config.triggers {
        if trigger_id.trim().is_empty() {
            anyhow::bail!("trigger id must not be empty");
        }
        trigger
            .validate()
            .with_context(|| format!("invalid trigger {trigger_id}"))?;
    }
    if config.self_update_check_hours == 0 {
        anyhow::bail!("service self_update_check_hours must be greater than zero");
    }
    Ok(config)
}

pub fn read_module_manifest(id: &str, root: &Path) -> anyhow::Result<ParsedModule> {
    let manifest_path = root.join("modules").join(id).join("module.yaml");
    let raw = fs::read_to_string(&manifest_path)?;
    let manifest: ModuleManifest = serde_yaml::from_str(&raw)?;
    if manifest.id != id {
        anyhow::bail!("module manifest id mismatch: {} != {}", manifest.id, id);
    }
    if manifest.legacy_interval_seconds.is_some() {
        anyhow::bail!(
            "module {id} uses removed interval_seconds; define a top-level service trigger"
        );
    }
    if manifest.mode != "task" && manifest.mode != "daemon" {
        anyhow::bail!(
            "module {id} has unsupported mode {}; expected task or daemon",
            manifest.mode
        );
    }

    Ok(ParsedModule {
        manifest,
        dir: manifest_path
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| root.join("modules").join(id)),
    })
}

pub fn build_state_freshness_reason(
    state: &crate::status::PersistedState,
    launchd_loaded: bool,
    launchd_pid: Option<u32>,
    config: &ServiceConfig,
) -> Option<String> {
    if state.label != config.label {
        return Some("label mismatch".into());
    }

    if state.root_dir != config.root_dir.to_string_lossy() {
        return Some("state file belongs to another repo root".into());
    }

    if state.config_path != config.path.to_string_lossy() {
        return Some("state file belongs to another config path".into());
    }

    if !launchd_loaded {
        return Some("LaunchAgent not loaded".into());
    }

    if let Some(loaded_pid) = launchd_pid {
        if loaded_pid != u32::try_from(state.supervisor.pid).ok().unwrap_or_default() {
            return Some("supervisor PID does not match launchd PID".into());
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Local;
    use tempfile::tempdir;

    #[test]
    fn parses_service_config_and_expands_home_dir() {
        let temp = tempdir().expect("temp dir");
        let repo = temp.path();
        let home = dirs::home_dir().unwrap_or_else(|| std::path::PathBuf::from("/"));
        let service_yaml = "label: com.omar.scriptd\nlog_dir: ~/Library/Logs/scriptd\nwatch: true\nself_update_check_hours: 12\nmodules:\n  mbrew:\n    enabled: true\ntriggers:\n  mbrew-maintenance:\n    enabled: true\n    module: mbrew\n    fire: { mode: every_match }\n    when:\n      schedule: { every_hours: 12 }\n";
        fs::write(repo.join("service.yaml"), service_yaml).expect("write service config");

        let config = read_service_config(repo).expect("read config");
        assert_eq!(config.label, "com.omar.scriptd");
        assert!(config.watch);
        assert_eq!(config.self_update_check_hours, 12);
        assert_eq!(config.log_dir, "~/Library/Logs/scriptd");
        assert_eq!(
            config.expanded_log_dir().to_string_lossy(),
            format!("{}/Library/Logs/scriptd", home.to_string_lossy())
        );
        assert!(config.modules.get("mbrew").expect("module").enabled);
        assert!(config.triggers.contains_key("mbrew-maintenance"));
    }

    #[test]
    fn read_module_manifest_rejects_id_mismatch() {
        let temp = tempdir().expect("temp dir");
        let module_dir = temp.path().join("modules").join("mwifi");
        std::fs::create_dir_all(&module_dir).expect("create module dir");
        std::fs::write(
            module_dir.join("module.yaml"),
            "id: wrong-id\nmode: interval\ninterval_seconds: 30\n",
        )
        .expect("write manifest");

        let result = read_module_manifest("mwifi", temp.path());
        assert!(result.is_err());
    }

    #[test]
    fn read_service_config_rejects_legacy_module_schedule() {
        let temp = tempdir().expect("temp dir");
        let service_yaml = "label: com.omar.scriptd\nlog_dir: ~/Library/Logs/scriptd\nwatch: true\nself_update_check_hours: 12\nmodules:\n  mbrew:\n    enabled: true\n    schedule:\n      every_hours: 12\n      daily_at:\n        - \"09:00\"\n";
        fs::write(temp.path().join("service.yaml"), service_yaml).expect("write service config");

        let error = read_service_config(temp.path()).expect_err("legacy schedule should fail");
        assert!(error
            .to_string()
            .contains("legacy modules.mbrew.schedule is no longer supported"));
    }

    #[test]
    fn state_freshness_marks_stale_when_launchd_not_loaded() {
        let state = crate::status::PersistedState {
            label: "com.omar.scriptd".to_string(),
            root_dir: "/tmp/repo".to_string(),
            config_path: "/tmp/service.yaml".to_string(),
            log_dir: "/tmp/logs".to_string(),
            updated_at: Local::now().to_rfc3339(),
            supervisor: crate::status::PersistedSupervisorState {
                pid: 100,
                started_at: Local::now().to_rfc3339(),
                watch: true,
            },
            modules: Default::default(),
            triggers: Default::default(),
        };
        let config = ServiceConfig {
            label: "com.omar.scriptd".to_string(),
            log_dir: "/tmp/logs".to_string(),
            watch: true,
            self_update_check_hours: 12,
            modules: Default::default(),
            triggers: Default::default(),
            path: "/tmp/service.yaml".into(),
            root_dir: "/tmp/repo".into(),
            state_dir: resolve_state_dir(),
            state_file: resolve_state_file(),
        };
        let reason = build_state_freshness_reason(&state, false, None, &config)
            .expect("expected stale reason");
        assert!(reason.contains("LaunchAgent not loaded"));
    }

    #[test]
    fn state_freshness_marks_stale_if_launchd_pid_mismatch() {
        let updated = Local::now().to_rfc3339();
        let state = crate::status::PersistedState {
            label: "com.omar.scriptd".to_string(),
            root_dir: "/tmp/repo".to_string(),
            config_path: "/tmp/service.yaml".to_string(),
            log_dir: "/tmp/logs".to_string(),
            updated_at: updated,
            supervisor: crate::status::PersistedSupervisorState {
                pid: 100,
                started_at: Local::now().to_rfc3339(),
                watch: true,
            },
            modules: Default::default(),
            triggers: Default::default(),
        };
        let config = ServiceConfig {
            label: "com.omar.scriptd".to_string(),
            log_dir: "/tmp/logs".to_string(),
            watch: true,
            self_update_check_hours: 12,
            modules: Default::default(),
            triggers: Default::default(),
            path: "/tmp/service.yaml".into(),
            root_dir: "/tmp/repo".into(),
            state_dir: resolve_state_dir(),
            state_file: resolve_state_file(),
        };

        let reason = build_state_freshness_reason(&state, true, Some(777), &config)
            .expect("expected pid mismatch reason");
        assert!(reason.contains("PID"));
    }

    #[test]
    fn state_freshness_reports_current_when_live() {
        let now = Local::now().to_rfc3339();
        let pid = 123i32;
        let state = crate::status::PersistedState {
            label: "com.omar.scriptd".to_string(),
            root_dir: "/tmp/repo".to_string(),
            config_path: "/tmp/service.yaml".to_string(),
            log_dir: "/tmp/logs".to_string(),
            updated_at: now.clone(),
            supervisor: crate::status::PersistedSupervisorState {
                pid,
                started_at: now.clone(),
                watch: true,
            },
            modules: Default::default(),
            triggers: Default::default(),
        };
        let config = ServiceConfig {
            label: "com.omar.scriptd".to_string(),
            log_dir: "/tmp/logs".to_string(),
            watch: true,
            self_update_check_hours: 12,
            modules: Default::default(),
            triggers: Default::default(),
            path: "/tmp/service.yaml".into(),
            root_dir: "/tmp/repo".into(),
            state_dir: resolve_state_dir(),
            state_file: resolve_state_file(),
        };

        let reason = build_state_freshness_reason(&state, true, Some(pid as u32), &config);
        assert!(reason.is_none());
    }

    #[test]
    fn state_freshness_allows_old_quiet_state_when_launchd_live() {
        let pid = 321i32;
        let state = crate::status::PersistedState {
            label: "com.omar.scriptd".to_string(),
            root_dir: "/tmp/repo".to_string(),
            config_path: "/tmp/service.yaml".to_string(),
            log_dir: "/tmp/logs".to_string(),
            updated_at: "2020-01-01T00:00:00Z".to_string(),
            supervisor: crate::status::PersistedSupervisorState {
                pid,
                started_at: "2020-01-01T00:00:00Z".to_string(),
                watch: true,
            },
            modules: Default::default(),
            triggers: Default::default(),
        };
        let config = ServiceConfig {
            label: "com.omar.scriptd".to_string(),
            log_dir: "/tmp/logs".to_string(),
            watch: true,
            self_update_check_hours: 12,
            modules: Default::default(),
            triggers: Default::default(),
            path: "/tmp/service.yaml".into(),
            root_dir: "/tmp/repo".into(),
            state_dir: resolve_state_dir(),
            state_file: resolve_state_file(),
        };

        let reason = build_state_freshness_reason(&state, true, Some(pid as u32), &config);
        assert!(reason.is_none());
    }
}
