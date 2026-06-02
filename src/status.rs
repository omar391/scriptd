#![allow(dead_code)]

use serde::{Deserialize, Serialize};

use crate::config::ServiceConfig;
use crate::launchd;
use crate::modules::ModulesRegistry;
use crate::paths::resolve_state_file;
use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;
use std::process::Command;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PersistedState {
    pub label: String,
    #[serde(rename = "rootDir")]
    pub root_dir: String,
    #[serde(rename = "configPath")]
    pub config_path: String,
    #[serde(rename = "logDir")]
    pub log_dir: String,
    #[serde(rename = "updatedAt")]
    pub updated_at: String,
    pub supervisor: PersistedSupervisorState,
    pub modules: BTreeMap<String, PersistedModuleState>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PersistedSupervisorState {
    pub pid: i32,
    #[serde(rename = "startedAt")]
    pub started_at: String,
    pub watch: bool,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PersistedModuleState {
    #[serde(rename = "desiredEnabled")]
    pub desired_enabled: bool,
    pub status: String,
    pub mode: String,
    #[serde(rename = "lastStartedAt")]
    pub last_started_at: Option<String>,
    #[serde(rename = "lastRunAt")]
    pub last_run_at: Option<String>,
    #[serde(rename = "lastExitAt")]
    pub last_exit_at: Option<String>,
    #[serde(rename = "nextRunAt")]
    pub next_run_at: Option<String>,
    pub runs: u64,
    pub restarts: u64,
    pub message: String,
    pub health: Option<serde_json::Value>,
    #[serde(rename = "moduleStatus")]
    pub module_status: Option<serde_json::Value>,
    #[serde(rename = "lastError")]
    pub last_error: Option<String>,
}

pub fn render_status(config: &ServiceConfig, _config_path: PathBuf) -> anyhow::Result<()> {
    let (launchd_loaded, launchd_pid, _launchd_exit) = launchd::status_loaded(&config.label);
    let registry = ModulesRegistry::load_from_disk(config).ok();
    let state_path = resolve_state_file();
    let state: Option<PersistedState> = fs::read_to_string(&state_path)
        .ok()
        .and_then(|text| serde_json::from_str(&text).ok());

    println!("scriptd label: {}", config.label);
    println!("Config path: {}", config.path.display());
    println!("Shared log dir: {}", config.expanded_log_dir().display());
    println!(
        "State file: {}",
        state_path
            .to_str()
            .unwrap_or(config.path.to_str().unwrap_or("state.json"))
    );

    println!(
        "LaunchAgent loaded: {}",
        if launchd_loaded { "yes" } else { "no" }
    );
    println!(
        "LaunchAgent PID: {}",
        launchd_pid
            .map(|value| value.to_string())
            .unwrap_or_else(|| "-".to_string())
    );

    if let Some(state) = &state {
        let stale_reason =
            crate::config::build_state_freshness_reason(state, launchd_loaded, launchd_pid, config);

        println!("State file updated: {}", state.updated_at);
        println!(
            "scriptd PID: {}",
            if stale_reason.is_none() {
                state.supervisor.pid.to_string()
            } else {
                format!("{} (stale)", state.supervisor.pid)
            }
        );
        println!("scriptd started: {}", state.supervisor.started_at);
        println!(
            "scriptd watch enabled: {}",
            if state.supervisor.watch { "yes" } else { "no" }
        );
        if let Some(reason) = stale_reason.as_deref() {
            println!("state: stale snapshot ({reason})");
        } else {
            println!("state: current");
        }

        let mut names = BTreeMap::new();
        for id in config.modules.keys() {
            names.insert(id.clone(), ());
        }
        for id in state.modules.keys() {
            names.insert(id.clone(), ());
        }

        println!("Modules:");
        for name in names.keys() {
            let desired = if config.modules.get(name).is_some_and(|entry| entry.enabled) {
                "enabled"
            } else {
                "disabled"
            };
            let definition = registry
                .as_ref()
                .and_then(|item| item.get(name))
                .map(|entry| entry.manifest.mode.clone())
                .unwrap_or_else(|| "interval".to_string());
            let state_status = state.modules.get(name);
            let (runtime_kind, status, runs, restarts) = state_status
                .as_ref()
                .map(|entry| {
                    (
                        if stale_reason.is_none() {
                            "runtime"
                        } else {
                            "last"
                        },
                        entry.status.clone(),
                        entry.runs,
                        entry.restarts,
                    )
                })
                .unwrap_or(("runtime", "unknown".to_string(), 0, 0));
            let mut details = vec![
                format!("desired={desired}"),
                definition,
                format!("{runtime_kind}={status}"),
                format!("runs={runs}"),
                format!("restarts={restarts}"),
            ];

            if let Some(next_run_at) = state_status.and_then(|entry| entry.next_run_at.clone()) {
                details.push(format!("next={next_run_at}"));
            } else if stale_reason.is_some() && desired == "enabled" {
                if let Some(entry) = config.modules.get(name) {
                    if let Some(schedule) = &entry.schedule {
                        if let Some(next) = crate::config::next_scheduled_run(
                            &Some(schedule.clone()),
                            chrono::Local::now(),
                        ) {
                            details.push(format!("next={}", next.to_rfc3339()));
                        }
                    }
                }
            }

            println!("- {name}: {}", details.join(", "));
        }
    } else {
        println!("state: unreadable");
    }

    Ok(())
}

pub fn maybe_state_from_file(path: &std::path::Path) -> Option<PersistedState> {
    fs::read_to_string(path)
        .ok()
        .and_then(|text| serde_json::from_str(&text).ok())
}

pub fn process_alive(pid: i32) -> bool {
    let output = Command::new("ps")
        .args(["-p", &pid.to_string(), "-o", "pid="])
        .output();
    match output {
        Ok(value) => value.status.success() && !value.stdout.is_empty(),
        Err(_) => false,
    }
}

pub fn is_process_alive(pid: i32) -> bool {
    process_alive(pid)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_state_shape() {
        let json = r#"{
            "label":"com.omar.scriptd",
            "rootDir":"/tmp",
            "configPath":"/tmp/service.yaml",
            "logDir":"/tmp/logs",
            "updatedAt":"2026-06-02T00:00:00Z",
            "supervisor":{ "pid":123, "startedAt":"2026-06-02T00:00:00Z", "watch":true },
            "modules":{}
        }"#;
        let parsed: PersistedState = serde_json::from_str(json).expect("state json");
        assert_eq!(parsed.supervisor.pid, 123);
        assert!(parsed.modules.is_empty());
    }
}
