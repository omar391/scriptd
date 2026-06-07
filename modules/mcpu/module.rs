#![allow(dead_code)]

use std::collections::HashMap;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use sysinfo::{ProcessesToUpdate, System};

use crate::modules::{ModuleContext, ModuleHealth, ModuleLogger, ModuleStatus};

#[derive(Debug, Clone, Serialize, Deserialize)]
struct McpuConfig {
    #[serde(rename = "cpu_threshold")]
    cpu_threshold: u64,
    #[serde(rename = "time_limit_seconds")]
    time_limit_seconds: u64,
    #[serde(rename = "exclude_apps")]
    exclude_apps: Vec<String>,
}

impl Default for McpuConfig {
    fn default() -> Self {
        Self {
            cpu_threshold: 50,
            time_limit_seconds: 600,
            exclude_apps: vec![
                "Finder".to_string(),
                "Dock".to_string(),
                "Terminal".to_string(),
                "Activity Monitor".to_string(),
                "kernel_task".to_string(),
                "loginwindow".to_string(),
            ],
        }
    }
}

#[derive(Clone, Debug)]
struct TrackedProcess {
    first_seen_at: u64,
    cpu: f32,
    name: String,
}

#[derive(Default)]
struct McpuState {
    tracked: HashMap<u32, TrackedProcess>,
    last_run_at: Option<String>,
    last_killed_pid: Option<u32>,
    last_message: Option<String>,
    last_error: Option<String>,
}

static STATE: once_cell::sync::Lazy<std::sync::Mutex<McpuState>> =
    once_cell::sync::Lazy::new(|| std::sync::Mutex::new(McpuState::default()));

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |value| value.as_secs())
}

fn read_cpu_config(module_dir: &Path) -> McpuConfig {
    let path = module_dir.join("module.yaml");
    match std::fs::read_to_string(&path) {
        Ok(contents) => serde_yaml::from_str(&contents).unwrap_or_else(|_| McpuConfig::default()),
        Err(_) => McpuConfig::default(),
    }
}

fn parse_cpu_snapshot(config: &McpuConfig, _logger: &ModuleLogger) -> Vec<(u32, TrackedProcess)> {
    let mut system = System::new_all();
    system.refresh_processes(ProcessesToUpdate::All, true);
    let mut out = Vec::new();

    for (pid, process) in system.processes() {
        let cpu = process.cpu_usage();
        let name = process.name().to_string_lossy().into_owned();
        if cpu <= config.cpu_threshold as f32 {
            continue;
        }
        if config
            .exclude_apps
            .iter()
            .any(|value| value.eq_ignore_ascii_case(&name))
        {
            continue;
        }
        out.push((
            pid.as_u32(),
            TrackedProcess {
                first_seen_at: now_secs(),
                cpu,
                name,
            },
        ));
    }

    out
}

fn reconcile_tracked_processes(
    snapshot: Vec<(u32, TrackedProcess)>,
    state: &HashMap<u32, TrackedProcess>,
    limit_seconds: u64,
) -> HashMap<u32, TrackedProcess> {
    let mut next = HashMap::new();
    let now = now_secs();
    for (pid, sampled) in snapshot {
        let first_seen = state
            .get(&pid)
            .map(|entry| entry.first_seen_at)
            .unwrap_or(now);
        let mut entry = sampled;
        entry.first_seen_at = first_seen;
        if now.saturating_sub(first_seen) < limit_seconds {
            next.insert(pid, entry);
        }
    }
    next
}

pub fn run_once(context: &mut ModuleContext) -> anyhow::Result<Option<ModuleStatus>> {
    let mut system = System::new_all();
    let config = read_cpu_config(&context.module_dir);
    system.refresh_processes(ProcessesToUpdate::All, true);
    let snapshot = parse_cpu_snapshot(&config, &context.logger);

    let mut state = STATE.lock().unwrap_or_else(|error| error.into_inner());
    state.tracked =
        reconcile_tracked_processes(snapshot, &state.tracked, config.time_limit_seconds);
    let now = now_secs();

    let stale: Vec<u32> = state
        .tracked
        .iter()
        .filter(|(_, value)| now.saturating_sub(value.first_seen_at) >= config.time_limit_seconds)
        .map(|(pid, _)| *pid)
        .collect();

    let mut killed: Option<String> = None;
    if !stale.is_empty() {
        for pid in stale {
            let _ = state.tracked.remove(&pid);
            if let Some(process) = system.process(sysinfo::Pid::from_u32(pid)) {
                if process.kill() {
                    let message = format!(
                        "Killed PID {pid} ({}) after sustained {}% CPU",
                        process.name().to_string_lossy(),
                        config.cpu_threshold
                    );
                    context.logger.info(&message);
                    state.last_message = Some(message.clone());
                    state.last_killed_pid = Some(pid);
                    state.last_error = None;
                    killed = Some(message);
                } else {
                    let message = format!("Could not kill pid {pid}");
                    context.logger.error(&message);
                    state.last_error = Some(message);
                }
            }
        }
    }

    state.last_run_at = Some(chrono::Utc::now().to_rfc3339());
    if killed.is_none() {
        state.last_error = None;
    }

    Ok(Some(ModuleStatus {
        state: "running".to_string(),
        message: state.last_message.clone(),
        started_at: None,
        last_run_at: state.last_run_at.clone(),
        next_run_at: None,
        metrics: Some(
            [
                (
                    "tracked".to_string(),
                    serde_json::Value::from(state.tracked.len() as u64),
                ),
                (
                    "last_killed_pid".to_string(),
                    serde_json::Value::from(
                        state
                            .last_killed_pid
                            .map(|value| value.to_string())
                            .unwrap_or_else(|| "none".to_string()),
                    ),
                ),
            ]
            .into_iter()
            .collect(),
        ),
    }))
}

pub fn setup(_context: &mut ModuleContext) -> anyhow::Result<()> {
    Ok(())
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
                    "tracked".to_string(),
                    serde_json::Value::from(0u64),
                )])),
            },
            ModuleHealth {
                ok: true,
                message: Some("cpu monitor healthy".to_string()),
            },
        ));
    }

    Some((
        ModuleStatus {
            state: "running".to_string(),
            message: state.last_message.clone(),
            started_at: None,
            last_run_at: state.last_run_at.clone(),
            next_run_at: None,
            metrics: Some(
                [
                    (
                        "tracked".to_string(),
                        serde_json::Value::from(state.tracked.len() as u64),
                    ),
                    (
                        "last_killed_pid".to_string(),
                        serde_json::Value::from(
                            state
                                .last_killed_pid
                                .map(|value| value.to_string())
                                .unwrap_or_else(|| "none".to_string()),
                        ),
                    ),
                ]
                .into_iter()
                .collect(),
            ),
        },
        ModuleHealth {
            ok: state.last_error.is_none(),
            message: state
                .last_error
                .clone()
                .or_else(|| Some("cpu monitor healthy".to_string())),
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reconcile_tracks_only_within_limit() {
        let now = now_secs();
        let state = HashMap::from([
            (
                1,
                TrackedProcess {
                    first_seen_at: now - 10,
                    cpu: 60.0,
                    name: "x".to_string(),
                },
            ),
            (
                2,
                TrackedProcess {
                    first_seen_at: now - 20,
                    cpu: 60.0,
                    name: "y".to_string(),
                },
            ),
        ]);
        let snapshot = vec![(
            1,
            TrackedProcess {
                first_seen_at: now,
                cpu: 90.0,
                name: "x".to_string(),
            },
        )];
        let next = reconcile_tracked_processes(snapshot, &state, 15);
        assert!(next.contains_key(&1));
        assert!(!next.contains_key(&2));
    }
}
