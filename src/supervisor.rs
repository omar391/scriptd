use std::collections::{BTreeMap, BTreeSet};
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result};
use chrono::{DateTime, Local, Utc};
use notify::event::EventKind;
use notify::{RecommendedWatcher, RecursiveMode, Watcher};
use sysinfo::{Pid, ProcessesToUpdate, System};
use tokio::select;
use tokio::signal::unix::{signal, SignalKind};
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender};
use tokio::time::{sleep, sleep_until, Instant};

use crate::config::{self, ServiceConfig};
use crate::modules::{
    self, BuiltInModule, ModuleDefinition, ModuleInvocation, ModulesRegistry, TriggerInvocation,
};
use crate::status::{
    PersistedModuleState, PersistedState, PersistedSupervisorState, PersistedTriggerState,
};
use crate::triggers::{FirePolicy, SensorSuite, TriggerDispatch, TriggerRuntime, WifiEventWatcher};

const SOURCE_STALENESS_TOLERANCE: Duration = Duration::from_secs(1);
const SENSOR_POLL_FALLBACK: Duration = Duration::from_secs(30);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RuntimeStatus {
    Disabled,
    Scheduled,
    Running,
    Error,
    Stopped,
}

impl RuntimeStatus {
    fn as_str(self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::Scheduled => "scheduled",
            Self::Running => "running",
            Self::Error => "error",
            Self::Stopped => "stopped",
        }
    }
}

#[derive(Debug)]
struct ModuleRuntime {
    id: String,
    definition: ModuleDefinition,
    kind: BuiltInModule,
    desired_enabled: bool,
    status: RuntimeStatus,
    mode: String,
    runs: u64,
    restarts: u64,
    message: String,
    last_started_at: Option<String>,
    last_run_at: Option<String>,
    last_exit_at: Option<String>,
    next_run_at: Option<DateTime<Utc>>,
    last_error: Option<String>,
    health: Option<serde_json::Value>,
    module_status: Option<serde_json::Value>,
}

impl ModuleRuntime {
    fn from_definition(definition: ModuleDefinition) -> Self {
        let kind = BuiltInModule::kind_from_id(&definition.id).unwrap_or(BuiltInModule::Mcpu);
        Self {
            id: definition.id.clone(),
            mode: definition.manifest.mode.as_str().to_string(),
            definition,
            kind,
            desired_enabled: false,
            status: RuntimeStatus::Disabled,
            runs: 0,
            restarts: 0,
            message: "discovered".to_string(),
            last_started_at: None,
            last_run_at: None,
            last_exit_at: None,
            next_run_at: None,
            last_error: None,
            health: None,
            module_status: None,
        }
    }

    fn update_from_definition(&mut self, definition: ModuleDefinition) {
        self.kind = BuiltInModule::kind_from_id(&definition.id).unwrap_or(self.kind);
        self.id = definition.id.clone();
        self.mode = definition.manifest.mode.as_str().to_string();
        self.definition = definition;
    }

    fn refresh_status(&mut self) {
        if let Some((status, health)) = modules::module_status(&self.kind) {
            self.health = serde_json::to_value(health).ok();
            let status_message = status.message.clone();
            self.module_status = serde_json::to_value(status).ok();
            if self.last_error.is_none() {
                if let Some(message) = status_message {
                    self.message = message;
                }
            }
        }
    }
}

#[derive(Debug)]
struct SingletonLock {
    path: PathBuf,
}

impl Drop for SingletonLock {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

fn process_is_alive(pid: u32) -> bool {
    let mut system = System::new_all();
    system.refresh_processes(ProcessesToUpdate::All, true);
    system.process(Pid::from_u32(pid)).is_some()
}

fn acquire_singleton_lock(config: &ServiceConfig) -> Result<SingletonLock> {
    let Some(state_dir) = config.state_file.parent() else {
        anyhow::bail!("state file has no parent directory");
    };
    std::fs::create_dir_all(state_dir).context("ensure state directory for singleton lock")?;
    let lock_path = state_dir.join("scriptd.lock");

    loop {
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&lock_path)
        {
            Ok(mut file) => {
                writeln!(file, "{}", std::process::id()).context("write singleton lock pid")?;
                return Ok(SingletonLock { path: lock_path });
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                let existing_pid = std::fs::read_to_string(&lock_path)
                    .ok()
                    .and_then(|value| value.trim().parse::<u32>().ok());
                if existing_pid.is_some_and(process_is_alive) {
                    anyhow::bail!(
                        "scriptd root supervisor is already running with pid {}",
                        existing_pid.unwrap_or_default()
                    );
                }
                let _ = std::fs::remove_file(&lock_path);
            }
            Err(error) => return Err(error).context("create singleton lock"),
        }
    }
}

#[derive(Debug)]
struct RunningSupervisor {
    _singleton_lock: SingletonLock,
    root: PathBuf,
    state_file: PathBuf,
    config_path: PathBuf,
    log_dir: PathBuf,
    label: String,
    started_at: String,
    watch: bool,
    modules: BTreeMap<String, ModuleRuntime>,
    triggers: BTreeMap<String, TriggerRuntime>,
    sensors: SensorSuite,
    watcher: Option<RecommendedWatcher>,
    reload_receiver: Option<UnboundedReceiver<()>>,
    wifi_event_watcher: Option<WifiEventWatcher>,
    wifi_event_receiver: Option<UnboundedReceiver<()>>,
    last_state_fingerprint: Option<String>,
}

fn file_modified_at(path: &Path) -> Result<std::time::SystemTime> {
    std::fs::metadata(path)
        .with_context(|| format!("stat {}", path.display()))?
        .modified()
        .with_context(|| format!("modified time {}", path.display()))
}

fn is_meaningfully_newer(left: std::time::SystemTime, right: std::time::SystemTime) -> bool {
    left.duration_since(right)
        .map(|delta| delta > SOURCE_STALENESS_TOLERANCE)
        .unwrap_or(false)
}

fn path_contains_newer_file(path: &Path, binary_modified: std::time::SystemTime) -> Result<bool> {
    if !path.exists() {
        return Ok(false);
    }
    if path.is_file() {
        return Ok(is_meaningfully_newer(
            file_modified_at(path)?,
            binary_modified,
        ));
    }
    for entry in std::fs::read_dir(path).with_context(|| format!("read {}", path.display()))? {
        let entry = entry?;
        if path_contains_newer_file(&entry.path(), binary_modified)? {
            return Ok(true);
        }
    }
    Ok(false)
}

fn sources_newer_than_binary(root: &Path, binary: &Path) -> Result<bool> {
    if !binary.exists() {
        return Ok(true);
    }
    let binary_modified = file_modified_at(binary)?;
    for path in [
        root.join("Cargo.toml"),
        root.join("Cargo.lock"),
        root.join("build.rs"),
        root.join("src"),
        root.join("modules"),
    ] {
        if path_contains_newer_file(&path, binary_modified)? {
            return Ok(true);
        }
    }
    Ok(false)
}

fn request_self_restart() -> Result<()> {
    let pid = unsafe { libc::getpid() };
    let rc = unsafe { libc::kill(pid, libc::SIGTERM) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error()).context("signal self for restart");
    }
    Ok(())
}

impl RunningSupervisor {
    fn build(
        root: &Path,
        config: ServiceConfig,
        registry: ModulesRegistry,
        singleton_lock: SingletonLock,
    ) -> Result<Self> {
        let restored = crate::status::state_from_file(&config.state_file)
            .context("restore persisted supervisor state")?;
        if let Some(state) = restored.as_ref() {
            validate_persisted_state_origin(state, root, &config)?;
        }
        let mut modules = BTreeMap::new();
        for definition in registry.modules() {
            let mut runtime = ModuleRuntime::from_definition(definition.clone());
            runtime.desired_enabled = config
                .modules
                .get(&definition.id)
                .is_some_and(|entry| entry.enabled);
            runtime.status = if runtime.desired_enabled {
                RuntimeStatus::Scheduled
            } else {
                RuntimeStatus::Disabled
            };
            runtime.message = if runtime.desired_enabled {
                "waiting for trigger".to_string()
            } else {
                "module disabled".to_string()
            };
            if let Some(saved) = restored
                .as_ref()
                .and_then(|state| state.modules.get(&definition.id))
            {
                runtime.runs = saved.runs;
                runtime.restarts = saved.restarts;
                runtime.last_started_at = saved.last_started_at.clone();
                runtime.last_run_at = saved.last_run_at.clone();
                runtime.last_exit_at = saved.last_exit_at.clone();
                runtime.last_error = saved.last_error.clone();
            }
            runtime.refresh_status();
            modules.insert(definition.id.clone(), runtime);
        }
        let triggers = build_trigger_runtimes(
            &config,
            Utc::now(),
            restored.as_ref().map(|state| &state.triggers),
        );

        let (wifi_sender, wifi_event_receiver) = unbounded_channel();
        let wifi_event_watcher = SensorSuite::spawn_wifi_event_watcher(wifi_sender);
        let mut supervisor = Self {
            _singleton_lock: singleton_lock,
            root: root.to_path_buf(),
            state_file: config.state_file.clone(),
            config_path: config.path.clone(),
            log_dir: config.expanded_log_dir(),
            label: config.label.clone(),
            started_at: Local::now().to_rfc3339(),
            watch: config.watch,
            modules,
            triggers,
            sensors: SensorSuite::default(),
            watcher: None,
            reload_receiver: None,
            wifi_event_watcher,
            wifi_event_receiver: Some(wifi_event_receiver),
            last_state_fingerprint: None,
        };
        supervisor.update_module_next_wakes();
        Ok(supervisor)
    }

    fn start_watcher(&mut self) -> Result<()> {
        let (tx, rx): (UnboundedSender<()>, UnboundedReceiver<()>) = unbounded_channel();
        let mut watcher =
            notify::recommended_watcher(move |event: notify::Result<notify::Event>| {
                if let Ok(event) = event {
                    if matches!(
                        event.kind,
                        EventKind::Modify(_) | EventKind::Create(_) | EventKind::Remove(_)
                    ) {
                        let _ = tx.send(());
                    }
                }
            })
            .context("create service config watcher")?;
        watcher
            .watch(&self.config_path, RecursiveMode::NonRecursive)
            .context("watch service config")?;
        watcher
            .watch(&self.root.join("modules"), RecursiveMode::Recursive)
            .context("watch module configuration")?;
        self.watcher = Some(watcher);
        self.reload_receiver = Some(rx);
        Ok(())
    }

    fn apply_service_config(
        &mut self,
        config: ServiceConfig,
        registry: ModulesRegistry,
    ) -> Result<()> {
        if config.watch && self.watcher.is_none() {
            self.config_path = config.path.clone();
            self.start_watcher()?;
        } else if !config.watch {
            self.watcher = None;
            self.reload_receiver = None;
        }
        self.watch = config.watch;
        self.label = config.label.clone();
        self.log_dir = config.expanded_log_dir();
        for definition in registry.modules() {
            let entry = self
                .modules
                .entry(definition.id.clone())
                .or_insert_with(|| ModuleRuntime::from_definition(definition.clone()));
            entry.update_from_definition(definition.clone());
            entry.desired_enabled = config
                .modules
                .get(&definition.id)
                .is_some_and(|value| value.enabled);
            entry.status = if entry.desired_enabled {
                RuntimeStatus::Scheduled
            } else {
                RuntimeStatus::Disabled
            };
            entry.message = if entry.desired_enabled {
                "waiting for trigger".to_string()
            } else {
                "module disabled".to_string()
            };
            entry.refresh_status();
        }
        self.modules.retain(|id, _| registry.get(id).is_some());

        let prior = self
            .triggers
            .iter()
            .map(|(id, runtime)| {
                (
                    id.clone(),
                    PersistedTriggerState {
                        target: runtime.module().to_string(),
                        enabled: runtime.enabled(),
                        config: Some(runtime.config().clone()),
                        next_wake_at: runtime.next_wake().map(|value| value.to_rfc3339()),
                        runtime: runtime.snapshot_state(),
                    },
                )
            })
            .collect();
        self.triggers = build_trigger_runtimes(&config, Utc::now(), Some(&prior));
        self.update_module_next_wakes();
        Ok(())
    }

    fn next_run_delay(&self, now: DateTime<Utc>) -> Duration {
        self.triggers
            .values()
            .filter(|trigger| {
                trigger.enabled()
                    && self
                        .modules
                        .get(trigger.module())
                        .is_some_and(|module| module.desired_enabled)
            })
            .filter_map(TriggerRuntime::next_wake)
            .map(|wake| wake.signed_duration_since(now).to_std().unwrap_or_default())
            .min()
            .unwrap_or(SENSOR_POLL_FALLBACK)
            .min(SENSOR_POLL_FALLBACK)
    }

    fn persisted_trigger_states(&self) -> BTreeMap<String, PersistedTriggerState> {
        self.triggers
            .iter()
            .map(|(id, runtime)| {
                (
                    id.clone(),
                    PersistedTriggerState {
                        target: runtime.module().to_string(),
                        enabled: runtime.enabled(),
                        config: Some(runtime.config().clone()),
                        next_wake_at: runtime.next_wake().map(|value| value.to_rfc3339()),
                        runtime: runtime.snapshot_state(),
                    },
                )
            })
            .collect()
    }

    fn persist_if_changed(&mut self) -> Result<()> {
        let module_states = self
            .modules
            .iter()
            .map(|(id, runtime)| {
                (
                    id.clone(),
                    PersistedModuleState {
                        desired_enabled: runtime.desired_enabled,
                        status: runtime.status.as_str().to_string(),
                        mode: runtime.mode.clone(),
                        last_started_at: runtime.last_started_at.clone(),
                        last_run_at: runtime.last_run_at.clone(),
                        last_exit_at: runtime.last_exit_at.clone(),
                        next_run_at: runtime.next_run_at.map(|value| value.to_rfc3339()),
                        runs: runtime.runs,
                        restarts: runtime.restarts,
                        message: runtime.message.clone(),
                        health: runtime.health.clone(),
                        module_status: runtime.module_status.clone(),
                        last_error: runtime.last_error.clone(),
                    },
                )
            })
            .collect::<BTreeMap<_, _>>();
        let trigger_states = self.persisted_trigger_states();
        let supervisor = PersistedSupervisorState {
            pid: std::process::id() as i32,
            started_at: self.started_at.clone(),
            watch: self.watch,
        };
        let fingerprint = serde_json::to_string(&serde_json::json!({
            "label": self.label.clone(),
            "rootDir": self.root.to_string_lossy().to_string(),
            "configPath": self.config_path.to_string_lossy().to_string(),
            "logDir": self.log_dir.to_string_lossy().to_string(),
            "supervisor": supervisor.clone(),
            "modules": module_states.clone(),
            "triggers": trigger_states.clone(),
        }))?;
        if self.last_state_fingerprint.as_deref() == Some(&fingerprint) {
            return Ok(());
        }
        let state = PersistedState {
            label: self.label.clone(),
            root_dir: self.root.to_string_lossy().to_string(),
            config_path: self.config_path.to_string_lossy().to_string(),
            log_dir: self.log_dir.to_string_lossy().to_string(),
            updated_at: Local::now().to_rfc3339(),
            supervisor,
            modules: module_states,
            triggers: trigger_states,
        };
        crate::paths::write_private_atomic(
            &self.state_file,
            serde_json::to_string_pretty(&state)?.as_bytes(),
        )
        .context("persist supervisor state")?;
        self.last_state_fingerprint = Some(fingerprint);
        Ok(())
    }

    fn run_module_once(&mut self, dispatch: &TriggerDispatch) -> Result<()> {
        let Some(runtime) = self.modules.get_mut(&dispatch.module) else {
            return Ok(());
        };
        let mut context = modules::module_context_with_settings(
            &runtime.id,
            self.root.clone(),
            runtime.definition.dir.clone(),
            self.log_dir.clone(),
            false,
            runtime.definition.settings.clone(),
        );
        context.invocation = ModuleInvocation::Trigger(TriggerInvocation {
            trigger_id: dispatch.trigger_id.clone(),
            incident_id: dispatch.incident_id.clone(),
            fired_at: dispatch.fired_at,
        });
        runtime.status = RuntimeStatus::Running;
        runtime.message = format!("trigger {} in progress", dispatch.trigger_id);
        runtime.last_started_at = Some(Local::now().to_rfc3339());
        runtime.last_error = None;

        let outcome = modules::run_once(&runtime.kind, &mut context);
        let completed = Local::now().to_rfc3339();
        runtime.last_exit_at = Some(completed.clone());
        runtime.last_run_at = Some(completed);
        runtime.runs = runtime.runs.saturating_add(1);
        match outcome {
            Ok(status) => {
                runtime.restarts = 0;
                runtime.status = RuntimeStatus::Scheduled;
                runtime.message = status
                    .and_then(|value| value.message)
                    .unwrap_or_else(|| format!("trigger {} completed", dispatch.trigger_id));
            }
            Err(error) => {
                runtime.restarts = runtime.restarts.saturating_add(1);
                runtime.last_error = Some(error.to_string());
                runtime.status = RuntimeStatus::Error;
                runtime.message = format!("trigger {} failed: {error}", dispatch.trigger_id);
            }
        }
        runtime.refresh_status();
        Ok(())
    }

    fn collect_sensor_requirements(&self) -> (BTreeSet<String>, BTreeSet<String>, bool) {
        let mut ssids = BTreeSet::new();
        let mut applications = BTreeSet::new();
        let mut needs_wifi_power = false;
        for trigger in self.triggers.values().filter(|trigger| {
            trigger.enabled()
                && !trigger.is_pending()
                && self
                    .modules
                    .get(trigger.module())
                    .is_some_and(|module| module.desired_enabled)
        }) {
            trigger.config().when.collect_sensor_requirements(
                &mut ssids,
                &mut applications,
                &mut needs_wifi_power,
            );
            if let FirePolicy::Latched { reset, .. } = &trigger.config().fire {
                reset.when.collect_sensor_requirements(
                    &mut ssids,
                    &mut applications,
                    &mut needs_wifi_power,
                );
            }
        }
        (ssids, applications, needs_wifi_power)
    }

    fn evaluate_and_dispatch(&mut self, now: DateTime<Utc>) -> Result<bool> {
        let enabled_modules = self
            .modules
            .iter()
            .filter(|(_, module)| module.desired_enabled)
            .map(|(id, _)| id.clone())
            .collect::<BTreeSet<_>>();
        let mut dispatches = collect_pending_dispatches(&mut self.triggers, &enabled_modules);
        let (ssids, applications, needs_wifi_power) = self.collect_sensor_requirements();
        let snapshot = self
            .sensors
            .snapshot(&ssids, &applications, needs_wifi_power);

        for (id, trigger) in &mut self.triggers {
            if dispatches.contains_key(id) {
                continue;
            }
            let target_enabled = self
                .modules
                .get(trigger.module())
                .is_some_and(|module| module.desired_enabled);
            if trigger.enabled() && target_enabled {
                if let Some(dispatch) = trigger.evaluate(now, &snapshot) {
                    dispatches.entry(id.clone()).or_insert(dispatch);
                }
            }
        }
        self.update_module_next_wakes();
        self.persist_if_changed()?;

        for dispatch in dispatches.values() {
            self.run_module_once(dispatch)?;
            if let Some(trigger) = self.triggers.get_mut(&dispatch.trigger_id) {
                trigger.mark_dispatched(&dispatch.incident_id);
            }
        }
        self.update_module_next_wakes();
        self.persist_if_changed()?;
        Ok(!dispatches.is_empty())
    }

    fn update_module_next_wakes(&mut self) {
        for module in self.modules.values_mut() {
            module.next_run_at = self
                .triggers
                .values()
                .filter(|trigger| {
                    trigger.enabled() && trigger.module() == module.id && module.desired_enabled
                })
                .filter_map(TriggerRuntime::next_wake)
                .min();
        }
    }

    fn apply_reload(&mut self) {
        let result = read_state_config(&self.root)
            .and_then(|(config, registry)| self.apply_service_config(config, registry));
        if let Err(error) = result {
            let message =
                format!("configuration reload rejected; retaining last valid triggers: {error}");
            crate::logger::append_warn(&self.log_dir.join("scriptd.log"), &message);
        }
    }

    async fn run_event_loop(&mut self) -> Result<()> {
        self.persist_if_changed()?;
        let mut sigint = signal(SignalKind::interrupt()).context("install SIGINT handler")?;
        let mut sigterm = signal(SignalKind::terminate()).context("install SIGTERM handler")?;
        let mut sighup = signal(SignalKind::hangup()).context("install SIGHUP handler")?;

        loop {
            self.evaluate_and_dispatch(Utc::now())?;
            let mut delay = self.next_run_delay(Utc::now());
            if delay == Duration::ZERO {
                delay = Duration::from_millis(250);
            }
            let wakeup_at = Instant::now() + delay;

            if self.reload_receiver.is_some() {
                select! {
                    _ = sleep_until(wakeup_at) => {}
                    event = receive_optional_event(&mut self.reload_receiver) => {
                        if event.is_some() {
                            sleep(Duration::from_millis(250)).await;
                            if let Some(receiver) = self.reload_receiver.as_mut() {
                                while receiver.try_recv().is_ok() {}
                            }
                            self.apply_reload();
                        } else {
                            self.reload_receiver = None;
                            self.watcher = None;
                        }
                    }
                    event = receive_optional_event(&mut self.wifi_event_receiver) => {
                        if event.is_none() {
                            self.wifi_event_receiver = None;
                            self.wifi_event_watcher = None;
                        }
                    }
                    _ = sighup.recv() => self.apply_reload(),
                    _ = sigint.recv() => return self.stop(),
                    _ = sigterm.recv() => return self.stop(),
                }
            } else {
                select! {
                    _ = sleep_until(wakeup_at) => {}
                    event = receive_optional_event(&mut self.wifi_event_receiver) => {
                        if event.is_none() {
                            self.wifi_event_receiver = None;
                            self.wifi_event_watcher = None;
                        }
                    }
                    _ = sighup.recv() => self.apply_reload(),
                    _ = sigint.recv() => return self.stop(),
                    _ = sigterm.recv() => return self.stop(),
                }
            }
        }
    }

    fn stop(&mut self) -> Result<()> {
        for runtime in self.modules.values_mut() {
            runtime.status = RuntimeStatus::Stopped;
            runtime.message = "supervisor stopped".to_string();
        }
        self.persist_if_changed()
    }
}

fn validate_persisted_state_origin(
    state: &PersistedState,
    root: &Path,
    config: &ServiceConfig,
) -> Result<()> {
    if state.label != config.label {
        anyhow::bail!(
            "persisted state label {} does not match service label {}",
            state.label,
            config.label
        );
    }
    if Path::new(&state.root_dir) != root {
        anyhow::bail!(
            "persisted state belongs to repo root {}, not {}",
            state.root_dir,
            root.display()
        );
    }
    if Path::new(&state.config_path) != config.path {
        anyhow::bail!(
            "persisted state belongs to config {}, not {}",
            state.config_path,
            config.path.display()
        );
    }
    Ok(())
}

fn collect_pending_dispatches(
    triggers: &mut BTreeMap<String, TriggerRuntime>,
    enabled_modules: &BTreeSet<String>,
) -> BTreeMap<String, TriggerDispatch> {
    let mut dispatches = BTreeMap::new();
    for (id, trigger) in triggers {
        let Some(dispatch) = trigger.pending_dispatch() else {
            continue;
        };
        if trigger.enabled() && enabled_modules.contains(trigger.module()) {
            dispatches.insert(id.clone(), dispatch);
        } else {
            trigger.suppress_pending();
        }
    }
    dispatches
}

async fn receive_optional_event(receiver: &mut Option<UnboundedReceiver<()>>) -> Option<()> {
    match receiver.as_mut() {
        Some(receiver) => receiver.recv().await,
        None => std::future::pending().await,
    }
}

fn build_trigger_runtimes(
    config: &ServiceConfig,
    now: DateTime<Utc>,
    restored: Option<&BTreeMap<String, PersistedTriggerState>>,
) -> BTreeMap<String, TriggerRuntime> {
    config
        .triggers
        .iter()
        .map(|(id, trigger)| {
            let state = restored
                .and_then(|states| states.get(id).or_else(|| states.get(legacy_trigger_id(id))))
                .filter(|saved| saved.target == trigger.module)
                .map(|saved| restored_trigger_state(saved, trigger));
            (
                id.clone(),
                TriggerRuntime::new(id.clone(), trigger.clone(), now, state),
            )
        })
        .collect()
}

fn restored_trigger_state(
    saved: &PersistedTriggerState,
    trigger: &crate::triggers::TriggerConfig,
) -> crate::triggers::TriggerState {
    let mut state = saved.runtime.clone();
    let Some(saved_config) = saved.config.as_ref() else {
        state.next_schedule_deadlines.clear();
        state.match_count = 0;
        state.match_started_at = None;
        state.reset_count = 0;
        state.reset_started_at = None;
        if matches!(
            state.phase,
            crate::triggers::TriggerPhase::Armed | crate::triggers::TriggerPhase::Matching
        ) {
            state.phase = crate::triggers::TriggerPhase::Armed;
            state.incident_id = None;
        }
        return state;
    };
    if saved_config == trigger {
        return state;
    }

    state.next_schedule_deadlines.clear();
    state.match_count = 0;
    state.match_started_at = None;
    state.reset_count = 0;
    state.reset_started_at = None;

    match state.phase {
        crate::triggers::TriggerPhase::Latched => {
            if !matches!(&trigger.fire, FirePolicy::Latched { .. }) {
                state.phase = crate::triggers::TriggerPhase::Armed;
                state.incident_id = None;
            }
        }
        crate::triggers::TriggerPhase::Pending => {
            state.phase = if matches!(&trigger.fire, FirePolicy::Latched { .. }) {
                crate::triggers::TriggerPhase::Latched
            } else {
                state.incident_id = None;
                crate::triggers::TriggerPhase::Armed
            };
        }
        crate::triggers::TriggerPhase::Armed | crate::triggers::TriggerPhase::Matching => {
            state.phase = crate::triggers::TriggerPhase::Armed;
            state.incident_id = None;
        }
    }
    state
}

fn read_state_config(root: &Path) -> Result<(ServiceConfig, ModulesRegistry)> {
    let config = config::read_service_config(root).context("read service configuration")?;
    let registry = ModulesRegistry::load_from_disk(&config).context("load module registry")?;
    for (id, trigger) in &config.triggers {
        if registry.get(&trigger.module).is_none() {
            anyhow::bail!("trigger {id} targets unknown module {}", trigger.module);
        }
    }
    Ok((config, registry))
}

fn legacy_trigger_id(canonical_id: &str) -> &str {
    match canonical_id {
        "mbrew.maintenance" => "mbrew-maintenance",
        "mcpu.sample" => "mcpu-sample",
        "mwifi.sample" => "mwifi-sample",
        "miwatch.outage" => "miwatch-outage",
        _ => canonical_id,
    }
}

pub fn run_supervisor(root: PathBuf) -> Result<()> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("build tokio runtime")?;
    runtime.block_on(run_supervisor_async(root))
}

pub fn run_one_module(root: PathBuf, module: &str) -> Result<()> {
    let (config, registry) = read_state_config(&root)?;
    let kind = BuiltInModule::kind_from_id(module).context("module not compiled")?;
    let definition = registry
        .get(module)
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("module \"{module}\" not found"))?;
    let mut context = modules::module_context_with_settings(
        module,
        root,
        definition.dir,
        config.expanded_log_dir(),
        true,
        definition.settings,
    );
    context.invocation = ModuleInvocation::Manual;
    println!("Running {module}...");
    modules::run_once(&kind, &mut context)?;
    println!("Completed {module}.");
    Ok(())
}

async fn run_supervisor_async(root: PathBuf) -> Result<()> {
    let (config, registry) = read_state_config(&root)?;
    let update_interval = config.self_update_check_interval();
    let singleton_lock = acquire_singleton_lock(&config)?;
    let mut supervisor = RunningSupervisor::build(&root, config, registry, singleton_lock)?;
    if supervisor.watch {
        supervisor.start_watcher()?;
    }

    let update_root = supervisor.root.clone();
    let update_log_dir = supervisor.log_dir.clone();
    let update_binary = std::env::current_exe().context("resolve current executable")?;
    tokio::spawn(async move {
        loop {
            sleep(update_interval).await;
            match sources_newer_than_binary(&update_root, &update_binary) {
                Ok(true) => {
                    let message =
                        "Detected newer source files; restarting to pick up the latest build";
                    crate::logger::append_info(&update_log_dir.join("scriptd.log"), message);
                    let _ = request_self_restart();
                }
                Ok(false) => {}
                Err(error) => {
                    crate::logger::append_warn(
                        &update_log_dir.join("scriptd.log"),
                        &format!("self-update check failed: {error}"),
                    );
                }
            }
        }
    });

    supervisor.run_event_loop().await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::triggers::{TriggerConfig, TriggerPhase, TriggerState};
    use chrono::TimeZone;

    #[test]
    fn compatible_reload_restores_a_latched_incident() {
        let config: ServiceConfig = serde_yaml::from_str(
            r#"
version: 1
service: { label: com.test.scriptd, log_dir: /tmp/logs }
modules:
  miwatch:
    enabled: false
    triggers:
      outage:
        enabled: true
        fire:
          mode: latched
          after: { consecutive_matches: 1, minimum_seconds: 0 }
          reset:
            after: { consecutive_matches: 1, minimum_seconds: 0 }
            when: { wifi_ssid: { ssid: test, state: connected } }
        when: { wifi_ssid: { ssid: test, state: unavailable } }
"#,
        )
        .expect("config");
        let saved = BTreeMap::from([(
            "miwatch.outage".to_string(),
            PersistedTriggerState {
                target: "miwatch".to_string(),
                enabled: true,
                config: None,
                next_wake_at: None,
                runtime: crate::triggers::TriggerState {
                    phase: TriggerPhase::Latched,
                    incident_id: Some("outage:1".to_string()),
                    generation: 1,
                    ..crate::triggers::TriggerState::default()
                },
            },
        )]);
        let runtimes = build_trigger_runtimes(&config, Utc::now(), Some(&saved));
        assert_eq!(
            runtimes["miwatch.outage"].state.phase,
            TriggerPhase::Latched
        );
        assert_eq!(
            runtimes["miwatch.outage"].state.incident_id.as_deref(),
            Some("outage:1")
        );
    }

    #[test]
    fn legacy_trigger_ids_restore_into_canonical_ids() {
        let config: ServiceConfig = serde_yaml::from_str(
            r#"
version: 1
service: { label: com.test.scriptd, log_dir: /tmp/logs }
modules:
  mbrew:
    enabled: true
    triggers:
      maintenance:
        enabled: true
        fire: { mode: every_match }
        when: { schedule: { every_minutes: 1 } }
  mcpu:
    enabled: true
    triggers:
      sample:
        enabled: true
        fire: { mode: every_match }
        when: { schedule: { every_minutes: 1 } }
  mwifi:
    enabled: true
    triggers:
      sample:
        enabled: true
        fire: { mode: every_match }
        when: { schedule: { every_minutes: 1 } }
  miwatch:
    enabled: false
    triggers:
      outage:
        enabled: true
        fire:
          mode: latched
          after: { consecutive_matches: 1, minimum_seconds: 0 }
          reset:
            after: { consecutive_matches: 1, minimum_seconds: 0 }
            when: { wifi_power: { state: on } }
        when: { wifi_power: { state: off } }
"#,
        )
        .expect("config");
        let saved = [
            ("mbrew-maintenance", "mbrew", "mbrew:1"),
            ("mcpu-sample", "mcpu", "mcpu:2"),
            ("mwifi-sample", "mwifi", "mwifi:3"),
            ("miwatch-outage", "miwatch", "miwatch:4"),
        ]
        .into_iter()
        .map(|(id, target, incident_id)| {
            (
                id.to_string(),
                PersistedTriggerState {
                    target: target.to_string(),
                    enabled: true,
                    config: None,
                    next_wake_at: None,
                    runtime: TriggerState {
                        phase: if target == "miwatch" {
                            TriggerPhase::Latched
                        } else {
                            TriggerPhase::Pending
                        },
                        generation: 1,
                        incident_id: Some(incident_id.to_string()),
                        ..TriggerState::default()
                    },
                },
            )
        })
        .collect::<BTreeMap<_, _>>();

        let runtimes = build_trigger_runtimes(&config, Utc::now(), Some(&saved));

        for (canonical_id, incident_id) in [
            ("mbrew.maintenance", "mbrew:1"),
            ("mcpu.sample", "mcpu:2"),
            ("mwifi.sample", "mwifi:3"),
            ("miwatch.outage", "miwatch:4"),
        ] {
            assert_eq!(
                runtimes[canonical_id].state.incident_id.as_deref(),
                Some(incident_id)
            );
        }
    }

    #[test]
    fn restored_pending_dispatch_requires_both_trigger_and_module_enablement() {
        for (trigger_enabled, module_enabled) in [(false, true), (true, false)] {
            let config: TriggerConfig = serde_yaml::from_str(&format!(
                r#"
enabled: {trigger_enabled}
module: miwatch
fire:
  mode: latched
  after: {{ consecutive_matches: 1, minimum_seconds: 0 }}
  reset:
    after: {{ consecutive_matches: 1, minimum_seconds: 0 }}
    when: {{ wifi_power: {{ state: on }} }}
when: {{ wifi_power: {{ state: off }} }}
"#
            ))
            .expect("trigger config");
            let now = Utc::now();
            let restored = TriggerState {
                phase: TriggerPhase::Pending,
                generation: 1,
                incident_id: Some("outage:1".to_string()),
                last_fired_at: Some(now),
                ..TriggerState::default()
            };
            let mut triggers = BTreeMap::from([(
                "outage".to_string(),
                TriggerRuntime::new("outage".to_string(), config, now, Some(restored)),
            )]);
            let enabled_modules = if module_enabled {
                BTreeSet::from(["miwatch".to_string()])
            } else {
                BTreeSet::new()
            };

            let dispatches = collect_pending_dispatches(&mut triggers, &enabled_modules);

            assert!(dispatches.is_empty());
            assert_eq!(triggers["outage"].state.phase, TriggerPhase::Latched);
        }
    }

    #[test]
    fn restored_pending_dispatch_is_retained_when_automation_is_enabled() {
        let config: TriggerConfig = serde_yaml::from_str(
            r#"
enabled: true
module: miwatch
fire: { mode: every_match }
when: { schedule: { every_minutes: 1 } }
"#,
        )
        .expect("trigger config");
        let now = Utc::now();
        let restored = TriggerState {
            phase: TriggerPhase::Pending,
            generation: 2,
            incident_id: Some("sample:2".to_string()),
            last_fired_at: Some(now),
            ..TriggerState::default()
        };
        let mut triggers = BTreeMap::from([(
            "sample".to_string(),
            TriggerRuntime::new("sample".to_string(), config, now, Some(restored)),
        )]);

        let dispatches =
            collect_pending_dispatches(&mut triggers, &BTreeSet::from(["miwatch".to_string()]));

        assert_eq!(dispatches["sample"].incident_id, "sample:2");
        assert_eq!(triggers["sample"].state.phase, TriggerPhase::Pending);
    }

    #[test]
    fn schedule_edits_recompute_deadlines_while_preserving_runtime_state() {
        let old_trigger: TriggerConfig = serde_yaml::from_str(
            r#"
enabled: true
module: mcpu
fire: { mode: every_match }
when: { schedule: { every_hours: 1 } }
"#,
        )
        .expect("old trigger");
        let config: ServiceConfig = serde_yaml::from_str(
            r#"
version: 1
service: { label: com.test.scriptd, log_dir: /tmp/logs }
modules:
  mcpu:
    enabled: true
    triggers:
      sample:
        enabled: true
        fire: { mode: every_match }
        when: { schedule: { every_minutes: 1 } }
"#,
        )
        .expect("new service config");
        let now = Utc
            .with_ymd_and_hms(2026, 7, 30, 0, 0, 0)
            .single()
            .expect("fixed time");
        let old_deadline = now + chrono::Duration::hours(1);
        let saved = BTreeMap::from([(
            "mcpu.sample".to_string(),
            PersistedTriggerState {
                target: "mcpu".to_string(),
                enabled: true,
                config: Some(old_trigger),
                next_wake_at: Some(old_deadline.to_rfc3339()),
                runtime: TriggerState {
                    generation: 7,
                    next_schedule_deadlines: vec![old_deadline],
                    ..TriggerState::default()
                },
            },
        )]);

        let runtimes = build_trigger_runtimes(&config, now, Some(&saved));

        assert_eq!(runtimes["mcpu.sample"].state.generation, 7);
        assert_eq!(
            runtimes["mcpu.sample"].next_wake(),
            Some(now + chrono::Duration::minutes(1))
        );
    }

    #[test]
    fn changed_rule_suppresses_a_stale_pending_incident_but_keeps_the_latch() {
        let old_trigger: TriggerConfig = serde_yaml::from_str(
            r#"
enabled: true
module: miwatch
fire:
  mode: latched
  after: { consecutive_matches: 1, minimum_seconds: 0 }
  reset:
    after: { consecutive_matches: 1, minimum_seconds: 0 }
    when: { wifi_power: { state: on } }
when: { wifi_ssid: { ssid: old-network, state: unavailable } }
"#,
        )
        .expect("old trigger");
        let config: ServiceConfig = serde_yaml::from_str(
            r#"
version: 1
service: { label: com.test.scriptd, log_dir: /tmp/logs }
modules:
  miwatch:
    enabled: true
    triggers:
      outage:
        enabled: true
        fire:
          mode: latched
          after: { consecutive_matches: 1, minimum_seconds: 0 }
          reset:
            after: { consecutive_matches: 1, minimum_seconds: 0 }
            when: { wifi_power: { state: on } }
        when: { wifi_ssid: { ssid: new-network, state: unavailable } }
"#,
        )
        .expect("new config");
        let now = Utc::now();
        let saved = BTreeMap::from([(
            "miwatch.outage".to_string(),
            PersistedTriggerState {
                target: "miwatch".to_string(),
                enabled: true,
                config: Some(old_trigger),
                next_wake_at: None,
                runtime: TriggerState {
                    phase: TriggerPhase::Pending,
                    generation: 3,
                    incident_id: Some("outage:3".to_string()),
                    last_fired_at: Some(now),
                    ..TriggerState::default()
                },
            },
        )]);

        let runtimes = build_trigger_runtimes(&config, now, Some(&saved));
        let runtime = &runtimes["miwatch.outage"];

        assert!(runtime.pending_dispatch().is_none());
        assert_eq!(runtime.state.phase, TriggerPhase::Latched);
        assert_eq!(runtime.state.generation, 3);
    }

    #[test]
    fn a_closed_optional_event_source_can_be_disabled_for_polling_fallback() {
        let (sender, receiver) = unbounded_channel();
        drop(sender);
        let mut receiver = Some(receiver);
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("runtime");

        assert!(runtime
            .block_on(receive_optional_event(&mut receiver))
            .is_none());
        receiver = None;
        assert!(receiver.is_none());
    }

    #[test]
    fn persisted_trigger_state_from_another_root_is_rejected() {
        let mut config: ServiceConfig = serde_yaml::from_str(
            "version: 1\nservice: { label: com.test.scriptd, log_dir: /tmp/logs }\nmodules: {}\n",
        )
        .expect("config");
        config.path = PathBuf::from("/current/service.yaml");
        let state = PersistedState {
            label: config.label.clone(),
            root_dir: "/other".to_string(),
            config_path: config.path.to_string_lossy().to_string(),
            log_dir: "/tmp/logs".to_string(),
            updated_at: Utc::now().to_rfc3339(),
            supervisor: PersistedSupervisorState {
                pid: 1,
                started_at: Utc::now().to_rfc3339(),
                watch: true,
            },
            modules: BTreeMap::new(),
            triggers: BTreeMap::new(),
        };

        let error = validate_persisted_state_origin(&state, Path::new("/current"), &config)
            .expect_err("foreign state must fail closed");

        assert!(error.to_string().contains("another") || error.to_string().contains("/other"));
    }
}
