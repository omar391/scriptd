use std::collections::BTreeMap;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result};
use chrono::{DateTime, Local};
use notify::event::EventKind;
use notify::{RecommendedWatcher, RecursiveMode, Watcher};
use sysinfo::{Pid, ProcessesToUpdate, System};
use tokio::select;
use tokio::signal::unix::{signal, SignalKind};
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender};
use tokio::time::{sleep, sleep_until, Instant};

use crate::config::{self, ModuleSchedule, ServiceConfig, ServiceModuleConfig};
use crate::modules::{self, BuiltInModule, ModuleDefinition, ModulesRegistry};
use crate::status::{PersistedModuleState, PersistedState, PersistedSupervisorState};

const SOURCE_STALENESS_TOLERANCE: Duration = Duration::from_secs(1);

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
            RuntimeStatus::Disabled => "disabled",
            RuntimeStatus::Scheduled => "scheduled",
            RuntimeStatus::Running => "running",
            RuntimeStatus::Error => "error",
            RuntimeStatus::Stopped => "stopped",
        }
    }
}

#[derive(Debug)]
struct ModuleRuntime {
    id: String,
    definition: ModuleDefinition,
    kind: BuiltInModule,
    schedule: Option<ModuleSchedule>,
    desired_enabled: bool,
    status: RuntimeStatus,
    mode: String,
    runs: u64,
    restarts: u64,
    message: String,
    last_started_at: Option<String>,
    last_run_at: Option<String>,
    last_exit_at: Option<String>,
    next_run_at: Option<DateTime<Local>>,
    last_error: Option<String>,
    health: Option<serde_json::Value>,
    module_status: Option<serde_json::Value>,
}

impl ModuleRuntime {
    fn from_definition(definition: ModuleDefinition) -> Self {
        let kind = BuiltInModule::kind_from_id(&definition.id).unwrap_or(BuiltInModule::CpuMonitor);
        Self {
            id: definition.id.clone(),
            mode: definition.manifest.mode.clone(),
            definition,
            kind,
            schedule: None,
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
        let kind = BuiltInModule::kind_from_id(&definition.id).unwrap_or(self.kind);
        self.id = definition.id.clone();
        self.definition = definition;
        self.kind = kind;
        self.mode = self.definition.manifest.mode.clone();
    }

    fn plan_next(&self, now: DateTime<Local>) -> Option<config::IntervalPlan> {
        Some(config::build_interval_plan(
            self.desired_enabled,
            self.status == RuntimeStatus::Running,
            &self.schedule,
            now,
        ))
    }

    fn apply_schedule(&mut self, now: DateTime<Local>) {
        let plan = config::build_interval_plan(
            self.desired_enabled,
            self.status == RuntimeStatus::Running,
            &self.schedule,
            now,
        );
        if plan.should_schedule {
            self.next_run_at = plan.next_run_at;
            self.status = RuntimeStatus::Scheduled;
            if let Some(next_run_at) = self.next_run_at {
                self.message = format!("next run at {next_run_at}");
            }
        } else {
            self.next_run_at = None;
            if self.desired_enabled {
                self.status = RuntimeStatus::Disabled;
                self.message = "scheduled run unavailable".to_string();
            } else {
                self.status = RuntimeStatus::Disabled;
                self.message = "module disabled".to_string();
            }
        }
    }

    fn refresh_status(&mut self) {
        if let Some((status, health)) = modules::module_status(&self.kind) {
            if let Ok(value) = serde_json::to_value(health) {
                self.health = Some(value);
            } else {
                self.health = None;
            }

            let status_message = status.message.clone();
            if let Ok(value) = serde_json::to_value(status) {
                self.module_status = Some(value);
                if self.last_error.is_none() && status_message.is_some() {
                    self.message = status_message.unwrap_or_else(|| "running".to_string());
                }
            } else {
                self.module_status = None;
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
                if let Some(pid) = existing_pid {
                    if process_is_alive(pid) {
                        anyhow::bail!("scriptd root supervisor is already running with pid {pid}");
                    }
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
    watcher: Option<RecommendedWatcher>,
    reload_receiver: Option<UnboundedReceiver<()>>,
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
    let tracked_paths = [
        root.join("Cargo.toml"),
        root.join("Cargo.lock"),
        root.join("build.rs"),
        root.join("src"),
        root.join("modules"),
    ];

    for path in tracked_paths {
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
    ) -> Self {
        let mut modules = BTreeMap::new();
        for definition in registry.modules() {
            let mut runtime = ModuleRuntime::from_definition(definition.clone());
            runtime.desired_enabled = config
                .modules
                .get(&definition.id)
                .is_some_and(|entry| entry.enabled);
            runtime.schedule =
                module_definition_schedule(definition, config.modules.get(&definition.id));
            runtime.apply_schedule(Local::now());
            runtime.refresh_status();
            modules.insert(definition.id.clone(), runtime);
        }

        RunningSupervisor {
            _singleton_lock: singleton_lock,
            root: root.to_path_buf(),
            state_file: config.state_file.clone(),
            config_path: config.path.clone(),
            log_dir: config.expanded_log_dir(),
            label: config.label.clone(),
            started_at: Local::now().to_rfc3339(),
            watch: config.watch,
            modules,
            watcher: None,
            reload_receiver: None,
            last_state_fingerprint: None,
        }
    }

    fn start_watcher(&mut self, path: &Path) -> Result<()> {
        if !self.watch {
            return Ok(());
        }

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
            .watch(path, RecursiveMode::NonRecursive)
            .context("watch service config")?;
        self.watcher = Some(watcher);
        self.reload_receiver = Some(rx);
        Ok(())
    }

    fn apply_service_config(&mut self, config: ServiceConfig, registry: ModulesRegistry) {
        self.watch = config.watch;
        self.started_at = Local::now().to_rfc3339();
        self.label = config.label;

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
            entry.schedule =
                module_definition_schedule(definition, config.modules.get(&definition.id));
            entry.apply_schedule(Local::now());
            entry.refresh_status();
        }

        self.modules.retain(|id, _| registry.get(id).is_some());
    }

    fn next_run_delay(&self, now: DateTime<Local>) -> Duration {
        let mut next: Option<Duration> = None;
        for runtime in self.modules.values() {
            if !runtime.desired_enabled {
                continue;
            }
            if let Some(run_at) = runtime.next_run_at {
                let delta = run_at
                    .signed_duration_since(now)
                    .to_std()
                    .unwrap_or_default();
                next = Some(match next {
                    Some(existing) if existing <= delta => existing,
                    _ => delta,
                });
            }
        }
        next.unwrap_or(Duration::from_secs(60 * 60))
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
        }))?;
        if self
            .last_state_fingerprint
            .as_ref()
            .is_some_and(|value| value == &fingerprint)
        {
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
        };

        let json = serde_json::to_string_pretty(&state)?;
        if let Some(parent) = self.state_file.parent() {
            std::fs::create_dir_all(parent).context("ensure state directory")?;
        }

        let tmp = self
            .state_file
            .with_extension(format!("{}.tmp", std::process::id()));
        std::fs::write(&tmp, &json).context("write temporary state")?;
        std::fs::rename(&tmp, &self.state_file).context("install state file")?;
        self.last_state_fingerprint = Some(fingerprint);
        Ok(())
    }

    fn run_module_once(&mut self, module_id: &str, now: DateTime<Local>) -> Result<()> {
        let Some(runtime) = self.modules.get_mut(module_id) else {
            return Ok(());
        };

        let mut context = modules::module_context(
            &runtime.id,
            self.root.clone(),
            runtime.definition.dir.clone(),
            self.log_dir.clone(),
        );

        runtime.status = RuntimeStatus::Running;
        runtime.message = "interval run in progress".to_string();
        runtime.last_started_at = Some(now.to_rfc3339());
        runtime.last_error = None;

        let outcome = modules::run_once(&runtime.kind, &mut context, &runtime.schedule);
        let completed = Local::now();
        runtime.last_exit_at = Some(completed.to_rfc3339());
        runtime.last_run_at = runtime.last_exit_at.clone();
        runtime.runs = runtime.runs.saturating_add(1);

        match outcome {
            Ok(status) => {
                runtime.restarts = 0;
                runtime.status = RuntimeStatus::Scheduled;
                runtime.message = status
                    .and_then(|value| value.message)
                    .unwrap_or_else(|| "interval run completed".to_string());
            }
            Err(error) => {
                runtime.restarts = runtime.restarts.saturating_add(1);
                runtime.last_error = Some(error.to_string());
                runtime.status = RuntimeStatus::Error;
                runtime.message = format!("interval run failed: {error}");
            }
        }

        runtime.refresh_status();
        runtime.apply_schedule(Local::now());
        Ok(())
    }

    fn schedule_and_run_due_modules(&mut self, now: DateTime<Local>) -> Result<bool> {
        let mut changed = false;
        let mut due = Vec::<String>::new();

        for (id, runtime) in self.modules.iter_mut() {
            if runtime.last_error.is_some() {
                runtime.last_error = None;
            }

            if !runtime.desired_enabled {
                if runtime.status != RuntimeStatus::Disabled {
                    runtime.status = RuntimeStatus::Disabled;
                    runtime.next_run_at = None;
                    runtime.message = "module disabled".to_string();
                    changed = true;
                }
                continue;
            }

            if runtime.status == RuntimeStatus::Running {
                continue;
            }

            let plan = runtime.plan_next(now).unwrap_or_else(|| {
                config::build_interval_plan(false, false, &runtime.schedule, now)
            });

            if !plan.should_schedule {
                if runtime.status != RuntimeStatus::Disabled {
                    runtime.apply_schedule(now);
                    changed = true;
                }
                continue;
            }

            runtime.next_run_at = plan.next_run_at;

            if plan.delay_ms.unwrap_or(0) == 0 {
                runtime.status = RuntimeStatus::Running;
                due.push(id.clone());
                changed = true;
            } else if runtime.status != RuntimeStatus::Scheduled {
                runtime.status = RuntimeStatus::Scheduled;
                changed = true;
            }
        }

        for id in due {
            self.run_module_once(&id, now)?;
            changed = true;
        }

        Ok(changed)
    }

    fn refresh_module_statuses(&mut self) {
        for runtime in self.modules.values_mut() {
            runtime.refresh_status();
        }
    }

    async fn run_event_loop(&mut self) -> Result<()> {
        self.persist_if_changed()?;
        let mut sigint = signal(SignalKind::interrupt()).context("install SIGINT handler")?;
        let mut sigterm = signal(SignalKind::terminate()).context("install SIGTERM handler")?;
        let mut sighup = signal(SignalKind::hangup()).context("install SIGHUP handler")?;

        loop {
            let now = Local::now();
            let mut changed = self.schedule_and_run_due_modules(now)?;

            if changed {
                self.persist_if_changed()?;
            }

            let mut delay = self.next_run_delay(now);
            if delay == Duration::ZERO {
                delay = Duration::from_millis(250);
            }
            let wakeup_at = Instant::now() + delay;

            if self.reload_receiver.is_some() {
                select! {
                        _ = sleep_until(wakeup_at) => {
                            changed = false;
                        }
                        _ = self.reload_receiver.as_mut().unwrap().recv() => {
                            sleep(Duration::from_millis(250)).await;
                            if let Some(receiver) = self.reload_receiver.as_mut() {
                                while receiver.try_recv().is_ok() {}
                            }
                            if let Ok((config, registry)) = read_state_config(&self.root) {
                                self.apply_service_config(config, registry);
                                self.refresh_module_statuses();
                                changed = true;
                            }
                        }
                _ = sigint.recv() => {
                            for runtime in self.modules.values_mut() {
                                runtime.status = RuntimeStatus::Stopped;
                                runtime.message = "supervisor stopped".to_string();
                            }
                            self.persist_if_changed()?;
                            return Ok(());
                        }
                        _ = sigterm.recv() => {
                            for runtime in self.modules.values_mut() {
                                runtime.status = RuntimeStatus::Stopped;
                                runtime.message = "supervisor stopped".to_string();
                            }
                            self.persist_if_changed()?;
                            return Ok(());
                        }
                        _ = sighup.recv() => {
                            if let Ok((config, registry)) = read_state_config(&self.root) {
                                self.apply_service_config(config, registry);
                                self.refresh_module_statuses();
                                changed = true;
                            }
                        }
                    }
            } else {
                select! {
                    _ = sleep_until(wakeup_at) => {
                        changed = false;
                    }
                    _ = sigint.recv() => {
                        for runtime in self.modules.values_mut() {
                            runtime.status = RuntimeStatus::Stopped;
                            runtime.message = "supervisor stopped".to_string();
                        }
                        self.persist_if_changed()?;
                        return Ok(());
                    }
                    _ = sigterm.recv() => {
                        for runtime in self.modules.values_mut() {
                            runtime.status = RuntimeStatus::Stopped;
                            runtime.message = "supervisor stopped".to_string();
                        }
                        self.persist_if_changed()?;
                        return Ok(());
                    }
                    _ = sighup.recv() => {
                        if let Ok((config, registry)) = read_state_config(&self.root) {
                            self.apply_service_config(config, registry);
                            self.refresh_module_statuses();
                            changed = true;
                        }
                    }
                }
            }

            if changed {
                self.persist_if_changed()?;
            }
        }
    }
}

fn module_definition_schedule(
    definition: &ModuleDefinition,
    service_entry: Option<&ServiceModuleConfig>,
) -> Option<ModuleSchedule> {
    service_entry
        .and_then(|entry| entry.schedule.clone())
        .or_else(|| {
            definition.manifest.interval_ms().and_then(|value| {
                Some(value / 1000)
                    .filter(|seconds| *seconds > 0)
                    .map(|seconds| ModuleSchedule {
                        every_seconds: Some(seconds),
                        ..ModuleSchedule::default()
                    })
            })
        })
}

fn read_state_config(root: &Path) -> Result<(ServiceConfig, ModulesRegistry)> {
    let config = config::read_service_config(root).context("read service configuration")?;
    let registry = ModulesRegistry::load_from_disk(&config).context("load module registry")?;
    Ok((config, registry))
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
    let module_schedule = module_definition_schedule(&definition, config.modules.get(module));
    let root_for_context = root.clone();
    let log_dir = config.expanded_log_dir();
    let module_dir = definition.dir.clone();
    let label = config.label.clone();
    let root_dir = config.root_dir.to_string_lossy().to_string();
    let config_path = config.path.to_string_lossy().to_string();
    let log_dir_path = log_dir.to_string_lossy().to_string();
    let watch = config.watch;

    let mut context =
        modules::module_context_with_console(module, root_for_context, module_dir, log_dir, true);
    let mut runtime = ModuleRuntime::from_definition(definition.clone());
    runtime.schedule = module_schedule;
    println!("Running {module}...");
    let status = modules::run_once(&kind, &mut context, &runtime.schedule)?;
    println!("Completed {module}.");

    let mut module_states = BTreeMap::new();
    let health = status
        .as_ref()
        .and_then(|_value| {
            modules::module_status(&kind).and_then(|(_, health)| serde_json::to_value(health).ok())
        })
        .or_else(|| Some(serde_json::json!({ "ok": true })));

    let message = status
        .as_ref()
        .and_then(|value| value.message.clone())
        .unwrap_or_else(|| "ok".to_string());
    module_states.insert(
        kind.id().to_string(),
        PersistedModuleState {
            desired_enabled: true,
            status: "running".to_string(),
            mode: definition.manifest.mode.clone(),
            last_started_at: Some(Local::now().to_rfc3339()),
            last_run_at: Some(Local::now().to_rfc3339()),
            last_exit_at: None,
            next_run_at: runtime.next_run_at.map(|value| value.to_rfc3339()),
            runs: 1,
            restarts: 0,
            message,
            health,
            module_status: status
                .as_ref()
                .and_then(|value| serde_json::to_value(value.clone()).ok()),
            last_error: None,
        },
    );

    let state = PersistedState {
        label,
        root_dir,
        config_path,
        log_dir: log_dir_path,
        updated_at: Local::now().to_rfc3339(),
        supervisor: PersistedSupervisorState {
            pid: std::process::id() as i32,
            started_at: Local::now().to_rfc3339(),
            watch,
        },
        modules: module_states,
    };

    if let Some(parent) = config.state_file.parent() {
        std::fs::create_dir_all(parent).context("ensure state directory")?;
    }
    let json = serde_json::to_string_pretty(&state)?;
    let tmp = config
        .state_file
        .with_extension(format!("{}.tmp", std::process::id()));
    std::fs::write(&tmp, json).context("write temporary state")?;
    std::fs::rename(tmp, &config.state_file).context("install state file")?;
    Ok(())
}

async fn run_supervisor_async(root: PathBuf) -> Result<()> {
    let (config, registry) = read_state_config(&root)?;
    let update_interval = config.self_update_check_interval();
    let singleton_lock = acquire_singleton_lock(&config)?;
    let mut supervisor = RunningSupervisor::build(&root, config, registry, singleton_lock);
    if supervisor.watch {
        let config_path = supervisor.config_path.clone();
        supervisor.start_watcher(&config_path)?;
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
                    println!("{message}");
                    let _ = request_self_restart();
                }
                Ok(false) => {}
                Err(error) => {
                    let message = format!("self-update check failed: {error}");
                    crate::logger::append_warn(&update_log_dir.join("scriptd.log"), &message);
                    eprintln!("{message}");
                }
            }
        }
    });

    supervisor.persist_if_changed()?;
    supervisor.run_event_loop().await
}
