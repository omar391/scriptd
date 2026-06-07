#![allow(dead_code)]

use std::collections::HashMap;
use std::path::PathBuf;

#[path = "../modules/better-wifi/module.rs"]
mod better_wifi;
#[path = "../modules/brew-manager/module.rs"]
mod brew_manager;
#[path = "../modules/cpu-monitor/module.rs"]
mod cpu_monitor;

use crate::config::{ModuleManifest, ModuleSchedule, ServiceConfig};

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum ModuleMode {
    Interval,
    Daemon,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum BuiltInModule {
    BrewManager,
    CpuMonitor,
    BetterWifi,
}

impl BuiltInModule {
    pub fn id(&self) -> &'static str {
        match self {
            Self::BrewManager => "brew-manager",
            Self::CpuMonitor => "cpu-monitor",
            Self::BetterWifi => "better-wifi",
        }
    }

    pub fn mode(&self) -> ModuleMode {
        match self {
            Self::BrewManager => ModuleMode::Interval,
            Self::CpuMonitor => ModuleMode::Interval,
            Self::BetterWifi => ModuleMode::Interval,
        }
    }

    pub fn all() -> &'static [Self; 3] {
        &[Self::BrewManager, Self::CpuMonitor, Self::BetterWifi]
    }

    pub fn kind_from_id(id: &str) -> anyhow::Result<Self> {
        match id {
            "brew-manager" => Ok(Self::BrewManager),
            "cpu-monitor" => Ok(Self::CpuMonitor),
            "better-wifi" => Ok(Self::BetterWifi),
            other => anyhow::bail!("module \"{other}\" not compiled into this build"),
        }
    }
}

#[derive(Debug)]
pub struct ModulesRegistry {
    modules: HashMap<String, ModuleDefinition>,
}

#[derive(Debug, Clone)]
pub struct ModuleDefinition {
    pub id: String,
    pub manifest: ModuleManifest,
    pub dir: PathBuf,
    pub mode: ModuleMode,
}

impl ModulesRegistry {
    pub fn load_from_disk(config: &ServiceConfig) -> anyhow::Result<Self> {
        let mut modules = HashMap::new();
        for kind in BuiltInModule::all() {
            let id = kind.id();
            let manifest = crate::config::read_module_manifest(id, &config.root_dir)?;
            if manifest.manifest.mode != "interval" && manifest.manifest.mode != "daemon" {
                anyhow::bail!(
                    "module \"{id}\" has unsupported mode \"{}\"",
                    manifest.manifest.mode
                );
            }
            if manifest.manifest.mode == "interval" && manifest.manifest.interval_seconds.is_none()
            {
                anyhow::bail!("module \"{id}\" interval mode requires interval_seconds");
            }
            modules.insert(
                id.to_string(),
                ModuleDefinition {
                    id: id.to_string(),
                    manifest: manifest.manifest,
                    dir: manifest.dir,
                    mode: kind.mode(),
                },
            );
        }
        Ok(Self { modules })
    }

    pub fn get(&self, id: &str) -> Option<&ModuleDefinition> {
        self.modules.get(id)
    }

    pub fn modules(&self) -> impl Iterator<Item = &ModuleDefinition> {
        self.modules.values()
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use tempfile::tempdir;

    use crate::{config::ServiceConfig, modules::ModulesRegistry};
    use std::collections::HashMap;

    fn write_manifest(base: &std::path::Path, module_id: &str, mode: &str, interval: Option<u64>) {
        let dir = base.join("modules").join(module_id);
        fs::create_dir_all(&dir).expect("create module dir");
        let interval_line = interval
            .map(|value| format!("interval_seconds: {value}\n"))
            .unwrap_or_default();
        let body = format!(
            "id: {module_id}\nmode: {mode}\n{interval_line}",
            module_id = module_id,
            mode = mode,
            interval_line = interval_line
        );
        fs::write(dir.join("module.yaml"), body).expect("write manifest");
    }

    fn service_config(root: &std::path::Path) -> ServiceConfig {
        ServiceConfig {
            label: "com.test.scriptd".to_string(),
            log_dir: "/tmp/scriptd-test-logs".to_string(),
            watch: false,
            self_update_check_hours: 12,
            modules: HashMap::new(),
            path: root.join("service.yaml"),
            root_dir: root.to_path_buf(),
            state_dir: crate::paths::resolve_state_dir(),
            state_file: crate::paths::resolve_state_file(),
        }
    }

    #[test]
    fn modules_registry_loads_interval_modules_with_interval_metadata() {
        let temp = tempdir().expect("temp dir");
        let root = temp.path();
        write_manifest(root, "brew-manager", "interval", Some(30));
        write_manifest(root, "cpu-monitor", "interval", Some(30));
        write_manifest(root, "better-wifi", "interval", Some(10));

        let config = service_config(root);
        let registry = ModulesRegistry::load_from_disk(&config).expect("load built-ins");
        assert_eq!(registry.modules.len(), 3);
        assert!(registry.get("better-wifi").is_some());
        assert_eq!(
            registry
                .get("cpu-monitor")
                .expect("cpu")
                .manifest
                .interval_ms(),
            Some(30_000)
        );
    }

    #[test]
    fn modules_registry_rejects_interval_manifest_without_interval_seconds() {
        let temp = tempdir().expect("temp dir");
        let root = temp.path();
        write_manifest(root, "brew-manager", "interval", Some(30));
        write_manifest(root, "cpu-monitor", "interval", Some(30));
        write_manifest(root, "better-wifi", "interval", None);

        let config = service_config(root);
        let error =
            ModulesRegistry::load_from_disk(&config).expect_err("expected validation failure");
        assert!(error
            .to_string()
            .contains("interval mode requires interval_seconds"));
    }

    #[test]
    fn modules_registry_rejects_unknown_mode() {
        let temp = tempdir().expect("temp dir");
        let root = temp.path();
        write_manifest(root, "brew-manager", "interval", Some(30));
        write_manifest(root, "cpu-monitor", "daemon", Some(30));
        write_manifest(root, "better-wifi", "stream", Some(30));

        let config = service_config(root);
        let error = ModulesRegistry::load_from_disk(&config).expect_err("unknown mode");
        assert!(error.to_string().contains("unsupported mode"));
    }
}

#[derive(Clone, Debug)]
pub struct ModuleContext {
    pub id: String,
    pub repo_root: PathBuf,
    pub module_dir: PathBuf,
    pub log_dir: PathBuf,
    pub env: HashMap<String, String>,
    pub logger: ModuleLogger,
}

#[derive(Clone, Debug)]
pub struct ModuleLogger {
    module_id: String,
    out_path: PathBuf,
    err_path: PathBuf,
    mirror_to_console: bool,
}

impl ModuleLogger {
    pub fn new(log_dir: PathBuf, module_id: &str, mirror_to_console: bool) -> Self {
        Self {
            module_id: module_id.to_string(),
            out_path: log_dir.join(format!("{module_id}.log")),
            err_path: log_dir.join(format!("{module_id}.err")),
            mirror_to_console,
        }
    }

    pub fn info(&self, message: &str) {
        crate::logger::append_info(&self.out_path, message);
        if self.mirror_to_console {
            println!("[{}] INFO: {}", self.module_id, message);
        }
    }

    pub fn warn(&self, message: &str) {
        crate::logger::append_warn(&self.out_path, message);
        if self.mirror_to_console {
            println!("[{}] WARN: {}", self.module_id, message);
        }
    }

    pub fn error(&self, message: &str) {
        crate::logger::append_error(&self.err_path, message);
        if self.mirror_to_console {
            eprintln!("[{}] ERROR: {}", self.module_id, message);
        }
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ModuleStatus {
    pub state: String,
    pub message: Option<String>,
    #[serde(rename = "startedAt")]
    pub started_at: Option<String>,
    #[serde(rename = "lastRunAt")]
    pub last_run_at: Option<String>,
    #[serde(rename = "nextRunAt")]
    pub next_run_at: Option<String>,
    #[serde(default)]
    pub metrics: Option<HashMap<String, serde_json::Value>>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ModuleHealth {
    pub ok: bool,
    pub message: Option<String>,
}

pub fn module_context(
    id: &str,
    repo_root: PathBuf,
    module_dir: PathBuf,
    log_dir: PathBuf,
) -> ModuleContext {
    module_context_with_console(id, repo_root, module_dir, log_dir, false)
}

pub fn module_context_with_console(
    id: &str,
    repo_root: PathBuf,
    module_dir: PathBuf,
    log_dir: PathBuf,
    mirror_to_console: bool,
) -> ModuleContext {
    let mut env = std::env::vars().collect::<HashMap<_, _>>();
    env.insert(
        "SCRIPTD_ROOT_DIR".to_string(),
        repo_root.to_string_lossy().to_string(),
    );
    env.insert("SCRIPTD_MODULE_NAME".to_string(), id.to_string());
    env.insert(
        "SCRIPTD_MODULE_DIR".to_string(),
        module_dir.to_string_lossy().to_string(),
    );
    env.insert(
        "SCRIPTD_SHARED_LOG_DIR".to_string(),
        log_dir.to_string_lossy().to_string(),
    );

    ModuleContext {
        id: id.to_string(),
        repo_root,
        module_dir,
        log_dir: log_dir.clone(),
        env,
        logger: ModuleLogger::new(log_dir, id, mirror_to_console),
    }
}

pub fn run_once(
    kind: &BuiltInModule,
    context: &mut ModuleContext,
    _schedule: &Option<ModuleSchedule>,
) -> anyhow::Result<Option<ModuleStatus>> {
    match kind {
        BuiltInModule::BrewManager => brew_manager::run_once(context),
        BuiltInModule::CpuMonitor => cpu_monitor::run_once(context),
        BuiltInModule::BetterWifi => better_wifi::run_once(context),
    }
}

pub fn setup_module(kind: &BuiltInModule, context: &mut ModuleContext) -> anyhow::Result<()> {
    match kind {
        BuiltInModule::BrewManager => brew_manager::setup(context),
        BuiltInModule::CpuMonitor => cpu_monitor::setup(context),
        BuiltInModule::BetterWifi => better_wifi::setup(context),
    }
}

pub fn module_status(kind: &BuiltInModule) -> Option<(ModuleStatus, ModuleHealth)> {
    match kind {
        BuiltInModule::BrewManager => brew_manager::status(),
        BuiltInModule::CpuMonitor => cpu_monitor::status(),
        BuiltInModule::BetterWifi => better_wifi::status(),
    }
}
