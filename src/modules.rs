#![allow(dead_code)]

use std::collections::HashMap;
use std::path::PathBuf;

#[path = "../modules/mbrew/module.rs"]
pub(crate) mod mbrew;
#[path = "../modules/mcpu/module.rs"]
pub(crate) mod mcpu;
#[path = "../modules/miwatch/module.rs"]
pub(crate) mod miwatch;
#[path = "../modules/mwifi/module.rs"]
pub(crate) mod mwifi;

use crate::config::{ModuleManifest, ModuleSettings, ServiceConfig};

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum ModuleMode {
    Task,
    Daemon,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum BuiltInModule {
    Mbrew,
    Mcpu,
    Mwifi,
    Miwatch,
}

impl BuiltInModule {
    pub fn id(&self) -> &'static str {
        match self {
            Self::Mbrew => "mbrew",
            Self::Mcpu => "mcpu",
            Self::Mwifi => "mwifi",
            Self::Miwatch => "miwatch",
        }
    }

    pub fn mode(&self) -> ModuleMode {
        match self {
            Self::Mbrew => ModuleMode::Task,
            Self::Mcpu => ModuleMode::Task,
            Self::Mwifi => ModuleMode::Task,
            Self::Miwatch => ModuleMode::Task,
        }
    }

    pub fn all() -> &'static [Self; 4] {
        &[Self::Mbrew, Self::Mcpu, Self::Mwifi, Self::Miwatch]
    }

    pub fn kind_from_id(id: &str) -> anyhow::Result<Self> {
        match id {
            "mbrew" => Ok(Self::Mbrew),
            "mcpu" => Ok(Self::Mcpu),
            "mwifi" => Ok(Self::Mwifi),
            "miwatch" => Ok(Self::Miwatch),
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
    pub settings: ModuleSettings,
    pub dir: PathBuf,
    pub mode: ModuleMode,
}

impl ModulesRegistry {
    pub fn load_from_disk(config: &ServiceConfig) -> anyhow::Result<Self> {
        let mut modules = HashMap::new();
        for kind in BuiltInModule::all() {
            let id = kind.id();
            let manifest = crate::config::read_module_manifest(id, &config.root_dir)?;
            modules.insert(
                id.to_string(),
                ModuleDefinition {
                    id: id.to_string(),
                    manifest: manifest.manifest,
                    settings: manifest.settings,
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

    use crate::{
        config::ServiceConfig,
        modules::{ModuleMode, ModulesRegistry},
    };
    use std::collections::HashMap;

    fn write_manifest(base: &std::path::Path, module_id: &str, mode: &str) {
        let dir = base.join("modules").join(module_id);
        fs::create_dir_all(&dir).expect("create module dir");
        let settings = match module_id {
            "mbrew" => "settings:\n  askpass_path: /tmp/askpass\n  homebrew_bin: /opt/homebrew/bin/brew\n  sudoers_path: /tmp/sudoers\n  sudoers_timeout_path: /tmp/sudoers-timeout\n  sudo_timeout_hours: 2\n",
            "mcpu" => "settings:\n  cpu_threshold: 50\n  time_limit_seconds: 600\n  exclude_apps: []\n",
            "mwifi" => "settings:\n  min_dwell: 1\n  ping_target: 1.1.1.1\n  ping_count: 1\n  ping_timeout: 1\n  ping_high_latency_ms: 250\n  health_failure_switch_runs: 1\n  band_bonus_2g: 0\n  band_bonus_5g: 35\n  band_bonus_6g: 50\n  preference_top_bonus: 30\n  preference_rank_decay: 5\n  current_sticky_bonus: 25\n  rssi_offset: 100\n  min_switch_score_delta: 10\n",
            "miwatch" => "settings: {}\n",
            _ => "settings: {}\n",
        };
        let body = format!(
            "version: 1\nmodule:\n  id: {module_id}\n  display_name: {module_id}\n  mode: {mode}\n{settings}"
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
            triggers: Default::default(),
            path: root.join("service.yaml"),
            root_dir: root.to_path_buf(),
            state_dir: crate::paths::resolve_state_dir(),
            state_file: crate::paths::resolve_state_file(),
        }
    }

    #[test]
    fn modules_registry_loads_task_modules() {
        let temp = tempdir().expect("temp dir");
        let root = temp.path();
        write_manifest(root, "mbrew", "task");
        write_manifest(root, "mcpu", "task");
        write_manifest(root, "mwifi", "task");
        write_manifest(root, "miwatch", "task");

        let config = service_config(root);
        let registry = ModulesRegistry::load_from_disk(&config).expect("load built-ins");
        assert_eq!(registry.modules.len(), 4);
        assert!(registry.get("mwifi").is_some());
        assert_eq!(registry.get("mcpu").expect("cpu").mode, ModuleMode::Task);
    }

    #[test]
    fn modules_registry_rejects_unknown_mode() {
        let temp = tempdir().expect("temp dir");
        let root = temp.path();
        write_manifest(root, "mbrew", "task");
        write_manifest(root, "mcpu", "daemon");
        write_manifest(root, "mwifi", "stream");
        write_manifest(root, "miwatch", "task");

        let config = service_config(root);
        let error = ModulesRegistry::load_from_disk(&config).expect_err("unknown mode");
        assert!(error.to_string().contains("mode task"));
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
    pub invocation: ModuleInvocation,
    pub settings: Option<ModuleSettings>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ModuleInvocation {
    Manual,
    Trigger(TriggerInvocation),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TriggerInvocation {
    pub trigger_id: String,
    pub incident_id: String,
    pub fired_at: chrono::DateTime<chrono::Utc>,
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
        invocation: ModuleInvocation::Manual,
        settings: None,
    }
}

pub fn module_context_with_settings(
    id: &str,
    repo_root: PathBuf,
    module_dir: PathBuf,
    log_dir: PathBuf,
    mirror_to_console: bool,
    settings: ModuleSettings,
) -> ModuleContext {
    let mut context =
        module_context_with_console(id, repo_root, module_dir, log_dir, mirror_to_console);
    context.settings = Some(settings);
    context
}

pub fn run_once(
    kind: &BuiltInModule,
    context: &mut ModuleContext,
) -> anyhow::Result<Option<ModuleStatus>> {
    match kind {
        BuiltInModule::Mbrew => mbrew::run_once(context),
        BuiltInModule::Mcpu => mcpu::run_once(context),
        BuiltInModule::Mwifi => mwifi::run_once(context),
        BuiltInModule::Miwatch => miwatch::run_once(context),
    }
}

pub fn wifi_trigger_link_snapshot() -> crate::triggers::WifiSnapshot {
    mwifi::repository_wifi_link_snapshot()
}

pub fn wifi_trigger_visibility_snapshot(
    ssids: &[String],
) -> (Option<std::collections::BTreeSet<String>>, Option<String>) {
    mwifi::repository_wifi_visibility_snapshot(ssids)
}

pub fn setup_module(kind: &BuiltInModule, context: &mut ModuleContext) -> anyhow::Result<()> {
    match kind {
        BuiltInModule::Mbrew => mbrew::setup(context),
        BuiltInModule::Mcpu => mcpu::setup(context),
        BuiltInModule::Mwifi => mwifi::setup(context),
        BuiltInModule::Miwatch => miwatch::setup(context),
    }
}

pub fn refresh_session(kind: &BuiltInModule, context: &mut ModuleContext) -> anyhow::Result<()> {
    match kind {
        BuiltInModule::Miwatch => miwatch::refresh_session(context),
        _ => anyhow::bail!("session refresh is only supported by miwatch"),
    }
}

pub fn verify_remote(kind: &BuiltInModule, context: &mut ModuleContext) -> anyhow::Result<()> {
    match kind {
        BuiltInModule::Miwatch => miwatch::verify_remote(context),
        _ => anyhow::bail!("remote verification is only supported by miwatch"),
    }
}

pub fn import_session(
    kind: &BuiltInModule,
    context: &mut ModuleContext,
    input: &str,
) -> anyhow::Result<()> {
    match kind {
        BuiltInModule::Miwatch => miwatch::import_session(context, input),
        _ => anyhow::bail!("session import is only supported by miwatch"),
    }
}

pub fn module_status(kind: &BuiltInModule) -> Option<(ModuleStatus, ModuleHealth)> {
    match kind {
        BuiltInModule::Mbrew => mbrew::status(),
        BuiltInModule::Mcpu => mcpu::status(),
        BuiltInModule::Mwifi => mwifi::status(),
        BuiltInModule::Miwatch => miwatch::status(),
    }
}
