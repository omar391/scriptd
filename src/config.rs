use anyhow::{Context, Result};
use schemars::JsonSchema;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::path::{Path, PathBuf};

use crate::modules::{self, BuiltInModule};
use crate::paths::{
    expand_home, resolve_service_config_path, resolve_state_dir, resolve_state_file,
};
use crate::triggers::{Condition, FirePolicy, TriggerConfig, TriggerMap};

pub const CONFIG_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[schemars(description = "Versioned daemon-wide scriptd policy and module trigger document.")]
pub struct ServiceDocument {
    pub version: u32,
    pub service: ServiceSettings,
    #[serde(default)]
    pub modules: ServiceModulePolicies,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[schemars(description = "Shared daemon settings used by all modules.")]
pub struct ServiceSettings {
    #[schemars(length(min = 1))]
    pub label: String,
    #[schemars(length(min = 1))]
    pub log_dir: String,
    #[serde(default)]
    pub watch: bool,
    #[serde(default = "default_self_update_check_hours")]
    #[schemars(range(min = 1))]
    pub self_update_check_hours: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, Default)]
#[serde(deny_unknown_fields)]
#[schemars(description = "Enablement and trigger policy owned by one module.")]
pub struct ServiceModuleConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub triggers: BTreeMap<String, ScopedTriggerConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[schemars(description = "A Boolean trigger scoped to its parent module.")]
pub struct ScopedTriggerConfig {
    #[serde(default = "default_true", skip_serializing_if = "is_true")]
    pub enabled: bool,
    pub fire: FirePolicy,
    pub when: Condition,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, Default)]
#[serde(deny_unknown_fields)]
#[schemars(description = "The built-in module policy sections accepted by scriptd.")]
pub struct ServiceModulePolicies {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mbrew: Option<ServiceModuleConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mcpu: Option<ServiceModuleConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mwifi: Option<ServiceModuleConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub miwatch: Option<ServiceModuleConfig>,
}

impl ServiceModulePolicies {
    fn into_map(self) -> HashMap<String, ServiceModuleConfig> {
        [
            ("mbrew", self.mbrew),
            ("mcpu", self.mcpu),
            ("mwifi", self.mwifi),
            ("miwatch", self.miwatch),
        ]
        .into_iter()
        .filter_map(|(id, config)| config.map(|config| (id.to_string(), config)))
        .collect()
    }

    fn from_map(map: &HashMap<String, ServiceModuleConfig>) -> Self {
        Self {
            mbrew: map.get("mbrew").cloned(),
            mcpu: map.get("mcpu").cloned(),
            mwifi: map.get("mwifi").cloned(),
            miwatch: map.get("miwatch").cloned(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[schemars(description = "Versioned module identity and typed module-specific settings.")]
pub struct ModuleDocument<T> {
    pub version: u32,
    pub module: ModuleManifest,
    pub settings: T,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[schemars(description = "Stable identity and execution mode for a module.")]
pub struct ModuleManifest {
    pub id: String,
    #[schemars(length(min = 1))]
    pub display_name: String,
    pub mode: ModuleMode,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum ModuleMode {
    Task,
    Daemon,
}

impl ModuleMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Task => "task",
            Self::Daemon => "daemon",
        }
    }
}

#[derive(Debug, Clone)]
pub enum ModuleSettings {
    Mbrew(modules::mbrew::MbrewConfig),
    Mcpu(modules::mcpu::McpuConfig),
    Mwifi(modules::mwifi::MwifiConfig),
    Miwatch(Box<modules::miwatch::WatchdogConfig>),
}

#[derive(Debug, Clone)]
pub struct ParsedModule {
    pub manifest: ModuleManifest,
    pub settings: ModuleSettings,
    pub dir: PathBuf,
}

#[derive(Debug, Clone)]
pub struct ServiceConfig {
    pub label: String,
    pub log_dir: String,
    pub watch: bool,
    pub self_update_check_hours: u64,
    pub modules: HashMap<String, ServiceModuleConfig>,
    pub triggers: TriggerMap,

    #[allow(dead_code)]
    pub path: PathBuf,
    #[allow(dead_code)]
    pub root_dir: PathBuf,
    #[allow(dead_code)]
    pub state_dir: PathBuf,
    #[allow(dead_code)]
    pub state_file: PathBuf,
}

impl Serialize for ServiceConfig {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.to_document().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for ServiceConfig {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let document = ServiceDocument::deserialize(deserializer)?;
        Self::from_document(document, PathBuf::new(), PathBuf::new())
            .map_err(serde::de::Error::custom)
    }
}

impl ServiceConfig {
    pub fn expanded_log_dir(&self) -> PathBuf {
        expand_home(&self.log_dir)
    }

    pub fn self_update_check_interval(&self) -> std::time::Duration {
        std::time::Duration::from_secs(self.self_update_check_hours.saturating_mul(60 * 60))
    }

    pub fn from_document(document: ServiceDocument, path: PathBuf, root: PathBuf) -> Result<Self> {
        if document.version != CONFIG_VERSION {
            anyhow::bail!(
                "unsupported service.yaml version {}; expected {}",
                document.version,
                CONFIG_VERSION
            );
        }
        if document.service.label.trim().is_empty() {
            anyhow::bail!("service label must not be empty");
        }
        if document.service.log_dir.trim().is_empty() {
            anyhow::bail!("service log_dir must not be empty");
        }
        crate::paths::validate_config_path("service log_dir", &document.service.log_dir, false)?;
        if document.service.self_update_check_hours == 0 {
            anyhow::bail!("service self_update_check_hours must be greater than zero");
        }

        let modules = document.modules.into_map();
        let mut triggers = BTreeMap::new();
        for (module_id, module) in &modules {
            if BuiltInModule::kind_from_id(module_id).is_err() {
                anyhow::bail!("module \"{module_id}\" is not compiled into this build");
            }
            for (local_id, trigger) in &module.triggers {
                validate_local_trigger_id(local_id)
                    .with_context(|| format!("invalid trigger {module_id}.{local_id}"))?;
                let id = canonical_trigger_id(module_id, local_id);
                let config = TriggerConfig {
                    enabled: trigger.enabled,
                    module: module_id.clone(),
                    fire: trigger.fire.clone(),
                    when: trigger.when.clone(),
                };
                config
                    .validate()
                    .with_context(|| format!("invalid trigger {id}"))?;
                if triggers.insert(id.clone(), config).is_some() {
                    anyhow::bail!("duplicate trigger {id}");
                }
            }
        }

        Ok(Self {
            label: document.service.label,
            log_dir: document.service.log_dir,
            watch: document.service.watch,
            self_update_check_hours: document.service.self_update_check_hours,
            modules,
            triggers,
            path,
            root_dir: root,
            state_dir: resolve_state_dir(),
            state_file: resolve_state_file(),
        })
    }

    pub fn to_document(&self) -> ServiceDocument {
        let mut modules = self.modules.clone();
        for (id, trigger) in &self.triggers {
            let Some((module_id, local_id)) = id.split_once('.') else {
                continue;
            };
            let entry = modules.entry(module_id.to_string()).or_default();
            entry.triggers.insert(
                local_id.to_string(),
                ScopedTriggerConfig {
                    enabled: trigger.enabled,
                    fire: trigger.fire.clone(),
                    when: trigger.when.clone(),
                },
            );
        }
        ServiceDocument {
            version: CONFIG_VERSION,
            service: ServiceSettings {
                label: self.label.clone(),
                log_dir: self.log_dir.clone(),
                watch: self.watch,
                self_update_check_hours: self.self_update_check_hours,
            },
            modules: ServiceModulePolicies::from_map(&modules),
        }
    }
}

pub fn canonical_trigger_id(module_id: &str, local_id: &str) -> String {
    format!("{module_id}.{local_id}")
}

fn validate_local_trigger_id(id: &str) -> Result<()> {
    let mut chars = id.chars();
    let valid_first = chars.next().is_some_and(|value| value.is_ascii_lowercase());
    let valid_rest = chars.all(|value| {
        value.is_ascii_lowercase() || value.is_ascii_digit() || value == '_' || value == '-'
    });
    if !valid_first || !valid_rest {
        anyhow::bail!("trigger name must match ^[a-z][a-z0-9_-]*$");
    }
    Ok(())
}

pub fn read_service_config(root: &Path) -> Result<ServiceConfig> {
    let path = resolve_service_config_path(root);
    let raw = fs::read_to_string(&path)
        .with_context(|| format!("read service configuration {}", path.display()))?;
    let value: serde_yaml::Value = serde_yaml::from_str(&raw).context("parse service YAML")?;
    reject_legacy_service_shape(&value)?;
    let document: ServiceDocument = serde_yaml::from_value(value).context("decode service YAML")?;
    ServiceConfig::from_document(document, path, root.to_path_buf())
}

fn reject_legacy_service_shape(value: &serde_yaml::Value) -> Result<()> {
    let mapping = value
        .as_mapping()
        .context("service.yaml must contain a mapping")?;
    if !mapping.contains_key(serde_yaml::Value::String("version".to_string())) {
        anyhow::bail!(
            "service.yaml requires version: 1; legacy global fields and top-level triggers must be migrated"
        );
    }
    if mapping.contains_key(serde_yaml::Value::String("triggers".to_string())) {
        anyhow::bail!(
            "legacy top-level triggers are no longer supported; move each trigger to modules.<module>.triggers"
        );
    }
    if let Some(modules) = mapping
        .get(serde_yaml::Value::String("modules".to_string()))
        .and_then(serde_yaml::Value::as_mapping)
    {
        for (module_id, module) in modules {
            if module.as_mapping().is_some_and(|entry| {
                entry.contains_key(serde_yaml::Value::String("schedule".to_string()))
            }) {
                anyhow::bail!(
                    "legacy modules.{}.schedule is no longer supported; define modules.<module>.triggers",
                    module_id.as_str().unwrap_or("<unknown>")
                );
            }
        }
    }
    Ok(())
}

pub fn read_module_manifest(id: &str, root: &Path) -> Result<ParsedModule> {
    let kind = BuiltInModule::kind_from_id(id)?;
    let manifest_path = root.join("modules").join(id).join("module.yaml");
    let raw = fs::read_to_string(&manifest_path)
        .with_context(|| format!("read module manifest {}", manifest_path.display()))?;
    let value: serde_yaml::Value =
        serde_yaml::from_str(&raw).with_context(|| format!("parse module YAML {id}"))?;
    reject_legacy_module_shape(id, &value)?;

    let parsed = match kind {
        BuiltInModule::Mbrew => {
            let document: ModuleDocument<modules::mbrew::MbrewConfig> =
                serde_yaml::from_value(value.clone()).context("decode mbrew module.yaml")?;
            validate_module_document(id, &document.module, document.version)?;
            modules::mbrew::validate_config(&document.settings)?;
            (document.module, ModuleSettings::Mbrew(document.settings))
        }
        BuiltInModule::Mcpu => {
            let document: ModuleDocument<modules::mcpu::McpuConfig> =
                serde_yaml::from_value(value.clone()).context("decode mcpu module.yaml")?;
            validate_module_document(id, &document.module, document.version)?;
            modules::mcpu::validate_config(&document.settings)?;
            (document.module, ModuleSettings::Mcpu(document.settings))
        }
        BuiltInModule::Mwifi => {
            let document: ModuleDocument<modules::mwifi::MwifiConfig> =
                serde_yaml::from_value(value.clone()).context("decode mwifi module.yaml")?;
            validate_module_document(id, &document.module, document.version)?;
            modules::mwifi::validate_config(&document.settings)?;
            (document.module, ModuleSettings::Mwifi(document.settings))
        }
        BuiltInModule::Miwatch => {
            let document: ModuleDocument<modules::miwatch::WatchdogConfig> =
                serde_yaml::from_value(value).context("decode miwatch module.yaml")?;
            validate_module_document(id, &document.module, document.version)?;
            document.settings.validate()?;
            (
                document.module,
                ModuleSettings::Miwatch(Box::new(document.settings)),
            )
        }
    };

    Ok(ParsedModule {
        manifest: parsed.0,
        settings: parsed.1,
        dir: manifest_path
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| root.join("modules").join(id)),
    })
}

fn reject_legacy_module_shape(id: &str, value: &serde_yaml::Value) -> Result<()> {
    let mapping = value
        .as_mapping()
        .context("module.yaml must contain a mapping")?;
    if !mapping.contains_key(serde_yaml::Value::String("version".to_string())) {
        anyhow::bail!(
            "modules/{id}/module.yaml requires version: 1; move metadata under module and runtime fields under settings"
        );
    }
    if mapping.contains_key(serde_yaml::Value::String("interval_seconds".to_string())) {
        anyhow::bail!(
            "modules/{id}/module.yaml interval_seconds was removed; scheduling belongs in service.yaml triggers"
        );
    }
    Ok(())
}

fn validate_module_document(id: &str, manifest: &ModuleManifest, version: u32) -> Result<()> {
    if version != CONFIG_VERSION {
        anyhow::bail!(
            "unsupported modules/{id}/module.yaml version {version}; expected {}",
            CONFIG_VERSION
        );
    }
    if manifest.id != id {
        anyhow::bail!("module manifest id mismatch: {} != {}", manifest.id, id);
    }
    if manifest.display_name.trim().is_empty() {
        anyhow::bail!("module {id} display_name must not be empty");
    }
    if manifest.mode != ModuleMode::Task {
        anyhow::bail!("module {id} must use mode task");
    }
    Ok(())
}

fn default_true() -> bool {
    true
}

fn is_true(value: &bool) -> bool {
    *value
}

fn default_self_update_check_hours() -> u64 {
    12
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

    fn service_yaml() -> &'static str {
        "version: 1\nservice:\n  label: com.omar.scriptd\n  log_dir: ~/Library/Logs/scriptd\n  watch: true\n  self_update_check_hours: 12\nmodules:\n  mbrew:\n    enabled: true\n    triggers:\n      maintenance:\n        fire: { mode: every_match }\n        when:\n          schedule: { every_hours: 12 }\n"
    }

    #[test]
    fn parses_scoped_service_config() {
        let temp = tempdir().expect("temp dir");
        fs::write(temp.path().join("service.yaml"), service_yaml()).expect("write service");
        let config = read_service_config(temp.path()).expect("read config");
        assert_eq!(config.label, "com.omar.scriptd");
        assert!(config.modules["mbrew"].enabled);
        assert!(config.triggers.contains_key("mbrew.maintenance"));
    }

    #[test]
    fn rejects_legacy_top_level_triggers() {
        let temp = tempdir().expect("temp dir");
        fs::write(
            temp.path().join("service.yaml"),
            "version: 1\nservice: { label: x, log_dir: /tmp }\nmodules: {}\ntriggers: {}\n",
        )
        .expect("write service");
        let error = read_service_config(temp.path()).expect_err("legacy triggers should fail");
        assert!(error.to_string().contains("top-level triggers"));
    }

    #[test]
    fn rejects_missing_version() {
        let temp = tempdir().expect("temp dir");
        fs::write(
            temp.path().join("service.yaml"),
            "label: x\nlog_dir: /tmp\nmodules: {}\n",
        )
        .expect("write service");
        let error = read_service_config(temp.path()).expect_err("missing version should fail");
        assert!(error.to_string().contains("requires version"));
    }

    #[test]
    fn rejects_relative_service_log_path() {
        let document: ServiceDocument = serde_yaml::from_str(
            "version: 1\nservice: { label: com.test.scriptd, log_dir: relative/logs }\nmodules: {}\n",
        )
        .expect("typed document");
        let error = ServiceConfig::from_document(document, PathBuf::new(), PathBuf::new())
            .expect_err("relative log path should fail");
        assert!(error
            .to_string()
            .contains("service log_dir must be absolute or start with ~/"));
    }

    #[test]
    fn rejects_legacy_module_layout_with_precise_migration_error() {
        let temp = tempdir().expect("temp dir");
        let module_dir = temp.path().join("modules/mbrew");
        fs::create_dir_all(&module_dir).expect("module dir");
        fs::write(
            module_dir.join("module.yaml"),
            "id: mbrew\ndisplay_name: Brew\nmode: task\ninterval_seconds: 60\n",
        )
        .expect("write legacy module");

        let error = read_module_manifest("mbrew", temp.path())
            .expect_err("legacy module layout should fail");
        assert!(error.to_string().contains("requires version: 1"));
        assert!(error.to_string().contains("under settings"));
    }

    #[test]
    fn rejects_unsupported_module_version_and_wrong_identity() {
        let temp = tempdir().expect("temp dir");
        let module_dir = temp.path().join("modules/mbrew");
        fs::create_dir_all(&module_dir).expect("module dir");
        let settings = "settings:\n  askpass_path: /tmp/askpass\n  homebrew_bin: /opt/homebrew/bin/brew\n  sudoers_path: /tmp/sudoers\n  sudoers_timeout_path: /tmp/sudoers-timeout\n  sudo_timeout_hours: 2\n";
        fs::write(
            module_dir.join("module.yaml"),
            format!(
                "version: 2\nmodule:\n  id: mcpu\n  display_name: Brew\n  mode: task\n{settings}"
            ),
        )
        .expect("write unsupported module");

        let error = read_module_manifest("mbrew", temp.path())
            .expect_err("unsupported module document should fail");
        assert!(error
            .to_string()
            .contains("unsupported modules/mbrew/module.yaml version 2"));

        fs::write(
            module_dir.join("module.yaml"),
            format!(
                "version: 1\nmodule:\n  id: mcpu\n  display_name: Brew\n  mode: task\n{settings}"
            ),
        )
        .expect("write mismatched module");
        let error = read_module_manifest("mbrew", temp.path())
            .expect_err("wrong module identity should fail");
        assert!(error.to_string().contains("module manifest id mismatch"));
    }

    #[test]
    fn mwifi_module_settings_layer_over_typed_defaults() {
        let temp = tempdir().expect("temp dir");
        let module_dir = temp.path().join("modules/mwifi");
        fs::create_dir_all(&module_dir).expect("module dir");
        fs::write(
            module_dir.join("module.yaml"),
            "version: 1\nmodule:\n  id: mwifi\n  display_name: Wi-Fi Monitor\n  mode: task\nsettings:\n  min_dwell: 240\n",
        )
        .expect("write partial mwifi module");

        let parsed = read_module_manifest("mwifi", temp.path()).expect("typed mwifi settings");
        let ModuleSettings::Mwifi(settings) = parsed.settings else {
            panic!("expected mwifi settings");
        };
        assert_eq!(settings.min_dwell_seconds, 240);
        assert_eq!(settings.ping_target, "1.1.1.1");
        assert_eq!(settings.ping_count, 3);
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
}
