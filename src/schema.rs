use anyhow::{bail, Context, Result};
use schemars::schema_for;
use serde_json::{Map, Value};

use crate::config::{self, ModuleDocument, ServiceDocument};
use crate::modules::{self, BuiltInModule};

pub fn render(target: &str, module_id: Option<&str>) -> Result<String> {
    let mut schema = match target {
        "service" if module_id.is_none() => serde_json::to_value(schema_for!(ServiceDocument))?,
        "module" => {
            let id = module_id.context("schema module requires a module id")?;
            module_schema(id)?
        }
        _ => bail!("schema supports: service; module <mbrew|mcpu|mwifi|miwatch>"),
    };

    if target == "service" {
        if let Some(value) = schema.pointer_mut("/properties/version") {
            value["const"] = Value::from(config::CONFIG_VERSION);
        }
        if let Some(value) = schema.pointer_mut("/$defs/ServiceModuleConfig") {
            value["propertyNames"] = serde_json::json!({
                "pattern": "^[a-z][a-z0-9_-]*$"
            });
        }
        if let Some(value) = schema.pointer_mut("/$defs/ServiceModuleConfig/properties/triggers") {
            value["propertyNames"] = serde_json::json!({
                "pattern": "^[a-z][a-z0-9_-]*$"
            });
        }
        if let Some(value) = schema.pointer_mut("/$defs/TimeWindowCondition/properties/weekdays") {
            value["uniqueItems"] = Value::Bool(true);
        }
    }
    if let Value::Object(root) = &mut schema {
        root.insert(
            "$schema".to_string(),
            Value::String("https://json-schema.org/draft/2020-12/schema".to_string()),
        );
        root.insert(
            "description".to_string(),
            Value::String(
                "Validated scriptd configuration document. Generated from Rust types.".to_string(),
            ),
        );
    }
    let schema = sort_json(schema);
    Ok(format!("{}\n", serde_json::to_string_pretty(&schema)?))
}

fn module_schema(id: &str) -> Result<Value> {
    let mut schema = match BuiltInModule::kind_from_id(id)? {
        BuiltInModule::Mbrew => {
            serde_json::to_value(schema_for!(ModuleDocument<modules::mbrew::MbrewConfig>))?
        }
        BuiltInModule::Mcpu => {
            serde_json::to_value(schema_for!(ModuleDocument<modules::mcpu::McpuConfig>))?
        }
        BuiltInModule::Mwifi => {
            serde_json::to_value(schema_for!(ModuleDocument<modules::mwifi::MwifiConfig>))?
        }
        BuiltInModule::Miwatch => serde_json::to_value(schema_for!(
            ModuleDocument<modules::miwatch::WatchdogConfig>
        ))?,
    };

    if let Some(version_schema) = schema.pointer_mut("/properties/version") {
        version_schema["const"] = Value::from(config::CONFIG_VERSION);
    }
    if let Some(id_schema) = schema.pointer_mut("/$defs/ModuleManifest/properties/id") {
        id_schema["const"] = Value::String(id.to_string());
    }
    if let Some(mode_schema) = schema.pointer_mut("/$defs/ModuleManifest/properties/mode") {
        mode_schema["const"] = Value::String("task".to_string());
    }
    if id == "miwatch" {
        if let Some(base_url) = schema.pointer_mut("/$defs/XiaomiRemoteConfig/properties/base_url")
        {
            *base_url = serde_json::json!({
                "enum": [
                    "https://api.miwifi.com",
                    "https://eu.api.miwifi.com",
                    "https://in.api.miwifi.com"
                ],
                "type": "string"
            });
        }
        if let Some(account_url) =
            schema.pointer_mut("/$defs/XiaomiRemoteConfig/properties/account_base_url")
        {
            *account_url = serde_json::json!({
                "const": "https://account.xiaomi.com",
                "type": "string"
            });
        }
    }
    if let Value::Object(root) = &mut schema {
        root.insert(
            "$id".to_string(),
            Value::String(format!("urn:scriptd:module:{id}:v1")),
        );
    }
    Ok(schema)
}

fn sort_json(value: Value) -> Value {
    match value {
        Value::Object(object) => {
            let mut sorted = Map::new();
            let mut entries = object.into_iter().collect::<Vec<_>>();
            entries.sort_by(|left, right| left.0.cmp(&right.0));
            for (key, value) in entries {
                sorted.insert(key, sort_json(value));
            }
            Value::Object(sorted)
        }
        Value::Array(values) => Value::Array(values.into_iter().map(sort_json).collect()),
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::Path;

    #[test]
    fn checked_in_schemas_match_generated_documents() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"));
        let service = fs::read_to_string(root.join("schemas/v1/service.schema.json"))
            .expect("checked-in service schema");
        assert_eq!(service, render("service", None).expect("service schema"));
        for module in ["mbrew", "mcpu", "mwifi", "miwatch"] {
            let checked_in =
                fs::read_to_string(root.join(format!("schemas/v1/modules/{module}.schema.json")))
                    .expect("checked-in module schema");
            assert_eq!(
                checked_in,
                render("module", Some(module)).expect("module schema")
            );
        }
    }

    #[test]
    fn repository_configuration_matches_all_document_types() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"));
        crate::config::read_service_config(root).expect("service configuration");
        for module in ["mbrew", "mcpu", "mwifi", "miwatch"] {
            crate::config::read_module_manifest(module, root).expect("module configuration");
        }
    }

    #[test]
    fn generated_schema_preserves_version_identity_and_string_list_shapes() {
        let service: Value =
            serde_json::from_str(&render("service", None).expect("service schema"))
                .expect("valid service schema JSON");
        assert_eq!(service["properties"]["version"]["const"], 1);
        for schedule in ["DailyAtSchedule", "CronSchedule"] {
            let field = if schedule == "DailyAtSchedule" {
                "daily_at"
            } else {
                "cron"
            };
            assert_eq!(
                service["$defs"][schedule]["properties"][field]["$ref"],
                "#/$defs/StringOrStringListSchema"
            );
        }

        let module: Value =
            serde_json::from_str(&render("module", Some("miwatch")).expect("module schema"))
                .expect("valid module schema JSON");
        assert_eq!(module["properties"]["version"]["const"], 1);
        assert_eq!(
            module["$defs"]["ModuleManifest"]["properties"]["id"]["const"],
            "miwatch"
        );
        assert_eq!(
            module["$defs"]["ModuleManifest"]["properties"]["mode"]["const"],
            "task"
        );
    }
}
