use std::env;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

mod config;
mod credentials;
mod launchd;
mod logger;
mod modules;
mod paths;
mod status;
mod supervisor;
mod triggers;
use crate::modules::BuiltInModule;

fn usage() {
    println!("Usage:");
    println!("  scriptd.sh start root");
    println!("  scriptd.sh stop root");
    println!("  scriptd.sh uninstall root");
    println!("  scriptd.sh run root");
    println!("  scriptd.sh run <module>");
    println!("  scriptd.sh miwatch session refresh");
    println!("  scriptd.sh miwatch session import");
    println!("  scriptd.sh miwatch remote verify");
    println!("  scriptd.sh config <module> show");
    println!("  scriptd.sh config <module> [--enable|--disable]");
    println!("  scriptd.sh status");
    println!("  scriptd.sh test");
}

fn show_module_config(args: &[String], repo_root: PathBuf) -> anyhow::Result<()> {
    use crate::modules::BuiltInModule;

    if args.len() != 1 {
        anyhow::bail!("config show requires exactly one module name");
    }

    let module_name = args[0].as_str();
    let cfg = read_service_config_with_setup(&repo_root)?;
    if BuiltInModule::kind_from_id(module_name).is_err() {
        anyhow::bail!("module \"{module_name}\" not compiled into this build");
    }

    let entry = cfg.modules.get(module_name).cloned().unwrap_or_default();
    let mut value = serde_yaml::to_value(entry)?;
    strip_null_yaml_values(&mut value);
    print!("{}", serde_yaml::to_string(&value)?);
    Ok(())
}

fn strip_null_yaml_values(value: &mut serde_yaml::Value) {
    match value {
        serde_yaml::Value::Mapping(mapping) => {
            mapping.retain(|_, child| {
                strip_null_yaml_values(child);
                !matches!(child, serde_yaml::Value::Null)
            });
        }
        serde_yaml::Value::Sequence(sequence) => {
            for child in sequence {
                strip_null_yaml_values(child);
            }
        }
        _ => {}
    }
}

fn parse_and_update_module_config(args: &[String], repo_root: PathBuf) -> anyhow::Result<()> {
    use crate::modules::BuiltInModule;

    if args.is_empty() {
        anyhow::bail!("module name is required");
    }

    let module_name = args[0].as_str();
    let mut cfg = read_service_config_with_setup(&repo_root)?;
    if BuiltInModule::kind_from_id(module_name).is_err() {
        anyhow::bail!("module \"{module_name}\" not compiled into this build");
    }

    if args.len() == 1 {
        let mut context = modules::module_context(
            module_name,
            repo_root.clone(),
            cfg::module_dir(module_name, &cfg.root_dir)?,
            cfg.expanded_log_dir(),
        );
        let kind = BuiltInModule::kind_from_id(module_name)?;
        modules::setup_module(&kind, &mut context)?;
        let entry = cfg.modules.entry(module_name.to_string()).or_default();
        entry.enabled = true;
        write_service_config(&cfg)?;
        return Ok(());
    }

    let mut enabled: Option<bool> = None;
    let mut enable_seen = false;
    let mut disable_seen = false;

    for arg in &args[1..] {
        match arg.as_str() {
            "--enable" => {
                enable_seen = true;
                enabled = Some(true);
            }
            "--disable" => {
                disable_seen = true;
                enabled = Some(false);
            }
            "--every-seconds" | "--every-minutes" | "--every-hours" | "--daily-at"
            | "--cron" | "--weekday" | "--window-start" | "--window-end" => anyhow::bail!(
                "schedule flags were removed; author complex rules in the top-level triggers section of service.yaml"
            ),
            other => anyhow::bail!("unknown config flag: {other}"),
        }
    }

    if enable_seen && disable_seen {
        anyhow::bail!("Use only one of --enable or --disable");
    }

    let entry = cfg.modules.entry(module_name.to_string()).or_default();
    if let Some(next_enabled) = enabled {
        entry.enabled = next_enabled;
    }
    let enabled = entry.enabled;

    write_service_config(&cfg)?;
    println!(
        "Updated {} in service.yaml (enabled={})",
        module_name,
        if enabled { "on" } else { "off" },
    );
    Ok(())
}

fn read_service_config_with_setup(repo_root: &Path) -> anyhow::Result<config::ServiceConfig> {
    config::read_service_config(repo_root)
}

fn write_service_config(config: &config::ServiceConfig) -> anyhow::Result<()> {
    let raw = serde_yaml::to_string(config)?;
    std::fs::write(&config.path, raw)?;
    Ok(())
}

mod cfg {
    use std::path::{Path, PathBuf};

    pub fn module_dir(module_id: &str, root: &Path) -> anyhow::Result<PathBuf> {
        let base = crate::paths::resolve_modules_dir(root);
        let path = base.join(module_id);
        if !path.exists() {
            anyhow::bail!("module directory missing: {}", path.display());
        }
        Ok(path)
    }
}

fn cmd_run(args: &[String], root: PathBuf) -> anyhow::Result<()> {
    if args.is_empty() {
        anyhow::bail!("run target required");
    }

    if args[0] == "root" {
        supervisor::run_supervisor(root)?;
        return Ok(());
    }

    let module = &args[0];
    BuiltInModule::kind_from_id(module)?;
    supervisor::run_one_module(root, module)
}

fn cmd_miwatch(args: &[String], root: PathBuf) -> anyhow::Result<()> {
    if args != ["session", "refresh"]
        && args != ["session", "import"]
        && args != ["remote", "verify"]
    {
        anyhow::bail!("miwatch supports only: session refresh|import; remote verify");
    }
    let config = config::read_service_config(&root)?;
    let module_dir = cfg::module_dir("miwatch", &config.root_dir)?;
    let mut context =
        modules::module_context("miwatch", root, module_dir, config.expanded_log_dir());
    if args == ["session", "refresh"] {
        modules::refresh_session(&BuiltInModule::Miwatch, &mut context)
    } else if args == ["remote", "verify"] {
        modules::verify_remote(&BuiltInModule::Miwatch, &mut context)
    } else {
        let mut input = String::new();
        std::io::stdin().read_to_string(&mut input)?;
        modules::import_session(&BuiltInModule::Miwatch, &mut context, &input)
    }
}

fn cmd_start(args: &[String], root: PathBuf) -> anyhow::Result<()> {
    if args != ["root"] {
        anyhow::bail!("start requires target root");
    }
    let config = config::read_service_config(&root)?;
    launchd::start_root(&config)?;
    Ok(())
}

fn cmd_stop(args: &[String], root: PathBuf) -> anyhow::Result<()> {
    if args != ["root"] {
        anyhow::bail!("stop requires target root");
    }
    let config = config::read_service_config(&root)?;
    launchd::stop_root(&config.label)?;
    Ok(())
}

fn cmd_uninstall(args: &[String], root: PathBuf) -> anyhow::Result<()> {
    if args != ["root"] {
        anyhow::bail!("uninstall requires target root");
    }
    let config = config::read_service_config(&root)?;
    launchd::uninstall_root(&config.label)?;
    Ok(())
}

fn cmd_status(root: PathBuf) -> anyhow::Result<()> {
    let config = config::read_service_config(&root)?;
    status::render_status(&config, config.path.clone())?;
    Ok(())
}

fn cmd_config(args: &[String], root: PathBuf) -> anyhow::Result<()> {
    if args.get(1).map(String::as_str) == Some("show") {
        if args.len() != 2 {
            anyhow::bail!("config <module> show does not accept extra arguments");
        }
        return show_module_config(&[args[0].clone()], root);
    }

    parse_and_update_module_config(args, root)
}

fn cmd_test() -> anyhow::Result<()> {
    let use_rustup = std::process::Command::new("rustup")
        .arg("--version")
        .output()
        .map(|value| value.status.success())
        .unwrap_or(false);

    let status = if use_rustup {
        std::process::Command::new("rustup")
            .args(["run", "stable", "cargo", "test", "--", "--nocapture"])
            .status()?
    } else {
        std::process::Command::new("cargo")
            .args(["test", "--", "--nocapture"])
            .status()?
    };
    if status.success() {
        Ok(())
    } else {
        anyhow::bail!("cargo test failed with {status}");
    }
}

fn main() -> ExitCode {
    let mut args = env::args().skip(1).collect::<Vec<_>>();
    if args.is_empty() {
        usage();
        return ExitCode::SUCCESS;
    }

    let root = paths::resolve_repo_root();
    let command = args.remove(0);
    let outcome = match command.as_str() {
        "status" => cmd_status(root),
        "start" => cmd_start(&args, root),
        "stop" => cmd_stop(&args, root),
        "uninstall" => cmd_uninstall(&args, root),
        "run" => cmd_run(&args, root),
        "miwatch" => cmd_miwatch(&args, root),
        "config" => cmd_config(&args, root),
        "test" => cmd_test(),
        "help" => {
            usage();
            return ExitCode::SUCCESS;
        }
        other => {
            eprintln!("unknown command: {other}");
            usage();
            return ExitCode::from(2);
        }
    };

    match outcome {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error:?}");
            ExitCode::from(1)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    fn write_service_yaml(root: &Path, body: &str) {
        fs::write(root.join("service.yaml"), body).expect("write service yaml");
        for builtin in ["mwifi", "mcpu", "mbrew", "miwatch"] {
            let dir = root.join("modules").join(builtin);
            fs::create_dir_all(&dir).expect("module dir");
            let manifest = format!("id: {builtin}\nmode: task\n");
            fs::write(dir.join("module.yaml"), manifest).expect("module manifest");
        }
    }

    #[test]
    fn parse_config_rejects_enable_and_disable_together() {
        let temp = tempdir().expect("temp dir");
        write_service_yaml(
            temp.path(),
            "label: com.omar.scriptd\nlog_dir: ~/Library/Logs/scriptd\nwatch: true\nmodules:\n  mwifi:\n    enabled: true\ntriggers:\n  mwifi-test:\n    enabled: true\n    module: mwifi\n    fire: { mode: every_match }\n    when: { schedule: { every_minutes: 5 } }\n",
        );

        let err = parse_and_update_module_config(
            &[
                "mwifi".to_string(),
                "--enable".to_string(),
                "--disable".to_string(),
            ],
            temp.path().to_path_buf(),
        )
        .expect_err("expected conflict");

        assert!(err
            .to_string()
            .contains("Use only one of --enable or --disable"));
    }

    #[test]
    fn parse_config_rejects_removed_schedule_flags() {
        let temp = tempdir().expect("temp dir");
        write_service_yaml(
            temp.path(),
            "label: com.omar.scriptd\nlog_dir: ~/Library/Logs/scriptd\nwatch: true\nmodules:\n  mwifi:\n    enabled: true\n",
        );

        let err = parse_and_update_module_config(
            &["mwifi".to_string(), "--every-minutes".to_string()],
            temp.path().to_path_buf(),
        )
        .expect_err("expected conflict");

        assert!(err.to_string().contains("schedule flags were removed"));
    }

    #[test]
    fn parse_config_updates_module_enablement_only() {
        let temp = tempdir().expect("temp dir");
        write_service_yaml(
            temp.path(),
            "label: com.omar.scriptd\nlog_dir: ~/Library/Logs/scriptd\nwatch: true\nmodules:\n  mwifi:\n    enabled: true\ntriggers:\n  mwifi-test:\n    enabled: true\n    module: mwifi\n    fire: { mode: every_match }\n    when: { schedule: { every_minutes: 5 } }\n",
        );

        parse_and_update_module_config(
            &["mwifi".to_string(), "--disable".to_string()],
            temp.path().to_path_buf(),
        )
        .expect("config parses");

        let updated = fs::read_to_string(temp.path().join("service.yaml")).expect("read service");
        let parsed: serde_yaml::Value = serde_yaml::from_str(&updated).expect("roundtrip yaml");
        assert_eq!(parsed["modules"]["mwifi"]["enabled"].as_bool(), Some(false));
        assert!(parsed["modules"]["mwifi"].get("schedule").is_none());
        assert!(parsed["triggers"].get("mwifi-test").is_some());
    }

    #[test]
    fn parse_config_rejects_unknown_flag() {
        let temp = tempdir().expect("temp dir");
        write_service_yaml(
            temp.path(),
            "label: com.omar.scriptd\nlog_dir: ~/Library/Logs/scriptd\nwatch: true\nmodules:\n  mwifi:\n    enabled: true\n",
        );

        let err = parse_and_update_module_config(
            &["mwifi".to_string(), "--funday".to_string()],
            temp.path().to_path_buf(),
        )
        .expect_err("expected invalid weekday");

        assert!(err.to_string().contains("unknown config flag"));
    }

    #[test]
    fn show_config_prints_module_service_yaml() {
        let temp = tempdir().expect("temp dir");
        write_service_yaml(
            temp.path(),
            "label: com.omar.scriptd\nlog_dir: ~/Library/Logs/scriptd\nwatch: true\nmodules:\n  mwifi:\n    enabled: true\n",
        );

        show_module_config(&["mwifi".to_string()], temp.path().to_path_buf()).expect("show config");
    }

    #[test]
    fn old_ts_artifacts_removed() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let expected_missing = [
            "src/config.ts",
            "src/interfaces.ts",
            "src/main.ts",
            "src/module-runner.ts",
            "src/paths.ts",
            "src/status.ts",
            "src/supervisor.ts",
            "src/test.ts",
            "package.json",
            "tsconfig.json",
        ];

        for entry in expected_missing {
            assert!(
                !root.join(entry).exists(),
                "{entry} should not exist in Rust migration"
            );
        }

        for module_id in ["mbrew", "mcpu", "mwifi", "miwatch"] {
            assert!(
                !root
                    .join(format!("modules/{module_id}/package.json"))
                    .exists(),
                "module package json removed for {module_id}"
            );
        }
    }
}
