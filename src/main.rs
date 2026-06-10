use std::env;
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
use crate::modules::BuiltInModule;

fn usage() {
    println!("Usage:");
    println!("  scriptd.sh start root");
    println!("  scriptd.sh stop root");
    println!("  scriptd.sh uninstall root");
    println!("  scriptd.sh run root");
    println!("  scriptd.sh run <module>");
    println!("  scriptd.sh config <module> show");
    println!(
        "  scriptd.sh config <module> [--enable|--disable] [--every-seconds n|--every-minutes n|--every-hours n|--daily-at HH:MM|--cron expr]"
    );
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
    use config::{ModuleSchedule, ServiceModuleConfig, WeekdayName};

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
    let mut schedule = ModuleSchedule::default();
    let mut has_schedule = false;
    let mut has_schedule_trigger = false;
    let mut has_window = false;
    let mut weekday_list: Vec<config::WeekdayName> = Vec::new();
    let mut window_start: Option<String> = None;
    let mut window_end: Option<String> = None;
    let mut enable_seen = false;
    let mut disable_seen = false;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--enable" => {
                enable_seen = true;
                enabled = Some(true);
            }
            "--disable" => {
                disable_seen = true;
                enabled = Some(false);
            }
            "--every-seconds" => {
                let value = args
                    .get(i + 1)
                    .ok_or_else(|| anyhow::anyhow!("missing value for --every-seconds"))?;
                schedule.every_seconds = Some(value.parse::<u64>()?);
                has_schedule = true;
                has_schedule_trigger = true;
                i += 1;
            }
            "--every-minutes" => {
                let value = args
                    .get(i + 1)
                    .ok_or_else(|| anyhow::anyhow!("missing value for --every-minutes"))?;
                schedule.every_minutes = Some(value.parse::<u64>()?);
                has_schedule = true;
                has_schedule_trigger = true;
                i += 1;
            }
            "--every-hours" => {
                let value = args
                    .get(i + 1)
                    .ok_or_else(|| anyhow::anyhow!("missing value for --every-hours"))?;
                schedule.every_hours = Some(value.parse::<u64>()?);
                has_schedule = true;
                has_schedule_trigger = true;
                i += 1;
            }
            "--daily-at" => {
                let value = args
                    .get(i + 1)
                    .ok_or_else(|| anyhow::anyhow!("missing value for --daily-at"))?;
                schedule
                    .daily_at
                    .get_or_insert_with(Vec::new)
                    .push(value.to_string());
                has_schedule = true;
                has_schedule_trigger = true;
                i += 1;
            }
            "--cron" => {
                let value = args
                    .get(i + 1)
                    .ok_or_else(|| anyhow::anyhow!("missing value for --cron"))?;
                schedule.cron = Some(vec![value.to_string()]);
                has_schedule = true;
                has_schedule_trigger = true;
                i += 1;
            }
            "--weekday" => {
                let raw = args
                    .get(i + 1)
                    .ok_or_else(|| anyhow::anyhow!("missing value for --weekday"))?;
                if let Some(weekday) = WeekdayName::parse(raw) {
                    weekday_list.push(weekday);
                } else {
                    anyhow::bail!("--weekday expects sun, mon, tue, wed, thu, fri, sat");
                }
                i += 1;
            }
            "--window-start" => {
                let raw = args
                    .get(i + 1)
                    .ok_or_else(|| anyhow::anyhow!("missing value for --window-start"))?;
                if raw.parse::<chrono::NaiveTime>().is_err() {
                    anyhow::bail!("--window-start must be HH:MM");
                }
                window_start = Some(raw.to_string());
                has_window = true;
                has_schedule = true;
                i += 1;
            }
            "--window-end" => {
                let raw = args
                    .get(i + 1)
                    .ok_or_else(|| anyhow::anyhow!("missing value for --window-end"))?;
                if raw.parse::<chrono::NaiveTime>().is_err() {
                    anyhow::bail!("--window-end must be HH:MM");
                }
                window_end = Some(raw.to_string());
                has_window = true;
                has_schedule = true;
                i += 1;
            }
            other => anyhow::bail!("unknown config flag: {other}"),
        }
        i += 1;
    }

    if enable_seen && disable_seen {
        anyhow::bail!("Use only one of --enable or --disable");
    }

    if has_schedule_trigger {
        let mut trigger_count = 0usize;
        trigger_count += schedule.cron.is_some() as usize;
        trigger_count += schedule.every_seconds.is_some() as usize;
        trigger_count += schedule.every_minutes.is_some() as usize;
        trigger_count += schedule.every_hours.is_some() as usize;
        trigger_count += schedule.daily_at.is_some() as usize;
        if trigger_count > 1 {
            anyhow::bail!("Use only one schedule trigger per config command");
        }
    }

    if has_schedule {
        if !weekday_list.is_empty() {
            schedule.weekdays = Some(weekday_list);
        }
        if has_window || window_start.is_some() || window_end.is_some() {
            schedule.window = Some(config::ScheduleWindow {
                start: window_start.unwrap_or_else(|| "00:00".to_string()),
                end: window_end.unwrap_or_else(|| "23:59".to_string()),
            });
        }
        schedule.validate()?;
    } else {
        schedule = ModuleSchedule::default();
    }

    let entry = cfg
        .modules
        .entry(module_name.to_string())
        .or_insert_with(|| ServiceModuleConfig {
            enabled: false,
            schedule: None,
        });
    if let Some(next_enabled) = enabled {
        entry.enabled = next_enabled;
    }
    if has_schedule {
        entry.schedule = Some(schedule);
    }
    let enabled = entry.enabled;
    let has_schedule = entry.schedule.is_some();

    write_service_config(&cfg)?;
    println!(
        "Updated {} in service.yaml (enabled={}, schedule={})",
        module_name,
        if enabled { "on" } else { "off" },
        if has_schedule { "custom" } else { "default" }
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
        for builtin in ["mwifi", "mcpu", "mbrew"] {
            let dir = root.join("modules").join(builtin);
            fs::create_dir_all(&dir).expect("module dir");
            let manifest = match builtin {
                "mwifi" => "id: mwifi\nmode: interval\ninterval_seconds: 30\n",
                "mcpu" => "id: mcpu\nmode: interval\ninterval_seconds: 30\n",
                "mbrew" => "id: mbrew\nmode: interval\ninterval_seconds: 30\n",
                _ => "",
            };
            fs::write(dir.join("module.yaml"), manifest).expect("module manifest");
        }
    }

    #[test]
    fn parse_config_rejects_enable_and_disable_together() {
        let temp = tempdir().expect("temp dir");
        write_service_yaml(
            temp.path(),
            "label: com.omar.scriptd\nlog_dir: ~/Library/Logs/scriptd\nwatch: true\nmodules:\n  mwifi:\n    enabled: true\n",
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

        assert!(
            err.to_string()
                .contains("Use only one of --enable or --disable")
        );
    }

    #[test]
    fn parse_config_rejects_conflicting_schedule_triggers() {
        let temp = tempdir().expect("temp dir");
        write_service_yaml(
            temp.path(),
            "label: com.omar.scriptd\nlog_dir: ~/Library/Logs/scriptd\nwatch: true\nmodules:\n  mwifi:\n    enabled: true\n",
        );

        let err = parse_and_update_module_config(
            &[
                "mwifi".to_string(),
                "--every-minutes".to_string(),
                "10".to_string(),
                "--every-hours".to_string(),
                "1".to_string(),
            ],
            temp.path().to_path_buf(),
        )
        .expect_err("expected conflict");

        assert!(
            err.to_string()
                .contains("Use only one schedule trigger per config command")
        );
    }

    #[test]
    fn parse_config_parses_window_and_weekday_flags() {
        let temp = tempdir().expect("temp dir");
        write_service_yaml(
            temp.path(),
            "label: com.omar.scriptd\nlog_dir: ~/Library/Logs/scriptd\nwatch: true\nmodules:\n  mwifi:\n    enabled: true\n",
        );

        parse_and_update_module_config(
            &[
                "mwifi".to_string(),
                "--enable".to_string(),
                "--every-minutes".to_string(),
                "15".to_string(),
                "--weekday".to_string(),
                "mon".to_string(),
                "--window-start".to_string(),
                "09:00".to_string(),
                "--window-end".to_string(),
                "17:00".to_string(),
            ],
            temp.path().to_path_buf(),
        )
        .expect("config parses");

        let updated = fs::read_to_string(temp.path().join("service.yaml")).expect("read service");
        assert!(updated.contains("enabled: true"));
        assert!(updated.contains("every_minutes: 15"));
        assert!(updated.contains("weekdays:") || updated.contains("weekday"));
        assert!(updated.contains("start: 09:00"));
        assert!(updated.contains("end: 17:00"));
    }

    #[test]
    fn parse_config_rejects_invalid_weekday() {
        let temp = tempdir().expect("temp dir");
        write_service_yaml(
            temp.path(),
            "label: com.omar.scriptd\nlog_dir: ~/Library/Logs/scriptd\nwatch: true\nmodules:\n  mwifi:\n    enabled: true\n",
        );

        let err = parse_and_update_module_config(
            &[
                "mwifi".to_string(),
                "--weekday".to_string(),
                "funday".to_string(),
            ],
            temp.path().to_path_buf(),
        )
        .expect_err("expected invalid weekday");

        assert!(
            err.to_string()
                .contains("--weekday expects sun, mon, tue, wed, thu, fri, sat")
        );
    }

    #[test]
    fn show_config_prints_module_service_yaml() {
        let temp = tempdir().expect("temp dir");
        write_service_yaml(
            temp.path(),
            "label: com.omar.scriptd\nlog_dir: ~/Library/Logs/scriptd\nwatch: true\nmodules:\n  mwifi:\n    enabled: true\n    schedule:\n      every_minutes: 5\n",
        );

        show_module_config(&["mwifi".to_string()], temp.path().to_path_buf()).expect("show config");
    }

    #[test]
    fn legacy_ts_artifacts_removed() {
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

        for module_id in ["mbrew", "mcpu", "mwifi"] {
            assert!(
                !root
                    .join(format!("modules/{module_id}/package.json"))
                    .exists(),
                "module package json removed for {module_id}"
            );
        }
    }
}
