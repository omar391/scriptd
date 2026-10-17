use anyhow::Context;
use std::env;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

mod broker;
mod config;
mod control;
mod credentials;
mod execution_lock;
mod launchd;
mod logger;
mod modules;
mod paths;
mod schema;
mod status;
mod supervisor;
mod triggers;
mod web;
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
    println!("  scriptd.sh broker activate");
    println!("  scriptd.sh status");
    println!("  scriptd.sh schema service");
    println!("  scriptd.sh schema module <module>");
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
        let registry = modules::ModulesRegistry::load_from_disk(&cfg)?;
        let definition = registry
            .get(module_name)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("module \"{module_name}\" not found"))?;
        let mut context = modules::module_context_with_settings(
            module_name,
            repo_root.clone(),
            definition.dir,
            cfg.expanded_log_dir(),
            false,
            definition.settings,
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
            "--every-seconds" | "--every-minutes" | "--every-hours" | "--daily-at" | "--cron"
            | "--weekday" | "--window-start" | "--window-end" => anyhow::bail!(
                "schedule flags were removed; author complex rules in modules.<module>.triggers in service.yaml"
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
    let raw = format!(
        "# yaml-language-server: $schema=./schemas/v1/service.schema.json\n{}",
        serde_yaml::to_string(config)?
    );
    let tmp = config
        .path
        .with_extension(format!("{}.tmp", std::process::id()));
    std::fs::write(&tmp, raw)?;
    std::fs::rename(tmp, &config.path)?;
    Ok(())
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

fn cmd_broker(args: &[String], root: &Path) -> ExitCode {
    use base64::Engine;
    use std::time::Duration;

    let fail = |message: &str| {
        eprintln!("{message}");
        ExitCode::from(1)
    };
    match args.first().map(String::as_str) {
        Some("serve") if args.len() == 1 => {
            return match control::run_broker_service(root.to_path_buf()) {
                Ok(()) => ExitCode::SUCCESS,
                Err(error) => fail(&error.to_string()),
            };
        }
        Some("activate") if args.len() == 1 => {
            if unsafe { libc::geteuid() } != 0 {
                return fail("activate the privilege broker with administrator privileges");
            }
            if let Err(error) = control::broker_activation_status(root) {
                return fail(&format!(
                    "privilege broker activation was rejected: {error}"
                ));
            }
            let plist = "/Library/LaunchDaemons/com.astronlab.scriptd.broker.plist";
            return match std::process::Command::new("/bin/launchctl")
                .args(["bootstrap", "system", plist])
                .status()
            {
                Ok(status) if status.success() => {
                    println!("Activated the generation-bound scriptd privilege broker.");
                    ExitCode::SUCCESS
                }
                Ok(status) => fail(&format!("launchctl bootstrap failed with status {status}")),
                Err(error) => fail(&format!("start privilege broker: {error}")),
            };
        }
        Some("exec") => {}
        _ => {
            return fail(
                "broker supports: activate, or exec --job <id> --token <capability> -- <command> [args…]",
            );
        }
    }
    if args.first().map(String::as_str) != Some("exec") {
        return fail(
            "broker supports only: exec --job <id> --token <capability> -- <command> [args…]",
        );
    }
    let mut job_id = None;
    let mut token = None;
    let mut index = 1;
    while index < args.len() {
        match args[index].as_str() {
            "--job" if index + 1 < args.len() => {
                job_id = Some(args[index + 1].clone());
                index += 2;
            }
            "--token" if index + 1 < args.len() => {
                token = Some(args[index + 1].clone());
                index += 2;
            }
            "--" => {
                index += 1;
                break;
            }
            _ => return fail("broker execution arguments are invalid"),
        }
    }
    let (Some(job_id), Some(token), Some(program)) = (job_id, token, args.get(index).cloned())
    else {
        return fail("broker execution requires a job, capability, and command");
    };
    let command_args = args[index + 1..].to_vec();
    let mut stdin = Vec::new();
    if let Err(error) = std::io::stdin().read_to_end(&mut stdin) {
        return fail(&format!("read broker command stdin: {error}"));
    }
    let payload = serde_json::json!({
        "args": command_args,
        "cwd": match std::env::current_dir() {
            Ok(path) => path.to_string_lossy().into_owned(),
            Err(error) => return fail(&format!("resolve broker working directory: {error}")),
        },
        "env": std::env::vars().collect::<Vec<_>>(),
        "stdin": base64::engine::general_purpose::STANDARD.encode(stdin),
    });
    let request_id = format!(
        "broker-{}-{}",
        std::process::id(),
        chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default()
    );
    let request = control::Request {
        v: control::PROTOCOL_VERSION,
        id: request_id.clone(),
        op: "broker_exec".to_string(),
        repo: root.to_string_lossy().into_owned(),
        document: Some(program),
        module: Some(job_id),
        yaml: Some(payload.to_string()),
        base_digest: None,
        request_id: Some(token),
        bypass: false,
        action: Some(request_id),
        max_lines: None,
        severity: None,
        query: None,
    };
    let uid = match credentials::console_uid() {
        Ok(uid) => uid,
        Err(error) => return fail(&error.to_string()),
    };
    let socket = control::broker_socket_path(root, uid);
    let response = match control::transact_with_timeout(
        &socket,
        &request,
        Duration::from_secs(15 * 60 + 10),
    ) {
        Ok(response) if response.ok => response,
        Ok(response) => {
            return fail(
                response
                    .message
                    .as_deref()
                    .unwrap_or("broker rejected command"),
            );
        }
        Err(error) => return fail(&format!("broker request failed: {error}")),
    };
    let Some(snapshot) = response.snapshot else {
        return fail("broker returned no command result");
    };
    let Some(status) = snapshot.get("status").and_then(serde_json::Value::as_i64) else {
        return fail("broker returned an invalid command status");
    };
    let decode_output = |key: &str| -> anyhow::Result<Vec<u8>> {
        let Some(encoded) = snapshot.get(key).and_then(serde_json::Value::as_str) else {
            return Ok(Vec::new());
        };
        base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .with_context(|| format!("broker returned invalid {key}"))
    };
    let stdout = match decode_output("stdout") {
        Ok(output) => output,
        Err(error) => return fail(&error.to_string()),
    };
    let stderr = match decode_output("stderr") {
        Ok(output) => output,
        Err(error) => return fail(&error.to_string()),
    };
    if let Err(error) = std::io::stdout().write_all(&stdout) {
        return fail(&format!("write broker command stdout: {error}"));
    }
    if let Err(error) = std::io::stderr().write_all(&stderr) {
        return fail(&format!("write broker command stderr: {error}"));
    }
    ExitCode::from(status.clamp(0, 255) as u8)
}

fn cmd_miwatch(args: &[String], root: PathBuf) -> anyhow::Result<()> {
    if args != ["session", "refresh"]
        && args != ["session", "import"]
        && args != ["remote", "verify"]
    {
        anyhow::bail!("miwatch supports only: session refresh|import; remote verify");
    }
    let config = config::read_service_config(&root)?;
    let registry = modules::ModulesRegistry::load_from_disk(&config)?;
    let definition = registry
        .get("miwatch")
        .cloned()
        .context("miwatch module is not available")?;
    let mut context = modules::module_context_with_settings(
        "miwatch",
        root,
        definition.dir,
        config.expanded_log_dir(),
        false,
        definition.settings,
    );
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

fn cmd_schema(args: &[String]) -> anyhow::Result<()> {
    let (target, module_id) = match args {
        [target] if target == "service" => (target.as_str(), None),
        [target, module_id] if target == "module" => (target.as_str(), Some(module_id.as_str())),
        _ => anyhow::bail!("schema supports: service; module <mbrew|mcpu|mwifi|miwatch>"),
    };
    print!("{}", schema::render(target, module_id)?);
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
        if env::var("SCRIPTD_BROWSER_BRIDGE").ok().as_deref() == Some("1") {
            return exit_from(web::serve_bridge());
        }
        if web::should_open_browser(
            args.len(),
            web::stdin_is_interactive(),
            web::stdout_is_interactive(),
        ) {
            let root = paths::resolve_repo_root();
            let log_dir = config::read_service_config(&root)
                .map(|config| config.expanded_log_dir())
                .unwrap_or_else(|_| root.join("logs"));
            return exit_from(web::open_control_center(&root, &log_dir));
        }
        usage();
        return ExitCode::SUCCESS;
    }

    let root = paths::resolve_repo_root();
    let command = args.remove(0);
    if command == "broker" {
        return cmd_broker(&args, &root);
    }
    let outcome = match command.as_str() {
        "status" => cmd_status(root),
        "start" => cmd_start(&args, root),
        "stop" => cmd_stop(&args, root),
        "uninstall" => cmd_uninstall(&args, root),
        "run" => cmd_run(&args, root),
        "miwatch" => cmd_miwatch(&args, root),
        "config" => cmd_config(&args, root),
        "schema" => cmd_schema(&args),
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

fn exit_from(result: anyhow::Result<()>) -> ExitCode {
    match result {
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
            let source = Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("modules")
                .join(builtin)
                .join("module.yaml");
            fs::copy(source, dir.join("module.yaml")).expect("module manifest");
        }
    }

    #[test]
    fn parse_config_rejects_enable_and_disable_together() {
        let temp = tempdir().expect("temp dir");
        write_service_yaml(
            temp.path(),
            "version: 1\nservice: { label: com.omar.scriptd, log_dir: ~/Library/Logs/scriptd, watch: true }\nmodules:\n  mwifi:\n    enabled: true\n    triggers:\n      test:\n        enabled: true\n        fire: { mode: every_match }\n        when: { schedule: { every_minutes: 5 } }\n",
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
            "version: 1\nservice: { label: com.omar.scriptd, log_dir: ~/Library/Logs/scriptd, watch: true }\nmodules:\n  mwifi: { enabled: true }\n",
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
            "version: 1\nservice: { label: com.omar.scriptd, log_dir: ~/Library/Logs/scriptd, watch: true }\nmodules:\n  mwifi:\n    enabled: true\n    triggers:\n      test:\n        enabled: true\n        fire: { mode: every_match }\n        when: { schedule: { every_minutes: 5 } }\n",
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
        assert!(parsed["modules"]["mwifi"]["triggers"].get("test").is_some());
    }

    #[test]
    fn parse_config_rejects_unknown_flag() {
        let temp = tempdir().expect("temp dir");
        write_service_yaml(
            temp.path(),
            "version: 1\nservice: { label: com.omar.scriptd, log_dir: ~/Library/Logs/scriptd, watch: true }\nmodules:\n  mwifi: { enabled: true }\n",
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
            "version: 1\nservice: { label: com.omar.scriptd, log_dir: ~/Library/Logs/scriptd, watch: true }\nmodules:\n  mwifi: { enabled: true }\n",
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
