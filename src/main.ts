import path from "node:path";
import { promises as fs } from "node:fs";
import { spawnSync } from "node:child_process";
import { discoverModules, ensureDirectory, loadServiceConfig, type ModuleSchedule, type ServiceConfig, type Weekday } from "./config.ts";
import { runModuleDirect, runModuleSetup } from "./module-runner.ts";
import { resolveManageScriptPath, resolveRepoRoot, resolveStateDir, resolveStateFile } from "./paths.ts";
import { renderStatus } from "./status.ts";
import { runSupervisor } from "./supervisor.ts";
import { runAllTests } from "./test.ts";

function usage(): string {
    return `Usage:
  scriptd.sh start root
  scriptd.sh stop root
  scriptd.sh uninstall root
  scriptd.sh run <module>
  scriptd.sh status
  scriptd.sh setup <module> [--enable|--disable] [--every-seconds n|--every-minutes n|--every-hours n|--daily-at HH:MM|--cron expr]
  scriptd.sh test`;
}

function escapeXml(value: string): string {
    return value
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;")
        .replaceAll("'", "&apos;");
}

function shellQuote(value: string): string {
    return `'${value.replaceAll("'", "'\\''")}'`;
}

function runLaunchctl(args: string[], check: boolean): void {
    const result = spawnSync("launchctl", args, { encoding: "utf8" });
    if (check && result.status !== 0) {
        throw new Error(result.stderr || `launchctl ${args.join(" ")} failed`);
    }
}

function launchctlResult(args: string[]): ReturnType<typeof spawnSync> {
    return spawnSync("launchctl", args, { encoding: "utf8" });
}

function launchdDomainLabel(label: string): string {
    const uid = typeof process.getuid === "function" ? process.getuid() : 0;
    return `gui/${uid}/${label}`;
}

function rootPlistPath(label: string): string {
    return path.join(process.env.HOME ?? "", "Library", "LaunchAgents", `${label}.plist`);
}

function rootAppPath(): string {
    return path.join(resolveStateDir(), "Scriptd.app");
}

function rootAppExecutablePath(): string {
    return path.join(rootAppPath(), "Contents", "MacOS", "scriptd");
}

function legacyLabels(): string[] {
    return ["com.omar.homebrew-autoupdate", "com.omar.wifi-monitor", "com.omar.cpu-monitor", "com.omar.scripts-root"];
}

async function cleanupLegacyServices(): Promise<void> {
    const homeDir = process.env.HOME ?? "";
    for (const label of legacyLabels()) {
        const plistPath = path.join(homeDir, "Library", "LaunchAgents", `${label}.plist`);
        runLaunchctl(["unload", plistPath], false);
        runLaunchctl(["remove", label], false);
        await fs.rm(plistPath, { force: true });
    }
}

function plistContents(options: {
    label: string;
    executablePath: string;
    workingDirectory: string;
    logDir: string;
}): string {
    return `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>${escapeXml(options.label)}</string>
  <key>ProgramArguments</key>
  <array>
    <string>${escapeXml(options.executablePath)}</string>
  </array>
  <key>WorkingDirectory</key>
  <string>${escapeXml(options.workingDirectory)}</string>
  <key>EnvironmentVariables</key>
  <dict>
    <key>PATH</key>
    <string>/opt/homebrew/bin:/opt/homebrew/sbin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin</string>
  </dict>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
  <key>ProcessType</key>
  <string>Standard</string>
  <key>StandardOutPath</key>
  <string>${escapeXml(path.join(options.logDir, "scriptd.log"))}</string>
  <key>StandardErrorPath</key>
  <string>${escapeXml(path.join(options.logDir, "scriptd.err"))}</string>
</dict>
</plist>
`;
}

function appInfoPlistContents(label: string): string {
    return `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleDisplayName</key>
  <string>scriptd</string>
  <key>CFBundleExecutable</key>
  <string>scriptd</string>
  <key>CFBundleIconFile</key>
  <string>Scriptd</string>
  <key>CFBundleIconName</key>
  <string>Scriptd</string>
  <key>CFBundleIdentifier</key>
  <string>${escapeXml(label)}</string>
  <key>CFBundleName</key>
  <string>scriptd</string>
  <key>CFBundlePackageType</key>
  <string>APPL</string>
  <key>LSBackgroundOnly</key>
  <true/>
</dict>
</plist>
`;
}

async function writeShellRootLauncher(executablePath: string, manageScriptPath: string): Promise<void> {
    await fs.writeFile(executablePath, `#!/bin/bash\nexec ${shellQuote(manageScriptPath)} run root\n`, "utf8");
    await fs.chmod(executablePath, 0o755);
}

async function writeCompiledRootLauncher(executablePath: string, manageScriptPath: string): Promise<boolean> {
    const swiftc = spawnSync("sh", ["-lc", "command -v swiftc >/dev/null 2>&1"], { encoding: "utf8" });
    if (swiftc.status !== 0) {
        return false;
    }

    const sourcePath = path.join(path.dirname(executablePath), "scriptd.swift");
    const source = `import Foundation

let process = Process()
process.executableURL = URL(fileURLWithPath: ${JSON.stringify(manageScriptPath)})
process.arguments = ["run", "root"]

try process.run()
process.waitUntilExit()
exit(process.terminationStatus)
`;

    await fs.writeFile(sourcePath, source, "utf8");
    const result = spawnSync("swiftc", [sourcePath, "-o", executablePath], { encoding: "utf8" });
    await fs.rm(sourcePath, { force: true });
    if (result.status !== 0) {
        await fs.rm(executablePath, { force: true });
        return false;
    }

    await fs.chmod(executablePath, 0o755);
    return true;
}

async function writeRootApp(repoRoot: string, label: string, manageScriptPath: string): Promise<string> {
    const appPath = rootAppPath();
    const contentsDir = path.join(appPath, "Contents");
    const macosDir = path.join(contentsDir, "MacOS");
    const resourcesDir = path.join(contentsDir, "Resources");
    const iconSourcePath = path.join(repoRoot, "assets", "Scriptd.icns");
    const executablePath = rootAppExecutablePath();

    await ensureDirectory(macosDir);
    await ensureDirectory(resourcesDir);
    await fs.writeFile(path.join(contentsDir, "Info.plist"), appInfoPlistContents(label), "utf8");
    await fs.copyFile(iconSourcePath, path.join(resourcesDir, "Scriptd.icns"));
    if (!(await writeCompiledRootLauncher(executablePath, manageScriptPath))) {
        await writeShellRootLauncher(executablePath, manageScriptPath);
    }
    return executablePath;
}

async function writeRootPlist(): Promise<{ label: string; plistPath: string }> {
    const repoRoot = resolveRepoRoot();
    const config = await loadServiceConfig(repoRoot);
    const plistPath = rootPlistPath(config.label);
    const manageScriptPath = resolveManageScriptPath(repoRoot);
    const executablePath = await writeRootApp(repoRoot, config.label, manageScriptPath);

    await ensureDirectory(path.dirname(plistPath));
    await ensureDirectory(config.logDir);
    await ensureDirectory(path.dirname(resolveStateFile()));
    await cleanupLegacyServices();

    await fs.writeFile(
        plistPath,
        plistContents({
            label: config.label,
            executablePath,
            workingDirectory: repoRoot,
            logDir: config.logDir,
        }),
        "utf8",
    );

    return { label: config.label, plistPath };
}

async function startRoot(): Promise<number> {
    const { label, plistPath } = await writeRootPlist();
    const wasLoaded = launchctlResult(["list"]).stdout?.split("\n").some((line) => line.trim().split(/\s+/)[2] === label) ?? false;

    if (wasLoaded) {
        runLaunchctl(["unload", plistPath], false);
    }
    runLaunchctl(["enable", launchdDomainLabel(label)], false);
    runLaunchctl(["load", "-w", plistPath], true);
    console.log(`${wasLoaded ? "Restarted" : "Started"} root LaunchAgent ${label}`);
    return 0;
}

async function uninstallRoot(): Promise<number> {
    const config = await loadServiceConfig(resolveRepoRoot());
    const plistPath = rootPlistPath(config.label);
    runLaunchctl(["unload", plistPath], false);
    runLaunchctl(["remove", config.label], false);
    await fs.rm(plistPath, { force: true });
    console.log(`Uninstalled root LaunchAgent ${config.label}`);
    return 0;
}

async function stopRoot(): Promise<number> {
    const config = await loadServiceConfig(resolveRepoRoot());
    const plistPath = rootPlistPath(config.label);
    runLaunchctl(["unload", plistPath], false);
    console.log(`Stopped root LaunchAgent ${config.label}`);
    return 0;
}

async function getModule(moduleName: string) {
    const modules = await discoverModules(resolveRepoRoot());
    const moduleDef = modules.get(moduleName);
    if (!moduleDef) {
        throw new Error(`Unknown module: ${moduleName}`);
    }

    return { moduleDef, config: await loadServiceConfig(resolveRepoRoot()) };
}

async function runModule(moduleName: string): Promise<number> {
    const { moduleDef, config } = await getModule(moduleName);
    await runModuleDirect(moduleDef, config.logDir);
    return 0;
}

async function setupModule(moduleName: string): Promise<number> {
    const { moduleDef, config } = await getModule(moduleName);
    await runModuleSetup(moduleDef, config.logDir);
    return 0;
}

type SetupOptions = {
    enabled?: boolean;
    schedule?: ModuleSchedule;
};

function parsePositiveInteger(raw: string | undefined, label: string): number {
    const parsed = Number(raw);
    if (!Number.isInteger(parsed) || parsed <= 0) {
        throw new Error(`${label} must be a positive integer`);
    }

    return parsed;
}

function assertTimeOfDay(value: string, label: string): void {
    if (!/^([01]\d|2[0-3]):([0-5]\d)$/.test(value)) {
        throw new Error(`${label} must use HH:MM 24-hour time`);
    }
}

function parseWeekdayOption(value: string, label: string): Weekday {
    const normalized = value.toLowerCase();
    if (!["sun", "mon", "tue", "wed", "thu", "fri", "sat"].includes(normalized)) {
        throw new Error(`${label} must be one of sun, mon, tue, wed, thu, fri, sat`);
    }

    return normalized as Weekday;
}

function assertCronExpression(value: string, label: string): void {
    if (value.trim().split(/\s+/).length !== 6) {
        throw new Error(`${label} must use six fields: second minute hour day month weekday`);
    }
}

function parseSetupOptions(args: string[]): SetupOptions {
    const options: SetupOptions = {};
    const schedule: ModuleSchedule = {};
    let enableFlagSeen = false;
    let disableFlagSeen = false;

    for (let index = 0; index < args.length; index += 1) {
        const flag = args[index];
        const next = () => {
            index += 1;
            if (index >= args.length) {
                throw new Error(`${flag} requires a value`);
            }

            return args[index];
        };

        if (flag === "--enable") {
            enableFlagSeen = true;
            options.enabled = true;
        } else if (flag === "--disable") {
            disableFlagSeen = true;
            options.enabled = false;
        } else if (flag === "--every-seconds") {
            schedule.everySeconds = parsePositiveInteger(next(), flag);
        } else if (flag === "--every-minutes") {
            schedule.everySeconds = parsePositiveInteger(next(), flag) * 60;
        } else if (flag === "--every-hours") {
            schedule.everySeconds = parsePositiveInteger(next(), flag) * 3600;
        } else if (flag === "--daily-at") {
            const value = next();
            assertTimeOfDay(value, flag);
            schedule.dailyAt = [...(schedule.dailyAt ?? []), value];
        } else if (flag === "--cron") {
            const value = next();
            assertCronExpression(value, flag);
            schedule.cron = [...(schedule.cron ?? []), value];
        } else if (flag === "--weekday") {
            schedule.weekdays = [...(schedule.weekdays ?? []), parseWeekdayOption(next(), flag)];
        } else if (flag === "--window-start") {
            const value = next();
            assertTimeOfDay(value, flag);
            schedule.window = { start: value, end: schedule.window?.end ?? "23:59" };
        } else if (flag === "--window-end") {
            const value = next();
            assertTimeOfDay(value, flag);
            schedule.window = { start: schedule.window?.start ?? "00:00", end: value };
        } else {
            throw new Error(`Unknown setup option: ${flag}`);
        }
    }

    if (enableFlagSeen && disableFlagSeen) {
        throw new Error("Use only one of --enable or --disable");
    }

    const triggerCount = [schedule.cron, schedule.dailyAt, schedule.everySeconds].filter((value) => value !== undefined).length;
    if (triggerCount > 1) {
        throw new Error("Use only one schedule trigger per setup command");
    }

    if (triggerCount > 0 || schedule.weekdays || schedule.window) {
        options.schedule = schedule;
    }

    return options;
}

function yamlString(value: string): string {
    return /^[A-Za-z0-9_.:/-]+$/.test(value) ? value : JSON.stringify(value);
}

function scheduleYaml(schedule: ModuleSchedule, indent: string): string[] {
    const lines: string[] = [];
    if (schedule.cron) {
        lines.push(`${indent}cron:`);
        for (const expression of schedule.cron) {
            lines.push(`${indent}  - ${yamlString(expression)}`);
        }
    } else if (schedule.dailyAt) {
        if (schedule.dailyAt.length === 1) {
            lines.push(`${indent}daily_at: ${yamlString(schedule.dailyAt[0])}`);
        } else {
            lines.push(`${indent}daily_at:`);
            for (const time of schedule.dailyAt) {
                lines.push(`${indent}  - ${yamlString(time)}`);
            }
        }
    } else if (schedule.everySeconds) {
        if (schedule.everySeconds >= 3600 && schedule.everySeconds % 3600 === 0) {
            lines.push(`${indent}every_hours: ${schedule.everySeconds / 3600}`);
        } else if (schedule.everySeconds >= 60 && schedule.everySeconds % 60 === 0) {
            lines.push(`${indent}every_minutes: ${schedule.everySeconds / 60}`);
        } else {
            lines.push(`${indent}every_seconds: ${schedule.everySeconds}`);
        }
    }

    if (schedule.weekdays && schedule.weekdays.length > 0) {
        lines.push(`${indent}weekdays:`);
        for (const weekday of schedule.weekdays) {
            lines.push(`${indent}  - ${weekday}`);
        }
    }

    if (schedule.window) {
        lines.push(`${indent}window:`);
        lines.push(`${indent}  start: ${yamlString(schedule.window.start)}`);
        lines.push(`${indent}  end: ${yamlString(schedule.window.end)}`);
    }

    return lines;
}

function serializeServiceConfig(config: ServiceConfig): string {
    const homeDir = process.env.HOME;
    const logDir = homeDir && config.logDir.startsWith(homeDir) ? config.logDir.replace(homeDir, "~") : config.logDir;
    const lines = [
        `label: ${config.label}`,
        `log_dir: ${logDir}`,
        `watch: ${config.watch ? "true" : "false"}`,
        "modules:",
    ];

    for (const moduleName of Object.keys(config.modules).sort()) {
        const moduleConfig = config.modules[moduleName];
        lines.push(`  ${moduleName}:`);
        lines.push(`    enabled: ${moduleConfig.enabled ? "true" : "false"}`);
        if (moduleConfig.schedule) {
            lines.push("    schedule:");
            lines.push(...scheduleYaml(moduleConfig.schedule, "      "));
        }
    }

    return `${lines.join("\n")}\n`;
}

async function updateModuleSetup(moduleName: string, options: SetupOptions): Promise<number> {
    if (options.enabled === undefined && !options.schedule) {
        return await setupModule(moduleName);
    }

    const repoRoot = resolveRepoRoot();
    const modules = await discoverModules(repoRoot);
    if (!modules.has(moduleName)) {
        throw new Error(`Unknown module: ${moduleName}`);
    }

    const config = await loadServiceConfig(repoRoot);
    const current = config.modules[moduleName] ?? { enabled: false };
    config.modules[moduleName] = {
        ...current,
        enabled: options.enabled ?? current.enabled,
        schedule: options.schedule ?? current.schedule,
    };

    await fs.writeFile(config.path, serializeServiceConfig(config), "utf8");
    console.log(`Updated ${moduleName} in service.yaml`);
    return 0;
}

export async function runCli(argv: string[] = process.argv.slice(2)): Promise<number> {
    const [command, target] = argv;

    if (command === "__runtime_probe") {
        return 0;
    }

    if (!command || command === "help" || command === "--help" || command === "-h") {
        console.log(usage());
        return command ? 0 : 2;
    }

    if (command === "start") {
        if (target !== "root") {
            console.error(usage());
            return 2;
        }

        return await startRoot();
    }

    if (command === "uninstall") {
        if (target !== "root") {
            console.error(usage());
            return 2;
        }

        return await uninstallRoot();
    }

    if (command === "stop") {
        if (target !== "root") {
            console.error(usage());
            return 2;
        }

        return await stopRoot();
    }

    if (command === "run") {
        if (!target) {
            console.error(usage());
            return 2;
        }

        if (target === "root") {
            await runSupervisor();
            return 0;
        }

        return await runModule(target);
    }

    if (command === "status") {
        await renderStatus();
        return 0;
    }

    if (command === "setup") {
        if (!target) {
            console.error(usage());
            return 2;
        }

        return await updateModuleSetup(target, parseSetupOptions(argv.slice(2)));
    }

    if (command === "test") {
        return await runAllTests();
    }

    console.error(usage());
    return 2;
}

runCli().then(
    (code) => {
        process.exitCode = code;
    },
    (error) => {
        console.error(error instanceof Error ? `Error: ${error.message}` : String(error));
        process.exitCode = 1;
    },
);
