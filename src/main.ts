import path from "node:path";
import { promises as fs } from "node:fs";
import { spawnSync } from "node:child_process";
import { discoverModules, ensureDirectory, loadServiceConfig } from "./config.ts";
import { runModuleDirect, runModuleSetup } from "./module-runner.ts";
import { resolveManageScriptPath, resolveRepoRoot, resolveStateDir, resolveStateFile } from "./paths.ts";
import { renderStatus } from "./status.ts";
import { runSupervisor } from "./supervisor.ts";
import { runAllTests } from "./test.ts";

type PersistedState = {
    supervisor?: {
        pid?: number;
    };
};

function usage(): string {
    return `Usage:
  scriptd.sh start root
  scriptd.sh restart root
  scriptd.sh stop root
  scriptd.sh uninstall root
  scriptd.sh run <module>
  scriptd.sh reload
  scriptd.sh status
  scriptd.sh setup <module>
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
    await fs.writeFile(executablePath, `#!/bin/bash\nexec ${shellQuote(manageScriptPath)} run root\n`, "utf8");
    await fs.chmod(executablePath, 0o755);
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

async function startRoot(options: { restart?: boolean; alias?: "install" } = {}): Promise<number> {
    const { label, plistPath } = await writeRootPlist();

    if (options.restart) {
        runLaunchctl(["unload", plistPath], false);
    }
    runLaunchctl(["enable", launchdDomainLabel(label)], false);
    runLaunchctl(["load", "-w", plistPath], true);
    console.log(`${options.alias === "install" ? "Installed" : options.restart ? "Restarted" : "Started"} root LaunchAgent ${label}`);
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

async function reloadRoot(): Promise<number> {
    const repoRoot = resolveRepoRoot();
    const config = await loadServiceConfig(repoRoot);
    const stateFile = resolveStateFile();

    try {
        const parsed = JSON.parse(await fs.readFile(stateFile, "utf8")) as PersistedState;
        const pid = parsed.supervisor?.pid;
        if (typeof pid === "number") {
            process.kill(pid, "SIGHUP");
            console.log(`Sent SIGHUP to supervisor PID ${pid}`);
            return 0;
        }
    } catch {
        // fall back to launchctl
    }

    const result = spawnSync("launchctl", ["kill", "HUP", launchdDomainLabel(config.label)], { encoding: "utf8" });
    if (result.status !== 0) {
        throw new Error("Could not find a running scriptd service to reload.");
    }

    console.log(`Requested launchd reload for ${config.label}`);
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

export async function runCli(argv: string[] = process.argv.slice(2)): Promise<number> {
    const [command, target] = argv;

    if (command === "__runtime_probe") {
        return 0;
    }

    if (!command || command === "help" || command === "--help" || command === "-h") {
        console.log(usage());
        return command ? 0 : 2;
    }

    if (command === "install" || command === "start" || command === "restart") {
        if (target !== "root") {
            console.error(usage());
            return 2;
        }

        return await startRoot({
            restart: command === "restart",
            alias: command === "install" ? "install" : undefined,
        });
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

    if (command === "reload") {
        return await reloadRoot();
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

        return await setupModule(target);
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
