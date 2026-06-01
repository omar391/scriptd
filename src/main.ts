import path from "node:path";
import { promises as fs } from "node:fs";
import { spawnSync } from "node:child_process";
import { discoverModules, ensureDirectory, loadServiceConfig } from "./config.ts";
import { runModuleDirect, runModuleSetup } from "./module-runner.ts";
import { resolveManageScriptPath, resolveRepoRoot, resolveStateFile } from "./paths.ts";
import { renderStatus } from "./status.ts";
import { runSupervisor } from "./supervisor.ts";
import { runAllTests } from "./test.ts";
import { assertNoDependencyDirs } from "./validate.ts";

type PersistedState = {
    supervisor?: {
        pid?: number;
    };
};

function usage(): string {
    return `Usage:
  scriptd.sh install root
  scriptd.sh uninstall root
  scriptd.sh run root
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

function runLaunchctl(args: string[], check: boolean): void {
    const result = spawnSync("launchctl", args, { encoding: "utf8" });
    if (check && result.status !== 0) {
        throw new Error(result.stderr || `launchctl ${args.join(" ")} failed`);
    }
}

function rootPlistPath(label: string): string {
    return path.join(process.env.HOME ?? "", "Library", "LaunchAgents", `${label}.plist`);
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
    manageScriptPath: string;
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
    <string>${escapeXml(options.manageScriptPath)}</string>
    <string>run</string>
    <string>root</string>
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

async function installRoot(): Promise<number> {
    const repoRoot = resolveRepoRoot();
    await assertNoDependencyDirs(repoRoot);

    const config = await loadServiceConfig(repoRoot);
    const plistPath = rootPlistPath(config.label);
    const manageScriptPath = resolveManageScriptPath(repoRoot);

    await ensureDirectory(path.dirname(plistPath));
    await ensureDirectory(config.logDir);
    await ensureDirectory(path.dirname(resolveStateFile()));
    await cleanupLegacyServices();

    await fs.writeFile(
        plistPath,
        plistContents({
            label: config.label,
            manageScriptPath,
            workingDirectory: repoRoot,
            logDir: config.logDir,
        }),
        "utf8",
    );

    runLaunchctl(["unload", plistPath], false);
    runLaunchctl(["load", "-w", plistPath], true);
    console.log(`Installed root LaunchAgent ${config.label}`);
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

    const uid = typeof process.getuid === "function" ? process.getuid() : 0;
    const result = spawnSync("launchctl", ["kill", "HUP", `gui/${uid}/${config.label}`], { encoding: "utf8" });
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

    if (command === "install") {
        if (target !== "root") {
            console.error(usage());
            return 2;
        }

        return await installRoot();
    }

    if (command === "uninstall") {
        if (target !== "root") {
            console.error(usage());
            return 2;
        }

        return await uninstallRoot();
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
        console.error(error instanceof Error ? error.stack ?? error.message : String(error));
        process.exitCode = 1;
    },
);
