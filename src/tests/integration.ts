import assert from "node:assert/strict";
import os from "node:os";
import path from "node:path";
import { existsSync, readFileSync } from "node:fs";
import { chmod, mkdtemp, mkdir, rm, writeFile } from "node:fs/promises";
import { spawn, spawnSync } from "node:child_process";
import { resolveManageScriptPath, resolveRepoRoot } from "../paths.ts";
import type { TestCase } from "./harness.ts";

type Sandbox = {
    repoRoot: string;
    homeDir: string;
    binDir: string;
    runtimeLogPath: string;
    launchctlLogPath: string;
    tempRoot: string;
};

const actualRepoRoot = resolveRepoRoot();
const actualManageScriptPath = resolveManageScriptPath(actualRepoRoot);
const actualBun = "/opt/homebrew/bin/bun";
const actualNode = "/opt/homebrew/bin/node";
const actualNpx = "/opt/homebrew/bin/npx";

async function createSandbox(): Promise<Sandbox> {
    const tempRoot = await mkdtemp(path.join(os.tmpdir(), "scriptd-integration-"));
    const repoRoot = path.join(tempRoot, "repo");
    const homeDir = path.join(tempRoot, "home");
    const binDir = path.join(tempRoot, "bin");
    const runtimeLogPath = path.join(tempRoot, "runtime.log");
    const launchctlLogPath = path.join(tempRoot, "launchctl.log");
    const launchctlStatePath = path.join(tempRoot, "launchctl-state");

    await mkdir(repoRoot, { recursive: true });
    await mkdir(path.join(repoRoot, "src"), { recursive: true });
    await mkdir(path.join(repoRoot, "assets"), { recursive: true });
    await mkdir(path.join(repoRoot, "modules", "wifi-monitor"), { recursive: true });
    await mkdir(path.join(repoRoot, "modules", "cpu-monitor"), { recursive: true });
    await mkdir(path.join(repoRoot, "modules", "brew-manager"), { recursive: true });
    await mkdir(path.join(homeDir, "Library", "LaunchAgents"), { recursive: true });
    await mkdir(binDir, { recursive: true });

    await writeFile(
        path.join(repoRoot, "service.yaml"),
        `label: com.omar.scriptd
log_dir: ~/Library/Logs/scriptd
watch: true
modules:
  wifi-monitor:
    enabled: true
    schedule:
      every_seconds: 30
  cpu-monitor:
    enabled: false
    schedule:
      every_seconds: 30
  brew-manager:
    enabled: true
    schedule:
      every_seconds: 30
`,
    );
    await writeFile(
        path.join(repoRoot, "scriptd.sh"),
        `#!/bin/bash
exit 0
`,
    );
    await chmod(path.join(repoRoot, "scriptd.sh"), 0o755);
    await writeFile(path.join(repoRoot, "assets", "Scriptd.icns"), "fake-icns\n", "utf8");
    await writeFile(path.join(repoRoot, "package.json"), `{"name":"scriptd","private":true,"type":"module","workspaces":["modules/*"]}\n`);
    await writeFile(
        path.join(repoRoot, "tsconfig.json"),
        `{"compilerOptions":{"target":"ES2022","module":"NodeNext","moduleResolution":"NodeNext","noEmit":true}}\n`,
    );
    await writeFile(path.join(repoRoot, "src", "main.ts"), "export {}\n");

    await writeFile(
        path.join(repoRoot, "modules", "wifi-monitor", "module.ts"),
        `export default {
  id: "wifi-monitor",
  mode: "interval",
  intervalMs: 30000,
  async runOnce(ctx) {
    ctx.log.info("sandbox wifi module ran");
  },
  status() {
    return { state: "running", message: "sandbox-ok", metrics: { loops: 1 } };
  },
  health() {
    return { ok: true, message: "healthy" };
  }
};`,
    );
    await writeFile(
        path.join(repoRoot, "modules", "wifi-monitor", "module.yaml"),
        `id: wifi-monitor
mode: interval
interval_seconds: 30
`,
    );
    await writeFile(
        path.join(repoRoot, "modules", "cpu-monitor", "module.ts"),
        `export default {
  id: "cpu-monitor",
  mode: "interval",
  intervalMs: 30000,
  async runOnce(ctx) {
    ctx.log.info("sandbox cpu module ran");
  }
};`,
    );
    await writeFile(
        path.join(repoRoot, "modules", "cpu-monitor", "module.yaml"),
        `id: cpu-monitor
mode: interval
interval_seconds: 30
`,
    );
    await writeFile(
        path.join(repoRoot, "modules", "brew-manager", "module.ts"),
        `export default {
  id: "brew-manager",
  mode: "interval",
  intervalMs: 30000,
  async runOnce(ctx) {
    ctx.log.info("sandbox brew module ran");
  }
};`,
    );
    await writeFile(
        path.join(repoRoot, "modules", "brew-manager", "module.yaml"),
        `id: brew-manager
mode: interval
interval_seconds: 30
`,
    );

    await writeFile(
        path.join(binDir, "launchctl"),
        `#!/bin/bash
echo "$*" >> "${launchctlLogPath}"
case "$1" in
  list)
    if [ -f "${launchctlStatePath}" ]; then
      echo "12345 0 com.omar.scriptd"
    fi
    ;;
  load)
    if [[ "$*" == *"com.omar.scriptd.plist"* ]]; then
      touch "${launchctlStatePath}"
    fi
    ;;
  unload)
    if [[ "$*" == *"com.omar.scriptd.plist"* ]]; then
      rm -f "${launchctlStatePath}"
    fi
    ;;
  remove)
    if [ "$2" = "com.omar.scriptd" ]; then
      rm -f "${launchctlStatePath}"
    fi
    ;;
esac
exit 0
`,
        "utf8",
    );
    await chmod(path.join(binDir, "launchctl"), 0o755);
    return { repoRoot, homeDir, binDir, runtimeLogPath, launchctlLogPath, tempRoot };
}

async function cleanupSandbox(sandbox: Sandbox): Promise<void> {
    await rm(sandbox.tempRoot, { recursive: true, force: true });
}

async function writeRuntimeWrapper(
    sandbox: Sandbox,
    name: string,
    mode: "delegate" | "fail",
    targetPath: string,
): Promise<void> {
    const wrapperPath = path.join(sandbox.binDir, name);
    const body =
        mode === "delegate"
            ? `#!/bin/bash
echo "${name}" >> "${sandbox.runtimeLogPath}"
PATH="${sandbox.binDir}:/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin"
exec "${targetPath}" "$@"
`
            : name === "node"
              ? `#!/bin/bash
echo "${name}" >> "${sandbox.runtimeLogPath}"
if [ "$1" = "--experimental-strip-types" ]; then
  exit 1
fi
PATH="${sandbox.binDir}:/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin"
exec "${targetPath}" "$@"
`
            : `#!/bin/bash
echo "${name}" >> "${sandbox.runtimeLogPath}"
exit 1
`;

    await writeFile(wrapperPath, body, "utf8");
    await chmod(wrapperPath, 0o755);
}

async function prepareRuntimeWrappers(
    sandbox: Sandbox,
    modes: { bun: "delegate" | "fail"; node: "delegate" | "fail"; npx: "delegate" | "fail" },
): Promise<void> {
    await writeRuntimeWrapper(sandbox, "bun", modes.bun, actualBun);
    await writeRuntimeWrapper(sandbox, "node", modes.node, actualNode);
    await writeRuntimeWrapper(sandbox, "npx", modes.npx, actualNpx);
}

function runManageCommand(
    sandbox: Sandbox,
    args: string[],
    extraEnv: NodeJS.ProcessEnv = {},
): { status: number | null; stdout: string; stderr: string } {
    const result = spawnSync(actualManageScriptPath, args, {
        cwd: actualRepoRoot,
        encoding: "utf8",
        env: {
            ...process.env,
            ...extraEnv,
            HOME: sandbox.homeDir,
            PATH: `${sandbox.binDir}:/usr/bin:/bin:/usr/sbin:/sbin`,
            SCRIPTD_ROOT_DIR: sandbox.repoRoot,
            SCRIPTD_ENTRY_SHELL_PATH: path.join(sandbox.repoRoot, "scriptd.sh"),
        },
    });

    return {
        status: result.status,
        stdout: result.stdout ?? "",
        stderr: result.stderr ?? "",
    };
}

function startManageCommand(sandbox: Sandbox, args: string[], extraEnv: NodeJS.ProcessEnv = {}) {
    return spawn(actualManageScriptPath, args, {
        cwd: actualRepoRoot,
        env: {
            ...process.env,
            ...extraEnv,
            HOME: sandbox.homeDir,
            PATH: `${sandbox.binDir}:/usr/bin:/bin:/usr/sbin:/sbin`,
            SCRIPTD_ROOT_DIR: sandbox.repoRoot,
            SCRIPTD_ENTRY_SHELL_PATH: path.join(sandbox.repoRoot, "scriptd.sh"),
        },
        stdio: "pipe",
    });
}

async function waitFor(predicate: () => boolean, timeoutMs = 5000): Promise<void> {
    const deadline = Date.now() + timeoutMs;

    while (Date.now() < deadline) {
        if (predicate()) {
            return;
        }

        await new Promise((resolve) => setTimeout(resolve, 50));
    }

    throw new Error(`Timed out after ${timeoutMs}ms`);
}

function readJsonFile<T>(filePath: string): T | undefined {
    try {
        return JSON.parse(readFileSync(filePath, "utf8")) as T;
    } catch {
        return undefined;
    }
}

export function createIntegrationTests(): TestCase[] {
    return [
        {
            name: "scriptd.sh status uses bun when available",
            run: async () => {
                const sandbox = await createSandbox();
                try {
                    await prepareRuntimeWrappers(sandbox, {
                        bun: "delegate",
                        node: "delegate",
                        npx: "delegate",
                    });

                    const result = runManageCommand(sandbox, ["status"]);
                    assert.equal(result.status, 0);
                    assert.match(result.stdout, /Config path: .*\/service\.yaml/);
                    assert.equal(readFileSync(sandbox.runtimeLogPath, "utf8").trim().split("\n")[0], "bun");
                } finally {
                    await cleanupSandbox(sandbox);
                }
            },
        },
        {
            name: "help exposes only the public root lifecycle commands",
            run: async () => {
                const sandbox = await createSandbox();
                try {
                    await prepareRuntimeWrappers(sandbox, {
                        bun: "delegate",
                        node: "delegate",
                        npx: "delegate",
                    });

                    const help = runManageCommand(sandbox, ["help"]);
                    assert.equal(help.status, 0);
                    assert.match(help.stdout, /scriptd\.sh start root/);
                    assert.doesNotMatch(help.stdout, /^\s*scriptd\.sh restart root/m);
                    assert.doesNotMatch(help.stdout, /^\s*scriptd\.sh install root/m);
                    assert.doesNotMatch(help.stdout, /^\s*scriptd\.sh reload/m);

                    const restart = runManageCommand(sandbox, ["restart", "root"]);
                    assert.equal(restart.status, 2);
                    const install = runManageCommand(sandbox, ["install", "root"]);
                    assert.equal(install.status, 2);
                    const reload = runManageCommand(sandbox, ["reload"]);
                    assert.equal(reload.status, 2);
                } finally {
                    await cleanupSandbox(sandbox);
                }
            },
        },
        {
            name: "scriptd.sh status falls back to node strip-types when bun fails",
            run: async () => {
                const sandbox = await createSandbox();
                try {
                    await prepareRuntimeWrappers(sandbox, {
                        bun: "fail",
                        node: "delegate",
                        npx: "delegate",
                    });

                    const result = runManageCommand(sandbox, ["status"]);
                    assert.equal(result.status, 0);
                    const runtimes = readFileSync(sandbox.runtimeLogPath, "utf8").trim().split("\n");
                    assert.deepEqual(runtimes.slice(0, 3), ["bun", "node", "node"]);
                } finally {
                    await cleanupSandbox(sandbox);
                }
            },
        },
        {
            name: "scriptd.sh status falls back to npx tsx when bun and node fail",
            run: async () => {
                const sandbox = await createSandbox();
                try {
                    await prepareRuntimeWrappers(sandbox, {
                        bun: "fail",
                        node: "fail",
                        npx: "delegate",
                    });

                    const result = runManageCommand(sandbox, ["status"]);
                    assert.equal(result.status, 0);
                    const runtimes = readFileSync(sandbox.runtimeLogPath, "utf8").trim().split("\n");
                    assert.deepEqual(runtimes.slice(0, 4), ["bun", "node", "npx", "node"]);
                } finally {
                    await cleanupSandbox(sandbox);
                }
            },
        },
        {
            name: "status shows desired config separately from a stale runtime snapshot",
            run: async () => {
                const sandbox = await createSandbox();
                try {
                    await prepareRuntimeWrappers(sandbox, {
                        bun: "delegate",
                        node: "delegate",
                        npx: "delegate",
                    });

                    const stateDir = path.join(sandbox.homeDir, "Library", "Application Support", "scriptd");
                    await mkdir(stateDir, { recursive: true });
                    await writeFile(
                        path.join(stateDir, "state.json"),
                        `${JSON.stringify(
                            {
                                label: "com.omar.scriptd",
                                rootDir: sandbox.repoRoot,
                                configPath: path.join(sandbox.repoRoot, "service.yaml"),
                                logDir: path.join(sandbox.homeDir, "Library", "Logs", "scriptd"),
                                updatedAt: "2026-06-01T18:40:25.545Z",
                                supervisor: {
                                    pid: 47473,
                                    startedAt: "2026-06-01T18:35:21.250Z",
                                    watch: true,
                                },
                                modules: {
                                    "brew-manager": {
                                        desiredEnabled: false,
                                        status: "disabled",
                                        mode: "interval",
                                        runs: 0,
                                        restarts: 0,
                                        message: "module disabled",
                                    },
                                    "cpu-monitor": {
                                        desiredEnabled: false,
                                        status: "disabled",
                                        mode: "daemon",
                                        runs: 0,
                                        restarts: 0,
                                        message: "module disabled",
                                    },
                                    "wifi-monitor": {
                                        desiredEnabled: false,
                                        status: "disabled",
                                        mode: "daemon",
                                        runs: 0,
                                        restarts: 0,
                                        message: "module disabled",
                                    },
                                },
                            },
                            null,
                            2,
                        )}\n`,
                    );

                    const result = runManageCommand(sandbox, ["status"]);
                    assert.equal(result.status, 0);
                    assert.match(result.stdout, /scriptd state: stale snapshot \(LaunchAgent not loaded\)/);
                    assert.match(result.stdout, /brew-manager: desired=enabled, interval, last=disabled, next=\d{4}-/);
                    assert.match(result.stdout, /wifi-monitor: desired=enabled, interval, last=disabled, next=/);
                    assert.doesNotMatch(result.stdout, /module disabled/);
                } finally {
                    await cleanupSandbox(sandbox);
                }
            },
        },
        {
            name: "status reports unreadable state without crashing",
            run: async () => {
                const sandbox = await createSandbox();
                try {
                    await prepareRuntimeWrappers(sandbox, {
                        bun: "delegate",
                        node: "delegate",
                        npx: "delegate",
                    });

                    const stateDir = path.join(sandbox.homeDir, "Library", "Application Support", "scriptd");
                    await mkdir(stateDir, { recursive: true });
                    await writeFile(path.join(stateDir, "state.json"), "{bad-json", "utf8");

                    const result = runManageCommand(sandbox, ["status"]);
                    assert.equal(result.status, 0);
                    assert.match(result.stdout, /scriptd state: unreadable/);
                    assert.match(result.stdout, /wifi-monitor: desired=enabled, interval, runtime=unknown, next=/);
                } finally {
                    await cleanupSandbox(sandbox);
                }
            },
        },
        {
            name: "run root preserves desired enabled state across shutdown",
            run: async () => {
                const sandbox = await createSandbox();
                try {
                    await prepareRuntimeWrappers(sandbox, {
                        bun: "delegate",
                        node: "delegate",
                        npx: "delegate",
                    });

                    const child = startManageCommand(sandbox, ["run", "root"]);
                    const stateFile = path.join(sandbox.homeDir, "Library", "Application Support", "scriptd", "state.json");
                    type State = {
                        modules: Record<string, { desiredEnabled: boolean; status: string; message: string }>;
                    };
                    await waitFor(() => {
                        const state = readJsonFile<State>(stateFile);
                        return state?.modules["wifi-monitor"]?.status === "scheduled" && state.modules["brew-manager"]?.status === "scheduled";
                    });

                    child.kill("SIGTERM");
                    await new Promise<void>((resolve, reject) => {
                        child.once("exit", () => resolve());
                        child.once("error", reject);
                    });

                    const state = JSON.parse(readFileSync(stateFile, "utf8")) as State;

                    assert.equal(state.modules["wifi-monitor"]?.desiredEnabled, true);
                    assert.equal(state.modules["wifi-monitor"]?.status, "stopped");
                    assert.equal(state.modules["wifi-monitor"]?.message, "supervisor stopped");
                    assert.equal(state.modules["brew-manager"]?.desiredEnabled, true);
                    assert.equal(state.modules["brew-manager"]?.status, "stopped");
                    assert.equal(state.modules["brew-manager"]?.message, "supervisor stopped");
                    assert.equal(state.modules["cpu-monitor"]?.desiredEnabled, false);
                } finally {
                    await cleanupSandbox(sandbox);
                }
            },
        },
        {
            name: "run root reloads service.yaml changes into live state",
            run: async () => {
                const sandbox = await createSandbox();
                let child: ReturnType<typeof startManageCommand> | undefined;
                try {
                    await prepareRuntimeWrappers(sandbox, {
                        bun: "delegate",
                        node: "delegate",
                        npx: "delegate",
                    });

                    child = startManageCommand(sandbox, ["run", "root"]);
                    const stateFile = path.join(sandbox.homeDir, "Library", "Application Support", "scriptd", "state.json");
                    type State = {
                        modules: Record<string, { desiredEnabled: boolean; status: string; mode: string; nextRunAt?: string }>;
                    };

                    await waitFor(() => readJsonFile<State>(stateFile)?.modules["wifi-monitor"]?.desiredEnabled === true);
                    await writeFile(
                        path.join(sandbox.repoRoot, "service.yaml"),
                        `label: com.omar.scriptd
log_dir: ~/Library/Logs/scriptd
watch: true
modules:
  wifi-monitor:
    enabled: false
    schedule:
      every_seconds: 30
  cpu-monitor:
    enabled: true
    schedule:
      every_seconds: 30
  brew-manager:
    enabled: true
    schedule:
      every_seconds: 30
`,
                    );

                    await waitFor(() => {
                        const state = readJsonFile<State>(stateFile);
                        return (
                            state?.modules["wifi-monitor"]?.desiredEnabled === false &&
                            state.modules["wifi-monitor"]?.status === "disabled" &&
                            state.modules["cpu-monitor"]?.desiredEnabled === true &&
                            state.modules["cpu-monitor"]?.status === "scheduled"
                        );
                    });

                    child.kill("SIGTERM");
                    await new Promise<void>((resolve, reject) => {
                        child.once("exit", () => resolve());
                        child.once("error", reject);
                    });
                } finally {
                    if (child && !child.killed) {
                        child.kill("SIGTERM");
                    }
                    await cleanupSandbox(sandbox);
                }
            },
        },
        {
            name: "start stop and uninstall root operate on the sandbox launch agents path",
            run: async () => {
                const sandbox = await createSandbox();
                try {
                    await prepareRuntimeWrappers(sandbox, {
                        bun: "delegate",
                        node: "delegate",
                        npx: "delegate",
                    });

                    await mkdir(path.join(sandbox.repoRoot, "node_modules"), { recursive: true });
                    const start = runManageCommand(sandbox, ["start", "root"]);
                    assert.equal(start.status, 0);
                    const plistPath = path.join(sandbox.homeDir, "Library", "LaunchAgents", "com.omar.scriptd.plist");
                    const appPath = path.join(sandbox.homeDir, "Library", "Application Support", "scriptd", "Scriptd.app");
                    const appExecutable = path.join(appPath, "Contents", "MacOS", "scriptd");
                    const sandboxManage = path.join(sandbox.repoRoot, "scriptd.sh");
                    assert.equal(existsSync(plistPath), true);
                    assert.match(readFileSync(plistPath, "utf8"), new RegExp(appExecutable.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
                    assert.match(readFileSync(plistPath, "utf8"), new RegExp(sandbox.repoRoot.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
                    assert.match(readFileSync(path.join(appPath, "Contents", "Info.plist"), "utf8"), /CFBundleIconFile/);
                    assert.equal(existsSync(path.join(appPath, "Contents", "Resources", "Scriptd.icns")), true);
                    assert.match(readFileSync(appExecutable, "utf8"), new RegExp(sandboxManage.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));

                    const secondStart = runManageCommand(sandbox, ["start", "root"]);
                    assert.equal(secondStart.status, 0);
                    const launchctlLog = readFileSync(sandbox.launchctlLogPath, "utf8");
                    assert.match(launchctlLog, /enable gui\/\d+\/com\.omar\.scriptd/);
                    assert.match(launchctlLog, /load -w .*com\.omar\.scriptd\.plist/);
                    assert.match(launchctlLog, /unload .*com\.omar\.scriptd\.plist/);

                    const stop = runManageCommand(sandbox, ["stop", "root"]);
                    assert.equal(stop.status, 0);
                    assert.equal(existsSync(plistPath), true);

                    const uninstall = runManageCommand(sandbox, ["uninstall", "root"]);
                    assert.equal(uninstall.status, 0);
                    assert.equal(existsSync(plistPath), false);
                } finally {
                    await cleanupSandbox(sandbox);
                }
            },
        },
        {
            name: "setup module updates enablement and schedule in service yaml",
            run: async () => {
                const sandbox = await createSandbox();
                try {
                    await prepareRuntimeWrappers(sandbox, {
                        bun: "delegate",
                        node: "delegate",
                        npx: "delegate",
                    });

                    const disable = runManageCommand(sandbox, ["setup", "wifi-monitor", "--disable"]);
                    assert.equal(disable.status, 0);
                    assert.match(disable.stdout, /Updated wifi-monitor in service\.yaml/);
                    let serviceYaml = readFileSync(path.join(sandbox.repoRoot, "service.yaml"), "utf8");
                    assert.match(serviceYaml, /wifi-monitor:\n    enabled: false/);

                    const schedule = runManageCommand(sandbox, [
                        "setup",
                        "wifi-monitor",
                        "--enable",
                        "--every-minutes",
                        "5",
                        "--weekday",
                        "mon",
                        "--window-start",
                        "09:00",
                        "--window-end",
                        "17:00",
                    ]);
                    assert.equal(schedule.status, 0);
                    serviceYaml = readFileSync(path.join(sandbox.repoRoot, "service.yaml"), "utf8");
                    assert.match(serviceYaml, /wifi-monitor:\n    enabled: true\n    schedule:\n      every_seconds: 300/);
                    assert.match(serviceYaml, /weekdays:\n        - mon/);
                    assert.match(serviceYaml, /window:\n        start: 09:00\n        end: 17:00/);
                } finally {
                    await cleanupSandbox(sandbox);
                }
            },
        },
        {
            name: "setup module rejects conflicting enablement flags",
            run: async () => {
                const sandbox = await createSandbox();
                try {
                    await prepareRuntimeWrappers(sandbox, {
                        bun: "delegate",
                        node: "delegate",
                        npx: "delegate",
                    });

                    const result = runManageCommand(sandbox, ["setup", "wifi-monitor", "--disable", "--enable"]);
                    assert.notEqual(result.status, 0);
                    assert.match(result.stderr, /Use only one of --enable or --disable/);
                } finally {
                    await cleanupSandbox(sandbox);
                }
            },
        },
        {
            name: "run module fails for an invalid module export in the sandbox repo",
            run: async () => {
                const sandbox = await createSandbox();
                try {
                    await prepareRuntimeWrappers(sandbox, {
                        bun: "delegate",
                        node: "delegate",
                        npx: "delegate",
                    });

                    await mkdir(path.join(sandbox.repoRoot, "modules", "broken-module"), { recursive: true });
                    await writeFile(path.join(sandbox.repoRoot, "modules", "broken-module", "module.ts"), `export default { id: "broken-module", mode: "interval" };`);
                    await writeFile(path.join(sandbox.repoRoot, "modules", "broken-module", "module.yaml"), `id: broken-module\nmode: interval\ninterval_seconds: 30\n`);

                    const result = runManageCommand(sandbox, ["run", "broken-module"]);
                    assert.notEqual(result.status, 0);
                    assert.match(result.stderr, /runOnce|RootServiceModule/);
                } finally {
                    await cleanupSandbox(sandbox);
                }
            },
        },
    ];
}
