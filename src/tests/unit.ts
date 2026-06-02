import assert from "node:assert/strict";
import os from "node:os";
import path from "node:path";
import { existsSync } from "node:fs";
import { mkdtemp, mkdir, rm, writeFile } from "node:fs/promises";
import {
    buildIntervalPlan,
    buildModuleStateDiff,
    discoverModules,
    expandHome,
    loadServiceConfig,
    nextScheduledRun,
    parseSimpleYaml,
} from "../config.ts";
import { resolveRepoRoot, resolveServiceConfigPath } from "../paths.ts";
import { decideWifiSwitch, parseSwiftWifiScanOutput, scoreNetwork, resolveWifiMonitorConfig } from "../../modules/wifi-monitor/module.ts";
import { buildBrewCommands } from "../../modules/brew-manager/module.ts";
import { parseCpuSnapshot, reconcileTrackedProcesses } from "../../modules/cpu-monitor/module.ts";
import type { TestCase } from "./harness.ts";

const tempDirs: string[] = [];

async function makeTempRoot(): Promise<string> {
    const dir = await mkdtemp(path.join(os.tmpdir(), "scriptd-test-"));
    tempDirs.push(dir);
    return dir;
}

async function cleanupTempDirs(): Promise<void> {
    while (tempDirs.length > 0) {
        const dir = tempDirs.pop();
        if (dir) {
            await rm(dir, { recursive: true, force: true });
        }
    }
}

export function createUnitTests(): TestCase[] {
    return [
        {
            name: "parseSimpleYaml parses nested service mappings",
            run: async () => {
                try {
                    const parsed = parseSimpleYaml(`
label: com.omar.scriptd
log_dir: ~/Library/Logs/scriptd
watch: true
modules:
  wifi-monitor:
    enabled: true
  cpu-monitor:
    enabled: false
`);

                    assert.equal(parsed.label, "com.omar.scriptd");
                    assert.equal(parsed.watch, true);
                    assert.deepEqual(parsed.modules, {
                        "wifi-monitor": { enabled: true },
                        "cpu-monitor": { enabled: false },
                    });
                } finally {
                    await cleanupTempDirs();
                }
            },
        },
        {
            name: "parseSimpleYaml parses simple lists for module manifests",
            run: async () => {
                try {
                    const parsed = parseSimpleYaml(`
exclude_apps:
  - Finder
  - Dock
`);

                    assert.deepEqual(parsed.exclude_apps, ["Finder", "Dock"]);
                } finally {
                    await cleanupTempDirs();
                }
            },
        },
        {
            name: "loadServiceConfig uses repo-root service.yaml and expands home",
            run: async () => {
                try {
                    const rootDir = await makeTempRoot();
                    await mkdir(rootDir, { recursive: true });
                    await writeFile(
                        path.join(rootDir, "service.yaml"),
                        `label: com.omar.scriptd
log_dir: ~/Library/Logs/scriptd
watch: true
modules:
  brew-manager:
    enabled: true
    schedule:
      every_hours: 12
`,
                    );

                    const config = await loadServiceConfig(rootDir);
                    assert.equal(config.path, path.join(rootDir, "service.yaml"));
                    assert.equal(config.logDir, path.join(process.env.HOME ?? os.homedir(), "Library", "Logs", "scriptd"));
                    assert.equal(config.modules["brew-manager"]?.enabled, true);
                    assert.equal(config.modules["brew-manager"]?.schedule?.everySeconds, 43_200);
                } finally {
                    await cleanupTempDirs();
                }
            },
        },
        {
            name: "discoverModules loads top-level module.ts plugins",
            run: async () => {
                try {
                    const rootDir = await makeTempRoot();
                    await mkdir(path.join(rootDir, "modules", "wifi-monitor"), { recursive: true });
                    await writeFile(
                        path.join(rootDir, "modules", "wifi-monitor", "module.ts"),
                        `export default {
  id: "wifi-monitor",
  mode: "daemon",
  async start() {}
};`,
                    );
                    await writeFile(
                        path.join(rootDir, "modules", "wifi-monitor", "module.yaml"),
                        `id: wifi-monitor
mode: daemon
`,
                    );

                    const modules = await discoverModules(rootDir);
                    const plugin = modules.get("wifi-monitor");
                    assert.equal(plugin?.plugin.mode, "daemon");
                    assert.equal(plugin?.modulePath, path.join(rootDir, "modules", "wifi-monitor", "module.ts"));
                } finally {
                    await cleanupTempDirs();
                }
            },
        },
        {
            name: "discoverModules rejects invalid module exports",
            run: async () => {
                try {
                    const rootDir = await makeTempRoot();
                    await mkdir(path.join(rootDir, "modules", "bad-module"), { recursive: true });
                    await writeFile(path.join(rootDir, "modules", "bad-module", "module.ts"), `export default { id: "bad-module", mode: "daemon" };`);
                    await writeFile(path.join(rootDir, "modules", "bad-module", "module.yaml"), `id: bad-module\nmode: daemon\n`);

                    await assert.rejects(() => discoverModules(rootDir), /must implement start/);
                } finally {
                    await cleanupTempDirs();
                }
            },
        },
        {
            name: "discoverModules validates interval metadata from module.yaml",
            run: async () => {
                try {
                    const rootDir = await makeTempRoot();
                    await mkdir(path.join(rootDir, "modules", "ticker"), { recursive: true });
                    await writeFile(
                        path.join(rootDir, "modules", "ticker", "module.ts"),
                        `export default {
  id: "ticker",
  mode: "interval",
  intervalMs: 1000,
  async runOnce() {}
};`,
                    );
                    await writeFile(path.join(rootDir, "modules", "ticker", "module.yaml"), `id: ticker\nmode: interval\ninterval_seconds: 2\n`);

                    await assert.rejects(() => discoverModules(rootDir), /interval mismatch/);
                } finally {
                    await cleanupTempDirs();
                }
            },
        },
        {
            name: "buildModuleStateDiff computes enable and disable transitions",
            run: async () => {
                try {
                    const diff = buildModuleStateDiff(
                        { "wifi-monitor": true, "cpu-monitor": false },
                        { "wifi-monitor": false, "cpu-monitor": true, "brew-manager": true },
                    );

                    assert.deepEqual(diff.toStart, ["brew-manager", "cpu-monitor"]);
                    assert.deepEqual(diff.toStop, ["wifi-monitor"]);
                } finally {
                    await cleanupTempDirs();
                }
            },
        },
        {
            name: "buildIntervalPlan prevents overlap and schedules idle runs",
            run: async () => {
                try {
                    const blocked = buildIntervalPlan({
                        desiredEnabled: true,
                        isRunning: true,
                        intervalMs: 30000,
                    });
                    assert.equal(blocked.shouldSchedule, false);
                    assert.equal(blocked.delayMs, null);

                    const scheduled = buildIntervalPlan({
                        desiredEnabled: true,
                        isRunning: false,
                        intervalMs: 30000,
                        now: new Date("2026-06-02T10:00:00.000Z"),
                    });
                    assert.equal(scheduled.shouldSchedule, true);
                    assert.equal(scheduled.delayMs, 30000);
                } finally {
                    await cleanupTempDirs();
                }
            },
        },
        {
            name: "service schedules normalize friendly timing to cron-backed next runs",
            run: () => {
                const everyHour = nextScheduledRun(
                    { everySeconds: 3600 },
                    new Date("2026-06-02T10:15:00.000Z"),
                    30000,
                );
                assert.equal(everyHour?.toISOString(), "2026-06-02T11:00:00.000Z");

                const daily = nextScheduledRun(
                    { dailyAt: ["09:30"], weekdays: ["wed"], window: { start: "09:00", end: "17:00" } },
                    new Date("2026-06-02T10:15:00.000Z"),
                    30000,
                );
                assert.equal(daily?.getDay(), 3);
                assert.equal(daily?.getHours(), 9);
                assert.equal(daily?.getMinutes(), 30);
            },
        },
        {
            name: "lean src layout exists and old root helpers are gone",
            run: async () => {
                try {
                    const repoRoot = resolveRepoRoot();
                    assert.equal(resolveServiceConfigPath(repoRoot), path.join(repoRoot, "service.yaml"));
                    assert.equal(existsSync(path.join(repoRoot, "service.yaml")), true);
                    assert.equal(existsSync(path.join(repoRoot, "src", "main.ts")), true);
                    assert.equal(existsSync(path.join(repoRoot, "run_tests.sh")), false);
                    assert.equal(existsSync(path.join(repoRoot, "tools", "check_no_dep_dirs.sh")), false);
                    assert.equal(existsSync(path.join(repoRoot, "test", "manage_smoke.sh")), false);
                    assert.equal(existsSync(path.join(repoRoot, "root-service")), false);
                } finally {
                    await cleanupTempDirs();
                }
            },
        },
        {
            name: "expandHome resolves leading tildes",
            run: async () => {
                try {
                    assert.equal(
                        expandHome("~/Library/Logs/scriptd"),
                        path.join(process.env.HOME ?? os.homedir(), "Library", "Logs", "scriptd"),
                    );
                } finally {
                    await cleanupTempDirs();
                }
            },
        },
        {
            name: "wifi-monitor config resolves env overrides and scores networks",
            run: () => {
                const config = resolveWifiMonitorConfig(
                    {
                        min_dwell: 180,
                        ping_target: "1.1.1.1",
                        ping_timeout: 1,
                        band_bonus_2g: 0,
                        band_bonus_5g: 100,
                        band_bonus_6g: 150,
                        rssi_offset: 100,
                        min_switch_score_delta: 10,
                        ssids: ["One"],
                    },
                    { WIFI_MONITOR_SSIDS: "Two,Three" },
                );

                assert.deepEqual(config.ssids, ["Two", "Three"]);
                assert.equal(
                    scoreNetwork(
                        { ssid: "X", band: "5g", rssi: -50, channel: "36", security: "WPA2", pingMs: 20 },
                        config,
                    ) > 0,
                    true,
                );
            },
        },
        {
            name: "wifi-monitor decision keeps stable connections unless priority or score clearly wins",
            run: () => {
                const config = resolveWifiMonitorConfig(
                    {
                        min_dwell: 180,
                        ping_target: "1.1.1.1",
                        ping_timeout: 1,
                        band_bonus_2g: 0,
                        band_bonus_5g: 100,
                        band_bonus_6g: 150,
                        rssi_offset: 100,
                        min_switch_score_delta: 10,
                        ssids: ["Office", "Home"],
                    },
                    {},
                );

                const networks = [
                    { ssid: "Home", band: "5g" as const, rssi: -45, channel: "36", security: "WPA2" },
                    { ssid: "Office", band: "2g" as const, rssi: -40, channel: "6", security: "WPA2" },
                ];

                assert.deepEqual(
                    decideWifiSwitch({
                        currentSsid: "Home",
                        networks,
                        config,
                        priorityOrder: ["Home", "Office"],
                        dwellSatisfied: true,
                        currentHealthy: true,
                    }).action,
                    "stay",
                );

                assert.deepEqual(
                    decideWifiSwitch({
                        currentSsid: "Home",
                        networks,
                        config,
                        priorityOrder: ["Office", "Home"],
                        dwellSatisfied: true,
                        currentHealthy: true,
                    }).action,
                    "switch",
                );
            },
        },
        {
            name: "wifi-monitor parses CoreWLAN fallback scan output",
            run: () => {
                const networks = parseSwiftWifiScanOutput(
                    JSON.stringify([
                        {
                            ssid: "knight_riders_5G",
                            rssi: -68,
                            channel: "161",
                            summary:
                                "<CWNetwork: 0x10afafb60> [ssid=knight_riders_5G, bssid=(null), security=WPA2 Personal, rssi=-68, channel=<CWChannel: 0x10afb3dd0> [channelNumber=161(5GHz), channelWidth={80MHz}], ibss=0]",
                        },
                        {
                            ssid: "Lab6E",
                            rssi: -55,
                            channel: "233",
                            summary:
                                "<CWNetwork: 0x10afb3a60> [ssid=Lab6E, bssid=(null), security=WPA3 Personal, rssi=-55, channel=<CWChannel: 0x10afb3db0> [channelNumber=233(6GHz), channelWidth={160MHz}], ibss=0]",
                        },
                    ]),
                );

                assert.deepEqual(networks, [
                    {
                        ssid: "knight_riders_5G",
                        band: "5g",
                        rssi: -68,
                        channel: "161",
                        security: "WPA2 Personal",
                    },
                    {
                        ssid: "Lab6E",
                        band: "6g",
                        rssi: -55,
                        channel: "233",
                        security: "WPA3 Personal",
                    },
                ]);
            },
        },
        {
            name: "brew-manager command plan includes cask fallback and cleanup",
            run: () => {
                const commands = buildBrewCommands("/opt/homebrew/bin/brew", ["alpha", "beta"]);
                assert.equal(commands.at(-1)?.args[0], "cleanup");
                assert.deepEqual(commands[3], {
                    args: ["upgrade", "--cask", "--force", "alpha"],
                    tolerateFailure: true,
                });
            },
        },
        {
            name: "cpu-monitor reconciliation tracks and cleans processes in TS",
            run: () => {
                const snapshot = parseCpuSnapshot(
                    `123 75.0 /Applications/Test.app/Contents/MacOS/Test
456 10.0 /usr/bin/low
`,
                    50,
                    ["Finder"],
                );
                const tracked = reconcileTrackedProcesses(new Map(), snapshot, 1000, 600);
                assert.equal(tracked.get(123)?.cpu, 75);
                const cleaned = reconcileTrackedProcesses(tracked, [], 1030, 600);
                assert.equal(cleaned.size, 0);
            },
        },
    ];
}
