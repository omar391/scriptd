import assert from "node:assert/strict";
import os from "node:os";
import path from "node:path";
import { existsSync } from "node:fs";
import { mkdtemp, mkdir, readFile, rm, stat, writeFile } from "node:fs/promises";
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
import {
    buildCandidateScore,
    decideWifiSwitch,
    dedupeNetworksBySsid,
    effectiveCurrentSsid,
    parsePingHealth,
    parseSwiftWifiScanOutput,
    scoreNetwork,
    resolveWifiMonitorConfig,
} from "../../modules/wifi-monitor/module.ts";
import { buildBrewCommands, ensureAskpassHelper, type BrewManagerConfig } from "../../modules/brew-manager/module.ts";
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
                        ping_count: 3,
                        ping_timeout: 1,
                        ping_high_latency_ms: 250,
                        health_failure_switch_runs: 2,
                        band_bonus_2g: 0,
                        band_bonus_5g: 35,
                        band_bonus_6g: 50,
                        preference_top_bonus: 30,
                        preference_rank_decay: 5,
                        current_sticky_bonus: 25,
                        rssi_offset: 100,
                        min_switch_score_delta: 25,
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
                        ping_count: 3,
                        ping_timeout: 1,
                        ping_high_latency_ms: 250,
                        health_failure_switch_runs: 2,
                        band_bonus_2g: 0,
                        band_bonus_5g: 35,
                        band_bonus_6g: 50,
                        preference_top_bonus: 30,
                        preference_rank_decay: 5,
                        current_sticky_bonus: 25,
                        rssi_offset: 100,
                        min_switch_score_delta: 25,
                        ssids: ["Office", "Home"],
                    },
                    {},
                );

                const networks = [
                    { ssid: "Home", band: "5g" as const, rssi: -40, channel: "36", security: "WPA2" },
                    { ssid: "Office", band: "2g" as const, rssi: -40, channel: "6", security: "WPA2" },
                ];
                const stickyCandidates = networks.map((network) =>
                    buildCandidateScore({
                        network,
                        config,
                        priorityOrder: ["Home", "Office"],
                        currentSsid: "Home",
                        currentHealthPenalty: 0,
                    }),
                );

                assert.deepEqual(
                    decideWifiSwitch({
                        currentSsid: "Home",
                        candidates: stickyCandidates,
                        config,
                        dwellSatisfied: true,
                        healthFailureStreak: 0,
                    }).action,
                    "stay",
                );

                const strongerOffice = [
                    { ssid: "Home", band: "5g" as const, rssi: -70, channel: "36", security: "WPA2" },
                    { ssid: "Office", band: "6g" as const, rssi: -20, channel: "233", security: "WPA3" },
                ].map((network) =>
                    buildCandidateScore({
                        network,
                        config,
                        priorityOrder: ["Office", "Home"],
                        currentSsid: "Home",
                        currentHealthPenalty: 0,
                    }),
                );
                assert.deepEqual(
                    decideWifiSwitch({
                        currentSsid: "Home",
                        candidates: strongerOffice,
                        config,
                        dwellSatisfied: true,
                        healthFailureStreak: 0,
                    }).action,
                    "switch",
                );
            },
        },
        {
            name: "wifi-monitor weighted scoring prefers strong 5g over weak 6g when total score is higher",
            run: () => {
                const config = resolveWifiMonitorConfig(
                    {
                        min_dwell: 180,
                        ping_target: "1.1.1.1",
                        ping_count: 3,
                        ping_timeout: 1,
                        ping_high_latency_ms: 250,
                        health_failure_switch_runs: 2,
                        band_bonus_2g: 0,
                        band_bonus_5g: 35,
                        band_bonus_6g: 50,
                        preference_top_bonus: 30,
                        preference_rank_decay: 5,
                        current_sticky_bonus: 25,
                        rssi_offset: 100,
                        min_switch_score_delta: 25,
                        ssids: ["Five", "Six"],
                    },
                    {},
                );

                const strong5g = buildCandidateScore({
                    network: { ssid: "Five", band: "5g", rssi: -35, channel: "149", security: "WPA2" },
                    config,
                    priorityOrder: ["Five", "Six"],
                    currentSsid: "",
                    currentHealthPenalty: 0,
                });
                const weak6g = buildCandidateScore({
                    network: { ssid: "Six", band: "6g", rssi: -70, channel: "233", security: "WPA3" },
                    config,
                    priorityOrder: ["Five", "Six"],
                    currentSsid: "",
                    currentHealthPenalty: 0,
                });

                assert.equal(strong5g.totalScore > weak6g.totalScore, true);
                assert.equal(weak6g.bandBonus > strong5g.bandBonus, true);
            },
        },
        {
            name: "wifi-monitor treats visible last-known SSID as current when macOS reports unknown",
            run: () => {
                const networks = [
                    { ssid: "knight_riders_5G", band: "5g" as const, rssi: -50, channel: "149", security: "WPA2" },
                    { ssid: "knight_riders", band: "2g" as const, rssi: -42, channel: "6", security: "WPA2" },
                ];

                assert.equal(effectiveCurrentSsid("", "knight_riders_5G", networks), "knight_riders_5G");
                assert.equal(effectiveCurrentSsid("", "missing", networks), "");
            },
        },
        {
            name: "wifi-monitor parses ping health penalties conservatively",
            run: () => {
                const healthy = parsePingHealth(
                    "3 packets transmitted, 3 packets received, 0.0% packet loss\nround-trip min/avg/max/stddev = 10.000/20.000/30.000/1.000 ms",
                    { pingHighLatencyMs: 250 },
                    0,
                );
                assert.equal(healthy.penalty, 0);
                assert.equal(healthy.healthy, true);

                const degraded = parsePingHealth(
                    "3 packets transmitted, 2 packets received, 33.3% packet loss\nround-trip min/avg/max/stddev = 10.000/260.000/400.000/1.000 ms",
                    { pingHighLatencyMs: 250 },
                    0,
                );
                assert.equal(degraded.penalty, 15);
                assert.equal(degraded.healthy, false);

                const severe = parsePingHealth(
                    "3 packets transmitted, 0 packets received, 100.0% packet loss",
                    { pingHighLatencyMs: 250 },
                    1,
                );
                assert.equal(severe.penalty, 70);
                assert.equal(severe.severe, true);
            },
        },
        {
            name: "wifi-monitor allows health-driven switch only after repeated failures",
            run: () => {
                const config = resolveWifiMonitorConfig(
                    {
                        min_dwell: 180,
                        ping_target: "1.1.1.1",
                        ping_count: 3,
                        ping_timeout: 1,
                        ping_high_latency_ms: 250,
                        health_failure_switch_runs: 2,
                        band_bonus_2g: 0,
                        band_bonus_5g: 35,
                        band_bonus_6g: 50,
                        preference_top_bonus: 30,
                        preference_rank_decay: 5,
                        current_sticky_bonus: 25,
                        rssi_offset: 100,
                        min_switch_score_delta: 25,
                        ssids: ["Home", "Backup"],
                    },
                    {},
                );
                const candidates = [
                    buildCandidateScore({
                        network: { ssid: "Home", band: "5g", rssi: -50, channel: "149", security: "WPA2" },
                        config,
                        priorityOrder: ["Home", "Backup"],
                        currentSsid: "Home",
                        currentHealthPenalty: 70,
                    }),
                    buildCandidateScore({
                        network: { ssid: "Backup", band: "2g", rssi: -40, channel: "6", security: "WPA2" },
                        config,
                        priorityOrder: ["Home", "Backup"],
                        currentSsid: "Home",
                        currentHealthPenalty: 70,
                    }),
                ];

                assert.equal(
                    decideWifiSwitch({
                        currentSsid: "Home",
                        candidates,
                        config,
                        dwellSatisfied: true,
                        healthFailureStreak: 1,
                    }).action,
                    "stay",
                );

                assert.equal(
                    decideWifiSwitch({
                        currentSsid: "Home",
                        candidates,
                        config,
                        dwellSatisfied: true,
                        healthFailureStreak: 2,
                    }).action,
                    "switch",
                );
            },
        },
        {
            name: "wifi-monitor deduplicates duplicate SSIDs to the strongest sample",
            run: () => {
                const config = resolveWifiMonitorConfig(
                    {
                        min_dwell: 180,
                        ping_target: "1.1.1.1",
                        ping_count: 3,
                        ping_timeout: 1,
                        ping_high_latency_ms: 250,
                        health_failure_switch_runs: 2,
                        band_bonus_2g: 0,
                        band_bonus_5g: 35,
                        band_bonus_6g: 50,
                        preference_top_bonus: 30,
                        preference_rank_decay: 5,
                        current_sticky_bonus: 25,
                        rssi_offset: 100,
                        min_switch_score_delta: 25,
                        ssids: ["Same", "Other"],
                    },
                    {},
                );
                const deduped = dedupeNetworksBySsid(
                    [
                        { ssid: "Same", band: "5g", rssi: -70, channel: "36", security: "WPA2" },
                        { ssid: "Same", band: "5g", rssi: -40, channel: "149", security: "WPA2" },
                        { ssid: "Other", band: "2g", rssi: -30, channel: "6", security: "WPA2" },
                    ],
                    config,
                    ["Same", "Other"],
                );

                assert.equal(deduped.length, 2);
                assert.equal(deduped.find((network) => network.ssid === "Same")?.rssi, -40);
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
            name: "brew-manager recreates missing askpass helper from keychain credential",
            run: async () => {
                try {
                    const rootDir = await makeTempRoot();
                    const config: BrewManagerConfig = {
                        keychainService: "BrewAutoUpdate",
                        askpassPath: path.join(rootDir, "brew_askpass.sh"),
                        legacyLogDir: path.join(rootDir, "logs"),
                        maxLogSizeMb: 50,
                        maxLogAgeDays: 30,
                        maxRotatedLogs: 5,
                        homebrewBin: "/opt/homebrew/bin/brew",
                        sudoersPath: "/etc/sudoers.d/homebrew",
                        sudoersTimeoutPath: "/etc/sudoers.d/homebrew_timeout",
                        sudoTimeoutHours: 2,
                    };

                    await ensureAskpassHelper(config, () => "stored-password");

                    const helper = await readFile(config.askpassPath, "utf8");
                    const mode = (await stat(config.askpassPath)).mode & 0o777;
                    assert.match(helper, /security find-generic-password -s "BrewAutoUpdate"/);
                    assert.equal(mode, 0o755);
                } finally {
                    await cleanupTempDirs();
                }
            },
        },
        {
            name: "brew-manager reports setup requirement when askpass credential is missing",
            run: async () => {
                try {
                    const rootDir = await makeTempRoot();
                    const config: BrewManagerConfig = {
                        keychainService: "BrewAutoUpdate",
                        askpassPath: path.join(rootDir, "brew_askpass.sh"),
                        legacyLogDir: path.join(rootDir, "logs"),
                        maxLogSizeMb: 50,
                        maxLogAgeDays: 30,
                        maxRotatedLogs: 5,
                        homebrewBin: "/opt/homebrew/bin/brew",
                        sudoersPath: "/etc/sudoers.d/homebrew",
                        sudoersTimeoutPath: "/etc/sudoers.d/homebrew_timeout",
                        sudoTimeoutHours: 2,
                    };

                    await assert.rejects(() => ensureAskpassHelper(config, () => ""), /setup required/);
                } finally {
                    await cleanupTempDirs();
                }
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
