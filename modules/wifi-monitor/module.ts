import path from "node:path";
import { promises as fs } from "node:fs";
import { spawnSync } from "node:child_process";
import type { ModuleContext, ModuleHealth, ModuleStatus, RootServiceModule } from "../../src/interfaces.ts";
import { assertPositiveInteger, parseSimpleYaml } from "../../src/config.ts";

const DEFAULT_AIRPORT_PATH = "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport";

export type Network = {
    ssid: string;
    band: "2g" | "5g" | "6g";
    rssi: number;
    channel: string;
    security: string;
    pingMs?: number;
};

export type WifiMonitorConfig = {
    minDwellSeconds: number;
    pingTarget: string;
    pingCount: number;
    pingTimeoutSeconds: number;
    pingHighLatencyMs: number;
    healthFailureSwitchRuns: number;
    bandBonus2g: number;
    bandBonus5g: number;
    bandBonus6g: number;
    preferenceTopBonus: number;
    preferenceRankDecay: number;
    currentStickyBonus: number;
    rssiOffset: number;
    minSwitchScoreDelta: number;
    ssids: string[];
    stateFile: string;
    configPath: string;
};

type WifiState = {
    currentSsid: string;
    lastSwitchAt?: string;
    lastDecision?: string;
    lastRunAt?: string;
    loopCount: number;
    lastError?: string;
};

const moduleState: WifiState = {
    currentSsid: "",
    loopCount: 0,
};

type PingHealth = {
    packetLossPercent: number;
    avgLatencyMs?: number;
    healthy: boolean;
    severe: boolean;
    penalty: number;
};

type PersistedWifiState = {
    lastSsid: string;
    lastConnectedAt?: string;
    lastSwitchAt?: string;
    healthFailureStreak: number;
    lastHealth?: {
        packetLossPercent: number;
        avgLatencyMs?: number;
    };
};

type CandidateScore = {
    network: Network;
    rank: number;
    rssiScore: number;
    bandBonus: number;
    preferenceBonus: number;
    stickyBonus: number;
    healthPenalty: number;
    totalScore: number;
};

function envNumber(raw: string | undefined, fallback: number): number {
    if (raw === undefined) {
        return fallback;
    }

    const parsed = Number(raw);
    return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
}

function airportPath(): string {
    const override = process.env.WIFI_MONITOR_AIRPORT_PATH?.trim();
    return override && override.length > 0 ? override : DEFAULT_AIRPORT_PATH;
}

function command(command: string, args: string[], check = true): string {
    const result = spawnSync(command, args, { encoding: "utf8" });
    if (check && result.status !== 0) {
        throw new Error(result.stderr || `command failed: ${[command, ...args].join(" ")}`);
    }

    return (result.stdout ?? "").trim();
}

async function readConfigFile(configPath: string): Promise<Record<string, unknown>> {
    try {
        const contents = await fs.readFile(configPath, "utf8");
        return parseSimpleYaml(contents);
    } catch {
        return {};
    }
}

function toStringArray(value: unknown): string[] {
    if (!Array.isArray(value)) {
        return [];
    }

    return value.filter((item): item is string => typeof item === "string");
}

function ensureStringValue(value: unknown, label: string): string {
    if (typeof value !== "string") {
        throw new Error(`${label} must be a string`);
    }

    return value;
}

function commandExists(commandName: string): boolean {
    const result = spawnSync("sh", ["-lc", `command -v ${JSON.stringify(commandName)} >/dev/null 2>&1`], {
        encoding: "utf8",
    });
    return result.status === 0;
}

function runSwift(code: string): string {
    const result = spawnSync("swift", ["-e", code], { encoding: "utf8" });
    if (result.status !== 0) {
        throw new Error(result.stderr || "swift command failed");
    }

    return (result.stdout ?? "").trim();
}

export function resolveWifiMonitorConfig(raw: Record<string, unknown>, env: NodeJS.ProcessEnv): WifiMonitorConfig {
    const configPath = typeof env.WIFI_MONITOR_CONFIG_PATH === "string" ? env.WIFI_MONITOR_CONFIG_PATH : "./module.yaml";
    const stateFile = env.WIFI_MONITOR_STATE_FILE ?? `${env.HOME ?? "/Users/omar"}/.local/share/wifi-monitor/state.txt`;
    const envSsids = (env.WIFI_MONITOR_SSIDS ?? "")
        .split(",")
        .map((item) => item.trim())
        .filter(Boolean);

    return {
        minDwellSeconds: envNumber(env.WIFI_MONITOR_MIN_DWELL, assertPositiveInteger(raw.min_dwell ?? 180, "wifi-monitor.min_dwell")),
        pingTarget: (env.WIFI_MONITOR_PING_TARGET ?? ensureStringValue(raw.ping_target ?? "1.1.1.1", "wifi-monitor.ping_target")).trim(),
        pingCount: envNumber(env.WIFI_MONITOR_PING_COUNT, assertPositiveInteger(raw.ping_count ?? 3, "wifi-monitor.ping_count")),
        pingTimeoutSeconds: envNumber(
            env.WIFI_MONITOR_PING_TIMEOUT,
            assertPositiveInteger(raw.ping_timeout ?? 1, "wifi-monitor.ping_timeout"),
        ),
        pingHighLatencyMs: envNumber(
            env.WIFI_MONITOR_PING_HIGH_LATENCY_MS,
            assertPositiveInteger(raw.ping_high_latency_ms ?? 250, "wifi-monitor.ping_high_latency_ms"),
        ),
        healthFailureSwitchRuns: envNumber(
            env.WIFI_MONITOR_HEALTH_FAILURE_SWITCH_RUNS,
            assertPositiveInteger(raw.health_failure_switch_runs ?? 2, "wifi-monitor.health_failure_switch_runs"),
        ),
        bandBonus2g: Number(raw.band_bonus_2g ?? 0),
        bandBonus5g: Number(raw.band_bonus_5g ?? 35),
        bandBonus6g: Number(raw.band_bonus_6g ?? 50),
        preferenceTopBonus: Number(raw.preference_top_bonus ?? 30),
        preferenceRankDecay: Number(raw.preference_rank_decay ?? 5),
        currentStickyBonus: Number(raw.current_sticky_bonus ?? 25),
        rssiOffset: Number(raw.rssi_offset ?? 100),
        minSwitchScoreDelta: envNumber(
            env.WIFI_MONITOR_MIN_SWITCH_SCORE_DELTA,
            assertPositiveInteger(raw.min_switch_score_delta ?? 25, "wifi-monitor.min_switch_score_delta"),
        ),
        ssids: envSsids.length > 0 ? envSsids : toStringArray(raw.ssids),
        stateFile,
        configPath,
    };
}

function wifiDevice(): string {
    const output = command("networksetup", ["-listallhardwareports"]);
    const lines = output.split("\n");

    for (let index = 0; index < lines.length; index += 1) {
        if (lines[index].trim() === "Hardware Port: Wi-Fi") {
            for (let offset = index + 1; offset < Math.min(index + 4, lines.length); offset += 1) {
                const match = lines[offset].trim().match(/^Device: (\S+)$/);
                if (match) {
                    return match[1];
                }
            }
        }
    }

    if (commandExists("swift")) {
        const output = runSwift(`
import Foundation
import CoreWLAN

if let iface = CWWiFiClient.shared().interface(), let name = iface.interfaceName {
    print(name)
}
`);
        if (output) {
            return output;
        }
    }

    throw new Error("could not find Wi-Fi device");
}

function currentSsid(device: string): string {
    const output = command("networksetup", ["-getairportnetwork", device], false);
    const match = output.match(/Current Wi-Fi Network: (.+)$/m);
    if (match?.[1]) {
        return match[1].trim();
    }

    if (commandExists("swift")) {
        return runSwift(`
import Foundation
import CoreWLAN

if let iface = CWWiFiClient.shared().interface(), let ssid = iface.ssid() {
    print(ssid)
}
`);
    }

    return "";
}

export function parsePingHealth(output: string, config: Pick<WifiMonitorConfig, "pingHighLatencyMs">, priorFailureStreak = 0): PingHealth {
    const lossMatch = output.match(/([0-9.]+)%\s+packet loss/);
    const avgMatch = output.match(/=\s*[0-9.]+\/([0-9.]+)\/[0-9.]+\/[0-9.]+\s*ms/);
    const packetLossPercent = lossMatch ? Number(lossMatch[1]) : 100;
    const avgLatencyMs = avgMatch ? Math.round(Number(avgMatch[1])) : undefined;
    const degraded = packetLossPercent > 0 || (avgLatencyMs !== undefined && avgLatencyMs > config.pingHighLatencyMs);
    const severe = packetLossPercent >= 100;
    let penalty = 0;
    if (severe) {
        penalty = 45;
    } else if (degraded) {
        penalty = 15;
    }

    if ((severe || degraded) && priorFailureStreak >= 1) {
        penalty += 25;
    }

    return {
        packetLossPercent,
        avgLatencyMs,
        healthy: !degraded,
        severe,
        penalty,
    };
}

function pingHealth(target: string, config: Pick<WifiMonitorConfig, "pingCount" | "pingTimeoutSeconds" | "pingHighLatencyMs">, priorFailureStreak = 0): PingHealth {
    if (!target) {
        return {
            packetLossPercent: 100,
            healthy: false,
            severe: true,
            penalty: priorFailureStreak >= 1 ? 70 : 45,
        };
    }

    const result = spawnSync("ping", ["-c", String(config.pingCount), "-W", String(config.pingTimeoutSeconds * 1000), target], {
        encoding: "utf8",
    });
    return parsePingHealth(`${result.stdout ?? ""}\n${result.stderr ?? ""}`, config, priorFailureStreak);
}

type SwiftScanRecord = {
    ssid: string;
    rssi: number;
    channel: string;
    summary?: string;
};

function parseSecurity(summary: string | undefined): string {
    if (!summary) {
        return "unknown";
    }

    const match = summary.match(/security=([^,\]]+)/i);
    return match?.[1]?.trim() ?? "unknown";
}

export function parseSwiftWifiScanOutput(output: string): Network[] {
    const parsed = JSON.parse(output) as SwiftScanRecord[];
    return parsed
        .filter((item) => item && typeof item.ssid === "string" && item.ssid.trim().length > 0)
        .map((item) => {
            const channelNumber = Number(item.channel.match(/(\d+)/)?.[1] ?? 0);
            let band: "2g" | "5g" | "6g" = "2g";
            if (channelNumber > 165) {
                band = "6g";
            } else if (channelNumber >= 36) {
                band = "5g";
            }

            return {
                ssid: item.ssid.trim(),
                band,
                rssi: Number(item.rssi),
                channel: item.channel,
                security: parseSecurity(item.summary),
            };
        });
}

function scanWifiViaSwift(allowedSsids: string[]): Network[] {
    if (!commandExists("swift")) {
        throw new Error("swift is not available for Wi-Fi scanning");
    }

    const output = runSwift(`
import Foundation
import CoreWLAN

let client = CWWiFiClient.shared()
guard let iface = client.interface() else {
    throw NSError(domain: "scriptd", code: 1, userInfo: [NSLocalizedDescriptionKey: "No Wi-Fi interface available"])
}

let networks = try iface.scanForNetworks(withSSID: nil)
let rows: [[String: Any]] = networks.compactMap { network in
    guard let ssid = network.ssid, !ssid.isEmpty else {
        return nil
    }

    return [
        "ssid": ssid,
        "rssi": network.rssiValue,
        "channel": String(network.wlanChannel?.channelNumber ?? 0),
        "summary": String(describing: network),
    ]
}

let data = try JSONSerialization.data(withJSONObject: rows, options: [])
print(String(data: data, encoding: .utf8) ?? "[]")
`);

    return parseSwiftWifiScanOutput(output).filter((network) => allowedSsids.length === 0 || allowedSsids.includes(network.ssid));
}

function scanWifi(allowedSsids: string[]): Network[] {
    const scannerPath = airportPath();
    const result = spawnSync(scannerPath, ["-s"], { encoding: "utf8" });
    if (result.status !== 0) {
        return scanWifiViaSwift(allowedSsids);
    }

    const output = (result.stdout ?? "").trim();

    const pattern =
        /^(?<ssid>.+?)\s+(?<bssid>(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2})\s+(?<rssi>-?\d+)\s+(?<channel>\S+)\s+(?<ht>\S+)\s+(?<cc>\S+)\s+(?<security>.+)$/;

    const networks: Network[] = [];
    for (const line of output.split("\n").slice(1)) {
        const match = line.trim().match(pattern);
        if (!match?.groups) {
            continue;
        }

        const ssid = match.groups.ssid.trim();
        if (allowedSsids.length > 0 && !allowedSsids.includes(ssid)) {
            continue;
        }

        const channel = match.groups.channel;
        const channelNumber = Number(channel.match(/(\d+)/)?.[1] ?? 0);
        let band: "2g" | "5g" | "6g" = "2g";
        if (channelNumber > 165) {
            band = "6g";
        } else if (channelNumber >= 36) {
            band = "5g";
        }

        networks.push({
            ssid,
            band,
            rssi: Number(match.groups.rssi),
            channel,
            security: match.groups.security.trim(),
        });
    }

    return networks;
}

async function readState(stateFile: string): Promise<PersistedWifiState> {
    try {
        const contents = await fs.readFile(stateFile, "utf8");
        const trimmed = contents.trim();
        if (trimmed.startsWith("{")) {
            const parsed = JSON.parse(trimmed) as PersistedWifiState;
            return {
                lastSsid: parsed.lastSsid ?? "",
                lastConnectedAt: parsed.lastConnectedAt,
                lastSwitchAt: parsed.lastSwitchAt,
                healthFailureStreak: parsed.healthFailureStreak ?? 0,
                lastHealth: parsed.lastHealth,
            };
        }

        const [ssid = "", startedAt = "0"] = trimmed.split("\n");
        const startedAtMs = Number(startedAt) || 0;
        return {
            lastSsid: ssid,
            lastConnectedAt: startedAtMs > 0 ? new Date(startedAtMs).toISOString() : undefined,
            lastSwitchAt: startedAtMs > 0 ? new Date(startedAtMs).toISOString() : undefined,
            healthFailureStreak: 0,
        };
    } catch {
        return { lastSsid: "", healthFailureStreak: 0 };
    }
}

async function writeState(stateFile: string, state: PersistedWifiState): Promise<void> {
    await fs.mkdir(path.dirname(stateFile), { recursive: true });
    await fs.writeFile(stateFile, `${JSON.stringify(state, null, 2)}\n`, "utf8");
}

export function scoreNetwork(network: Network, config: WifiMonitorConfig): number {
    const bandBonus =
        network.band === "6g" ? config.bandBonus6g : network.band === "5g" ? config.bandBonus5g : config.bandBonus2g;
    const signalScore = Math.max(0, Math.min(100, network.rssi + config.rssiOffset));
    return bandBonus + signalScore;
}

function preferredSsids(device: string): string[] {
    const output = command("networksetup", ["-listpreferredwirelessnetworks", device], false);
    return output
        .split("\n")
        .slice(1)
        .map((line) => line.trim())
        .filter(Boolean);
}

function connect(device: string, ssid: string): void {
    command("networksetup", ["-setairportnetwork", device, ssid]);
}

type ScoredNetwork = {
    network: Network;
    score: number;
    priority: number;
};

export type WifiDecision =
    | { action: "stay"; ssid: string; reason: string }
    | { action: "switch"; from: string; to: string; reason: string };

function priorityFor(ssid: string, priorityOrder: string[]): number {
    const index = priorityOrder.indexOf(ssid);
    return index === -1 ? Number.MAX_SAFE_INTEGER : index;
}

function preferenceBonus(rank: number, config: Pick<WifiMonitorConfig, "preferenceTopBonus" | "preferenceRankDecay">): number {
    if (!Number.isFinite(rank) || rank === Number.MAX_SAFE_INTEGER) {
        return 0;
    }

    return Math.max(0, config.preferenceTopBonus - rank * config.preferenceRankDecay);
}

function bandBonusFor(network: Network, config: Pick<WifiMonitorConfig, "bandBonus2g" | "bandBonus5g" | "bandBonus6g">): number {
    return network.band === "6g" ? config.bandBonus6g : network.band === "5g" ? config.bandBonus5g : config.bandBonus2g;
}

export function buildCandidateScore(options: {
    network: Network;
    config: WifiMonitorConfig;
    priorityOrder: string[];
    currentSsid: string;
    currentHealthPenalty: number;
}): CandidateScore {
    const rank = priorityFor(options.network.ssid, options.priorityOrder);
    const rssiScore = Math.max(0, Math.min(100, options.network.rssi + options.config.rssiOffset));
    const bandBonus = bandBonusFor(options.network, options.config);
    const prefBonus = preferenceBonus(rank, options.config);
    const stickyBonus = options.network.ssid === options.currentSsid ? options.config.currentStickyBonus : 0;
    const healthPenalty = options.network.ssid === options.currentSsid ? options.currentHealthPenalty : 0;

    return {
        network: options.network,
        rank,
        rssiScore,
        bandBonus,
        preferenceBonus: prefBonus,
        stickyBonus,
        healthPenalty,
        totalScore: rssiScore + bandBonus + prefBonus + stickyBonus - healthPenalty,
    };
}

export function dedupeNetworksBySsid(networks: Network[], config: WifiMonitorConfig, priorityOrder: string[]): Network[] {
    const bestBySsid = new Map<string, ScoredNetwork>();
    for (const network of networks) {
        const scored = {
            network,
            score: scoreNetwork(network, config) + preferenceBonus(priorityFor(network.ssid, priorityOrder), config),
            priority: priorityFor(network.ssid, priorityOrder),
        };
        const current = bestBySsid.get(network.ssid);
        if (!current || scored.score > current.score) {
            bestBySsid.set(network.ssid, scored);
        }
    }

    return Array.from(bestBySsid.values()).map((entry) => entry.network);
}

export function effectiveCurrentSsid(currentSsid: string, persistedSsid: string, networks: Network[]): string {
    const current = currentSsid.trim();
    if (current) {
        return current;
    }

    const persisted = persistedSsid.trim();
    if (persisted && networks.some((network) => network.ssid === persisted)) {
        return persisted;
    }

    return "";
}

function describeCandidates(candidates: CandidateScore[]): string {
    if (candidates.length === 0) {
        return "none";
    }

    return candidates
        .slice()
        .sort((left, right) => right.totalScore - left.totalScore || left.rank - right.rank)
        .map(
            (candidate) =>
                `${candidate.network.ssid}(band=${candidate.network.band}, rssi=${candidate.network.rssi}, pref=${candidate.preferenceBonus}, bandBonus=${candidate.bandBonus}, sticky=${candidate.stickyBonus}, healthPenalty=${candidate.healthPenalty}, total=${candidate.totalScore})`,
        )
        .join("; ");
}

export function decideWifiSwitch(options: {
    currentSsid: string;
    candidates: CandidateScore[];
    config: WifiMonitorConfig;
    dwellSatisfied: boolean;
    healthFailureStreak: number;
}): WifiDecision {
    const ranked = options.candidates.slice().sort((left, right) => right.totalScore - left.totalScore || left.rank - right.rank);
    const best = ranked[0];
    if (!best) {
        return { action: "stay", ssid: options.currentSsid, reason: "no eligible networks found" };
    }

    const current = ranked.find((candidate) => candidate.network.ssid === options.currentSsid);
    if (best.network.ssid === options.currentSsid || !current) {
        return { action: "stay", ssid: options.currentSsid, reason: `staying on ${options.currentSsid || "current network"}` };
    }

    if (!options.dwellSatisfied) {
        return { action: "stay", ssid: options.currentSsid, reason: `holding ${options.currentSsid || "current network"} until dwell window completes` };
    }

    const healthDriven = options.healthFailureStreak >= options.config.healthFailureSwitchRuns;
    const delta = best.totalScore - current.totalScore;
    if (healthDriven && delta >= 10) {
        return {
            action: "switch",
            from: options.currentSsid,
            to: best.network.ssid,
            reason: `switching to ${best.network.ssid}; repeated health failures and score delta ${delta} >= 10`,
        };
    }

    if (delta >= options.config.minSwitchScoreDelta) {
        return {
            action: "switch",
            from: options.currentSsid,
            to: best.network.ssid,
            reason: `switching to ${best.network.ssid}; score delta ${delta} >= ${options.config.minSwitchScoreDelta}`,
        };
    }

    return {
        action: "stay",
        ssid: options.currentSsid,
        reason: `staying on ${options.currentSsid}; best score delta ${delta} is below required threshold`,
    };
}

async function monitorPass(ctx: ModuleContext, config: WifiMonitorConfig): Promise<void> {
    const device = wifiDevice();
    const current = currentSsid(device);
    const preferences = preferredSsids(device);
    const allowedSsids = config.ssids.length > 0 ? config.ssids : preferences;
    const scannedNetworks = scanWifi(allowedSsids);

    moduleState.loopCount += 1;
    moduleState.lastRunAt = new Date().toISOString();
    const persisted = await readState(config.stateFile);
    const networks = dedupeNetworksBySsid(scannedNetworks, config, allowedSsids);
    const effectiveCurrent = effectiveCurrentSsid(current, persisted.lastSsid, networks);
    moduleState.currentSsid = effectiveCurrent;
    const currentHealth = pingHealth(config.pingTarget, config, persisted.healthFailureStreak);
    const nextFailureStreak = currentHealth.healthy ? 0 : persisted.healthFailureStreak + 1;
    const lastConnectedAtMs = persisted.lastConnectedAt ? Date.parse(persisted.lastConnectedAt) : 0;
    const dwellSatisfied = !lastConnectedAtMs || Date.now() - lastConnectedAtMs >= config.minDwellSeconds * 1000;
    const currentDescription = current || (effectiveCurrent ? `unknown; using last known ${effectiveCurrent}` : "unknown");
    const candidates = networks.map((network) =>
        buildCandidateScore({
            network,
            config,
            priorityOrder: allowedSsids,
            currentSsid: effectiveCurrent,
            currentHealthPenalty: currentHealth.penalty,
        }),
    );
    ctx.log.info(
        `current=${currentDescription}; health=loss:${currentHealth.packetLossPercent}% latency:${currentHealth.avgLatencyMs ?? "n/a"}ms streak:${nextFailureStreak}; candidates=${describeCandidates(candidates)}`,
    );
    const decision = decideWifiSwitch({
        currentSsid: effectiveCurrent,
        candidates,
        config,
        dwellSatisfied,
        healthFailureStreak: nextFailureStreak,
    });

    moduleState.lastDecision = decision.reason;
    if (decision.action === "stay") {
        const log = networks.length === 0 ? ctx.log.warn : ctx.log.info;
        log(decision.reason);
        await writeState(config.stateFile, {
            lastSsid: effectiveCurrent || persisted.lastSsid,
            lastConnectedAt: effectiveCurrent ? persisted.lastConnectedAt ?? new Date().toISOString() : persisted.lastConnectedAt,
            lastSwitchAt: persisted.lastSwitchAt,
            healthFailureStreak: nextFailureStreak,
            lastHealth: {
                packetLossPercent: currentHealth.packetLossPercent,
                avgLatencyMs: currentHealth.avgLatencyMs,
            },
        });
        return;
    }

    if (decision.to === effectiveCurrent) {
        ctx.log.info(`staying on ${effectiveCurrent}; chosen SSID already matches current`);
        return;
    }

    connect(device, decision.to);
    const switchedAt = new Date().toISOString();
    await writeState(config.stateFile, {
        lastSsid: decision.to,
        lastConnectedAt: switchedAt,
        lastSwitchAt: switchedAt,
        healthFailureStreak: 0,
        lastHealth: {
            packetLossPercent: currentHealth.packetLossPercent,
            avgLatencyMs: currentHealth.avgLatencyMs,
        },
    });
    moduleState.currentSsid = decision.to;
    moduleState.lastSwitchAt = switchedAt;
    ctx.log.info(moduleState.lastDecision);
}

const modulePlugin: RootServiceModule<WifiMonitorConfig> = {
    id: "wifi-monitor",
    mode: "interval",
    intervalMs: 30_000,
    async loadConfig(ctx) {
        const configPath = path.join(ctx.moduleDir, "module.yaml");
        const raw = await readConfigFile(configPath);
        return resolveWifiMonitorConfig(raw, {
            ...ctx.env,
            WIFI_MONITOR_CONFIG_PATH: configPath,
        });
    },
    async runOnce(ctx, config) {
        try {
            await monitorPass(ctx, config);
            moduleState.lastError = undefined;
        } catch (error) {
            moduleState.lastError = error instanceof Error ? error.message : String(error);
            ctx.log.error(moduleState.lastError);
            throw error;
        }
    },
    status(): ModuleStatus {
        return {
            state: "running",
            message: moduleState.lastDecision,
            lastRunAt: moduleState.lastRunAt,
            metrics: {
                loops: moduleState.loopCount,
                connected: moduleState.currentSsid || "none",
            },
        };
    },
    health(): ModuleHealth {
        return {
            ok: !moduleState.lastError,
            message: moduleState.lastError ?? "wifi monitor healthy",
        };
    },
};

export default modulePlugin;
