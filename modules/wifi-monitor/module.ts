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
    pingTimeoutSeconds: number;
    bandBonus2g: number;
    bandBonus5g: number;
    bandBonus6g: number;
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
        pingTimeoutSeconds: envNumber(
            env.WIFI_MONITOR_PING_TIMEOUT,
            assertPositiveInteger(raw.ping_timeout ?? 1, "wifi-monitor.ping_timeout"),
        ),
        bandBonus2g: Number(raw.band_bonus_2g ?? 0),
        bandBonus5g: Number(raw.band_bonus_5g ?? 100),
        bandBonus6g: Number(raw.band_bonus_6g ?? 150),
        rssiOffset: Number(raw.rssi_offset ?? 100),
        minSwitchScoreDelta: envNumber(
            env.WIFI_MONITOR_MIN_SWITCH_SCORE_DELTA,
            assertPositiveInteger(raw.min_switch_score_delta ?? 10, "wifi-monitor.min_switch_score_delta"),
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

function pingMs(target: string, timeoutSeconds: number): number | undefined {
    if (!target) {
        return undefined;
    }

    const result = spawnSync("ping", ["-c", "1", "-W", String(timeoutSeconds * 1000), target], { encoding: "utf8" });
    if (result.status !== 0) {
        return undefined;
    }

    const match = (result.stdout ?? "").match(/time=([0-9.]+)\s*ms/);
    return match ? Math.round(Number(match[1])) : undefined;
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

async function readState(stateFile: string): Promise<{ ssid: string; startedAt: number }> {
    try {
        const contents = await fs.readFile(stateFile, "utf8");
        const [ssid = "", startedAt = "0"] = contents.trim().split("\n");
        return { ssid, startedAt: Number(startedAt) || 0 };
    } catch {
        return { ssid: "", startedAt: 0 };
    }
}

async function writeState(stateFile: string, ssid: string): Promise<void> {
    await fs.mkdir(path.dirname(stateFile), { recursive: true });
    await fs.writeFile(stateFile, `${ssid}\n${Date.now()}\n`, "utf8");
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

function chooseBestNetwork(networks: Network[], config: WifiMonitorConfig, priorityOrder: string[]): ScoredNetwork | undefined {
    return networks
        .map((network) => ({
            network,
            score: scoreNetwork(network, config),
            priority: priorityFor(network.ssid, priorityOrder),
        }))
        .sort((left, right) => left.priority - right.priority || right.score - left.score)[0];
}

export function decideWifiSwitch(options: {
    currentSsid: string;
    networks: Network[];
    config: WifiMonitorConfig;
    priorityOrder: string[];
    dwellSatisfied: boolean;
    currentHealthy: boolean;
}): WifiDecision {
    const best = chooseBestNetwork(options.networks, options.config, options.priorityOrder);
    if (!best) {
        return { action: "stay", ssid: options.currentSsid, reason: "no eligible networks found" };
    }

    const current = options.networks.find((network) => network.ssid === options.currentSsid);
    if (best.network.ssid === options.currentSsid) {
        return { action: "stay", ssid: options.currentSsid, reason: `staying on ${options.currentSsid}` };
    }

    if (!options.dwellSatisfied) {
        return { action: "stay", ssid: options.currentSsid, reason: `holding ${options.currentSsid || "current network"} until dwell window completes` };
    }

    if (!current || !options.currentHealthy) {
        return {
            action: "switch",
            from: options.currentSsid,
            to: best.network.ssid,
            reason: `switching to ${best.network.ssid}; current network is unavailable or unhealthy`,
        };
    }

    const currentScore = scoreNetwork(current, options.config);
    const currentPriority = priorityFor(options.currentSsid, options.priorityOrder);
    if (best.priority < currentPriority) {
        return {
            action: "switch",
            from: options.currentSsid,
            to: best.network.ssid,
            reason: `switching to higher-priority network ${best.network.ssid}`,
        };
    }

    if (best.priority === currentPriority && best.score >= currentScore + options.config.minSwitchScoreDelta) {
        return {
            action: "switch",
            from: options.currentSsid,
            to: best.network.ssid,
            reason: `switching to ${best.network.ssid}; score ${best.score} beats current ${currentScore}`,
        };
    }

    return {
        action: "stay",
        ssid: options.currentSsid,
        reason: `staying on ${options.currentSsid}; best alternative is not enough better`,
    };
}

async function monitorPass(ctx: ModuleContext, config: WifiMonitorConfig): Promise<void> {
    const device = wifiDevice();
    const current = currentSsid(device);
    const preferences = preferredSsids(device);
    const allowedSsids = config.ssids.length > 0 ? config.ssids : preferences;
    const networks = scanWifi(allowedSsids);
    const currentHealthy = pingMs(config.pingTarget, config.pingTimeoutSeconds) !== undefined;

    moduleState.loopCount += 1;
    moduleState.lastRunAt = new Date().toISOString();
    moduleState.currentSsid = current;
    const persisted = await readState(config.stateFile);
    const dwellSatisfied = !persisted.startedAt || Date.now() - persisted.startedAt >= config.minDwellSeconds * 1000;
    const decision = decideWifiSwitch({
        currentSsid: current,
        networks,
        config,
        priorityOrder: allowedSsids,
        dwellSatisfied,
        currentHealthy,
    });

    moduleState.lastDecision = decision.reason;
    if (decision.action === "stay") {
        if (networks.length === 0) {
            ctx.log.warn(decision.reason);
        }
        return;
    }

    connect(device, decision.to);
    await writeState(config.stateFile, decision.to);
    moduleState.currentSsid = decision.to;
    moduleState.lastSwitchAt = new Date().toISOString();
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
