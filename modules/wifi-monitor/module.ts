import path from "node:path";
import { promises as fs } from "node:fs";
import { spawnSync } from "node:child_process";
import type { ModuleContext, ModuleHealth, ModuleStatus, RootServiceModule } from "../../src/interfaces.ts";
import { assertPositiveInteger, parseSimpleYaml } from "../../src/config.ts";

export type Network = {
    ssid: string;
    band: "2g" | "5g" | "6g";
    rssi: number;
    channel: string;
    security: string;
    pingMs?: number;
};

export type WifiMonitorConfig = {
    scanIntervalSeconds: number;
    minDwellSeconds: number;
    pingTarget: string;
    pingTimeoutSeconds: number;
    pingWeight: number;
    bandBonus2g: number;
    bandBonus5g: number;
    bandBonus6g: number;
    rssiOffset: number;
    maxPingPenalty: number;
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
    const parsed = Number(raw);
    return Number.isFinite(parsed) ? parsed : fallback;
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

export function resolveWifiMonitorConfig(raw: Record<string, unknown>, env: NodeJS.ProcessEnv): WifiMonitorConfig {
    const configPath = typeof env.WIFI_MONITOR_CONFIG_PATH === "string" ? env.WIFI_MONITOR_CONFIG_PATH : "./module.yaml";
    const stateFile = env.WIFI_MONITOR_STATE_FILE ?? `${env.HOME ?? "/Users/omar"}/.local/share/wifi-monitor/state.txt`;
    const envSsids = (env.WIFI_MONITOR_SSIDS ?? "")
        .split(",")
        .map((item) => item.trim())
        .filter(Boolean);

    return {
        scanIntervalSeconds: envNumber(env.WIFI_MONITOR_INTERVAL, assertPositiveInteger(raw.scan_interval ?? 30, "wifi-monitor.scan_interval")),
        minDwellSeconds: envNumber(env.WIFI_MONITOR_MIN_DWELL, assertPositiveInteger(raw.min_dwell ?? 180, "wifi-monitor.min_dwell")),
        pingTarget: (env.WIFI_MONITOR_PING_TARGET ?? ensureStringValue(raw.ping_target ?? "1.1.1.1", "wifi-monitor.ping_target")).trim(),
        pingTimeoutSeconds: envNumber(
            env.WIFI_MONITOR_PING_TIMEOUT,
            assertPositiveInteger(raw.ping_timeout ?? 1, "wifi-monitor.ping_timeout"),
        ),
        pingWeight: envNumber(env.WIFI_MONITOR_PING_WEIGHT, assertPositiveInteger(raw.ping_weight ?? 8, "wifi-monitor.ping_weight")),
        bandBonus2g: Number(raw.band_bonus_2g ?? 0),
        bandBonus5g: Number(raw.band_bonus_5g ?? 100),
        bandBonus6g: Number(raw.band_bonus_6g ?? 150),
        rssiOffset: Number(raw.rssi_offset ?? 100),
        maxPingPenalty: assertPositiveInteger(raw.max_ping_penalty ?? 30, "wifi-monitor.max_ping_penalty"),
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

    throw new Error("could not find Wi-Fi device");
}

function currentSsid(device: string): string {
    const output = command("networksetup", ["-getairportnetwork", device], false);
    const match = output.match(/Current Wi-Fi Network: (.+)$/m);
    return match ? match[1].trim() : "";
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

function scanWifi(allowedSsids: string[]): Network[] {
    const output = command(
        "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport",
        ["-s"],
    );

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
    const pingPenalty =
        network.pingMs === undefined ? 0 : Math.min(config.maxPingPenalty, Math.floor(network.pingMs / Math.max(1, config.pingWeight)));
    return bandBonus + signalScore - pingPenalty;
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

async function monitorPass(ctx: ModuleContext, config: WifiMonitorConfig): Promise<void> {
    const device = wifiDevice();
    const current = currentSsid(device);
    const preferences = preferredSsids(device);
    const allowedSsids = config.ssids.length > 0 ? config.ssids : preferences;
    const networks = scanWifi(allowedSsids).map((network) => ({
        ...network,
        pingMs: pingMs(config.pingTarget, config.pingTimeoutSeconds),
    }));
    const scored = networks
        .map((network) => ({ network, score: scoreNetwork(network, config) }))
        .sort((left, right) => right.score - left.score);

    moduleState.loopCount += 1;
    moduleState.lastRunAt = new Date().toISOString();
    moduleState.currentSsid = current;

    if (scored.length === 0) {
        moduleState.lastDecision = "no eligible networks found";
        ctx.log.warn(moduleState.lastDecision);
        return;
    }

    const top = scored[0];
    const persisted = await readState(config.stateFile);
    const dwellSatisfied = !persisted.startedAt || Date.now() - persisted.startedAt >= config.minDwellSeconds * 1000;

    if (top.network.ssid === current) {
        moduleState.lastDecision = `staying on ${current}`;
        return;
    }

    if (!dwellSatisfied && persisted.ssid === current) {
        moduleState.lastDecision = `holding ${current} until dwell window completes`;
        return;
    }

    connect(device, top.network.ssid);
    await writeState(config.stateFile, top.network.ssid);
    moduleState.currentSsid = top.network.ssid;
    moduleState.lastSwitchAt = new Date().toISOString();
    moduleState.lastDecision = `switched from ${current || "none"} to ${top.network.ssid}`;
    ctx.log.info(moduleState.lastDecision);
}

function sleep(ms: number, signal: AbortSignal): Promise<void> {
    if (signal.aborted) {
        return Promise.resolve();
    }

    return new Promise((resolve) => {
        const timer = setTimeout(resolve, ms);
        signal.addEventListener(
            "abort",
            () => {
                clearTimeout(timer);
                resolve();
            },
            { once: true },
        );
    });
}

const modulePlugin: RootServiceModule<WifiMonitorConfig> = {
    id: "wifi-monitor",
    mode: "daemon",
    async loadConfig(ctx) {
        const configPath = path.join(ctx.moduleDir, "module.yaml");
        const raw = await readConfigFile(configPath);
        return resolveWifiMonitorConfig(raw, {
            ...ctx.env,
            WIFI_MONITOR_CONFIG_PATH: configPath,
        });
    },
    async start(ctx, config) {
        while (!ctx.signal.aborted) {
            try {
                await monitorPass(ctx, config);
                moduleState.lastError = undefined;
            } catch (error) {
                moduleState.lastError = error instanceof Error ? error.message : String(error);
                ctx.log.error(moduleState.lastError);
            }

            await sleep(config.scanIntervalSeconds * 1000, ctx.signal);
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
