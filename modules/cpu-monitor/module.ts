import { basename } from "node:path";
import { spawnSync } from "node:child_process";
import { promises as fs } from "node:fs";
import path from "node:path";
import type { ModuleContext, ModuleHealth, ModuleStatus, RootServiceModule } from "../../src/interfaces.ts";
import { assertPositiveInteger, parseSimpleYaml } from "../../src/config.ts";

export type CpuProcessSnapshot = {
    pid: number;
    cpu: number;
    command: string;
    name: string;
};

export type CpuTrackedProcess = CpuProcessSnapshot & {
    firstSeenAt: number;
};

type CpuMonitorState = {
    tracked: Map<number, CpuTrackedProcess>;
    lastRunAt?: string;
    lastKilledPid?: number;
    lastMessage?: string;
    lastError?: string;
};

type CpuMonitorConfig = {
    cpuThreshold: number;
    timeLimitSeconds: number;
    excludeApps: string[];
};

const DEFAULT_CPU_THRESHOLD = 50;
const DEFAULT_TIME_LIMIT_SECONDS = 600;
const DEFAULT_EXCLUDE_APPS = ["Finder", "Dock", "Terminal", "Activity Monitor", "kernel_task", "loginwindow"];

const moduleState: CpuMonitorState = {
    tracked: new Map(),
};

function readPsSnapshot(): string {
    const result = spawnSync("ps", ["-axo", "pid=,%cpu=,comm="], { encoding: "utf8" });
    if (result.status !== 0) {
        throw new Error(result.stderr || "ps command failed");
    }

    return result.stdout ?? "";
}

async function loadConfigFile(moduleDir: string): Promise<Record<string, unknown>> {
    try {
        const text = await fs.readFile(path.join(moduleDir, "module.yaml"), "utf8");
        return parseSimpleYaml(text);
    } catch {
        return {};
    }
}

function toStringArray(value: unknown, fallback: string[]): string[] {
    if (!Array.isArray(value)) {
        return fallback.slice();
    }

    return value.filter((item): item is string => typeof item === "string");
}

function resolveCpuMonitorConfig(raw: Record<string, unknown>): CpuMonitorConfig {
    return {
        cpuThreshold: assertPositiveInteger(raw.cpu_threshold ?? DEFAULT_CPU_THRESHOLD, "cpu-monitor.cpu_threshold"),
        timeLimitSeconds: assertPositiveInteger(raw.time_limit_seconds ?? DEFAULT_TIME_LIMIT_SECONDS, "cpu-monitor.time_limit_seconds"),
        excludeApps: toStringArray(raw.exclude_apps, DEFAULT_EXCLUDE_APPS),
    };
}

export function parseCpuSnapshot(output: string, cpuThreshold: number, excludeApps: string[]): CpuProcessSnapshot[] {
    return output
        .split("\n")
        .map((line) => line.trim())
        .filter(Boolean)
        .map((line) => {
            const match = line.match(/^(\d+)\s+([0-9.]+)\s+(.+)$/);
            if (!match) {
                return undefined;
            }

            const command = match[3].trim();
            return {
                pid: Number(match[1]),
                cpu: Number(match[2]),
                command,
                name: basename(command),
            };
        })
        .filter((item): item is CpuProcessSnapshot => Boolean(item))
        .filter((item) => item.cpu > cpuThreshold && !excludeApps.includes(item.name));
}

export function reconcileTrackedProcesses(
    tracked: Map<number, CpuTrackedProcess>,
    snapshot: CpuProcessSnapshot[],
    currentTimeSeconds: number,
    timeLimitSeconds: number,
): Map<number, CpuTrackedProcess> {
    const next = new Map<number, CpuTrackedProcess>();
    const snapshotByPid = new Map(snapshot.map((item) => [item.pid, item]));

    for (const item of snapshot) {
        const existing = tracked.get(item.pid);
        next.set(item.pid, {
            ...item,
            firstSeenAt: existing?.firstSeenAt ?? currentTimeSeconds,
        });
    }

    for (const [pid, existing] of tracked.entries()) {
        const current = snapshotByPid.get(pid);
        if (!current) {
            continue;
        }

        next.set(pid, {
            ...current,
            firstSeenAt: existing.firstSeenAt,
        });

        if (currentTimeSeconds - existing.firstSeenAt >= timeLimitSeconds) {
            next.set(pid, {
                ...current,
                firstSeenAt: existing.firstSeenAt,
            });
        }
    }

    return next;
}

async function monitorPass(log: { info(message: string): void; error(message: string): void }, config: CpuMonitorConfig): Promise<void> {
    const now = Math.floor(Date.now() / 1000);
    const snapshot = parseCpuSnapshot(readPsSnapshot(), config.cpuThreshold, config.excludeApps);
    moduleState.tracked = reconcileTrackedProcesses(moduleState.tracked, snapshot, now, config.timeLimitSeconds);

    for (const tracked of moduleState.tracked.values()) {
        if (now - tracked.firstSeenAt >= config.timeLimitSeconds) {
            try {
                process.kill(tracked.pid, "SIGKILL");
                moduleState.lastKilledPid = tracked.pid;
                moduleState.lastMessage = `Killed PID ${tracked.pid} (${tracked.name}) after sustained ${tracked.cpu}% CPU`;
                moduleState.lastError = undefined;
                log.info(moduleState.lastMessage);
                moduleState.tracked.delete(tracked.pid);
            } catch (error) {
                moduleState.lastError = error instanceof Error ? error.message : String(error);
                log.error(moduleState.lastError);
            }
        }
    }

    moduleState.lastRunAt = new Date().toISOString();
}

const modulePlugin: RootServiceModule<CpuMonitorConfig> = {
    id: "cpu-monitor",
    mode: "interval",
    intervalMs: 30_000,
    async loadConfig(ctx: ModuleContext) {
        return resolveCpuMonitorConfig(await loadConfigFile(ctx.moduleDir));
    },
    async runOnce(ctx, config) {
        await monitorPass(ctx.log, config);
    },
    status(): ModuleStatus {
        return {
            state: "running",
            message: moduleState.lastMessage,
            lastRunAt: moduleState.lastRunAt,
            metrics: {
                tracked: moduleState.tracked.size,
                lastKilledPid: moduleState.lastKilledPid ?? "none",
            },
        };
    },
    health(): ModuleHealth {
        return {
            ok: !moduleState.lastError,
            message: moduleState.lastError ?? "cpu monitor healthy",
        };
    },
};

export default modulePlugin;
