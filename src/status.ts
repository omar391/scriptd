import { existsSync, readFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { discoverModules, loadServiceConfig } from "./config.ts";
import { resolveRepoRoot } from "./paths.ts";
import type { ModuleHealth, ModuleStatus } from "./interfaces.ts";

type PersistedModuleState = {
    desiredEnabled: boolean;
    status: string;
    mode: string;
    nextRunAt?: string;
    lastStartedAt?: string;
    lastRunAt?: string;
    lastExitAt?: string;
    runs: number;
    restarts: number;
    message: string;
    health?: ModuleHealth;
    moduleStatus?: ModuleStatus;
    lastError?: string;
};

type PersistedState = {
    label?: string;
    rootDir?: string;
    configPath?: string;
    logDir?: string;
    updatedAt: string;
    supervisor: {
        pid: number;
        startedAt: string;
        watch: boolean;
    };
    modules: Record<string, PersistedModuleState>;
};

type LaunchdStatus = {
    loaded: boolean;
    pid: string;
    lastExitStatus: string;
};

const HIDDEN_STALE_MESSAGES = new Set(["module disabled", "supervisor stopped"]);

function launchctlStatus(label: string): LaunchdStatus {
    const result = spawnSync("launchctl", ["list"], { encoding: "utf8" });
    const output = result.stdout ?? "";

    for (const line of output.split("\n")) {
        const parts = line.trim().split(/\s+/);
        if (parts.length >= 3 && parts[2] === label) {
            return {
                loaded: true,
                pid: parts[0] ?? "-",
                lastExitStatus: parts[1] ?? "-",
            };
        }
    }

    return {
        loaded: false,
        pid: "-",
        lastExitStatus: "-",
    };
}

function processExists(pid: number): boolean {
    try {
        process.kill(pid, 0);
        return true;
    } catch {
        return false;
    }
}

function resolveStateFreshness(
    state: PersistedState,
    options: {
        launchd: LaunchdStatus;
        repoRoot: string;
        configPath: string;
    },
): { current: boolean; reason?: string } {
    if (state.rootDir && state.rootDir !== options.repoRoot) {
        return { current: false, reason: "State file belongs to a different repo root" };
    }

    if (state.configPath && state.configPath !== options.configPath) {
        return { current: false, reason: "State file was written from a different config path" };
    }

    if (!options.launchd.loaded) {
        return { current: false, reason: "LaunchAgent not loaded" };
    }

    if (options.launchd.pid === "-") {
        return { current: false, reason: "LaunchAgent loaded but not currently running" };
    }

    if (!processExists(state.supervisor.pid)) {
        return { current: false, reason: `Supervisor PID ${state.supervisor.pid} is not running` };
    }

    const launchdPid = Number(options.launchd.pid);
    if (Number.isFinite(launchdPid) && launchdPid !== state.supervisor.pid) {
        return { current: false, reason: `State PID ${state.supervisor.pid} does not match launchd PID ${launchdPid}` };
    }

    return { current: true };
}

function formatDurationMs(durationMs: number): string {
    const totalSeconds = Math.max(0, Math.round(durationMs / 1000));
    if (totalSeconds < 60) {
        return `${totalSeconds}s`;
    }

    const totalMinutes = Math.round(totalSeconds / 60);
    if (totalMinutes < 60) {
        return `${totalMinutes}m`;
    }

    const totalHours = Math.round(totalMinutes / 60);
    if (totalHours < 24) {
        return `${totalHours}h`;
    }

    const totalDays = Math.round(totalHours / 24);
    return `${totalDays}d`;
}

function staleNextHint(options: {
    desiredEnabled: boolean;
    mode?: string;
    intervalMs?: number;
}): string | undefined {
    if (!options.desiredEnabled || !options.mode) {
        return undefined;
    }

    if (options.mode === "daemon") {
        return "immediately when service starts";
    }

    if (options.mode === "interval" && typeof options.intervalMs === "number" && options.intervalMs > 0) {
        return `${formatDurationMs(options.intervalMs)} after service starts`;
    }

    if (options.mode === "interval") {
        return "after service starts";
    }

    return undefined;
}

function shouldShowModuleMessage(
    moduleState: PersistedModuleState,
    options: {
        stateIsCurrent: boolean;
    },
): boolean {
    if (!moduleState.message) {
        return false;
    }

    if (!options.stateIsCurrent && HIDDEN_STALE_MESSAGES.has(moduleState.message)) {
        return false;
    }

    if (moduleState.nextRunAt && moduleState.message === `next run at ${moduleState.nextRunAt}`) {
        return false;
    }

    return true;
}

export async function renderStatus(): Promise<void> {
    const repoRoot = resolveRepoRoot();
    const config = await loadServiceConfig(repoRoot);
    const modules = await discoverModules(repoRoot);
    const launchd = launchctlStatus(config.label);

    console.log(`scriptd label: ${config.label}`);
    console.log(`LaunchAgent loaded: ${launchd.loaded ? "yes" : "no"}`);
    console.log(`LaunchAgent PID: ${launchd.pid}`);
    console.log(`LaunchAgent last exit status: ${launchd.lastExitStatus}`);
    console.log(`Config path: ${config.path}`);
    console.log(`Shared log dir: ${config.logDir}`);
    console.log(`State file: ${config.stateFile}`);

    const state = existsSync(config.stateFile) ? (JSON.parse(readFileSync(config.stateFile, "utf8")) as PersistedState) : undefined;
    const stateFreshness = state
        ? resolveStateFreshness(state, {
              launchd,
              repoRoot,
              configPath: config.path,
          })
        : undefined;
    const stateIsCurrent = Boolean(stateFreshness?.current);

    if (!state) {
        console.log("scriptd state: unavailable");
    } else {
        console.log(stateIsCurrent ? "scriptd state: current" : `scriptd state: stale snapshot (${stateFreshness?.reason})`);
        console.log(`${stateIsCurrent ? "scriptd PID" : "Last known scriptd PID"}: ${state.supervisor.pid}`);
        console.log(`${stateIsCurrent ? "scriptd started" : "Last known scriptd start"}: ${state.supervisor.startedAt}`);
        console.log(`scriptd watch enabled: ${state.supervisor.watch ? "yes" : "no"}`);
        console.log(`State updated: ${state.updatedAt}`);
    }

    const moduleNames = new Set<string>([...Object.keys(config.modules), ...Object.keys(state?.modules ?? {})]);
    if (moduleNames.size === 0) {
        console.log("Modules: none discovered");
        return;
    }

    console.log("Modules:");
    for (const moduleName of [...moduleNames].sort()) {
        const moduleState = state?.modules[moduleName];
        const desiredEnabled = config.modules[moduleName]?.enabled ?? false;
        const discoveredModule = modules.get(moduleName);
        const details: string[] = [`desired=${desiredEnabled ? "enabled" : "disabled"}`];

        if (moduleState?.mode) {
            details.push(moduleState.mode);
        } else if (discoveredModule?.plugin.mode) {
            details.push(discoveredModule.plugin.mode);
        }

        if (!moduleState) {
            details.push("runtime=unknown");
            const nextHint = staleNextHint({
                desiredEnabled,
                mode: discoveredModule?.plugin.mode,
                intervalMs: discoveredModule?.plugin.intervalMs,
            });
            if (nextHint) {
                details.push(`next=${nextHint}`);
            }
            console.log(`- ${moduleName}: ${details.join(", ")}`);
            continue;
        }

        details.push(`${stateIsCurrent ? "runtime" : "last"}=${moduleState.status}`);

        if (stateIsCurrent && moduleState.desiredEnabled !== desiredEnabled) {
            details.push(`lastDesired=${moduleState.desiredEnabled ? "enabled" : "disabled"}`);
        }

        if (moduleState.nextRunAt) {
            details.push(`next=${moduleState.nextRunAt}`);
        } else if (!stateIsCurrent && desiredEnabled && moduleState.mode === "interval") {
            const nextHint = staleNextHint({
                desiredEnabled,
                mode: moduleState.mode,
                intervalMs: discoveredModule?.plugin.intervalMs,
            });
            if (nextHint) {
                details.push(`next=${nextHint}`);
            }
        } else if (!stateIsCurrent && desiredEnabled && moduleState.mode === "daemon") {
            const nextHint = staleNextHint({
                desiredEnabled,
                mode: moduleState.mode,
                intervalMs: discoveredModule?.plugin.intervalMs,
            });
            if (nextHint) {
                details.push(`next=${nextHint}`);
            }
        }

        details.push(`runs=${moduleState.runs}`);
        details.push(`restarts=${moduleState.restarts}`);

        if (moduleState.health) {
            details.push(`health=${moduleState.health.ok ? "ok" : "bad"}`);
        }

        if (moduleState.moduleStatus?.metrics) {
            const metrics = Object.entries(moduleState.moduleStatus.metrics)
                .map(([key, value]) => `${key}=${String(value)}`)
                .join(" ");
            if (metrics) {
                details.push(metrics);
            }
        }

        if (shouldShowModuleMessage(moduleState, { stateIsCurrent })) {
            details.push(moduleState.message);
        }
        console.log(`- ${moduleName}: ${details.join(", ")}`);

        if (moduleState.health?.message) {
            console.log(`  health: ${moduleState.health.message}`);
        }

        if (moduleState.moduleStatus?.message) {
            console.log(`  module: ${moduleState.moduleStatus.message}`);
        }

        if (moduleState.lastError) {
            console.log(`  last error: ${moduleState.lastError}`);
        }
    }
}
