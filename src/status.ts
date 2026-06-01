import { existsSync, readFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { loadServiceConfig } from "./config.ts";
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
    updatedAt: string;
    supervisor: {
        pid: number;
        startedAt: string;
        watch: boolean;
    };
    modules: Record<string, PersistedModuleState>;
};

function launchctlStatus(label: string): { loaded: boolean; pid: string; lastExitStatus: string } {
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

export async function renderStatus(): Promise<void> {
    const config = await loadServiceConfig(resolveRepoRoot());
    const launchd = launchctlStatus(config.label);

    console.log(`scriptd label: ${config.label}`);
    console.log(`LaunchAgent loaded: ${launchd.loaded ? "yes" : "no"}`);
    console.log(`LaunchAgent PID: ${launchd.pid}`);
    console.log(`LaunchAgent last exit status: ${launchd.lastExitStatus}`);
    console.log(`Config path: ${config.path}`);
    console.log(`Shared log dir: ${config.logDir}`);
    console.log(`State file: ${config.stateFile}`);

    if (!existsSync(config.stateFile)) {
        console.log("scriptd state: unavailable");
        return;
    }

    const state = JSON.parse(readFileSync(config.stateFile, "utf8")) as PersistedState;
    console.log(`scriptd PID: ${state.supervisor.pid}`);
    console.log(`scriptd started: ${state.supervisor.startedAt}`);
    console.log(`scriptd watch enabled: ${state.supervisor.watch ? "yes" : "no"}`);
    console.log(`State updated: ${state.updatedAt}`);

    const moduleNames = Object.keys(state.modules).sort();
    if (moduleNames.length === 0) {
        console.log("Modules: none discovered");
        return;
    }

    console.log("Modules:");
    for (const moduleName of moduleNames) {
        const moduleState = state.modules[moduleName];
        const details: string[] = [
            moduleState.desiredEnabled ? "enabled" : "disabled",
            moduleState.mode,
            moduleState.status,
        ];

        if (moduleState.nextRunAt) {
            details.push(`next=${moduleState.nextRunAt}`);
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

        details.push(moduleState.message);
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
