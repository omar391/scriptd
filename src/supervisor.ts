import { promises as fs, watch, type FSWatcher } from "node:fs";
import type { DiscoveredModule, ServiceConfig } from "./config.ts";
import { buildIntervalPlan, buildModuleStateDiff, discoverModules, ensureDirectory, loadServiceConfig } from "./config.ts";
import type { ModuleContext, ModuleHealth, ModuleStatus } from "./interfaces.ts";
import {
    createModuleExecutionHandle,
    loadModuleConfig,
    resolveModuleHealth,
    resolveModuleStatus,
    waitForAbort,
} from "./module-runner.ts";
import { resolveRepoRoot } from "./paths.ts";

type RuntimeStatus = "disabled" | "scheduled" | "running" | "stopped" | "error" | "stopping";

type ModuleRuntimeState = {
    moduleDef: DiscoveredModule;
    desiredEnabled: boolean;
    status: RuntimeStatus;
    controller?: AbortController;
    context?: ModuleContext;
    runPromise?: Promise<void>;
    timer?: NodeJS.Timeout;
    lastStartedAt?: string;
    lastRunAt?: string;
    lastExitAt?: string;
    nextRunAt?: string;
    runs: number;
    restarts: number;
    message: string;
    lastError?: string;
    health?: ModuleHealth;
    moduleStatus?: ModuleStatus;
};

type PersistedModuleState = {
    desiredEnabled: boolean;
    status: RuntimeStatus;
    mode: "daemon" | "interval";
    lastStartedAt?: string;
    lastRunAt?: string;
    lastExitAt?: string;
    nextRunAt?: string;
    runs: number;
    restarts: number;
    message: string;
    health?: ModuleHealth;
    moduleStatus?: ModuleStatus;
    lastError?: string;
};

type PersistedState = {
    label: string;
    rootDir: string;
    configPath: string;
    logDir: string;
    updatedAt: string;
    supervisor: {
        pid: number;
        startedAt: string;
        watch: boolean;
    };
    modules: Record<string, PersistedModuleState>;
};

const REPO_ROOT = resolveRepoRoot();
const supervisorStartedAt = new Date().toISOString();

function timestamp(): string {
    return new Date().toISOString();
}

function wait(ms: number): Promise<void> {
    return new Promise((resolve) => setTimeout(resolve, ms));
}

export async function runSupervisor(): Promise<void> {
    let currentConfig!: ServiceConfig;
    let watcher: FSWatcher | undefined;
    let reloadTimer: NodeJS.Timeout | undefined;
    let shuttingDown = false;
    const moduleStates = new Map<string, ModuleRuntimeState>();

    async function refreshModuleSignals(state: ModuleRuntimeState): Promise<void> {
        if (!state.context) {
            return;
        }

        state.moduleStatus = await resolveModuleStatus(state.moduleDef, state.context).catch(() => undefined);
        state.health = await resolveModuleHealth(state.moduleDef, state.context).catch(() => undefined);
    }

    async function writeStateFile(): Promise<void> {
        const persisted: PersistedState = {
            label: currentConfig.label,
            rootDir: currentConfig.rootDir,
            configPath: currentConfig.path,
            logDir: currentConfig.logDir,
            updatedAt: timestamp(),
            supervisor: {
                pid: process.pid,
                startedAt: supervisorStartedAt,
                watch: currentConfig.watch,
            },
            modules: {},
        };

        for (const [moduleName, state] of moduleStates.entries()) {
            await refreshModuleSignals(state);
            persisted.modules[moduleName] = {
                desiredEnabled: state.desiredEnabled,
                status: state.status,
                mode: state.moduleDef.plugin.mode,
                lastStartedAt: state.lastStartedAt,
                lastRunAt: state.lastRunAt,
                lastExitAt: state.lastExitAt,
                nextRunAt: state.nextRunAt,
                runs: state.runs,
                restarts: state.restarts,
                message: state.message,
                health: state.health,
                moduleStatus: state.moduleStatus,
                lastError: state.lastError,
            };
        }

        await ensureDirectory(currentConfig.stateDir);
        await fs.writeFile(currentConfig.stateFile, `${JSON.stringify(persisted, null, 2)}\n`, "utf8");
    }

    function setState(state: ModuleRuntimeState, status: RuntimeStatus, message: string): void {
        state.status = status;
        state.message = message;
    }

    function clearModuleTimer(state: ModuleRuntimeState): void {
        if (state.timer) {
            clearTimeout(state.timer);
            state.timer = undefined;
        }

        state.nextRunAt = undefined;
    }

    async function stopModule(state: ModuleRuntimeState): Promise<void> {
        state.desiredEnabled = false;
        clearModuleTimer(state);

        if (!state.controller) {
            setState(state, "disabled", "module disabled");
            await writeStateFile();
            return;
        }

        setState(state, "stopping", "stopping module");
        await writeStateFile();
        state.controller.abort();

        if (state.context && state.moduleDef.plugin.stop) {
            await state.moduleDef.plugin.stop(state.context).catch((error) => {
                state.lastError = error instanceof Error ? error.message : String(error);
            });
        }

        if (state.runPromise) {
            await state.runPromise.catch(() => undefined);
        }

        state.controller = undefined;
        state.context = undefined;
        state.runPromise = undefined;
        state.health = undefined;
        state.moduleStatus = undefined;
        state.lastExitAt = timestamp();
        setState(state, "disabled", "module disabled");
        await writeStateFile();
    }

    async function createContext(state: ModuleRuntimeState): Promise<{ context: ModuleContext; config: unknown }> {
        const controller = new AbortController();
        state.controller = controller;
        const handle = await createModuleExecutionHandle(state.moduleDef, {
            logDir: currentConfig.logDir,
            signal: controller.signal,
            repoRoot: REPO_ROOT,
        });
        state.context = handle.context;
        const config = await loadModuleConfig(state.moduleDef, handle.context);
        return { context: handle.context, config };
    }

    async function runDaemon(state: ModuleRuntimeState): Promise<void> {
        if (!state.moduleDef.plugin.start) {
            throw new Error(`Daemon module ${state.moduleDef.id} is missing start()`);
        }

        const { context, config } = await createContext(state);
        state.lastStartedAt = timestamp();
        setState(state, "running", "daemon running");
        await writeStateFile();

        state.runPromise = state.moduleDef.plugin.start(context, config);
        try {
            await state.runPromise;
            state.lastExitAt = timestamp();

            if (state.desiredEnabled && !shuttingDown) {
                setState(state, "stopped", "daemon exited cleanly");
            } else {
                setState(state, "disabled", "module disabled");
            }
        } catch (error) {
            state.lastExitAt = timestamp();
            state.lastError = error instanceof Error ? error.stack ?? error.message : String(error);
            setState(state, "error", "daemon crashed");
            await writeStateFile();

            if (state.desiredEnabled && !shuttingDown) {
                state.restarts += 1;
                await wait(2000);
                await startModule(state);
                return;
            }
        } finally {
            state.controller = undefined;
            state.context = undefined;
            state.runPromise = undefined;
            await writeStateFile();
        }
    }

    async function runInterval(state: ModuleRuntimeState): Promise<void> {
        if (!state.moduleDef.plugin.runOnce) {
            throw new Error(`Interval module ${state.moduleDef.id} is missing runOnce()`);
        }

        const { context, config } = await createContext(state);
        state.lastStartedAt = timestamp();
        setState(state, "running", "interval run in progress");
        await writeStateFile();

        state.runPromise = state.moduleDef.plugin.runOnce(context, config);
        try {
            await state.runPromise;
            state.runs += 1;
            state.lastRunAt = timestamp();
            state.lastExitAt = timestamp();
            setState(state, "scheduled", "interval run completed");
        } catch (error) {
            state.runs += 1;
            state.lastRunAt = timestamp();
            state.lastExitAt = timestamp();
            state.lastError = error instanceof Error ? error.stack ?? error.message : String(error);
            setState(state, "error", "interval run failed");
        } finally {
            state.controller = undefined;
            state.context = undefined;
            state.runPromise = undefined;
            await writeStateFile();
            await scheduleInterval(state);
        }
    }

    async function scheduleInterval(state: ModuleRuntimeState): Promise<void> {
        clearModuleTimer(state);

        const plan = buildIntervalPlan({
            desiredEnabled: state.desiredEnabled,
            isRunning: Boolean(state.runPromise),
            intervalMs: state.moduleDef.plugin.intervalMs ?? 0,
        });

        if (!plan.shouldSchedule || plan.delayMs === null) {
            if (!state.desiredEnabled) {
                setState(state, "disabled", "interval disabled");
            }

            await writeStateFile();
            return;
        }

        state.nextRunAt = new Date(Date.now() + plan.delayMs).toISOString();
        setState(state, "scheduled", `next run at ${state.nextRunAt}`);
        await writeStateFile();

        state.timer = setTimeout(() => {
            state.timer = undefined;
            state.nextRunAt = undefined;
            void runInterval(state);
        }, plan.delayMs);
    }

    async function startModule(state: ModuleRuntimeState): Promise<void> {
        if (!state.desiredEnabled || shuttingDown) {
            return;
        }

        if (state.moduleDef.plugin.mode === "interval") {
            await scheduleInterval(state);
            return;
        }

        void runDaemon(state).catch(async (error) => {
            state.lastError = error instanceof Error ? error.stack ?? error.message : String(error);
            setState(state, "error", "daemon failed to start");
            await writeStateFile();
        });
    }

    function ensureModuleState(moduleDef: DiscoveredModule): ModuleRuntimeState {
        const existing = moduleStates.get(moduleDef.id);
        if (existing) {
            existing.moduleDef = moduleDef;
            return existing;
        }

        const state: ModuleRuntimeState = {
            moduleDef,
            desiredEnabled: false,
            status: "disabled",
            runs: 0,
            restarts: 0,
            message: "module discovered",
        };

        moduleStates.set(moduleDef.id, state);
        return state;
    }

    async function syncModules(nextConfig: ServiceConfig): Promise<void> {
        const modules = await discoverModules(REPO_ROOT);
        const currentEnabled: Record<string, boolean> = {};
        const desiredEnabled: Record<string, boolean> = {};

        for (const [moduleName, state] of moduleStates.entries()) {
            currentEnabled[moduleName] = state.desiredEnabled;
        }

        for (const [moduleName, moduleDef] of modules.entries()) {
            const state = ensureModuleState(moduleDef);
            desiredEnabled[moduleName] = nextConfig.modules[moduleName]?.enabled ?? false;
            state.desiredEnabled = desiredEnabled[moduleName];
        }

        for (const state of moduleStates.values()) {
            if (!modules.has(state.moduleDef.id)) {
                state.desiredEnabled = false;
            }
        }

        const diff = buildModuleStateDiff(currentEnabled, desiredEnabled);

        for (const [moduleName, state] of moduleStates.entries()) {
            if (!modules.has(moduleName)) {
                await stopModule(state);
                moduleStates.delete(moduleName);
            }
        }

        for (const moduleName of diff.toStop) {
            const state = moduleStates.get(moduleName);
            if (state) {
                await stopModule(state);
            }
        }

        for (const moduleName of diff.toStart) {
            const state = moduleStates.get(moduleName);
            if (state) {
                await startModule(state);
            }
        }

        for (const [moduleName, state] of moduleStates.entries()) {
            const shouldBeEnabled = desiredEnabled[moduleName] ?? false;

            if (shouldBeEnabled && state.moduleDef.plugin.mode === "interval" && !state.runPromise && !state.timer) {
                await scheduleInterval(state);
            }

            if (!shouldBeEnabled && !state.runPromise && !state.timer) {
                setState(state, "disabled", "module disabled");
            }
        }
    }

    async function applyConfig(reason: string): Promise<void> {
        const nextConfig = await loadServiceConfig(REPO_ROOT);
        currentConfig = nextConfig;
        await ensureDirectory(currentConfig.logDir);
        await syncModules(nextConfig);
        await configureWatcher();
        await writeStateFile();
        console.log(`[${timestamp()}] Applied config (${reason})`);
    }

    function safeApplyConfig(reason: string): void {
        void applyConfig(reason).catch((error) => {
            const message = error instanceof Error ? error.stack ?? error.message : String(error);
            console.error(`[${timestamp()}] Failed to apply config (${reason}): ${message}`);
        });
    }

    async function configureWatcher(): Promise<void> {
        if (watcher) {
            watcher.close();
            watcher = undefined;
        }

        if (!currentConfig.watch) {
            return;
        }

        watcher = watch(currentConfig.path, () => {
            if (reloadTimer) {
                clearTimeout(reloadTimer);
            }

            reloadTimer = setTimeout(() => {
                safeApplyConfig("service.yaml changed");
            }, 250);
        });
    }

    async function shutdown(): Promise<void> {
        shuttingDown = true;

        if (reloadTimer) {
            clearTimeout(reloadTimer);
            reloadTimer = undefined;
        }

        if (watcher) {
            watcher.close();
            watcher = undefined;
        }

        for (const state of moduleStates.values()) {
            await stopModule(state);
        }

        await writeStateFile();
    }

    process.on("SIGHUP", () => {
        safeApplyConfig("sighup");
    });

    process.on("SIGINT", () => {
        void shutdown().finally(() => process.exit(0));
    });

    process.on("SIGTERM", () => {
        void shutdown().finally(() => process.exit(0));
    });

    await applyConfig("startup");
    await waitForAbort(new AbortController().signal);
}
