import path from "node:path";
import { appendFileSync } from "node:fs";
import type { DiscoveredModule } from "./config.ts";
import type { ModuleContext, ModuleHealth, ModuleLogger, ModuleStatus } from "./interfaces.ts";
import { ensureDirectory } from "./config.ts";
import { resolveRepoRoot } from "./paths.ts";

export type ModuleExecutionHandle = {
    context: ModuleContext;
    logger: ModuleLogger;
};

export function waitForAbort(signal: AbortSignal): Promise<void> {
    if (signal.aborted) {
        return Promise.resolve();
    }

    return new Promise((resolve) => {
        signal.addEventListener("abort", () => resolve(), { once: true });
    });
}

function writeLogLine(filePath: string, level: string, message: string): void {
    const line = `[${new Date().toISOString()}] [${level}] ${message}\n`;
    appendFileSync(filePath, line, "utf8");
}

function createLogger(logDir: string, moduleId: string): ModuleLogger {
    const outPath = path.join(logDir, `${moduleId}.log`);
    const errPath = path.join(logDir, `${moduleId}.err`);

    return {
        info(message: string) {
            writeLogLine(outPath, "INFO", message);
        },
        warn(message: string) {
            writeLogLine(outPath, "WARN", message);
        },
        error(message: string) {
            writeLogLine(errPath, "ERROR", message);
        },
    };
}

export async function createModuleExecutionHandle(
    moduleDef: DiscoveredModule,
    options: { logDir: string; signal: AbortSignal; env?: NodeJS.ProcessEnv; repoRoot?: string },
): Promise<ModuleExecutionHandle> {
    await ensureDirectory(options.logDir);

    const logger = createLogger(options.logDir, moduleDef.id);
    const context: ModuleContext = {
        id: moduleDef.id,
        repoRoot: options.repoRoot ?? resolveRepoRoot(),
        moduleDir: moduleDef.dir,
        logDir: options.logDir,
        signal: options.signal,
        env: {
            ...process.env,
            ...options.env,
            SCRIPTD_ROOT_DIR: options.repoRoot ?? resolveRepoRoot(),
            SCRIPTD_MODULE_NAME: moduleDef.id,
            SCRIPTD_MODULE_DIR: moduleDef.dir,
            SCRIPTD_SHARED_LOG_DIR: options.logDir,
        },
        log: logger,
    };

    return { context, logger };
}

export async function loadModuleConfig(moduleDef: DiscoveredModule, context: ModuleContext): Promise<unknown> {
    if (!moduleDef.plugin.loadConfig) {
        return undefined;
    }

    return await moduleDef.plugin.loadConfig(context);
}

export async function resolveModuleStatus(moduleDef: DiscoveredModule, context: ModuleContext): Promise<ModuleStatus | undefined> {
    if (!moduleDef.plugin.status) {
        return undefined;
    }

    return await moduleDef.plugin.status(context);
}

export async function resolveModuleHealth(moduleDef: DiscoveredModule, context: ModuleContext): Promise<ModuleHealth | undefined> {
    if (!moduleDef.plugin.health) {
        return undefined;
    }

    return await moduleDef.plugin.health(context);
}

export async function runModuleSetup(moduleDef: DiscoveredModule, logDir: string): Promise<void> {
    if (!moduleDef.plugin.setup) {
        throw new Error(`Module ${moduleDef.id} has no setup() implementation`);
    }

    const controller = new AbortController();
    const { context } = await createModuleExecutionHandle(moduleDef, {
        logDir,
        signal: controller.signal,
    });
    await moduleDef.plugin.setup(context);
}

export async function runModuleDirect(moduleDef: DiscoveredModule, logDir: string): Promise<void> {
    const controller = new AbortController();
    const { context } = await createModuleExecutionHandle(moduleDef, {
        logDir,
        signal: controller.signal,
    });
    const config = await loadModuleConfig(moduleDef, context);

    const shutdown = async () => {
        controller.abort();
        if (moduleDef.plugin.stop) {
            await moduleDef.plugin.stop(context);
        }
    };

    process.once("SIGINT", () => {
        void shutdown().finally(() => process.exit(0));
    });
    process.once("SIGTERM", () => {
        void shutdown().finally(() => process.exit(0));
    });

    if (moduleDef.plugin.mode === "interval") {
        if (!moduleDef.plugin.runOnce) {
            throw new Error(`Interval module ${moduleDef.id} is missing runOnce()`);
        }

        await moduleDef.plugin.runOnce(context, config);
        return;
    }

    if (!moduleDef.plugin.start) {
        throw new Error(`Daemon module ${moduleDef.id} is missing start()`);
    }

    await moduleDef.plugin.start(context, config);
}
