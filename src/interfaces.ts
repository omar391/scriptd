export type ModuleMode = "daemon" | "interval";

export type ModuleState = "idle" | "starting" | "running" | "stopping" | "stopped" | "error";

export type ModuleStatus = {
    state: ModuleState;
    message?: string;
    startedAt?: string;
    lastRunAt?: string;
    nextRunAt?: string;
    metrics?: Record<string, number | string | boolean>;
};

export type ModuleHealth = {
    ok: boolean;
    message?: string;
};

export type ModuleLogger = {
    info(message: string): void;
    warn(message: string): void;
    error(message: string): void;
};

export type ModuleContext = {
    id: string;
    repoRoot: string;
    moduleDir: string;
    logDir: string;
    signal: AbortSignal;
    env: NodeJS.ProcessEnv;
    log: ModuleLogger;
};

export type RootServiceModule<TConfig = unknown> = {
    id: string;
    displayName?: string;
    mode: ModuleMode;
    intervalMs?: number;
    loadConfig?(ctx: ModuleContext): Promise<TConfig> | TConfig;
    setup?(ctx: ModuleContext): Promise<void>;
    start?(ctx: ModuleContext, config: TConfig): Promise<void>;
    stop?(ctx: ModuleContext): Promise<void>;
    runOnce?(ctx: ModuleContext, config: TConfig): Promise<void>;
    status?(ctx: ModuleContext): Promise<ModuleStatus> | ModuleStatus;
    health?(ctx: ModuleContext): Promise<ModuleHealth> | ModuleHealth;
};
