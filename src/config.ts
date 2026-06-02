import path from "node:path";
import { promises as fs } from "node:fs";
import { pathToFileURL } from "node:url";
import type { RootServiceModule } from "./interfaces.ts";
import { resolveHomeDir, resolveModulesDir, resolveServiceConfigPath, resolveStateDir, resolveStateFile } from "./paths.ts";

export type ServiceModuleConfig = {
    enabled: boolean;
    schedule?: ModuleSchedule;
};

export type ServiceConfig = {
    label: string;
    logDir: string;
    watch: boolean;
    modules: Record<string, ServiceModuleConfig>;
    path: string;
    rootDir: string;
    stateDir: string;
    stateFile: string;
};

export type Weekday = "sun" | "mon" | "tue" | "wed" | "thu" | "fri" | "sat";

export type ScheduleWindow = {
    start: string;
    end: string;
};

export type ModuleSchedule = {
    cron?: string[];
    everySeconds?: number;
    dailyAt?: string[];
    weekdays?: Weekday[];
    window?: ScheduleWindow;
};

export type ModuleManifest = {
    id: string;
    displayName?: string;
    mode: "daemon" | "interval";
    intervalSeconds?: number;
    path: string;
};

export type DiscoveredModule = {
    id: string;
    dir: string;
    modulePath: string;
    manifest: ModuleManifest;
    plugin: RootServiceModule<unknown>;
};

type YamlScalar = boolean | number | string;
type YamlValue = YamlObject | YamlScalar | YamlScalar[];
type YamlObject = Record<string, YamlValue>;

type YamlStackEntry = {
    indent: number;
    value: YamlObject;
};

function stripInlineComment(line: string): string {
    let inSingle = false;
    let inDouble = false;

    for (let index = 0; index < line.length; index += 1) {
        const char = line[index];

        if (char === "'" && !inDouble) {
            inSingle = !inSingle;
            continue;
        }

        if (char === '"' && !inSingle) {
            inDouble = !inDouble;
            continue;
        }

        if (char === "#" && !inSingle && !inDouble) {
            if (index === 0 || /\s/.test(line[index - 1] ?? "")) {
                return line.slice(0, index).trimEnd();
            }
        }
    }

    return line;
}

function parseScalar(raw: string): YamlScalar {
    const trimmed = raw.trim();

    if (/^(true|false)$/i.test(trimmed)) {
        return trimmed.toLowerCase() === "true";
    }

    if (/^-?\d+$/.test(trimmed)) {
        return Number(trimmed);
    }

    if ((trimmed.startsWith('"') && trimmed.endsWith('"')) || (trimmed.startsWith("'") && trimmed.endsWith("'"))) {
        return trimmed.slice(1, -1);
    }

    return trimmed;
}

function isListItem(rawLine: string): boolean {
    return /^\s*-\s+/.test(rawLine);
}

function parseListItem(rawLine: string): { indent: number; value: YamlScalar } {
    const indent = rawLine.match(/^\s*/)?.[0].length ?? 0;
    const trimmed = rawLine.trim().replace(/^-+\s*/, "");
    return {
        indent,
        value: parseScalar(trimmed),
    };
}

function ensureObject(value: unknown, label: string): Record<string, unknown> {
    if (!value || typeof value !== "object" || Array.isArray(value)) {
        throw new Error(`${label} must be a mapping`);
    }

    return value as Record<string, unknown>;
}

function ensureString(value: unknown, label: string): string {
    if (typeof value !== "string" || value.length === 0) {
        throw new Error(`${label} must be a non-empty string`);
    }

    return value;
}

function ensureBoolean(value: unknown, label: string): boolean {
    if (typeof value !== "boolean") {
        throw new Error(`${label} must be a boolean`);
    }

    return value;
}

function ensurePositiveInteger(value: unknown, label: string): number {
    if (typeof value !== "number" || !Number.isInteger(value) || value <= 0) {
        throw new Error(`${label} must be a positive integer`);
    }

    return value;
}

function ensureOptionalPositiveInteger(value: unknown, label: string): number | undefined {
    if (value === undefined) {
        return undefined;
    }

    return ensurePositiveInteger(value, label);
}

function ensureOptionalString(value: unknown, label: string): string | undefined {
    if (value === undefined) {
        return undefined;
    }

    return ensureString(value, label);
}

function ensureStringArray(value: unknown, label: string): string[] {
    if (typeof value === "string") {
        return [value];
    }

    if (!Array.isArray(value) || value.some((item) => typeof item !== "string")) {
        throw new Error(`${label} must be a string or a list of strings`);
    }

    return value;
}

function ensureOptionalStringArray(value: unknown, label: string): string[] | undefined {
    if (value === undefined) {
        return undefined;
    }

    return ensureStringArray(value, label);
}

function assertAllowedKeys(record: Record<string, unknown>, allowedKeys: string[], label: string): void {
    const allowed = new Set(allowedKeys);
    const unexpected = Object.keys(record).filter((key) => !allowed.has(key));

    if (unexpected.length > 0) {
        throw new Error(`${label} contains unsupported keys: ${unexpected.join(", ")}`);
    }
}

function parseTimeOfDay(value: string, label: string): { hour: number; minute: number } {
    const match = value.match(/^([01]\d|2[0-3]):([0-5]\d)$/);
    if (!match) {
        throw new Error(`${label} must use HH:MM 24-hour time`);
    }

    return {
        hour: Number(match[1]),
        minute: Number(match[2]),
    };
}

function parseWeekday(value: string, label: string): Weekday {
    const normalized = value.toLowerCase();
    if (!["sun", "mon", "tue", "wed", "thu", "fri", "sat"].includes(normalized)) {
        throw new Error(`${label} must be one of sun, mon, tue, wed, thu, fri, sat`);
    }

    return normalized as Weekday;
}

function parseSchedule(rawValue: unknown, label: string): ModuleSchedule {
    const record = ensureObject(rawValue, label);
    assertAllowedKeys(record, ["cron", "every_seconds", "every_minutes", "every_hours", "daily_at", "weekdays", "window"], label);

    const cron = ensureOptionalStringArray(record.cron, `${label}.cron`);
    const dailyAt = ensureOptionalStringArray(record.daily_at, `${label}.daily_at`);
    const everySeconds = ensureOptionalPositiveInteger(record.every_seconds, `${label}.every_seconds`);
    const everyMinutes = ensureOptionalPositiveInteger(record.every_minutes, `${label}.every_minutes`);
    const everyHours = ensureOptionalPositiveInteger(record.every_hours, `${label}.every_hours`);
    const triggerCount = [cron, dailyAt, everySeconds, everyMinutes, everyHours].filter((value) => value !== undefined).length;
    if (triggerCount !== 1) {
        throw new Error(`${label} must define exactly one trigger: cron, daily_at, every_seconds, every_minutes, or every_hours`);
    }

    for (const expression of cron ?? []) {
        parseCronExpression(expression, `${label}.cron`);
    }

    const parsedDailyAt = dailyAt?.map((value, index) => {
        parseTimeOfDay(value, `${label}.daily_at[${index}]`);
        return value;
    });

    const weekdays = ensureOptionalStringArray(record.weekdays, `${label}.weekdays`)?.map((value, index) =>
        parseWeekday(value, `${label}.weekdays[${index}]`),
    );

    let window: ScheduleWindow | undefined;
    if (record.window !== undefined) {
        const windowRecord = ensureObject(record.window, `${label}.window`);
        assertAllowedKeys(windowRecord, ["start", "end"], `${label}.window`);
        window = {
            start: ensureString(windowRecord.start, `${label}.window.start`),
            end: ensureString(windowRecord.end, `${label}.window.end`),
        };
        parseTimeOfDay(window.start, `${label}.window.start`);
        parseTimeOfDay(window.end, `${label}.window.end`);
    }

    return {
        cron,
        dailyAt: parsedDailyAt,
        everySeconds: everySeconds ?? (everyMinutes ? everyMinutes * 60 : everyHours ? everyHours * 3600 : undefined),
        weekdays,
        window,
    };
}

function isRootServiceModule(value: unknown): value is RootServiceModule<unknown> {
    if (!value || typeof value !== "object") {
        return false;
    }

    const candidate = value as Partial<RootServiceModule<unknown>>;
    return typeof candidate.id === "string" && (candidate.mode === "daemon" || candidate.mode === "interval");
}

function validateDiscoveredModule(moduleDir: string, manifest: ModuleManifest, plugin: RootServiceModule<unknown>): void {
    const moduleName = path.basename(moduleDir);

    if (plugin.id !== moduleName) {
        throw new Error(`module id "${plugin.id}" must match folder "${moduleName}"`);
    }

    if (manifest.id !== moduleName) {
        throw new Error(`module manifest id "${manifest.id}" must match folder "${moduleName}"`);
    }

    if (plugin.id !== manifest.id) {
        throw new Error(`module plugin id "${plugin.id}" must match manifest id "${manifest.id}"`);
    }

    if (plugin.mode !== manifest.mode) {
        throw new Error(`module "${plugin.id}" mode mismatch between module.ts and module.yaml`);
    }

    if (plugin.mode === "daemon" && typeof plugin.start !== "function") {
        throw new Error(`daemon module "${plugin.id}" must implement start()`);
    }

    if (plugin.mode === "interval") {
        if (typeof plugin.runOnce !== "function") {
            throw new Error(`interval module "${plugin.id}" must implement runOnce()`);
        }

        if (!Number.isInteger(plugin.intervalMs) || (plugin.intervalMs ?? 0) <= 0) {
            throw new Error(`interval module "${plugin.id}" must define a positive intervalMs`);
        }

        if (manifest.intervalSeconds === undefined) {
            throw new Error(`interval module "${plugin.id}" must define interval_seconds in module.yaml`);
        }

        if (plugin.intervalMs !== manifest.intervalSeconds * 1000) {
            throw new Error(`interval module "${plugin.id}" interval mismatch between module.ts and module.yaml`);
        }
    }
}

async function importModuleFile(modulePath: string): Promise<RootServiceModule<unknown>> {
    const href = `${pathToFileURL(modulePath).href}?v=${Date.now()}`;
    const imported = await import(href);
    const plugin = imported.default;

    if (!isRootServiceModule(plugin)) {
        throw new Error(`module ${modulePath} must default-export a RootServiceModule`);
    }

    return plugin;
}

async function readYamlFile(filePath: string): Promise<YamlObject> {
    const contents = await fs.readFile(filePath, "utf8");
    return parseSimpleYaml(contents);
}

function parseModuleManifest(parsed: YamlObject, manifestPath: string): ModuleManifest {
    const record = ensureObject(parsed, `module manifest ${manifestPath}`);
    const mode = ensureString(record.mode, `${manifestPath}.mode`);

    if (mode !== "daemon" && mode !== "interval") {
        throw new Error(`${manifestPath}.mode must be "daemon" or "interval"`);
    }

    const intervalSeconds =
        mode === "interval" ? ensurePositiveInteger(record.interval_seconds, `${manifestPath}.interval_seconds`) : undefined;

    return {
        id: ensureString(record.id, `${manifestPath}.id`),
        displayName: ensureOptionalString(record.display_name, `${manifestPath}.display_name`),
        mode,
        intervalSeconds,
        path: manifestPath,
    };
}

export function expandHome(value: string): string {
    if (value === "~") {
        return resolveHomeDir();
    }

    if (value.startsWith("~/")) {
        return path.join(resolveHomeDir(), value.slice(2));
    }

    return value;
}

export function parseSimpleYaml(text: string): YamlObject {
    const root: YamlObject = {};
    const stack: YamlStackEntry[] = [{ indent: -1, value: root }];
    const pendingListKeys = new Map<number, { parent: YamlObject; key: string }>();

    for (const rawLine of text.split("\n")) {
        const normalized = stripInlineComment(rawLine.replace(/\r$/, ""));

        if (normalized.trim().length === 0) {
            continue;
        }

        if (isListItem(normalized)) {
            const item = parseListItem(normalized);
            const pending =
                pendingListKeys.get(item.indent - 2) ?? pendingListKeys.get(item.indent - 1) ?? pendingListKeys.get(item.indent);
            if (!pending) {
                throw new Error(`list item has no parent key: ${normalized.trim()}`);
            }

            const existing = pending.parent[pending.key];
            if (!Array.isArray(existing)) {
                pending.parent[pending.key] = [];
            }

            (pending.parent[pending.key] as YamlScalar[]).push(item.value);
            continue;
        }

        const indent = normalized.match(/^\s*/)?.[0].length ?? 0;
        const trimmed = normalized.trim();
        const match = trimmed.match(/^([A-Za-z0-9_.-]+):(?:\s+(.*))?$/);

        if (!match) {
            throw new Error(`unsupported YAML line: ${trimmed}`);
        }

        while (stack.length > 1 && indent <= stack[stack.length - 1].indent) {
            stack.pop();
        }

        const parent = stack[stack.length - 1]?.value;
        if (!parent) {
            throw new Error(`invalid indentation near: ${trimmed}`);
        }

        const key = match[1];
        const rawValue = match[2];
        pendingListKeys.delete(indent);

        if (rawValue === undefined || rawValue.trim().length === 0) {
            const child: YamlObject = {};
            parent[key] = child;
            stack.push({ indent, value: child });
            pendingListKeys.set(indent, { parent, key });
            continue;
        }

        parent[key] = parseScalar(rawValue);
    }

    return root;
}

export function buildModuleStateDiff(
    currentEnabled: Record<string, boolean>,
    desiredEnabled: Record<string, boolean>,
): { toStart: string[]; toStop: string[] } {
    const toStart: string[] = [];
    const toStop: string[] = [];
    const moduleNames = new Set([...Object.keys(currentEnabled), ...Object.keys(desiredEnabled)]);

    for (const moduleName of moduleNames) {
        const current = currentEnabled[moduleName] ?? false;
        const desired = desiredEnabled[moduleName] ?? false;

        if (!current && desired) {
            toStart.push(moduleName);
        } else if (current && !desired) {
            toStop.push(moduleName);
        }
    }

    return {
        toStart: toStart.sort(),
        toStop: toStop.sort(),
    };
}

export function buildIntervalPlan(options: {
    desiredEnabled: boolean;
    isRunning: boolean;
    intervalMs: number;
    schedule?: ModuleSchedule;
    now?: Date;
}): { shouldSchedule: boolean; delayMs: number | null; reason: string } {
    if (!options.desiredEnabled) {
        return { shouldSchedule: false, delayMs: null, reason: "disabled" };
    }

    if (options.isRunning) {
        return { shouldSchedule: false, delayMs: null, reason: "already running" };
    }

    const nextRunAt = nextScheduledRun(options.schedule, options.now ?? new Date(), options.intervalMs);
    if (!nextRunAt) {
        return { shouldSchedule: false, delayMs: null, reason: "no matching schedule" };
    }

    return {
        shouldSchedule: true,
        delayMs: Math.max(0, nextRunAt.getTime() - (options.now ?? new Date()).getTime()),
        reason: "enabled",
    };
}

type CronField = {
    min: number;
    max: number;
    values: Set<number>;
};

function parseCronField(raw: string, min: number, max: number, label: string): CronField {
    const values = new Set<number>();

    for (const part of raw.split(",")) {
        const stepMatch = part.match(/^(\*|\d+)(?:-(\d+))?(?:\/(\d+))?$/);
        if (!stepMatch) {
            throw new Error(`${label} contains unsupported cron field: ${raw}`);
        }

        const start = stepMatch[1] === "*" ? min : Number(stepMatch[1]);
        const end = stepMatch[2] ? Number(stepMatch[2]) : stepMatch[1] === "*" ? max : start;
        const step = stepMatch[3] ? Number(stepMatch[3]) : 1;
        if (start < min || end > max || start > end || step <= 0) {
            throw new Error(`${label} contains out-of-range cron field: ${raw}`);
        }

        for (let value = start; value <= end; value += step) {
            values.add(value);
        }
    }

    return { min, max, values };
}

function parseCronExpression(expression: string, label = "cron"): CronField[] {
    const parts = expression.trim().split(/\s+/);
    if (parts.length !== 6) {
        throw new Error(`${label} must use six fields: second minute hour day month weekday`);
    }

    return [
        parseCronField(parts[0], 0, 59, label),
        parseCronField(parts[1], 0, 59, label),
        parseCronField(parts[2], 0, 23, label),
        parseCronField(parts[3], 1, 31, label),
        parseCronField(parts[4], 1, 12, label),
        parseCronField(parts[5], 0, 6, label),
    ];
}

function cronMatches(expression: string, date: Date): boolean {
    const fields = parseCronExpression(expression);
    const values = [date.getSeconds(), date.getMinutes(), date.getHours(), date.getDate(), date.getMonth() + 1, date.getDay()];
    return fields.every((field, index) => field.values.has(values[index]));
}

function weekdayMatches(schedule: ModuleSchedule, date: Date): boolean {
    if (!schedule.weekdays || schedule.weekdays.length === 0) {
        return true;
    }

    const weekdays: Weekday[] = ["sun", "mon", "tue", "wed", "thu", "fri", "sat"];
    return schedule.weekdays.includes(weekdays[date.getDay()]);
}

function minutesOfDay(date: Date): number {
    return date.getHours() * 60 + date.getMinutes();
}

function windowMatches(schedule: ModuleSchedule, date: Date): boolean {
    if (!schedule.window) {
        return true;
    }

    const start = parseTimeOfDay(schedule.window.start, "schedule.window.start");
    const end = parseTimeOfDay(schedule.window.end, "schedule.window.end");
    const now = minutesOfDay(date);
    const startMinute = start.hour * 60 + start.minute;
    const endMinute = end.hour * 60 + end.minute;

    if (startMinute <= endMinute) {
        return now >= startMinute && now <= endMinute;
    }

    return now >= startMinute || now <= endMinute;
}

function scheduleGatesMatch(schedule: ModuleSchedule, date: Date): boolean {
    return weekdayMatches(schedule, date) && windowMatches(schedule, date);
}

export function cronFromSchedule(schedule: ModuleSchedule, fallbackIntervalMs: number): string[] {
    if (schedule.cron) {
        return schedule.cron.slice();
    }

    if (schedule.dailyAt) {
        return schedule.dailyAt.map((value) => {
            const parsed = parseTimeOfDay(value, "schedule.daily_at");
            return `0 ${parsed.minute} ${parsed.hour} * * *`;
        });
    }

    const seconds = schedule.everySeconds ?? Math.max(1, Math.round(fallbackIntervalMs / 1000));
    if (seconds < 60) {
        return [`*/${seconds} * * * * *`];
    }

    if (seconds % 3600 === 0) {
        return [`0 0 */${Math.max(1, seconds / 3600)} * * *`];
    }

    if (seconds % 60 === 0) {
        return [`0 */${Math.max(1, seconds / 60)} * * * *`];
    }

    return [`*/${seconds} * * * * *`];
}

export function nextScheduledRun(schedule: ModuleSchedule | undefined, after: Date, fallbackIntervalMs: number): Date | undefined {
    const effectiveSchedule: ModuleSchedule = schedule ?? {
        everySeconds: Math.max(1, Math.round(fallbackIntervalMs / 1000)),
    };
    const expressions = cronFromSchedule(effectiveSchedule, fallbackIntervalMs);
    const candidate = new Date(after.getTime() + 1000);
    candidate.setMilliseconds(0);
    const deadline = after.getTime() + 366 * 24 * 60 * 60 * 1000;

    while (candidate.getTime() <= deadline) {
        if (scheduleGatesMatch(effectiveSchedule, candidate) && expressions.some((expression) => cronMatches(expression, candidate))) {
            return candidate;
        }

        candidate.setSeconds(candidate.getSeconds() + 1);
    }

    return undefined;
}

export async function loadServiceConfig(rootDir: string, configPath = resolveServiceConfigPath(rootDir)): Promise<ServiceConfig> {
    const parsed = await readYamlFile(configPath);
    const record = ensureObject(parsed, `service config ${configPath}`);
    assertAllowedKeys(record, ["label", "log_dir", "watch", "modules"], "service config");
    const modulesValue = record.modules ? ensureObject(record.modules, "service.modules") : {};
    const modules: Record<string, ServiceModuleConfig> = {};

    for (const [moduleName, rawValue] of Object.entries(modulesValue)) {
        const moduleConfig = ensureObject(rawValue, `service.modules.${moduleName}`);
        assertAllowedKeys(moduleConfig, ["enabled", "schedule"], `service.modules.${moduleName}`);
        modules[moduleName] = {
            enabled: ensureBoolean(moduleConfig.enabled, `service.modules.${moduleName}.enabled`),
            schedule: moduleConfig.schedule ? parseSchedule(moduleConfig.schedule, `service.modules.${moduleName}.schedule`) : undefined,
        };
    }

    return {
        label: ensureString(record.label, "service.label"),
        logDir: path.resolve(expandHome(ensureString(record.log_dir, "service.log_dir"))),
        watch: ensureBoolean(record.watch, "service.watch"),
        modules,
        path: configPath,
        rootDir,
        stateDir: resolveStateDir(),
        stateFile: resolveStateFile(),
    };
}

export async function discoverModules(rootDir: string): Promise<Map<string, DiscoveredModule>> {
    const modulesDir = resolveModulesDir(rootDir);
    let dirents: Awaited<ReturnType<typeof fs.readdir>>;

    try {
        dirents = await fs.readdir(modulesDir, { withFileTypes: true });
    } catch {
        return new Map();
    }

    const modules = new Map<string, DiscoveredModule>();

    for (const dirent of dirents) {
        if (!dirent.isDirectory()) {
            continue;
        }

        const moduleDir = path.join(modulesDir, dirent.name);
        const modulePath = path.join(moduleDir, "module.ts");
        const manifestPath = path.join(moduleDir, "module.yaml");

        await fs.access(modulePath);
        await fs.access(manifestPath);

        const manifest = parseModuleManifest(await readYamlFile(manifestPath), manifestPath);
        const plugin = await importModuleFile(modulePath);
        validateDiscoveredModule(moduleDir, manifest, plugin);

        modules.set(plugin.id, {
            id: plugin.id,
            dir: moduleDir,
            modulePath,
            manifest,
            plugin,
        });
    }

    return modules;
}

export async function ensureDirectory(dirPath: string): Promise<void> {
    await fs.mkdir(dirPath, { recursive: true });
}

export function assertPositiveInteger(value: unknown, label: string): number {
    return ensurePositiveInteger(value, label);
}
