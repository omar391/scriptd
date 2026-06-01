import path from "node:path";
import { promises as fs } from "node:fs";
import { pathToFileURL } from "node:url";
import type { RootServiceModule } from "./interfaces.ts";
import { resolveHomeDir, resolveModulesDir, resolveServiceConfigPath, resolveStateDir, resolveStateFile } from "./paths.ts";

export type ServiceModuleConfig = {
    enabled: boolean;
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
type YamlValue = YamlObject | YamlScalar;
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

function ensureOptionalString(value: unknown, label: string): string | undefined {
    if (value === undefined) {
        return undefined;
    }

    return ensureString(value, label);
}

function assertAllowedKeys(record: Record<string, unknown>, allowedKeys: string[], label: string): void {
    const allowed = new Set(allowedKeys);
    const unexpected = Object.keys(record).filter((key) => !allowed.has(key));

    if (unexpected.length > 0) {
        throw new Error(`${label} contains unsupported keys: ${unexpected.join(", ")}`);
    }
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
}): { shouldSchedule: boolean; delayMs: number | null; reason: string } {
    if (!options.desiredEnabled) {
        return { shouldSchedule: false, delayMs: null, reason: "disabled" };
    }

    if (options.isRunning) {
        return { shouldSchedule: false, delayMs: null, reason: "already running" };
    }

    return {
        shouldSchedule: true,
        delayMs: options.intervalMs,
        reason: "enabled",
    };
}

export async function loadServiceConfig(rootDir: string, configPath = resolveServiceConfigPath(rootDir)): Promise<ServiceConfig> {
    const parsed = await readYamlFile(configPath);
    const record = ensureObject(parsed, `service config ${configPath}`);
    assertAllowedKeys(record, ["label", "log_dir", "watch", "modules"], "service config");
    const modulesValue = record.modules ? ensureObject(record.modules, "service.modules") : {};
    const modules: Record<string, ServiceModuleConfig> = {};

    for (const [moduleName, rawValue] of Object.entries(modulesValue)) {
        const moduleConfig = ensureObject(rawValue, `service.modules.${moduleName}`);
        assertAllowedKeys(moduleConfig, ["enabled"], `service.modules.${moduleName}`);
        modules[moduleName] = {
            enabled: ensureBoolean(moduleConfig.enabled, `service.modules.${moduleName}.enabled`),
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
