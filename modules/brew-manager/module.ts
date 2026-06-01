import os from "node:os";
import path from "node:path";
import { promises as fs } from "node:fs";
import { spawnSync } from "node:child_process";
import type { ModuleContext, ModuleHealth, ModuleStatus, RootServiceModule } from "../../src/interfaces.ts";
import { assertPositiveInteger, parseSimpleYaml } from "../../src/config.ts";

type BrewManagerConfig = {
    keychainService: string;
    askpassPath: string;
    legacyLogDir: string;
    maxLogSizeMb: number;
    maxLogAgeDays: number;
    maxRotatedLogs: number;
    homebrewBin: string;
    sudoersPath: string;
    sudoersTimeoutPath: string;
    sudoTimeoutHours: number;
};

type BrewCommand = {
    args: string[];
    tolerateFailure?: boolean;
};

type BrewState = {
    lastRunAt?: string;
    lastMessage?: string;
    lastError?: string;
    repairedCasks: string[];
};

const moduleState: BrewState = {
    repairedCasks: [],
};

function expandHome(value: string): string {
    if (value === "~") {
        return process.env.HOME ?? os.homedir();
    }

    if (value.startsWith("~/")) {
        return path.join(process.env.HOME ?? os.homedir(), value.slice(2));
    }

    return value;
}

async function loadConfigFile(moduleDir: string): Promise<Record<string, unknown>> {
    const configPath = path.join(moduleDir, "module.yaml");
    try {
        const text = await fs.readFile(configPath, "utf8");
        return parseSimpleYaml(text);
    } catch {
        return {};
    }
}

function run(command: string, args: string[], options: { input?: string; check?: boolean } = {}): { stdout: string; stderr: string; status: number } {
    const result = spawnSync(command, args, {
        encoding: "utf8",
        input: options.input,
    });
    const status = typeof result.status === "number" ? result.status : 1;
    if ((options.check ?? true) && status !== 0) {
        throw new Error(result.stderr || `command failed: ${[command, ...args].join(" ")}`);
    }

    return {
        stdout: result.stdout ?? "",
        stderr: result.stderr ?? "",
        status,
    };
}

function resolveBrewConfig(raw: Record<string, unknown>): BrewManagerConfig {
    return {
        keychainService: String(raw.keychain_service ?? "BrewAutoUpdate"),
        askpassPath: expandHome(String(raw.askpass_path ?? "~/Library/Application Support/scriptd/brew-manager/brew_askpass.sh")),
        legacyLogDir: expandHome(String(raw.legacy_log_dir ?? "~/Library/Logs/Homebrew")),
        maxLogSizeMb: assertPositiveInteger(raw.max_log_size_mb ?? 50, "brew-manager.max_log_size_mb"),
        maxLogAgeDays: assertPositiveInteger(raw.max_log_age_days ?? 30, "brew-manager.max_log_age_days"),
        maxRotatedLogs: assertPositiveInteger(raw.max_rotated_logs ?? 5, "brew-manager.max_rotated_logs"),
        homebrewBin: String(raw.homebrew_bin ?? "/opt/homebrew/bin/brew"),
        sudoersPath: String(raw.sudoers_path ?? "/etc/sudoers.d/homebrew"),
        sudoersTimeoutPath: String(raw.sudoers_timeout_path ?? "/etc/sudoers.d/homebrew_timeout"),
        sudoTimeoutHours: assertPositiveInteger(raw.sudo_timeout_hours ?? 2, "brew-manager.sudo_timeout_hours"),
    };
}

async function rotateLogFile(logFile: string, maxLogSizeMb: number, maxRotatedLogs: number): Promise<void> {
    try {
        const stats = await fs.stat(logFile);
        const fileSizeMb = Math.floor(stats.size / 1024 / 1024);
        if (fileSizeMb <= maxLogSizeMb) {
            return;
        }

        for (let index = maxRotatedLogs - 1; index >= 1; index -= 1) {
            const source = `${logFile}.${index}`;
            const target = `${logFile}.${index + 1}`;
            try {
                await fs.rename(source, target);
            } catch {
                // ignore missing segments
            }
        }

        await fs.rename(logFile, `${logFile}.1`);
        await fs.writeFile(logFile, "", "utf8");
    } catch {
        // no log file yet
    }
}

async function cleanupLegacyLogs(config: BrewManagerConfig, ctx: ModuleContext): Promise<void> {
    try {
        await fs.access(config.legacyLogDir);
    } catch {
        return;
    }

    ctx.log.info(`Cleaning up legacy Homebrew logs in ${config.legacyLogDir}`);
    await rotateLogFile(path.join(config.legacyLogDir, "autoupdate.log"), config.maxLogSizeMb, config.maxRotatedLogs);
    await rotateLogFile(path.join(config.legacyLogDir, "autoupdate.err"), config.maxLogSizeMb, config.maxRotatedLogs);
}

function keychainPassword(service: string): string {
    return run("security", ["find-generic-password", "-s", service, "-a", process.env.USER ?? "", "-w"], { check: false }).stdout.trim();
}

async function writeAskpassHelper(config: BrewManagerConfig): Promise<void> {
    await fs.mkdir(path.dirname(config.askpassPath), { recursive: true });
    await fs.writeFile(
        config.askpassPath,
        `#!/bin/bash\nsecurity find-generic-password -s "${config.keychainService}" -a "${process.env.USER ?? ""}" -w\n`,
        "utf8",
    );
    await fs.chmod(config.askpassPath, 0o755);
}

async function promptHidden(prompt: string): Promise<string> {
    if (!process.stdin.isTTY || !process.stdout.isTTY) {
        throw new Error("Interactive setup requires a TTY");
    }

    process.stdout.write(prompt);
    const stdin = process.stdin;
    stdin.setRawMode?.(true);
    stdin.resume();
    stdin.setEncoding("utf8");

    return await new Promise((resolve, reject) => {
        let value = "";

        const cleanup = () => {
            stdin.setRawMode?.(false);
            stdin.pause();
            stdin.removeListener("data", onData);
            process.stdout.write("\n");
        };

        const onData = (chunk: string) => {
            if (chunk === "\u0003") {
                cleanup();
                reject(new Error("setup cancelled"));
                return;
            }

            if (chunk === "\r" || chunk === "\n") {
                cleanup();
                resolve(value);
                return;
            }

            if (chunk === "\u007f") {
                value = value.slice(0, -1);
                return;
            }

            value += chunk;
        };

        stdin.on("data", onData);
    });
}

function verifySudoPassword(password: string): boolean {
    const result = spawnSync("sudo", ["-S", "-v"], {
        encoding: "utf8",
        input: `${password}\n`,
    });
    return result.status === 0;
}

function storePasswordInKeychain(service: string, password: string): void {
    run("security", ["add-generic-password", "-U", "-s", service, "-a", process.env.USER ?? "", "-w", password]);
}

async function configureSudo(config: BrewManagerConfig, password: string): Promise<void> {
    const rulesTmp = path.join(os.tmpdir(), `brew-manager-rules-${process.pid}.tmp`);
    const timeoutTmp = path.join(os.tmpdir(), `brew-manager-timeout-${process.pid}.tmp`);

    await fs.writeFile(
        rulesTmp,
        `${process.env.USER} ALL=(ALL) NOPASSWD: ${config.homebrewBin} upgrade*, ${config.homebrewBin} cleanup\n`,
        "utf8",
    );
    await fs.writeFile(timeoutTmp, `Defaults:${process.env.USER} timestamp_timeout=${config.sudoTimeoutHours * 60}\n`, "utf8");

    run("sudo", ["-S", "cp", rulesTmp, config.sudoersPath], { input: `${password}\n` });
    run("sudo", ["-S", "chmod", "440", config.sudoersPath], { input: `${password}\n` });
    run("sudo", ["-S", "cp", timeoutTmp, config.sudoersTimeoutPath], { input: `${password}\n` });
    run("sudo", ["-S", "chmod", "440", config.sudoersTimeoutPath], { input: `${password}\n` });

    await fs.rm(rulesTmp, { force: true });
    await fs.rm(timeoutTmp, { force: true });
}

async function ensureSudoPassword(config: BrewManagerConfig): Promise<string> {
    const existing = keychainPassword(config.keychainService);
    if (existing && verifySudoPassword(existing)) {
        return existing;
    }

    if (existing) {
        run("security", ["delete-generic-password", "-s", config.keychainService, "-a", process.env.USER ?? ""], { check: false });
    }

    for (let attempt = 1; attempt <= 3; attempt += 1) {
        run("sudo", ["-k"], { check: false });
        const password = await promptHidden("Enter your sudo password: ");
        if (verifySudoPassword(password)) {
            storePasswordInKeychain(config.keychainService, password);
            return password;
        }

        console.error(`Password verification failed (attempt ${attempt}/3).`);
    }

    throw new Error("Could not verify your password after 3 attempts.");
}

function brewCommand(config: BrewManagerConfig, args: string[]): { stdout: string; stderr: string; status: number } {
    const env = {
        ...process.env,
        SUDO_ASKPASS: config.askpassPath,
    };
    const result = spawnSync(config.homebrewBin, args, {
        encoding: "utf8",
        env,
    });

    return {
        stdout: result.stdout ?? "",
        stderr: result.stderr ?? "",
        status: typeof result.status === "number" ? result.status : 1,
    };
}

export function buildBrewCommands(homebrewBin: string, outdatedCasks: string[]): BrewCommand[] {
    const commands: BrewCommand[] = [
        { args: ["update"] },
        { args: ["upgrade", "--formula"], tolerateFailure: true },
        { args: ["upgrade", "--cask"], tolerateFailure: true },
    ];

    if (outdatedCasks.length > 0) {
        for (const cask of outdatedCasks) {
            commands.push({ args: ["upgrade", "--cask", "--force", cask], tolerateFailure: true });
            commands.push({ args: ["uninstall", "--cask", "--force", cask], tolerateFailure: true });
            commands.push({ args: ["install", "--cask", cask], tolerateFailure: true });
        }
    } else {
        commands.push({ args: ["upgrade", "--cask", "--force"], tolerateFailure: true });
    }

    commands.push({ args: ["cleanup"], tolerateFailure: true });
    return commands.map((entry) => ({ ...entry, args: entry.args.slice() }));
}

async function runBrewMaintenance(ctx: ModuleContext, config: BrewManagerConfig): Promise<void> {
    await cleanupLegacyLogs(config, ctx);
    await fs.access(config.askpassPath);

    const update = brewCommand(config, ["update"]);
    if (update.status !== 0) {
        throw new Error(update.stderr || "brew update failed");
    }
    ctx.log.info(update.stdout.trim() || "brew update completed");

    const formula = brewCommand(config, ["upgrade", "--formula"]);
    if (formula.stdout.trim()) {
        ctx.log.info(formula.stdout.trim());
    }

    const cask = brewCommand(config, ["upgrade", "--cask"]);
    if (cask.status !== 0) {
        ctx.log.warn("Regular cask upgrade failed, attempting repair flow");
        const outdated = brewCommand(config, ["outdated", "--cask", "--quiet"]);
        const outdatedCasks = outdated.stdout
            .split("\n")
            .map((item) => item.trim())
            .filter(Boolean);
        const commandPlan = buildBrewCommands(config.homebrewBin, outdatedCasks).slice(3, -1);
        moduleState.repairedCasks = outdatedCasks;

        for (const entry of commandPlan) {
            const result = brewCommand(config, entry.args);
            if (result.stdout.trim()) {
                ctx.log.info(result.stdout.trim());
            }
        }
    }

    const cleanup = brewCommand(config, ["cleanup"]);
    if (cleanup.stdout.trim()) {
        ctx.log.info(cleanup.stdout.trim());
    }
}

const modulePlugin: RootServiceModule<BrewManagerConfig> = {
    id: "brew-manager",
    mode: "interval",
    intervalMs: 43_200_000,
    async loadConfig(ctx) {
        return resolveBrewConfig(await loadConfigFile(ctx.moduleDir));
    },
    async setup(ctx) {
        const config = resolveBrewConfig(await loadConfigFile(ctx.moduleDir));
        const password = await ensureSudoPassword(config);
        await writeAskpassHelper(config);
        await configureSudo(config, password);
        ctx.log.info("brew-manager setup complete");
        console.log("brew-manager setup complete.");
    },
    async runOnce(ctx, config) {
        await runBrewMaintenance(ctx, config);
        moduleState.lastRunAt = new Date().toISOString();
        moduleState.lastMessage = "Homebrew maintenance completed";
        moduleState.lastError = undefined;
    },
    status(): ModuleStatus {
        return {
            state: "running",
            message: moduleState.lastMessage,
            lastRunAt: moduleState.lastRunAt,
            metrics: {
                repairedCasks: moduleState.repairedCasks.join(",") || "none",
            },
        };
    },
    health(): ModuleHealth {
        return {
            ok: !moduleState.lastError,
            message: moduleState.lastError ?? "brew manager healthy",
        };
    },
};

export default modulePlugin;
