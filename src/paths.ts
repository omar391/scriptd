import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const SOURCE_DIR = path.dirname(fileURLToPath(import.meta.url));

export function resolveHomeDir(): string {
    return process.env.HOME ?? os.homedir();
}

export function resolveRepoRoot(): string {
    if (process.env.SCRIPTD_ROOT_DIR) {
        return path.resolve(process.env.SCRIPTD_ROOT_DIR);
    }

    return path.resolve(SOURCE_DIR, "..");
}

export function resolveServiceConfigPath(repoRoot = resolveRepoRoot()): string {
    return path.join(repoRoot, "service.yaml");
}

export function resolveManageScriptPath(repoRoot = resolveRepoRoot()): string {
    if (process.env.SCRIPTD_ENTRY_SHELL_PATH) {
        return path.resolve(process.env.SCRIPTD_ENTRY_SHELL_PATH);
    }

    return path.join(repoRoot, "scriptd.sh");
}

export function resolveModulesDir(repoRoot = resolveRepoRoot()): string {
    return path.join(repoRoot, "modules");
}

export function resolveStateDir(homeDir = resolveHomeDir()): string {
    return path.join(homeDir, "Library", "Application Support", "scriptd");
}

export function resolveRuntimeDir(homeDir = resolveHomeDir()): string {
    return path.join(resolveStateDir(homeDir), "runtime");
}

export function resolveStateFile(homeDir = resolveHomeDir()): string {
    return path.join(resolveStateDir(homeDir), "state.json");
}
