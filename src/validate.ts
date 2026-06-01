import path from "node:path";
import { promises as fs } from "node:fs";

const FORBIDDEN_DIRECTORIES = ["node_modules", "venv", ".venv", "env", "__pycache__", ".pytest_cache"];

export async function findForbiddenDependencyDirectories(rootDir: string): Promise<string[]> {
    const found: string[] = [];

    for (const dirName of FORBIDDEN_DIRECTORIES) {
        try {
            await fs.access(path.join(rootDir, dirName));
            found.push(dirName);
        } catch {
            // no-op
        }
    }

    return found;
}

export async function assertNoDependencyDirs(rootDir: string): Promise<void> {
    const found = await findForbiddenDependencyDirectories(rootDir);

    if (found.length === 0) {
        return;
    }

    throw new Error(
        `Forbidden dependency directories detected in repo root: ${found.join(
            ", ",
        )}. Move them elsewhere before installing the root service.`,
    );
}
