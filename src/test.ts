import { runTestCases } from "./tests/harness.ts";
import { createUnitTests } from "./tests/unit.ts";
import { createIntegrationTests } from "./tests/integration.ts";
import { assertNoDependencyDirs } from "./validate.ts";
import { resolveRepoRoot } from "./paths.ts";

export async function runAllTests(): Promise<number> {
    await assertNoDependencyDirs(resolveRepoRoot());

    const tests = [...createUnitTests(), ...createIntegrationTests()];
    const failed = await runTestCases(tests);

    console.log(`Ran ${tests.length} tests: ${tests.length - failed} passed, ${failed} failed`);
    return failed === 0 ? 0 : 1;
}
