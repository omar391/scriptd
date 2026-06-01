export type TestCase = {
    name: string;
    run: () => Promise<void> | void;
};

export async function runTestCases(cases: TestCase[]): Promise<number> {
    let failed = 0;

    for (const testCase of cases) {
        try {
            await testCase.run();
            console.log(`pass ${testCase.name}`);
        } catch (error) {
            failed += 1;
            const message = error instanceof Error ? error.stack ?? error.message : String(error);
            console.error(`fail ${testCase.name}`);
            console.error(message);
        }
    }

    return failed;
}
