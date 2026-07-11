/**
 * Runs the node QUnit suite against the Istanbul-instrumented build and writes the collected counters
 * to .nyc_output so `nyc report` can render them. DOMFORTIFY_COV is set before the suite is imported
 * (dynamic import, so it is read in time) to select the instrumented module.
 */
process.env.DOMFORTIFY_COV = '1';

const QUnit = (await import('qunit')).default;
const { mkdirSync, writeFileSync } = await import('node:fs');
await import('../test/test-suite.mjs');

QUnit.on('runEnd', (data) => {
  if (globalThis.__coverage__) {
    mkdirSync('.nyc_output', { recursive: true });
    writeFileSync('.nyc_output/out.json', JSON.stringify(globalThis.__coverage__));
  }
  if (data.testCounts.failed > 0) process.exitCode = 1;
});

QUnit.start();
