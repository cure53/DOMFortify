/**
 * Runs the QUnit suite in Node and exits non-zero on any failure (for CI).
 */
import QUnit from 'qunit';
import './test-suite.mjs';

QUnit.on('testEnd', (t) => {
  if (t.status === 'failed') {
    for (const a of t.assertions) {
      if (!a.passed) console.error(`  FAIL: ${t.fullName.join(' > ')} - ${a.message}`);
    }
  }
});

QUnit.on('runEnd', (data) => {
  const { passed, failed, total } = data.testCounts;
  console.log(`\nDOMFortify: ${passed}/${total} tests passed, ${failed} failed.`);
  process.exitCode = failed > 0 ? 1 : 0;
});

QUnit.start();
