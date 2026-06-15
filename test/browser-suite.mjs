/**
 * In-browser smoke tests (QUnit). These run under real Trusted Types via Playwright and check the
 * public surface and environment reporting. The exhaustive logic tests live in test-suite.mjs,
 * which runs in Node where the environment is fully controllable.
 */
import { init, status, DOMFortify } from '../dist/fortify.es.mjs';

QUnit.module('public surface (browser)');

QUnit.test('exports are present and frozen', (assert) => {
  assert.strictEqual(typeof init, 'function', 'init is a function');
  assert.strictEqual(typeof status, 'function', 'status is a function');
  assert.strictEqual(typeof DOMFortify.init, 'function', 'DOMFortify.init');
  assert.strictEqual(typeof DOMFortify.status, 'function', 'DOMFortify.status');
  assert.true(Object.isFrozen(DOMFortify), 'DOMFortify is frozen');
});

QUnit.test('init returns a well-formed status object', (assert) => {
  const s = init({ ON_VIOLATION() {} });
  for (const key of [
    'version',
    'ttSupported',
    'enforcementActive',
    'defaultPolicyOwned',
    'sanitizerReady',
    'protected',
    'reason',
  ]) {
    assert.true(key in s, `status has ${key}`);
  }
  assert.strictEqual(s.ttSupported, 'trustedTypes' in window, 'ttSupported reflects the browser');
  assert.strictEqual(typeof s.protected, 'boolean', 'protected is a boolean');
  assert.strictEqual(status(), s, 'status() returns the cached result');
});
