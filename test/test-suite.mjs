/**
 * DOMFortify test suite (QUnit).
 *
 * These tests exercise the security-relevant logic against a controllable mock of Trusted Types,
 * the DOM, and the sanitizer, so each scenario gets a fresh realm. They run in Node via
 * `node-runner.mjs` (the verified gate) and can also run in a browser; the in-browser smoke tests
 * live in `browser-suite.mjs`.
 */
import QUnit from 'qunit';

QUnit.config.autostart = false;

let counter = 0;
const MODULE_URL = new URL('../dist/fortify.es.mjs', import.meta.url);

// Fresh module instance each call, so the module-level "installed once" state never leaks between tests.
function freshModule() {
  const url = new URL(MODULE_URL);
  url.search = 'u=' + counter++;
  return import(url.href);
}

// --- mock builders -------------------------------------------------------------------------------

function makeTT(opts = {}) {
  return {
    _created: null,
    _rules: null,
    _preexisting: opts.preexisting ? { foreign: 'preexisting' } : null,
    get defaultPolicy() {
      if (this._preexisting) return this._preexisting;
      if (opts.foreignAfterCreate && this._created) return { foreign: 'race' };
      return this._created;
    },
    createPolicy(name, rules) {
      if (opts.createThrows) throw new Error('default policy already exists');
      this._rules = rules;
      this._created = { name, rules };
      return this._created;
    },
  };
}

function makeDoc({ enforced = true } = {}) {
  return {
    createElement() {
      let value = '';
      return {
        get innerHTML() {
          return value;
        },
        set innerHTML(next) {
          if (enforced) throw new TypeError('This document requires TrustedHTML assignment');
          value = next;
        },
      };
    },
  };
}

async function install(env, options) {
  globalThis.trustedTypes = env.tt;
  globalThis.document = env.doc;
  if ('DOMPurify' in env) globalThis.DOMPurify = env.DOMPurify;
  else delete globalThis.DOMPurify;
  const mod = await freshModule();
  const status = mod.init(options || {});
  return { mod, status, rules: env.tt._rules };
}

function cleanup() {
  delete globalThis.trustedTypes;
  delete globalThis.document;
  delete globalThis.DOMPurify;
  delete Object.prototype.ALLOW_SCRIPT_URL;
  delete Object.prototype.ALLOW_SCRIPT;
}

// --- sanitizer resolution ------------------------------------------------------------------------

QUnit.module('sanitizer resolution', (hooks) => {
  hooks.afterEach(cleanup);

  QUnit.test('object with .sanitize is used directly', async (assert) => {
    const dp = { sanitize: (s) => '[clean]' + s };
    const { status, rules } = await install({ tt: makeTT(), doc: makeDoc(), DOMPurify: dp });
    assert.true(status.sanitizerReady, 'smoke test passed');
    assert.strictEqual(rules.createHTML('<x>'), '[clean]<x>', 'createHTML returns the sanitized string');
  });

  QUnit.test('callable DOMPurify factory uses .sanitize, not the factory', async (assert) => {
    // Real DOMPurify is a callable factory that ALSO carries .sanitize. Calling the factory with a
    // string returns the instance (which stringifies to an arrow fn). We must use .sanitize.
    const dp = () => dp;
    dp.sanitize = (s) => '[clean]' + s;
    const { status, rules } = await install({ tt: makeTT(), doc: makeDoc(), DOMPurify: dp });
    assert.true(status.sanitizerReady, 'smoke test passed');
    const out = rules.createHTML('<img src=x>');
    assert.strictEqual(typeof out, 'string', 'returns a string, not the factory');
    assert.strictEqual(out, '[clean]<img src=x>', 'used .sanitize');
  });

  QUnit.test('bare function is wrapped as a sanitizer', async (assert) => {
    const fn = (s) => '[san]' + s;
    const { status, rules } = await install({ tt: makeTT(), doc: makeDoc() }, { SANITIZER: fn });
    assert.true(status.sanitizerReady, 'smoke test passed');
    assert.strictEqual(rules.createHTML('<x>'), '[san]<x>', 'wrapped function used');
  });

  QUnit.test('sanitizer returning a non-string fails closed', async (assert) => {
    const dp = { sanitize: () => ({ not: 'a string' }) };
    const { status, rules } = await install({ tt: makeTT(), doc: makeDoc(), DOMPurify: dp });
    assert.false(status.sanitizerReady, 'smoke test failed -> not ready');
    assert.strictEqual(rules.createHTML('<x>'), null, 'createHTML fails closed (null)');
  });

  QUnit.test('no sanitizer at all fails closed', async (assert) => {
    const { status, rules } = await install({ tt: makeTT(), doc: makeDoc() });
    assert.false(status.sanitizerReady, 'no sanitizer -> not ready');
    assert.strictEqual(rules.createHTML('<x>'), null, 'createHTML fails closed');
  });
});

// --- prototype-pollution resistance --------------------------------------------------------------

QUnit.module('prototype-pollution resistance', (hooks) => {
  hooks.afterEach(cleanup);

  QUnit.test('polluted ALLOW_SCRIPT_URL cannot open the script-url sink', async (assert) => {
    Object.prototype.ALLOW_SCRIPT_URL = () => 'https://evil.example/x.js';
    const dp = { sanitize: (s) => '[clean]' + s };
    const { rules } = await install({ tt: makeTT(), doc: makeDoc(), DOMPurify: dp });
    assert.strictEqual(rules.createScriptURL('https://evil.example/x.js'), null, 'still refused');
  });

  QUnit.test('polluted ALLOW_SCRIPT cannot open the script sink', async (assert) => {
    Object.prototype.ALLOW_SCRIPT = () => 'alert(1)';
    const dp = { sanitize: (s) => '[clean]' + s };
    const { rules } = await install({ tt: makeTT(), doc: makeDoc(), DOMPurify: dp });
    assert.strictEqual(rules.createScript('alert(1)'), null, 'still refused');
  });
});

// --- script sinks --------------------------------------------------------------------------------

QUnit.module('script sinks', (hooks) => {
  hooks.afterEach(cleanup);

  QUnit.test('refused by default', async (assert) => {
    const dp = { sanitize: (s) => s };
    const { rules } = await install({ tt: makeTT(), doc: makeDoc(), DOMPurify: dp });
    assert.strictEqual(rules.createScript('alert(1)'), null, 'createScript refused');
    assert.strictEqual(rules.createScriptURL('https://x/y.js'), null, 'createScriptURL refused');
  });

  QUnit.test('own ALLOW_SCRIPT hook can mint an exact value', async (assert) => {
    const dp = { sanitize: (s) => s };
    const { rules } = await install(
      { tt: makeTT(), doc: makeDoc(), DOMPurify: dp },
      {
        ALLOW_SCRIPT: (code) => (code === 'OK' ? code : null),
      },
    );
    assert.strictEqual(rules.createScript('OK'), 'OK', 'allowed exact match');
    assert.strictEqual(rules.createScript('alert(1)'), null, 'refused otherwise');
  });

  QUnit.test('a throwing hook fails closed', async (assert) => {
    const dp = { sanitize: (s) => s };
    const { rules } = await install(
      { tt: makeTT(), doc: makeDoc(), DOMPurify: dp },
      {
        ALLOW_SCRIPT: () => {
          throw new Error('boom');
        },
      },
    );
    assert.strictEqual(rules.createScript('whatever'), null, 'refused on hook error');
  });
});

// --- default-policy ownership --------------------------------------------------------------------

QUnit.module('default policy ownership', (hooks) => {
  hooks.afterEach(cleanup);

  QUnit.test('pre-existing default policy -> not owned, not protected', async (assert) => {
    const dp = { sanitize: (s) => s };
    const { status } = await install({ tt: makeTT({ preexisting: true }), doc: makeDoc(), DOMPurify: dp });
    assert.false(status.defaultPolicyOwned, 'did not claim a foreign policy');
    assert.false(status.protected, 'not protected');
  });

  QUnit.test('createPolicy throwing -> not owned', async (assert) => {
    const dp = { sanitize: (s) => s };
    const { status } = await install({ tt: makeTT({ createThrows: true }), doc: makeDoc(), DOMPurify: dp });
    assert.false(status.defaultPolicyOwned, 'lost the race');
  });

  QUnit.test('allow-duplicates race lost -> not owned', async (assert) => {
    const dp = { sanitize: (s) => s };
    const { status } = await install({ tt: makeTT({ foreignAfterCreate: true }), doc: makeDoc(), DOMPurify: dp });
    assert.false(status.defaultPolicyOwned, 'created but not the active default');
  });

  QUnit.test('happy path -> owned and protected', async (assert) => {
    const dp = { sanitize: (s) => '[clean]' + s };
    const { status } = await install({ tt: makeTT(), doc: makeDoc({ enforced: true }), DOMPurify: dp });
    assert.true(status.defaultPolicyOwned, 'owned');
    assert.true(status.enforcementActive, 'enforced');
    assert.true(status.sanitizerReady, 'sanitizer ready');
    assert.true(status.protected, 'protected');
  });
});

// --- status / inertness --------------------------------------------------------------------------

QUnit.module('status', (hooks) => {
  hooks.afterEach(cleanup);

  QUnit.test('no Trusted Types -> inert, reports unsupported', async (assert) => {
    globalThis.document = makeDoc();
    delete globalThis.trustedTypes;
    delete globalThis.DOMPurify;
    const mod = await freshModule();
    const status = mod.init({});
    assert.false(status.ttSupported, 'ttSupported false');
    assert.false(status.protected, 'inert');
  });

  QUnit.test('init is idempotent and status() returns the cached result', async (assert) => {
    const dp = { sanitize: (s) => s };
    const { mod, status } = await install({ tt: makeTT(), doc: makeDoc(), DOMPurify: dp });
    assert.strictEqual(mod.init({}), status, 'second init returns the same status');
    assert.strictEqual(mod.status(), status, 'status() returns it too');
  });
});
