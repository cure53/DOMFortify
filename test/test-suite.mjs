/**
 * DOMFortify test suite (QUnit).
 *
 * These tests exercise the security-relevant logic against a controllable mock of Trusted Types,
 * the DOM, and the sanitizer, so each scenario gets a fresh realm. They run in Node via
 * `node-runner.mjs` (the verified gate) and can also run in a browser; the in-browser smoke tests
 * live in `browser-suite.mjs`.
 */
import QUnit from 'qunit';
import { readFileSync } from 'node:fs';

QUnit.config.autostart = false;

let counter = 0;
const MODULE_URL = new URL(
  process.env.DOMFORTIFY_COV ? '../dist/fortify.cov.es.mjs' : '../dist/fortify.es.mjs',
  import.meta.url,
);

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

function makeDoc({ enforced = true, readyState = 'complete' } = {}) {
  const writes = [];
  const appended = [];
  return {
    readyState,
    _writes: writes,
    _appended: appended,
    write(s) {
      writes.push(s);
    },
    head: {
      appendChild(n) {
        appended.push(n);
      },
    },
    documentElement: {
      appendChild(n) {
        appended.push(n);
      },
    },
    createElement() {
      let value = '';
      const attrs = {};
      return {
        attributes: attrs,
        setAttribute(k, v) {
          attrs[k] = v;
        },
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
  globalThis.location = env.location || { href: 'https://example.test/' };
  if ('DOMPurify' in env) globalThis.DOMPurify = env.DOMPurify;
  else delete globalThis.DOMPurify;
  const mod = await freshModule();
  const status = mod.init(options || {});
  return { mod, status, rules: env.tt._rules };
}

function cleanup() {
  delete globalThis.trustedTypes;
  delete globalThis.document;
  delete globalThis.location;
  delete globalThis.DOMPurify;
  delete Object.prototype.ALLOW_SCRIPT_URL;
  delete Object.prototype.ALLOW_SCRIPT;
  delete Object.prototype.EXCLUDE;
  delete Object.prototype.URL_CONFIG;
  delete Object.prototype.sanitize;
  delete Object.prototype.match;
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

  QUnit.test('a class-based sanitizer (method on its own prototype) is accepted', async (assert) => {
    // The .sanitize lives on the class prototype (below Object.prototype), not as an own key. It must
    // still be recognised: the pollution guard only rejects a sanitize reached from Object.prototype.
    class S {
      sanitize(s) {
        return '[class]' + s;
      }
    }
    const { status, rules } = await install({ tt: makeTT(), doc: makeDoc() }, { SANITIZER: new S() });
    assert.true(status.sanitizerReady, 'class instance accepted as a sanitizer');
    assert.strictEqual(rules.createHTML('<x>'), '[class]<x>', 'its prototype sanitize is used');
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

  QUnit.test('polluted Object.prototype.sanitize is not adopted as the sanitizer', async (assert) => {
    // Identity "sanitize" on the prototype would pass payloads through untouched if adopted. The
    // global sanitizer is a DOM-clobbered truthy non-sanitizer (e.g. window.DOMPurify -> an element),
    // which on its own would fail closed; the danger is the prototype method getting mistaken for it.
    Object.prototype.sanitize = (s) => s;
    const clobbered = { tagName: 'IMG' }; // truthy, no own .sanitize
    const { status, rules } = await install({ tt: makeTT(), doc: makeDoc(), DOMPurify: clobbered });
    assert.false(status.sanitizerReady, 'prototype sanitize is not a usable sanitizer');
    assert.strictEqual(rules.createHTML('<img src=x onerror=alert(1)>'), null, 'HTML sink fails closed');
  });

  QUnit.test('a hostile throwing sanitize getter fails closed, never bricks init', async (assert) => {
    const evil = {};
    Object.defineProperty(evil, 'sanitize', {
      get() {
        throw new Error('boom');
      },
    });
    const { mod, status } = await install({ tt: makeTT(), doc: makeDoc() }, { SANITIZER: evil });
    assert.true(status != null, 'init returned a status object (did not throw or brick)');
    assert.true(mod.status() != null, 'status() is not null after a hostile getter');
    assert.false(status.sanitizerReady, 'sanitizer not ready');
    assert.false(status.protected, 'not protected; HTML sinks fail closed');
    assert.true(status.defaultPolicyOwned, 'default slot still claimed, so nothing else can grab it');
  });

  QUnit.test(
    'a sanitizer throwing a self-referential hostile error still fails closed, never bricks',
    async (assert) => {
      // The error's `message` is a getter that re-throws the error itself, so a naive emsg() would
      // throw every time it is read - defeating both the inner and outer catch and bricking init.
      const selfRef = {};
      Object.defineProperty(selfRef, 'message', {
        get() {
          throw selfRef;
        },
      });
      const dp = {
        sanitize() {
          throw selfRef;
        },
      };
      const { mod, status } = await install({ tt: makeTT(), doc: makeDoc(), DOMPurify: dp });
      assert.true(status != null, 'init returned a status (did not throw or brick)');
      assert.true(mod.status() != null, 'status() is not null');
      assert.false(status.sanitizerReady, 'sanitizer not ready');
      assert.false(status.protected, 'fails closed');
      assert.true(status.defaultPolicyOwned, 'default slot still claimed');
    },
  );

  QUnit.test('polluted Object.prototype.match cannot apply a rule that lacks its own match', async (assert) => {
    Object.prototype.match = '/'; // would match every URL if read off the prototype
    const dp = { sanitize: (_s, c) => JSON.stringify(c) };
    const env = { tt: makeTT(), doc: makeDoc(), DOMPurify: dp, location: { href: 'https://app.test/home' } };
    const rule = { SANITIZER_CONFIG: { LOOSENED: true } }; // NO own `match` key
    const { rules } = await install(env, { SANITIZER_CONFIG: { strict: true }, URL_CONFIG: [rule] });
    assert.deepEqual(
      JSON.parse(rules.createHTML('<x>')),
      { strict: true },
      'base config used; the match-less rule did not apply',
    );
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

// --- URL targeting (EXCLUDE / URL_CONFIG) & meta injection ---------------------------------------

QUnit.module('url targeting & meta injection', (hooks) => {
  hooks.afterEach(cleanup);

  QUnit.test('EXCLUDE (substring) keeps DOMFortify fully inactive', async (assert) => {
    const dp = { sanitize: (s) => '[clean]' + s };
    const env = { tt: makeTT(), doc: makeDoc(), DOMPurify: dp, location: { href: 'https://app.test/admin/users' } };
    const { status } = await install(env, { EXCLUDE: '/admin/' });
    assert.true(status.excluded, 'status.excluded is true');
    assert.false(status.defaultPolicyOwned, 'no default policy claimed');
    assert.false(status.protected, 'not protected');
    assert.strictEqual(env.tt._rules, null, 'createPolicy was never called');
  });

  QUnit.test('EXCLUDE (regex) matches against location.href', async (assert) => {
    const dp = { sanitize: (s) => '[clean]' + s };
    const env = { tt: makeTT(), doc: makeDoc(), DOMPurify: dp, location: { href: 'https://app.test/p?debug=1' } };
    const { status } = await install(env, { EXCLUDE: [/[?&]debug=1\b/] });
    assert.true(status.excluded, 'excluded by regex');
    assert.strictEqual(env.tt._rules, null, 'no policy');
  });

  QUnit.test('EXCLUDE that does not match installs normally', async (assert) => {
    const dp = { sanitize: (s) => '[clean]' + s };
    const env = { tt: makeTT(), doc: makeDoc(), DOMPurify: dp, location: { href: 'https://app.test/home' } };
    const { status, rules } = await install(env, { EXCLUDE: '/admin/' });
    assert.false(status.excluded, 'not excluded');
    assert.true(status.protected, 'protected as usual');
    assert.strictEqual(rules.createHTML('<x>'), '[clean]<x>', 'policy active');
  });

  QUnit.test('INCLUDE activates only on matching URLs', async (assert) => {
    const dp = { sanitize: (s) => '[clean]' + s };
    const hit = { tt: makeTT(), doc: makeDoc(), DOMPurify: dp, location: { href: 'https://app.test/admin/users' } };
    const onHit = await install(hit, { INCLUDE: ['/admin/'] });
    assert.false(onHit.status.excluded, 'in scope, not excluded');
    assert.true(onHit.status.protected, 'protected on an included URL');
    assert.strictEqual(onHit.rules.createHTML('<x>'), '[clean]<x>', 'policy active in scope');

    const miss = { tt: makeTT(), doc: makeDoc(), DOMPurify: dp, location: { href: 'https://app.test/home' } };
    const offHit = await install(miss, { INCLUDE: ['/admin/'] });
    assert.true(offHit.status.excluded, 'out of scope is reported as excluded');
    assert.false(offHit.status.protected, 'not protected outside INCLUDE');
    assert.strictEqual(miss.tt._rules, null, 'no policy claimed outside scope');
  });

  QUnit.test('EXCLUDE wins over INCLUDE when a URL matches both', async (assert) => {
    const dp = { sanitize: (s) => '[clean]' + s };
    const env = { tt: makeTT(), doc: makeDoc(), DOMPurify: dp, location: { href: 'https://app.test/admin/secret' } };
    const { status } = await install(env, { INCLUDE: ['/admin/'], EXCLUDE: ['/secret'] });
    assert.true(status.excluded, 'excluded');
    assert.false(status.protected, 'not protected');
    assert.strictEqual(env.tt._rules, null, 'no policy claimed');
  });

  QUnit.test('no INCLUDE means active everywhere (minus EXCLUDE)', async (assert) => {
    const dp = { sanitize: (s) => '[clean]' + s };
    const env = { tt: makeTT(), doc: makeDoc(), DOMPurify: dp, location: { href: 'https://app.test/anywhere' } };
    const { status } = await install(env, {});
    assert.false(status.excluded, 'active by default');
    assert.true(status.protected, 'protected everywhere when INCLUDE is unset');
  });

  QUnit.test('polluted EXCLUDE cannot silently disable the library', async (assert) => {
    Object.prototype.EXCLUDE = '/'; // would match every URL if read off the prototype
    const dp = { sanitize: (s) => '[clean]' + s };
    const { status } = await install({ tt: makeTT(), doc: makeDoc(), DOMPurify: dp });
    assert.false(status.excluded, 'prototype EXCLUDE ignored (own-key only)');
    assert.true(status.protected, 'still protected');
  });

  QUnit.test('URL_CONFIG overrides SANITIZER_CONFIG for a matching URL', async (assert) => {
    const dp = { sanitize: (_s, cfg) => JSON.stringify(cfg) }; // echo the effective config
    const env = { tt: makeTT(), doc: makeDoc(), DOMPurify: dp, location: { href: 'https://app.test/comments/42' } };
    const { rules } = await install(env, {
      SANITIZER_CONFIG: { ALLOWED_TAGS: ['div'] },
      URL_CONFIG: [{ match: '/comments/', SANITIZER_CONFIG: { ALLOWED_TAGS: ['b', 'i'] } }],
    });
    assert.deepEqual(
      JSON.parse(rules.createHTML('<x>')),
      { ALLOWED_TAGS: ['b', 'i'] },
      'override config reached sanitizer',
    );
  });

  QUnit.test('URL_CONFIG falls back to the base config when nothing matches', async (assert) => {
    const dp = { sanitize: (_s, cfg) => JSON.stringify(cfg) };
    const env = { tt: makeTT(), doc: makeDoc(), DOMPurify: dp, location: { href: 'https://app.test/home' } };
    const { rules } = await install(env, {
      SANITIZER_CONFIG: { ALLOWED_TAGS: ['div'] },
      URL_CONFIG: [{ match: '/comments/', SANITIZER_CONFIG: { ALLOWED_TAGS: ['b'] } }],
    });
    assert.deepEqual(JSON.parse(rules.createHTML('<x>')), { ALLOWED_TAGS: ['div'] }, 'base config used');
  });

  QUnit.test('URL_CONFIG can override the sanitizer and a script hook per URL', async (assert) => {
    const env = { tt: makeTT(), doc: makeDoc(), location: { href: 'https://app.test/trusted/page' } };
    const { rules } = await install(env, {
      SANITIZER: (s) => '[base]' + s,
      URL_CONFIG: [
        {
          match: /\/trusted\//,
          SANITIZER: (s) => '[override]' + s,
          ALLOW_SCRIPT_URL: (u) => (u.startsWith('https://cdn.test/') ? u : null),
        },
      ],
    });
    assert.strictEqual(rules.createHTML('<x>'), '[override]<x>', 'override sanitizer used');
    assert.strictEqual(
      rules.createScriptURL('https://cdn.test/a.js'),
      'https://cdn.test/a.js',
      'override hook allows vetted URL',
    );
    assert.strictEqual(rules.createScriptURL('https://evil.test/a.js'), null, 'override hook refuses the rest');
  });

  QUnit.test('first matching URL_CONFIG rule wins', async (assert) => {
    const dp = { sanitize: (_s, cfg) => JSON.stringify(cfg) };
    const env = { tt: makeTT(), doc: makeDoc(), DOMPurify: dp, location: { href: 'https://app.test/a/b' } };
    const { rules } = await install(env, {
      URL_CONFIG: [
        { match: '/a/', SANITIZER_CONFIG: { tag: 'first' } },
        { match: '/b', SANITIZER_CONFIG: { tag: 'second' } },
      ],
    });
    assert.deepEqual(JSON.parse(rules.createHTML('<x>')), { tag: 'first' }, 'first match applied');
  });

  QUnit.test('INJECT_META writes the meta during parse (readyState loading)', async (assert) => {
    const dp = { sanitize: (s) => s };
    const doc = makeDoc({ readyState: 'loading' });
    const { status } = await install({ tt: makeTT(), doc, DOMPurify: dp }, { INJECT_META: true });
    assert.true(status.metaInjected, 'metaInjected true when written during parse');
    assert.strictEqual(doc._writes.length, 1, 'document.write called once');
    assert.true(
      doc._writes[0].includes("require-trusted-types-for 'script'") &&
        doc._writes[0].includes('trusted-types default dompurify'),
      'wrote the enabling directive (default dompurify)',
    );
  });

  QUnit.test('INJECT_META with a bare-function sanitizer drops the dompurify policy name', async (assert) => {
    const doc = makeDoc({ readyState: 'loading' });
    await install({ tt: makeTT(), doc }, { INJECT_META: true, SANITIZER: (s) => s });
    assert.true(doc._writes[0].includes('trusted-types default;'), 'directive lists only default');
    assert.false(doc._writes[0].includes('dompurify'), 'no dompurify policy name');
  });

  QUnit.test('INJECT_META after parse falls back to append and reports not written', async (assert) => {
    const dp = { sanitize: (s) => s };
    const doc = makeDoc({ readyState: 'complete' });
    const { status } = await install({ tt: makeTT(), doc, DOMPurify: dp }, { INJECT_META: true });
    assert.false(status.metaInjected, 'metaInjected false: append after parse does not enforce');
    assert.strictEqual(doc._writes.length, 0, 'document.write not called');
    assert.strictEqual(doc._appended.length, 1, 'a meta node was appended as a (non-enforcing) fallback');
    assert.strictEqual(doc._appended[0].attributes['http-equiv'], 'Content-Security-Policy', 'appended a CSP meta');
  });

  QUnit.test('META_DIRECTIVE overrides the injected directive', async (assert) => {
    const dp = { sanitize: (s) => s };
    const doc = makeDoc({ readyState: 'loading' });
    await install(
      { tt: makeTT(), doc, DOMPurify: dp },
      { INJECT_META: true, META_DIRECTIVE: 'trusted-types default custom;' },
    );
    assert.strictEqual(
      doc._writes[0],
      '<meta http-equiv="Content-Security-Policy" content="trusted-types default custom;">',
      'custom directive used verbatim',
    );
  });

  QUnit.test('a hostile META_DIRECTIVE cannot break out of the written meta tag', async (assert) => {
    const dp = { sanitize: (s) => s };
    const doc = makeDoc({ readyState: 'loading' });
    await install(
      { tt: makeTT(), doc, DOMPurify: dp },
      { INJECT_META: true, META_DIRECTIVE: 'default x"><script>alert(1)</script>' },
    );
    const written = doc._writes[0];
    assert.false(written.includes('<script'), 'no injected <script tag survives');
    assert.false(written.includes('</script'), 'no injected closing tag survives');
    assert.strictEqual(
      (written.match(/"/g) || []).length,
      4,
      'no extra quote: the content attribute cannot be closed early (http-equiv + content = 4 quotes)',
    );
    assert.true(written.endsWith('">'), 'the tag closes normally');
  });

  QUnit.test('no INJECT_META means no write and no append', async (assert) => {
    const dp = { sanitize: (s) => s };
    const doc = makeDoc({ readyState: 'loading' });
    const { status } = await install({ tt: makeTT(), doc, DOMPurify: dp });
    assert.false(status.metaInjected, 'metaInjected false');
    assert.strictEqual(doc._writes.length, 0, 'no write');
    assert.strictEqual(doc._appended.length, 0, 'no append');
  });
});

// --- reentrancy guard ----------------------------------------------------------------------------

QUnit.module('reentrancy guard', (hooks) => {
  hooks.afterEach(cleanup);

  QUnit.test(
    'a sanitizer that re-enters createHTML gets the raw string back; the outer call still sanitizes',
    async (assert) => {
      // A sanitizer without its own Trusted Types policy would, on writing to an internal HTML sink,
      // re-enter our default policy. The guard must hand that re-entrant call the RAW string so the
      // sanitizer can finish parsing inertly, instead of recursing forever - while the top-level call
      // still returns sanitized output. holder.createHTML is wired only AFTER install, so the smoke test
      // during init does not itself re-enter.
      const holder = {};
      let reentrantResult;
      const reentrantSanitizer = {
        sanitize(input) {
          if (holder.createHTML) reentrantResult = holder.createHTML('<i>probe</i>');
          return '<clean>' + input + '</clean>';
        },
      };
      const { rules } = await install({ tt: makeTT(), doc: makeDoc(), DOMPurify: reentrantSanitizer }, {});
      holder.createHTML = rules.createHTML;

      const out = rules.createHTML('<img src=x onerror=alert(1)>');
      assert.strictEqual(
        reentrantResult,
        '<i>probe</i>',
        're-entrant createHTML returns the raw string (guard active, no recursion)',
      );
      assert.strictEqual(
        out,
        '<clean><img src=x onerror=alert(1)></clean>',
        'the top-level call returns sanitized output, not raw',
      );

      reentrantResult = undefined;
      const out2 = rules.createHTML('<b>two</b>');
      assert.strictEqual(
        out2,
        '<clean><b>two</b></clean>',
        'the reentry flag resets between top-level calls (still sanitizes)',
      );
      assert.strictEqual(reentrantResult, '<i>probe</i>', 'and the guard still applies on the next call');
    },
  );
});

// --- public API surface (1.0 contract lock) ------------------------------------------------------
// Snapshots the public surface so an unintended addition, removal, or rename - to the runtime exports,
// the status() shape, the config keys, the per-URL override keys, or the violation codes - fails CI
// loudly. When a change here is INTENTIONAL, update the matching baseline below in the same commit:
// that diff is the deliberate, reviewable record of a public-contract change.

const DTS = readFileSync(new URL('../dist/fortify.d.ts', import.meta.url), 'utf8');

function interfaceKeys(name) {
  const start = DTS.indexOf('interface ' + name + ' {');
  const body = DTS.slice(start, DTS.indexOf('\n}', start));
  return [...body.matchAll(/^ {4}([A-Za-z_]\w*)\??:/gm)].map((m) => m[1]).sort();
}
function unionLiterals(name) {
  const line = DTS.match(new RegExp('type ' + name + ' = ([^;]+);'))[1];
  return [...line.matchAll(/'([^']+)'/g)].map((m) => m[1]);
}
function exportList(prefix) {
  return DTS.match(new RegExp('export ' + prefix + '\\{([^}]+)\\}'))[1]
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean)
    .sort();
}

QUnit.module('public API surface', (hooks) => {
  hooks.afterEach(cleanup);

  const EXPECTED_EXPORTS = ['DOMFortify', 'default', 'init', 'status'];
  const EXPECTED_METHODS = ['init', 'status'];
  const EXPECTED_STATUS_FIELDS = [
    'defaultPolicyOwned',
    'enforcementActive',
    'excluded',
    'metaInjected',
    'protected',
    'reason',
    'sanitizerReady',
    'ttSupported',
    'version',
  ];
  const EXPECTED_CONFIG_KEYS = [
    'ALLOW_SCRIPT',
    'ALLOW_SCRIPT_URL',
    'EXCLUDE',
    'INCLUDE',
    'INJECT_META',
    'META_DIRECTIVE',
    'ON_VIOLATION',
    'SANITIZER',
    'SANITIZER_CONFIG',
    'URL_CONFIG',
  ];
  const EXPECTED_URLCONFIG_KEYS = ['ALLOW_SCRIPT', 'ALLOW_SCRIPT_URL', 'SANITIZER', 'SANITIZER_CONFIG', 'match'];
  const EXPECTED_VIOLATION_CODES = [
    'tt-unsupported',
    'sanitizer-smoketest-failed',
    'sanitizer-unavailable',
    'sanitize-threw',
    'script-hook-threw',
    'script-sink-allowed',
    'script-sink-refused',
    'preexisting-default-policy',
    'default-policy-lost',
    'default-policy-not-active',
    'enforcement-inactive',
    'excluded-by-url',
    'outside-include-scope',
    'meta-injection-attempted',
    'failing-closed',
  ];
  const EXPECTED_VALUE_EXPORTS = ['DOMFortify', 'DOMFortify as default', 'init', 'status'];
  const EXPECTED_TYPE_EXPORTS = [
    'DOMFortifyApi',
    'DOMFortifyConfig',
    'DOMFortifyStatus',
    'SanitizeFn',
    'Sanitizer',
    'ScriptHook',
    'ViolationCode',
  ];
  const hint = (what) =>
    `public API changed: if intentional, update the ${what} baseline in this test (it is a 1.0 contract change)`;

  QUnit.test('runtime exports and DOMFortify methods are exactly the public set', async (assert) => {
    const { mod } = await install({ tt: makeTT(), doc: makeDoc(), DOMPurify: { sanitize: (s) => String(s) } }, {});
    assert.deepEqual(Object.keys(mod).sort(), EXPECTED_EXPORTS, hint('module exports'));
    assert.deepEqual(Object.keys(mod.DOMFortify).sort(), EXPECTED_METHODS, hint('DOMFortify methods'));
  });

  QUnit.test('status() shape is exactly the documented set, and the runtime matches the .d.ts', async (assert) => {
    const { status } = await install({ tt: makeTT(), doc: makeDoc(), DOMPurify: { sanitize: (s) => String(s) } }, {});
    assert.deepEqual(Object.keys(status).sort(), EXPECTED_STATUS_FIELDS, hint('status fields'));
    assert.deepEqual(interfaceKeys('DOMFortifyStatus'), EXPECTED_STATUS_FIELDS, hint('DOMFortifyStatus type'));
  });

  QUnit.test('config keys are exactly the public set', (assert) => {
    assert.deepEqual(interfaceKeys('DOMFortifyConfig'), EXPECTED_CONFIG_KEYS, hint('DOMFortifyConfig keys'));
    assert.deepEqual(interfaceKeys('UrlConfigRule'), EXPECTED_URLCONFIG_KEYS, hint('UrlConfigRule keys'));
  });

  QUnit.test('violation codes are exactly the public set', (assert) => {
    assert.deepEqual(unionLiterals('ViolationCode'), EXPECTED_VIOLATION_CODES, hint('ViolationCode union'));
  });

  QUnit.test('the published export lists are exactly the public set', (assert) => {
    assert.deepEqual(exportList(''), EXPECTED_VALUE_EXPORTS, hint('value exports'));
    assert.deepEqual(exportList('type '), EXPECTED_TYPE_EXPORTS, hint('type exports'));
  });
});
