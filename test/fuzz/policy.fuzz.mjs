/**
 * Property-based fuzzing of DOMFortify's Trusted Types policy callbacks (fast-check).
 *
 * We do not fuzz the sanitizer itself - that's DOMPurify's job. We fuzz the contract DOMFortify is
 * responsible for: that the default policy is a total function over arbitrary input and upholds its
 * guarantees no matter what string is thrown at it.
 */
import fc from 'fast-check';

globalThis.trustedTypes = {
  _rules: null,
  get defaultPolicy() {
    return this._rules ? { name: 'default' } : null;
  },
  createPolicy(_name, rules) {
    this._rules = rules;
    return rules;
  },
};
globalThis.document = {
  createElement() {
    return {
      set innerHTML(_v) {
        throw new TypeError('enforced realm requires TrustedHTML');
      },
      get innerHTML() {
        return '';
      },
    };
  },
};

const sanitize = (s) =>
  String(s)
    .replace(/<script[\s\S]*?<\/script>/gi, '')
    .replace(/\son\w+=("[^"]*"|'[^']*'|[^\s>]+)/gi, '');
globalThis.DOMPurify = { sanitize };

const { init } = await import('../../dist/fortify.es.mjs');
const status = init({});
if (!status.sanitizerReady) {
  console.error('fuzz setup failed: sanitizer not ready');
  process.exit(1);
}
const rules = globalThis.trustedTypes._rules;
const runs = 2000;

// 1. createHTML is total and returns exactly the sanitizer's string output.
fc.assert(
  fc.property(fc.string(), (s) => {
    const out = rules.createHTML(s);
    return typeof out === 'string' && out === sanitize(s);
  }),
  { numRuns: runs },
);

// 2. Script sinks refuse everything when no allow-hook is configured.
fc.assert(
  fc.property(fc.string(), (s) => rules.createScript(s) === null && rules.createScriptURL(s) === null),
  { numRuns: runs },
);

console.log(`fuzz: all properties held over ${runs} runs each`);
