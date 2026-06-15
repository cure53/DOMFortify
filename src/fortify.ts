/**
 * DOMFortify - bolt Trusted Types onto a legacy page so old DOM-XSS sinks get sanitized
 * without touching the code. See README for the full picture; the short version:
 *
 *  - Claims the realm's `default` Trusted Types policy and routes every HTML sink through a
 *    sanitizer. Script sinks (eval, javascript: URLs, script.src) are refused.
 *  - Does NOT switch enforcement on; a CSP does (header best, `<meta>` works).
 *  - Must load FIRST: the default policy is winner-takes-all.
 *  - Fails closed: no sanitizer means sinks throw, never leak.
 *  - Only covers Trusted Types sinks; inline handlers / style / URL props stay open.
 */
import type {
  DOMFortifyApi,
  DOMFortifyConfig,
  DOMFortifyStatus,
  Sanitizer,
  SanitizeFn,
  ScriptHook,
  ViolationCode,
} from './types';

const VERSION = '__VERSION__';

interface TtFactory {
  createPolicy(name: string, rules: unknown): unknown;
  defaultPolicy?: unknown;
}

// Grab natives up front so later prototype-pollution or clobbering can't swap them out.
const hasOwn = Object.prototype.hasOwnProperty;
const root: typeof globalThis =
  typeof globalThis !== 'undefined' ? globalThis : (window as unknown as typeof globalThis);
const doc: Document | undefined = typeof document !== 'undefined' ? document : undefined;

const own = (obj: unknown, key: string): boolean => obj != null && hasOwn.call(obj, key);
const cfg = (obj: unknown, key: string): unknown => (own(obj, key) ? (obj as Record<string, unknown>)[key] : undefined);
const clip = (s: unknown): string => String(s).slice(0, 80);
const emsg = (e: unknown): string => String((e as { message?: unknown } | undefined)?.message);

const TT = (root as unknown as { trustedTypes?: TtFactory }).trustedTypes;

let installed = false;
let cachedStatus: Readonly<DOMFortifyStatus> | null = null;

// Are we actually enforced? Under enforcement with no default policy yet, a sink write throws.
// Run this BEFORE we install our policy, or it would always read as "off".
function enforcementActive(): boolean {
  try {
    (doc as Document).createElement('div').innerHTML = 'x';
    return false;
  } catch {
    return true;
  }
}

// Copy config off the caller's object, skipping keys that could pollute. Don't JSON-clone - that
// would corrupt RegExp and functions.
function shallowCopy(obj: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const k in obj) {
    if (hasOwn.call(obj, k) && k !== '__proto__' && k !== 'constructor' && k !== 'prototype') out[k] = obj[k];
  }
  return out;
}

export function init(options: DOMFortifyConfig = {}): Readonly<DOMFortifyStatus> {
  if (installed) return cachedStatus as Readonly<DOMFortifyStatus>;
  installed = true;

  const onv = cfg(options, 'ON_VIOLATION');
  const report = (typeof onv === 'function' ? onv : () => {}) as (code: ViolationCode, detail?: unknown) => void;

  const status: DOMFortifyStatus = {
    version: VERSION,
    ttSupported: !!TT,
    enforcementActive: false,
    defaultPolicyOwned: false,
    sanitizerReady: false,
    protected: false,
    reason: '',
  };
  const done = (reason: string, code?: ViolationCode): Readonly<DOMFortifyStatus> => {
    status.protected = status.defaultPolicyOwned && status.enforcementActive && status.sanitizerReady;
    status.reason = reason;
    if (code) report(code, status);
    cachedStatus = Object.freeze({ ...status });
    return cachedStatus;
  };

  if (!TT || typeof TT.createPolicy !== 'function') {
    return done('Trusted Types not supported; library is inert. Sinks are NOT routed.', 'tt-unsupported');
  }

  status.enforcementActive = enforcementActive();

  // Resolve config once, reading own keys only so a polluted prototype can't supply a value - and,
  // most importantly, can't loosen a refusal. Nothing is re-read later, so runtime clobbering can't
  // retarget the policy either.
  let rawSan: unknown = cfg(options, 'SANITIZER');
  if (rawSan === undefined) rawSan = (root as unknown as { DOMPurify?: unknown }).DOMPurify;
  // DOMPurify's export is itself a callable function (the factory) that also exposes `.sanitize`, so
  // check for a `.sanitize` method FIRST - otherwise we'd wrap the factory and call the wrong thing. A
  // bare function (e.g. a Sanitizer-API adapter) has no `.sanitize` and falls through to the function case.
  const DP: Sanitizer | null =
    rawSan && typeof (rawSan as Sanitizer).sanitize === 'function'
      ? (rawSan as Sanitizer)
      : typeof rawSan === 'function'
        ? { sanitize: rawSan as SanitizeFn }
        : null;
  const sanitizeConfig = own(options, 'SANITIZER_CONFIG')
    ? shallowCopy((options as { SANITIZER_CONFIG: Record<string, unknown> }).SANITIZER_CONFIG)
    : undefined;

  // Sink openers count only if they're own functions, so prototype pollution can never open a sink.
  const asCand = cfg(options, 'ALLOW_SCRIPT');
  const asuCand = cfg(options, 'ALLOW_SCRIPT_URL');
  const allowScript = typeof asCand === 'function' ? (asCand as ScriptHook) : null;
  const allowScriptURL = typeof asuCand === 'function' ? (asuCand as ScriptHook) : null;

  // Smoke-test once so a broken sanitizer fails loudly here, not silently on the first real write. It
  // must return a string - a sanitizer that returns anything else would otherwise inject junk.
  let sanitizerReady = false;
  if (DP && typeof DP.sanitize === 'function') {
    try {
      sanitizerReady = typeof DP.sanitize('<b>x</b>', sanitizeConfig) === 'string';
      if (!sanitizerReady) report('sanitizer-smoketest-failed', { error: 'sanitize() did not return a string' });
    } catch (e) {
      report('sanitizer-smoketest-failed', { error: emsg(e) });
    }
  }
  status.sanitizerReady = sanitizerReady;

  // `reentry` is true only while the sanitizer parses our input internally - inert and synchronous - so
  // handing the raw string straight back is safe, and keeps us alive if its own sink re-enters us.
  let reentry = false;
  const sanitizeHTML = (s: string): string | null => {
    if (!sanitizerReady) {
      report('sanitizer-unavailable', { sink: 'createHTML' });
      return null; // fail closed
    }
    if (reentry) return s;
    try {
      reentry = true;
      return (DP as Sanitizer).sanitize(s, sanitizeConfig) as string;
    } catch (e) {
      report('sanitize-threw', { error: emsg(e) });
      return null; // fail closed - never hand back raw markup on error
    } finally {
      reentry = false;
    }
  };

  // Code has no safe subset, so refuse by default. A caller hook may allow specific values; if it throws
  // or returns a non-string, we refuse.
  const scriptHook =
    (kind: 'createScript' | 'createScriptURL', fn: ScriptHook | null) =>
    (s: string): string | null => {
      if (fn) {
        let r: unknown;
        try {
          r = fn(s);
        } catch (e) {
          report('script-hook-threw', { sink: kind, error: emsg(e) });
          return null; // fail closed
        }
        if (typeof r === 'string') {
          report('script-sink-allowed', { sink: kind });
          return r;
        }
      }
      report('script-sink-refused', { sink: kind, sample: clip(s) });
      return null;
    };

  const policyDef = {
    createHTML: sanitizeHTML,
    createScript: scriptHook('createScript', allowScript),
    createScriptURL: scriptHook('createScriptURL', allowScriptURL),
  };

  // Did someone grab the default slot first? We can't evict them and won't vouch for them.
  if (TT.defaultPolicy) {
    return done(
      'A default Trusted Types policy already exists; DOMFortify did NOT install and cannot vouch for it. ' +
        'Load DOMFortify first, inline in <head>.',
      'preexisting-default-policy',
    );
  }

  let ours: unknown;
  try {
    ours = TT.createPolicy('default', policyDef);
  } catch (e) {
    // Throws when a default policy exists and 'allow-duplicates' is off - someone won the race.
    return done(
      `createPolicy("default") threw (${emsg(e)}); another default policy won the race.`,
      'default-policy-lost',
    );
  }

  // With 'allow-duplicates' the create can succeed yet not be the active default.
  if (TT.defaultPolicy && TT.defaultPolicy !== ours) {
    return done(
      'Our policy was created but is not the active default (allow-duplicates race lost). ' +
        'Remove "allow-duplicates" from the trusted-types directive.',
      'default-policy-not-active',
    );
  }

  status.defaultPolicyOwned = true;

  if (!status.enforcementActive) {
    return done(
      'Default policy installed and slot locked, but TT enforcement is NOT active - sinks are not routed. ' +
        'Deliver require-trusted-types-for (header preferred).',
      'enforcement-inactive',
    );
  }
  if (!sanitizerReady) {
    return done(
      'Enforcement active and slot locked, but the sanitizer is unavailable - HTML sinks will THROW ' +
        '(failing closed). Bundle DOMPurify and load it before DOMFortify.',
      'failing-closed',
    );
  }
  return done(
    `Active: HTML sinks sanitized, script sinks ${allowScript || allowScriptURL ? 'partly allowed by hooks' : 'refused'}.`,
  );
}

export function status(): Readonly<DOMFortifyStatus> | null {
  return cachedStatus;
}

export const DOMFortify: DOMFortifyApi = Object.freeze({ init, status });
export default DOMFortify;
