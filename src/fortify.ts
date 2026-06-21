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
import { cfg, clip, emsg, own, shallowCopy, urlMatches } from './internal';
import type {
  DOMFortifyApi,
  DOMFortifyConfig,
  DOMFortifyStatus,
  Sanitizer,
  SanitizeFn,
  ScriptHook,
  UrlPattern,
  ViolationCode,
} from './types';

const VERSION = '__VERSION__';

interface TtFactory {
  createPolicy(name: string, rules: unknown): unknown;
  defaultPolicy?: unknown;
}

type Report = (code: ViolationCode, detail?: unknown) => void;

// Natives captured up front, so later prototype pollution or clobbering can't swap them out.
const root: typeof globalThis =
  typeof globalThis !== 'undefined' ? globalThis : (window as unknown as typeof globalThis);
const doc: Document | undefined = typeof document !== 'undefined' ? document : undefined;
const loc: { href?: unknown } | undefined = (root as unknown as { location?: { href?: unknown } }).location;
const TT = (root as unknown as { trustedTypes?: TtFactory }).trustedTypes;

let installed = false;
let cachedStatus: Readonly<DOMFortifyStatus> | null = null;

// --- environment probes --------------------------------------------------------------------------

// Are we actually enforced? Under enforcement with no default policy yet, a sink write throws. Must
// run BEFORE we install our policy, or it would always read as "off".
function enforcementActive(): boolean {
  try {
    (doc as Document).createElement('div').innerHTML = 'x';
    return false;
  } catch {
    return true;
  }
}

// Best-effort CSP <meta> injection (opt-in). A <meta> CSP is honored only when the PARSER inserts it,
// so document.write during the initial parse is the one path that can switch enforcement on - and only
// for content parsed afterwards. We return true only on that path. After parse we still append the node
// (harmless) but report that it did NOT take.
//
// `content` is the trusted directive built from config. META_DIRECTIVE is developer-controlled, but
// because this path reaches document.write we still strip the characters that could break out of the
// content="..." attribute. A valid directive never contains ", <, >, or newlines, so the strip is
// lossless for good input and neutralizes a hostile or malformed one. Defense in depth.
function injectMeta(content: string): boolean {
  if (!doc) return false;
  const d = doc as Document & { write?: (s: string) => void; readyState?: string };
  const safe = content.replace(/["<>\r\n]/g, '');
  const tag = '<meta http-equiv="Content-Security-Policy" content="' + safe + '">';
  if (d.readyState === 'loading' && typeof d.write === 'function') {
    try {
      d.write(tag);
      return true;
    } catch {
      /* fall through to the append fallback */
    }
  }
  try {
    const m = d.createElement('meta');
    m.setAttribute('http-equiv', 'Content-Security-Policy');
    m.setAttribute('content', content);
    (d.head || d.documentElement).appendChild(m);
  } catch {
    /* ignore */
  }
  return false;
}

// --- config resolution (all own-key only, so a polluted prototype can't loosen anything) ---------

// First URL_CONFIG rule whose `match` hits, else null. Own-key reads only, so a polluted prototype
// can neither inject a rule nor reach one.
function selectOverride(options: DOMFortifyConfig, url: string): Record<string, unknown> | null {
  const rules = cfg(options, 'URL_CONFIG');
  if (!Array.isArray(rules)) return null;
  for (let i = 0; i < rules.length; i++) {
    const r = rules[i];
    // Read `match` own-key only, so a polluted Object.prototype.match can't make a rule that lacks
    // its own match apply to every URL.
    if (r && typeof r === 'object' && urlMatches(cfg(r, 'match') as UrlPattern | UrlPattern[] | undefined, url)) {
      return r as Record<string, unknown>;
    }
  }
  return null;
}

// Does `raw` carry a `.sanitize` method of its own (or on its own class prototype), as opposed to one
// merely inherited from Object.prototype? We walk the chain but STOP before Object.prototype, so a
// polluted Object.prototype.sanitize is never mistaken for a real sanitizer. Class-based sanitizers,
// whose method lives on their own prototype below Object.prototype, still qualify. Tolerant of a
// hostile getter on the lookup path, which is treated as "not a sanitizer".
function looksLikeSanitizer(raw: unknown): boolean {
  try {
    for (let o: unknown = raw; o && o !== Object.prototype; o = Object.getPrototypeOf(o)) {
      if (own(o, 'sanitize')) return typeof (o as { sanitize?: unknown }).sanitize === 'function';
    }
  } catch {
    /* a throwing getter on the chain means we cannot trust it as a sanitizer */
  }
  return false;
}

// Normalize whatever the caller handed us into a sanitizer with a `.sanitize` method, or null.
// DOMPurify's export is itself a callable factory that ALSO carries `.sanitize`, so we must check for
// `.sanitize` FIRST - otherwise we'd wrap the factory and call the wrong thing. A bare function (e.g. a
// Sanitizer-API adapter) has no `.sanitize` and falls through to the function case.
function resolveSanitizer(raw: unknown): Sanitizer | null {
  if (raw && looksLikeSanitizer(raw)) return raw as Sanitizer;
  if (typeof raw === 'function') return { sanitize: raw as SanitizeFn };
  return null;
}

// The trusted-types directive for INJECT_META. META_DIRECTIVE wins; otherwise we list the policies
// that will exist: our own `default`, plus `dompurify` unless a bare-function sanitizer is in use.
function metaDirective(md: unknown, functionSanitizer: boolean): string {
  if (typeof md === 'string' && md) return md;
  const ttNames = functionSanitizer ? 'default' : 'default dompurify';
  return `require-trusted-types-for 'script'; trusted-types ${ttNames};`;
}

// Exercise the sanitizer once so a broken one fails loudly here, not silently on the first real write.
// It must return a string; anything else would inject junk into every sink.
function smokeTest(sanitizer: Sanitizer, config: unknown): { ready: boolean; error: string | null } {
  try {
    const out = sanitizer.sanitize('<b>x</b>', config);
    return typeof out === 'string'
      ? { ready: true, error: null }
      : { ready: false, error: 'sanitize() did not return a string' };
  } catch (e) {
    return { ready: false, error: emsg(e) };
  }
}

// --- the default policy --------------------------------------------------------------------------

// createHTML: route through the sanitizer, fail closed on any problem. `reentry` is true only while
// the sanitizer parses our input internally (inert and synchronous), so handing the raw string back
// is safe and keeps us alive if the sanitizer's own sink re-enters us.
function makeSanitizeHTML(
  sanitizer: Sanitizer | null,
  config: unknown,
  ready: boolean,
  report: Report,
): (s: string) => string | null {
  let reentry = false;
  return (s: string): string | null => {
    if (!ready) {
      report('sanitizer-unavailable', { sink: 'createHTML' });
      return null; // fail closed
    }
    if (reentry) return s;
    try {
      reentry = true;
      return (sanitizer as Sanitizer).sanitize(s, config) as string;
    } catch (e) {
      report('sanitize-threw', { error: emsg(e) });
      return null; // fail closed - never hand back raw markup on error
    } finally {
      reentry = false;
    }
  };
}

// createScript / createScriptURL: code has no safe subset, so refuse by default. A caller hook may
// allow specific values; if it throws or returns a non-string, we refuse.
function makeScriptHook(
  kind: 'createScript' | 'createScriptURL',
  fn: ScriptHook | null,
  report: Report,
): (s: string) => string | null {
  return (s: string): string | null => {
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
}

// --- public entry point --------------------------------------------------------------------------

export function init(options: DOMFortifyConfig = {}): Readonly<DOMFortifyStatus> {
  if (installed) return cachedStatus as Readonly<DOMFortifyStatus>;
  installed = true;

  // The violation reporter is observability, never control flow. Wrap it so a throwing ON_VIOLATION
  // can neither abort init() (which would leave us installed with a null status) nor turn a
  // fail-closed sink - one that should quietly return null - into a thrown exception.
  const onv = cfg(options, 'ON_VIOLATION');
  const report: Report =
    typeof onv === 'function'
      ? (code, detail) => {
          try {
            (onv as Report)(code, detail);
          } catch {
            /* a misbehaving reporter must never break the policy */
          }
        }
      : () => {};

  const status: DOMFortifyStatus = {
    version: VERSION,
    ttSupported: !!TT,
    enforcementActive: false,
    defaultPolicyOwned: false,
    sanitizerReady: false,
    excluded: false,
    metaInjected: false,
    protected: false,
    reason: '',
  };
  const done = (reason: string, code?: ViolationCode): Readonly<DOMFortifyStatus> => {
    status.protected = status.defaultPolicyOwned && status.enforcementActive && status.sanitizerReady;
    status.reason = reason;
    // Freeze the snapshot first, then report it: the reporter sees exactly the authoritative status
    // that gets cached and returned, and has no window to mutate the cached copy.
    cachedStatus = Object.freeze({ ...status });
    if (code) report(code, cachedStatus);
    return cachedStatus;
  };

  try {
    const url = loc && typeof loc.href !== 'undefined' ? String(loc.href) : '';

    // EXCLUDE: on a match, stay completely out of the way - no policy, no meta. We do NOT install a
    // passthrough (that would be a silent XSS hole); under globally delivered enforcement, excluded
    // pages are the developer's responsibility. Reported via status.excluded.
    if (urlMatches(cfg(options, 'EXCLUDE') as UrlPattern | UrlPattern[] | undefined, url)) {
      status.excluded = true;
      return done('URL matched EXCLUDE; DOMFortify is intentionally inactive on this page.', 'excluded-by-url');
    }

    if (!TT || typeof TT.createPolicy !== 'function') {
      return done('Trusted Types not supported; library is inert. Sinks are NOT routed.', 'tt-unsupported');
    }

    // Resolve config once. `eff(key)` reads the matching URL_CONFIG rule's own key when present, else the
    // base config - both own-key only. Nothing is re-read later, so runtime clobbering can't retarget
    // the policy after this point either.
    const override = selectOverride(options, url);
    const eff = (key: string): unknown => (override && own(override, key) ? override[key] : cfg(options, key));

    // INJECT_META (opt-in, best-effort - see injectMeta and the README).
    if (cfg(options, 'INJECT_META') === true) {
      const directive = metaDirective(cfg(options, 'META_DIRECTIVE'), typeof eff('SANITIZER') === 'function');
      status.metaInjected = injectMeta(directive);
      report('meta-injection-attempted', { directive, written: status.metaInjected });
    }

    status.enforcementActive = enforcementActive();

    // Sanitizer: explicit SANITIZER (possibly per-URL), else window.DOMPurify. Config is forwarded
    // verbatim as the second argument, copied to drop pollution-prone keys.
    let rawSan: unknown = eff('SANITIZER');
    if (rawSan === undefined) rawSan = (root as unknown as { DOMPurify?: unknown }).DOMPurify;
    const sanitizer = resolveSanitizer(rawSan);
    const rawCfg = eff('SANITIZER_CONFIG');
    const sanitizeConfig =
      rawCfg && typeof rawCfg === 'object' ? shallowCopy(rawCfg as Record<string, unknown>) : undefined;

    // Sink openers count only if they're own functions, so prototype pollution can never open a sink.
    const asCand = eff('ALLOW_SCRIPT');
    const asuCand = eff('ALLOW_SCRIPT_URL');
    const allowScript = typeof asCand === 'function' ? (asCand as ScriptHook) : null;
    const allowScriptURL = typeof asuCand === 'function' ? (asuCand as ScriptHook) : null;

    let sanitizerReady = false;
    if (sanitizer) {
      const result = smokeTest(sanitizer, sanitizeConfig);
      sanitizerReady = result.ready;
      if (!result.ready) report('sanitizer-smoketest-failed', { error: result.error });
    }
    status.sanitizerReady = sanitizerReady;

    // createHTML closes over sanitizeConfig; the script hooks refuse unless an own-function hook allows.
    const policyDef = {
      createHTML: makeSanitizeHTML(sanitizer, sanitizeConfig, sanitizerReady, report),
      createScript: makeScriptHook('createScript', allowScript, report),
      createScriptURL: makeScriptHook('createScriptURL', allowScriptURL, report),
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
  } catch (e) {
    // Defense in depth: init() must never throw or leave the library bricked with a null status. A
    // hostile getter or exotic environment that slips past the guards above fails closed here, with a
    // real status object still cached and returned.
    return done(`init() hit an unexpected error (${emsg(e)}); failing closed.`, 'failing-closed');
  }
}

export function status(): Readonly<DOMFortifyStatus> | null {
  return cachedStatus;
}

export const DOMFortify: DOMFortifyApi = Object.freeze({ init, status });
export default DOMFortify;
