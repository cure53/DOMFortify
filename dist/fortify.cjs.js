/*! DOMFortify 0.1.0 | (c) Cure53 and contributors | (MPL-2.0 OR Apache-2.0) */
'use strict';

Object.defineProperty(exports, '__esModule', { value: true });

const VERSION = '0.1.0';
// Grab natives up front so later prototype-pollution or clobbering can't swap them out.
const hasOwn = Object.prototype.hasOwnProperty;
const root = typeof globalThis !== 'undefined' ? globalThis : window;
const doc = typeof document !== 'undefined' ? document : undefined;
const loc = root.location;
const own = (obj, key) => obj != null && hasOwn.call(obj, key);
const cfg = (obj, key) => (own(obj, key) ? obj[key] : undefined);
const clip = (s) => String(s).slice(0, 80);
const emsg = (e) => String(e?.message);
const TT = root.trustedTypes;
let installed = false;
let cachedStatus = null;
// Are we actually enforced? Under enforcement with no default policy yet, a sink write throws.
// Run this BEFORE we install our policy, or it would always read as "off".
function enforcementActive() {
    try {
        doc.createElement('div').innerHTML = 'x';
        return false;
    }
    catch {
        return true;
    }
}
// Copy config off the caller's object, skipping keys that could pollute. Don't JSON-clone - that
// would corrupt RegExp and functions.
function shallowCopy(obj) {
    const out = {};
    for (const k in obj) {
        if (hasOwn.call(obj, k) && k !== '__proto__' && k !== 'constructor' && k !== 'prototype')
            out[k] = obj[k];
    }
    return out;
}
// Test a URL against one or more patterns. String = substring match; RegExp = test. Used for both
// EXCLUDE and URL_CONFIG, always against the realm's own location.href.
function urlMatches(pattern, url) {
    if (pattern == null)
        return false;
    const list = Array.isArray(pattern) ? pattern : [pattern];
    for (let i = 0; i < list.length; i++) {
        const p = list[i];
        if (typeof p === 'string') {
            if (p !== '' && url.indexOf(p) !== -1)
                return true;
        }
        else if (p instanceof RegExp) {
            try {
                if (p.test(url))
                    return true;
            }
            catch {
                /* ignore a pattern that throws */
            }
        }
    }
    return false;
}
// Best-effort CSP <meta> injection (opt-in). IMPORTANT: a <meta> CSP is honored only when the PARSER
// inserts it, so document.write during the initial parse is the only path that can actually switch
// enforcement on - and only for content parsed afterwards. A node appended after parsing is ignored by
// the CSP engine; we still add it (harmless) but report that injection did NOT take. Returns true only
// when written during parse.
function injectMeta(content) {
    if (!doc)
        return false;
    const d = doc;
    const tag = '<meta http-equiv="Content-Security-Policy" content="' + content + '">';
    if (d.readyState === 'loading' && typeof d.write === 'function') {
        try {
            d.write(tag);
            return true;
        }
        catch {
            /* fall through to the append fallback */
        }
    }
    try {
        const m = d.createElement('meta');
        m.setAttribute('http-equiv', 'Content-Security-Policy');
        m.setAttribute('content', content);
        (d.head || d.documentElement).appendChild(m);
    }
    catch {
        /* ignore */
    }
    return false;
}
function init(options = {}) {
    if (installed)
        return cachedStatus;
    installed = true;
    const onv = cfg(options, 'ON_VIOLATION');
    const report = (typeof onv === 'function' ? onv : () => { });
    const status = {
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
    const done = (reason, code) => {
        status.protected = status.defaultPolicyOwned && status.enforcementActive && status.sanitizerReady;
        status.reason = reason;
        if (code)
            report(code, status);
        cachedStatus = Object.freeze({ ...status });
        return cachedStatus;
    };
    const url = loc && typeof loc.href !== 'undefined' ? String(loc.href) : '';
    // EXCLUDE: on a matching URL, DOMFortify stays completely out of the way - no policy, no meta. It
    // does NOT install a passthrough (that would be a silent XSS hole); under globally delivered
    // enforcement, excluded pages are the developer's responsibility. Reported via status.excluded.
    if (urlMatches(cfg(options, 'EXCLUDE'), url)) {
        status.excluded = true;
        return done('URL matched EXCLUDE; DOMFortify is intentionally inactive on this page.', 'excluded-by-url');
    }
    if (!TT || typeof TT.createPolicy !== 'function') {
        return done('Trusted Types not supported; library is inert. Sinks are NOT routed.', 'tt-unsupported');
    }
    // URL_CONFIG: the first rule whose `match` hits supplies per-URL overrides. `eff(key)` reads that
    // rule's own key when present, else falls back to the base config - both own-key only, so a polluted
    // prototype can neither inject a rule nor loosen a refusal.
    let override = null;
    const rules = cfg(options, 'URL_CONFIG');
    if (Array.isArray(rules)) {
        for (let i = 0; i < rules.length; i++) {
            const r = rules[i];
            if (r && urlMatches(r.match, url)) {
                override = r;
                break;
            }
        }
    }
    const eff = (key) => (override && own(override, key) ? override[key] : cfg(options, key));
    // INJECT_META (opt-in, best-effort - see injectMeta and the README). We only attempt it when TT is
    // supported; the directive lists the policies that will exist: our own `default`, plus `dompurify`
    // unless a bare-function sanitizer (e.g. the native Sanitizer API) is in use. META_DIRECTIVE overrides.
    if (cfg(options, 'INJECT_META') === true) {
        const md = cfg(options, 'META_DIRECTIVE');
        const ttNames = typeof eff('SANITIZER') === 'function' ? 'default' : 'default dompurify';
        const directive = typeof md === 'string' && md ? md : `require-trusted-types-for 'script'; trusted-types ${ttNames};`;
        status.metaInjected = injectMeta(directive);
        report('meta-injection-attempted', { directive, written: status.metaInjected });
    }
    status.enforcementActive = enforcementActive();
    // Resolve config once, reading own keys only so a polluted prototype can't supply a value - and,
    // most importantly, can't loosen a refusal. Nothing is re-read later, so runtime clobbering can't
    // retarget the policy either. URL_CONFIG overrides are applied here via `eff`.
    let rawSan = eff('SANITIZER');
    if (rawSan === undefined)
        rawSan = root.DOMPurify;
    // DOMPurify's export is itself a callable function (the factory) that also exposes `.sanitize`, so
    // check for a `.sanitize` method FIRST - otherwise we'd wrap the factory and call the wrong thing. A
    // bare function (e.g. a Sanitizer-API adapter) has no `.sanitize` and falls through to the function case.
    const DP = rawSan && typeof rawSan.sanitize === 'function'
        ? rawSan
        : typeof rawSan === 'function'
            ? { sanitize: rawSan }
            : null;
    const rawCfg = eff('SANITIZER_CONFIG');
    const sanitizeConfig = rawCfg && typeof rawCfg === 'object' ? shallowCopy(rawCfg) : undefined;
    // Sink openers count only if they're own functions, so prototype pollution can never open a sink.
    const asCand = eff('ALLOW_SCRIPT');
    const asuCand = eff('ALLOW_SCRIPT_URL');
    const allowScript = typeof asCand === 'function' ? asCand : null;
    const allowScriptURL = typeof asuCand === 'function' ? asuCand : null;
    // Smoke-test once so a broken sanitizer fails loudly here, not silently on the first real write. It
    // must return a string - a sanitizer that returns anything else would otherwise inject junk.
    let sanitizerReady = false;
    if (DP && typeof DP.sanitize === 'function') {
        try {
            sanitizerReady = typeof DP.sanitize('<b>x</b>', sanitizeConfig) === 'string';
            if (!sanitizerReady)
                report('sanitizer-smoketest-failed', { error: 'sanitize() did not return a string' });
        }
        catch (e) {
            report('sanitizer-smoketest-failed', { error: emsg(e) });
        }
    }
    status.sanitizerReady = sanitizerReady;
    // `reentry` is true only while the sanitizer parses our input internally - inert and synchronous - so
    // handing the raw string straight back is safe, and keeps us alive if its own sink re-enters us.
    let reentry = false;
    const sanitizeHTML = (s) => {
        if (!sanitizerReady) {
            report('sanitizer-unavailable', { sink: 'createHTML' });
            return null; // fail closed
        }
        if (reentry)
            return s;
        try {
            reentry = true;
            return DP.sanitize(s, sanitizeConfig);
        }
        catch (e) {
            report('sanitize-threw', { error: emsg(e) });
            return null; // fail closed - never hand back raw markup on error
        }
        finally {
            reentry = false;
        }
    };
    // Code has no safe subset, so refuse by default. A caller hook may allow specific values; if it throws
    // or returns a non-string, we refuse.
    const scriptHook = (kind, fn) => (s) => {
        if (fn) {
            let r;
            try {
                r = fn(s);
            }
            catch (e) {
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
        return done('A default Trusted Types policy already exists; DOMFortify did NOT install and cannot vouch for it. ' +
            'Load DOMFortify first, inline in <head>.', 'preexisting-default-policy');
    }
    let ours;
    try {
        ours = TT.createPolicy('default', policyDef);
    }
    catch (e) {
        // Throws when a default policy exists and 'allow-duplicates' is off - someone won the race.
        return done(`createPolicy("default") threw (${emsg(e)}); another default policy won the race.`, 'default-policy-lost');
    }
    // With 'allow-duplicates' the create can succeed yet not be the active default.
    if (TT.defaultPolicy && TT.defaultPolicy !== ours) {
        return done('Our policy was created but is not the active default (allow-duplicates race lost). ' +
            'Remove "allow-duplicates" from the trusted-types directive.', 'default-policy-not-active');
    }
    status.defaultPolicyOwned = true;
    if (!status.enforcementActive) {
        return done('Default policy installed and slot locked, but TT enforcement is NOT active - sinks are not routed. ' +
            'Deliver require-trusted-types-for (header preferred).', 'enforcement-inactive');
    }
    if (!sanitizerReady) {
        return done('Enforcement active and slot locked, but the sanitizer is unavailable - HTML sinks will THROW ' +
            '(failing closed). Bundle DOMPurify and load it before DOMFortify.', 'failing-closed');
    }
    return done(`Active: HTML sinks sanitized, script sinks ${allowScript || allowScriptURL ? 'partly allowed by hooks' : 'refused'}.`);
}
function status() {
    return cachedStatus;
}
const DOMFortify = Object.freeze({ init, status });

exports.DOMFortify = DOMFortify;
exports.default = DOMFortify;
exports.init = init;
exports.status = status;
//# sourceMappingURL=fortify.cjs.js.map
