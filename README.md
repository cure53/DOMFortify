# DOMFortify

[![License: MPL-2.0 OR Apache-2.0](https://img.shields.io/badge/license-MPL--2.0%20OR%20Apache--2.0-blue.svg)](LICENSE)
[![Build & Test](https://github.com/cure53/DOMFortify/actions/workflows/build-and-test.yml/badge.svg)](https://github.com/cure53/DOMFortify/actions/workflows/build-and-test.yml)
[![CodeQL](https://github.com/cure53/DOMFortify/actions/workflows/codeql-analysis.yml/badge.svg)](https://github.com/cure53/DOMFortify/actions/workflows/codeql-analysis.yml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/cure53/DOMFortify/badge)](https://scorecard.dev/viewer/?uri=github.com/cure53/DOMFortify)

DOMFortify turns on Trusted Types for a page and quietly takes over the browser's `default` policy,
so that old, vulnerable code like `el.innerHTML = location.hash` gets sanitized before it ever hits
the DOM. You don't touch the code. You don't even need to know where the bug is.

It's for the sites you can't easily fix: complex apps or legacy apps nobody wants to touch, the third-party widget you
can't patch, the 2000+ `innerHTML` sinks written before anyone had heard of XSS.

**Just ship the policy, and the browser automatically protects every HTML sink with DOMPurify or other sanitizers.**

## Is there a demo?

Of course there is. [Play with DOMFortify](https://cure53.de/fortify) - throw payloads at a
deliberately broken page and watch the browser neutralize them before they reach the DOM.

## How it works

Trusted Types lets a page register one `default` policy that the browser calls for every dangerous
sink. DOMFortify is that policy.

HTML goes through [DOMPurify](https://github.com/cure53/DOMPurify)
(or any sanitizer you hand it); script sinks like `eval` and `script.src` are refused outright,
because there is no safe way to sanitize executable code.

## Usage

Two parts. First, turn enforcement on with a CSP - a response header if you can set one:

```
Content-Security-Policy: require-trusted-types-for 'script'; trusted-types default dompurify;
```

...or via `<meta>` tag if you cannot set any headers:

```html
<meta
  http-equiv="Content-Security-Policy"
  content="require-trusted-types-for 'script'; trusted-types default dompurify"
/>
```

Second, load the sanitizer and then DOMFortify, **first thing in `<head>`**, before anything an
attacker could reach. Pin both with SRI so a bad CDN day fails closed instead of open:

```html
<script
  src="https://cdn.jsdelivr.net/npm/dompurify@3.4.10/dist/purify.min.js"
  integrity="sha384-eguRoJERj8ghOpzO//Rl7+ScQsQIR1cH+ajll7+fG+IpbNPlkZsQn9h8ccr+wPXx"
  crossorigin="anonymous"
></script>
<script
  src="https://cdn.jsdelivr.net/npm/domfortify@0.1.0/dist/fortify.min.js"
  integrity="sha384-K9huyIl4RBuiqJ7yfQIjf5T8Zz+BbxYMTXgfC8rNhXZNdGRtzCUb5AtDQKI5G6IE"
  crossorigin="anonymous"
></script>
```

That's it. The script installs itself on load. Want to check it actually worked?

```js
DOMFortify.status().protected; // true when enforced, owning the policy, and sanitizer ready
```

If you have to go through a bundler, import the module build and call `init()` as early as you can -
but understand that a bundler will not place your code first, which is the one thing this needs:

```js
import { init } from 'domfortify';
init();
```

## Configuration

Set `window.DOMFortifyConfig` before the script tag, or pass the same object to `DOMFortify.init()`.
Every option is optional; the defaults give you DOMPurify on every HTML sink and a hard refusal on
every script sink. Config is read once, own-properties only, so a polluted prototype can't sneak a
value in or loosen a refusal.

Each topic below has a runnable page in [`/demos`](demos/) - the links point straight at them.

### Picking a sanitizer

```js
// Default: window.DOMPurify sanitizes every HTML sink.
window.DOMFortifyConfig = { SANITIZER: window.DOMPurify };

// Any object with .sanitize(input, config) works...
window.DOMFortifyConfig = { SANITIZER: myCustomSanitizer };

// ...as does a bare (string) => string function, e.g. the native Sanitizer API.
window.DOMFortifyConfig = {
  SANITIZER: (s) => {
    const d = document.createElement('div');
    d.setHTML(s);
    return d.innerHTML;
  },
};

// SANITIZER_CONFIG is forwarded verbatim as the sanitizer's second argument (a DOMPurify config here).
window.DOMFortifyConfig = {
  SANITIZER_CONFIG: { ALLOWED_TAGS: ['b', 'i', 'a'], ALLOWED_ATTR: ['href'] },
};
```

Demos: [sanitizer config](demos/config-demo.html), [native Sanitizer API](demos/native-sanitizer-demo.html).

### Allowing script sinks

```js
// Script sinks (eval, javascript: URLs, script.src, Worker URLs) are REFUSED by default.
// A hook may allow specific, vetted values: return a string to mint it, anything else to refuse.
window.DOMFortifyConfig = {
  ALLOW_SCRIPT: (code) => null, // default: refuse every eval-like sink
  ALLOW_SCRIPT_URL: (url) => (url.startsWith('https://cdn.example/') ? url : null), // allow one origin
};
```

Demo: [allow one script URL](demos/allow-script-url-demo.html).

### Scoping by URL

```js
// EXCLUDE: URL pattern(s) where DOMFortify stays completely inactive - no policy, no meta injection.
// It does NOT install a passthrough (that would be a silent XSS hole). Matched against location.href:
// a string is a substring match, a RegExp is test()ed, and either may be given as an array.
window.DOMFortifyConfig = { EXCLUDE: ['/admin/', /\/internal\b/] };

// URL_CONFIG: per-URL overrides; the FIRST matching rule's own keys override the base config. Handy
// for a stricter (or looser) sanitizer config, sanitizer, or script hook on specific routes.
window.DOMFortifyConfig = {
  SANITIZER_CONFIG: { ALLOWED_TAGS: ['b', 'i'] }, // the baseline
  URL_CONFIG: [{ match: '/comments/', SANITIZER_CONFIG: { ALLOWED_TAGS: ['b'] } }],
};
```

Demo: [scoping by URL](demos/url-config-demo.html).

### Turning enforcement on (advanced)

DOMFortify does not enable Trusted Types - a CSP does, and a response header is the only fully
reliable way. For pages that can set neither a header nor a hand-placed `<meta>`, `INJECT_META` is an
opt-in, best-effort fallback (see [What it won't do](#what-it-wont-do) for the caveat).

```js
// Opt-in, default false. Best-effort: a <meta> CSP is honored only when the parser inserts it, so
// this can work only when DOMFortify runs during the initial parse and only for content parsed
// afterwards. Otherwise it appends a non-enforcing node and reports status().metaInjected === false.
window.DOMFortifyConfig = { INJECT_META: true };

// META_DIRECTIVE overrides the whole trusted-types directive, e.g. if your policy names differ.
window.DOMFortifyConfig = {
  INJECT_META: true,
  META_DIRECTIVE: "require-trusted-types-for 'script'; trusted-types default dompurify my-policy;",
};
```

Demo: [meta injection](demos/meta-inject-demo.html).

### Monitoring (report-only)

```js
// ON_VIOLATION fires on every notable decision: refusals, allowed sinks, a missing sanitizer, an
// excluded URL, and so on. Wire it to your telemetry as a safe on-ramp before you rely on enforcement.
window.DOMFortifyConfig = {
  ON_VIOLATION: (code, detail) => console.warn('[DOMFortify]', code, detail),
};
```

Demo: [report-only monitoring](demos/report-only-demo.html).

## What it won't do

It's a retrofit, not magic. Know the edges:

- **It needs the CSP.** No enforcement, no protection - and it'll tell you so via `status()`.
- **`INJECT_META` is best-effort.** A script-inserted `<meta>` CSP is ignored unless the parser
  inserts it during the initial parse. Don't rely on it where a header or hand-placed `<meta>` is an
  option; check `status()` to see whether enforcement actually took.
- **Load it first.** Whoever registers the `default` policy first wins. If attacker code beats you to
  it, you're worse off than before. Don't add `'allow-duplicates'`.
- **One realm at a time.** Each iframe is its own world and needs its own DOMFortify.
- **Trusted Types sinks only.** Inline handlers (`onclick=`), `style`, and `href` URLs aren't TT
  sinks. Close those with a real `script-src` that drops `'unsafe-inline'`.
- **One sanitizer.** A bypass in the sanitizer is a bypass in everything it guards.
- **It sanitizes a string, then the sink re-parses it.** The `default` policy returns sanitized HTML as a
  string that the browser parses again in context - the serialize/re-parse step that can re-open
  [mutation XSS](https://html.spec.whatwg.org/multipage/dynamic-markup-insertion.html#sanitizer-security-mxss).
  DOMFortify leans on the sanitizer's own mXSS hardening (DOMPurify's, by default) to close it; a weaker
  sanitizer reopens it. A browser-native sink-level sanitizer avoids the round trip entirely - see
  [Relationship to the platform](#relationship-to-the-platform).

## Security

Found a hole? Please report it privately - see [SECURITY.md](SECURITY.md). Don't open a public issue.

---

Built on the shoulders of Frederik Braun's
[Perfect types with setHTML()](https://frederikbraun.de/perfect-types-with-sethtml.html) and his Mozilla explainer [Trusted or Sanitized HTML](https://github.com/mozilla/explainers/blob/main/trusted-or-sanitized-html.md), plus Jun
Kokatsu's "Perfect Types". By [Cure53](https://cure53.de).

## Relationship to the platform

DOMFortify implements, in userland and available today, the model Mozilla has proposed for standardization in [Trusted or Sanitized HTML](https://github.com/mozilla/explainers/blob/main/trusted-or-sanitized-html.md) (Frederik Braun, 2026): an opt-in CSP keyword that makes the browser sanitize HTML at every sink with no code changes, and refuse script sinks it cannot vet. Where that proposal adds a browser-native `trusted-types 'sanitize-html'` keyword that sanitizes each sink in its parsing context, DOMFortify reaches the same outcome now through a `default` Trusted Types policy backed by a sanitizer. When browsers ship `'sanitize-html'`, DOMFortify becomes a thin compatibility shim or simply unnecessary - which is the goal, not a threat.

The one design difference worth stating plainly: the platform proposal sanitizes the parsed fragment directly at the sink, in context, avoiding a serialize/re-parse round trip. DOMFortify's policy returns a sanitized string that the sink re-parses, so it depends on the sanitizer's mutation-XSS hardening to stay safe (see [What it won't do](#what-it-wont-do)). With DOMPurify as the sanitizer that surface is well covered; with a weaker sanitizer it may not be.

## Prior Art

DOMFortify builds on established browser and ecosystem concepts rather than claiming to invent Trusted Types-based HTML sanitization from scratch. The underlying enforcement mechanism is the browser-native [Trusted Types API](https://developer.mozilla.org/en-US/docs/Web/API/Trusted_Types_API), and the sanitizer commonly used with DOMFortify, [DOMPurify](https://github.com/cure53/DOMPurify), already provides Trusted Types integration. Earlier tooling such as [`melloware/csp-webpack-plugin`](https://github.com/melloware/csp-webpack-plugin) and its Rspack counterpart [`rspack-contrib/csp-rspack-plugin`](https://github.com/rspack-contrib/csp-rspack-plugin) also demonstrated the idea of installing a DOMPurify-backed `default` Trusted Types policy to retrofit protection for legacy `innerHTML`-style sinks.

DOMFortify differs in its focus and packaging: it is a standalone runtime hardening layer, not a bundler-side CSP helper, and it emphasizes safer defaults for script-like sinks, sanitizer abstraction, route-aware configuration, CSP/telemetry integration, and defensive handling of configuration and prototype-pollution edge cases. Related ecosystem work includes framework- or type-system-oriented approaches such as [Angular’s Trusted Types integration](https://angular.dev/best-practices/security), Google’s [`safevalues`](https://github.com/google/safevalues), and earlier Trusted Types integrations collected by the [W3C Trusted Types project](https://github.com/w3c/trusted-types/wiki/Integrations). The browser-native direction this whole approach points toward is set out in Mozilla's [Trusted or Sanitized HTML](https://github.com/mozilla/explainers/blob/main/trusted-or-sanitized-html.md) explainer (see [Relationship to the platform](#relationship-to-the-platform)).
