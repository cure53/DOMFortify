## What is this?

This is a collection of small, standalone demos showing how to use DOMFortify. Each page is the whole
thing: a CSP `<meta>` that turns Trusted Types on, the sanitizer, and `fortify.js`. The deliberately
vulnerable code on each page is never changed - the browser routes it through the sanitizer because
DOMFortify owns the realm's `default` policy.

Open them from a served copy (GitHub Pages, `node test/serve.mjs`, or any static server) rather than
`file://`, since Trusted Types enforcement needs a real origin. They load `fortify.js` straight from
the jsDelivr CDN at `@main`, so there's nothing to build - each page always runs the latest published
library.

Suggestions for more demos are welcome. Here's what we have so far.

### Basic usage [Link](basic-demo.html)

The simplest case: no config, no hooks. Just the CSP and `fortify.js`. The app does the unsafe thing
and the browser cleans it up.

```js
// The vulnerable line, untouched. DOMFortify makes the browser sanitize it.
out.innerHTML = dirty;
```

### Sanitizer config [Link](config-demo.html)

Forward a configuration object to the sanitizer (here DOMPurify) so every sink on the page is cleaned
with it. This example keeps only a handful of formatting tags.

```js
window.DOMFortifyConfig = {
  SANITIZER_CONFIG: { ALLOWED_TAGS: ['b', 'i', 'em', 'strong', 'p', '#text'] },
};
```

### Report-only monitoring [Link](report-only-demo.html)

Wire `ON_VIOLATION` to a logger or your telemetry to watch what the policy decides - refusals, allowed
sinks, a missing sanitizer - as a safe on-ramp before you rely on enforcement.

```js
window.DOMFortifyConfig = {
  ON_VIOLATION: (code, detail) => report(code, detail),
};
```

### Native Sanitizer API [Link](native-sanitizer-demo.html)

No DOMPurify. `SANITIZER` accepts a bare `(string) => string` function, so you can drive the browser's
built-in `Element.setHTML()` instead. Drop `dompurify` from the directive (`trusted-types default;`).

```js
window.DOMFortifyConfig = {
  SANITIZER: (s) => {
    const d = document.createElement('div');
    d.setHTML(s);
    return d.innerHTML;
  },
};
```

### Allow one script URL [Link](allow-script-url-demo.html)

Script sinks are refused by default. An `ALLOW_SCRIPT_URL` hook can permit specific, vetted URLs and
refuse everything else. (There is a matching `ALLOW_SCRIPT` for `eval`-style sinks.)

```js
window.DOMFortifyConfig = {
  ALLOW_SCRIPT_URL: (url) => (url.startsWith('https://cdn.jsdelivr.net/') ? url : null),
};
```

### Status / self-report [Link](status-demo.html)

`DOMFortify.status()` reports, honestly, whether the page is actually protected and why. `protected`
is true only when enforcement is on, DOMFortify owns the default policy, and the sanitizer works.

```js
const s = DOMFortify.status();
// { version, ttSupported, enforcementActive, defaultPolicyOwned, sanitizerReady,
//   excluded, metaInjected, protected, reason }
```

### Fails closed [Link](fail-closed-demo.html)

Enforcement is on but the sanitizer is missing. DOMFortify will not hand back unsanitized markup, so
the sink throws rather than leak. Breaking loudly beats failing open.

### Scoping by URL [Link](url-config-demo.html)

`EXCLUDE` and `URL_CONFIG` match against `location.href` (string = substring, RegExp = test, arrays
allowed). Exclude a route entirely, or apply a different sanitizer config per route - first match
wins. This page keys off the query string, so add `?strict` or `?off` and reload.

```js
window.DOMFortifyConfig = {
  EXCLUDE: [/[?&]off\b/], // DOMFortify stands down completely on a match
  SANITIZER_CONFIG: { ALLOWED_TAGS: ['b', 'i', 'p', 'a', 'img', '#text'] }, // baseline
  URL_CONFIG: [{ match: /[?&]strict\b/, SANITIZER_CONFIG: { ALLOWED_TAGS: ['b', '#text'] } }],
};
```

### Scoping with INCLUDE [Link](include-demo.html)

The allow-list complement of `EXCLUDE`: activate ONLY on matching URLs and stay inactive elsewhere.
Paired with `INJECT_META` so enforcement is scoped to the same pages, this is the gradual-rollout
pattern - protect a few routes first, leave the rest untouched. Add `?admin` and reload.

```js
window.DOMFortifyConfig = {
  INCLUDE: [/[?&]admin\b/], // active only here
  INJECT_META: true, // and enforcement scoped to the same pages
};
```

### Meta injection (best-effort) [Link](meta-inject-demo.html)

`INJECT_META` is an opt-in attempt to add the enabling CSP `<meta>` for pages that can set neither a
header nor a hand-placed `<meta>`. It is best-effort: a `<meta>` CSP is honored only when the parser
inserts it. This page ships no CSP and shows, honestly, what `status()` reports in your browser.

```js
window.DOMFortifyConfig = { INJECT_META: true };
const s = DOMFortify.status(); // check s.metaInjected and s.protected to see whether it actually took
```
