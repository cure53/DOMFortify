# DOMFortify

Retrofit [Trusted Types](https://w3c.github.io/trusted-types/dist/spec/) onto a legacy page so old
DOM-XSS sinks get sanitized **without touching the code**.

DOMFortify claims the realm's `default` Trusted Types policy. From then on the browser routes every
HTML sink (`innerHTML`, `outerHTML`, `insertAdjacentHTML`, `document.write`) through a sanitizer, and
refuses the script sinks (`eval`, `javascript:` URLs, `script.src`) outright. The deliberately
vulnerable line `el.innerHTML = userInput` keeps working - it just can't inject anymore.

> **Not secure. Just less broken.** This is a retrofit for code you cannot fix, not a substitute for
> fixing it.

## How it works

A CSP turns enforcement on; DOMFortify provides the policy the browser then calls for every sink:

```
CSP  ->  Trusted Types enforcement  ->  default policy (DOMFortify)  ->  sanitizer (DOMPurify)
```

There is no safe subset of executable code, so script sinks are refused rather than sanitized.

## Install

It's two parts. The package is only half - the CSP has to arrive out of band.

### 1. Turn enforcement on with a CSP

A response **header** is the production form:

```
Content-Security-Policy: require-trusted-types-for 'script'; trusted-types default dompurify;
```

If you cannot set headers, a `<meta>` is the equivalent (it can be neutralized by markup injected
above it, so a header is sturdier):

```html
<meta
  http-equiv="Content-Security-Policy"
  content="require-trusted-types-for 'script'; trusted-types default dompurify"
/>
```

### 2. Load DOMFortify first, in `<head>`

The default policy is winner-takes-all: whoever registers it first owns every DOM write. Load the
sanitizer, then DOMFortify, ahead of anything attacker-reachable. Pin both with
[SRI](https://developer.mozilla.org/docs/Web/Security/Subresource_Integrity) so a CDN compromise
fails closed:

```html
<script
  src="https://cdn.jsdelivr.net/npm/dompurify@3/dist/purify.min.js"
  integrity="sha384-..."
  crossorigin="anonymous"
></script>
<script
  src="https://cdn.jsdelivr.net/npm/domfortify@0.1.0/dist/fortify.min.js"
  integrity="sha384-..."
  crossorigin="anonymous"
></script>
```

The IIFE build (`dist/fortify.js`) auto-installs on load using `window.DOMFortifyConfig` if present.
SRI hashes are published per release.

### Bundler / ESM

If you must bundle, import the module build and call `init()` yourself **as early as possible** - a
bundler will not place an `import` first, which is the one thing this library needs:

```js
import { init } from 'domfortify';
init({
  /* config */
});
```

The module build does not auto-run. Note that bundling works against the load-first guarantee; a
plain first-in-`<head>` script is the recommended path.

## Configuration

Set `window.DOMFortifyConfig` before the script, or pass options to `init()`.

| Key                | Type                                   | Default            | Purpose                                                           |
| ------------------ | -------------------------------------- | ------------------ | ----------------------------------------------------------------- |
| `SANITIZER`        | object with `.sanitize`, or a function | `window.DOMPurify` | The sanitizer. Pass a function to adapt the native Sanitizer API. |
| `SANITIZER_CONFIG` | object                                 | none               | Passed to the sanitizer as its second argument.                   |
| `ALLOW_SCRIPT`     | `(code) => string \| null`             | refuse all         | Return a string to mint a specific `eval`/`javascript:` value.    |
| `ALLOW_SCRIPT_URL` | `(url) => string \| null`              | refuse all         | Return a string to mint a specific `script.src`/Worker URL.       |
| `ON_VIOLATION`     | `(code, detail) => void`               | none               | Fires on every notable event. Useful as a report-only on-ramp.    |

Config is read once, from own properties only, so a polluted prototype cannot supply a value or
loosen a refusal.

### Using the native Sanitizer API instead of DOMPurify

```js
window.DOMFortifyConfig = {
  SANITIZER: (s) => {
    const d = document.createElement('div');
    d.setHTML(s);
    return d.innerHTML;
  },
};
```

And drop `dompurify` from the directive: `trusted-types default`.

## Checking status

`DOMFortify.status()` (or the return value of `init()`) reports honestly whether you are protected:

```js
const s = DOMFortify.status();
// { version, ttSupported, enforcementActive, defaultPolicyOwned, sanitizerReady, protected, reason }
```

`protected` is true only when enforcement is active, DOMFortify owns the default policy, and the
sanitizer passed its smoke test.

## Limits (read these)

- **Enforcement must be on.** Without the CSP, DOMFortify is inert and says so.
- **Load it first.** If attacker code claims `default` first, you are worse off than not running at
  all. Do not add `'allow-duplicates'` - it drops the lock.
- **It fails closed.** No sanitizer means sinks throw, not leak. Bundle the sanitizer and pin it with
  SRI rather than trusting a CDN.
- **Per realm.** Each frame is its own realm and needs its own DOMFortify.
- **Trusted Types sinks only.** Inline handlers (`onclick=...`), `style` sinks, and plain URL
  properties (`a.href = ...`) are not TT sinks and stay open; close handlers with a `script-src` that
  drops `'unsafe-inline'`.
- **One sanitizer.** A single mXSS bypass in the sanitizer reopens everything it guards.

## Development

```bash
npm install
npm run build        # tsc types + rollup (IIFE, ESM, CJS, min, d.ts)
npm test             # typecheck + build + node QUnit suite
npm run test:browser # QUnit in a real browser via Playwright
```

See [CONTRIBUTING.md](CONTRIBUTING.md).

## Security

Report vulnerabilities privately - see [SECURITY.md](SECURITY.md). Do not open public issues for
security reports.

## Prior art

Inspired by Frederik Braun's
[Perfect types with setHTML()](https://frederikbraun.de/perfect-types-with-sethtml.html), building on
Jun Kokatsu's "Perfect Types".

## License

Dual-licensed under `MPL-2.0 OR Apache-2.0`, the same terms as DOMPurify. See [LICENSE](LICENSE).
