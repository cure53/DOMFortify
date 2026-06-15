# DOMFortify

DOMFortify turns on Trusted Types for a page and quietly takes over the browser's `default` policy,
so that old, vulnerable code like `el.innerHTML = location.hash` gets sanitized before it ever hits
the DOM. You don't touch the code. You don't even need to know where the bug is.

It's for the sites you can't fix: the legacy app nobody wants to touch, the third-party widget you
can't patch, the 200 `innerHTML` sinks written before anyone had heard of XSS. Ship the policy once
and the browser routes every HTML sink through a sanitizer for you.

> **Not secure. Just less broken.** This is a seatbelt for code you can't rewrite, not a reason to
> stop rewriting it.

## How it works

Trusted Types lets a page register one `default` policy that the browser calls for every dangerous
sink. DOMFortify is that policy. HTML goes through [DOMPurify](https://github.com/cure53/DOMPurify)
(or any sanitizer you hand it); script sinks like `eval` and `script.src` are refused outright,
because there is no safe way to sanitize executable code.

```
CSP enables Trusted Types  ->  default policy (DOMFortify)  ->  sanitizer  ->  DOM
```

## Usage

Two parts. First, turn enforcement on with a CSP - a response header if you can set one:

```
Content-Security-Policy: require-trusted-types-for 'script'; trusted-types default dompurify;
```

...or a `<meta>` tag if you can't:

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

Set `window.DOMFortifyConfig` before the script, or pass the same object to `init()`:

```js
window.DOMFortifyConfig = {
  SANITIZER: window.DOMPurify, // default. Or a function (s) => string to use the native Sanitizer API
  SANITIZER_CONFIG: {}, // forwarded to the sanitizer
  ON_VIOLATION(code, detail) {}, // called on every notable event - good for report-only rollouts
};
```

By default script sinks are refused. If you genuinely need to allow a specific one, hand over an
`ALLOW_SCRIPT(code)` or `ALLOW_SCRIPT_URL(url)` function that returns a string to permit it, or
anything else to refuse. Config is read once, own-properties only, so a polluted prototype can't
sneak a value in or loosen a refusal.

## What it won't do

It's a retrofit, not magic. Know the edges:

- **It needs the CSP.** No enforcement, no protection - and it'll tell you so via `status()`.
- **Load it first.** Whoever registers the `default` policy first wins. If attacker code beats you to
  it, you're worse off than before. Don't add `'allow-duplicates'`.
- **One realm at a time.** Each iframe is its own world and needs its own DOMFortify.
- **Trusted Types sinks only.** Inline handlers (`onclick=`), `style`, and `href` URLs aren't TT
  sinks. Close those with a real `script-src` that drops `'unsafe-inline'`.
- **One sanitizer.** A bypass in the sanitizer is a bypass in everything it guards.

## Security

Found a hole? Please report it privately - see [SECURITY.md](SECURITY.md). Don't open a public issue.

## License

`MPL-2.0 OR Apache-2.0`, the same as DOMPurify.

---

Built on the shoulders of Frederik Braun's
[Perfect types with setHTML()](https://frederikbraun.de/perfect-types-with-sethtml.html) and Jun
Kokatsu's "Perfect Types". By [Cure53](https://cure53.de).
