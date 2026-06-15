# Deployment fixtures

Each `.html` here is a minimal, real-life-style page with **one** serious DOM-XSS sink and **one** way
of deploying DOMFortify. They double as documentation: open one and read it top to bottom to see
exactly how a page is wired and what is meant to happen.

Every fixture declares itself in a header comment:

```
VULN:   the sink and where the attacker input comes from
DEPLOY: none | meta | header | auto-inject
EXPECT: vulnerable | protected | best-effort
```

`test/e2e/deployment.spec.ts` reads those directives - so the fixture is the single source of truth -
drives the sink with a payload through the URL hash, and asserts the outcome in a real browser:

- **vulnerable** - nothing enforces Trusted Types, so the payload runs. The control that proves the
  sink is genuinely exploitable (and that DOMFortify reports `protected: false`, never pretending).
- **protected** - the payload is sanitized, nothing runs, and `status().protected` is `true`.
- **best-effort** - meta auto-injection: the attempt is made (`status().metaInjected`), and the
  invariant checked is that DOMFortify never lets the payload through while claiming to be protected.

The deployment ladder, sturdiest first:

| Fixture            | DEPLOY      | How Trusted Types is enabled                                       |
| ------------------ | ----------- | ------------------------------------------------------------------ |
| `header.html`      | header      | response header (the test adds it; in production your server does) |
| `meta.html`        | meta        | a parse-time `<meta>` CSP in the page                              |
| `auto-inject.html` | auto-inject | `INJECT_META` writes the `<meta>` during parse (best-effort)       |
| `unprotected.html` | none        | nothing - the control showing the raw vuln                         |

The remaining fixtures (`sink-*.html`) hold the deployment constant (`meta`) and vary the sink
(`insertAdjacentHTML`, `Range.createContextualFragment`) to show the protection is sink-agnostic.

The pages load `fortify.js` and DOMPurify from local paths so the tests are hermetic; a real site
would self-host or use a CDN. Run them with `npm run test:browser` (needs `npx playwright install
--with-deps chromium`).

## Attack vectors and detection

`deployment.spec.ts` does not trust a single payload. Alongside the deployment matrix it runs a
battery against `meta.html` (and, for the auto-firing ones, `unprotected.html`):

- **Auto-firing vectors** - `img/onerror`, `svg/onload`, `svg` SMIL `animate/onbegin`, and
  `iframe/onload`. Each is checked to genuinely fire on the unprotected page (so it is a real XSS,
  not a no-op) and to be neutralized under DOMFortify.
- **Mutation XSS** - the classic `mglyph`/`style`, `noscript`, `svg`/`style`, and `form`/`math`
  cases that mutate into an executing node when parsed. Asserted blocked under DOMFortify. (They are
  not required to fire unprotected: modern browsers have fixed several at the parser level.)

Execution is caught by overriding `alert`/`confirm`/`prompt` before any page script runs, with a
native-dialog listener as a backstop. A `canary` test requires a known-good XSS to fire on the
unprotected page first - if that ever fails, the detector is broken and no "blocked" result can be
trusted.
