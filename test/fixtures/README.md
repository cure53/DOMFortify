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

`deployment.spec.ts` runs an attack-vector battery from `vectors.json` - a human-readable,
easy-to-extend corpus of DOM-XSS and mutation-XSS payloads (many adapted from the DOMPurify test
suite). Each entry is `{ name, kind, firesUnprotected, payload }`:

- **Every** vector is asserted _neutralized_ under DOMFortify (run against `meta.html`).
- Vectors flagged `firesUnprotected` (the deterministic simple handlers) are _also_ asserted to fire
  on `unprotected.html` - proving each is a real, working XSS and that the detector sees it.

The corpus covers simple auto-firing handlers beyond `<img>` (`svg/onload`, SMIL `animate/onbegin`,
`iframe/onload`, media `onerror`, `autofocus/onfocus`) and the classic mutation/namespace-confusion
families: `mglyph`/`style`, `noscript`, foster-parented `svg`/`style`, `form`/`math`/`mglyph`,
`style` self-closing tricks, comment and CDATA breakouts, `template`/`select`/`option` nesting, and
more. To add a vector, append one line to `vectors.json`.

Execution is caught by overriding `alert`/`confirm`/`prompt` before any page script runs, with a
native-dialog listener as a backstop. A `canary` test requires a known-good XSS to fire on the
unprotected page first - if that ever fails, the detector is broken and no "blocked" result can be
trusted.
