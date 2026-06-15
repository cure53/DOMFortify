# Contributing to DOMFortify

Thanks for helping. A few notes to keep changes smooth.

## Ground rules

- This is a browser-only library. There is no Node runtime target; keep server-isms out of `src/`.
- It is a security control. Favor minimal, auditable changes over features. New runtime dependencies
  are effectively not accepted - the supply-chain surface is part of the threat model.
- Default to failing closed. If a code path is unsure whether something is safe, it must refuse.

## Development

```bash
npm install
npm run build        # tsc types + rollup builds
npm test             # typecheck + build + node QUnit suite
npm run test:browser # QUnit in a real browser via Playwright (needs: npx playwright install)
npm run format       # prettier
npm run lint         # prettier --check
```

Sources are TypeScript in `src/`, built to `dist/`. Do not edit `dist/` by hand.

## Pull requests

- Add or update tests in `test/test-suite.mjs` for any behavior change; security-relevant logic needs
  a test that fails without your fix.
- Run `npm test` and `npm run lint` before pushing.
- Keep commits focused and describe the security reasoning, not just the change.

## Security issues

Do not file security problems as public issues or PRs. See [SECURITY.md](SECURITY.md).
