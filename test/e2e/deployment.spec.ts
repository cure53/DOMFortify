/**
 * End-to-end deployment fixtures.
 *
 * Each file in test/fixtures/ is a minimal, real-life-style page with exactly one DOM-XSS sink and a
 * single way of turning Trusted Types on (or not). The fixture documents itself in a header comment:
 *
 *   DEPLOY: none | meta | header | auto-inject
 *   EXPECT: vulnerable | protected | best-effort
 *
 * This spec reads those directives (so the fixture is the single source of truth - what you read in
 * the file is exactly what is asserted), drives the sink with a payload via the URL hash, and checks
 * the outcome in a real browser. The payload's onerror sets window.__xss only if the markup survives
 * unsanitized, so window.__xss === 1 means script actually ran.
 */
import { test, expect } from '@playwright/test';
import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';

const FIXTURE_DIR = join(process.cwd(), 'test', 'fixtures');
const PAYLOAD = '<img src=x onerror="window.__xss=1">';
const CSP = "require-trusted-types-for 'script'; trusted-types default dompurify;";

function directive(src: string, key: string): string | undefined {
  const m = src.match(new RegExp(key + ':\\s*([\\w-]+)'));
  return m ? m[1] : undefined;
}

for (const file of readdirSync(FIXTURE_DIR).filter((f) => f.endsWith('.html'))) {
  const src = readFileSync(join(FIXTURE_DIR, file), 'utf8');
  const deploy = directive(src, 'DEPLOY');
  const expectKind = directive(src, 'EXPECT');
  const vuln = (src.match(/VULN:\s*(.+)/)?.[1] ?? '').trim();
  if (!deploy || !expectKind) continue; // not a fixture

  test(`${file}: ${deploy} -> ${expectKind} (${vuln})`, async ({ page }) => {
    // DEPLOY: header means the page ships no CSP markup; the server supplies it as a response header.
    if (deploy === 'header') {
      await page.route(`**/${file}`, async (route) => {
        const response = await route.fetch();
        await route.fulfill({
          response,
          headers: { ...response.headers(), 'content-security-policy': CSP },
        });
      });
    }

    await page.goto(`/test/fixtures/${file}#${encodeURIComponent(PAYLOAD)}`);
    // Give an unsanitized payload's async onerror a chance to run; resolves immediately once it does.
    await page
      .waitForFunction(() => (window as unknown as { __xss?: number }).__xss === 1, null, { timeout: 400 })
      .catch(() => {});

    const r = await page.evaluate(() => ({
      xss: (window as unknown as { __xss?: number }).__xss ?? 0,
      status:
        (window as unknown as { DOMFortify?: { status?: () => Record<string, unknown> | null } }).DOMFortify?.status?.() ??
        null,
      out: document.getElementById('out')?.innerHTML ?? '',
    }));

    if (expectKind === 'vulnerable') {
      expect(r.xss, 'with nothing enforcing Trusted Types, the DOM-XSS should fire').toBe(1);
      expect(r.status?.protected, 'DOMFortify must not claim protection it does not have').toBeFalsy();
    } else if (expectKind === 'protected') {
      expect(r.xss, 'no script should run under enforcement').toBe(0);
      expect(r.status?.protected, 'DOMFortify should report the page as protected').toBe(true);
      expect(r.out.toLowerCase(), 'the onerror handler should be stripped from the DOM').not.toContain('onerror');
    } else if (expectKind === 'best-effort') {
      expect(r.status?.metaInjected, 'a parse-time <meta> write should have been attempted').toBe(true);
      // The robust invariant regardless of whether the browser honored the injected meta:
      // DOMFortify never lets the payload through while reporting the page as protected.
      expect(
        r.xss === 1 && r.status?.protected === true,
        'must never be XSS-through while reporting protected',
      ).toBe(false);
    } else {
      throw new Error(`fixture ${file} has an unknown EXPECT: ${expectKind}`);
    }
  });
}
