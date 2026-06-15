/**
 * End-to-end deployment fixtures, plus an attack-vector battery.
 *
 * Each file in test/fixtures/ is a minimal, real-life-style page with exactly one DOM-XSS sink and a
 * single way of turning Trusted Types on (or not). The fixture documents itself in a header comment:
 *
 *   DEPLOY: none | meta | header | auto-inject
 *   EXPECT: vulnerable | protected | best-effort
 *
 * Detection is deliberately paranoid so a real execution is *definitely* caught:
 *   1. window.alert/confirm/prompt are overridden BEFORE any page script (addInitScript), so any
 *      payload that runs and calls one of them is counted, however it executes.
 *   2. A Playwright dialog listener is a backstop: if a native dialog ever surfaces (override
 *      bypassed), it is counted and dismissed so the run can't hang.
 *   3. The "canary" test proves the detector works by requiring a known-good XSS to fire on the
 *      unprotected page. Only then is a "did not fire" result on a protected page trustworthy.
 *
 * Payloads are driven through the URL hash (the fixtures' sink reads location.hash), so the fixtures
 * stay pure - what you read in a fixture is exactly the example, with no test hooks.
 */
import { test, expect, type Page } from '@playwright/test';
import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';

const FIXTURE_DIR = join(process.cwd(), 'test', 'fixtures');
const CSP = "require-trusted-types-for 'script'; trusted-types default dompurify;";

// Auto-firing vectors: each runs without interaction and calls alert(). More than just <img> so a
// sanitizer that special-cases one element can't pass by luck.
const AUTO_FIRING: ReadonlyArray<readonly [string, string]> = [
  ['img/onerror', '<img src=x onerror=alert(1)>'],
  ['svg/onload', '<svg onload=alert(1)></svg>'],
  ['svg/animate-onbegin', '<svg><animate onbegin=alert(1) attributeName=x dur=1s></svg>'],
  ['iframe/onload', '<iframe onload=alert(1)></iframe>'],
];

// Mutation-XSS: strings that look inert but mutate into an executing node when the browser parses
// (and a naive sanitizer re-serializes) them. The classic DOMPurify cases.
const MXSS: ReadonlyArray<readonly [string, string]> = [
  [
    'mglyph+style',
    '<math><mtext><table><mglyph><style><img src=x onerror=alert(1)></style></mglyph></table></mtext></math>',
  ],
  ['noscript', '<noscript><p title="</noscript><img src=x onerror=alert(1)>">'],
  ['svg+style', '<svg></p><style><a id="</style><img src=x onerror=alert(1)>">'],
  ['form+math', '<form><math><mtext></form><form><mglyph><style></math><img src=x onerror=alert(1)>'],
];

const REFERENCE = '<img src=x onerror=alert(1)>'; // the representative payload for the deployment matrix

function directive(src: string, key: string): string | undefined {
  return src.match(new RegExp(key + ':\\s*([\\w-]+)'))?.[1];
}

interface Dialoged extends Page {
  __dialogs?: number;
}

test.beforeEach(async ({ page }: { page: Dialoged }) => {
  // (1) Count any dialog-style call, however the payload reaches it, before page scripts run.
  await page.addInitScript(() => {
    const w = window as unknown as Record<string, unknown>;
    w.__alerts = 0;
    for (const k of ['alert', 'confirm', 'prompt']) {
      w[k] = () => {
        w.__alerts = (w.__alerts as number) + 1;
      };
    }
  });
  // (2) Backstop: a real native dialog (override somehow bypassed) is counted and dismissed.
  page.__dialogs = 0;
  page.on('dialog', (d) => {
    page.__dialogs = (page.__dialogs ?? 0) + 1;
    d.dismiss().catch(() => {});
  });
});

async function visit(
  page: Dialoged,
  fixture: string,
  payload: string,
): Promise<{ fired: boolean; status: Record<string, unknown> | null }> {
  await page.goto(`/test/fixtures/${fixture}#${encodeURIComponent(payload)}`);
  // Resolves the instant something fires; otherwise waits out the window so "did not fire" is real.
  await page
    .waitForFunction(() => (window as unknown as { __alerts: number }).__alerts > 0, null, { timeout: 700 })
    .catch(() => {});
  const r = await page.evaluate(() => ({
    alerts: (window as unknown as { __alerts?: number }).__alerts ?? 0,
    status:
      (
        window as unknown as { DOMFortify?: { status?: () => Record<string, unknown> | null } }
      ).DOMFortify?.status?.() ?? null,
  }));
  return { fired: r.alerts + (page.__dialogs ?? 0) > 0, status: r.status };
}

// --- The detector itself: a known-good XSS must be caught on an unprotected page ----------------
test('canary: the detector catches a real XSS on an unprotected page', async ({ page }) => {
  const { fired } = await visit(page, 'unprotected.html', REFERENCE);
  expect(fired, 'if this fails, the detector is broken and every "blocked" result is meaningless').toBe(true);
});

// --- Deployment matrix: one representative payload, each fixture's declared DEPLOY/EXPECT ---------
for (const file of readdirSync(FIXTURE_DIR).filter((f) => f.endsWith('.html'))) {
  const src = readFileSync(join(FIXTURE_DIR, file), 'utf8');
  const deploy = directive(src, 'DEPLOY');
  const expectKind = directive(src, 'EXPECT');
  const vuln = (src.match(/VULN:\s*(.+)/)?.[1] ?? '').trim();
  if (!deploy || !expectKind) continue;

  test(`deploy ${file}: ${deploy} -> ${expectKind} (${vuln})`, async ({ page }: { page: Dialoged }) => {
    if (deploy === 'header') {
      await page.route(`**/${file}`, async (route) => {
        const response = await route.fetch();
        await route.fulfill({ response, headers: { ...response.headers(), 'content-security-policy': CSP } });
      });
    }
    const { fired, status } = await visit(page, file, REFERENCE);

    if (expectKind === 'vulnerable') {
      expect(fired, 'with nothing enforcing Trusted Types the DOM-XSS should fire').toBe(true);
      expect(status?.protected, 'DOMFortify must not claim protection it does not have').toBeFalsy();
    } else if (expectKind === 'protected') {
      expect(fired, 'the payload must be neutralized under enforcement').toBe(false);
      expect(status?.protected, 'DOMFortify should report the page as protected').toBe(true);
    } else if (expectKind === 'best-effort') {
      expect(status?.metaInjected, 'a parse-time <meta> write should have been attempted').toBe(true);
      expect(fired && status?.protected === true, 'must never be XSS-through while reporting protected').toBe(false);
    } else {
      throw new Error(`fixture ${file} has an unknown EXPECT: ${expectKind}`);
    }
  });
}

// --- Attack-vector battery -----------------------------------------------------------------------
// Auto-firing vectors are checked both ways: they genuinely fire when unprotected (proving each is a
// real, working XSS and that the detector sees it), and are neutralized under DOMFortify.
for (const [name, payload] of AUTO_FIRING) {
  test(`vector ${name}: fires on the unprotected page`, async ({ page }: { page: Dialoged }) => {
    const { fired } = await visit(page, 'unprotected.html', payload);
    expect(fired, `${name} should execute when nothing is enforcing`).toBe(true);
  });
  test(`vector ${name}: neutralized under DOMFortify`, async ({ page }: { page: Dialoged }) => {
    const { fired, status } = await visit(page, 'meta.html', payload);
    expect(status?.protected, 'page should be protected').toBe(true);
    expect(fired, `${name} must not execute under enforcement`).toBe(false);
  });
}

// mXSS payloads are asserted blocked under DOMFortify. We do not assert they fire unprotected: modern
// browsers have fixed several at the parser level, so a non-fire there is a browser win, not our bug.
for (const [name, payload] of MXSS) {
  test(`mXSS ${name}: neutralized under DOMFortify`, async ({ page }: { page: Dialoged }) => {
    const { fired, status } = await visit(page, 'meta.html', payload);
    expect(status?.protected, 'page should be protected').toBe(true);
    expect(fired, `mXSS ${name} must not execute under enforcement`).toBe(false);
  });
}
