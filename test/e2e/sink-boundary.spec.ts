/**
 * Sink-boundary coverage matrix.
 *
 * Proves, vector by vector, exactly where DOMFortify's protection begins and ends, so a future change
 * cannot silently reopen a sink. Every vector runs in genuine page context inside the fixture (see the
 * note in sink-boundary.runner.js for why this must not move into page.evaluate); the spec only reads
 * the recorded result after a short settle that lets async sinks (string setTimeout, script.src) land.
 *
 * COVERED: must be neutralized under DOMFortify, and must execute on the unprotected canary (which
 *   proves each vector is a real, working sink and that the detector sees it).
 * BOUNDARY: outside the Trusted Types contract by design (function-handler assignment); documented,
 *   not guarded as a vulnerability.
 */
import { test, expect, type Page } from '@playwright/test';

const COVERED = [
  'innerHTML',
  'outerHTML',
  'insertAdjacentHTML',
  'createContextualFragment',
  'template.innerHTML',
  'eval',
  'Function',
  'setTimeout(string)',
  'script.text',
  'script.src',
  'setAttribute-onclick',
];
const BOUNDARY = ['el.onclick = fn'];

interface Probe {
  status: Record<string, unknown> | null;
  fired: Record<string, boolean>;
  matrix: { label: string; category: string; threw: boolean; msg: string }[];
}

async function probe(page: Page, fixture: string): Promise<Probe> {
  await page.goto(`/test/fixtures/${fixture}`);
  await page.waitForFunction(() => (window as unknown as { __matrixReady?: boolean }).__matrixReady === true, null, {
    timeout: 5_000,
  });
  await page.waitForTimeout(300); // let async sinks (string setTimeout, script.src) settle
  return page.evaluate(() => ({
    status:
      (window as unknown as { DOMFortify?: { status?: () => Record<string, unknown> | null } }).DOMFortify?.status?.() ??
      null,
    fired: (window as unknown as { __fired: Record<string, boolean> }).__fired,
    matrix: (window as unknown as { __matrix: Probe['matrix'] }).__matrix,
  }));
}

// --- Canary: on an unprotected page every covered vector must execute -----------------------------
test('canary: every covered sink executes on the unprotected page', async ({ page }) => {
  const { fired } = await probe(page, 'sink-boundary-unprotected.html');
  for (const label of COVERED) {
    expect(fired[label], `${label} must execute when nothing is enforcing, or the test is meaningless`).toBe(true);
  }
});

// --- Protected: every covered vector is neutralized -----------------------------------------------
test('every covered sink is neutralized under DOMFortify', async ({ page }) => {
  const { status, fired } = await probe(page, 'sink-boundary.html');
  // Only assert the guarantee where the engine actually enforces Trusted Types (matches the rest of
  // the e2e suite); non-enforcing engine builds skip rather than fail.
  test.skip(!status?.enforcementActive, 'engine build does not enforce Trusted Types natively');
  expect(status?.protected, 'page should report protected').toBe(true);
  for (const label of COVERED) {
    expect(fired[label] ?? false, `${label} must be neutralized under enforcement`).toBe(false);
  }
});

// --- Boundary: function-handler assignment is outside the contract and stays so --------------------
test('boundary sinks remain outside the Trusted Types contract (documented, not guarded)', async ({ page }) => {
  const { status, fired } = await probe(page, 'sink-boundary.html');
  test.skip(!status?.enforcementActive, 'engine build does not enforce Trusted Types natively');
  for (const label of BOUNDARY) {
    expect(
      fired[label] ?? false,
      `${label} sits outside Trusted Types; if this changes, re-evaluate the threat model and docs`,
    ).toBe(true);
  }
});
