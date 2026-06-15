import { test, expect } from '@playwright/test';

test('QUnit suite passes in the browser', async ({ page }) => {
  await page.goto('/test/index.html');
  const handle = await page.waitForFunction(
    () => (window as unknown as { __qunitResults?: unknown }).__qunitResults,
    null,
    { timeout: 30_000 },
  );
  const results = (await handle.jsonValue()) as { passed: number; failed: number; total: number };
  expect(results.failed, JSON.stringify(results)).toBe(0);
  expect(results.total).toBeGreaterThan(0);
});
