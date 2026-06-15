import { test, expect } from '@playwright/test';
import { fileURLToPath, pathToFileURL } from 'node:url';
import path from 'node:path';

const here = path.dirname(fileURLToPath(import.meta.url));

test('QUnit suite passes in the browser', async ({ page }) => {
  const url = pathToFileURL(path.join(here, 'index.html')).href;
  await page.goto(url);
  const handle = await page.waitForFunction(
    () => (window as unknown as { __qunitResults?: unknown }).__qunitResults,
    null,
    {
      timeout: 30_000,
    },
  );
  const results = (await handle.jsonValue()) as { passed: number; failed: number; total: number };
  expect(results.failed, JSON.stringify(results)).toBe(0);
  expect(results.total).toBeGreaterThan(0);
});
