import { defineConfig } from '@playwright/test';

// Runs the QUnit suite in a real browser. The suite (test/index.html) is self-contained and
// served as a static file, so no dev server is needed.
export default defineConfig({
  testDir: '../test',
  testMatch: /browser-runner\.ts/,
  fullyParallel: true,
  reporter: 'list',
  use: { headless: true },
  projects: [{ name: 'chromium', use: { browserName: 'chromium' } }],
});
