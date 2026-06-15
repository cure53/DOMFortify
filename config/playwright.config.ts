import { defineConfig } from '@playwright/test';

const PORT = 5173;
const baseURL = `http://127.0.0.1:${PORT}`;

// Runs the QUnit suite in a real browser. A tiny static server hosts the suite over http:// so its
// ES module imports resolve (file:// would be blocked by CORS).
export default defineConfig({
  testDir: '../test',
  testMatch: /browser-runner\.ts/,
  reporter: 'list',
  use: { baseURL, headless: true },
  webServer: {
    command: 'node test/serve.mjs',
    // Playwright defaults webServer cwd to the config dir; pin it to the repo root (where npm runs)
    // so the relative command and the served paths resolve correctly.
    cwd: process.cwd(),
    url: `${baseURL}/test/index.html`,
    reuseExistingServer: !process.env.CI,
    timeout: 30_000,
  },
  projects: [{ name: 'chromium', use: { browserName: 'chromium' } }],
});
