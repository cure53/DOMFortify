#!/usr/bin/env node
/**
 * Guard: every in-repo file referenced by a package.json script must exist in the tree.
 *
 * Catches the 0.5.0 slip where build:cov and coverage referenced config/rollup.coverage.config.mjs
 * and scripts/coverage.mjs, but those two files were never committed - so a clean checkout (CI
 * included) had a broken `npm run coverage`. Pure Node built-ins, no dependencies.
 *
 * Narrow by design. It inspects script command strings only, and flags a token as a must-exist
 * reference when it looks like a concrete source file: a relative path with a source extension,
 * not a glob, and not under a built/output directory. That covers entry points passed to `node`,
 * `rollup -c`, `tsc -p`, `playwright --config`, and the like, while deliberately ignoring rimraf
 * targets (dist/, coverage/, .nyc_output), prettier globs, and flags. It does not parse `files`,
 * `exports`, `bin`, or other packaging fields - those point at built output and have a better home
 * in `publint` / `npm pack`, without this guard's build-order traps.
 */
import { existsSync, readFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const pkg = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8'));

const SOURCE_EXT = /\.(?:mjs|cjs|js|ts|json)$/;
const GLOB = /[*?{}[\]]/;
const BUILT_OR_OUTPUT = /^(?:dist|coverage|node_modules|\.nyc_output)\//;

const misses = [];
for (const [name, command] of Object.entries(pkg.scripts ?? {})) {
  for (let token of command.split(/\s+/)) {
    // --flag=path keeps the path side; bare flags are dropped.
    if (token.startsWith('-')) {
      const eq = token.indexOf('=');
      if (eq === -1) continue;
      token = token.slice(eq + 1);
    }
    token = token.replace(/^['"]|['"]$/g, '');

    if (!token || token.includes('://') || token.startsWith('/')) continue;
    if (GLOB.test(token) || BUILT_OR_OUTPUT.test(token) || !SOURCE_EXT.test(token)) continue;

    if (!existsSync(join(root, token))) misses.push({ name, token });
  }
}

if (misses.length > 0) {
  console.error('package.json references files that are not in the tree:');
  for (const { name, token } of misses) console.error(`  scripts.${name} -> ${token}`);
  console.error('\nCommit the missing file(s), or remove the reference.');
  process.exit(1);
}

console.log('check-referenced-files: all script-referenced source files exist.');
