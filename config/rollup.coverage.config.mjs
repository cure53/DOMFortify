/**
 * Coverage build: the ESM module instrumented with Istanbul, written to a separate file the node
 * test suite imports when DOMFORTIFY_COV is set. Mirrors DOMPurify's instrument-then-nyc approach;
 * Istanbul's per-file counters accumulate correctly across the suite's fresh-module-per-test imports,
 * where V8 coverage would fragment on the cache-busting query.
 */
import { createRequire } from 'node:module';
import typescript from '@rollup/plugin-typescript';
import replace from '@rollup/plugin-replace';
import istanbul from 'rollup-plugin-istanbul';

const require = createRequire(import.meta.url);
const pkg = require('../package.json');

export default {
  input: 'src/index.ts',
  output: { file: 'dist/fortify.cov.es.mjs', format: 'es', sourcemap: true },
  plugins: [
    replace({ preventAssignment: true, values: { __VERSION__: pkg.version } }),
    typescript({ tsconfig: './config/tsconfig.build.json' }),
    istanbul({ include: ['src/**/*.ts'] }),
  ],
};
