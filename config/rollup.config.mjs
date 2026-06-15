import { createRequire } from 'node:module';
import typescript from '@rollup/plugin-typescript';
import replace from '@rollup/plugin-replace';
import terser from '@rollup/plugin-terser';
import dts from 'rollup-plugin-dts';

const require = createRequire(import.meta.url);
const pkg = require('../package.json');

const banner = `/*! DOMFortify ${pkg.version} | (c) Cure53 and contributors | ${pkg.license} */`;

// Inject the real version in place of the __VERSION__ placeholder in src/fortify.ts.
const version = () =>
  replace({
    preventAssignment: true,
    values: { __VERSION__: pkg.version },
  });

const ts = () => typescript({ tsconfig: './config/tsconfig.build.json' });

export default [
  // IIFE auto-install build (the canonical <script>-first-in-head path) + minified twin.
  {
    input: 'src/auto.ts',
    output: [
      { file: 'dist/fortify.js', format: 'iife', banner, sourcemap: true },
      { file: 'dist/fortify.min.js', format: 'iife', banner, sourcemap: true, plugins: [terser()] },
    ],
    plugins: [version(), ts()],
  },
  // Module builds (ESM + CJS). No auto-run - the consumer calls init() themselves.
  {
    input: 'src/index.ts',
    output: [
      { file: 'dist/fortify.es.mjs', format: 'es', banner, sourcemap: true },
      { file: 'dist/fortify.cjs.js', format: 'cjs', banner, sourcemap: true, exports: 'named' },
    ],
    plugins: [version(), ts()],
  },
  // Bundled type declarations.
  {
    input: 'src/index.ts',
    output: { file: 'dist/fortify.d.ts', format: 'es' },
    plugins: [dts()],
  },
];
