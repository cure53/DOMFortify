/**
 * Module entry (ESM / CJS). Does NOT auto-install - call `init()` yourself, as early as possible.
 * For a plain `<script>` that auto-installs on load, use the IIFE build (`dist/fortify.js`).
 */
export { init, status, DOMFortify, DOMFortify as default } from './fortify';
export type {
  DOMFortifyApi,
  DOMFortifyConfig,
  DOMFortifyStatus,
  Sanitizer,
  SanitizeFn,
  ScriptHook,
  ViolationCode,
} from './types';
