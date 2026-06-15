/**
 * Browser auto-install entry (IIFE build). Attaches `window.DOMFortify` and installs the default
 * policy the instant this file runs, to win the slot as early as possible. Configure beforehand via
 * `window.DOMFortifyConfig`.
 */
import { DOMFortify } from './fortify';
import type { DOMFortifyConfig } from './types';

declare global {
  interface Window {
    DOMFortify?: typeof DOMFortify;
    DOMFortifyConfig?: DOMFortifyConfig;
  }
}

if (typeof window !== 'undefined') {
  window.DOMFortify = DOMFortify;
  DOMFortify.init(window.DOMFortifyConfig || {});
}
