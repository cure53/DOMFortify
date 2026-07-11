/**
 * Internal helpers shared by DOMFortify. Everything here is pure and free of side effects: no DOM,
 * no Trusted Types, no module state. The environment captures and the policy logic live in
 * fortify.ts; these are the small building blocks it leans on.
 */
import type { UrlPattern } from './types';

// Cached up front so later prototype pollution or clobbering can't swap hasOwnProperty out.
const hasOwn = Object.prototype.hasOwnProperty;

/** True only for an own (non-inherited) property, so a polluted prototype is never consulted. */
export function own(obj: unknown, key: string): boolean {
  return obj != null && hasOwn.call(obj, key);
}

/** Read an own key off a config-like object, else undefined. Never walks the prototype chain. */
export function cfg(obj: unknown, key: string): unknown {
  return own(obj, key) ? (obj as Record<string, unknown>)[key] : undefined;
}

/** A short, safe preview of an arbitrary value, for violation reports. */
export function clip(s: unknown): string {
  return String(s).slice(0, 80);
}

/**
 * Best-effort error message, tolerant of non-Error throws. Must never throw itself: it runs inside
 * init()'s catch and several sink catches, so a hostile error whose `message` is a throwing getter
 * must not be able to re-throw from here and brick init(). Falls back to a constant.
 */
export function emsg(e: unknown): string {
  try {
    return String((e as { message?: unknown } | undefined)?.message);
  } catch {
    return 'unknown error';
  }
}

/**
 * Copy an object's own keys, dropping the three that could pollute a prototype. Deliberately not a
 * JSON clone: that would corrupt the RegExps and functions a sanitizer config may carry.
 */
export function shallowCopy(obj: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const k in obj) {
    if (hasOwn.call(obj, k) && k !== '__proto__' && k !== 'constructor' && k !== 'prototype') {
      out[k] = obj[k];
    }
  }
  return out;
}

/**
 * Test a URL against one or more patterns. A string matches as a substring (the empty string never
 * matches); a RegExp is test()ed, and a pattern that throws is treated as no match. Used for both
 * EXCLUDE and URL_CONFIG, always against the realm's own location.href.
 */
export function urlMatches(pattern: UrlPattern | UrlPattern[] | undefined, url: string): boolean {
  if (pattern == null) return false;
  const list = Array.isArray(pattern) ? pattern : [pattern];
  for (let i = 0; i < list.length; i++) {
    const p = list[i];
    if (typeof p === 'string') {
      if (p !== '' && url.indexOf(p) !== -1) return true;
    } else if (p instanceof RegExp) {
      try {
        if (p.test(url)) return true;
      } catch {
        /* a pattern that throws is treated as no match */
      }
    }
  }
  return false;
}
