/**
 * Public type definitions for DOMFortify.
 */

/** A sanitizer object, e.g. DOMPurify. */
export interface Sanitizer {
  sanitize(input: string, config?: unknown): unknown;
}

/** A bare sanitize function, e.g. a Sanitizer-API adapter. */
export type SanitizeFn = (input: string, config?: unknown) => unknown;

/** A hook that decides whether a script body / script URL may be minted. */
export type ScriptHook = (value: string) => string | null;

/** A URL matcher: a substring (matched against `location.href`) or a RegExp. */
export type UrlPattern = string | RegExp;

/** A per-URL configuration override; the first rule whose `match` hits wins. */
export interface UrlConfigRule {
  /** URL pattern(s) to test against `location.href`. String = substring; RegExp = test. */
  match: UrlPattern | UrlPattern[];
  /** Override the sanitizer for matching pages. */
  SANITIZER?: Sanitizer | SanitizeFn;
  /** Override the sanitizer config (e.g. a different DOMPurify config) for matching pages. */
  SANITIZER_CONFIG?: unknown;
  /** Override the `eval` / `javascript:` hook for matching pages. */
  ALLOW_SCRIPT?: ScriptHook;
  /** Override the `script.src` / Worker URL hook for matching pages. */
  ALLOW_SCRIPT_URL?: ScriptHook;
}

/** Notable events emitted to `ON_VIOLATION`. */
export type ViolationCode =
  | 'tt-unsupported'
  | 'sanitizer-smoketest-failed'
  | 'sanitizer-unavailable'
  | 'sanitize-threw'
  | 'script-hook-threw'
  | 'script-sink-allowed'
  | 'script-sink-refused'
  | 'preexisting-default-policy'
  | 'default-policy-lost'
  | 'default-policy-not-active'
  | 'enforcement-inactive'
  | 'excluded-by-url'
  | 'outside-include-scope'
  | 'meta-injection-attempted'
  | 'failing-closed';

export interface DOMFortifyConfig {
  /** Object with `.sanitize`, or a bare function. Defaults to `window.DOMPurify`. */
  SANITIZER?: Sanitizer | SanitizeFn;
  /** Passed to the sanitizer as its second argument. */
  SANITIZER_CONFIG?: unknown;
  /** Allow specific `eval` / `javascript:` code. Return a string to mint, else refuse. */
  ALLOW_SCRIPT?: ScriptHook;
  /** Allow specific `script.src` / Worker URLs. Return a string to mint, else refuse. */
  ALLOW_SCRIPT_URL?: ScriptHook;
  /** Fires on every notable event; handy for report-only monitoring. */
  ON_VIOLATION?: (code: ViolationCode, detail: unknown) => void;
  /**
   * URL pattern(s) on which DOMFortify stays completely inactive: it claims no policy and injects no
   * meta. Matched against `location.href` (string = substring, RegExp = test).
   */
  EXCLUDE?: UrlPattern | UrlPattern[];

  /**
   * Allow-list complement of `EXCLUDE`. When set, DOMFortify activates ONLY on URLs that match and
   * stays completely inactive (no policy, no meta) everywhere else - useful for scoping a rollout to
   * specific routes. `EXCLUDE` still wins for a URL that matches both. Matched against `location.href`
   * (string = substring, RegExp = test). Best paired with page-scoped enforcement (e.g. INJECT_META):
   * under a globally delivered enforcement header, non-included pages have enforcement on but no
   * default policy, so their sinks fail closed.
   */
  INCLUDE?: UrlPattern | UrlPattern[];
  /** Per-URL configuration overrides; the first matching rule's keys override the base config. */
  URL_CONFIG?: UrlConfigRule[];
  /**
   * Opt-in (default off): attempt to inject the enabling CSP `<meta>` tag. Best-effort only - a `<meta>`
   * CSP is honored solely when the parser inserts it, so this can work only when DOMFortify runs during
   * the initial parse (inline/blocking, early in `<head>`), and only for content parsed afterwards. A
   * response header or a hand-placed parse-time `<meta>` is strongly preferred. See README.
   */
  INJECT_META?: boolean;
  /** Override the full `trusted-types` directive used when `INJECT_META` is on (advanced). */
  META_DIRECTIVE?: string;
}

export interface DOMFortifyStatus {
  version: string;
  /** Whether the Trusted Types API exists in this realm. */
  ttSupported: boolean;
  /** Whether `require-trusted-types-for 'script'` is actually being enforced. */
  enforcementActive: boolean;
  /** Whether DOMFortify owns the realm's `default` policy. */
  defaultPolicyOwned: boolean;
  /** Whether the sanitizer passed its smoke test. */
  sanitizerReady: boolean;
  /** Whether the URL is out of scope (matched `EXCLUDE`, or fell outside `INCLUDE`); inactive here. */
  excluded: boolean;
  /** Whether a CSP `<meta>` injection was attempted via document.write this load. */
  metaInjected: boolean;
  /** True only when enforced, owned, and the sanitizer is ready. */
  protected: boolean;
  /** Human-readable explanation of the current state. */
  reason: string;
}

export interface DOMFortifyApi {
  init(options?: DOMFortifyConfig): Readonly<DOMFortifyStatus>;
  status(): Readonly<DOMFortifyStatus> | null;
}
