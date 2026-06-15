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
  /** True only when enforced, owned, and the sanitizer is ready. */
  protected: boolean;
  /** Human-readable explanation of the current state. */
  reason: string;
}

export interface DOMFortifyApi {
  init(options?: DOMFortifyConfig): Readonly<DOMFortifyStatus>;
  status(): Readonly<DOMFortifyStatus> | null;
}
