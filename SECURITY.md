# Security Policy

DOMFortify is a security control, so please treat issues in it accordingly.

## Reporting a vulnerability

**Do not open a public issue or pull request for a security report.**

Report privately via one of:

- GitHub: open a [private security advisory](https://github.com/cure53/DOMFortify/security/advisories/new).
- Email: security report to Cure53 at `mario@cure53.de` with `[DOMFortify]` in the subject.

Please include a description, affected versions, and a minimal reproduction (a page plus the CSP and
config used). We aim to acknowledge within a few business days and will coordinate disclosure with
you, crediting reporters who wish to be named.

## Scope

In scope: ways to defeat the sanitization or script-refusal guarantees when DOMFortify is deployed as
documented (loaded first, enforcement on, sanitizer present).

Out of scope, because they are documented limitations rather than bugs:

- Anything that never reaches a Trusted Types sink (inline event handlers, `style`, plain URL
  properties, template/expression injection).
- Deployments where attacker-controlled code runs before DOMFortify and claims the `default` policy.
- Sanitizer bypasses themselves - report those to the sanitizer's project (e.g. DOMPurify).
- Missing or misconfigured CSP (DOMFortify reports this via `status()`).

## Supported versions

This is pre-1.0 software; only the latest release is supported.
