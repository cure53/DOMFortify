# Maintaining DOMFortify

The code-level hardening (SHA-pinned actions, `harden-runner` egress auditing, minimal token
permissions, CodeQL, OSV via `osv-scanner.toml`, npm provenance, zero runtime deps) lives in the
repo. A few OpenSSF Scorecard checks depend on **GitHub repository settings**, which cannot be
committed and must be enabled once on the repo.

## Branch protection / ruleset on `main`

Covers the Branch-Protection and Code-Review checks:

- Require a pull request before merging; require at least 1 approving review.
- Dismiss stale approvals on new commits.
- Require status checks to pass: `build-test`, `browser` (CI), and `Analyze` (CodeQL).
- Require branches to be up to date before merging.
- Require linear history; block force pushes and deletions.

## Secrets

- `NPM_TOKEN` - a granular npm automation token scoped to publish this package only. Keep 2FA on the
  npm account. Publishing runs from `publish.yml` via OIDC with `--provenance`.
- `SCORECARD_TOKEN` - a fine-grained PAT so the Scorecard workflow can read branch-protection status
  on a public repo. See the
  [scorecard-action docs](https://github.com/ossf/scorecard-action#authentication-with-fine-grained-pat-optional).

## Repository features

- Enable Dependency graph, Dependabot alerts, and Dependabot security updates.
- Code scanning is provided by `codeql-analysis.yml`; leave GitHub's "default setup" off so it does
  not conflict with the committed workflow.
- After the first scheduled Scorecard run, add the badge to the README:
  `https://api.securityscorecards.dev/projects/github.com/cure53/DOMFortify/badge`.

## Releasing

1. Bump the version in `package.json` (the build injects it in place of `__VERSION__`).
2. Create a GitHub Release / tag. `publish.yml` builds, tests, and publishes with provenance.
3. Publish the SRI hashes for `dist/fortify.min.js` in the release notes so integrators can pin them.
