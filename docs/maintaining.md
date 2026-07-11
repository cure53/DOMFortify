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

- npm publishing is done **manually** by a maintainer (`npm publish` from the release tag); there is
  no publish workflow and no `NPM_TOKEN` repo secret. Keep 2FA on the npm account.
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

1. Bump the version in `package.json` (the build injects it in place of `__VERSION__`), sync the
   lockfile (`npm install --package-lock-only`), run `npm run build`, and commit the rebuilt `dist`
   - CI (`Verify committed dist is in sync with src`) fails otherwise. If DOMPurify shipped, bump
     the `dompurify` devDependency and refresh the pinned version and SRI hash in the README first.
2. Land that via PR, then create a GitHub Release / tag on the release commit. On publish,
   `sign-release.yml` checks out the tag, rebuilds, and attaches Sigstore bundles, and
   `slsa-provenance.yml` attests build provenance for the same bytes.
3. Publish manually from a clean checkout of the tag: `npm ci && npm publish`
   (`prepublishOnly` rebuilds `dist`; the build is reproducible, so the published bytes match the
   committed and attested ones).
4. Publish the SRI hashes for `dist/fortify.min.js` in the release notes so integrators can pin
   them (`openssl dgst -sha384 -binary dist/fortify.min.js | openssl base64 -A`), and verify the
   hash in the README's CDN snippet matches the published artifact.
