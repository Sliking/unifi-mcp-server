# Contributing

Thanks for helping improve the UniFi MCP Server!

## Ground rules

1. **Read-only stays read-only.** PRs that add write operations to the UniFi client will not be merged into the default build. If you want to propose write support, open an issue first to discuss an opt-in design (separate tool set, explicit confirmation, separate scope).
2. **Never leak secrets.** Any new endpoint must go through `redact()`, and you must add a test that proves sensitive fields are removed.
3. **New endpoints must be added to `ALLOWED_PATHS`** in `src/unifi/client.ts`, with a justification in the PR.
4. **No real network data in fixtures.** Anonymise IPs, MACs, hostnames and names.

## Workflow

```bash
npm install
npm run check        # tsc --noEmit + vitest
npm run dev          # local server on :8788 (needs .dev.vars)
```

- Branch from `main`, keep PRs focused, and use [Conventional Commits](https://www.conventionalcommits.org) (`feat:`, `fix:`, `docs:` …).
- Add or update tests in `test/` for every behaviour change. Analysis code is pure and easy to test with fixtures.
- CI must pass (type-check and tests).

## Adding an audit check

1. Add a function or a block in `src/analysis/audit.ts` that pushes a `Finding` with a stable `id` (`AREA-SHORT-NAME`), a severity, a clear `detail` and an actionable `recommendation`.
2. Add fixture data and a test in `test/analysis.test.ts`.
3. Document the check ID in the PR description.

## Reporting bugs

Please include your UniFi console model, UniFi OS and Network application versions, and the firewall mode (zone-based or legacy). Remove any personal data first.

## Code of conduct

Be respectful and constructive. This project follows the [Contributor Covenant](https://www.contributor-covenant.org/version/2/1/code_of_conduct/).
