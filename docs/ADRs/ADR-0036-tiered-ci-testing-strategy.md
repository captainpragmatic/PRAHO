# ADR-0036: Tiered CI Testing Strategy

## Status
**Active** - March 2026

## Context

As the PRAHO test suite grew beyond 900 tests across Platform and Portal, running the full PostgreSQL test suite on every pull request became a bottleneck. A full CI run (platform + portal + integration) took approximately 12 minutes on the GitHub Actions runners, creating a slow feedback loop for contributors.

Several observations shaped the solution:

1. The majority of test failures are logic errors detectable with SQLite — not PostgreSQL-specific behaviour.
2. PostgreSQL-specific failures (transaction isolation, `ARRAY` fields, `DISTINCT ON`, advisory locks, `LISTEN/NOTIFY`) are rare and almost always caught during feature development rather than in unrelated PRs.
3. Not every PR touches every app — running the full suite for a one-line change in `apps/tickets/` is wasteful.
4. The nightly CI slot is unconstrained; production-parity validation belongs there.

## Decision

Adopt a **two-tier CI strategy** that separates fast-feedback PR checks from production-parity nightly runs, supplemented by on-demand full runs and affected-module detection.

### Tier 1 — PR Checks (SQLite, fast)

Every pull request runs:
- Platform tests against SQLite (Django test runner, `config.settings.test`)
- Portal tests (already SQLite-only by design)
- Ruff lint, mypy type checks, pre-commit hooks
- Security static analysis

Target: **under 4 minutes** from push to green check.

### Tier 2 — Nightly and Master Merges (PostgreSQL, full)

Run nightly at 02:00 UTC and on every merge to `master`:
- Full platform test suite against a real PostgreSQL instance (same version as production)
- Integration tests (cross-service HMAC auth, provisioning flows)
- E2E Playwright tests (when `services/` or `shared/` are touched)

Target: complete within 15 minutes.

### Affected-Module Detection

`scripts/affected_test_modules.py` maps changed file paths to their corresponding test modules using the `apps/ → tests/` mirror structure. CI passes the module list to `make test-fast FILE=<modules>` to reduce unnecessary test runs without skipping tests.

The script maps:
- `services/platform/apps/billing/**` → `tests.billing.*`
- `services/platform/apps/orders/**` → `tests.orders.*`
- `shared/ui/**` → all UI-related test modules
- `services/portal/apps/**` → portal test suite

If the diff touches `config/`, `requirements`, or more than 5 apps, the full suite runs unconditionally.

### On-Demand Full Suite

Any contributor can trigger a full PostgreSQL run on their PR by posting `/full-test` as a PR comment. The `full-test.yml` workflow listens for `issue_comment` events filtered to this trigger phrase and runs the complete Tier 2 suite against the PR branch.

### Workflow Files

| File | Purpose |
|------|---------|
| `.github/workflows/ci.yml` | Tier 1 — runs on every PR push |
| `.github/workflows/nightly.yml` | Tier 2 — scheduled nightly + master merge |
| `.github/workflows/full-test.yml` | On-demand Tier 2 triggered by `/full-test` comment |

## Consequences

### Positive
- PR feedback time reduced from ~12 minutes to ~3 minutes
- PostgreSQL-specific regressions are caught nightly before they compound
- Affected-module detection eliminates irrelevant test runs on focused PRs
- `/full-test` gives contributors a self-service escape hatch without requiring CI config changes
- No test is permanently skipped — the full suite always runs somewhere

### Negative
- A PostgreSQL-specific bug introduced in a PR will not surface until the nightly run (or a `/full-test` trigger)
- Affected-module detection adds a mapping maintenance burden — new apps must be added to `scripts/affected_test_modules.py`
- Two CI configurations to maintain (SQLite settings vs PostgreSQL CI settings)

### Neutral
- Portal tests are always SQLite (no change — Portal has no business database)
- E2E tests remain gated on service availability; Tier 2 provisions services before running them
- The `DJANGO_SETTINGS_MODULE` override in nightly workflow (`config.settings.test_pg`) was necessary to avoid the portal's SQLite-only settings leaking into platform CI (see commit f65392b4)

## Reference Commits

| Commit | Change |
|--------|--------|
| c00e4807 | Initial tiered CI split — SQLite for PRs, PG for nightly |
| 46f4ae7f | Add affected-module detection script |
| 1b6bbf92 | Add `/full-test` PR comment trigger workflow |
| 45868c51 | Fix portal `DJANGO_SETTINGS_MODULE` override in nightly workflow |

## Related

- ADR-0001: pytest-playwright for E2E Testing (E2E gates live in Tier 2)
- ADR-0014: No Test Suppression Policy (tiering does not suppress — it defers)
- ADR-0011: Feature-Based Test Organization (mirrors `apps/` → `tests/` mapping used by affected-module detection)
