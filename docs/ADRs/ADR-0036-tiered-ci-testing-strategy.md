# ADR-0036: Tiered CI Testing Strategy

## Status
**Active** - March 2026, amended October 2026 (PR CI as the merge gate, release-candidate promotion)

## Context

As the PRAHO test suite grew beyond 900 tests across Platform and Portal, running the full PostgreSQL test suite on every pull request became a bottleneck. A full CI run (platform + portal + integration) took approximately 12 minutes on the GitHub Actions runners, creating a slow feedback loop for contributors.

Several observations shaped the solution:

1. The majority of test failures are logic errors detectable with SQLite — not PostgreSQL-specific behaviour.
2. PostgreSQL-specific failures (transaction isolation, `ARRAY` fields, `DISTINCT ON`, advisory locks, `LISTEN/NOTIFY`) are rare and almost always caught during feature development rather than in unrelated PRs.
3. Not every PR touches every app — running the full suite for a one-line change in `apps/tickets/` is wasteful.
4. The nightly CI slot is unconstrained; production-parity validation belongs there.

### October 2026 amendment

Three facts changed the decision:

1. **The repository is public, so standard GitHub-hosted runners are free and unlimited** (4 CPU / 16 GB). The 20-concurrent-job limit of the Free plan is the only constraint; minutes are not.
2. **CI was not binding.** `master` had no branch protection, Integration CI was path-filtered and optional, and the security scans could not fail (Bandit and Semgrep were never installed; `continue-on-error` hid it). Contributors and AI agents compensated by re-running the full gate locally (15–20 minutes per push).
3. **The tiers drifted from this record.** The whole platform suite never ran on PostgreSQL in any workflow, browser tests ran only nightly, the strict-CSP gates ran nowhere, and the `/full-test` comment trigger ran a pull request's code with write permissions when a trusted person commented.

## Decision

### Tier 1 — every pull request is the full merge gate

Every pull request to `master` runs, with no paths filter on any required workflow:

| Workflow | Required jobs | What they cover |
|---|---|---|
| `platform.yml` | `coverage-gate`, `platform-test`, `platform-postgres`, `platform-security` | the whole platform suite on SQLite with coverage floors, affected-module fast signal, pytest-only classes, mypy, PostgreSQL-gated tests, Bandit (blocking) |
| `portal.yml` | `portal-test`, `portal-server` | portal unit tests and coverage floor, mypy, prod-settings server acceptance |
| `integration.yml` | `lint-and-quality`, `integration-test` | every `make lint` phase, migration checks with the base branch's validators, parity, Semgrep (new findings, blocking), cross-service, cache, isolation and deploy tests on PostgreSQL |
| `browser.yml` | `browser-e2e`, `browser-csp` | the Playwright suite against both live services, and the strict-CSP gates on their own stack |
| `virtualmin-lab.yml` | `pull-request` | the lab suites on the pinned Virtualmin, when `scripts/ci_lab_needed.py` says the change can reach them (it fails open) |
| `dco-check.yml` | `dco` | sign-off on every commit |

`.github/rulesets/master.json` makes these checks required (only the GitHub Actions app can satisfy them), requires the branch to be up to date, and allows squash merges only. The owner may bypass on a pull request, never by a direct push. A workflow skipped by a paths filter never reports, so a required check on it would block forever: selection, where it exists, happens inside a job that reports success when it skips. `tests/integration/test_ci_required_checks.py` enforces this.

A new push to a pull request cancels the run on its previous head (`concurrency` with `cancel-in-progress` on `pull_request` only).

### Local checks

Locally, contributors and agents run only what takes seconds on what they touched: the pre-commit hooks, `make check-pysyntax FILE=`, `make lint FILE=`, `make test-file` (platform) or `pytest <path>` (portal), and `make check-types FILE=`. The full gate runs in CI. Exceptions: reproducing a CI failure, and the strict-CSP or Docker deploy suites when changing CSP or deploy code.

### Tier 2 — nightly and release candidates (PostgreSQL, full)

`nightly.yml` runs at 02:30 UTC when there was activity: the whole platform suite on PostgreSQL (`make test-platform-postgres-full`), the full suite with coverage, integration, cache and security suites on PostgreSQL, types, Semgrep against the staging release, and the browser suite with server-side coverage. `virtualmin-lab.yml` runs the full lab nightly and a drift run against the latest Virtualmin.

`release-candidate.yml` is dispatched by hand on a `master` commit (blank = the current tip). It confirms that the commit's pull request passed every required check, then runs only what pull requests cannot afford, on that exact SHA: the whole platform suite on PostgreSQL and the full Virtualmin lab. On success it posts the commit status `release-candidate`.

### Promotion to staging

`staging` is a pointer to what fi-staging runs, never a branch anyone merges into. Commits flow one way: pull request → `master` → release candidate → staging → (later) production.

1. Run the release candidate and wait (an hour or more, mostly the lab). A red run changes nothing: fix it through a pull request and start a new candidate.
2. From an approved operator IP: `make promote-staging SHA=<sha>` (`DRY_RUN=1` to see the checks only). It refuses a commit that is not on `master` or lacks the green status, deploys with `make deploy-staging VERSION=<sha>`, and only then fast-forwards `staging` (`--rollback` deploys an older approved commit).
3. Accept on staging and record the deployed SHA.

A release candidate is not a GitHub Release: a `v*` tag publishes one. For production the order will be release candidate → staging accepted → tag that same commit → deploy the tag. `.github/rulesets/staging.json` and `release-tags.json` restrict both refs to the owner.

Staging deploys stay manual: fi-staging admits only the operator IPs, and the deploy inputs live on the operator's machine. A later "Promote to staging" button would be a `workflow_dispatch` behind a protected `staging` environment (scoped secrets, the owner as required reviewer) that joins the tailnet and calls the same `scripts/promote_staging.sh`. It needs its own security review first, and a self-hosted runner is not an option on a public repository.

### Affected-Module Detection

`scripts/affected_test_modules.py` maps changed platform paths to test modules; `platform-test` uses it for a fast first signal on pull requests. It no longer limits what must pass: `coverage-gate` runs the whole suite on every pull request.

### Workflow Files

| File | Purpose |
|------|---------|
| `.github/workflows/platform.yml`, `portal.yml`, `integration.yml`, `browser.yml`, `dco-check.yml` | Tier 1 — every pull request, required |
| `.github/workflows/virtualmin-lab.yml` | Tier 1 when relevant; nightly full and drift runs; the release candidate's lab |
| `.github/workflows/nightly.yml` | Tier 2 — scheduled nightly |
| `.github/workflows/release-candidate.yml` | Tier 2 — the release gate before staging |
| `.github/rulesets/*.json` | Branch and tag rules, applied with `gh api` (see that directory's README) |

`full-test.yml` and its `/full-test` comment trigger were removed in October 2026: pull requests now run everything it did, and it executed pull-request code with write permissions.

## Consequences

### Positive
- A red check blocks the merge; nothing depends on contributors or agents remembering to run the full gate
- Local machines run seconds of checks instead of 15–20 minutes, and agents are not blocked waiting for them
- Every commit staging receives passed the whole suite on PostgreSQL and the full lab on that exact SHA
- No test is permanently skipped — the full suite always runs somewhere

### Negative
- Pull request feedback takes about 30 minutes (Integration and the lab are the long jobs)
- A required browser test that flakes blocks merges; flakes must be fixed, never retried away (ADR-0014)
- A PostgreSQL-only bug outside the gated modules surfaces at the nightly or release-candidate run, not on the pull request
- Semgrep blocks only new findings; the debt from before it ran in CI remains to be worked down

### Neutral
- Portal tests are always SQLite (no change — Portal has no business database)
- Merge queue is not used: "up to date" requirement gives the same guarantee for a solo maintainer. Adopting it needs `merge_group` triggers on every required workflow and a DCO range rework

## Reference Commits

| Commit | Change |
|--------|--------|
| c00e4807 | Initial tiered CI split — SQLite for PRs, PG for nightly |
| 46f4ae7f | Add affected-module detection script |
| 1b6bbf92 | Add `/full-test` PR comment trigger workflow (removed October 2026) |
| 45868c51 | Fix portal `DJANGO_SETTINGS_MODULE` override in nightly workflow |

## Related

- ADR-0001: pytest-playwright for E2E Testing
- ADR-0014: No Test Suppression Policy (tiering does not suppress — it defers)
- ADR-0011: Feature-Based Test Organization (mirrors `apps/` → `tests/` mapping used by affected-module detection)
