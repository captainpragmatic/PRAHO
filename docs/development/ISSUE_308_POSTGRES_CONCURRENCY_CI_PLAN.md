# Issue #308: PostgreSQL billing concurrency CI

**Status:** Implemented; verification complete

**Issue:** [#308](https://github.com/captainpragmatic/PRAHO/issues/308)

**Scope:** Nightly CI coverage for the existing payment-intent concurrency regressions

## Objective

Run PRAHO's PostgreSQL-only payment-intent concurrency tests in an automated,
blocking workflow so a reintroduced double-charge race cannot pass every CI
configuration unnoticed.

The workflow must prove the real database behavior exercised by
`DirectPaymentIntentPostgresConcurrencyTests`:

1. two concurrent requests for one order create one remote intent and one local
   payment;
2. successful remote replays converge on one local payment; and
3. the tests execute against PostgreSQL rather than being skipped under SQLite.

## Evidence and root cause

- Both concurrency regressions are `TransactionTestCase` tests that use real
  threads, separate Django connections, and `threading.Barrier`.
- Each test skips unless `connection.vendor == "postgresql"`.
- The PR, merge-gate, and nightly Platform commands all currently select
  `config.settings.test`, which uses SQLite.
- `nightly.yml` already provisions PostgreSQL 16 and uses it for integration,
  cache, and security checks, but not for the Platform billing tests.
- A local `make test-ci` run on current `master` reached the known 300-second
  DigitalOcean fixture defect fixed separately by PR #306. Restoring the entire
  nightly Platform suite to PostgreSQL here would therefore make #308 depend on
  an unrelated, unmerged PR.

## Approaches considered

### A. Restore the complete nightly Platform suite to PostgreSQL

This is the long-term architecture described by ADR-0036 and the suite has
received substantial PostgreSQL hardening. It is not independently safe on the
current base, however: the broad run reaches the unrelated DigitalOcean delete
poll before it can complete.

### B. Add a focused blocking PostgreSQL step (selected)

Run the existing `DirectPaymentIntentPostgresConcurrencyTests` class against the
nightly job's PostgreSQL service before the broad SQLite Platform suite.

- Closes the continuous-protection gap directly.
- Reuses the existing service container and CI settings.
- Remains independently mergeable from PR #306.
- Keeps the test serial and adds a bounded timeout for deadlock safety.
- Leaves production code and the fast PR feedback tier unchanged.

### C. Invoke `make test-ci` from the nightly job

The Make target starts and binds its own Docker container. GitHub Actions already
provides a PostgreSQL service on the same port, so invoking that target inside
the job would duplicate lifecycle ownership and can conflict on port 5432.

## Test-driven implementation plan

### Task 1: Add a failing workflow contract test

**File:** `services/platform/tests/common/test_nightly_ci_workflow.py`

Parse `.github/workflows/nightly.yml` and require that:

- the nightly job provisions PostgreSQL 16;
- a named billing concurrency step appears before the broad Platform suite;
- the step uses `config.settings.ci` with explicit PostgreSQL connection values;
- it invokes the exact concurrency test class without `--parallel`; and
- it has a five-minute timeout and remains blocking.

Run the test before modifying the workflow and record the expected failure that
the step is absent.

### Task 2: Wire the focused PostgreSQL step

**File:** `.github/workflows/nightly.yml`

Add the focused step after lint and before Platform coverage. Use the existing
PostgreSQL service credentials, the shared uv environment, and Django's
`config.settings.ci` settings. Do not add `continue-on-error` or parallel test
execution.

### Task 3: Verify real PostgreSQL execution

Run the exact test class against PostgreSQL 16 and confirm that both tests run
and pass rather than skip. Then run the workflow contract test, the surrounding
billing security module under the normal test settings, workflow syntax checks,
lint, and the relevant Platform regression suites.

## Invariants and non-goals

- Do not change payment or idempotency production logic.
- Do not weaken, skip, or replace either concurrency regression.
- Do not make every PR wait for PostgreSQL; Tier 1 remains SQLite and fast.
- Do not start a second PostgreSQL container inside the GitHub Actions job.
- Do not make this branch depend on PR #306.
- Do not claim the complete nightly Platform suite is PostgreSQL-backed; this
  PR deliberately adds focused coverage for the proven billing class.

## Completion criteria

- The contract test is observed failing for the missing workflow step.
- Both real concurrency tests pass against PostgreSQL 16 with zero skips.
- The workflow contract passes and proves ordering, settings, serial execution,
  timeout, and blocking behavior.
- Relevant lint and regression suites pass.
- Every commit contains the DCO `Signed-off-by:` trailer before first push.

## Verification record

Verified on 2026-07-18:

- RED: the workflow contract failed in 0.004 seconds because the named
  PostgreSQL billing step was absent.
- GREEN: the workflow contract passed in 0.005 seconds after the step was
  added.
- PostgreSQL 16: both concurrency tests executed and passed in 1.019 seconds;
  no test was skipped.
- The complete payment-intent security module passed 18 tests under the normal
  SQLite tier, with only the two expected PostgreSQL-only skips.
- The complete common test package passed 848 tests in 5.222 seconds.
- Focused Ruff and MyPy checks passed for the new contract test.
- `make lint` passed all seven repository phases, including Platform and Portal
  checks, test-layout audit, suppression scan, i18n, code health, and FSM
  guardrails.
- The nightly YAML parses successfully and `git diff --check` reports no
  whitespace errors.
- A full `make test-ci` diagnostic was intentionally stopped when current
  `master` reached the unrelated DigitalOcean delete polling defect at
  `test_digitalocean_service.py:101`. PR #306 fixes that base-branch defect;
  this focused #308 implementation does not depend on it.
