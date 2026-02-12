# ADR-0014: No Test Suppression Policy

**Status:** Accepted
**Date:** 2026-02-11
**Authors:** Development Team

## Context

During E2E test stabilization (Feb 2026), we discovered that `ignore_patterns` parameters
in `ComprehensivePageMonitor` were being used to suppress real application errors — 429 rate
limiting responses, 401 HMAC auth failures, and missing API endpoints. All 130 instances of
`ignore_patterns` across 14 E2E test files turned out to be either:

1. **Dead code** — the security hardening layer (`ComprehensivePageMonitor.__init__`) strips
   patterns containing `401`, `403`, `404`, `Forbidden`, and `Unauthorized` unless
   `allow_auth_error_ignores=True` (never set to True anywhere in the codebase).
2. **Masking real bugs** — rate limiting errors (429) caused by the platform's HMAC middleware
   were hidden instead of fixed. A staff ticket form that made `fetch()` API calls without
   HMAC headers was silently broken for all staff users.

Removing every `ignore_patterns` instance and instead fixing root causes led to the
discovery and fix of two real production bugs:
- Staff browser `fetch()` calls to `/api/` routes were rejected by HMAC middleware (no
  session auth fallback)
- Portal login did not populate `user_memberships` in the session, causing billing
  decorators to return 403 for all customers

## Decision

**Tests must never suppress, ignore, or skip errors just to make them pass.**

When a test encounters an error, the response must be one of:
1. **Fix the application code** — the error is a real bug
2. **Fix the test code** — the test assertion is wrong or the test setup is incomplete
3. **Disable the system causing the error** — e.g., disable rate limiting via
   `RATELIMIT_ENABLE=false` during E2E runs (not per-test, but system-wide)

If suppression is truly unavoidable (e.g., a known upstream bug with an open issue), it
requires:
- A `# SUPPRESSION:` comment in the code explaining **why**
- A `print()` warning at runtime so the suppression is visible in CI output
- A linked tracking issue for removal

## Rules

### Prohibited Patterns (enforced by `scripts/lint_test_suppressions.py`)

| ID | Pattern | Severity | Rationale |
|----|---------|----------|-----------|
| TS001 | `ignore_patterns=[...]` | Critical | Hides real errors in page monitors |
| TS002 | `ignore_console_patterns=[...]` | Critical | Hides JavaScript bugs |
| TS003 | `@pytest.mark.skip` without issue link | High | Skipped tests accumulate silently |
| TS004 | `pytest.skip()` without issue link | High | Same as above |
| TS005 | `@pytest.mark.xfail` without `strict=True` | Medium | Hides when bugs are fixed |
| TS006 | Bare `except: pass/continue` in tests | Medium | Swallows real failures |
| TS007 | `@unittest.skip` without justification | High | Same as TS003 |
| TS008 | `check_console=False` without comment | Low | Should explain why |
| TS009 | `check_network=False` without comment | Low | Should explain why |

### Acceptable Alternatives

| Problem | Wrong Fix | Right Fix |
|---------|-----------|-----------|
| Rate limiting in E2E tests | `ignore_patterns=["429"]` | `RATELIMIT_ENABLE=false make dev` |
| HMAC auth on browser fetch | `ignore_patterns=["401"]` | Staff session auth fallback in middleware |
| Missing session data | `pytest.skip("broken")` | Populate session data in login flow |
| Flaky login timing | `ignore_patterns=["timeout"]` | Add retry logic in `login_platform_user()` |
| A11Y issues in templates | `check_accessibility=False` | Fix the template (add `aria-label`, `<h1>`, etc.) |

### Monitoring Disable Flags

For system-level disabling (rate limiting, caching, etc.) during test runs:

| Flag | Scope | How |
|------|-------|-----|
| `RATELIMIT_ENABLE=false` | All rate limiting | Set in environment before starting services |
| `SESSION_ENGINE=db` | Session backend | Set in test settings to avoid cache-clear conflicts |

These are **system-wide** toggles, not per-test suppressions. They are set once at the start
of the test run and affect all tests equally.

## Enforcement

### Automated (CI Gate)

The scanner script runs during linting:

```bash
# In Makefile (lint target):
python scripts/lint_test_suppressions.py --fail-on critical

# Full check with fix suggestions:
python scripts/lint_test_suppressions.py --fail-on high --fix-hint
```

The script scans all files matching `test_*.py` in:
- `tests/` (E2E and integration tests)
- `services/platform/tests/` (platform unit tests)
- `services/portal/tests/` (portal unit tests)

### Pre-commit Hook

Add to `.pre-commit-config.yaml`:

```yaml
- repo: local
  hooks:
    - id: lint-test-suppressions
      name: Check for test error suppressions
      entry: python scripts/lint_test_suppressions.py --fail-on critical
      language: system
      pass_filenames: false
      files: 'test_.*\.py$'
```

### Code Review

Reviewers should reject PRs that introduce any TS001 or TS002 findings. For TS003-TS009
findings, the PR author must explain why suppression is necessary and link to a tracking
issue.

## Consequences

### Positive
- Tests catch real bugs instead of hiding them
- Two production bugs were found and fixed by removing suppressions
- CI output is trustworthy — green means actually working
- Forced investigation of errors leads to better application code

### Negative
- Fixing root causes takes longer than adding `ignore_patterns`
- Some tests may temporarily fail when new bugs are introduced
- Requires rate limiting to be disabled system-wide for E2E runs

### Neutral
- Scanner script adds ~2s to lint time
- Developers need to understand the alternative approaches

## References

- ADR-0002: Strategic Linting Framework (test quality standards)
- ADR-0011: Feature-Based Test Organization (test file structure)
- `scripts/lint_test_suppressions.py` — enforcement scanner
- `tests/e2e/utils.py:ComprehensivePageMonitor` — E2E monitoring framework
