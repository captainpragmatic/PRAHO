# ADR-0028: Server Log Checking in E2E Tests

**Status:** Accepted
**Date:** 2026-03-03
**Authors:** Development Team

## Context

E2E tests validate user-facing behavior through the browser, but Django backend errors can
occur silently without failing any test. A view might catch an exception and return a 200
response with degraded content, or a background signal handler might raise — neither would
be visible to Playwright assertions.

`ComprehensivePageMonitor` (ADR-0014) already monitors browser-side console errors and
network failures, but has no visibility into server-side logs. Both services write structured
logs during E2E runs:

- `logs/platform_e2e.log` (Platform service on :8700)
- `logs/portal_e2e.log` (Portal service on :8701)

Django's `RequestIDMiddleware` attaches an `X-Request-ID` header to every HTTP response,
providing a correlation key between browser requests and server log entries.

Without server log checking, tests can pass green while the backend logs Python tracebacks,
database errors, or unhandled exceptions — violating the spirit of ADR-0014's "no suppression"
policy.

## Decision

Implement a hybrid 3-layer server log checking approach, integrated into
`ComprehensivePageMonitor`:

### Layer 1: HTTP Response Monitoring

`page.on("response")` callback captures:
- Any response with status >= 500 (server errors)
- `X-Request-ID` headers from all responses for later log correlation

### Layer 2: Request-ID-Correlated Log Scanning

On test teardown, `ServerLogScanner` reads the log files and filters entries by the set of
`X-Request-ID` values collected during the test. This attributes specific server errors to
the test that triggered them, avoiding false positives from concurrent test activity.

### Layer 3: Uncorrelated Background Error Detection

Any `ERROR` or `CRITICAL` log lines that do not match any collected request ID are also
reported. These catch errors from signal handlers, background tasks, or middleware that
runs outside a normal request-response cycle.

**Note:** Log entries with `NO_REQUEST_ID` (produced when Django processes requests outside
the `RequestIDMiddleware` pipeline, e.g. management commands, signals, or early middleware)
are excluded from Layer 3 by design. These entries lack request context and would cause
false positives in concurrent test environments. To monitor these entries, use dedicated
management-command or signal-handler tests instead of E2E log correlation.

### Opt-Out Mechanism

Expected server errors (e.g., tests that intentionally trigger 500s) can be marked with:

```python
@pytest.mark.expect_server_errors("pattern")
```

Matched error lines are excluded from the failure report. All other errors still fail the
test. This follows ADR-0014's principle: suppression must be explicit and intentional.

### Graceful Degradation

When log files are absent (e.g., services not running or logs not configured), the scanner
skips log checking without failing the test. This allows the same test suite to run in
environments where server logs are unavailable.

## Consequences

### Positive
- Backend errors are now caught by the same E2E tests that trigger them
- Request-ID correlation provides precise error attribution per test
- Previously-hidden server errors (silent exceptions, degraded responses) are surfaced
- Extends ADR-0014's no-suppression philosophy to the server side

### Negative
- Log file I/O on every test teardown adds minor overhead
- Tests that intentionally trigger server errors must use `expect_server_errors` marker
- Log format changes require updating the parser

### Neutral
- Log files must be configured in E2E test settings (`LOG_FILE_PATH` in dev/test config)
- `ServerLogScanner` is decoupled from `ComprehensivePageMonitor` and can be used standalone

## References

- ADR-0001: Pytest + Playwright for E2E Testing
- ADR-0014: No Test Suppression Policy
- ADR-0017: Portal Auth Fail-Open Strategy
- `tests/e2e/helpers/server_logs.py` — log scanner implementation
- `tests/e2e/helpers/constants.py` — log file path constants
