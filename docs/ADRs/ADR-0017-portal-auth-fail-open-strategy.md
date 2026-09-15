# ADR-0017: Portal Authentication Fail-Open Strategy

**Status:** Accepted
**Date:** 2026-02-28
**Authors:** Development Team
**Supersedes:** N/A
**Related:** ADR-0004 (Custom 2FA Implementation), ADR-0018 (Django Encryption Key Management), ADR-0021 (Email Enumeration Prevention)

## Context

PRAHO uses a **two-service architecture**: Platform (`:8700`, has PostgreSQL) and Portal (`:8701`, fully stateless — no database, no local user store). Portal authenticates customers by calling Platform's `/users/session/validate/` endpoint via HMAC-signed HTTP requests.

`PortalAuthenticationMiddleware` re-validates each customer's session every 10–12 minutes (jittered) by calling Platform. This raises a critical question: **what should Portal do when Platform is unreachable?**

There are exactly two options:

### Option A: Fail-Closed (reject access)

Every request whose validation timer fires during a Platform outage gets rejected. The session is flushed and the user is redirected to `/login/`. Since login itself requires a Platform API call (`authenticate_customer`), the user cannot log back in either.

**Consequence:** A 30-second Platform restart causes a rolling wave of customer logouts. With typical session jitter, ~5% of active users hit their validation window per minute. A 5-minute maintenance window logs out ~25% of concurrent users, and none can return until Platform recovers. This creates a **total customer-facing outage** that is indistinguishable from Portal being down.

### Option B: Fail-Open (allow access temporarily)

Already-authenticated users with a previous successful validation continue to use Portal during the outage. New logins still fail (no way to verify credentials). Sessions that have never been validated are rejected.

**Consequence:** Users continue browsing invoices, viewing tickets, checking hosting status. The trade-off is that if an account is disabled on Platform *during* the outage, Portal has no way to know and continues granting access until the next successful validation.

## Decision

PRAHO adopts **Option B: Fail-Open** with bounded safeguards.

The fail-open applies **only** to `PlatformAPIError` (network failures: connection refused, timeout, DNS failure). Unexpected `Exception` types (programming bugs) **always fail closed** — a logic error must never silently grant access.

### Safeguards

| Safeguard | Bound | Mechanism |
|-----------|-------|-----------|
| **Hard TTL deadline** | 6 hours | `HARD_TTL_GRACE = 21600`. After 6 hours past the last successful validation, `validate_customer_with_timing` returns `False` unconditionally — no Platform call attempted, no fail-open possible. User is force-logged-out. |
| **No metadata update** | Next request | When failing open, `validated_at` and `next_validate_at` are **not updated**. The very next request re-enters the validation path and retries the Platform call. Fail-open does not grant a free 10-minute window. |
| **Independent session security** | 1 hour idle / IP+UA binding | `SessionSecurityMiddleware` (separate middleware, `apps.common.middleware`) enforces a 1-hour activity timeout and IP/User-Agent fingerprint binding. It fails **closed** on all exceptions, including its own bugs. |
| **Error type split** | Immediate | `except PlatformAPIError` → fail open. `except Exception` → fail closed. This ensures only infrastructure failures (not code bugs) trigger the open path. |
| **Thundering herd protection** | 30s lock | `cache.set(f"validating:{customer_id}", ...)` single-flight lock prevents concurrent validation storms during recovery. |

### Accepted Risk

If a customer account is **disabled or deleted on Platform** while Platform is simultaneously **unreachable from Portal**, that customer retains access for up to 6 hours (hard deadline) or 1 hour (idle timeout), whichever comes first.

This requires two simultaneous conditions:
1. The account is actively being disabled (administrative action)
2. Platform is unreachable from Portal at that exact moment

In practice, account disablement is a staff action performed on Platform. If Platform is down, staff cannot disable accounts either. The risk window is therefore limited to the scenario where Platform becomes unreachable *after* the disable action but *before* Portal's next validation — a narrow race condition.

### Why Not a Circuit Breaker?

A circuit breaker would add:
- Local state tracking (open/closed/half-open) per endpoint
- Configuration complexity (thresholds, timeouts, recovery probes)
- A dependency on shared state (cache or in-memory) for the circuit status

For a single validation endpoint with 10-minute jittered intervals, the existing stale-while-revalidate pattern with hard TTL provides equivalent protection with less complexity. If PRAHO scales to multiple Platform API dependencies, a circuit breaker should be reconsidered.

## Implementation

### Code Location

`services/portal/apps/users/middleware.py` — `PortalAuthenticationMiddleware._perform_validation()`

```python
except PlatformAPIError as e:
    logger.error(f"🔥 [Auth] Platform API error during validation for {customer_id}: {e}")
    logger.info(f"🛡️ [Auth] Failing open for customer {customer_id} due to API unavailability")
    return True  # praho-security: ignore[PRAHO-006] — ADR-0017 fail-open strategy

except Exception as e:
    logger.error(f"🔥 [Auth] Unexpected validation error for {customer_id}: {e}", exc_info=True)
    # Fail CLOSED for unexpected errors (programming bugs should not grant access)
    return False
```

### Scanner Suppression

The PRAHO security scanner (rule PRAHO-006) detects `return True` inside `except` blocks in middleware files as a potential fail-open vulnerability. This specific instance is suppressed with an inline `# praho-security: ignore[PRAHO-006]` comment referencing this ADR.

### Observability

All fail-open events are logged at two levels:
- `ERROR` — the Platform API failure itself (with exception details)
- `INFO` — the fail-open decision (with customer ID)

These log lines can be monitored to detect prolonged Platform outages affecting Portal authentication.

## Consequences

### Positive
- Customers experience zero disruption during brief Platform maintenance (deploys, restarts)
- Portal availability is decoupled from Platform availability for already-authenticated users
- No additional infrastructure (Redis, circuit breaker library) required

### Negative
- Disabled accounts may retain access for up to 6 hours during Platform outages (accepted risk)
- Fail-open events must be monitored — silent Platform degradation could go unnoticed without alerting

### Neutral
- New customer logins still fail during Platform outages (no way to verify credentials without Platform)
- The pattern is well-documented and scanner-suppressed, reducing confusion for future developers

---

## Addendum: the `session_key` trap

The safeguards described above are enforced by `SessionSecurityMiddleware`. An earlier
version of that middleware guarded on `request.session.session_key`, which silently disabled
every check under a session backend that keeps no server-side record. The guard is now
backend-agnostic (see Decision below); this addendum records the failure mode so it is not
reintroduced.

### The trap

`django.contrib.sessions.backends.signed_cookies` always returns `session_key = None`,
because there is no server-side session record. Middleware that guards on that value exits
before running any check:

```python
if not request.session.session_key:  # Always None under signed_cookies
    return None  # Skips ALL security checks
```

With such a guard, every safeguard in the table above goes inert under that backend — IP
address fingerprinting and change detection, User-Agent fingerprint binding, the 1-hour
activity timeout, and session activity tracking. Nothing errors and nothing logs: the
middleware simply stops doing its job, so the failure is invisible to any test that exercises
the checks rather than their activation.

### Root cause

`session_key` is a Django `SessionBase` property that returns the unique server-side
identifier for a session. For DB/cache backends this is a random 32-character string.
For the `signed_cookies` backend, there is no server-side record, so `session_key` is
always `None`. Code that branches on `session_key` truthiness silently changes behavior
when the session backend is switched.

### Decision

1. **Session backend**: all environments (base, dev, prod) pin
   `django.contrib.sessions.backends.db`, backed by the existing `portal.sqlite3` file,
   so a real `session_key` exists for every security check.

2. **Defensive guard**: `SessionSecurityMiddleware` guards on
   `"user_id" not in request.session` rather than on `session_key` truthiness, which makes
   it backend-agnostic and removes the silent-bypass mode entirely.

3. **Cart rate limiting** and **order idempotency** key on `user_id`, not `session_key`,
   for the same reason.

4. **Tests**: `tests/common/test_session_backend.py` asserts that `session_key` is non-None
   after login and that `SessionSecurityMiddleware` activates for authenticated sessions —
   testing the control's *activation*, not just its correctness, which is what this class of
   defect requires.
