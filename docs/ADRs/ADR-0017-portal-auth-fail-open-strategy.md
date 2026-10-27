# ADR-0017: Portal Sessions and Authentication Fail-Open

**Status:** Accepted
**Date:** 2026-02-28
**Revised:** 2026-10-28 (rewritten to match the code; session policy added)
**Authors:** Development Team
**Related:** ADR-0004 (Custom 2FA), ADR-0032 (Dual HMAC), ADR-0050 (Portal Infrastructure Tables),
ADR-0055 (Portal Sessions Merge Concurrent Writes), ADR-0058 (Pending TOTP Enrolment)

This ADR owns every decision about the customer's portal session: where it lives, what binds it to
the customer, how it is validated, what happens when Platform is unreachable, and how long it lasts.

## Context

PRAHO runs two services. Platform (`:8700`, PostgreSQL) owns every business record. Portal (`:8701`)
is the customer-facing service and **holds no business data**: customers, users, invoices, orders,
services and tickets reach it only through HMAC-signed calls to Platform (ADR-0032).

Portal does hold disposable, per-visitor state in its local SQLite file, `portal.sqlite3`: the
server-side sessions described here and the counter table of ADR-0050. A session row is a live
credential for its customer until it expires or its binding changes, so the file is treated as a
credential store: owner-only permissions, never backed up. Losing it logs everyone out and loses
nothing else. `services/portal/PORTAL_STATE.md` describes that state and what enforces the invariant.

Platform holds the credential each portal session is bound to, and the portal re-checks it
periodically. The original question of this ADR still stands: what should the portal do when it
cannot reach Platform to re-check?

## Decision

### 1. Where the session lives

- Server-side sessions in `portal.sqlite3`, through `apps.common.session_store`, Django's database
  session store with merge-on-save (ADR-0055). Signed-cookie sessions were tried first and rejected
  (History).
- Logout deletes the session row on the portal. Platform is not told (see the gaps in section 5).
- `portal.sqlite3` is never backed up.

### 2. What binds a session to the customer

- Login (`POST /api/users/login/`) returns `session_auth_hash`, Django's session hash over the
  password and, once the customer's 2FA state has changed, the MFA credential version
  (`User._get_session_auth_hash`, ADR-0004). The portal keeps it in the session's identity key group
  (ADR-0055) and sends it with every validation.
- A password change or reset, or any 2FA enable or disable, changes the hash, so every portal session
  of that customer is refused at its next validation. A password change made through the portal
  stores the new hash in the session that made it, so that session continues.
- Platform also accepts a hash computed under `SECRET_KEY_FALLBACKS` and returns the current one, so
  rotating the secret key logs nobody out.

### 3. Validation and fail-open, as implemented

`PortalAuthenticationMiddleware` (`services/portal/apps/users/middleware.py`) calls
`POST /api/users/session/validate/` on this schedule:

| Step | Behaviour |
|------|-----------|
| Schedule | Every 600 s plus 0-120 s of jitter (`REVALIDATE_EVERY`, `JITTER_MAX`). A session with no validation record or no binding validates on its next request; login records none, so the first request after login validates. |
| Soft grace | Up to 300 s past due (`SOFT_TTL_GRACE`), one request per session validates under a single-flight lease (the longest Platform call plus 5 s) while the session's other requests continue. |
| Hard deadline | 6 h after the scheduled validation (`HARD_TTL_GRACE`, counted from `next_validate_at`), the session ends without calling Platform. |
| Authoritative denial | A 401 or 403 whose body says `"active": false` ends the session at once. |
| Fail-open | Any other `PlatformAPIError` (a transport error, a 5xx, a 429, a 401 or 403 without `"active": false` such as an HMAC fault) lets the request through. Nothing is recorded, so the next request tries again. |
| Breaker | Each fail-open increments `auth:fail_open:{user_id}` in the counter table, with a one-hour window; the fifth ends the session (`_MAX_FAIL_OPEN_COUNT = 5`). If the counter store itself fails, access is denied. A successful validation resets the breaker. |
| Programming errors | Any other exception fails closed. |

In plain terms: during a Platform outage an authenticated customer gets about four more requests in
the hour before being logged out. Pages need Platform for their data anyway, so fail-open smooths
over brief faults (a restart, a slow call); it does not keep customers working through a long outage.
New logins fail whenever Platform is unreachable.

### 4. Session checks that do not depend on Platform

`SessionSecurityMiddleware` (`services/portal/apps/common/middleware.py`) runs on every authenticated
request and fails closed on any error:

- idle timeout 1 h (`SESSION_TIMEOUT_SECONDS`), with the activity stamp written at most every 60 s;
- absolute limit 8 h (`MAX_SESSION_AGE_SECONDS`), counted from the first request after login;
- binding to the IP address and the user agent seen on that first request (`IP_CHANGE_TOLERANCE = False`);
- it decides whether a session is authenticated from `user_id` in the session, never from
  `session_key` (History).

The authentication middleware separately ends a session 24 h after login, or 30 days with
"remember me" (`SESSION_COOKIE_AGE_DEFAULT`, `SESSION_COOKIE_AGE_REMEMBER_ME`); the 8 h limit above
ends every session first.

### 5. Session policy (decided 2026-10-28)

Session lifetimes follow NIST SP 800-63B-4 (Sec. 2.1.3 and 2.2.3) and the OWASP Session Management
Cheat Sheet. The same policy applies in PRAHO and appstractor-platform, and a change to it lands in
both.

| Tier | Who | Absolute | Idle | Browser cookie | NIST SP 800-63B-4 |
|------|-----|----------|------|----------------|-------------------|
| `standard` | "Remember me" unticked, and every staff account | 24 h | 1 h | Ends with the browser | AAL2: overall <= 24 h, inactivity <= 1 h |
| `remember` | "Remember me" ticked, customers only | 30 days | 7 days | Kept 30 days | AAL1: overall <= 30 days, inactivity optional |

Rules that apply to both tiers:

- **Sensitive actions need fresh proof.** Changing members or roles, contact details, the legal or
  tax identity, revealing gift-card codes or exporting personal data requires a password check (plus
  the second factor when enabled) within the last 300 s. A login counts as that check. This is what
  makes the AAL1 tier acceptable: a customer may browse for weeks, but cannot change what matters
  without proving it is them.
- **Only the customer's own activity extends the idle limit.** NIST resets the inactivity timeout on
  "activity from the subscriber"; background calls do not count.
- **Without "remember me" the cookie ends with the browser.** OWASP advises non-persistent cookies
  when authentication need not persist across browser sessions. Platform still enforces every limit,
  because browsers that restore sessions can keep such cookies.
- **Sessions are bound to the browser, not the IP address.** A network change (mobile data to Wi-Fi,
  home to office) keeps the session; a different user agent ends it.
- **A credential change keeps the session that made it and ends every other one.**
- **Platform owns the policy and enforces it server-side.** OWASP requires server-side enforcement of
  timeouts; the portal follows the deadlines Platform returns and computes none of its own.

Why these numbers: 24 h with 1 h of inactivity is NIST's current limit for AAL2, the level a password
plus TOTP login reaches, and the strongest-backed choice for a normal session. 30 days with no
required inactivity limit is NIST's AAL1; it is offered only because the 300 s re-check guards every
sensitive action. OWASP's cheat sheet suggests stricter values for high-value applications (idle
2-5 min, absolute 4-8 h); NIST's current revision is followed instead, with the re-check as the
compensating control.

**Gap until the implementation lands.** This list is removed when the code does what section 5 says:

- every session ends after 8 h (section 4), so "remember me" does not last longer;
- sessions are still bound to the IP address;
- the cookie of a standard session persists for 24 h;
- there is no 300 s re-check on sensitive actions;
- every request extends the idle limit;
- Platform cannot end a portal session without a credential change, and logout does not reach Platform.

### Accepted risk

If a customer account is disabled on Platform while Platform is unreachable from the portal, the
customer keeps access until the breaker trips (about four requests) or the hard deadline passes,
whichever comes first. Disabling an account needs Platform to be up, so the exposure is the race
between a disable and an outage that starts right after it.

## Consequences

### Positive
- A Platform restart or a slow call does not log customers out.
- A credential change ends every other session of that customer within one validation interval
  (about 12 minutes).
- The portal holds no business data, so a portal compromise exposes sessions, not records.

### Negative
- During a real outage customers are logged out after a few requests.
- A session row is a credential; the portal's SQLite file must be protected accordingly.
- Until section 5 is implemented, Platform cannot end a single session, and logout is portal-local.

### Neutral
- Fail-open events are logged: the Platform error at ERROR, each fail-open decision at INFO with the
  breaker count, a tripped breaker at WARNING.

## History

- **2026-02-28.** First decision. The portal was then described as "fully stateless — no database,
  no local user store", used signed-cookie sessions, and the ADR promised continued access for up to
  6 h during an outage, a 30 s lock per customer, and no circuit breaker.
- **Signed cookies replaced by database sessions.** Under signed cookies `session_key` is always
  `None`, and `SessionSecurityMiddleware` guarded on it, so every check it runs (IP and user-agent
  binding, the idle timeout, activity tracking) was silently off. The guard now reads `user_id`,
  cart rate limits and order idempotency key on `user_id`, and
  `services/portal/tests/common/test_session_backend.py` asserts that the checks activate.
- **#130.** A per-user fail-open breaker was added; the original "why not a circuit breaker" reasoning
  no longer applies.
- **2026-09.** Sessions were bound to `session_auth_hash`; credential changes revoke sessions at the
  next validation. #549 (2026-09-28) then narrowed the immediate denial to an explicit
  `"active": false`, so an HMAC fault falls under the bounded breaker instead of logging every
  customer out.
- **2026-09 / 2026-10.** The counter table (ADR-0050) and merge-on-save sessions (ADR-0055) were added.
- The scanner rule PRAHO-006 and its inline suppression, which an earlier version cited here, no
  longer exist.
- **2026-10-28.** Rewritten to describe the code as it is, "stateless" replaced by "holds no business
  data", and the session policy of section 5 recorded.
