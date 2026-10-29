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
- Platform holds the session itself: a `PortalSession` row (`apps.users.portal_sessions`), opened at
  login. The portal keeps the row's id in its own session and sends it, inside the HMAC-signed body,
  with every call it makes for that customer (section 6).
- Logout ends the Platform row (`POST /api/users/session/end/`) and then deletes the portal's row.
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
| Hard grace | 6 h after the scheduled validation (`HARD_TTL_GRACE`, counted from `next_validate_at`), the portal asks Platform before the request goes on, without failing open: a live session continues, any error ends it. |
| Platform's deadlines | The portal keeps the tier, the end and the idle deadline Platform answers at login and at every validation. At the end, which never moves, the session ends without calling Platform. Once the stored idle deadline passes (a lower bound: the customer's activity moves Platform's without a validation), the portal asks Platform as at the hard grace, as a background call that never extends the idle deadline. |
| Authoritative denial | A 401 or 403 whose body says `"active": false` ends the session at once. |
| Fail-open | Any other `PlatformAPIError` (a transport error, a 5xx, a 429, a 401 or 403 without `"active": false` such as an HMAC fault) lets the request through. Nothing is recorded, so the next request tries again. |
| Breaker | Each fail-open increments `auth:fail_open:{user_id}` in the counter table, with a one-hour window; the fifth ends the session (`_MAX_FAIL_OPEN_COUNT = 5`). If the counter store itself fails, access is denied. A successful validation resets the breaker. |
| Programming errors | Any other exception fails closed. |

In plain terms: during a Platform outage an authenticated customer gets about four more requests in
the hour before being logged out, and never runs past the idle deadline Platform last gave. Pages need Platform for their data anyway, so fail-open smooths
over brief faults (a restart, a slow call); it does not keep customers working through a long outage.
New logins fail whenever Platform is unreachable.

### 4. Session checks that do not depend on Platform

`SessionSecurityMiddleware` (`services/portal/apps/common/middleware.py`) runs on every authenticated
request and fails closed on any error:

- binding to the browser that signed in: its family and operating system, without versions, stamped
  at login. A browser update keeps the session (the stored user agent is re-stamped); another browser
  or operating system ends it, and so does a session login did not stamp
  (`PORTAL_BROWSER_FINGERPRINT_REQUIRED`). A new network address never does;
- it decides whether a session is authenticated from `user_id` in the session, never from
  `session_key` (History).

It keeps no lifetime of its own: the session's deadlines are Platform's (sections 3 and 5).

### 5. Session policy (decided 2026-10-28)

Session lifetimes follow NIST SP 800-63B-4 (Sec. 2.1.3 and 2.2.3) and the OWASP Session Management
Cheat Sheet. The same policy applies in PRAHO and appstractor-platform, and a change to it lands in
both.

| Tier | Who | Absolute | Idle | Browser cookie | NIST SP 800-63B-4 |
|------|-----|----------|------|----------------|-------------------|
| `standard` | "Remember me" unticked, and every staff account | 24 h | 1 h | Ends with the browser | AAL2: overall <= 24 h, inactivity <= 1 h |
| `remember` | "Remember me" ticked, customers only | 30 days | 7 days | Kept until the session's end | AAL1: overall <= 30 days, inactivity optional |

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
  home to office) keeps the session, and so does a browser update; a different browser family or
  operating system ends it.
- **A credential change keeps the session that made it and ends every other one.**
- **Platform owns the policy and enforces it server-side.** OWASP requires server-side enforcement of
  timeouts; the portal follows the deadlines Platform returns and computes none of its own.

Why these numbers: 24 h with 1 h of inactivity is NIST's current limit for AAL2, the level a password
plus TOTP login reaches, and the strongest-backed choice for a normal session. 30 days with no
required inactivity limit is NIST's AAL1; it is offered only because the 300 s re-check guards every
sensitive action. OWASP's cheat sheet suggests stricter values for high-value applications (idle
2-5 min, absolute 4-8 h); NIST's current revision is followed instead, with the re-check as the
compensating control.

**Implemented (2026-10-29).**

- `apps/users/session_policy.py` on Platform is the only owner of each tier's lifetimes, a staff
  member's view as a customer (ADR-0065, 30 min with 10 min idle) included. A row whose tier it does
  not know ends, and a remembered row ends once its person becomes staff.
- The login sends "remember me" as a signed boolean (anything else is no); Platform opens the
  remembered tier only for a customer who asked.
- The portal signs in only with deadlines that can be Platform's (a known tier, aware times in the
  future, the idle deadline no later than the end, the end at most 30 days plus the clock difference
  Platform accepts away), keeps them, and follows them as section 3 describes. A browser session
  without them (one from before this release) ends once (`PORTAL_SESSION_DEADLINES_REQUIRED`).
- A standard session's cookie ends with the browser; a remembered one's lasts until Platform's end.
  Either way the portal's stored row expires at Platform's end.
- A page that makes no call to Platform does not extend the idle deadline; almost every portal page
  makes one.

### 6. Platform-owned sessions (implemented 2026-10-28)

- **Binding.** `PortalServiceHMACMiddleware` resolves the session a verified body names before any
  view runs, so the views that read the signed `user_id` themselves are bound like the decorated
  ones. A body the views could read differently from the middleware (not JSON, not an object,
  duplicate keys, a `user_id` outside its one spelling) is refused first.
- **Liveness.** A row is live while it is not revoked, both deadlines are in the future, the user is
  active, and its credential snapshot matches the user's session hash (or a `SECRET_KEY_FALLBACKS`
  hash, which is then promoted). A refusal answers `{"active": false}`, so the portal ends the
  browser session at once instead of counting it against the fail-open breaker.
- **Credential changes.** Every password or second-factor change moves the session hash, so it ends
  every other session at its next request, with no hook at each place a credential changes. The
  portal endpoints where customers change their own password or second factor re-stamp the calling
  session inside the same locked transaction.
- **Idle.** Only calls the customer makes extend the idle deadline, at most once a minute and never
  backwards; the portal marks its own revalidation calls as background.
- **Portal.** The session id is bound for the whole request, public routes included. A Platform
  refusal during a view ends the browser session even when the view caught the error. A browser
  session without a Platform session id (one from before this release) ends at its next request.
- **Operator revocation.** `manage.py revoke_portal_sessions` ends one person's sessions (`--user`),
  every session (`--all`), or every session live during a window (`--active-between`, by overlap, so
  quiet sessions are included), with one audit event naming the operator, the selector and the reason.
  The selection is taken when the command starts, so for an incident disable the account or reset its
  password first. A revoked session is refused at its next call to Platform or periodic validation: at
  most about 12 minutes while Platform is reachable; during an outage, the bounded fail-open of
  section 3 applies.
- **Deploying.** Deploy Platform with `PORTAL_SESSION_REQUIRED=false`, then Portal, then set it true
  (the default in production and staging). Roll back in the reverse order: set it false, roll Portal
  back, then Platform. A new Portal against an old Platform ends every login at once.

### 7. Fresh proof for sensitive actions (implemented 2026-10-29)

- **The window.** Each Platform session records when its identity was last checked (`reauth_at`).
  Login sets it, and an action counts the check as fresh from 0 to 300 s after it, both included; a
  missing or future time never counts.
- **The refusal.** A guarded view calls `apps.api.step_up.step_up_refusal` after its own owner and
  role checks and before it writes. Outside the window it answers `403 {"code": "reauth_required"}`,
  `no-store`, with no `active` key, so the portal never reads it as an ended session. A request
  with no bound session is refused as an ended one, whatever `PORTAL_SESSION_REQUIRED` says.
- **The check.** `POST /api/users/session/reauth/` takes the password and, when 2FA is on, the
  code. It locks the user, then the session, re-checks the session there, and checks both factors as
  login does: each failure counts toward the lockout and answers `reauth_failed`, a locked account
  is told so first, a 2FA account with no code is refused before its password is checked, and a
  spent second-factor budget answers 429. A window that cannot be recorded rolls the check back, so
  a backup code used for it stays unspent.
- **What is guarded.** Members and roles, the company's contact details and addresses, a change to
  an existing legal or tax identity (a first fill is free), the person's name or phone, a GDPR export
  request and its download, revealing a gift-card code, every change to what a hosted DNS zone
  publishes (confirming an import, switching name servers, deleting the zone, adding, changing or
  deleting a record), a request to upgrade, downgrade, suspend or cancel a service, and authorizing
  a saved card for automatic charges. Payments the portal can start all need the cardholder present;
  only that authorization lets a card be charged without them.
  `tests/api/test_step_up_inventory.py` lists every route under `api/` as guarded or exempt with a
  reason, and fails on a new one nobody has classified.
- **Portal.** The API client raises `StepUpRequiredError` and records it; once the view returns, the
  auth middleware sends the browser to `/confirm-identity/` with the page to come back to (HTMX gets
  `HX-Redirect`; a fetch that asks for JSON gets `403 {"error": "reauth_required", "redirect": …}`
  and goes there), and drops the messages the refused view queued. A session refusal in the same
  request still wins. The confirm page reads the 2FA state from Platform each time, and only a wrong
  answer spends the per-person re-auth budget.
- **Deploying.** After section 6 is deployed everywhere: Portal first (it handles a refusal it does
  not yet receive), then Platform. Every portal session open at the deploy ends once: none carries
  the browser stamp or Platform's deadlines yet.
- **Rolling back**, this section and the tiers of section 5 together, before rolling back section 6.
  An old Platform enforces neither the re-check nor the tiers, so no session the new one opened may
  outlive it:
  1. on the new Platform, run `manage.py revoke_portal_sessions --all --reason rollback` (the
     operator is recorded from the login name);
  2. roll Platform back;
  3. end any remembered row opened between steps 1 and 2, which the old code would honour for its
     30 days: `PortalSession.objects.filter(tier="remember", revoked_at__isnull=True)
     .update(revoked_at=now(), revoke_reason="operator")`;
  4. roll the Portal back. The users migration only widens the tier choices, so it stays.

Accepted: a compromised *running* portal sees passwords as customers type them, at login and on the
confirm page, so it can pass the re-check at will. Protecting against that needs a confirmation
outside the portal.

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
- Sensitive actions ask for the password again after 5 minutes, also within a long session.

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
- **2026-10-28.** Platform-owned sessions implemented (section 6). Lifetimes unchanged until the
  300 s re-check lands.
- **2026-10-29.** The 300 s re-check implemented (section 7).
