# Portal State: No Business Data

## The invariant

**The portal holds no business data.** Every customer, user, invoice, order, service and ticket
lives in Platform's database and reaches the portal only through HMAC-signed API calls (ADR-0032).
Nothing the portal stores is the authoritative copy of anything.

The portal does hold **disposable, per-visitor state** in one local SQLite file
(`portal.sqlite3`, path set by `SESSION_DB_PATH`):

| Table | Holds | Lives for | Decided in |
|-------|-------|-----------|------------|
| `django_session` (engine `apps.common.session_store`) | Each visitor's session: the identity binding (`user_id`, `session_auth_hash`), the selected company, cached memberships, the cart, account-health hints | The session | ADR-0017, ADR-0055 |
| `common_counters` | Rate-limit windows, replay and idempotency claims, the authentication fail-open breaker | Seconds to an hour | ADR-0050 |

*Disposable* means that deleting the file logs everyone out and resets the counters, and nothing
else is lost. *Sensitive* means that a session row is a live credential for its customer until it
expires or its binding changes. Treat the file as a credential store: owner-only permissions, never
backed up, never copied off the host.

## Why "stateless" was the wrong word

The portal started with signed-cookie sessions and no database, and the early ADRs called it
"fully stateless". It has since gained server-side sessions (ADR-0017), a counter table (ADR-0050)
and sessions that merge concurrent writes (ADR-0055). What never changed, and what the separation
exists for, is that it holds no business data. That is the invariant; "stateless" is not.

Server-side sessions replaced signed cookies because signed cookies:

1. **Switched off security checks silently.** `session_key` is always `None` under signed cookies,
   and `SessionSecurityMiddleware` used to skip every check when it was empty.
2. **Risked silent session loss.** The portal keeps 25-40 session keys (cart, memberships, account
   health), close to the 4 KB cookie limit.
3. **Could not be revoked.** Logout cannot invalidate a signed cookie; a stolen one stays valid until
   it expires.
4. **Are classed as bad practice for authentication state** by OWASP and Fortify.

## What enforces the invariant

- `services/portal/tests/common/test_portal_counter_sites.py` pins the portal's model inventory to
  exactly `sessions.Session` and `common.Counter`. A new table needs an ADR and a change to that test.
- `make test-portal` runs the portal without business database access, `make test-security` checks
  service isolation, and the pre-commit import checks refuse a Platform import in portal code.
- Portal CI fails if an external database driver appears in the portal's `pyproject.toml` or settings
  (`.github/workflows/portal.yml`).

## Rules for portal code

1. **No business models.** The only models are `sessions.Session` and `common.Counter`.
2. **No Platform imports.**
3. **No business data of record.** Data fetched from Platform may be cached in the session or in
   LocMemCache to render a page, never kept as the authoritative copy.
4. **Sessions are credentials.** Never log session keys or binding values (use the digest helpers);
   never back the file up.
5. **Shared counters live in `common_counters`.** LocMemCache is per worker and holds only legal
   documents, localisation data and validation leases.

## Data flow

```
Customer browser → Portal (:8701) → Platform API (:8700) → PostgreSQL
                      │
                      ├─ portal.sqlite3: django_session + common_counters (no business data)
                      └─ templates + views → rendered HTML
```

## Scaling

Sessions and counters live in one SQLite file per host (WAL mode), shared by every gunicorn worker
on that host. Several portal hosts would need shared session and counter storage; that is not
supported today.

## Service structure

```
services/portal/
├── apps/
│   ├── api_client/     # Platform API communication (HMAC-signed)
│   ├── users/          # Login/logout, session validation, customer switching
│   ├── dashboard/      # Customer dashboard views
│   ├── billing/        # Billing display (via API)
│   ├── orders/         # Cart, checkout, payment flows
│   ├── services/       # Service management UI
│   ├── tickets/        # Support ticket interface
│   ├── ui/             # Template tags and components
│   └── common/         # Middleware, rate limiting, session store, Counter model
├── templates/          # Customer-facing templates
├── static/             # CSS, JS, images
├── config/             # Django settings
├── portal.sqlite3      # Sessions and counters only (no business data, never backed up)
└── locale/             # i18n translations (RO/EN)
```

---

**Updated** 2026-10-28: renamed from `STATELESS_ARCHITECTURE.md`; describes the counter table
(ADR-0050) and the merge-on-save session store (ADR-0055); states the invariant as "no business data".
