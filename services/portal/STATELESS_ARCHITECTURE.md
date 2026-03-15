# Portal Stateless Architecture

## Architectural Principle

**The Portal service has no business data.** All domain data (users, customers,
invoices, orders, services) lives in the Platform database and is accessed via
HMAC-signed API calls (ADR-0032).

Portal does maintain **infrastructure state** — Django sessions in a local
SQLite file — which is auth/UX plumbing, not business state. Losing
`portal.sqlite3` forces users to re-login but loses no business data.

## What "Stateless" Means Here

| Category | Portal has it? | Notes |
|----------|:-:|-------|
| Business models (User, Customer, Invoice, …) | No | All in Platform's PostgreSQL |
| Django ORM migrations | No | Session table is created by `django.contrib.sessions` |
| Redis / shared cache | No | LocMemCache only (per-process, accepted tradeoff) |
| Cross-service shared state | No | Portal ↔ Platform via HMAC HTTP only |
| **Session storage (SQLite)** | **Yes** | Server-side DB sessions for security middleware |
| **`django.contrib.sessions`** | **Yes** | Required for auth, cart, rate limiting |
| **`django.contrib.messages`** | **Yes** | User feedback on login/checkout flows |
| **CSRF protection** | **Yes** | Required for POST forms (login, checkout, tickets) |

## Why Server-Side Sessions (Not Signed Cookies)

Portal originally used `signed_cookies` for sessions to stay fully stateless.
This was changed to `django.contrib.sessions.backends.db` after discovering
that signed-cookie sessions silently disabled critical security controls:

1. **`session_key` is always `None`** under signed cookies — this bypassed
   `SessionSecurityMiddleware` (IP fingerprinting, session timeout, activity
   tracking) which ADR-0017 relies on as a safety net.
2. **Cookie size risk** — portal stores 25-40 session keys (cart, memberships,
   account health). Exceeding the 4KB browser cookie limit causes silent
   session loss.
3. **No server-side revocation** — signed cookies cannot be invalidated on
   logout; a stolen cookie remains valid for up to 30 days.
4. **OWASP and Fortify** classify signed-cookie sessions as a "Bad Practice"
   for auth state.

Server-side SQLite sessions fix all four issues while keeping the portal free
of business data. See ADR-0017 addendum for the full incident writeup.

## Data Flow

```
Customer Browser → Portal (:8701) → Platform API (:8700) → PostgreSQL
                      ↓
                 Templates + Views
                      ↓
                 Rendered HTML

Session state: portal.sqlite3 (django_session table only)
```

## Portal Service Structure

```
services/portal/
├── apps/
│   ├── api_client/     # Platform API communication (HMAC-signed)
│   ├── users/          # Login/logout, session management, customer switching
│   ├── dashboard/      # Customer dashboard views
│   ├── billing/        # Billing display (via API)
│   ├── orders/         # Cart, checkout, payment flows
│   ├── services/       # Service management UI
│   ├── tickets/        # Support ticket interface
│   ├── ui/             # Template tags and components
│   └── common/         # Middleware, rate limiting, validators (no models)
├── templates/          # Customer-facing templates
├── static/             # CSS, JS, images
├── config/             # Django settings
├── portal.sqlite3      # Session storage only (no business data)
└── locale/             # i18n translations (RO/EN)
```

## Key Invariants

1. **No business models** — portal apps must never define Django ORM models
2. **No Platform imports** — portal must never import from platform apps
3. **No direct database queries** — all domain data via Platform API
4. **Session = infrastructure** — losing sessions forces re-login, not data loss
5. **LocMemCache = per-worker** — rate limit counters are not shared across
   gunicorn workers (accepted tradeoff for no-Redis constraint)

## Benefits

1. **Security**: No business data to compromise locally
2. **Consistency**: Single source of truth (Platform database)
3. **Deployment**: Portal can restart; users just re-login
4. **Worker scale**: Add gunicorn workers on the same host (SQLite WAL handles
   concurrent reads). Multi-instance scale requires shared session storage (Redis
   or PostgreSQL) — not currently supported.
5. **Clear separation**: Domain logic in Platform, presentation in Portal

---

**Updated**: March 2026 — switched from signed-cookie to DB sessions (see ADR-0017 addendum)
