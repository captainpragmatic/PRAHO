# ADR-0031: API Token Authentication Strategy

**Status:** Accepted (partial — Gap 7 web UI remaining)
**Date:** 2026-03-06 (updated 2026-03-31)
**Authors:** Development Team
**Related:** ADR-0017 (Portal Auth Fail-Open), ADR-0024 (User Role Clarification)
**Gap tracking:** [Issue #77 — close ADR-0031 token authentication gaps](https://github.com/captainpragmatic/PRAHO/issues/77)

---

## Context

PRAHO Platform exposes a REST API on `:8700`. Three distinct consumers need to authenticate
against it:

| Consumer | Mechanism | Status |
|----------|-----------|--------|
| Portal service (backend) | HMAC-signed `X-User-Context` requests | Production-ready |
| Platform web UI (staff) | Django session cookies | Production-ready |
| Scripts, CLI tools, automation | DRF opaque bearer tokens | Partial — gaps documented below |

This ADR covers the third category: **API token authentication for direct API consumers**
such as operator scripts, future CLI tools, and future mobile clients.

---

## What Exists Today

### Endpoints

Three endpoints are registered at `services/platform/apps/api/users/urls.py`:

```
POST   /api/users/token/        obtain_token   — exchange credentials for a token
DELETE /api/users/token/revoke/ revoke_token   — delete the caller's own token
GET    /api/users/token/verify/ verify_token   — ⚠️  broken for token consumers (see gaps)
```

### Token Model

Uses DRF's built-in `rest_framework.authtoken.Token`:

```python
class Token(models.Model):
    key     = CharField(max_length=40, primary_key=True)  # 40-char hex, stored plaintext
    user    = OneToOneField(User)                          # one token per user, ever
    created = DateTimeField(auto_now_add=True)
```

### `obtain_token` — What Works

- Accepts `POST` with `{"email": "...", "password": "..."}` body
- Calls `authenticate()` — runs through Django auth backends
- Integrates with account lockout: increments `User.failed_login_attempts` on failure,
  resets on success, rejects if `user.is_account_locked()` returns `True`
- Throttled at 5 requests/minute via `AuthThrottle(AnonRateThrottle)`
- Returns `{"token": "<key>", "user_id": <id>, "email": "<email>"}`
- Logs authentication events with masked email (`_mask_email()`)

### `revoke_token` — What Works

- Accepts `DELETE` only (405 on any other verb)
- Requires `Authorization: Token <key>` header (`TokenAuthentication + IsAuthenticated`)
- Deletes `request.auth` — the token that authenticated the request
- Self-revocation only: the body is ignored; you cannot revoke another user's token
- No throttle (low risk — requires a valid token to call)

### How to Use Today (Script / CLI)

```bash
# 1. Obtain token (use a dedicated service-account staff user, minimal role)
TOKEN=$(curl -s -X POST https://platform.example.com/api/users/token/ \
  -H "Content-Type: application/json" \
  -d '{"email":"automation@pragmatichost.com","password":"<password>"}' \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['token'])")

# 2. Make authenticated requests
curl -H "Authorization: Token $TOKEN" \
  https://platform.example.com/api/customers/search/?q=test

# 3. Revoke when done
curl -X DELETE https://platform.example.com/api/users/token/revoke/ \
  -H "Authorization: Token $TOKEN"
```

---

## Known Gaps (As of 2026-03-06)

These are not blocking for simple internal scripts today, but are required before
offering API token access to external parties or building a multi-script automation layer.

### Gap 1 — `verify_token` is broken for token consumers (CRITICAL)

`GET /api/users/token/verify/` is decorated with `@require_customer_authentication`,
which expects HMAC-signed portal context headers. A client calling this endpoint with
`Authorization: Token <key>` receives a 401/403 because the decorator never sees a
token — it looks for HMAC headers that do not exist in a standard token request.

**A CLI tool cannot verify its own token via this endpoint.**

The endpoint was built for the portal (HMAC consumer), not for token consumers. Its
presence at `token/verify/` is misleading. Fix: add a separate token-auth-gated
`GET /api/users/token/me/` endpoint that accepts `TokenAuthentication` and returns
caller identity.

### Gap 2 — No token expiry

DRF's `Token` model has a `created` field but no `expires_at`. Tokens are valid
indefinitely until explicitly revoked. A token issued today is still valid in 5 years.

Industry standard is short-lived access tokens (hours to days) with optional rotation.
For internal scripts, a 90-day rolling expiry with a warning at 80 days is a reasonable
baseline.

### Gap 3 — No `last_used_at` tracking

No field records when a token was last used. This means:
- Impossible to detect stale tokens (issued but never used, or used years ago)
- No basis for automatic expiry of inactive tokens
- No audit trail at the token level (only at the request level via logs)

### Gap 4 — One token per user (OneToOneField)

DRF's model enforces a single token per `User`. You cannot have separate tokens for:
- `laptop-cli` vs `ci-pipeline` vs `monitoring-script`
- Revoking one without revoking all
- Different expiry windows per purpose

This is the most significant architectural limitation. A multi-device or multi-script
deployment cannot be managed safely with this model.

### Gap 5 — Tokens stored in plaintext

The `key` field is the primary key and is stored as-is in the database. A database
dump or `SELECT * FROM authtoken_token` exposes all active tokens immediately.

Mitigation today: the `authtoken` table should be treated as sensitive as the `users`
password hash table. Row-level access controls, backup encryption, and audit logging on
reads apply.

Long-term fix: hash tokens at rest (store `sha256(key)`, return the raw key only once
at creation). This is what `django-rest-knox` does by default.

### Gap 6 — No token name or description

Tokens have no label. When a user has multiple tokens (after Gap 4 is fixed), there is
no way to know which one belongs to which script or device.

### Gap 7 — No web UI for token management

There is no page in the platform staff interface where a user can:
- See their active tokens
- Create a new token (without calling the API directly)
- Revoke a specific token
- See when a token was last used

The only way to manage tokens today is via `curl` or the Django shell.

### Gap 8 — `Authorization: Token` vs RFC 6750 `Bearer`

RFC 6750 specifies the `Authorization: Bearer <token>` scheme for bearer tokens.
DRF uses `Authorization: Token <token>` by default. These are functionally identical
but syntactically non-standard. Any tooling that hard-codes RFC 6750 `Bearer` will
fail against the PRAHO API.

This is a cosmetic gap — not a security issue — but worth noting if PRAHO ever
exposes a public API that external developers expect to be RFC-compliant.

---

## Decision

### Implemented: Custom `APIToken` model (replaces DRF authtoken)

As of 2026-03-31, DRF's `rest_framework.authtoken.Token` has been replaced by a custom
`APIToken` model in `apps/users/models.py` with a `HashedTokenAuthentication` backend
in `apps/api/users/authentication.py`. No external dependencies were added.

**What changed:**

| Capability | Before (DRF authtoken) | After (APIToken) |
| ---------- | ---------------------- | ---------------- |
| Tokens per user | 1 (OneToOneField) | Multiple (ForeignKey), capped by `API_TOKEN_MAX_ACTIVE_PER_USER` (default 20) |
| Storage | Plaintext | SHA-256 hashed |
| Expiry | None | Default 90-day TTL (`API_TOKEN_DEFAULT_TTL_DAYS`); callers may shorten via `ttl_days`, clamped to `API_TOKEN_MAX_TTL_DAYS` (365) — only the server default can select "no expiry" |
| Usage tracking | None | `last_used_at` (throttled to 5-min intervals, condition evaluated in SQL) |
| Token naming | None | `name` (API) + `description` (model field, not yet API-exposed) |
| Auth header | `Token` only | `Bearer` and `Token`; malformed recognized schemes fail closed |
| Auth failures | Token state exposed | One generic response for unknown, expired, and disabled-user tokens |
| Raw key visibility | Always readable | Shown once at creation, never stored |
| Audit trail | None | `api_token_created` / `api_token_deleted` audit events on every create/delete path (ADR-0016) |

**Operating constraints (still apply):**

1. **Use a dedicated service-account `User`** per script/integration with the minimum
   `staff_role` needed. Never use a personal staff account's token in automation.
2. **Expiry is on by default** (90 days). Pass `ttl_days` to shorten it for CI/CD or
   temporary automation; callers cannot opt out of expiry.
3. **Store tokens in secrets management** (environment variables, a vault) — never
   hardcode in scripts or commit to version control.
4. **Expired tokens are purged automatically** — the `user-api-token-purge` Django-Q
   schedule runs `purge_expired_api_tokens` daily at 3 AM; the `purge_expired_tokens`
   management command remains for manual runs.
5. **The active-token cap is deployment policy** — `API_TOKEN_MAX_ACTIVE_PER_USER`
   defaults to 20 and is startup-validated with the two TTL settings.

### Global authenticator interaction with HMAC / public endpoints

`HashedTokenAuthentication` is a **default** authenticator (`DEFAULT_AUTHENTICATION_CLASSES`),
so DRF runs it before the view body on every `@api_view`. Because it fails closed on a
recognized-but-malformed `Bearer`/`Token` header, an endpoint that performs its own
authentication (HMAC via `@require_customer_authentication` / `@require_portal_authentication`,
or credential/public endpoints) would be rejected before its own auth runs if a caller sent
a stray or invalid `Authorization` header. Every such endpoint therefore declares
`@authentication_classes([])`, opting out of DRF-level authentication so its dedicated
mechanism is authoritative. `tests/api/test_api_token_auth.py::StrayAuthorizationHeaderTests`
locks this in; the CI auth-coverage test (`public_api_endpoint` marker) enforces that every
API view has an explicit auth posture.

### Remaining: Gap 7 (web UI for token management)

A staff-facing page at `/app/settings/api-tokens/` is not yet implemented. Token
management is currently API-only. This is tracked separately and is not blocking.

---

## RFC and Industry Standard Compliance Assessment

| Standard | Requirement | Status |
| -------- | ----------- | ------ |
| RFC 6750 (Bearer Tokens) | `Authorization: Bearer <token>` header | **Compliant** — accepts both `Bearer` and `Token` |
| RFC 6749 (OAuth 2.0) | Short-lived access tokens, refresh flow | Partial — default 90-day TTL, no refresh flow |
| RFC 6819 (OAuth Threat Model) | Token binding, expiry, rotation | Partial — default expiry, rotation via revoke+create |
| OWASP API Security Top 10 | Broken Auth (API2) — token expiry, rotation | **Compliant** — hashed storage, default expiry, scheduled purge |
| General practice | Hash tokens at rest | **Compliant** — SHA-256 hashed |
| General practice | Per-device token isolation | **Compliant** — multiple tokens per user |
| General practice | Audit trail (last_used_at) | **Compliant** — `last_used_at` tracked |

---

## Consequences

### Positive

- SHA-256 hashed storage — DB dump does not expose tokens
- Multiple tokens per user — per-script revocation without affecting other consumers
- Default expiry — every issued token is time-bounded unless the server explicitly opts out
- `last_used_at` tracking — stale tokens are detectable
- Both `Bearer` and `Token` auth headers accepted — RFC 6750 compliant
- No external dependencies — pure Django/DRF implementation
- Token issuance input is validated (`name`, `ttl_days`) — malformed requests get 400s,
  and names cannot inject control characters into security logs
- Token lifecycle reaches the immutable audit trail (ADR-0016)
- Account lockout integration preserved from original implementation

### Negative

- No web UI for token management (Gap 7 — tracked separately)
- Raw token shown only once at creation — if lost, must create a new one

### Migration note
The cutover is a **clean break**: no data migration carries DRF `authtoken_token`
rows into `APIToken`. No environment held live DRF tokens at cutover time, and
copying them would have re-created the plaintext-at-rest exposure (the raw keys
would remain in `authtoken_token`) while making the copies unreachable by TTL
enforcement. Any consumer that did hold a legacy token obtains a fresh one via
`POST /api/users/token/`. Because the platform is pre-release with no such data
anywhere, `rest_framework.authtoken` was **removed from `INSTALLED_APPS`
entirely** rather than kept for migration-history consistency — nothing in the
repo depends on the `authtoken` app or its models, so fresh databases simply
never create its tables. No portal code is affected (portal does not use token
auth).

---

## Gap Closure Log

| Gap | Description | Status | Closed by |
| --- | ----------- | ------ | --------- |
| 1 | `verify_token` broken for token consumers | Closed | `GET /api/users/token/me/` endpoint (prior work) |
| 2 | No token expiry | Closed | Default 90-day TTL on issuance, `HashedTokenAuthentication` expiry check, daily scheduled purge; startup checks (`security.E062/E063/E064`) keep issuance policy coherent |
| 3 | No `last_used_at` tracking | Closed | `APIToken.last_used_at` field, updated at 5-min intervals (SQL-side condition) |
| 4 | One token per user (OneToOneField) | Closed | `APIToken` uses `ForeignKey(User)` — multiple tokens, capped by `API_TOKEN_MAX_ACTIVE_PER_USER` (default 20) |
| 5 | Tokens stored in plaintext | Closed | SHA-256 hashed via `APIToken.key_hash`; raw key shown once; no plaintext rows carried over (clean-break cutover) |
| 6 | No token name or description | Closed | `APIToken.name` settable via API; `description` exists on the model (API/UI exposure lands with Gap 7) |
| 7 | No web UI for token management | **Open** | Not yet implemented |
| 8 | `Authorization: Token` vs RFC 6750 `Bearer` | Closed | `HashedTokenAuthentication` accepts both schemes |
