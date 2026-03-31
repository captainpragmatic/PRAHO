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
| Tokens per user | 1 (OneToOneField) | Unlimited (ForeignKey) |
| Storage | Plaintext | SHA-256 hashed |
| Expiry | None | Optional `expires_at` |
| Usage tracking | None | `last_used_at` (throttled to 5-min intervals) |
| Token naming | None | `name` + `description` fields |
| Auth header | `Token` only | `Bearer` and `Token` |
| Raw key visibility | Always readable | Shown once at creation, never stored |

**Operating constraints (still apply):**

1. **Use a dedicated service-account `User`** per script/integration with the minimum
   `staff_role` needed. Never use a personal staff account's token in automation.
2. **Set `expires_at`** for tokens used in CI/CD or temporary automation.
3. **Store tokens in secrets management** (environment variables, a vault) — never
   hardcode in scripts or commit to version control.
4. **Run `purge_expired_tokens`** periodically to clean up expired tokens.

### Remaining: Gap 7 (web UI for token management)

A staff-facing page at `/app/settings/api-tokens/` is not yet implemented. Token
management is currently API-only. This is tracked separately and is not blocking.

---

## RFC and Industry Standard Compliance Assessment

| Standard | Requirement | Status |
| -------- | ----------- | ------ |
| RFC 6750 (Bearer Tokens) | `Authorization: Bearer <token>` header | **Compliant** — accepts both `Bearer` and `Token` |
| RFC 6749 (OAuth 2.0) | Short-lived access tokens, refresh flow | Partial — optional `expires_at`, no refresh flow |
| RFC 6819 (OAuth Threat Model) | Token binding, expiry, rotation | Partial — expiry supported, rotation via revoke+create |
| OWASP API Security Top 10 | Broken Auth (API2) — token expiry, rotation | **Compliant** — hashed storage, optional expiry |
| General practice | Hash tokens at rest | **Compliant** — SHA-256 hashed |
| General practice | Per-device token isolation | **Compliant** — multiple tokens per user |
| General practice | Audit trail (last_used_at) | **Compliant** — `last_used_at` tracked |

---

## Consequences

### Positive

- SHA-256 hashed storage — DB dump does not expose tokens
- Multiple tokens per user — per-script revocation without affecting other consumers
- Optional expiry — leaked tokens can be time-bounded
- `last_used_at` tracking — stale tokens are detectable
- Both `Bearer` and `Token` auth headers accepted — RFC 6750 compliant
- No external dependencies — pure Django/DRF implementation
- Existing tokens migrated via data migration — no consumer disruption
- Account lockout integration preserved from original implementation

### Negative

- No web UI for token management (Gap 7 — tracked separately)
- Raw token shown only once at creation — if lost, must create a new one
- `rest_framework.authtoken` still in INSTALLED_APPS for migration history

### Migration note
The `rest_framework.authtoken` app remains in `INSTALLED_APPS` because the data
migration (`0003_migrate_drf_tokens`) references it. It can be removed after
confirming all tokens have been migrated and the `authtoken_token` table is empty.
No portal code is affected (portal does not use token auth).

---

## Gap Closure Log

| Gap | Description | Status | Closed by |
| --- | ----------- | ------ | --------- |
| 1 | `verify_token` broken for token consumers | Closed | `GET /api/users/token/me/` endpoint (prior work) |
| 2 | No token expiry | Closed | `APIToken.expires_at` field + `HashedTokenAuthentication` expiry check |
| 3 | No `last_used_at` tracking | Closed | `APIToken.last_used_at` field, updated at 5-min intervals |
| 4 | One token per user (OneToOneField) | Closed | `APIToken` uses `ForeignKey(User)` — unlimited tokens |
| 5 | Tokens stored in plaintext | Closed | SHA-256 hashed via `APIToken.key_hash`; raw key shown once |
| 6 | No token name or description | Closed | `APIToken.name` + `APIToken.description` fields |
| 7 | No web UI for token management | **Open** | Not yet implemented |
| 8 | `Authorization: Token` vs RFC 6750 `Bearer` | Closed | `HashedTokenAuthentication` accepts both schemes |
