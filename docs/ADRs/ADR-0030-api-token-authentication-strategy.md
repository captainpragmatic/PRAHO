# ADR-0030: API Token Authentication Strategy

**Status:** Accepted (partial — gaps documented, roadmap defined)
**Date:** 2026-03-06
**Authors:** Development Team
**Related:** ADR-0017 (Portal Auth Fail-Open), ADR-0024 (User Role Clarification)
**Gap tracking:** [Issue #77 — close ADR-0030 token authentication gaps](https://github.com/captainpragmatic/PRAHO/issues/77)

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

### Current: Use DRF authtoken for internal automation, with constraints

For scripts and internal tooling today, DRF authtoken is acceptable with these
operating constraints:

1. **Use a dedicated service-account `User`** per script/integration with the minimum
   `staff_role` needed. Never use a personal staff account's token in automation.
2. **Rotate tokens on a schedule** — even without enforced expiry, manually revoke and
   reissue tokens quarterly as a hygiene practice.
3. **Store tokens in secrets management** (environment variables, a vault) — never
   hardcode in scripts or commit to version control.
4. **One service account per independent consumer** — until Gap 4 is fixed, this is the
   only way to have isolated revocation.

### Near-term: Fix the two blocking gaps

**Gap 1 (`verify_token` broken)** and **Gap 7 (no web UI)** are the most user-facing.
Fix before any external or self-service token use.

Fix for Gap 1 — add a dedicated endpoint:

```python
@api_view(["GET"])
@authentication_classes([TokenAuthentication])
@permission_classes([IsAuthenticated])
def token_info(request: HttpRequest) -> Response:
    """Return identity of the token caller. Safe for CLI/script use."""
    user = cast(User, request.user)
    return Response({
        "user_id": user.id,
        "email": _mask_email(user.email),
        "staff_role": user.staff_role,
        "token_created": request.auth.created.isoformat(),
    })
```

Register at `GET /api/users/token/me/`.

### Long-term: Replace DRF authtoken with a proper multi-token model

When any of these conditions is true, replace DRF authtoken:
- A user needs more than one active token simultaneously
- Token expiry needs to be enforced programmatically
- Tokens need to be manageable via the web UI by end users

**Recommended library:** `django-rest-knox` — drops in as a DRF authentication class,
stores hashed tokens, supports multiple tokens per user, has configurable expiry and
`last_used` tracking. Migration path:

1. Install `knox`, add to `INSTALLED_APPS`, run migrations
2. Replace `TokenAuthentication` with `knox.auth.TokenAuthentication` in
   `DEFAULT_AUTHENTICATION_CLASSES`
3. Replace `obtain_token` and `revoke_token` views with knox equivalents
4. Migrate existing `authtoken_token` rows (one-time: create knox tokens for each
   active DRF token, notify owners to re-obtain)

---

## RFC and Industry Standard Compliance Assessment

| Standard | Requirement | Current Status |
|----------|-------------|----------------|
| RFC 6750 (Bearer Tokens) | `Authorization: Bearer <token>` header | Non-compliant — uses `Token` not `Bearer` |
| RFC 6749 (OAuth 2.0) | Short-lived access tokens, refresh flow | Not implemented — tokens do not expire |
| RFC 6819 (OAuth Threat Model) | Token binding, expiry, rotation | Partial — no expiry, no rotation |
| OWASP API Security Top 10 | Broken Auth (API2) — token expiry, rotation | Gap 2 and Gap 5 are relevant findings |
| General practice | Hash tokens at rest | Non-compliant — stored plaintext |
| General practice | Per-device token isolation | Non-compliant — one token per user |
| General practice | Audit trail (last_used_at) | Non-compliant — no tracking |

**For internal automation only, the current implementation is acceptable.** The gaps
above become blocking if PRAHO offers a public API, a developer portal, or token-based
access to external customers.

---

## Consequences

### Positive (current implementation)
- Works for internal scripts today with zero additional infrastructure
- Self-revocation prevents cross-user token abuse (#60 fix)
- Account lockout integration prevents brute-force via token endpoint
- Simple to reason about — no expiry edge cases, no refresh flow

### Negative (current implementation)
- No expiry means a leaked token is valid forever unless manually revoked
- One token per user means you cannot isolate revocation per script
- `verify_token` endpoint is misleadingly named and broken for its apparent audience
- No web UI means ops work requires direct API calls or Django shell access
- Plaintext storage means DB access = token access

### Migration note
If `django-rest-knox` is adopted in future, the `authtoken_token` table can be
drained and dropped. The `rest_framework.authtoken` app can be removed from
`INSTALLED_APPS`. No portal code is affected (portal does not use token auth).
