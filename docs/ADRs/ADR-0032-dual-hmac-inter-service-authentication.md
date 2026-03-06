# ADR-0032: Dual HMAC Inter-Service Authentication

**Status:** Accepted
**Date:** 2026-03-06
**Authors:** Development Team
**Related:** ADR-0017 (Portal Auth Fail-Open), ADR-0031 (API Token Authentication Strategy)

---

## Context

PRAHO uses a two-service architecture: Platform (`:8700`, PostgreSQL, full business logic) and Portal (`:8701`, stateless, no database). These services need to authenticate requests to each other across two distinct communication patterns:

1. **Portal calls Platform** — every customer action on Portal (viewing invoices, managing domains, checking tickets) requires a signed API call to Platform to fetch or mutate data.
2. **Platform pushes to Portal** — after processing a Stripe payment webhook, Platform notifies Portal that a payment succeeded so the customer's session can reflect the updated order status.

These two patterns have fundamentally different trust models, infrastructure constraints, and threat profiles, which led to the decision to implement two independent HMAC systems rather than a unified one.

---

## Decision

PRAHO implements **two independent HMAC-SHA256 authentication systems** with separate secrets, separate signing schemes, and separate replay protection mechanisms.

### System 1: Portal to Platform (Request Signing)

Portal signs every outbound API request to Platform using a canonical string scheme.

| Property | Value |
|----------|-------|
| **Secret** | `PLATFORM_API_SECRET` / `HMAC_SECRET` (same value, two setting names) |
| **Algorithm** | HMAC-SHA256 over a 7-field canonical string |
| **Headers sent** | `X-Portal-Id`, `X-Nonce`, `X-Timestamp`, `X-Body-Hash`, `X-Signature` |
| **Replay protection** | Per-nonce dedup via `cache.add()` (database cache, shared across workers) |
| **Timestamp window** | 300 seconds (5 minutes), with 2-second forward skew tolerance for NTP jitter |
| **Nonce requirements** | 32-256 characters, UUID4 recommended |
| **User identity** | Signed in JSON body (`user_id` field), not in headers |
| **Rate limiting** | Applied after signature validation, keyed on verified `portal_id` |

**Canonical string** (newline-separated, in order):

1. HTTP method (uppercased)
2. Path with query params percent-encoded and sorted by key, then value
3. Content-Type lowercased, no parameters
4. Body hash: `base64(SHA-256(raw body bytes))`
5. `X-Portal-Id` value
6. Nonce
7. Timestamp (integer Unix)

**Code locations:**
- Middleware (verifier): `services/platform/apps/common/middleware.py` — `PortalServiceHMACMiddleware`
- Client (signer): `services/portal/apps/api_client/services.py` — `PlatformAPIClient`
- Exempt paths: `_AUTH_EXEMPT_EXACT_PATHS_RAW` frozenset with `_is_auth_exempt()` helper (handles `APPEND_SLASH`)

### System 2: Platform to Portal (Webhook Signing)

Platform signs outbound payment notification webhooks to Portal using a simpler timestamp-dot-body scheme.

| Property | Value |
|----------|-------|
| **Secret** | `PLATFORM_TO_PORTAL_WEBHOOK_SECRET` (separate from System 1) |
| **Algorithm** | HMAC-SHA256 over `str(int(ts)) + "." + body` |
| **Headers sent** | `X-Platform-Signature` (64-char lowercase hex), `X-Platform-Timestamp` (integer Unix) |
| **Replay protection** | Per-process dedup via `cache.add()` (LocMemCache, per-worker) |
| **Timestamp window** | 300 seconds (5 minutes), with 2-second forward skew tolerance |
| **Signature format** | Pre-validated: exactly 64 lowercase hex characters |
| **Endpoint** | `POST /orders/payment/webhook/` (CSRF-exempt) |
| **Fail-secure** | Empty or missing secret rejects all webhooks |

**Code locations:**
- Sender: `services/platform/apps/integrations/webhooks/stripe.py` — `_notify_portal_payment_success()`
- Verifier: `services/portal/apps/orders/views.py` — `_verify_platform_webhook()`
- Handler: `services/portal/apps/orders/views.py` — `payment_success_webhook()`

---

## Alternatives Considered

### 1. JWT (JSON Web Tokens)

JWTs are widely used for service-to-service auth and would eliminate the need for shared secrets by using asymmetric keys (RS256/ES256).

**Rejected because:**
- Portal is stateless with no database — there is no local store for a JWKS cache or token blacklist
- JWT revocation requires infrastructure (blacklist store, short expiry + refresh tokens) that adds complexity without clear benefit for a two-service system where both services are under the same operator
- JWTs are typically larger than HMAC signatures, adding overhead to every Portal-to-Platform request (hundreds per page load)
- The canonical string scheme provides request-level integrity (method, path, body hash are all signed), which JWT does not inherently offer — a JWT proves identity but not that the request body is untampered

### 2. Mutual TLS (mTLS)

Each service presents a client certificate; the other verifies it against a trusted CA.

**Rejected because:**
- Adds certificate lifecycle management (issuance, rotation, revocation, CA infrastructure) for a system that currently runs on a single host or small cluster
- mTLS authenticates the transport, not individual requests — it cannot bind a specific user identity or request body to the authentication proof
- In development and Docker environments, certificate management adds friction with minimal security benefit over HMAC
- Would be reconsidered if PRAHO moves to a multi-tenant or multi-region deployment where network-level identity matters

### 3. Single Unified HMAC System

Use one HMAC scheme and one shared secret for both directions.

**Rejected because:**
- **Different infrastructure constraints**: System 1 runs on Platform with a database-backed cache shared across workers, enabling reliable cross-worker nonce dedup. System 2 runs on Portal with only LocMemCache (per-process, no cross-worker visibility). A unified nonce dedup strategy would either require adding shared cache infrastructure to Portal (violating its stateless design) or downgrading Platform's replay protection.
- **Different threat models**: System 1 faces external-facing risk (Portal is internet-exposed, an attacker who compromises Portal could forge requests to Platform). System 2 is internal-only (Platform calls Portal on a private network). Secret isolation ensures compromise of one direction does not compromise the other.
- **Different signing needs**: System 1 signs 7 fields (method, path, query, content-type, body hash, portal ID, nonce, timestamp) because Portal makes diverse API calls. System 2 signs only `timestamp.body` because it has a single fixed endpoint with a predictable payload shape.
- **Operational rotation**: Separate secrets can be rotated independently. Rotating the Platform-to-Portal webhook secret does not require restarting Portal's API client or vice versa.

### 4. OAuth 2.0 Client Credentials

Standard OAuth2 flow where Portal obtains short-lived access tokens from Platform.

**Rejected because:**
- Requires Platform to implement an OAuth2 authorization server (token endpoint, token storage, expiry management)
- Adds a round-trip token exchange before every request burst, or requires token caching and refresh logic on Portal
- Over-engineered for a two-service system under single-operator control
- Does not provide request-level integrity (same limitation as JWT)

---

## Security Properties

### Shared Across Both Systems

| Property | Implementation |
|----------|---------------|
| **Timing-safe comparison** | `hmac.compare_digest()` — prevents timing side-channels |
| **Integer timestamps only** | Float timestamps rejected; prevents precision-based attacks |
| **Future timestamp rejection** | `0 <= (now - ts) <= window` with small NTP skew allowance |
| **Startup validation** | Both `prod.py` settings files raise `ValueError` on missing secrets |
| **Constant names** | `HMAC_TIMESTAMP_WINDOW_SECONDS` (300s) and `HMAC_NTP_SKEW_SECONDS` (2s) in `apps.common.constants` |

### System 1 Specific

| Property | Implementation |
|----------|---------------|
| **Body integrity** | SHA-256 hash of raw body included in canonical string |
| **Path integrity** | Full path + sorted query params in canonical string |
| **Method integrity** | HTTP method in canonical string (prevents GET-to-POST confusion) |
| **Nonce dedup** | Database cache `cache.add()` — atomic, shared across all workers |
| **Nonce TTL** | `HMAC_TIMESTAMP_WINDOW_SECONDS + 30s` buffer |
| **Rate limiting placement** | After signature validation — keyed on verified `portal_id`, not attacker-controlled header |

### System 2 Specific

| Property | Implementation |
|----------|---------------|
| **Signature format validation** | 64-char lowercase hex pre-filter before HMAC computation |
| **Per-process replay dedup** | LocMemCache `cache.add()` with signature prefix as key |
| **Idempotent handler** | Webhook handler is safe for per-process dedup (logs + session hint only) |
| **Fail-secure on missing secret** | Empty `PLATFORM_TO_PORTAL_WEBHOOK_SECRET` rejects all webhooks |

---

## Known Limitations

1. **System 2 replay dedup is per-process**: Portal uses LocMemCache, so each Gunicorn worker has its own replay cache. A replayed webhook could succeed if it hits a different worker than the original. This is acceptable because the handler is idempotent (it updates a session hint, not a database record) and the 5-minute timestamp window bounds the replay risk.

2. **No automatic secret rotation**: Both secrets are static environment variables. Rotation requires coordinated restart of both services. A future improvement could implement graceful rotation by accepting two secrets during a transition window.

3. **Single Portal ID**: System 1 currently supports a single portal instance (`X-Portal-Id`). Multi-portal deployments would need per-portal secrets or a registry.

4. **No request signing on System 2**: The webhook only signs `timestamp.body`, not the HTTP method or path. This is acceptable because the endpoint is fixed (`POST /orders/payment/webhook/`) and CSRF-exempt, so method/path confusion is not a practical attack vector.

---

## Consequences

### Positive

- Clear separation of trust boundaries — compromise of one secret does not affect the other direction
- Portal remains fully stateless — no shared cache or database required for webhook verification
- Request-level integrity on System 1 — every field that affects request routing or processing is signed
- Both systems fail secure — missing secrets, expired timestamps, and invalid formats all result in rejection
- Independent rotation — each secret can be changed without affecting the other

### Negative

- Two HMAC systems to understand, test, and maintain instead of one
- Developers must know which system applies to their code path
- Two sets of security constants and two verification code paths to keep in sync

### Neutral

- The dual system is fully documented in `AUTHENTICATION.md` (operational reference) and this ADR (decision rationale)
- Security scanner (`scripts/security_scanner.py`) has patterns to detect direct `REMOTE_ADDR` access and env-var bypasses that could weaken either system
- Integration tests in `tests/integration/test_security_hardening.py` verify structural properties of both systems
