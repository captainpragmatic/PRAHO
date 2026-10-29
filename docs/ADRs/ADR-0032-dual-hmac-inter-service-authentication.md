# ADR-0032: Dual HMAC Inter-Service Authentication

**Status:** Accepted
**Date:** 2026-03-06
**Amended:** 2026-10-13
**Authors:** Development Team
**Related:** ADR-0017 (Portal Auth Fail-Open), ADR-0031 (API Token Authentication Strategy)

---

## Context

PRAHO uses a two-service architecture: Platform (`:8700`, PostgreSQL, full business logic) and Portal (`:8701`, no business data; its local SQLite file holds only sessions and counters, ADR-0017 and ADR-0050). These services need to authenticate requests to each other across two distinct communication patterns:

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
| **Secret** | Per-portal `PORTAL_HMAC_SECRET` on the portal, resolved by `X-Portal-Id` against the `PORTAL_HMAC_CREDENTIALS` keyring on the platform. The shared `PLATFORM_API_SECRET` (`HMAC_SECRET` in the environment) is the fallback, see the amendment below |
| **Algorithm** | HMAC-SHA256 over a 7-field canonical string |
| **Headers sent** | `X-Portal-Id`, `X-Nonce`, `X-Timestamp`, `X-Body-Hash`, `X-Signature` |
| **Replay protection** | Per-nonce claim in the shared counter table (`apps.common.counters.claim`, atomic; a cache could evict a live nonce) |
| **Timestamp window** | 300 seconds (5 minutes), with 2-second forward skew tolerance for NTP jitter. Fractional timestamps are accepted and truncated with `int(float())`, so a portal on an older release keeps verifying during a rolling deploy |
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
- Exemption: `_is_auth_exempt()` resolves the request and reads the `@public_api_endpoint`
  marker off the view (handles `APPEND_SLASH`, limited to `/api/`). There is deliberately no
  parallel list of literal paths. The frozenset this replaced, `_AUTH_EXEMPT_EXACT_PATHS_RAW`,
  had drifted from the marker: six of the eight views documented as public were missing from
  it and answered 401, including the token endpoint. One fact, one source.

### System 2: Platform to Portal (Webhook Signing)

Platform signs outbound payment notification webhooks to Portal using a simpler timestamp-dot-body scheme.

| Property | Value |
|----------|-------|
| **Secret** | `PLATFORM_TO_PORTAL_WEBHOOK_SECRET` (separate from System 1) |
| **Algorithm** | HMAC-SHA256 over `str(int(ts)) + "." + body` |
| **Headers sent** | `X-Platform-Signature` (64-char lowercase hex), `X-Platform-Timestamp` (integer Unix) |
| **Replay protection** | Per-signature claim in the portal's shared counter table (`counters.claim`, atomic across workers, held for the full acceptance window) |
| **Timestamp window** | 300 seconds (5 minutes), with 2-second forward skew tolerance |
| **Signature format** | Pre-validated: exactly 64 lowercase hex characters |
| **Endpoint** | `POST /order/payment/webhook/` (CSRF-exempt). The portal mounts the orders app at `order/` |
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
- When this was decided Portal had no database, so there was no local store for a JWKS cache or token blacklist. Portal now has one for sessions and counters (ADR-0050), so this reason has lapsed; the reasons below still hold
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
- **Different infrastructure constraints** (when this was decided): System 1 runs on Platform with a store shared across workers, enabling reliable cross-worker nonce dedup (today the counter table). System 2 ran on Portal with only LocMemCache (per-process, no cross-worker visibility); Portal has since gained its own counter table (ADR-0050). At the time, a unified nonce dedup strategy would have required adding shared infrastructure to Portal, which then had none, or downgrading Platform's replay protection.
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
| **Timestamp parsing** | System 2 accepts integer timestamps only. System 1 accepts a fractional value and truncates it with `int(float())`. In both, the truncated value must fall inside the window |
| **Future timestamp rejection** | `0 <= (now - ts) <= window` with small NTP skew allowance |
| **Startup validation** | Both `prod.py` settings files raise `ValueError` on missing secrets |
| **Constant names** | `HMAC_TIMESTAMP_WINDOW_SECONDS` (300s) and `HMAC_NTP_SKEW_SECONDS` (2s) in `apps.common.constants` |

### System 1 Specific

| Property | Implementation |
|----------|---------------|
| **Body integrity** | SHA-256 hash of raw body included in canonical string |
| **Path integrity** | Full path + sorted query params in canonical string |
| **Method integrity** | HTTP method in canonical string (prevents GET-to-POST confusion) |
| **Nonce dedup** | Counter-table claim (`counters.claim`) — atomic, shared across all workers, never evicted while live; a store failure answers 503 |
| **Nonce TTL** | `HMAC_TIMESTAMP_WINDOW_SECONDS + 30s` buffer |
| **Rate limiting placement** | After signature validation — keyed on verified `portal_id`, not attacker-controlled header |

### System 2 Specific

| Property | Implementation |
|----------|---------------|
| **Signature format validation** | 64-char lowercase hex pre-filter before HMAC computation |
| **Shared replay dedup** | `counters.claim` keyed on the signature. Only the owning delivery may release a failed attempt, and a successful delivery keeps its claim until expiry. A store failure answers 503 |
| **Idempotent handler** | The handler logs and leaves a session hint only, so a redelivery after a failed attempt is harmless |
| **Fail-secure on missing secret** | Empty `PLATFORM_TO_PORTAL_WEBHOOK_SECRET` rejects all webhooks |

---

## Known Limitations

1. **No automatic secret rotation for System 2**: `PLATFORM_TO_PORTAL_WEBHOOK_SECRET` is a single static value. Rotation requires a coordinated restart of both services. System 1 does not share this limit, see the amendment.

2. **No request signing on System 2**: The webhook only signs `timestamp.body`, not the HTTP method or path. This is acceptable because the endpoint is fixed (`POST /order/payment/webhook/`) and CSRF-exempt, so method/path confusion is not a practical attack vector.

3. **System 1 timestamp parsing is looser than System 2**: System 1 truncates fractional timestamps. This is deliberate for rolling deploys and costs nothing, because the truncated value is still held to the window and the nonce is still single-use.

---

## Amendment (2026-10-13)

The decision above stands. Several details drifted as the code moved on, and this section brings the record back to the code. The tables above were corrected in place. Nothing here reverses a decision.

### System 1 now has per-portal secrets, a keyring and a rollout mode

- The portal signs with `PORTAL_HMAC_SECRET` when it is set. It falls back to the shared `PLATFORM_API_SECRET` only when the per-portal setting is absent. An explicitly empty value raises instead of degrading silently (`services/portal/apps/api_client/services.py`, `_resolve_portal_signing_secret`).
- The platform resolves the verifying secret by the signed `X-Portal-Id` from `PORTAL_HMAC_CREDENTIALS`, a keyring of the form `{portal_id: [secret, ...]}` (`services/platform/apps/common/portal_hmac.py`). A keyring holds up to three secrets, so rotation is make-before-break: add the new secret, roll the portal, drop the old one.
- `PORTAL_HMAC_MODE` selects how the registry is used. `legacy` (the default) verifies against the shared secret for any well-formed portal id and ignores the registry. `audit` tries the registry first, falls back to the shared secret, and logs a warning only when that fallback succeeds. `enforce` uses the registry alone and rejects an unregistered id. Startup validation refuses `enforce` with an empty registry.
- Every candidate secret is evaluated with no short-circuit, so the position of a key does not leak through timing.

This retires two of the original limitations. There is rotation for System 1, and more than one portal can be registered. The shared secret and `legacy` mode remain the defaults until each deployment opts in.

### System 2 replay protection is shared, not per process

The portal gained its own counter table (ADR-0050). `_verify_platform_webhook` claims the signature with `counters.claim` for the acceptance window plus the skew allowance. The earlier text described a per-worker `LocMemCache`, and the per-process limitation that followed from it no longer applies.

### Timestamp parsing differs between the systems

System 1 reads the timestamp with `int(float(value))` (`PortalServiceHMACMiddleware._validate_hmac_signature`) and accepts fractional values. System 2 reads it with `int(value)` and rejects them (`_verify_platform_webhook`). The older line "float timestamps rejected" was true only for System 2.

### The webhook endpoint

The portal mounts the orders app at `order/`, so the endpoint is `POST /order/payment/webhook/`. Earlier text and the dev and e2e settings defaults said `/orders/...`, which the portal does not serve. A root integration test now resolves each default against the portal URLconf.

---

## Consequences

### Positive

- Clear separation of trust boundaries — compromise of one secret does not affect the other direction
- Portal holds no business data; webhook verification needs only its counter table for replay claims (ADR-0050)
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
