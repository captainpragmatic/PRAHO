# 🔐 PRAHO API Authentication Guide

## Authentication Methods

PRAHO Platform API supports multiple authentication methods for different use cases:

### 0. HMAC Authentication (Portal → Platform) 🔐
- Use case: Portal backend calling Platform APIs
- Method: HMAC-SHA256 over a canonical string; identity and context in a signed JSON body
- Required headers: `X-Portal-Id`, `X-Nonce`, `X-Timestamp`, `X-Body-Hash`, `X-Signature`

Canonical string (each on its own line):

1) METHOD (uppercased)
2) PATH?QUERY with query params percent-encoded and sorted by key, then value
3) content-type lowercased, no parameters (e.g., application/json)
4) body-hash as base64(SHA-256(raw body bytes))
5) X-Portal-Id value
6) X-Nonce
7) X-Timestamp

Signed JSON body must include:
- user_id: the acting user identity (required)
- timestamp: unix timestamp (5-minute freshness window)
- Domain fields (e.g., customer_id, action, etc.)

Notes:
- X-User-Id header is ignored; user identity must be signed in the body.
- Query parameter fallbacks for customer_id are deprecated and rejected.

### 1. **Session Authentication** 🍪
- **Use case**: Web UI (HTMX calls from platform service)
- **Method**: Django session cookies
- **Setup**: Automatic for logged-in users

### 2. **Token Authentication** 🎫
- **Use case**: Intended for CLI tools and scripts
- **Method**: Authorization header with token
- **Setup**: Obtain token via API endpoint

> **A bare token reaches its own lifecycle only (#569).** `POST /api/users/token/`,
> `GET /api/users/token/me/` and `DELETE /api/users/token/revoke/` answer without the
> Portal's signature. Every other `/api/` route sits behind the Portal's HMAC gate, so a
> request carrying only a token is rejected there before the view runs. See ADR-0031,
> "What a bare token can reach".

## Getting API Tokens

### **Obtain Token**
```bash
POST /api/users/token/
Content-Type: application/json

{
    "email": "user@example.com",
    "password": "your-password",
    "mfa_token": "123456"
}
```

`mfa_token` is required when the account has two-factor authentication enabled: a current
TOTP code or an unused backup code. Every refusal returns the same `401 Invalid
credentials` body, whether the password or the code was wrong.

Optional fields: `name`, `description`, and `ttl_days` (1 to 365; the default lifetime is 90 days).

**Response** (the raw token is shown once and never again):
```json
{
    "token": "<40-char-hex-key>",
    "user_id": 123,
    "email": "user@example.com",
    "key_prefix": "<first-8-chars>",
    "name": "ci-pipeline",
    "description": "Production deploys",
    "expires_at": "2026-12-30T09:00:00+00:00"
}
```

### **Using Tokens**
Include the token in the Authorization header, with either the `Bearer` or the `Token` scheme:

```bash
curl -H "Authorization: Bearer $PRAHO_API_TOKEN" \
     https://platform.praho.com/api/users/token/me/
```

### **Verify Token**
```bash
GET /api/users/token/me/
Authorization: Token <your-token>
```

**Response:**
```json
{
    "user_id": 123,
    "email": "user@example.com",
    "staff_role": "",
    "is_active": true,
    "token_name": "ci-pipeline",
    "token_description": "Production deploys",
    "key_prefix": "<first-8-chars>",
    "created_at": "2026-10-01T09:00:00+00:00",
    "expires_at": "2026-12-30T09:00:00+00:00",
    "last_used_at": null
}
```

### **Revoke Token**

Self-revocation only — revokes the token used to authenticate this request.
No body needed; the token in the `Authorization` header is the one deleted.

```bash
DELETE /api/users/token/revoke/
Authorization: Token <your-token>
```

**Response:**
```json
{
    "message": "Token revoked successfully"
}
```

> **Security note:** The endpoint accepts `DELETE` only. `POST` returns 405.
> Passing another user's token key in a request body has no effect — only
> the token in the `Authorization` header is ever revoked.

## Rate Limiting 🚦

### **Rate Limits by Authentication**

| User Type | Limit | Usage |
|-----------|-------|--------|
| **Anonymous** | 40/min per client (`anon`) | Public reference-data endpoints |
| **Token lifecycle** | 120/min and 2000/hour per user (`api_burst`, `sustained`) | `token/me/`, `token/revoke/`. Counted only once the token is valid |
| **Auth endpoints** | 10/min per client (`auth`) | Login/token requests |
| **Token requests** | 5/min per submitted address (`token_request`) | `/api/users/token/` |
| **Credential endpoints** | Account lockout | `/users/login/`, `/api/users/login/`. `/api/users/token/` refuses locked accounts; a wrong password does not count toward the lock (it is public), a failed second factor does |

### **Rate Limit Headers**
API responses include rate limit information:

```http
X-RateLimit-Limit: 1000
X-RateLimit-Remaining: 999
X-RateLimit-Reset: 1625097600
```

### **Rate Limit Exceeded**
```json
{
    "detail": "Request was throttled. Expected available in 3600 seconds."
}
```

## Portal Service Integration

The **portal service does not use DRF token authentication**. Portal→Platform
communication uses **HMAC-SHA256 signed requests** instead. Every call from
the portal carries a signed `X-User-Context` header and a canonical signature
computed over method, path, content-type, body hash, portal ID, nonce, and
timestamp (see section 0 above).

The Python client is at `services/portal/apps/api_client/services.py`. It
handles signing transparently — portal views call methods like
`api_client.authenticate_customer()` without managing tokens or headers
directly.

**DRF tokens (`Authorization: Token ...`) are for:**
- Direct API consumers such as CLI tools or future mobile clients
- Platform staff automation scripts
- Any external system granted direct platform access

**The portal is not and should not be any of those.** Portal↔Platform trust
is established by the shared `HMAC_SECRET` and the
`PortalServiceHMACMiddleware` that validates every inbound request from the
portal.

## Security Best Practices

### **For Scripts and Service Accounts**
1. **Service Account**: Create a dedicated user per script, with the minimum `staff_role`
2. **Environment Variables**: Store tokens in environment or a vault, never in code
3. **Token Rotation**: Revoke and re-issue tokens periodically; pick a short `ttl_days` for CI
4. **HTTPS Only**: Never send tokens over HTTP

The Portal does not use tokens; it signs every request (see above).

### **For Users**
1. **Secure Storage**: Store tokens securely (encrypted storage)
2. **Limited Scope**: Use tokens only for intended purposes
3. **Revoke Unused**: Revoke tokens when no longer needed
4. **Monitor Usage**: Check for suspicious API activity

## Troubleshooting

### **Common Issues**

#### **401 Unauthorized**
```bash
# Check the token: 200 shows its user and expiry, 401 means unknown, expired or disabled
curl -H "Authorization: Bearer YOUR_TOKEN_HERE" /api/users/token/me/
```

A 401 with `{"error": "HMAC authentication failed"}` means the route is not one a bare
token can reach; only the token lifecycle routes are.

#### **403 Forbidden**
- User doesn't have access to requested resource
- Check customer membership permissions

#### **429 Too Many Requests**
- Rate limit exceeded
- Wait for reset time or reduce request frequency

### **Managing Tokens**
Staff create, list and revoke their own tokens at `/settings/api-tokens/`. Tokens are
stored hashed (`APIToken.key_hash`), so a lost key cannot be recovered; revoke it and
issue a new one. Deleting a token writes an `api_token_deleted` audit event.

## Authentication by Consumer

| Consumer | Method | Where configured |
|----------|--------|-----------------|
| Portal service | HMAC-signed requests | `HMAC_SECRET` env var, `PortalServiceHMACMiddleware` |
| Platform web UI (staff) | Django session cookies | Automatic for logged-in staff |
| CLI tools / external API clients | API token (`Authorization: Bearer ...`), token lifecycle routes only | `POST /api/users/token/` to obtain |
| Platform→Portal webhooks | Dedicated HMAC (`PLATFORM_TO_PORTAL_WEBHOOK_SECRET`) | `X-Platform-Signature` + `X-Platform-Timestamp` headers |

## Platform→Portal Webhook Authentication (System 2)

PRAHO uses **two independent HMAC systems** with separate secrets for different trust boundaries:

| | System 1: Portal → Platform | System 2: Platform → Portal Webhook |
|---|---|---|
| **Secret** | `PLATFORM_API_SECRET` / `HMAC_SECRET` | `PLATFORM_TO_PORTAL_WEBHOOK_SECRET` |
| **Direction** | Portal calls Platform API | Platform pushes payment notifications |
| **Maturity** | Battle-tested (nonce dedup, canonical signing, rate limiting) | Signature-based dedup, format validation |
| **Why separate** | Multi-endpoint API, untrusted client | Single endpoint, trusted internal service |

**Why not unify:** Portal is stateless (LocMemCache per-process, no DB). Can't do reliable cross-worker nonce dedup. Different threat models. Different trust boundaries. Secret isolation is a feature.

### Signature Scheme

```
signature = HMAC-SHA256(secret, str(int(ts)) + "." + body)
```

- **Payload**: integer Unix timestamp concatenated with `"."` and the raw JSON body bytes
- **Algorithm**: HMAC-SHA256 (timing-safe comparison via `hmac.compare_digest`)
- **Headers**: `X-Platform-Signature` (64-char lowercase hex), `X-Platform-Timestamp` (integer Unix)

### Security Properties

| Property | Implementation |
|----------|---------------|
| **Replay window** | 5 minutes (`_WEBHOOK_REPLAY_WINDOW_SECONDS = 300`) |
| **Future timestamps** | Rejected — only `0 <= (now - ts) <= window` accepted |
| **Signature format** | Pre-validated: exactly 64 lowercase hex characters |
| **Per-process replay dedup** | `cache.add()` with signature prefix as key (LocMemCache) |
| **Fail-secure** | Empty/missing secret → all webhooks rejected |
| **Startup validation** | Both `prod.py` settings raise on missing secret |

### Endpoint

```
POST /orders/payment/webhook/
```

- CSRF-exempt (HMAC-authenticated inter-service endpoint)
- Idempotent handler (logs + session hint — safe for per-process dedup)
- Sender: `apps.integrations.webhooks.stripe._notify_portal_payment_success()`
- Receiver: `apps.orders.views.payment_success_webhook()`
