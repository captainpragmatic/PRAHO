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
- **Use case**: Portal service, mobile apps, CLI tools
- **Method**: Authorization header with token
- **Setup**: Obtain token via API endpoint

## Getting API Tokens

### **Obtain Token**
```bash
POST /api/users/token/
Content-Type: application/json

{
    "email": "user@example.com",
    "password": "your-password"
}
```

**Response:**
```json
{
    "token": "9944b09199c62bcf9418ad846dd0e4bbdfc6ee4b",
    "user_id": 123,
    "email": "user@example.com"
}
```

### **Using Tokens**
Include the token in the Authorization header:

```bash
curl -H "Authorization: Token 9944b09199c62bcf9418ad846dd0e4bbdfc6ee4b" \
     https://platform.praho.com/api/customers/search/?q=test
```

### **Verify Token**
```bash
GET /api/users/token/verify/
Authorization: Token 9944b09199c62bcf9418ad846dd0e4bbdfc6ee4b
```

**Response:**
```json
{
    "user_id": 123,
    "email": "user@example.com",
    "is_staff": false,
    "accessible_customers": [1, 2, 3],
    "full_name": "John Doe"
}
```

### **Revoke Token**

Self-revocation only — revokes the token used to authenticate this request.
No body needed; the token in the `Authorization` header is the one deleted.

```bash
DELETE /api/users/token/revoke/
Authorization: Token 9944b09199c62bcf9418ad846dd0e4bbdfc6ee4b
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
| **Anonymous** | 100/hour | Public endpoints only |
| **Authenticated** | 1000/hour | General API usage |
| **Burst** | 60/min | Search/autocomplete |
| **Auth endpoints** | 5/min | Login/token requests |

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

### **For Portal Service**
1. **Service Account**: Create dedicated user for portal service
2. **Environment Variables**: Store tokens in environment, never in code
3. **Token Rotation**: Periodically revoke and regenerate tokens
4. **HTTPS Only**: Never send tokens over HTTP

### **For Users**
1. **Secure Storage**: Store tokens securely (encrypted storage)
2. **Limited Scope**: Use tokens only for intended purposes
3. **Revoke Unused**: Revoke tokens when no longer needed
4. **Monitor Usage**: Check for suspicious API activity

## Troubleshooting

### **Common Issues**

#### **401 Unauthorized**
```bash
# Check token format
curl -H "Authorization: Token YOUR_TOKEN_HERE" /api/users/token/verify/

# Verify token exists
python manage.py shell
>>> from rest_framework.authtoken.models import Token
>>> Token.objects.filter(key='YOUR_TOKEN_HERE').exists()
```

#### **403 Forbidden**
- User doesn't have access to requested resource
- Check customer membership permissions

#### **429 Too Many Requests**
- Rate limit exceeded
- Wait for reset time or reduce request frequency

### **Django Shell Helpers**
```python
# Create token for user
from django.contrib.auth import get_user_model
from rest_framework.authtoken.models import Token

User = get_user_model()
user = User.objects.get(email='user@example.com')
token, created = Token.objects.get_or_create(user=user)
print(f"Token: {token.key}")

# Revoke all tokens for user
Token.objects.filter(user=user).delete()
```

## Authentication by Consumer

| Consumer | Method | Where configured |
|----------|--------|-----------------|
| Portal service | HMAC-signed requests | `HMAC_SECRET` env var, `PortalServiceHMACMiddleware` |
| Platform web UI (staff) | Django session cookies | Automatic for logged-in staff |
| CLI tools / external API clients | DRF token (`Authorization: Token ...`) | `POST /api/users/token/` to obtain |
| Platform→Portal webhooks | Dedicated HMAC (`PLATFORM_TO_PORTAL_WEBHOOK_SECRET`) | `X-Platform-Signature` + `X-Platform-Timestamp` headers |
