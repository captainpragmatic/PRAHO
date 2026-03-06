# PRAHO Security Configuration Guide

Production deployment security settings and operational reference for PRAHO platform.

---

## 1. Environment Variables

Set these environment variables for production deployment:

```bash
# CRITICAL: Secure SECRET_KEY (50+ chars)
DJANGO_SECRET_KEY="your-secure-random-key-here-50-plus-characters"

# AES-256-GCM Encryption Key (for 2FA secrets, settings, tokens)
DJANGO_ENCRYPTION_KEY="base64-encoded-32-byte-key"
# Generate: python -c "import secrets, base64; print(base64.urlsafe_b64encode(secrets.token_bytes(32)).decode())"

# Credential Vault Master Key (AES-256-GCM, for encrypted credential storage)
CREDENTIAL_VAULT_MASTER_KEY="base64-encoded-32-byte-key"
# Generate: python -c "import secrets, base64; print(base64.urlsafe_b64encode(secrets.token_bytes(32)).decode())"

# SSL/TLS Configuration
ALLOWED_HOSTS="yourdomain.com,www.yourdomain.com"
DOMAIN="yourdomain.com"

# Database Security (with SSL)
DB_NAME="your_production_db"
DB_USER="your_db_user"
DB_PASSWORD="secure_db_password"
DB_HOST="localhost"
DB_PORT="5432"
DB_SSLMODE="require"

# Inter-Service HMAC Authentication
HMAC_SECRET="portal-to-platform-hmac-secret"
# Generate: python -c "import secrets; print(secrets.token_urlsafe(32))"
PLATFORM_TO_PORTAL_WEBHOOK_SECRET="platform-to-portal-webhook-hmac-secret"

# Database Cache (default, no Redis required)
# Redis is optional — Platform uses Django's DatabaseCache backend by default
REDIS_URL="redis://localhost:6379/0"

# Email Security
EMAIL_HOST="smtp.your-provider.com"
EMAIL_PORT="587"
EMAIL_HOST_USER="your-email@domain.com"
EMAIL_HOST_PASSWORD="your-email-password"
EMAIL_USE_TLS="true"
```

> See `.env.example.prod` for the full variable list.

---

## 2. Encryption at Rest

PRAHO uses **AES-256-GCM** authenticated encryption with two independent keys to limit blast radius:

| System | Key | Purpose |
|--------|-----|---------|
| App-level encryption | `DJANGO_ENCRYPTION_KEY` | Model field data: 2FA secrets, registrar credentials, EPP codes, OAuth tokens, server management credentials |
| Credential vault | `CREDENTIAL_VAULT_MASTER_KEY` | Infrastructure identity: VirtualMin root creds, cloud provider tokens (HCloud), SSH keys |

**Key format**: 32 random bytes, URL-safe base64 encoded. No PBKDF2 — random keys are used directly with AESGCM.

```bash
# Generate either key:
python -c "import secrets, base64; print(base64.urlsafe_b64encode(secrets.token_bytes(32)).decode())"
```

**Wire format**: `"aes:" + base64url(NONCE[12B] + CIPHERTEXT + TAG[16B])`

**Fail mode**: `ImproperlyConfigured` if keys are missing (fail-closed).

> For standards rationale (NIST SP 800-38D, RFC 5116, ISO 19772, GDPR mapping), see [ADR-0033: Encryption Architecture Consolidation](../ADRs/ADR-0033-encryption-architecture-consolidation.md).

### 2.1 Key Isolation (HKDF Domain Separation)

Beyond the two AES-256-GCM encryption keys, PRAHO derives **domain-specific keys** using HKDF-SHA256 (RFC 5869) for HMAC operations and non-encryption crypto. This implements NIST SP 800-57 Part 1 Section 5.2 (key separation) — a compromise of one derived key does not affect others.

| Domain | Purpose | Optional env var override |
|--------|---------|--------------------------|
| `mfa-backup` | MFA backup code pepper | `MFA_BACKUP_CODE_PEPPER` |
| `unsubscribe` | Unsubscribe token generation | `UNSUBSCRIBE_TOKEN_SECRET` |
| `siem-hash-chain` | SIEM audit log hash chain | `SIEM_HASH_CHAIN_SECRET` (recommended for production) |
| `sensitive-data-hash` | HMAC for sensitive data hashing | `SENSITIVE_DATA_HASH_KEY` |

**How it works**: `apps/common/key_derivation.py` uses `HKDF(SHA256, length=32, info=f"praho-{domain}")` with `settings.SECRET_KEY` as input key material. If a domain-specific env var is set (>= 32 chars), it is used directly instead of HKDF derivation.

**GDPR Art. 5(1)(c) compliance**: Unsubscribe URLs use opaque UUID tokens (`UnsubscribeToken` model) instead of hash-based tokens. No email addresses or PII appear in unsubscribe URLs, satisfying the data minimization principle.

---

## 3. TLS/SSL Configuration

### Protocol Versions

| Setting | Value | Notes |
|---------|-------|-------|
| Minimum TLS | TLS 1.2 | For compatibility |
| Preferred TLS | TLS 1.3 | Modern security |
| SSL Redirect | Enabled | All HTTP -> HTTPS |

### Cipher Suites (TLS 1.2)

```
ECDHE-ECDSA-AES128-GCM-SHA256
ECDHE-RSA-AES128-GCM-SHA256
ECDHE-ECDSA-AES256-GCM-SHA384
ECDHE-RSA-AES256-GCM-SHA384
ECDHE-ECDSA-CHACHA20-POLY1305
ECDHE-RSA-CHACHA20-POLY1305
```

### HSTS Configuration

```
Strict-Transport-Security: max-age=31536000; includeSubDomains
```

Django settings (`config/settings/prod.py`):
- `SECURE_HSTS_SECONDS = 31536000` (1 year)
- `SECURE_HSTS_INCLUDE_SUBDOMAINS = True`
- `SECURE_HSTS_PRELOAD = False` (nginx template enables preload independently — coordinate before enabling in Django)

### Nginx SSL Setup

```bash
cp deploy/nginx/nginx-ssl.conf /etc/nginx/nginx.conf
nginx -t && nginx -s reload
```

### Certificate Automation (Let's Encrypt)

```bash
# Initial certificate
./deploy/ssl/certbot-init.sh $DOMAIN production

# Docker with SSL
docker-compose -f docker-compose.yml -f deploy/ssl/docker-compose.ssl.yml up -d

# Systemd renewal timer
sudo cp deploy/ssl/systemd/certbot-renew.* /etc/systemd/system/
sudo systemctl enable --now certbot-renew.timer
```

> For full TLS rollout procedures, see [HTTPS Deployment Checklist](../deployment/HTTPS_DEPLOYMENT_CHECKLIST.md).

---

## 4. Security Headers

### Django SecurityHeadersMiddleware

Source: `apps/common/middleware.py` — `SecurityHeadersMiddleware`

| Header | Value |
|--------|-------|
| `X-Content-Type-Options` | `nosniff` |
| `X-Frame-Options` | `DENY` |
| `X-XSS-Protection` | `1; mode=block` |
| `Referrer-Policy` | `strict-origin-when-cross-origin` |
| `Cross-Origin-Opener-Policy` | `same-origin` |

### Content Security Policy (CSP)

```
default-src 'self';
style-src 'self' 'unsafe-inline' fonts.googleapis.com cdn.tailwindcss.com;
font-src 'self' fonts.gstatic.com;
script-src 'self' 'unsafe-inline' 'unsafe-eval' unpkg.com cdn.tailwindcss.com;
img-src 'self' data: https:;
connect-src 'self';
object-src 'none';
base-uri 'self';
form-action 'self';
```

**Trade-off**: `'unsafe-inline'` and `'unsafe-eval'` are required for Tailwind CSS CDN and Alpine.js/HTMX inline scripts. Replacing with nonces is tracked as a production hardening gap (see [Security Compliance Assessment](SECURITY_COMPLIANCE_ASSESSMENT.md) gap analysis).

### Nginx-Level Headers

Source: `deploy/nginx/nginx-ssl.conf`

| Header | Value |
|--------|-------|
| `Permissions-Policy` | `geolocation=(), microphone=(), camera=(), payment=(self)` |
| `Cross-Origin-Resource-Policy` | `same-origin` |

### Production Cookie Security

Source: `config/settings/prod.py`

| Setting | Value |
|---------|-------|
| `CSRF_COOKIE_SECURE` | `True` |
| `CSRF_COOKIE_HTTPONLY` | `True` |
| `SESSION_COOKIE_SECURE` | `True` |
| `SESSION_COOKIE_HTTPONLY` | `True` |
| `SESSION_COOKIE_SAMESITE` | `Lax` |

---

## 5. Authentication and Session Security

### Password Hashing

Primary: **Argon2id** (memory-hard). Fallbacks: PBKDF2-SHA256, BCrypt.

Source: `config/settings/base.py` — `PASSWORD_HASHERS`

### Account Lockout

- `ACCOUNT_LOCKOUT_THRESHOLD = 1` — progressive lockout starts on first failed attempt
- Lockout escalation: 5 min -> 15 min -> 30 min -> 60 min -> 120 min -> 240 min
- Tracked via `failed_login_attempts` and `account_locked_until` fields on User model

### Session Security

Source: `config/settings/prod.py`

| Setting | Value |
|---------|-------|
| `SESSION_COOKIE_AGE` | `3600` (1 hour) |
| `SESSION_EXPIRE_AT_BROWSER_CLOSE` | `True` |
| `SESSION_COOKIE_NAME` | `pragmatichost_sessionid` |
| `SESSION_SAVE_EVERY_REQUEST` | `True` |
| `SECURE_PROXY_SSL_HEADER` | `("HTTP_X_FORWARDED_PROTO", "https")` |

### Login Rate Limiting

- 10 requests/minute global on login endpoint
- 5 requests/minute per email address

> For MFA setup and key management details, see [MFA Setup and Key Management](MFA-SETUP-AND-KEY-MANAGEMENT.md).

---

## 6. Inter-Service Security

Portal authenticates to Platform using HMAC-SHA256 signed requests. No JWT.

### HMAC Authentication Protocol

Source: `apps/common/middleware.py` — `PortalServiceHMACMiddleware`

**Canonical string** (signed payload):
```
METHOD\n
NORMALIZED_PATH\n
CONTENT_TYPE\n
BODY_HASH\n
PORTAL_ID\n
NONCE\n
TIMESTAMP
```

| Component | Details |
|-----------|---------|
| Body hash | SHA-256 of request body, base64-encoded |
| Signature | HMAC-SHA256 of canonical string, hex-encoded |
| Timestamp window | 300 seconds (5 minutes) |
| NTP skew tolerance | 2 seconds forward |
| Nonce length | 32-256 bytes |
| Nonce deduplication | Cache-based with atomic `cache.add()`, TTL = timestamp window + 30s |
| Comparison | `hmac.compare_digest()` (timing-safe) |

### HMAC Rate Limiting

- Key: `hmac_rl:{portal_id}:{client_ip}`
- Default: 300 calls per 60 seconds
- Configurable via `HMAC_RATE_LIMIT_WINDOW` and `HMAC_RATE_LIMIT_MAX_CALLS`

### CSRF and Host Validation

- `CSRF_TRUSTED_ORIGINS` derived from `ALLOWED_HOSTS`
- `ALLOWED_HOSTS` validated at startup: raises `ImproperlyConfigured` if contains `*` wildcard

---

## 7. Rate Limiting

Source: `apps/common/performance/rate_limiting.py`

| Throttle Class | Scope | Rate |
|---------------|-------|------|
| `CustomerRateThrottle` | Per customer tier | Basic: 100/min, Professional: 500/min, Enterprise: 2000/min |
| `BurstRateThrottle` | Global burst | 30 requests per 10 seconds |
| `SustainedRateThrottle` | Global sustained | 1000 requests per hour |
| `ServiceRateThrottle` | Token bucket | Capacity: 100, refill: 10 tokens/sec, weighted by operation cost |
| `AnonymousRateThrottle` | Unauthenticated | 20 requests per minute |
| `WriteOperationThrottle` | POST/PUT/PATCH/DELETE | 60 per minute |
| `EndpointThrottle` | Per-endpoint | login: 5/min, 2fa_verify: 10/min, provision: 10/min |

Token bucket operation costs: `provision: 10`, `backup: 5`, `sync: 2`, `query: 1`.

> See [ADR-0030: Rate Limiting Architecture](../ADRs/ADR-0030-rate-limiting-architecture.md) for design rationale.

---

## 8. Outbound HTTP Security

All outbound HTTP requests **must** use the helpers in `apps.common.outbound_http` to prevent SSRF.

### API Functions

| Function | Service | Purpose |
|----------|---------|---------|
| `safe_request(method, url, policy=...)` | Platform | DNS-pinned `requests`-compatible API |
| `safe_urlopen(url, policy=...)` | Platform | `urllib` wrapper for callsites needing `HTTPResponse` |
| `portal_request(method, url, ...)` | Portal | Thin wrapper enforcing HTTPS/timeout/no-redirects |

### Pre-Built Policies

| Policy | HTTPS Required | Redirects | Timeout | DNS Pinning | Retries |
|--------|---------------|-----------|---------|-------------|---------|
| `STRICT_EXTERNAL` (default) | Yes | No | 30s (10s connect) | Yes | 0 |
| `TRUSTED_PROVIDER` | Yes | No | 60s | Yes | 3 |
| `INTERNAL_SERVICE` | No (HTTP allowed) | No | 30s | No | 0 |

### SSRF Prevention

- **DNS pinning**: Resolved IPs checked against private ranges before connection
- **Private IP blocking**: RFC 1918, loopback, link-local, RFC 6598 ranges blocked
- **Dangerous ports blocked**: FTP(21), SSH(22), Telnet(23), SMTP(25), DNS(53), RPC(135), NetBIOS(139), SMB(445), MSSQL(1433), Oracle(1521), MySQL(3306), RDP(3389), PostgreSQL(5432), Redis(6379), Elasticsearch(9200), Memcached(11211), MongoDB(27017)

### Adding a New Outbound Integration

1. Define an `OutboundPolicy` with appropriate `allowed_domains`, `timeout_seconds`, and `verify_tls`
2. Call `safe_request(method, url, policy=your_policy, ...)`
3. Add tests verifying private IP rejection and redirect blocking
4. Never use raw `requests.get/post` or `urllib.request.urlopen` outside the helper module

---

## 9. Production Validation

### Secret Key Validation

`validate_production_secret_key()` in `config/settings/base.py` raises `ValueError` if `SECRET_KEY` starts with `django-insecure-` prefix.

### ALLOWED_HOSTS Enforcement

Production settings (`config/settings/prod.py`) parse `ALLOWED_HOSTS` from environment and raise `ImproperlyConfigured` if the value contains a `*` wildcard.

### Django Deploy Check

```bash
python manage.py check --deploy
# Expected: "System check identified no issues"
```

### Pre-Deploy Security Commands

```bash
# Static security analysis (Semgrep + credential scanning)
make lint-security

# Service isolation validation
make test-security

# Django deployment checks
python manage.py check --deploy
```

---

## 9. SSL Certificate Automation (Let's Encrypt)

### Initial Certificate Setup

```bash
# Set your domain
export DOMAIN="yourdomain.com"
export CERTBOT_EMAIL="admin@yourdomain.com"

# Obtain initial certificate (use staging for testing)
./deploy/ssl/certbot-init.sh $DOMAIN staging

# For production certificate
./deploy/ssl/certbot-init.sh $DOMAIN production
```

### Docker Deployment with SSL

```bash
# Start with SSL support
docker-compose -f docker-compose.yml -f deploy/ssl/docker-compose.ssl.yml up -d
```

### Automated Renewal

Certificates auto-renew via:

1. **Docker container**: Certbot runs every 12 hours
2. **Systemd timer** (alternative):

```bash
# Install systemd timer
sudo cp deploy/ssl/systemd/certbot-renew.* /etc/systemd/system/
sudo systemctl enable --now certbot-renew.timer

# Check timer status
sudo systemctl list-timers certbot-renew.timer
```

### Certificate Verification

```bash
# Check certificate expiry
echo | openssl s_client -connect yourdomain.com:443 2>/dev/null | openssl x509 -noout -dates

# Test TLS configuration
curl -I https://yourdomain.com
```

### Security Headers Enabled

The platform automatically applies these security headers:

- **HSTS**: HTTP Strict Transport Security (1 year)
- **CSP**: Content Security Policy
- **X-Frame-Options**: DENY (prevents clickjacking)
- **X-Content-Type-Options**: nosniff
- **X-XSS-Protection**: 1; mode=block
- **Referrer-Policy**: strict-origin-when-cross-origin

### Authentication Security

- Secure Password Hashing: Argon2 (industry standard)
- Two-Factor Authentication: TOTP with encrypted secrets
- Account Lockout: Progressive delays (5min → 4hr)
- Rate Limiting: Three-layer protection (portal middleware + platform global DRF + platform per-view DRF)
- Session Security: Secure, HttpOnly cookies
- CSRF Protection: Enabled for all user endpoints

Rate-limit scopes are centrally configured via `THROTTLE_RATES` and validated at startup.
Platform responses standardize `429` handling with parseable error payloads and `Retry-After`.

---

## 10. OWASP Top 10 Compliance

| Vulnerability | Status | Implementation |
|---------------|--------|----------------|
| A01 - Broken Access Control | Mitigated | Role-based permissions (7 decorators), object-level checks |
| A02 - Cryptographic Failures | Mitigated | AES-256-GCM encryption, Argon2 hashing — see [ADR-0033](../ADRs/ADR-0033-encryption-architecture-consolidation.md) |
| A03 - Injection | Mitigated | Django ORM, parameterized queries, no raw SQL |
| A04 - Insecure Design | Mitigated | CSRF protection, HMAC inter-service auth, strategic seams pattern |
| A05 - Security Misconfiguration | Mitigated | Hardened settings, security headers, `check --deploy` validation |
| A06 - Vulnerable Components | Mitigated | UV lockfile, Semgrep SAST, pre-commit credential scanning |
| A07 - Auth Failures | Mitigated | Argon2 hashing, MFA (TOTP + WebAuthn), progressive lockout |
| A08 - Software Integrity | Mitigated | Package verification, Docker non-root user, portal isolation |
| A09 - Logging Failures | Mitigated | 180+ audit event types, SIEM-ready JSON formatting, rotating file handlers |
| A10 - SSRF | Mitigated | `safe_request()` with DNS pinning, private IP blocking, dangerous port list |

---

## 11. Pre-Deployment Checklist

- [ ] Set secure `DJANGO_SECRET_KEY` (50+ characters, not `django-insecure-` prefix)
- [ ] Set `DJANGO_ENCRYPTION_KEY` and `CREDENTIAL_VAULT_MASTER_KEY`
- [ ] Configure `ALLOWED_HOSTS` for your domain (no wildcards)
- [ ] Enable SSL/TLS with valid certificate
- [ ] Set secure database passwords with `DB_SSLMODE=require`
- [ ] Configure email with TLS encryption
- [ ] Set `HMAC_SECRET` for portal-platform communication
- [ ] Review [HTTPS Deployment Checklist](../deployment/HTTPS_DEPLOYMENT_CHECKLIST.md) for TLS rollout
- [ ] Run `make lint-security` before deploy
- [ ] Run `python manage.py check --deploy`
- [ ] Verify rate limiting is working
- [ ] Test MFA functionality
- [ ] Check security headers in browser DevTools

---

## Related Documents

- [ADR-0033: Encryption Architecture Consolidation](../ADRs/ADR-0033-encryption-architecture-consolidation.md) — standards compliance mapping
- [MFA Setup and Key Management](MFA-SETUP-AND-KEY-MANAGEMENT.md) — TOTP/WebAuthn setup and key operations
- [Template and CSP Security](../development/TEMPLATE-AND-CSP-SECURITY.md) — secure template patterns and CSP guidance
- [Security Compliance Assessment](SECURITY_COMPLIANCE_ASSESSMENT.md) — full compliance posture assessment
- [ADR-0030: Rate Limiting Architecture](../ADRs/ADR-0030-rate-limiting-architecture.md) — rate limiting design
- [HTTPS Deployment Checklist](../deployment/HTTPS_DEPLOYMENT_CHECKLIST.md) — TLS rollout procedures
- [Audit System Guide](../domain/AUDIT_SYSTEM_GUIDE.md) — audit trail details

---

**Last Updated**: March 2026
**Review Schedule**: Quarterly
