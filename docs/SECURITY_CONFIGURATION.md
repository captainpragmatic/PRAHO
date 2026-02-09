# PRAHO Platform Security Configuration

## 🔒 Production Security Checklist

### ✅ REQUIRED Environment Variables

Set these environment variables for production deployment:

```bash
# 🔑 CRITICAL: Secure SECRET_KEY (50+ chars)
DJANGO_SECRET_KEY="your-secure-random-key-here-50-plus-characters"

# 🔐 AES-256 Encryption Key (generate with command below)
DJANGO_AES256_KEY="base64-encoded-32-byte-key"
# Generate: python -c "import secrets, base64; print(base64.urlsafe_b64encode(secrets.token_bytes(32)).decode())"

# 🗄️ Credential Vault Master Key (for encrypted credential storage)
CREDENTIAL_VAULT_MASTER_KEY="fernet-key-here"
# Generate: python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"

# 🌐 SSL/TLS Configuration
ALLOWED_HOSTS="yourdomain.com,www.yourdomain.com"
DOMAIN="yourdomain.com"

# 📊 Database Security (with SSL)
DB_NAME="your_production_db"
DB_USER="your_db_user"
DB_PASSWORD="secure_db_password"
DB_HOST="localhost"
DB_PORT="5432"
DB_SSLMODE="require"

# 🔐 Redis Security
REDIS_URL="redis://localhost:6379/0"

# 📧 Email Security
EMAIL_HOST="smtp.your-provider.com"
EMAIL_PORT="587"
EMAIL_HOST_USER="your-email@domain.com"
EMAIL_HOST_PASSWORD="your-email-password"
EMAIL_USE_TLS="true"
```

---

## 🔐 Data Encryption (AES-256-GCM)

### Encryption at Rest

PRAHO uses **AES-256-GCM** authenticated encryption for sensitive data:

| Component | Algorithm | Key Size | Mode |
|-----------|-----------|----------|------|
| **Sensitive Data** | AES-256-GCM | 256-bit | Authenticated |
| **Credential Vault** | Fernet (AES-128-CBC) | 128-bit | Legacy (upgrade path available) |
| **Password Hashing** | Argon2id | N/A | Memory-hard |

### Usage Example

```python
from apps.common.aes256_encryption import encrypt_aes256, decrypt_aes256

# Encrypt sensitive data
encrypted = encrypt_aes256("sensitive-api-key")

# Decrypt when needed
plaintext = decrypt_aes256(encrypted)

# Migrate legacy Fernet data to AES-256
from apps.common.aes256_encryption import migrate_to_aes256
new_encrypted = migrate_to_aes256(old_fernet_encrypted)
```

### Key Derivation

- **Algorithm**: PBKDF2-HMAC-SHA256
- **Iterations**: 310,000 (OWASP 2023 recommendation)
- **Salt**: 128-bit derived from master key

---

## 🌐 TLS/SSL Configuration (TLS 1.3)

### Protocol Versions

| Setting | Value | Notes |
|---------|-------|-------|
| **Minimum TLS** | TLS 1.2 | For compatibility |
| **Preferred TLS** | TLS 1.3 | Modern security |
| **SSL Redirect** | Enabled | All HTTP -> HTTPS |

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
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
```

### Nginx SSL Configuration

Use the production SSL config:

```bash
# Copy SSL configuration
cp deploy/nginx/nginx-ssl.conf /etc/nginx/nginx.conf

# Test configuration
nginx -t

# Reload
nginx -s reload
```

---

## 📜 SSL Certificate Automation (Let's Encrypt)

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

### 🛡️ Security Headers Enabled

The platform automatically applies these security headers:

- **HSTS**: HTTP Strict Transport Security (1 year)
- **CSP**: Content Security Policy 
- **X-Frame-Options**: DENY (prevents clickjacking)
- **X-Content-Type-Options**: nosniff
- **X-XSS-Protection**: 1; mode=block
- **Referrer-Policy**: strict-origin-when-cross-origin

### 🔐 Authentication Security

- ✅ **Secure Password Hashing**: Argon2 (industry standard)
- ✅ **Two-Factor Authentication**: TOTP with encrypted secrets
- ✅ **Account Lockout**: Progressive delays (5min → 4hr)
- ✅ **Rate Limiting**: Applied to login and API endpoints
- ✅ **Session Security**: Secure, HttpOnly cookies
- ✅ **CSRF Protection**: Enabled for all user endpoints

### 📊 OWASP Top 10 Compliance

| Vulnerability | Status | Implementation |
|---------------|--------|----------------|
| A01 - Broken Access Control | ✅ Secure | Role-based permissions, object-level checks |
| A02 - Cryptographic Failures | ✅ Secure | Strong encryption, secure defaults |
| A03 - Injection | ✅ Secure | Django ORM, parameterized queries |
| A04 - Insecure Design | ✅ Secure | CSRF protection, secure architecture |
| A05 - Security Misconfiguration | ✅ Secure | Hardened settings, security headers |
| A06 - Vulnerable Components | ✅ Secure | Updated dependencies, security patches |
| A07 - Auth Failures | ✅ Secure | Strong authentication, 2FA, lockouts |
| A08 - Software Integrity | ✅ Secure | Package verification, secure deployment |
| A09 - Logging Failures | ✅ Secure | Comprehensive audit logging |
| A10 - SSRF | ✅ Secure | No user-controlled external requests |

### 🚀 Quick Security Validation

Run this command to validate your production security:

```bash
# Check Django security settings
python manage.py check --deploy

# Expected: "System check identified no issues"
```

### 📋 Pre-Deployment Security Checklist

- [ ] Set secure `DJANGO_SECRET_KEY` (50+ characters)
- [ ] Configure `ALLOWED_HOSTS` for your domain
- [ ] Enable SSL/TLS with valid certificate
- [ ] Set secure database passwords
- [ ] Configure email with TLS encryption
- [ ] Review and test 2FA functionality
- [ ] Verify rate limiting is working
- [ ] Test account lockout protection
- [ ] Validate CSRF protection
- [ ] Check security headers in browser

### 🔍 Security Monitoring

Monitor these security events:

- Failed login attempts
- Account lockouts
- 2FA setup/disable events
- Admin access
- Password changes
- Suspicious API requests

All security events are logged in the audit system for compliance.
