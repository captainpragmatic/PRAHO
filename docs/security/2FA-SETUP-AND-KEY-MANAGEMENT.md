# PRAHO Platform - 2FA Setup and Key Management Guide

## Overview

PRAHO Platform implements enterprise-grade Two-Factor Authentication (2FA) with encrypted storage of sensitive data. This guide covers setup, configuration, and operational procedures for development, testing, and production environments.

## 🔐 Quick Start

### 1. Generate Encryption Key
```bash
# Generate a new Fernet encryption key
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

### 2. Configure Environment
```bash
# Add to your .env file
echo "DJANGO_ENCRYPTION_KEY=your-generated-key-here" >> .env
```

### 3. Apply Migrations
```bash
python manage.py migrate
```

### 4. Test 2FA Functionality
```bash
python manage.py test tests.test_2fa_security_improvements
```

## 📋 Environment Setup

### Development Environment

1. **Install Dependencies**
   ```bash
   uv sync --group platform
   ```

2. **Create .env File**
   ```bash
   cp .env.example .env
   ```

3. **Generate and Set Encryption Key**
   ```bash
   # Generate key
   python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"

   # Add to .env (replace the placeholder)
   DJANGO_ENCRYPTION_KEY=VCxwdmuZL09WGdWLI203O64yhNs48IiafhjFIq0o_JE=
   ```

4. **Apply Database Migrations**
   ```bash
   python manage.py makemigrations
   python manage.py migrate
   ```

### Production Environment

1. **Secure Key Generation**
   ```bash
   # Generate on secure, isolated system
   python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())" > encryption_key.txt

   # Store in secure vault (HashiCorp Vault, AWS Secrets Manager, etc.)
   ```

2. **Environment Variable Injection**
   ```yaml
   # docker-compose.prod.yml
   services:
     web:
       environment:
         DJANGO_ENCRYPTION_KEY: ${DJANGO_ENCRYPTION_KEY}
       secrets:
         - django_encryption_key

   secrets:
     django_encryption_key:
       external: true
   ```

3. **Kubernetes Secrets**
   ```yaml
   apiVersion: v1
   kind: Secret
   metadata:
     name: django-encryption-key
   type: Opaque
   data:
     DJANGO_ENCRYPTION_KEY: <base64-encoded-key>
   ```

## 🏗️ System Architecture

### Encryption Flow
```
User Input (TOTP Secret)
    ↓
Fernet.encrypt(secret, DJANGO_ENCRYPTION_KEY)
    ↓
Encrypted Storage (User._two_factor_secret)
    ↓
Fernet.decrypt(encrypted_secret, DJANGO_ENCRYPTION_KEY)
    ↓
TOTP Verification (pyotp.TOTP.verify())
```

### Database Schema
```sql
-- Users table (simplified)
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    email VARCHAR(254) UNIQUE NOT NULL,
    two_factor_enabled BOOLEAN DEFAULT FALSE,
    _two_factor_secret VARCHAR(256) DEFAULT '',  -- Encrypted TOTP secret
    backup_tokens JSONB DEFAULT '[]'            -- Hashed backup codes
);

-- User login logs for audit trail
CREATE TABLE user_login_logs (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id),
    timestamp TIMESTAMPTZ DEFAULT NOW(),
    ip_address INET NOT NULL,
    user_agent TEXT,
    status VARCHAR(20) NOT NULL,  -- 'success', 'failed_password', 'failed_2fa'
    country VARCHAR(100),
    city VARCHAR(100)
);
```

## 🔧 Configuration Options

### Environment Variables
```bash
# Required - Fernet encryption key for sensitive data
DJANGO_ENCRYPTION_KEY=VCxwdmuZL09WGdWLI203O64yhNs48IiafhjFIq0o_JE=

# Optional - Customize 2FA settings
TOTP_ISSUER_NAME="PRAHO Platform"
BACKUP_CODES_COUNT=8
TOTP_PERIOD=30  # seconds
TOTP_DIGITS=6
```

### Django Settings Override
```python
# config/settings/prod.py
DJANGO_ENCRYPTION_KEY = os.environ.get('DJANGO_ENCRYPTION_KEY')

# Customize 2FA behavior
TOTP_ISSUER_NAME = os.environ.get('TOTP_ISSUER_NAME', 'PRAHO Platform')
BACKUP_CODES_COUNT = int(os.environ.get('BACKUP_CODES_COUNT', '8'))
```

## 👥 User Experience

### 2FA Setup Flow
1. **User navigates to Profile → Security**
2. **Click "Enable 2FA"**
3. **QR Code Display**: User scans with authenticator app
4. **Verification**: User enters 6-digit code to confirm setup
5. **Backup Codes**: System generates and displays 8 backup codes
6. **Confirmation**: User acknowledges saving backup codes

### Authentication Flow
1. **Standard Login**: Email + Password
2. **2FA Prompt**: If 2FA enabled, redirect to verification
3. **Code Entry**: User enters 6-digit TOTP or 8-digit backup code
4. **Verification**: System validates and completes login
5. **Backup Code Warnings**: If backup code used, warn about remaining count

### Admin Tools
- **User Management**: Disable 2FA for users (with audit log)
- **Backup Code Reset**: Generate new backup codes for users
- **Security Dashboard**: View 2FA adoption rates and usage stats
- **Audit Logs**: Track all 2FA-related security events

## 🔄 Operational Procedures

### Key Rotation (Planned Maintenance)

1. **Pre-Rotation Checklist**
   ```bash
   # Backup database
   pg_dump praho_production > backup_pre_rotation.sql

   # Generate new key
   python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"

   # Store old key temporarily
   export OLD_DJANGO_ENCRYPTION_KEY="current_key_value"
   export NEW_DJANGO_ENCRYPTION_KEY="new_key_value"
   ```

2. **Create Rotation Migration**
   ```bash
   python manage.py makemigrations --empty users --name rotate_encryption_key
   # Edit migration to include key rotation logic
   ```

3. **Execute Rotation**
   ```bash
   # Test on staging first
   python manage.py migrate --settings=config.settings.staging

   # Apply to production during maintenance window
   python manage.py migrate --settings=config.settings.prod
   ```

4. **Post-Rotation Verification**
   ```bash
   # Test 2FA functionality
   python manage.py test tests.test_2fa_security_improvements

   # Verify user can authenticate
   # Monitor logs for encryption errors
   ```

### Emergency Key Recovery

**Scenario**: Production encryption key is lost/corrupted

1. **Immediate Actions**
   - Enable maintenance mode
   - Stop all application servers
   - Preserve database backups

2. **Recovery Options**
   - **Key Backup**: Restore from secure key vault
   - **Database Restore**: Restore from last good backup
   - **2FA Reset**: Force disable 2FA for all users (last resort)

3. **2FA Reset Procedure** (Emergency Only)
   ```python
   # Emergency script: reset_2fa.py
   from django.contrib.auth import get_user_model
   User = get_user_model()

   # Disable 2FA for all users
   User.objects.filter(two_factor_enabled=True).update(
       two_factor_enabled=False,
       _two_factor_secret='',
       backup_tokens=[]
   )
   print("2FA disabled for all users - SECURITY NOTICE REQUIRED")
   ```

### Monitoring and Alerting

1. **Key Performance Indicators**
   - 2FA adoption rate: `SELECT COUNT(*) FROM users WHERE two_factor_enabled = true`
   - Backup code usage: Monitor `user_login_logs` for backup code events
   - Failed 2FA attempts: Track failed verification patterns

2. **Security Alerts**
   ```bash
   # Alert on multiple failed 2FA attempts
   SELECT user_id, COUNT(*) as failures
   FROM user_login_logs
   WHERE status = 'failed_2fa'
     AND timestamp > NOW() - INTERVAL '1 hour'
   GROUP BY user_id
   HAVING COUNT(*) > 3;
   ```

3. **Health Checks**
   ```python
   # Health check endpoint
   def health_check_2fa():
       try:
           # Test encryption/decryption
           test_data = "test_secret_data"
           encrypted = encrypt_sensitive_data(test_data)
           decrypted = decrypt_sensitive_data(encrypted)
           return decrypted == test_data
       except Exception:
           return False
   ```

## 🧪 Testing Strategy

### Unit Tests
```bash
# Test encryption utilities
python manage.py test tests.test_2fa_security_improvements.EncryptionUtilsTestCase

# Test user model 2FA methods
python manage.py test tests.test_2fa_security_improvements.UserModel2FATestCase

# Test admin functionality
python manage.py test tests.test_2fa_security_improvements.TwoFactorAdminTestCase
```

### Integration Tests
```bash
# Test complete 2FA flows
python manage.py test tests.test_2fa_security_improvements.TwoFactor2FAViewsTestCase

# Test with different environments
python manage.py test --settings=config.settings.test
```

### Security Tests
```bash
# Test key isolation between environments
python -c "
from apps.common.encryption import encrypt_sensitive_data, decrypt_sensitive_data
import os

# Test with different keys
os.environ['DJANGO_ENCRYPTION_KEY'] = 'key1'
encrypted = encrypt_sensitive_data('test')

os.environ['DJANGO_ENCRYPTION_KEY'] = 'key2'
try:
    decrypt_sensitive_data(encrypted)  # Should fail
    print('ERROR: Key isolation failed')
except:
    print('SUCCESS: Key isolation working')
"
```

## 📊 Analytics and Reporting

### 2FA Adoption Metrics
```sql
-- 2FA adoption rate
SELECT
    COUNT(CASE WHEN two_factor_enabled THEN 1 END) as enabled_users,
    COUNT(*) as total_users,
    ROUND(COUNT(CASE WHEN two_factor_enabled THEN 1 END) * 100.0 / COUNT(*), 2) as adoption_rate
FROM users;

-- Backup code usage trends
SELECT
    DATE_TRUNC('day', timestamp) as date,
    COUNT(*) as backup_code_logins
FROM user_login_logs
WHERE status = 'success'
  AND user_agent LIKE '%backup_code%'
GROUP BY DATE_TRUNC('day', timestamp)
ORDER BY date DESC;
```

### Security Dashboard Queries
```sql
-- Recent 2FA events
SELECT
    u.email,
    ull.timestamp,
    ull.status,
    ull.ip_address
FROM user_login_logs ull
JOIN users u ON ull.user_id = u.id
WHERE ull.status IN ('success_2fa_totp', 'success_2fa_backup_code', 'failed_2fa')
ORDER BY ull.timestamp DESC
LIMIT 100;

-- Users with low backup code counts
SELECT
    u.email,
    jsonb_array_length(u.backup_tokens) as remaining_codes
FROM users u
WHERE u.two_factor_enabled = true
  AND jsonb_array_length(u.backup_tokens) <= 2
ORDER BY remaining_codes ASC;
```

## 🚨 Security Considerations

### Data Protection
- **Encryption at Rest**: TOTP secrets encrypted with Fernet
- **Hashed Backup Codes**: Uses Django's password hashing (Argon2)
- **Secure Transport**: All 2FA operations over HTTPS only
- **Session Security**: 2FA sessions isolated and time-limited

### Audit Trail
- All 2FA setup/disable events logged
- Login attempts with 2FA status tracked
- Admin actions on user 2FA recorded
- IP addresses and user agents captured

### GDPR Compliance
- **Data Minimization**: Only necessary 2FA data stored
- **Encryption**: Sensitive data encrypted at rest
- **Audit Logs**: 7-year retention for Romanian tax compliance
- **Right to Deletion**: 2FA data removed when user account deleted

## 📞 Support and Troubleshooting

### Common Issues

1. **"Invalid 2FA code" Error**
   - Check device time synchronization
   - Verify user entered 6-digit TOTP (not backup code format)
   - Check for typos in authenticator app setup

2. **Lost Authenticator Device**
   - User can use 8-digit backup codes
   - Admin can reset backup codes if needed
   - Last resort: Admin disable 2FA (requires security approval)

3. **Backup Codes Not Working**
   - Ensure exact format (8 digits, no spaces)
   - Check if code was already used (single-use only)
   - Verify user account has backup codes generated

### Debug Commands
```bash
# Check user 2FA status
python manage.py shell -c "
from django.contrib.auth import get_user_model
User = get_user_model()
user = User.objects.get(email='user@example.com')
print(f'2FA Enabled: {user.two_factor_enabled}')
print(f'Backup Codes: {len(user.backup_tokens)}')
"

# Test encryption key
python manage.py shell -c "
from apps.common.encryption import encrypt_sensitive_data, decrypt_sensitive_data
test = 'test_data'
encrypted = encrypt_sensitive_data(test)
decrypted = decrypt_sensitive_data(encrypted)
print(f'Encryption test: {test == decrypted}')
"
```

## 📚 Related Documentation

- [ADR-001: DJANGO_ENCRYPTION_KEY Management](./adrs/ADR-001-django-encryption-key-management.md)
- [Security Architecture Overview](./SECURITY.md)
- [Production Deployment Guide](./DEPLOYMENT.md)
- [GDPR Compliance Documentation](./GDPR.md)

---

**Last Updated**: December 2024
**Version**: 1.0
**Review Schedule**: Quarterly
