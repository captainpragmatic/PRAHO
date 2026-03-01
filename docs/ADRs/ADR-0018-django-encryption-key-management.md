# ADR-0018: DJANGO_ENCRYPTION_KEY Management for 2FA Security

## Status
**Accepted** - December 2024

## Context

The PRAHO Platform implements Two-Factor Authentication (2FA) with encrypted storage of sensitive user data including TOTP secrets and backup codes. This requires a robust encryption key management strategy to ensure:

1. **Data Security**: TOTP secrets and backup codes must be encrypted at rest
2. **Key Rotation**: Support for periodic key rotation without data loss
3. **Environment Isolation**: Different keys for development, testing, and production
4. **Recovery**: Ability to decrypt data for legitimate access while preventing unauthorized access
5. **Compliance**: Meet Romanian GDPR requirements for data protection

## Decision

### 1. Encryption Algorithm
- **Algorithm**: Fernet (symmetric encryption) from the Python `cryptography` library
- **Rationale**:
  - Cryptographically secure with AES 128 in CBC mode
  - Built-in timestamp verification
  - Simple key derivation from URL-safe base64 encoded strings
  - Well-tested and widely adopted in Django applications

### 2. Key Storage and Management
- **Environment Variable**: `DJANGO_ENCRYPTION_KEY`
- **Format**: 32-byte Fernet key encoded as URL-safe base64 string (44 characters)
- **Generation Command**:
  ```bash
  python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
  ```

### 3. Environment-Specific Keys
- **Development**: Stored in `.env` file (excluded from git via `.gitignore`)
- **Testing**: Loaded from `.env` during test runs via `manage.py` dotenv integration
- **Production**: Set via secure environment variable injection (Docker secrets, K8s secrets, etc.)

### 4. Implementation Details
```python
# apps/common/encryption.py
def get_encryption_key():
    """Get encryption key from Django settings or environment"""
    # Try Django settings first (for test overrides)
    encryption_key = getattr(settings, 'DJANGO_ENCRYPTION_KEY', None)

    if not encryption_key:
        # Try environment variable
        encryption_key = os.environ.get('DJANGO_ENCRYPTION_KEY')

    if not encryption_key:
        raise ImproperlyConfigured(
            "DJANGO_ENCRYPTION_KEY environment variable must be set"
        )

    return encryption_key.encode() if isinstance(encryption_key, str) else encryption_key
```

### 5. Data Encrypted
- **TOTP Secrets**: User 2FA TOTP secrets in `User._two_factor_secret` field
- **Backup Codes**: Stored as hashed values (not encrypted) using Django's password hashing
- **Future**: Additional PII fields as needed for GDPR compliance

### 6. Key Rotation Strategy
- **Migration Support**: Custom Django migration to re-encrypt data with new keys
- **Dual Key Period**: Support temporary dual-key operation during rotation
- **Zero Downtime**: Rotation possible without service interruption
- **Audit Trail**: All key rotation events logged for compliance

## Consequences

### Positive
- **Security**: Sensitive 2FA data encrypted at rest with industry-standard encryption
- **Compliance**: Meets Romanian GDPR requirements for data protection
- **Flexibility**: Easy to rotate keys without data loss
- **Auditability**: Clear audit trail of encryption operations
- **Testability**: Test-specific keys don't interfere with development

### Negative
- **Complexity**: Additional operational complexity for key management
- **Dependencies**: Requires `cryptography` library and proper key distribution
- **Key Loss Risk**: Lost encryption key means permanent data loss
- **Performance**: Slight overhead for encrypt/decrypt operations (negligible for 2FA use case)

### Risks and Mitigations
1. **Key Loss**:
   - Risk: Lost key = permanent data loss
   - Mitigation: Secure backup procedures, multiple key escrow locations
2. **Key Exposure**:
   - Risk: Exposed key compromises all encrypted data
   - Mitigation: Secure storage, regular rotation, access auditing
3. **Migration Failures**:
   - Risk: Key rotation migration could corrupt data
   - Mitigation: Comprehensive testing, database backups before rotation

## Implementation Notes

### Migration Example (Future Key Rotation)
```python
# Migration: 0004_rotate_encryption_key.py
def rotate_encryption_key(apps, schema_editor):
    """Rotate encryption key for all encrypted fields"""
    User = apps.get_model('users', 'User')

    old_key = os.environ.get('OLD_DJANGO_ENCRYPTION_KEY')
    new_key = os.environ.get('DJANGO_ENCRYPTION_KEY')

    for user in User.objects.filter(two_factor_enabled=True):
        # Decrypt with old key, encrypt with new key
        if user._two_factor_secret:
            old_fernet = Fernet(old_key.encode())
            new_fernet = Fernet(new_key.encode())

            decrypted = old_fernet.decrypt(user._two_factor_secret.encode())
            user._two_factor_secret = new_fernet.encrypt(decrypted).decode()
            user.save(update_fields=['_two_factor_secret'])
```

### Production Deployment
```dockerfile
# Dockerfile
ENV DJANGO_ENCRYPTION_KEY=""
# Key injected at runtime via orchestration secrets
```

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

## Testing Strategy
- **Unit Tests**: Use temporary generated keys via `@patch.dict(os.environ)`
- **Integration Tests**: Use test-specific key loaded from `.env`
- **Security Tests**: Verify encryption/decryption integrity and key isolation

## Monitoring and Alerting
- **Key Usage**: Monitor encryption/decryption operations for anomalies
- **Key Rotation**: Alert on rotation events and failures
- **Access Logs**: Log all key access for security auditing

## Related Documents
- GDPR Compliance Documentation
- Security Incident Response Plan
- Database Backup and Recovery Procedures
- Production Deployment Guide

---

**Decision Date**: December 2024
**Decision Makers**: Development Team, Security Team
**Review Date**: June 2025 (6-month review cycle)
