# ADR-004: Custom 2FA Implementation vs django-otp

## Status
✅ **Accepted** - 2024-08-24

## Context
PRAHO Platform requires Two-Factor Authentication (2FA) for enhanced security, particularly for admin users and sensitive customer data access. We evaluated using the popular `django-otp` library versus building a custom implementation.

## Decision Drivers
1. **Romanian Compliance** - GDPR and local audit requirements
2. **UI/UX Standards** - Modern card-based interface requirements
3. **Architecture Consistency** - Services pattern across platform
4. **Future Extensibility** - WebAuthn/Passkeys support planned
5. **Performance Requirements** - O(1) lookups, Redis caching

## Options Considered

### Option 1: django-otp Library
**Pros:**
- ✅ Battle-tested security (thousands of production deployments)
- ✅ Regular security updates from community
- ✅ Built-in support for HOTP, Yubikey, SMS
- ✅ Comprehensive test coverage
- ✅ ~200 hours saved on initial development

**Cons:**
- ❌ Forces `Device` model naming vs our `two_factor_*` convention
- ❌ Generic forms incompatible with our card-based UI
- ❌ No Romanian-specific audit event types
- ❌ Scattered across multiple Django apps vs single module
- ❌ Migration would require ~140 hours to match current functionality

### Option 2: Custom Implementation (CHOSEN)
**Pros:**
- ✅ Full control over modern UI/UX (card layouts, progress indicators)
- ✅ Romanian compliance with 11 custom audit event types
- ✅ Unified architecture in single `apps/users/mfa.py` module
- ✅ WebAuthn/Passkeys framework ready
- ✅ Custom business logic (rate limiting, replay protection)
- ✅ O(1) performance with Redis caching
- ✅ Consistent with platform's services.py pattern

**Cons:**
- ❌ Security responsibility on our team
- ❌ More code to maintain (~700 lines)
- ❌ Need to implement security patches ourselves

## Decision
**We will maintain our custom 2FA implementation** in `apps/users/mfa.py`.

## Rationale

### 1. UI/UX Excellence
Our modern card-based designs with progress indicators provide superior user experience:
- 3-step visual flow (Choose Method → Setup → Complete)
- Positioned badges for recommendations
- Hover effects and transitions
- Mobile-first responsive design

### 2. Romanian Compliance
Custom audit events required for local regulations:
```python
'2FA_ENABLED', '2FA_DISABLED', '2FA_LOGIN_SUCCESS',
'2FA_LOGIN_FAILED', 'BACKUP_CODES_GENERATED',
'BACKUP_CODE_USED', 'WEBAUTHN_CREDENTIAL_ADDED',
'WEBAUTHN_CREDENTIAL_REMOVED', 'WEBAUTHN_LOGIN_SUCCESS',
'WEBAUTHN_LOGIN_FAILED', '2FA_ADMIN_RESET'
```

### 3. Architecture Consistency
Follows platform patterns:
```python
apps/users/mfa.py
├── TOTPService         # TOTP generation/verification
├── BackupCodeService   # Backup codes with Argon2
├── WebAuthnService     # Future passkeys support
└── MFAService         # Orchestrator with audit
```

### 4. Performance Control
- O(1) lookups via Redis caching
- Custom rate limiting (5 attempts/5 minutes)
- Replay protection with 90-second windows
- Optimized for Romanian hosting scale

## Implementation Details

### Security Measures
- **Encryption**: Fernet (AES-256) for TOTP secrets
- **Hashing**: Argon2 for backup codes
- **Rate Limiting**: Redis-based with configurable windows
- **Time Windows**: ±30 seconds tolerance for clock drift
- **Audit Trail**: Complete GDPR-compliant logging

### Testing Strategy
- Unit tests: `tests/users/test_mfa_services.py`
- Security tests: `tests/integration-tests/test_mfa_security.py`
- Integration tests with Redis and audit system
- Manual testing with popular authenticator apps

## Consequences

### Positive
- ✅ Full control over user experience
- ✅ Romanian business context integrated
- ✅ Consistent architecture across platform
- ✅ WebAuthn ready for future enhancement
- ✅ No external dependency security risks

### Negative
- ⚠️ Security review responsibility on our team
- ⚠️ Need to track CVEs and implement patches
- ⚠️ Higher maintenance burden long-term
- ⚠️ Missing advanced features (Yubikey, HOTP)

### Mitigation
- Regular security audits (quarterly)
- Comprehensive test coverage (>90%)
- Follow OWASP guidelines
- Monitor django-otp for security patterns

## Review Triggers
Reconsider this decision if:
- Need for hardware token support (Yubikey)
- Enterprise SSO/SAML requirements
- Security incident related to custom code
- Team size reduction affecting maintenance

## References
- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- [django-otp Documentation](https://django-otp-official.readthedocs.io/)
- [RFC 6238 - TOTP](https://tools.ietf.org/html/rfc6238)
- [WebAuthn Specification](https://www.w3.org/TR/webauthn/)

## Related Documents
- `apps/users/mfa.py` - Custom MFA implementation
- `tests/integration-tests/test_mfa_security.py` - Security test suite
- `docs/2FA-SETUP-AND-KEY-MANAGEMENT.md` - Setup documentation
