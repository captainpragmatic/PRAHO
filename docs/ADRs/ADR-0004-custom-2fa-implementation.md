# ADR-0004: Custom 2FA Implementation vs django-otp

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
- **Encryption**: AES-256-GCM for TOTP secrets
- **Hashing**: Argon2 for backup codes
- **Rate Limiting**: Redis-based with configurable windows
- **Time Windows**: ±30 seconds tolerance for clock drift
- **Audit Trail**: Complete GDPR-compliant logging

### Staff enforcement and recovery (2026-10)

2FA is opt-in unless an administrator switches on `users.mfa_required_for_staff` (off by
default, in the admin-only platform zone of the settings). While it is on, a staff account
without 2FA can only enrol:

- `StaffMFAEnrollmentMiddleware` sends a staff session without 2FA to TOTP setup on every
  Platform page, so sessions that already exist are caught as well as new sign-ins. It is
  registered in base, prod and staging, which each define `MIDDLEWARE`.
- API token issuance (both the API and the staff token page), the Portal login, and every
  signed Portal call made for such an account refuse it: the identity checks in
  `apps/api/secure_auth.py`, session validation, and the few calls that name their user
  themselves (company creation, the person's GDPR calls). An existing Portal session ends at its
  next check.
- Staff cannot disable 2FA, on Platform or through the Portal.

`staff_mfa_required()` in `apps/users/mfa.py` is the setting's only reader; the checks use
`two_factor_enabled` and `User.is_staff_user`.

Enrolment asks for the current password, checked on the locked row in the transaction that
enables 2FA, binds the session to the credentials that transaction committed, and keeps one
secret until it succeeds or the person starts over (a GET that redirects, so a submitted form
never replaces the scanned secret). On Platform, setup, disable and backup-code regeneration
allow 15 attempts an hour per user; on Platform and in the Portal API they answer a wrong
password and a wrong code alike, and a refused attempt stays audited.

**Recovery.** An administrator resets another person's 2FA from their user page
(`users:mfa_admin_reset`: admin only, POST, confirmed, never your own account). The audit
event `2fa_admin_reset` names the administrator as its actor. The person's Platform sessions
end at once; their Portal session ends at its next session check (at most about 12 minutes),
as after any credential change. When no administrator can sign in, for example a sole
administrator who has lost both their authenticator and their backup codes,
`manage.py reset_two_factor --email … --reason …` does the same from the server and is
audited as an operator action with no actor, naming the server account that ran it.

The event's user is whoever acted (the administrator), as for other audit events; the reset
account is its subject (the content object), so queries by user (GDPR export, the audit
filter) list it under the administrator. The reset asks for no password re-entry: misusing it
takes a hijacked administrator session and the target's password, and the event is high
severity and flagged for review.

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
- `docs/security/MFA-SETUP-AND-KEY-MANAGEMENT.md` - Setup documentation
