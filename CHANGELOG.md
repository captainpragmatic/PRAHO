# Changelog

All notable changes to PRAHO Platform will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **Secure Password Reset System**: Complete password reset functionality with 2-hour token expiry
  - Rate limiting (5 attempts/hour per IP, 10/hour per user-agent)
  - Comprehensive audit logging for security monitoring
  - Bilingual templates (Romanian/English) with professional styling
  - Integration with existing UserLoginLog system
  - Account lockout reset on successful password change
  - No user enumeration vulnerability protection

- **Enhanced Two-Factor Authentication Security**: Major security improvements to 2FA system
  - **Encrypted 2FA Secret Storage**: TOTP secrets now encrypted at rest using Fernet encryption
  - **Backup Codes System**: 8 secure backup codes for device recovery
    - One-time use backup codes (8 digits each)
    - Secure hashing using Django's password hashers
    - Automatic consumption after use
    - Low backup code warnings
  - **2FA Recovery Flow**: Complete recovery system for lost authenticator devices
    - Backup code verification during login
    - 2FA disable with password confirmation
    - Backup code regeneration
  - **Admin 2FA Management**: Admin tools for user support
    - Visual backup code count indicators
    - One-click 2FA disable for user recovery
    - Backup code reset functionality
    - Comprehensive audit logging for admin actions
  - **Enhanced Templates**: Professional UI templates for all 2FA flows
    - Backup codes display with copy-to-clipboard
    - Security warnings and guidance
    - Responsive design matching platform branding

### Security
- **2FA Encryption**: Critical fix - 2FA secrets no longer stored in plain text
- **Password Reset Rate Limiting**: Prevents brute force attacks on reset endpoints
- **Backup Code Security**: Secure generation, hashing, and one-time use enforcement
- **Admin Audit Logging**: All admin 2FA actions logged for security monitoring
- **Database Migration**: Secure migration of existing 2FA secrets to encrypted storage

### Technical
- Added `apps/common/encryption.py` for secure data encryption utilities
- Added comprehensive test suite for 2FA security improvements (25+ test cases)
- Database migration for 2FA secret encryption with backward compatibility
- Enhanced admin interface with 2FA management tools
- Added `django-ratelimit` and `cryptography` dependencies

### Fixed
- **Password Reset**: Replaced non-functional placeholder with complete secure implementation
- **2FA Security Vulnerability**: Eliminated plain-text storage of sensitive TOTP secrets

## [v0.3.0] - Previous Release

### Features
- Initial release of PRAHO Platform
- Complete hosting provider management system
- Romanian business compliance (CUI, VAT, e-Factura ready)
- Multi-tenant customer management
- Billing system with Romanian tax compliance
- Basic two-factor authentication
- Comprehensive audit logging

---

### Security Notice

**IMPORTANT**: This release contains critical security improvements for two-factor authentication. If you are upgrading from a previous version:

1. **Set Encryption Key**: Add `DJANGO_ENCRYPTION_KEY` environment variable before migrating
   ```bash
   # Generate a key:
   python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
   ```

2. **Run Migration**: The database migration will encrypt existing 2FA secrets
   ```bash
   python manage.py migrate
   ```

3. **User Action Required**: Users with existing 2FA may need to re-setup if encryption key is not available during migration

4. **Admin Training**: Inform support staff about new admin 2FA management tools

### Romanian Compliance

This release maintains full compliance with Romanian business requirements:
- CUI validation and formatting
- 19% VAT calculations
- Sequential invoice numbering
- GDPR audit trails
- Romanian language localization
- Europe/Bucharest timezone defaults