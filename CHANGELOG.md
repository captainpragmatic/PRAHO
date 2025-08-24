# Changelog

All notable changes to PRAHO Platform will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security
- **🔒 CRITICAL FIX**: Removed CSRF exemption from email check API endpoint
  - Fixed OWASP A04 (Insecure Design) vulnerability allowing cross-site request forgery
  - Added rate limiting (30 requests/minute per IP) to prevent email enumeration
  - Enhanced input validation with email format checking
  - Restored full CSRF protection for all user-facing endpoints
  - Risk Level: Critical → Resolved ✅

### Added
- **VS Code Development Environment**: Enhanced development setup and automation
  - Terminal auto-approve for common dev commands (make test, make dev, git status)
  - Improved Django template syntax highlighting and file associations
  - Better IntelliSense and debugging support for PRAHO development
  - Optimized settings for Django project structure

- **UI/UX Component System**: Modern, consistent user interface components
  - **Reusable Checkbox Component**: Standardized checkbox implementation platform-wide
    - Variant support (primary, warning, success, danger)
    - Perfect text alignment and centering with Romanian theming
    - Required field indicators and error state styling
    - ARIA accessibility and HTMX integration support
  - **PRAHO Platform Branding**: Professional visual identity
    - SVG favicon with PRAHO branding and automation symbols
    - Consistent logo usage in header navigation and authentication pages
    - Removed emoji branding for cleaner professional appearance
    - Admin interface favicon support

- **Customer Management System**: Comprehensive user assignment workflow
  - **User Assignment Workflow**: Three-option customer user assignment
    - Create new user accounts with automated welcome emails
    - Link existing users to customer organizations
    - Skip user assignment for immediate customer creation
  - **CustomerMembership Integration**: Proper relationship management in templates
  - **Service Layer Architecture**: Enhanced CustomerUserService for user management
  - **Bilingual Support**: Complete Romanian/English i18n for all assignment workflows

- **Enhanced Two-Factor Authentication**: Complete custom 2FA implementation
  - **Custom MFA Module**: Professional TOTP implementation with WebAuthn framework
  - **Modern UI/UX Templates**: Card-based method selection with hover effects
    - 3-step setup flow with progress indicators and QR codes
    - Responsive design with Tailwind CSS and mobile-first approach
    - Generic step navigation component for reusability
  - **Admin Security Dashboard**: 2FA adoption metrics and user status overview
    - Low backup codes alerts and quick reset actions
    - Recent 2FA activity monitoring with IP tracking
    - Security recommendations and Django admin integration

- **Development Infrastructure**: Improved development experience
  - **Automatic .env Loading**: python-dotenv integration for local development
  - **Test Organization**: Mirror directory structure following apps/ layout
  - **macOS Compatibility**: Updated Makefile to use python3 for macOS

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

- **Secure Password Change**: Enhanced password change functionality with security improvements
  - SecurePasswordChangeView with rate limiting and audit logging
  - Current password verification for security
  - Romanian business styling and dark theme compatibility
  - Complete integration from user profile page

### Security
- **2FA Encryption**: Critical fix - 2FA secrets no longer stored in plain text
- **Password Reset Rate Limiting**: Prevents brute force attacks on reset endpoints
- **Backup Code Security**: Secure generation, hashing, and one-time use enforcement
- **Admin Audit Logging**: All admin 2FA actions logged for security monitoring
- **Database Migration**: Secure migration of existing 2FA secrets to encrypted storage
- **Password Change Security**: Enhanced password change with current password verification
- **Development Security**: Improved input field styling fixing white-on-white visibility issues

### Technical
- **Component Architecture**: Reusable UI component system for consistent theming
  - checkbox_field template tag with comprehensive parameter support
  - Generic step navigation components for multi-step workflows
  - Consistent Romanian business compliance theming
- **Environment Management**: 
  - Added automatic .env file loading with python-dotenv integration
  - DJANGO_ENCRYPTION_KEY configuration for 2FA encryption
  - Clear logging feedback for development environment setup
- **Test Infrastructure**:
  - Reorganized tests to mirror apps/ directory structure
  - Integration tests directory for cross-app workflow testing
  - Enhanced test discovery and pytest compatibility
- **Development Tools**:
  - VS Code settings optimization for Django development
  - Terminal auto-approval for common development commands
  - Improved Django template syntax highlighting
- **Internationalization**: Enhanced i18n implementation with updated locale files
  - Missing i18n imports added to template components
  - Improved Romanian translations for modal actions and system messages
  - Cleaner translation management with fixed duplicate entries
- Added `apps/common/encryption.py` for secure data encryption utilities
- Added comprehensive test suite for 2FA security improvements (25+ test cases)
- Database migration for 2FA secret encryption with backward compatibility
- Enhanced admin interface with 2FA management tools
- Added `django-ratelimit`, `cryptography`, and `python-dotenv` dependencies
- Custom MFA module (apps/users/mfa.py) with TOTP, backup codes, WebAuthn framework
- 2FA table naming consistency improvements and index optimization

### Fixed
- **Password Reset**: Replaced non-functional placeholder with complete secure implementation
- **2FA Security Vulnerability**: Eliminated plain-text storage of sensitive TOTP secrets
- **Customer Template Queries**: Fixed customer detail template to use customer.memberships.exists()
- **Input Field Styling**: Fixed white text on white background in dark theme form inputs
- **macOS Development**: Updated Makefile python commands for macOS compatibility
- **Template Accessibility**: Improved checkbox component accessibility and error handling
- **Navigation Branding**: Removed redundant "Hello" greeting from navigation header

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

5. **Development Setup**: Use automatic .env file loading for local development
   ```bash
   # .env file automatically loaded by manage.py
   echo "DJANGO_ENCRYPTION_KEY=your_key_here" >> .env
   ```

### Development Improvements

This release significantly improves the development experience:

- **VS Code Integration**: Enhanced settings for Django development with auto-approval for common commands
- **Component System**: Reusable UI components for consistent Romanian business theming
- **Test Organization**: Restructured tests to mirror apps/ directory for better maintainability
- **Environment Setup**: Automatic .env loading eliminates manual environment variable management
- **macOS Compatibility**: Fixed Python command compatibility for macOS development environments

### Romanian Compliance

This release maintains full compliance with Romanian business requirements:
- CUI validation and formatting
- 19% VAT calculations
- Sequential invoice numbering
- GDPR audit trails
- Romanian language localization
- Europe/Bucharest timezone defaults