# Changelog

All notable changes to PRAHO Platform will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

_No unreleased changes._

### Planned for v1.0.0
- Production deployment and hardening
- Complete template system with polished UI
- Comprehensive test coverage (>90%)
- Production deployment guides and Docker optimization

### Planned for v1.1.0+
- Advanced business intelligence dashboards
- Mobile application for technicians
- Multi-tenant architecture for resellers
- API-first architecture with GraphQL

---

## [0.13.0] - 2026-02-11

### Added
- **GDPR Cookie Consent on Portal**: Moved cookie consent system from Platform (staff-only) to Portal (customer-facing) where GDPR compliance actually matters
  - Cookie consent banner with granular per-category controls (essential, functional, analytics, marketing)
  - Cookie policy page accessible without authentication, bilingual (RO/EN)
  - Footer links for Cookie Policy and Cookie Preferences re-opening
  - Server-side consent recording via HMAC-authenticated Platform API
  - Anonymous visitor consent via `cookie_id`, linked to user account on login
- **GDPR API Namespace** (`/api/gdpr/`): Three new Platform endpoints for Portal-to-Platform GDPR communication
  - `POST /api/gdpr/cookie-consent/` — Record consent (anonymous or authenticated)
  - `POST /api/gdpr/consent-history/` — Fetch consent history for authenticated users
  - `POST /api/gdpr/data-export/` — Request GDPR data export (Article 20)
- **Portal GDPR Views Wired to Real Data**: Consent history and data export views now call Platform API instead of using mock/TODO stubs
- **Audit Coverage**: Security logging for payments, notifications, tickets, and promotions via centralized AuditService
- **ADR-0014**: No-test-suppression policy with automated scanner (`scripts/lint_test_suppressions.py`) integrated into `make lint`
- **Audit Coverage Scanner** (`scripts/audit_coverage_scan.py`): Automated detection of unaudited security-sensitive operations

### Changed
- **E2E Test Suite Stabilized**: 166/166 passing (was 76 failing), removed 11 duplicate test files (-11.4k lines)
- Portal membership cache uses TTL-based invalidation (5-min expiry) to prevent stale session data
- Portal role resolver performs fresh fetch from Platform API before fallback
- Rate limiting middleware respects `RATELIMIT_ENABLE` Django setting and environment variable
- DRF throttling disabled in test and dev-test environments

### Fixed
- Infrastructure URL wiring in Platform router and nav context processor
- Portal login membership caching (populate `user_memberships` in session on login)
- Portal ticket creation API call signature (`dict` to `TicketCreateRequest`)
- `getattr` instead of `hasattr` for `_portal_authenticated` check (defensive coding)
- Hardcoded `/cookie-policy/` URL replaced with `{% url 'cookie_policy' %}` in Portal footer
- Unused `import json` removed from E2E test module
- Flaky `page.on('response')` replaced with deterministic `page.expect_response()` in E2E tests

### Security
- HMAC staff session bypass restricted from all `/api/*` to explicit allowlist
- Portal role fallback hardened: `owner` role for verified primary customer only
- Customer create API now requires HMAC authentication
- `@throttle_classes([])` on GDPR API views to bypass DRF global throttle on service-to-service endpoints
- Cookie consent signal (`cookie_consent_updated`) now emits for audit trail creation

---

## [0.12.0] - 2026-02-10

### Added
- **e-Factura Integration**: Complete Romanian electronic invoicing with XML generation and ANAF submission
- **Subscription Billing**: Recurring billing engine with PDF invoice generation
- **Usage-Based Billing**: Metering and tiered pricing system for hosting resources
- **Promotions System**: Coupons, discounts, and loyalty program management
- **Multi-Provider Email**: Pluggable email sending infrastructure (SMTP, SendGrid, Mailgun)
- **VPS Node Deployment**: Terraform + Ansible automation for server provisioning
- **AES-256-GCM Encryption**: Enhanced credential and data encryption at rest
- **SIEM Integration**: Security event logging and compliance monitoring
- **GDPR Cookie Consent**: Cookie consent banner and legal pages
- **File Integrity Monitoring**: Upload security and integrity checking
- **Dynamic Analysis Middleware**: Trace-based runtime analysis tooling
- **Static Flow Analysis**: Codebase analysis tooling
- **E2E Test**: Signup-to-order flow end-to-end test
- **Idempotent Rollback Tracking**: Enhanced provisioning rollback reliability

### Changed
- CI/CD migration from pip to uv package manager
- CI workflows upgraded setup-uv from v4 to v7
- Comprehensive test coverage infrastructure improvements

### Fixed
- Portal security hardening and input validation
- Race conditions in webhook and refund processing
- Pre-existing test failures in CI pipeline
- Merge conflict resolution across 14 files
- Portal requirements for Django 5.2 and python-ipware compatibility

### Security
- OWASP vulnerability remediation (P1-P3 audit findings)
- SSL/TLS configuration hardened for production
- Security audit findings addressed across platform
- Caching, connection pooling, and rate limiting middleware

---

## [0.11.0] - 2026-02-09

### Added
- **Platform/Portal Service Separation**: Complete architectural split into two Django services
  - **Platform Service** (staff/admin): Business operations, billing, provisioning, customer management
  - **Portal Service** (customer-facing): Order placement, service management, account self-service
- **HMAC API Authentication**: SHA-256 signed inter-service communication
- **Stripe Payment Integration**: Complete payment flow with payment intents and webhook processing
- **Async Provisioning**: Celery-based task queue for service provisioning with failure tracking
- **Order Checkout Flow**: End-to-end order placement from portal through platform API

### Fixed
- CI workflow requirements paths updated for services architecture
- Django test runner configured for platform CI

---

## [0.10.0] - 2025-09-05

### Added
- **Services-Based Architecture Migration**: Complete restructure into `services/platform` and `services/portal` layout
- Production-ready Virtualmin optimizations and architecture improvements

### Changed
- Monorepo layout established for multi-service architecture
- Refund service transaction handling improvements
- Credential vault enhancements

---

## [0.9.0] - 2025-09-04

### Added
- **Virtualmin Integration**: Two-phase provisioning with rollback capability
  - Pre-flight validation (server capacity, domain availability, resource limits)
  - Ordered rollback operations for failed provisioning
- **Credential Vault**: Fernet-encrypted credential storage with monthly rotation
- **PRAHO-as-Source-of-Truth**: Authoritative data model driving all Virtualmin operations
- **Multi-Path Authentication**: ACL risk mitigation with SSH/sudo fallback
- **Production Safety**: Health checks, rate limiting, retry logic with exponential backoff
- **Virtualmin Account Protection**: Security system for provisioned accounts
- Comprehensive type safety and code quality improvements

### Changed
- Migrated from Celery to Django-Q2 for task processing
- Feature-based file organization for provisioning and customers apps

---

## [0.8.0] - 2025-08-31

### Added
- **Secure IP Detection**: Centralized `get_safe_client_ip()` with CIDR-based trusted proxy configuration (IPv4/IPv6)
- **HTTPS Security Hardening**: Environment-specific SSL/TLS configuration
  - Production: SSL redirect, secure cookies, HSTS (1 year)
  - Staging: Flexible HTTPS with shorter HSTS for rollback safety
  - Development: HTTPS disabled for local development
- **Email Enumeration Prevention**: Uniform response system eliminating account discovery attacks
  - Zero database queries, consistent timing with jitter, same HTTP status regardless of email existence
- **System Settings App**: Centralized configuration management with category-based organization

### Changed
- 100% lint compliance achieved across entire platform
- Cross-app security hardening with comprehensive test coverage
- Billing system security enhancements
- Settings encryption and access control refinement

### Security
- IP spoofing attack prevention with CIDR-based proxy validation
- Production HSTS (1 year), secure cookies, SSL redirect
- Email enumeration vulnerability eliminated (OWASP A01, A04, A07)
- Django system checks for security configuration validation

---

## [0.7.0] - 2025-08-30

### Added
- **Complete Domain Management System**
  - TLD management with registration/renewal/transfer pricing
  - Multi-registrar framework with cost tracking and profit margins
  - Domain lifecycle: registration, renewal, transfer, expiration monitoring
  - Romanian-specific TLD support (`.ro`, `.com.ro`)
  - Domain-order integration with `DomainOrderItem` model
- **Service Relationships & Groups**
  - Parent-child service hierarchies (hosting -> domains -> SSL)
  - ServiceGroup and ServiceGroupMember for package management
  - ServiceDomain model for service-domain binding
- **System Settings**: Centralized configuration with category-based organization
- Comprehensive test suites for common, customers, orders, tickets
- Enhanced provisioning UI templates
- Staff management E2E test suites

---

## [0.6.0] - 2025-08-28

### Added
- **GDPR Compliance System**: Complete Romanian GDPR (Law 190/2018) implementation
  - Data export with immediate JSON download
  - Secure data deletion workflow with confirmation
  - Consent history tracking with timeline visualization
  - Privacy dashboard for user self-service
- **Comprehensive Audit System**: 200+ categorized action types with signal-based logging
  - Authentication audit with security logging
  - Business transaction audit with 100+ event types
  - GDPR management dashboard for staff
- **Order Management**: Complete order lifecycle with Romanian VAT compliance
- **Bidirectional Refund System**: Order-invoice synchronized refund processing
  - Full and partial refunds with amount validation
  - Refund reason categories for audit compliance
  - Payment gateway integration ready (Stripe/PayPal)
- Modernized navigation header with dropdown menus

### Removed
- **BREAKING: Django Admin Interface** completely removed (4,239 lines across 11 files)
  - Replaced by custom staff interface at `/app/`
  - Following NetBox v4.0 pattern for hosting platforms
  - Staff users must use `/app/` instead of `/admin/`

---

## [0.5.0] - 2025-08-27

### Added
- **Order Management System**: Complete order lifecycle with status workflow
  - Status progression: draft -> pending -> processing -> completed -> refunded
  - Romanian VAT-compliant order totals with sequential numbering (ORD-YYYYMMDD-XXXXXX)
- **Romanian Business Types System**: Centralized type system for compliance
  - `CUIString`, `VATString`, `Money`, `PhoneNumber`, `EmailAddress`, `DomainName`
  - Result pattern: Rust-inspired `Ok[T]`/`Err[E]` error handling
  - Django integration types: `RequestHandler`, `AjaxHandler`, `HTMXHandler`
- **Type Safety Enhancement**: 33.4% reduction in type errors (842 -> 561)
  - 170 ANN001 + 111 ANN201 errors fixed
  - MyPy strict mode configured with Django type stubs
- **Strategic Linting Framework**: Ruff + MyPy with business-focused rules
- Modernized UI: Shadcn-style pagination, badge component
- Comprehensive E2E testing (invoices, tickets, mobile)
- Complete Romanian translations for dashboard

### Changed
- Django upgrade from 5.0 to 5.2
- Code deduplication: consolidated phone/CUI/VAT validation into centralized types
- JSON response standardization with `json_success()`/`json_error()`

### Fixed
- N+1 query optimization for User model methods (smart prefetch detection)
- 10 PERF401 performance anti-patterns eliminated

---

## [0.4.0] - 2025-08-25

### Added
- **Secure Password Reset**: Rate-limited (5/hour per IP) with 2-hour token expiry
  - Comprehensive audit logging, bilingual templates (RO/EN)
  - Account lockout reset on successful password change
- **2FA Encryption**: TOTP secrets encrypted at rest using Fernet encryption
- **Backup Codes System**: 8 secure one-time use recovery codes per user
  - Hashed with Django password hashers, automatic consumption after use
- **2FA Recovery Flow**: Complete recovery for lost authenticator devices
- **Session Security System**: Dynamic role-based timeouts
  - Admin/Billing: 30 min, Standard: 1 hr, Shared Device: 15 min, Remember Me: 7 days
  - Automatic session rotation on password/2FA changes
  - Multi-IP detection for suspicious activity (3+ IPs within 1 hour)
- **Enterprise Security Framework**: Validation decorators and rate limiting
  - `@secure_user_registration`, `@secure_customer_operation`, `@atomic_with_retry`
  - Injection attack prevention (XSS, SQL injection, code execution patterns)
  - Privilege escalation prevention
- **Customer User Assignment**: Three-option workflow (create, link, skip)
- **Ticket Replies System**: Comprehensive reply system with internal comments
- **Mobile Navigation**: Responsive header with DRY components
- **UI Components**: PRAHO favicon, consistent checkbox component, auth page branding

### Fixed
- CSRF exemption removed from email check API (OWASP A04)
- XSS vulnerabilities in templates: `|safe` replaced with `|escape` (OWASP A07)
- Cryptographic security: insecure random replaced with `secrets` for MFA backup codes
- Enhanced Content Security Policy headers

### Security
- OWASP A01 (Access Control), A02 (Crypto), A03 (Injection), A04 (Design), A07 (Auth)
- Rate limiting on registration (5/hr), invitations (10/hr), company validation (30/hr)

---

## [0.3.0] - 2025-08-20

### Added
- **Initial Release**: Complete hosting platform foundation for Romanian providers
- **8 Django Apps**: Users, Customers, Billing, Tickets, Provisioning, Audit, Common, UI
- **Email-Based Authentication**: Custom user model (no usernames), profile system, customer memberships
- **Customer Management**: Normalized profiles (Tax, Billing, Address), CUI/VAT validation, multi-user access
- **Billing System**: Proforma/Invoice models, sequential numbering, multi-currency (RON/EUR/USD)
- **Tax/VAT Compliance**: Romanian 19% VAT, EU cross-border handling, VIES integration ready
- **Dunning System**: Automated payment retry with configurable per-tier policies
- **Product Catalog**: Hosting products with multi-currency pricing and billing cycles
- **Order System**: Complete order lifecycle management with Romanian compliance
- **Support Tickets**: SLA tracking, ticket numbering (TK2024-XXXXX), file attachments, time tracking
- **Service Provisioning**: Plans, server management, lifecycle tracking, Virtualmin API ready
- **Audit & Compliance**: Immutable logging, GDPR tracking, Romanian compliance
- **Notifications System**: 14 bilingual email templates (RO/EN) for all customer communications
  - Billing, payment reminders, service activation, support, onboarding
- **Webhook Deduplication**: Stripe-ready event processing with exponential backoff retry
- **Domain Management**: Multi-registrar support (.ro via ROTLD, international via Namecheap/GoDaddy)
- **Service Relationships**: Parent-child hierarchies, service groups for hosting packages
- **UI Components**: Template tags for Romanian business formatting, HTMX foundations
- **Database Performance**: Composite indexes for orders, domains, services, and provisioning tasks

### Security
- Argon2 password hashing, CSRF protection, secure cookies
- Append-only audit trails for forensic analysis
- e-Factura compliance ready (XML generation)
- GDPR data export, erasure, and consent tracking

---

## Version History Summary

| Version | Date | Milestone |
|---------|------|-----------|
| 0.13.0 | 2026-02-11 | GDPR Cookie Consent, Audit Coverage & E2E Stabilization |
| 0.12.0 | 2026-02-10 | Billing, e-Factura & CI Stabilization |
| 0.11.0 | 2026-02-09 | Platform/Portal Service Separation |
| 0.10.0 | 2025-09-05 | Services Architecture Migration |
| 0.9.0 | 2025-09-04 | Virtualmin Integration |
| 0.8.0 | 2025-08-31 | Security Infrastructure & Compliance |
| 0.7.0 | 2025-08-30 | Domain Management & System Settings |
| 0.6.0 | 2025-08-28 | GDPR Compliance & Admin Removal |
| 0.5.0 | 2025-08-27 | Order Management & Type Safety |
| 0.4.0 | 2025-08-25 | Security & Authentication Hardening |
| 0.3.0 | 2025-08-20 | Initial Release - Core Foundation |

---

**For detailed technical information, see [ARCHITECTURE.md](ARCHITECTURE.md) and the `/docs/decisions/` folder for Architecture Decision Records.**
