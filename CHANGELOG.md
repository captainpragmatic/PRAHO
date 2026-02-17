# Changelog

All notable changes to PRAHO Platform will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

_No unreleased changes._

---

## [0.16.0] - 2026-02-17

### Changed
- **Lint Zero-Debt**: Eliminated all Ruff violations across Platform and Portal services — zero warnings, zero errors
- **Portal Lint**: Reduced portal lint debt with code fixes and type annotations
- **Platform Lint**: Reduced lint debt across billing, orders, API, audit, common, and remaining apps
- **Lint Infrastructure**: Fixed URL collisions, deploy check, and test suppressions in lint tooling
- **SettingsService Coverage**: Wired 78 hardcoded constants to `SettingsService` with getter functions, backward-compatible aliases, and `DEFAULT_SETTINGS` entries (224 total keys)

### Added
- **Type Stubs**: Added type stubs and expanded MyPy overrides for third-party libraries
- **Settings Allowlist**: Added `scripts/settings_allowlist.txt` for structural constants that cannot be runtime-configurable

### Fixed
- **pyproject.toml**: Updated lint configuration — scoped Ruff rules for runtime import architecture, expanded MyPy overrides

---

## [0.15.2] - 2026-02-16

### Added
- **Audit Enforcement**: Added ADR-0016 and a model allowlist with justification requirements to formalize audit-trail coverage policy
- **Audit Coverage Tests**: Added runtime model-classification checks and signal-registration regression tests for critical apps
- **Audit Pipeline Tests**: Added integration/E2E tests for settings, billing, notifications, and customer audit event creation paths

### Fixed
- **Signal Registration**: Restored `ready()` signal imports for `billing`, `orders`, `customers`, and `domains` apps to ensure receivers are connected at startup
- **Tax Rate Migration Drift**: Added migrations to align `InvoiceLine.tax_rate` and `OrderItem.tax_rate` schema metadata with current model definitions
- **Portal Security**: Hardened security defaults and removed lint regressions
- **CI Pipeline**: Fixed baseline SHA fetching and hardened ruff no-new-debt baseline resolution
- **Portal Isolation**: Hardened runtime and E2E test settings to enforce stateless behavior
- **E2E Workflow**: Stabilized development and test workflow
- **Pre-commit Hooks**: Stabilized compatibility and enabled configured hooks with local cache isolation
- **Audit Coverage**: Enforced signal wiring and model audit lifecycle coverage for all critical models

### Changed
- **Platform Lint Debt**: Reduced technical debt with safe complexity and security fixes
- **Repository Normalization**: Applied repository-wide normalization and refactor updates

---

## [0.15.1] - 2026-02-15

### Fixed
- **Settings**: Corrected default values, removed stale caches, and added missing configuration keys identified during code review (#9)
- **Billing**: Replaced deprecated `CheckConstraint.check` with `.condition` to align with Django 5.2 API changes

---

## [0.15.0] - 2026-02-12

### Changed
- **Configuration Sprawl Cleanup**: Eliminated hardcoded `ROMANIAN_VAT_RATE` from 5 locations (`constants.py`, `types.py`, `context_processors.py`, `products/signals.py`, `base.py`). All callsites now use `TaxService.get_vat_rate('RO')` per ADR-0005/ADR-0015
- **Billing Terms Consolidated**: Wired invoice payment terms, proforma validity, and payment grace period through `SettingsService` with proper fallback cascade. Renamed setting key `billing.invoice_due_days` → `billing.invoice_payment_terms_days` with data migration preserving admin overrides
- **Invoice Payment Terms Corrected**: Default payment terms aligned to 14 days across `constants.py`, `SettingsService`, and `billing/config.py` (previously 30 in constants, 14 in config — now consistent)
- **Page Size Unified**: `DEFAULT_PAGE_SIZE` corrected from 25 → 20 across `constants.py`, `mixins.py`, and billing views (previously inconsistent between modules)
- **Proforma/Invoice Views Dynamic**: 7 hardcoded `timedelta(days=30)` and `Decimal("21.00")` VAT values in `billing/views.py` replaced with SettingsService and TaxService calls

### Removed
- `ROMANIAN_VAT_RATE` and `ROMANIAN_VAT_RATE_PERCENT` from `constants.py` and `types.py` (use `TaxService` instead)
- `VAT_RATE` and `ROMANIA_VAT_RATE` from `config/settings/base.py` (redundant with TaxService)
- Dead constants: `PASSWORD_RESET_TOKEN_VALIDITY_HOURS`, `EMAIL_SEND_RATE_PER_HOUR` (never imported, conflicted with authoritative sources)
- Dead SettingsService key: `users.password_reset_timeout_hours` (Django's `PASSWORD_RESET_TIMEOUT` is authoritative)
- Dead alias: `INVOICE_DUE_DATE_DAYS` from `billing/config.py` (zero consumers)

### Added
- `get_invoice_payment_terms_days()` in `billing/config.py` — reads from SettingsService with env-var fallback, positive-value clamping, and logged exception handling
- Data migration `0002_rename_invoice_due_days_key` — idempotent rename with key-collision handling
- **12 guardrail tests** preventing configuration drift:
  - `test_constants_consistency.py`: VAT sprawl guard, billing term sync, page size consistency, dead constant detection, `calculate_romanian_vat` TaxService integration, context processor regression
  - `test_billing_terms.py`: SettingsService billing term defaults and DB override integration tests

---

## [0.14.0] - 2026-02-12

### Added
- **ADR-0015: Configuration Resolution Order** — Documents the 4-tier configuration cascade pattern (Cache → DB → Settings → Code Defaults) as a platform-wide architectural standard, with decision criteria for when to use each tier
- **Temporal VAT Rate Support**: `TaxRule` model now seeds historical (19%, pre-Aug 2025) and current (21%, post-Aug 2025) Romanian rates via `setup_tax_rules` management command
- **Per-Customer VAT Overrides**: Wired orphaned `CustomerTaxProfile` fields (`is_vat_payer`, `vat_rate`, `reverse_charge_eligible`) into the VAT calculation flow via `TaxService` and `OrderVATCalculator`
- **VAT Guard Test**: Grep-based test that scans `apps/` for hardcoded `Decimal("0.19")` or `Decimal("19.00")` outside allowlisted files, preventing future rate sprawl
- **Temporal VAT Boundary Tests**: Tests verifying correct rate resolution at the July 31 / August 1, 2025 transition boundary
- **E2E Test**: Playwright test verifying proforma form dropdown shows 21%/11%/0% with no stale 19%

### Changed
- **Single Source of Truth for VAT**: `TaxService` is now the sole VAT rate authority — `billing.config.get_vat_rate()` delegates to `TaxService` instead of independently querying `TaxRule`
- **TaxService Database Tier Fixed**: `_get_rate_from_database()` now queries the real `TaxRule` model instead of non-existent `TaxSettings`
- **Romanian VAT Rate Updated to 21%**: All hardcoded 19% references updated across billing views, model defaults, PDF generators, e-Factura settings/validator, sample data generators, proforma templates, and documentation (per Emergency Ordinance 156/2024, effective August 1, 2025)
- **Romanian Reduced VAT Rates Consolidated**: 5% and 9% reduced rates merged to single 11% rate across e-Factura settings, validator, and proforma form templates
- **ADR-0005 Amended**: Added scope clarification distinguishing value-immutable constants from regulatory/temporal values, with forward reference to ADR-0015

### Fixed
- **Proforma Form Value/Label Mismatch** (CRITICAL): `<option value="19">21% (Standard)</option>` — the submitted value was 19 while the label showed 21%. Both value and label now correctly show 21%
- **e-Factura XML Tax Rate**: `xml_builder._get_tax_rate()` now reads from the invoice's stored line tax rate (frozen at creation) instead of live `TaxService`, preserving document immutability for regulatory compliance
- **Custom VAT Rate Guard**: Fixed `Decimal("0.00")` being falsy — changed `if tax_profile.vat_rate and ...` to `if tax_profile.vat_rate is not None:` to correctly apply 0% VAT overrides
- **TaxService `calculate_vat()` Business Flags**: `is_business` and `vat_number` parameters were accepted but completely ignored — now properly trigger reverse charge for EU B2B transactions
- **Non-EU Default Rate**: Countries without explicit `TaxRule` records now fail-safe to Romanian VAT (21%) instead of silently returning 0%

### Security
- Per-customer reverse charge eligibility now enforced in VAT calculation (previously orphaned field)
- Invoice tax rates frozen at document creation time, preventing retroactive rate changes on issued documents

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
| 0.14.0 | 2026-02-12 | VAT Architecture Consolidation & ADR-0015 |
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
