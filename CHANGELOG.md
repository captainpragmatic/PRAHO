# Changelog

All notable changes to PRAHO Platform will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

_No unreleased changes._

---

## [0.19.1] - 2026-02-28

### Fixed
- **Security Hardening**: Harden templates against XSS across platform and portal services, fix CSRF and security decorator issues in views
- **Portal Auth**: Add ADR-0017 documenting portal auth fail-open strategy
- **E2E Stability**: Add `NORELOAD=1` support to dev targets for E2E reliability, harden billing and services test selectors

### Changed
- **Dependencies**: Remove legacy `requirements.txt` files — all dependencies now managed via uv workspace
- **Docker**: Update Dockerfiles and Makefile for uv-only dependency management
- **Billing Tests**: Expand portal billing test coverage

### Added
- **HMAC Test Helpers**: Shared `HMACTestMixin` for portal-to-platform API tests (`tests/helpers/hmac.py`)

---

## [0.19.0] - 2026-02-28

### Added
- **Security Hardening**: Applied `@secure_user_registration()` and `@secure_invitation_system()` decorators to `UserService` — enforces privilege escalation prevention (strips `is_staff`/`is_superuser` from user data), XSS sanitization (`strip_tags` on name fields), cache-based rate limiting, and role validation against allowed roles
- **Audit → Notification Integration**: Critical audit alerts and file integrity alerts now trigger admin email notifications via `NotificationService.send_admin_alert()`, gated by `SettingsService` toggles (`audit.notify_on_critical_alerts`, `audit.notify_on_file_integrity_alerts`)
- **Settings Import Endpoint**: New `POST /settings/api/import/` endpoint accepting JSON body or multipart file upload — validates keys against `DEFAULT_SETTINGS`, skips sensitive settings unless `?include_sensitive=true`, logs imports via `log_security_event`, protected by `@admin_required`
- **Customer Analytics**: `update_customer_analytics` task now queries real data — `total_orders` from Order count, `total_revenue` from paid Invoice aggregation, `engagement_score` from weighted formula (order frequency 40%, login recency 30%, ticket activity 30%) with configurable weights via `SettingsService`
- **Metering Threshold Enforcement**: `_take_threshold_action` in `UsageAlertService` now executes real enforcement — `throttle`/`suspend` call `ProvisioningService.suspend_services_for_customer()`, `block_new` sets a 24h cache flag, all actions audit-logged
- **E2E Portal Test Suite**: Comprehensive Playwright E2E tests for customer services (detail views, plans, action requests, usage stats), billing (invoice sync, filtering), users (team management, invitations, roles, access control), tickets (creation, replies, search/filter), dashboard (widgets, responsive layout), navigation (sidebar, breadcrumbs, mobile), and signup/order flows
- **Makefile `dev-e2e-bg`**: Backgrounded dev server target that starts both services with rate limiting disabled, waits for readiness, and returns — suitable for CI pipelines

### Changed
- **README Badges**: Added PostgreSQL, Tailwind CSS, GDPR compliance, and test count (4,000+) badges; added mypy strict and Ruff lint quality badges; removed DCO badge (PR-only workflow)
- **CI Coverage**: Switched from Codecov to gist-based dynamic badge for coverage reporting, then removed Codecov integration entirely
- **Portal Billing Template**: Added invoice sync button (desktop + mobile responsive) to `invoices_list.html` using HTMX `hx-post` with CSRF token

### Testing
- **Audit Coverage**: 6 new test files — compliance reporting, SIEM integration, logging formatters, management commands, services coverage, views coverage (692 tests)
- **Billing Coverage**: 11 new test files — views, signals, tasks, e-Factura, invoices, payments, refunds, subscriptions, metering gateway, misc coverage (1,165 tests)
- **Security Tests**: Updated 6 placeholder assertions in `test_enhanced_validation.py` from `is_ok()` to proper `is_err()` failure checks

### Security
- **🔒 Semgrep Full Triage & Remediation**: Triaged and resolved all 192 Semgrep findings (15 true positives, 73 defense-in-depth, 104 false positives)
  - **True Positives Fixed (15)**:
    - **CRITICAL**: Stored XSS via `user.first_name` in `{% blocktranslate %}` — wrapped with `{% filter force_escape %}`
    - **HIGH**: Open redirect in customer switch views — validated with `url_has_allowed_host_and_scheme()`
    - **HIGH**: Unauthenticated `resource_allocation_webhook` — added HMAC validation
    - **MEDIUM**: Stored XSS via `search_query` in customer list — wrapped with `{% filter force_escape %}`
    - **MEDIUM**: DOM XSS via `innerHTML` in `showNotification()` — replaced with `textContent`
    - **MEDIUM**: Unescaped f-strings in Virtualmin HTMX responses (5 locations) — replaced with `format_html()`
    - **MEDIUM**: HttpResponse XSS in ticket views — replaced with `format_html()`
    - **LOW**: Missing `validate_password()` in password reset serializer — added Django password policy enforcement
  - **Defense-in-Depth Hardening (73)**:
    - Wrapped all `{% blocktranslate %}` blocks across 18 template files with `{% filter force_escape %}` (excluding plain-text email templates)
    - Added `secure=request.is_secure()`, `httponly=True`, `samesite="Lax"` to language and consent cookies
    - Added DRF anonymous rate throttling (60/min) to Portal REST endpoints
    - Removed redundant Alpine.js CDN tag from `service_detail.html` (already loaded from base.html)
    - Added `|escapejs` filter to JS-interpolated domain name in `domain_renew.html`
  - **False Positive Suppression (104)**: Added `nosemgrep` comments with justifications
    - 34 `template-translate-as-no-escape` — output already escaped via `|escapejs` filter
    - 14 `avoid-mark-safe` — content sanitized by bleach/escape before `mark_safe`
    - 8 `unvalidated-password` — test data generation and `UserManager` (not user-facing)
    - 6 `direct-use-of-httpresponse` — string literals and developer-configured integers
    - 6 `django-no-csrf-token` — CSRF token present on adjacent line (parser limitation)
    - 5 `no-csrf-exempt` — HMAC-authenticated inter-service endpoints
    - Remaining misc: plain-text email templates, admin-managed URLs, Stripe SRI limitation, internal network HTTP
- **🔒 PRAHO Architectural Security Scanner**: 18 custom rules detecting PRAHO-specific vulnerabilities
  - Rules PRAHO-001 through PRAHO-018 covering: missing middleware, HMAC secret fallback, AllowAny on destructive endpoints, fail-open middleware, unprotected billing views, SSL verification, CSP misconfiguration, and more
  - AST-based detection for complex patterns (decorator analysis, class scope tracking, inline auth recognition)
  - Inline suppression support via `# praho-security: ignore[RULE-ID]`
  - Wired into `make lint-security` as third scanning phase
  - 22 unit tests with 100% rule coverage
- **🔒 Legacy HMAC Removal**: Eliminated all legacy pipe-delimited HMAC canonical format code
  - Removed `_should_use_legacy_canonical()`, `_prepare_legacy_request_headers()`, and legacy retry block from Portal API client
  - Modern newline-separated format with body hash is now the only HMAC implementation
- **🔒 ADR-0017 Portal Auth Fail-Open Strategy**: Documented intentional fail-open behavior in Portal authentication middleware
  - Critical path comments explaining why Portal fails open during Platform API outages (stateless service cannot fail closed)
  - 5 safeguards: 6h hard TTL, no metadata update on failure, independent session security, error type split, thundering herd protection
  - Scanner suppression with `# praho-security: ignore[PRAHO-006]`
- **🔒 CVE Patches**: Patched hardcoded secrets and removed sensitive defaults from non-dev settings

### Changed
- **📦 Complete uv Migration**: Fully migrated package management from pip/requirements.txt to uv
  - `make install` now runs `uv sync --all-groups` instead of `pip install -r requirements/*.txt`
  - Dockerfiles use `COPY --from=ghcr.io/astral-sh/uv:latest` with `uv sync --frozen` for reproducible builds
  - All 4 GitHub Actions workflows migrated to `astral-sh/setup-uv@v4`
  - Added `semgrep>=1.56.0` to dev dependency group
  - Deleted 8 legacy requirements files
  - Updated 5 documentation files with uv commands
- **🔧 Ruff Bug Fixes**: Fixed pre-existing code quality issues
  - Fixed undefined variable `ticket_number` in API ticket views (F821)
  - Fixed bare `except` in customer serializer (E722)
  - Removed unused import `User` in customer API views (F811)
  - Removed unused variable assignments in portal conftest and ticket views (F841)

---

## [0.18.0] - 2026-02-27

### Added
- **Full i18n Coverage**: 100% Romanian translations for Platform (4,470 entries) and Portal (1,285 entries) — wrapped all hardcoded Python strings (`ValidationError`, `help_text`, `verbose_name`, `short_description`, `choices`) and template strings (`alert()`, `{% button %}`) with `_()` / `{% trans %}`
- **i18n Linter** (`scripts/lint_i18n_coverage.py`): AST-based linter detecting unwrapped i18n strings (7 Python checks + 3 template checks), integrated into `make lint` Phase 4 and pre-commit
- **Translation Tooling** (`scripts/translate_po.py`): Dictionary engine (500+ Romanian terms), Claude AI mode (`--claude`), YAML review workflow (generate → review → approve → apply), per-app coverage stats
- **Makefile i18n Targets**: `make translate`, `make translate-ai`, `make translate-apply`, `make translate-stats`, `make i18n-extract`, `make i18n-compile`
- **i18n Allowlist** (`scripts/i18n_coverage_allowlist.txt`): Suppression file for programmatic strings that are not user-facing (filter tuples, seed data, `unique_together` constraints); `--allowlist` flag wired into all `lint_i18n_coverage.py` invocations in Makefile and pre-commit hook
- **CI**: Automated GitHub Release creation from annotated tags

### Fixed
- **Subscription Resume Bug**: Fixed `Subscription.resume()` clearing `paused_at` before calculating paused duration, which caused subscriptions to not extend `current_period_end` and `next_billing_date` by the time spent paused
- **Legal Views DateTime**: Replaced `timezone.datetime(..., tzinfo=timezone.utc)` with stdlib `datetime(..., tzinfo=UTC)` in legal views — the Django `timezone` module has no `datetime` constructor, so the previous code was using a re-export that could break across Django versions
- **WebAuthn Model Registration**: Fixed `signals.E001` system check error — `WebAuthnCredential` model (defined in `mfa.py`) was not discoverable by Django's model registry; now imported in `UsersConfig.ready()`
- **e-Factura XML Tax Fallback**: Fixed `or`-based tax amount fallback that treated `0` as falsy — replaced with explicit `None`-check so zero-tax invoices generate correct XML
- **Portal Page Param Parsing**: Added `try/except` around `int()` conversion of page query parameters in billing, tickets, and services views to prevent 500 errors on malformed input

### Changed
- **MyPy Type Safety Cleanup**: Removed 178 redundant `# type: ignore` comments across 75 files, fixed real type bugs (`any` → `Any`, missing imports, incorrect return types), removed dead code, and audited all remaining type suppressions to use specific error codes (`[arg-type]`, `[assignment]`, etc.) instead of bare `# type: ignore`
- **Incremental Type-Check Hook**: Rewrote `check_types_modified.py` to use a ratchet pattern — compares mypy error counts against the merge-base and only fails if new errors are introduced, allowing the hook to work on codebases with pre-existing type errors
- **Test Passwords**: Standardized test passwords to `testpass123` across all test suites

---

## [0.17.0] - 2026-02-24

### Added
- **Security Scanner**: `scripts/security_scanner.py` — AST-based static security scanner covering OWASP Top 10 categories; detects hardcoded secrets, dangerous function calls (eval/exec with dynamic args, pickle.loads), SQL injection patterns, and insecure subprocess usage; integrates pip-audit/safety for dependency vulnerability scanning; supports JSON and console output modes with configurable severity thresholds; invokable standalone or via `make lint-security`
- **Architecture Diagrams**: New `docs/architecture/` directory with seven Mermaid diagram files — system overview, entity relationships, data flow, deployment topology, and app dependencies; accompanied by `README.md` (diagram index and render instructions) and `CHANGELOG.md` (diagram history)
- **Documentation Updates**: `README.md` and `docs/ARCHITECTURE.md` updated to reflect current two-service architecture (Platform :8700 + Portal :8701), session-scoped E2E fixtures, and `make dev-e2e` target
- **ORM E2E Tests (billing)**: `test_billing_workflow.py` — order-to-invoice, invoice-to-payment, proforma conversion, full/partial refund flows using Django TestCase with direct DB access; Romanian VAT rate sourced from `TaxService.get_vat_rate("RO")` (no hardcoded percentage)
- **ORM E2E Tests (signup)**: `test_signup_workflow.py` — complete company and individual customer signup, GDPR consent tracking, multi-address support, user registration and onboarding steps; both files bootstrap via `django.setup()` with E402 noqa on post-setup imports and are marked `@pytest.mark.e2e`

### Fixed
- **E2E Portal Navigation Assertions**: `verify_role_based_content` now treats `superuser` and `customer` identically on the portal — both check for `/tickets/` and `/billing/` links; removed the stale `superuser` branch that asserted `/app/` and `/customers/` which are platform-only routes at :8700
- **E2E Test Quality**: `navigation.py` catches only `PlaywrightTimeoutError` in admin-blocked check (unknown exceptions now return `False` instead of silently passing), replaces stale `/admin/` expectation with `/app/`, and lets `verify_role_based_content` failures propagate; `monitoring.py` skips HTMX extended selectors (`closest`/`find`/`next`) in `hx-target` check; `test_navigation.py` raises success threshold from `>0` to `>=75%` of sections
- **Security Scanner Severity Filter**: `security_scanner.py` replaces lexicographic severity string comparison with a numeric rank map (`CRITICAL=4` … `INFO=0`) so `--min-severity HIGH` correctly includes `CRITICAL` findings
- **E2E Signup Flow Tests**: Disabled CSS monitor (`check_css=False`) on `test_signup_then_login_flow` and `test_complete_new_customer_journey` — both tests navigate across multiple pages (signup -> login -> dashboard), destroying the original page execution context and causing the CSS monitor to raise spurious failures
- **E2E Test Suite**: Fixed 37 test issues (19 assertion failures + 18 teardown errors) caused by stale `.pyc` cache and incorrect test selectors/assumptions — zero app code changes, all test bugs
- **E2E Cache Prevention**: Added `PYTHONDONTWRITEBYTECODE=1` to `conftest.py` and `__pycache__` cleanup to all `make test-e2e*` Makefile targets to prevent stale bytecode issues in Docker bind mounts

### Changed
- **E2E Helpers Refactor**: Extracted focused helpers package (`tests/e2e/helpers/`) from monolithic `utils.py` — navigation, monitoring, interactions, auth, and constants are now separate modules
- **OS-Scoped Dev Database**: Platform dev database is now `db-{darwin,linux}.sqlite3` to prevent SQLite corruption when macOS host and Docker container share the same bind-mounted directory (VirtioFS cannot coordinate file locks cross-platform)
- **E2E Rate Limit Guard**: `make test-e2e` now detects active rate limiting and fails fast with actionable error instead of running 179 tests that will all fail
- **CSS Build Portability**: `make build-css` gracefully skips when npm is not available (Docker container support)
- **pre-commit hook patching**: `scripts/patch_precommit_hook.py` now patches all pre-commit-generated hooks (not just `pre-commit`), uses a versioned `PATCHED_MARKER` sentinel for true idempotency, switches from `uname -s | tr` to a POSIX `case` statement for OS detection, and resolves repo root via `git rev-parse --show-toplevel`

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
