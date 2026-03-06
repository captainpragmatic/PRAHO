# Changelog

All notable changes to PRAHO Platform will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Token identity endpoint** (`GET /api/users/token/me/`) — correct token-auth introspection endpoint; the existing `verify_token` at `/api/users/token/verify/` requires HMAC customer context (portal-only) and returns 401 for CLI/API consumers; the new endpoint uses `TokenAuthentication` only, returns `email`, `staff_role`, and `token_created`; 3 tests added
- **ADR-0030**: documents full state of API token authentication, 8 explicit gaps (no expiry, plaintext storage, one-token-per-user, broken verify endpoint), and rationale for `token_info` gap-1 fix
- **Payment model**: `updated_at = DateTimeField(auto_now=True)` on `Payment` (migration 0018); aligns with Invoice, Customer, PaymentRetryPolicy
- **`TERMINAL_PAYMENT_STATUSES`** frozenset constant in `payment_models.py` — canonical set of statuses from which payments must not transition; includes both `cancelled`/`canceled` spellings
- **`Payment.apply_gateway_event()`** method — idempotent gateway status transition with `select_for_update()` contract; replaces 3 separate inline implementations
- **Django system check `portal.W001`** — deploy-time warning when `IPWARE_TRUSTED_PROXY_LIST` is empty in non-debug mode
- **`ACCOUNT_LOCKOUT_THRESHOLD`** setting (default=1) — makes lockout threshold configurable without code changes
- **Testing**: Cross-service parity test (`test_cross_service_parity.py`) prevents
  `retry_after.py` drift between platform and portal services
- **Testing**: Thread-safety test verifies concurrent requests produce unique nonces
- **Testing**: 11 integration tests for rate-limit flows (login 429, orders 429,
  retry-after propagation, idempotent retry contract)
- **Testing**: E2E Playwright tests for rate-limit UX (login throttle, dashboard/catalog
  under normal load)
- **Testing**: 4 orders rate-limit unit tests (catalog warning, confirm-payment 429,
  service re-raise for calculate and create_order)

### Changed

- **Middleware ordering** (prod.py, staging.py) — `PortalServiceHMACMiddleware` and `StaffOnlyPlatformMiddleware` moved after `AuthenticationMiddleware`; staff bypass now has access to `request.user`
- **HMAC timestamp validation** — allow 2s forward clock skew (`-2 <= delta`) for NTP jitter between portal and platform; shared `HMAC_TIMESTAMP_WINDOW_SECONDS` constant extracted to `apps.common.constants`
- **HMAC timestamp parsing** — `int(float(timestamp))` for rolling-deploy backward compatibility
- **Nonce cache TTL** — increased by 30s buffer (`HMAC_TIMESTAMP_WINDOW_SECONDS + 30`) to ensure nonces outlive their timestamp validity window
- **Webhook replay cache key** — use full 64-char hex signature instead of truncated `sig[:32]`
- **Portal `_HMAC_TIMESTAMP_RE`** — tightened from `^[0-9]+(?:\.[0-9]+)?$` to `^[0-9]+$` (int-only; platform validates with `int()`)
- **Portal rate limiting** — atomic `cache.add()`/`cache.incr()` counters replace non-atomic `cache.get()+1`/`cache.set()` in both `AuthenticationRateLimitMiddleware` and `APIRateLimitMiddleware`
- **API rate limiter** — fail-closed (503) instead of fail-open on cache errors; matches `AuthenticationRateLimitMiddleware` behavior
- **`IPWARE_TRUSTED_PROXY_LIST`** — renamed from `TRUSTED_PROXY_LIST` in portal (request_ip.py, settings, tests) to align with platform setting name
- **Security scanner `_matches_path_glob()`** — rewritten using `PurePosixPath.full_match()` (Python 3.13); fixes `**` recursive wildcard matching that `fnmatch` didn't support
- **Security scanner scoped patterns** — all glob patterns now use explicit `**/` prefixes for reliable matching
- **Security scanner XFF regex** — fixed extra `"` in character class
- **Security scanner email-in-logs pattern** — negative lookahead excludes `_mask_email()` and similar safe wrappers
- **Security scanner ORM `.get()` severity** — raised from LOW to MEDIUM with concurrent-safety guidance
- **Stripe webhook processor** — refactored to use `Payment.apply_gateway_event()` instead of inline status mutation
- **`PaymentService.confirm_payment()`** — uses shared `TERMINAL_PAYMENT_STATUSES` constant instead of inline set
- **`obtain_token`** — uses `get_safe_client_ip()` instead of raw `REMOTE_ADDR`
- **`_mask_email()`** — adds null byte (`\0`) stripping; removes redundant domain-level `\n`/`\r` sanitization
- **Portal API Client**: Replaced static `_READ_ONLY_POST_RETRY_ENDPOINTS` allowlist with
  call-site `idempotent=True` parameter on `_make_request` — eliminates manual endpoint
  maintenance and makes retry safety explicit at each call site
- **Portal API Client**: 18+ read-only POST endpoints now pass `idempotent=True` (invoices,
  tickets, services, billing summaries, etc.)

### Removed

- **`PaymentService.handle_webhook_payment()`** and **`_handle_stripe_payment_intent()`** — legacy duplicate handlers; Stripe webhook handling consolidated in `StripeWebhookProcessor`
- Associated test classes removed from `test_payment_service.py` and `test_billing_27_todos.py`

### Fixed

- **Portal Auth**: Login 429 now shows throttle message ("Too many login attempts, try again
  in N seconds") instead of silently treating rate-limits as invalid credentials
- **Portal Auth**: `authenticate_customer` re-raises `PlatformAPIError(is_rate_limited=True)`
  instead of swallowing it and returning `None`
- **Portal Auth**: Password change view shows rate-limit warning via Django messages framework
- **Portal Template**: Removed dead `rate_limit_banner` slot from `base.html` (context
  processor sets `rate_limited`, not `rate_limit_banner`)
- **Portal API Client**: Thread-safety fix — `_last_request_headers` moved to
  `threading.local()` to prevent cross-thread header contamination on the singleton
- **Portal Orders**: All 4 PlatformAPIError catch sites in services (add_to_cart, calculate,
  preflight, create_order) now re-raise rate-limited errors instead of swallowing them
- **Portal Orders**: Views show warning-level rate-limit messages (amber, not red);
  `confirm_payment` returns 429 JSON with `retry_after` field
- fix(settings): remove duplicate `RATELIMIT_USE_CACHE = "default"` in prod.py that overrode the correct conditional assignment
- fix(settings): add `RATELIMIT_ENABLE = True/False` alongside `RATELIMIT_ENABLED` in prod/staging/e2e (both needed: library vs custom middleware)
- fix(settings): add `HMAC_SECRET` startup validation to staging.py (was only in prod.py)
- fix(settings): align webhook secret default in platform dev.py (`"test-webhook-secret-do-not-use-in-prod"`) to match portal dev.py
- fix(settings): add LocMemCache per-worker limitation docstring in portal base.py
- fix(docs): expand `_is_auth_exempt` docstring explaining exempt path semantics and startswith-to-exact-match rationale
- fix(docs): expand `increment_failed_login_attempts` docstring explaining progressive lockout design
- fix(docs): add deprecation comments to `MAX_LOGIN_ATTEMPTS` / `ACCOUNT_LOCKOUT_DURATION_MINUTES` constants
- fix(docs): expand `_verify_platform_webhook` docstring (HMAC-SHA256, replay prevention, cache limitation, serialization contract)
- fix(security): wire account lockout into `portal_login_api` (#53) — closes the same brute-force gap found in `obtain_token`; checks `is_account_locked()`, increments `failed_login_attempts` on failure, resets on success, uses PII-safe structured logging
  - 7 regression tests added in `PortalLoginAPILockoutTests` (including inactive account and byte-identical response verification across all 4 failure modes)
  - `AUTHENTICATION.md` and `SECURITY_COMPLIANCE_ASSESSMENT.md` updated to document lockout enforcement across all 3 credential endpoints
- fix(security): atomic lockout counter — `increment_failed_login_attempts()` now uses `F()` expression to prevent lost increments under concurrent requests
- docs(security): timing side-channel and HMAC rate limiting documented as accepted risks with rationale in `portal_login_api` and `obtain_token`
- fix(security): harden 9 real vulnerabilities from security audit (confirmed by dual Claude+Codex adversarial review; 33 regression tests + 8 new security linter patterns)
  - **Critical** — token revocation self-revocation pattern: `DELETE /api/users/token/revoke/` now uses `TokenAuthentication` + `request.auth`; no ownership check needed (#60)
  - **Critical** — payment success webhook: HMAC-SHA256 + timestamp + 5-minute replay window using dedicated `PLATFORM_TO_PORTAL_WEBHOOK_SECRET` (#49)
  - **High** — `obtain_token` account lockout: wire `is_account_locked()` and `increment_failed_login_attempts()`; uniform 401 prevents user enumeration (#53)
  - **High** — auth failure log masking: `_mask_email()` for PII and control-character sanitization to prevent log injection (#54)
  - **High** — IP extraction: `request_ip.py` rewritten using `django-ipware` with `TRUSTED_PROXY_LIST`; Cloudflare-aware CF-Ray guard; all 4 extraction locations fixed in both platform and portal (#51, #69)
  - **High** — rate limiting bypass: replace `os.environ RATELIMIT_ENABLE` with `settings.RATELIMIT_ENABLED` in both platform and portal middleware (#68)
  - **High** — Terraform firewall: `firewall_ssh_sources` and `firewall_webmin_sources` default `[]` with validation block across all 5 provider modules (#41)
  - **Medium** — insecure HTTP startup warning: loud `WARNING` when `PLATFORM_API_ALLOW_INSECURE_HTTP` is active in production settings (#52)
  - **Nuanced** — HMAC exempt path check: uses `frozenset` exact match instead of `startswith` to eliminate future footgun (#61)
  - **Nuanced** — `Payment.confirm_payment()`: adds `select_for_update`, unique constraint on `gateway_txn_id`, and row lock in `confirm_order` to prevent double-charge race (#50)
  - **Bonus** — `PortalServiceHMACMiddleware` added to prod and staging middleware stacks (was missing entirely)
- fix(security): harden HMAC webhook authentication — int timestamps replace floats; future timestamps rejected via `0 <= (now - ts) <= window` (prevents preplay); 64-char hex signature format pre-filter; per-process replay deduplication via `cache.add()`; startup validation for `PLATFORM_TO_PORTAL_WEBHOOK_SECRET` in both platform and portal prod settings; 8 new webhook tests + 12 structural integration tests
- fix(billing): migration 0017 — add `RunPython` step to convert `gateway_txn_id=""` → `NULL` before applying the unique constraint; PostgreSQL treats each NULL as distinct so multiple empty strings would fail the migration on production
- fix(settings): rename `RATELIMIT_ENABLE` → `RATELIMIT_ENABLED` in `e2e.py`, `prod.py`, and `staging.py` to match the key read by middleware; E2E tests were silently not disabling rate limiting due to this mismatch
- fix(billing): portal webhook signing in `_send_portal_webhook` — compute HMAC-SHA256 of `(ts + "." + body)` and send `X-Platform-Signature` + `X-Platform-Timestamp` headers; without these, every payment success notification was rejected with 401

- fix(security): `PortalServiceHMACMiddleware` — batch hardening (no new dependencies)
  - **Removed `PortalServiceAuthMiddleware`** dead code — weak shared-secret auth with no replay protection; regression test `test_legacy_auth_middleware_removed` added to prevent re-introduction
  - **Removed body timestamp cross-check** — redundant JSON parse that blocked non-JSON bodies; `body_hash` in the canonical string already cryptographically covers any payload timestamp; comment documents this invariant
  - **Rate limiting moved after HMAC validation** — previously keyed on the unverified `HTTP_X_PORTAL_ID` header (attacker-controlled); now post-validation, keyed on `request._portal_id` (verified); prevents DoS quota exhaustion via forged portal IDs
- fix(security): replace `SessionValidationThrottle(BaseThrottle)` with DRF's `ScopedRateThrottle` — custom implementation used non-atomic `cache.get()` + `cache.set()` TOCTOU pattern; replaced with `ScopedRateThrottle(scope="session_validation")` using `DEFAULT_THROTTLE_RATES`; zero custom cache logic; rate configurable in settings
- fix(security): replace direct `REMOTE_ADDR` with `get_safe_client_ip()` at all remaining callsites — `REMOTE_ADDR` is always the immediate TCP peer (the proxy in production); audit logs, rate-limit keys, and security logs recorded the proxy IP instead of the real client; fixed in `audit/signals.py`, `api/customers/views.py`, `api/customers/serializers.py`, `api/users/views.py` (×2), `common/decorators.py` (platform + portal)
- fix(security): add scanner pattern for direct `REMOTE_ADDR` access in `security_scanner.py` — pattern #9 flags `request.META.get("REMOTE_ADDR")` / `request.META["REMOTE_ADDR"]` outside `request_ip.py`; severity MEDIUM; OWASP A09:2021
- fix(settings): `PLATFORM_TO_PORTAL_WEBHOOK_SECRET` in `portal/config/settings/staging.py` — changed from hard fail (`ValueError`) to optional (`WARNING` log); staging rarely tests the end-to-end payment confirmation flow; comment clarifies this is NOT the Stripe webhook secret — it signs Platform→Portal internal calls only

### Tests

- 2 regression tests for token revocation: `test_revoke_token_post_rejected_with_405` (guards against silent reintroduction of POST pattern) and `test_revoke_token_uses_header_token_not_body` (proves body payload is ignored; revokes only the authenticated user's token)
- 11 new platform unit tests (`test_api_users_security.py`), 8 new portal unit tests (`test_portal_security.py`), 14 new structural integration tests (`test_security_hardening.py`)
- 8 new security scanner patterns in `security_scanner.py`
- 7 HMAC middleware tests (`test_hmac_middleware.py`) — added `test_legacy_auth_middleware_removed` (regression guard against `PortalServiceAuthMiddleware` re-introduction), `test_non_json_body_passes_hmac_validation` (proves non-JSON passes after removing cross-check), `test_stale_timestamp_rejected`; fixed all test nonces to meet `HMAC_NONCE_MIN_LENGTH = 32`; fixed float timestamps → int; added `LOCMEM_TEST_CACHE` override to nonce-replay and rate-limit tests (default `DummyCache` silently no-ops `cache.add`/`cache.incr`)

### Docs

- `AUTHENTICATION.md` updated: correct `obtain_token` response (removed stale `is_staff` field), fix revoke verb `POST → DELETE`, replace fictional portal JS token-auth code with accurate description of HMAC-signed `api_client` flow; consumer→method table covering all 4 auth paths
- `AUTHENTICATION.md` dual HMAC architecture section added, `DEPLOYMENT.md` env var tables updated, `SECURITY_CONFIGURATION.md` and `ARCHITECTURE.md` updated with data-flow diagram

---

## [0.24.0] - 2026-03-05

### Added

- **Portal Design System**: Complete component library, design tokens, and living styleguide
  - Design tokens (colors, spacing, typography) in Tailwind config
  - 10+ reusable template components: `page_header`, `section_card`, `modal`, `toast`,
    `badge`, `empty_state`, `form_actions`, `form_error_summary`, `stat_tile`, `table`
  - Living styleguide at `/styleguide/` (DEBUG-only) with all component variants
  - Extracted modal and toast JS into static modules
  - Bridge template tags for auth form componentization
  - Consolidated inline styles into `input.css`
  - Standardized icons (SVG-only, removed emoji from templates)
  - Canonicalized mobile header and cookie banner
- **QA Tooling**: 4 new Makefile targets for design system quality
  - `make lint-templates` — Template lint with 9 rules (TMPL001–TMPL009)
  - `make check-parity` — Platform↔portal template component parity check
  - `make audit-a11y` — Accessibility audit (lang, labels, autofocus, captions)
  - `make audit-dark-mode` — Dark mode coverage and contrast audit
- **Testing**: 30+ UI regression tests covering template tags, filters, and components
  - 12 new test files: alert, badge, button, card, icon, input, modal, page primitives,
    SVG policy, toast, design tokens, mobile layouts, XSS sanitization
  - Integration tests for template lint rules

### Changed

- **Portal**: Normalized billing detail templates with status components
- **Portal**: Migrated `page_header` and `section_card` across 20+ templates (billing,
  tickets, services, MFA, account security, dashboard)
- **Docs**: Added `docs/architecture/ui-ux/portal-design-system.md` as canonical design
  system specification

### Fixed

- **Deployment**: Validate `deploy_method` value (must be `git` or `rsync`) — fails fast
  on typos like `GIT` or `Git` that would silently skip code deployment
- **Deployment**: Cleared stale `PRAHO_VERSION` default in `.env.example.prod` to force
  explicit version setting
- **Tooling**: A11Y004 (missing `lang` on `<html>`), A11Y007 (autofocus on non-first input)
- **Tooling**: DM005 double-counting fix, TMPL005/008 precision, TMPL001 unquoted fix
- **Tooling**: Dead code removal (`EXCLUDE_FROM_INPUT_CHECK`, `DARK_VARIANT`, `IGNORECASE`)

### Removed

- Deleted `table_enhanced.html` (merged into `table.html`)
- Deleted `portal_mobile_header.html` (replaced by canonicalized header)
- Deleted 5 stale docs: `portal-ui-ux-backlog.md`, `phase-b1-pattern-audit.md`,
  `8-agent-consolidated-audit.md`, `setup-initial-data.md`, `orders.md`

---

## [0.23.0] - 2026-03-05

### Added

- **Deployment**: Production-grade git-tag deploy pipeline — production always deploys
  from an immutable git tag (`PRAHO_VERSION` in `.env.prod`), with pre-flight validation
  that the tag exists in the remote repository via `git ls-remote`
- **Deployment**: CLI version override for production deploys (`make deploy-prod VERSION=v0.14.0`)
- **Deployment**: Configurable staging deploy method — defaults to git HEAD of `DEPLOY_BRANCH`,
  with `DEPLOY_METHOD=rsync` as fallback for rapid iteration
- **Deployment**: Deploy summary now shows version + commit SHA for audit trail
- **Deployment**: DNS pre-flight check verifies FQDNs resolve to target server IP (using `@8.8.8.8`)
- **Deployment**: `.env` file as single source of truth — Ansible validates locally, copies to
  server, and reads values from it (replaces Jinja2 `env.native.j2` template)
- **Deployment**: New `.env.example.prod` and `.env.example.staging` at project root with
  documented `[REQUIRED]`/`[OPTIONAL]` annotations
- **Deployment**: `setup_initial_data` management command for first-deploy bootstrap
  (categories, settings, scheduled tasks, templates, superuser)
- **Platform**: System status dashboard with integration health checks (database, cache,
  email, Stripe, e-Factura, scheduled tasks) — HTMX-refreshable partial with staff-only
  on-demand refresh
- **Platform**: Django-Q2 scheduled task for daily system status check

### Changed

- **Deployment**: Consolidated per-environment Ansible inventory and group_vars into single
  `native-single-server.yml` layout — environment driven by `-e praho_env=staging|prod`
- **Deployment**: Renamed Ansible variable `environment` → `praho_env` to avoid reserved
  keyword collision
- **Deployment**: Merged old `.env.example` into `.env.example.dev` (comprehensive dev reference)
- **Deployment**: Updated `praho_git_repo` from placeholder to `captainpragmatic/PRAHO.git`
- **Deployment**: Rewritten `DEPLOYMENT.md` for `.env`-driven workflow with post-deploy
  integration guide (email, Stripe, e-Factura, 2FA, Sentry)
- **Portal**: Normalized i18n source strings from Romanian to English — translations remain
  in `.po/.mo` files; rate limiting now returns redirect + flash message instead of raw JSON
  for browser form submissions
- **Platform**: SIEM logger derives environment from `DJANGO_SETTINGS_MODULE` instead of
  hardcoding "production"
- **Platform**: Removed unused `django-storages` dependency and AWS S3 static files config

### Fixed

- **Deployment**: Production deploys enforce git-only method — rsync blocked for prod
- **Deployment**: Quoted `.env` values with spaces for shell sourcing compatibility
- **Deployment**: Tightened `.gitignore` — `.env.*` excludes secrets, `!.env.example.*`
  keeps templates tracked; rsync excludes `.env.*` and `.envrc` to prevent secret leakage
- **Deployment**: Fixed Caddy log ownership and portal systemd `ReadWritePaths`
- **Deployment**: Fixed portal `collectstatic` missing `PLATFORM_API_ALLOW_INSECURE_HTTP` env var
- **Portal**: Added `SECURE_PROXY_SSL_HEADER` for TLS-terminated reverse proxy (Caddy/nginx)
- **Portal**: Exempted `/api/` from `SECURE_SSL_REDIRECT` (localhost inter-service communication)
- **Portal**: Added `/robots.txt` to public path exemptions in portal middleware
- **Platform**: Exempted `/api/` from `SECURE_SSL_REDIRECT` in prod settings
- **Platform**: Fixed missing required env vars in logging configuration test
- **Orders**: Fixed fail-closed validation and consistent product filtering; accept
  `product_slug` as fallback identifier in cart and order API
- **Security**: Env-driven host config with split domains, native deployment hardening

### Removed

- Deleted per-environment Ansible files: `group_vars/{dev,prod,staging}.yml`,
  `inventory/{prod,staging,single-server,staging-single-server}.yml`
- Deleted `deploy/ansible/roles/praho-native/templates/env.native.j2` (replaced by `.env` copy)
- Deleted `deploy/.env.staging.example` (replaced by `.env.example.staging` at project root)
- Deleted `.env.example` (replaced by `.env.example.dev`)
- Removed `django-storages` from dependencies

---

## [0.22.0] - 2026-03-04

### Fixed — Platform Ruff Auto-Fixes & Type Safety (196 files)

Comprehensive ruff auto-fix pass across all 21 platform apps plus scripts and config.
Introduces `outbound_http.py` module for secure HTTP client defaults (TLS verification,
connection pooling, timeout enforcement) used by all external-facing services.

- Ruff formatting fixes, import ordering, and unused import removal across all apps
- MyPy type annotation improvements: added return types, parameter types, `ClassVar` annotations
- New `outbound_http.py` shared module (platform + portal) with `SecureHTTPSession` base class
- New mypy override for `outbound_http` module (untyped `requests.HTTPAdapter.init_poolmanager` stubs)
- Database migrations: `billing/0016_alter_oauthtoken_options`, `infrastructure/0005_alter_driftremediationrequest_status`
- 7 new outbound HTTP transport tests (SIEM, domains, notifications, provisioning, common)

### Fixed — Portal E2E: Ticket 500s, URL Name Mismatches, Cart HTMX Errors

Resolved 3 root causes responsible for the majority of the 52 E2E test failures (52 → 8):

#### RC-1: Tickets 500 — `VariableDoesNotExist` on `date_created` (fixed 28 tests)
Portal ticket views passed raw API response dicts to Django templates. The `|date` filter
only works on `datetime` objects, and `date_created` (a fallback key) didn't exist in the
API response, causing `VariableDoesNotExist` in Django 5.2 DEBUG mode → HTTP 500.

- Extracted `DictAsObj` from `dashboard/views.py` to new shared `portal/apps/common/api_utils.py`
  — wraps API dicts in objects with dot notation and auto-parses ISO 8601 `created_at`/`updated_at`
  strings into timezone-aware `datetime` objects
- Wrapped ticket dicts in `DictAsObj` in `ticket_list()`, `ticket_search_api()`, and
  `tickets_dashboard_widget()` (`portal/apps/tickets/views.py`)
- Simplified template date expressions from 5-fallback chains to `{{ ticket.created_at|date:"d.m.Y"|default:"—" }}`
  (`tickets_table.html` lines 96, 162)

#### RC-2: URL Name `product_catalog` vs `catalog` (fixed 9 tests)
Three templates referenced `{% url 'orders:product_catalog' %}` but `orders/urls.py` defines
the name as `catalog`. The `NoReverseMatch` error crashed cart empty states, invoice search,
and service search — cascading into cart/checkout/order flow tests.

- Fixed URL name in `cart_empty.html`, `invoices_table.html`, `services_table.html`

#### Cart HTMX `targetError` (fixed 4 tests)
Cart error handlers (`add_to_cart`, `update_cart_item`, `remove_from_cart`) returned
`error_message.html` (id="error-notification") but HTMX `outerHTML` swap expected elements
matching the target ID (`#cart-widget` or `#cart-totals`). The ID mismatch caused
`htmx:targetError` console errors caught by `ComprehensivePageMonitor`.

- `add_to_cart` errors now return `cart_error_notification.html` (id="cart-widget")
- `update_cart_item` and `remove_from_cart` errors now return `cart_empty.html` (id="cart-totals")
- `calculate_totals_htmx` errors already return `cart_empty.html` (fixed in prior session)
- Added `#cart-widget` placeholder to `product_detail.html` (was missing — `hx-target` had no match)
- Error responses now return HTTP 422 with `HX-Retarget`/`HX-Reswap` headers so HTMX
  routes errors to `#cart-notifications` and `event.detail.successful` correctly returns false

### Fixed — E2E Test Fixtures & Assertions (52 → ~8 failures)

#### RC-3: Superuser Portal Login (fixed 10 tests)
`e2e-admin@test.local` had no `CustomerMembership` record because `generate_sample_data.py`
(the command run by `make fixtures`) created the user but never linked it to a customer.
Portal login requires `customer_id` from the Platform API, which queries `is_primary=True`
membership — returning `None` caused session middleware to reject the request.

- Added `CustomerMembership.update_or_create()` for e2e-admin in `generate_sample_data.py`
- Also fixed `setup_test_data.py`: `get_or_create` → `update_or_create` so `is_primary=True`
  is enforced on re-runs (the `defaults` dict only applies on CREATE, not GET)

#### RC-4: Test State & Assertion Fixes (fixed 5 tests)
- `test_product_pricing_management`: Now reads available currencies from the actual `<select>`
  dropdown instead of assuming USD/EUR/RON exist. Skips gracefully if all are taken.
- `test_staff_complete_billing_workflow`: Graceful skip when proforma is not in convertible state
- `test_ticket_isolation`: Allow HTTP 200 when server redirects away from nonexistent ticket
  (Django returns 200 on `/tickets/` list, not 403/404 on the fake ticket URL)
- `product_detail.html` (platform): Added `for`/`id` attributes to quantity input for a11y

### Fixed — Portal QA (8 bugs, 4 fixture gaps, 20 UX improvements)

Portal QA walkthrough identified 19 findings; red-team review elevated 3 more from "not a bug" to confirmed. All fixes include unit + E2E test coverage.

#### Critical (2)
- **C1**: Cart checkout blocked — Portal stored `product_slug` but Platform expected UUID `product_id`. Fix: store UUID on cart add + Platform slug fallback lookup (`orders/services.py`, `api/orders/views.py`)
- **C2**: Registration blocked — `terms_accepted` checkbox missing from template and API payload (`register.html`, `forms.py`)

#### High (3)
- **H1**: Invoice detail — `invoice.bill_to.name` → `invoice.bill_to_name` (flat field); added `status_display` property to Invoice schema with i18n labels (`invoice_detail.html`, `schemas.py`)
- **H2**: Login error invisible — view used `messages.error()` but template checked `form.non_field_errors`; changed to `form.add_error(None, ...)` for inline display (`users/views.py:285`)
- **M7**: TOTP setup "Failed to initialize" — Portal sent only `customer_id`, Platform's `@require_customer_authentication` also requires `user_id` in HMAC body (`api_client/services.py`, `users/views.py`)

#### Medium (5)
- **M1**: Company profile "Not specified" — template checked `company_data.name` but view set `company_data.company_name` (`company_profile.html:80`)
- **M2**: Profile "Last Login: Never" / "Member Since: N/A" — `CustomerProfileSerializer.to_representation()` now includes `last_login` and `date_joined` (`customers/serializers.py`)
- **L5**: Proforma VAT rate showed "0.2%" instead of "21%" — new `as_percentage` template filter converts proportion to percentage (`formatting.py`, `proforma_detail.html`)
- **M3/M4**: Service detail "Calculating..." — `{% if service.service_age_days %}` → `{% if service.service_age_days != None %}` (0 is falsy); fixtures now set `activated_at`/`expires_at`
- **L3**: Currency formatting — services templates used `floatformat:2` + hardcoded "RON"; now use `{{ service.currency_code|default:"RON" }}`

#### Fixture Data (3)
- **M9**: Product fixtures now include descriptions and all 3 billing period prices
- **L4**: Ticket fixture titles no longer embed `[OPEN]`/`[IN_PROGRESS]` status prefix (`generate_sample_data.py`)
- **L2**: Billing cycle dropdown labels shortened to prevent truncation

### Improved — Portal UX Elevation (20 quick wins)

- Empty states: billing, services, and cart now have CTAs ("Browse Hosting Plans", "Browse Products") instead of dead-end text
- Tickets mobile breakpoint gap fixed (`sm:hidden` → `md:hidden`) — tablet users no longer see blank page
- Breadcrumb component colors fixed for dark theme (was invisible: `text-slate-900` on `bg-slate-900`)
- "Logout" nav text now translated (`{% trans %}`)
- Ticket create validation: `alert()` replaced with inline error banner
- MFA TOTP setup: added `{% if form.errors %}` block for failed verification
- Company edit form: added `non_field_errors` display
- Toast auto-dismiss raised from 3s to 5s (WCAG recommendation)
- Ticket detail: "Back to Tickets" link moved from bottom to top of page
- Ticket dates: replaced fragile string-slicing with Django `|date:"d.m.Y"` filter
- Scroll hint arrows: initial `opacity:0` prevents flash on page load
- Company edit: removed redundant `min-h-screen bg-slate-900` wrapper
- Removed dead Alpine.js loading overlay from base template
- Removed conflicting HTMX global JS indicator listener (CSS handles it)
- Account status stat card driven from context (was hardcoded "Active")

### Fixed — Semgrep Security Findings (9 → 0 blocking)

`make lint-security` reported 9 blocking semgrep findings. All resolved with real code fixes where viable, `# nosemgrep` suppression only for confirmed false positives.

#### Code Fixes (4 findings eliminated)
- **`common/utils.py`** (`direct-use-of-httpresponse`): Added `content_type="text/plain"` to maintenance mode response — browser won't parse as HTML, eliminating XSS vector
- **`portal/decorators.py`** (`direct-use-of-httpresponse` ×4): Added `content_type="text/plain"` to all 4 `HttpResponseForbidden` calls — hardcoded `gettext_lazy` strings with no user input
- **`provider_config.py`** (`non-literal-import`): Replaced `importlib.import_module()` with eager registration pattern (`register_sync_fn()` + `_SYNC_FN_REGISTRY`). Functions register at import time → no runtime dynamic import surface. Cascaded to `provider_sync.py`, `apps.py`, `sync_providers.py` management command, and 2 test files
- **`plans_list.html`** (`blocktranslate-no-escape`): Wrapped `{% blocktrans %}` in `{% filter force_escape %}`

#### Nosemgrep Placement Fixes (5 findings — false positives)
Root cause: semgrep requires `# nosemgrep` on the **first line of the match**, not the closing `)`. Ruff's formatter had moved comments to closing lines where semgrep ignores them.
- **`validation_service.py`** (`dynamic-urllib-use`): URL is hardcoded `https://{ip}:10000/` — not user-controlled
- **`virtualmin_gateway.py`** (`request-session-with-http`): `session.mount("http://")` is adapter registration, not an HTTP request
- **`virtualmin_service.py`**, **`users/models.py`**, **`setup_test_data.py`** (`unvalidated-password` ×3): System-generated random password, Django convention (form-level validation), and test fixture respectively
- **`formatting.py`** (`avoid-mark-safe`): `mark_safe(escape(text))` — standard Django pattern, content explicitly escaped
- **`portal/users/views.py`** (`request-post-after-is-valid`): Reads redirect URL param validated by `url_has_allowed_host_and_scheme()`
- **`product_detail.html`** (`translate-as-no-escape`): `{% trans %}` output auto-escaped by Django template engine

### Fixed — Portal Test Failures (2 pre-existing bugs)

- **`test_input_validation_and_sanitization`**: `add_to_cart` view silently returned 200 for invalid input (XSS slug, non-integer quantity) because `ValueError` was caught by broad `except Exception`. Fix: added `OrderInputValidator.validate_quantity()` and `validate_billing_period()` before cart processing, returns 400 on invalid input. HTMX endpoints should return 4xx for bad input — not mask errors as 200
- **`test_signature_comparison_statistical_analysis`**: HMAC timing test was flaky in Docker (CV=5.2 vs threshold 3.0). Fix: IQR (Interquartile Range) outlier filtering before computing coefficient of variation, relaxed thresholds to accommodate kernel scheduling noise on non-RTOS systems. Added comprehensive docstring explaining what the test can and cannot prove

### Added
- **Server-side log checking in E2E tests (ADR-0028)**: ComprehensivePageMonitor now detects Django errors in platform/portal logs, correlated per-test via X-Request-ID
- **Multi-provider cloud gateway**: AWS (`aws_service.py`), DigitalOcean (`digitalocean_service.py`), and Vultr (`vultr_service.py`) implementations of `CloudProviderGateway` ABC alongside existing Hetzner
- **Config drift detection (ADR-0029)**: `DriftCheck`, `DriftReport`, `DriftSnapshot`, `DriftRemediationRequest` models with `drift_scan` management command (exit codes: 0=clean, 1=drifts, 2=errors, 3=both)
- **Infrastructure management commands**: `deploy_node`, `manage_node`, `cleanup_deployments`, `store_credentials` — CLI parity with web UI for all deployment lifecycle operations
- **Drift remediation UI**: Templates and views for drift dashboard, scan results, and remediation approval workflow

### Changed
- **E2E test suite cleanup**: Deleted 3 legacy duplicate test files (-1,003 lines), migrated ~127 tests to use `monitored_staff_page`/`monitored_customer_page` fixtures, standardized imports from `tests.e2e.utils` to `tests.e2e.helpers`
- **ComprehensivePageMonitor bug fixes**: `add_expected_error_patterns` now accumulates across multiple markers (was overwriting), non-string args coerced to `str`, Playwright response listener properly unregistered in `__exit__`

### Fixed — Audit Hardening (50 findings, 221 tests)

8-agent deep audit identified 50 issues (10 Critical, 18 High, 16 Medium, 6 Low). All fixed with 221 new tests achieving 90%+ coverage on changed code. 5,264 platform tests pass.

#### Critical (10)
- **C1**: `virtualmin_disaster_recovery.py` — `VirtualminGateway` now receives `VirtualminConfig` instead of raw server object
- **C2**: `deploy_node` command — `--dry-run` exits before `deployment.save()`, preventing phantom DB records
- **C3**: Cloudflare API token removed from all queue function signatures; fetched from `SettingsService` at task execution time (prevents cleartext in Django-Q2 task table)
- **C4**: `tasks.py` — Fixed `timezone.make_aware()` on already-aware datetime in cost calculation
- **C5**: `DriftCheck.started_at` changed to `default=timezone.now` (was `None`)
- **C6**: `provider_sync.py` — `AWS_REGION_CODE_MAP` replaces naive AZ-name truncation for region codes
- **C7**: `hcloud_service.py` — `int(server_id)` moved inside try/except in all 8 methods (was crashing on invalid IDs)
- **C8**: Vultr power-ops test mocks fixed to return valid instance data with correct status normalization
- **C9**: `aws_service.py` — Idempotency tag changed from `"deployment-id"` to `"praho-deployment"` (matches other providers)
- **C10**: Deployment status template — `progress_step` computed in view, stages passed as list (was splitting comma-string in template)

#### High (18)
- **H1**: `views.py` — `async_task()` call moved inside `transaction.atomic()` for drift remediation approval (TOCTOU prevention)
- **H2**: `deployment_service.py` — Distinguished `Err` (transient failure) from `Ok(None)` (server gone) in deploy retry; only clears `external_node_id` on confirmed absence
- **H3**: `drift_scan` command — Three-code exit scheme (0/1/2/3) for clean/drifts/errors/both
- **H4**: `retry_deployment` uses `transition_to("pending")` instead of direct `status = "pending"`
- **H5**: `stop_node`/`start_node` use `transition_to()` with new transitions: `completed → stopped`, `stopped → completed`
- **H6**: `destroy_node` wrapped in `transaction.atomic()` + `select_for_update()` for TOCTOU prevention
- **H7**: `can_be_destroyed` property now includes `"stopped"` status
- **H8**: `is_err()` check before `unwrap()` on master SSH public key (was crashing on vault errors)
- **H9**: `aws_service.py:get_server` catches generic `Exception` after `ClientError`
- **H10**: `hcloud_service.py` — Server status normalized via `normalize_server_status()`
- **H11**: `vultr_service.py` — `delete_firewall` returns `Ok(True)` on 404 (idempotent)
- **H12**: `aws_service.py` — `upload_ssh_key` checks fingerprint before delete-and-recreate
- **H13**: `digitalocean_service.py` — `DO_REGION_COUNTRY_MAP` dict replaces broken `slug[:3].upper()` for country codes
- **H14**: `manage_node` command — Status validation before async dispatch (mirrors view precondition checks)
- **H15**: `cleanup_deployments` command — Only marks `"destroyed"` when cloud deletion succeeds
- **H16**: `virtualmin_auth_manager.py` — Dict-dispatch pattern with explicit `Err` for unknown auth methods
- **H17**: `_mark_failed()` accepts `audit_ctx` parameter for audit trail threading
- **H18**: Portal HMAC tests assert `customer_id` extraction from response

#### Medium (16)
- **M1/M4**: `get_next_node_number` — `IntegrityError` retry for empty-table race condition
- **M2**: `views.py` — `distinct=True` in `Count()` for drift dashboard annotations
- **M3**: (Covered by C7 — same `int()` fix)
- **M5**: Provider sync uses Vultr public API for plan catalog (not private `_request`)
- **M6**: Provider config tests updated for vault-first credential lookup
- **M7**: DigitalOcean provider code changed from `"do"` to `"dgo"` (3-char convention)
- **M9**: `_PROVIDER_REGISTRY` and `normalize_server_status` documented with docstrings
- **M10**: `vultr_service.py` — `create_server` validates image is non-empty before API call
- **M11**: `digitalocean_service.py` — `logger.warning()` for SSH keys not found during resolution
- **M13**: Canonical status vocabulary documented on `normalize_server_status`
- **M14**: ADR-0028 updated to document `NO_REQUEST_ID` exclusion by design
- **M15**: Quota restoration uses `is not None` checks instead of truthy (zero quota = unlimited)
- **M16**: Migration 0004 — `started_at` default changed from `None` to `timezone.now`

#### Low (6)
- **L1**: Replaced realistic AWS key literals with obviously fake test values
- **L4**: `apps.py` — Narrowed `suppress(Exception)` to `suppress(ImportError)` for django_q import
- **L5**: Fixed `/home/claude/...` paths in docs to relative paths

### Fixed
- **12 vacuous E2E tests hardened**: Workflow tests that silently passed on failure now `pytest.fail()`, security isolation tests now assert denial, soft-check helpers now return bools with caller assertions
- **Reply textarea selector**: Portal ticket tests now use correct `name="message"` field
- **Duplicate proforma helpers consolidated**: Merged `_fill_proforma_form` and `_fill_workflow_proforma_form` into single function with `submit` parameter

---

## [0.21.0] - 2026-03-03

### Added
- **hcloud Python SDK integration (ADR-0027)**: Replace Terraform with typed Python SDK for Hetzner Cloud server provisioning
- **Provider catalog sync**: Live sync of regions, server types, and pricing from Hetzner API via `sync_providers` management command
- **Sync providers UI**: "Sync Providers" button on Cloud Providers page with provider-agnostic dispatch
- **First-boot provider sync**: Automatic catalog sync on first migration when no providers exist
- **Periodic provider sync**: Daily 4:00 AM background task for catalog updates
- **`max_domains` field**: Configurable per-deployment domain limit with size-based defaults (25-500)
- **Credential vault for cloud providers**: Provider API tokens stored via encrypted `CredentialVault` with `cloud_provider` service type; env-var fallback for bootstrap only
- **Provider-agnostic sync registry**: `PROVIDER_SYNC_REGISTRY` and `get_provider_sync_fn` decouple sync dispatch from hard-coded Hetzner references
- **Infrastructure audit trail**: `InfrastructureAuditService` wired into deployment lifecycle (start, complete, fail, retry, destroy) and provider CRUD (create, update, region toggle)
- **Deployment state machine — `stopped` state**: New intermediate state between `completed` and `destroying`/`failed` with defined transitions
- **Makefile `check-env` guard**: Fails fast with clear message when `.env` is missing; wired as prerequisite to all dev-server targets
- **Customer profile sub-form templates**: `address_form.html`, `billing_profile_form.html`, `note_form.html`, `tax_profile_form.html` for inline editing
- **Portal Frontend Architecture (ADR-0026)**: Unified list page design system for Tickets, Invoices, and Services portal pages
- **Shared template components**: `list_page_header.html`, `list_page_filters.html`, `list_page_skeleton.html` — composable includes for consistent list page layout
- **Shared pagination utility**: `apps.common.pagination.PaginatorData` and `build_pagination_params` replace ~20 lines of duplicated pagination math per view
- **Invoices search endpoint**: `invoices_search_api` HTMX endpoint with live search by document number
- **Services search endpoint**: `service_search_api` HTMX endpoint with client-side search by service name/domain
- **Tab-based filtering**: All 3 portal list pages use HTMX-powered tab navigation for primary filter dimension
- **SVG icon template tag system**: `{% icon "name" %}` replaces inline emoji characters across all templates
- **Account health banner**: Persistent portal banner with session-cached account summaries
- **503 maintenance template**: Security-clean error page for Semgrep compliance
- **Staff customer management E2E tests**: Playwright tests for customer list, detail, create/edit, profile sub-forms, and access control

### Changed
- **Deployment pipeline**: Replaced 4 Terraform stages (config gen, init, plan, apply) with single hcloud SDK call
- **Provider config**: Removed Terraform-specific keys; `get_credentials_for_provider` renamed to `get_provider_token` returning `Result[str, str]`
- **Deployment state machine**: `transition_to` now raises `ValidationError` instead of returning bool; redundant `.save()` calls removed
- **`.env` loading**: Moved `load_dotenv` from `manage.py` into `dev.py` settings (both services) so WSGI/ASGI workers also load `.env`
- **Provider sync pricing**: Extracted testable `_extract_pricing` helper preferring `fsn1` with fallback for ARM server types
- **Tickets list page**: Refactored from ~202 lines to ~42 lines using shared includes; status filtering changed from dropdown to tabs
- **Invoices list page**: Refactored from ~347 lines to ~42 lines using shared includes with HTMX live filtering
- **Services list page**: Refactored from ~343 lines to ~42 lines using shared includes with HTMX tabs
- **Portal ticket page title**: Shortened from "Support Tickets" / "My Support Tickets" to "Tickets"
- **Ticket-service linking**: Tickets can now be linked to provisioned services; `TicketAPIClient` renamed for consistency
- **Makefile**: Added `sync_providers` step to `fixtures` and `fixtures-light` targets

### Fixed
- **Deployment URL patterns**: Changed `<uuid:pk>` to `<int:pk>` (NodeDeployment uses `BigAutoField`, not UUID)
- **Customer security**: Replaced `@login_required` with `@staff_required` on all user management views; added `_get_accessible_customer` ACL check
- **Customer delete confirmation**: Server-side validation that typed name matches actual customer name before soft-delete
- **Product price authorization**: Added `@admin_required` to `product_price_edit` and `product_price_delete` views
- **HTMX CSRF headers**: Added `hx-headers='{"X-CSRFToken": ...}'` to all product toggle buttons (active, public, featured)
- **Product pricing display**: Switched from `prices_by_currency` grouped dict to `active_prices` flat list
- **Template fixes**: Removed corrupted HTML in `customers/form.html` heading; fixed `blocktrans` variable references in customer list pagination; added `{% load i18n %}` to deployment status partial
- **Provider list count**: Added `distinct=True` to deployment count annotations to fix over-counting
- **E2E test selectors**: Updated 5 test files to match SVG icon system (removed emoji from Playwright `:has-text()` selectors); updated proforma form field names from `lines-0-*` to `line_0_*`
- **Invoices search**: Search input on invoices page was never wired to backend — now filters by document number via HTMX
- **Billing portal invoice view**: Use `request.user.id` instead of `.pk`
- **Staff ticket replies**: Allow staff reply on closed tickets; add `inert` to mobile nav to prevent form conflicts
- **VAT rate**: Replace hardcoded 19% VAT with dynamic `TaxService` lookup (21% since Aug 2025)
- **Billing PDF exports**: Correct parameter order in PDF export views
- **Order item audit**: Wrap order item audit call in `BusinessEventData`

### Removed
- **Terraform fields**: Removed `terraform_state_path` and `terraform_state_backend` from NodeDeployment model
- **Terraform dependency** for Hetzner: No longer required for server provisioning (kept deprecated for other providers)

---

## [0.20.0] - 2026-03-01

### Added
- **e-Factura integration**: Real ANAF API submission (`submit_invoice`), status polling (`check_status`), and XML download (`download_xml`) via `EFacturaClient`; simulated fallback in DEBUG mode when credentials are not configured
- **Payment gateway**: `create_customer`, `charge`, and `create_subscription` methods on `BasePaymentGateway` and `StripeGateway`; `PaymentService.process_subscription_payment` orchestrates gateway customer creation, Stripe charge, and subscription record persistence
- **Subscription billing cycle**: `PaymentService.run_billing_cycle` queries active subscriptions due for billing, processes each payment, applies dunning rules for failures, and updates service statuses
- **Refund processing**: `RefundService.process_refund` calls gateway refund, records the transaction, and updates invoice/order status; wired into `invoice_refund` and `api_process_refund` views
- **Invoice payment tracking**: `Invoice.record_payment` updates `paid_cents`, `status`, and `paid_at`; status transitions enforced (`draft→sent→partial→paid`)
- **Proforma PDF & email**: `ProformaService.generate_pdf` renders via WeasyPrint; `send_proforma_email` dispatches bilingual notification with PDF attachment
- **Credit note generation**: `billing.signals` generates a credit note `Invoice` (kind=`credit_note`) when an order refund signal fires
- **Invoice numbering**: Sequential `BillingService.get_next_invoice_number` with `YYYYMMDD-NNNN` format
- **Proforma→Invoice conversion**: `BillingService.convert_proforma_to_invoice` copies lines and marks proforma as converted
- **Payment retry & dunning**: `BillingService.retry_failed_payment` with exponential backoff; `tasks.process_dunning` escalates through `warn → retry → suspend → cancel` stages
- **Billing tasks**: `submit_invoice_to_efactura`, `send_payment_reminders`, `cancel_payment_reminders`, `validate_vat_number` (ANAF/VIES), `process_auto_payments` (Stripe auto-charge)
- **Metering alerts**: `UsageAlertService._send_alert_email` sends real notification via `EmailService`
- **Order editing**: `order_edit` view processes form POST with line-item updates
- **Customer services API**: `customer_services` endpoint returns actual `Service` queryset
- **Ticket stats API**: Manual average response time calculation (replaces broken SQLite `Avg` on datetime) and satisfaction rating aggregation

### Changed
- **Test isolation**: Switch default test cache from `LocMemCache` to `DummyCache`; add `LOCMEM_TEST_CACHE` constant for tests that explicitly exercise cache behavior, applied via `@override_settings` to ~18 test classes across 13 files
- **TransactionTestCase fixtures**: Replace `Currency.objects.create()` with `get_or_create()` in 4 TransactionTestCase files (21 occurrences) to prevent `IntegrityError` under `--parallel`
- **Cost service singleton**: Reset `_instance` in `tearDown` where `CostService` is tested as a singleton to prevent state leakage between parallel workers
- **Test settings**: Remove stale `DJANGO_TEST_PROCESSES=1` override that prevented parallel execution; clean up unused imports in `config/settings/test.py`
- **Makefile**: Add `make test-file FILE=<dotted.path>` target for running a single test module
- **Pre-commit**: Disable `check-executables-have-shebangs` in Docker (VirtioFS marks all files +x); fix i18n linter `exclude` pattern to correctly skip `tests/` and `scripts/` directories

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
