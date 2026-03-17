# Platform Test Audit Log

## Progress
- Total files: 244
- Audited: 244/244
- Folders completed: [api, audit, billing, common, customers, domains, factories, helpers, infrastructure, integrations, mocks, notifications, orders, performance, products, promotions, provisioning, security, settings, tickets, tracing, ui, users, root]
- Status: ✅ COMPLETE

## Vector Map
<!-- Compact: one line per file. Used for cross-file duplicate detection -->
| File | Tests |
|------|-------|
| api/test_api_auth_regressions.py | api URL resolver + auth decorator/permission coverage — structural CI guardrail for unprotected /api/ endpoints |
| api/test_api_users_security.py | api.users.views (obtain_token, portal_login_api, token/revoke, token/me) — token revocation, lockout integration, PII masking, HMAC exempt exact-match |
| api/test_customer_details_api.py | api.customers.views (customer_details) — full HMAC-signed POST with membership check, signature rejection, access denied |
| api/test_gdpr_api.py | api.gdpr.views (cookie_consent_api, consent_history_api, data_export_api) — GDPR endpoints, anonymous/auth consent, linkage, export |
| api/test_hmac_billing_staff_bypass.py | common.middleware.PortalServiceHMACMiddleware — staff session bypass for /billing/ UI paths, HMAC required for inter-service billing API |
| api/test_hmac_middleware.py | common.middleware.PortalServiceHMACMiddleware — valid sig, invalid sig, stale timestamp, non-JSON body, legacy class removed, rate limiting, nonce replay |
| api/test_secure_auth.py | api.secure_auth.validate_hmac_authenticated_request + api.services.views parameter order AST check |
| api/test_security_linter.py | api.security_linter.OutboundHTTPVisitor — allowlist path matching (stem vs substring vs directory) |
| api/test_throttle_architecture_guardrails.py | api.core.throttling + api.orders.views throttles + common.performance.rate_limiting — scope/rate config consistency, legacy class removal, portal HMAC key stability |
| api/test_throttle_exception_handler.py | api.exception_handlers.platform_exception_handler + common.performance.rate_limiting throttle classes — 429 normalization, scope config, portal HMAC throttle keys |
| audit/test_audit_authentication.py | audit.services.AuthenticationAuditService — login/logout/failed auth logging, signal integration, view integration, query performance, GDPR compliance |
| audit/test_audit_categorization.py | audit.services.AuditService._get_action_category/severity/sensitive/review — category/severity mapping for ~50 action types, event creation with categorization |
| audit/test_audit_compliance.py | audit.compliance (PasswordPolicyRule, MFAEnforcementRule, ComplianceReportService, LogRetentionService) — compliance rules, reports, retention policies |
| audit/test_audit_e2e.py | Signal → AuditEvent pipeline — SystemSetting API update, direct model create (Setting, Customer, Invoice) → AuditEvent |
| audit/test_audit_event_creation.py | Signal → AuditEvent pipeline — SystemSetting CRUD, EmailSuppression, EmailPreference, EmailTemplate, Invoice, Payment, log_security_event |
| audit/test_audit_gdpr.py | audit.services (gdpr_export_service, gdpr_deletion_service, gdpr_consent_service) — comprehensive GDPR: export, anonymization, consent withdrawal, security |
| audit/test_audit_gdpr_regressions.py | audit.services (gdpr_export_service, gdpr_deletion_service, gdpr_consent_service) — basic GDPR: export, consent, deletion, views, compliance logging |
| audit/test_audit_logging_formatters.py | audit.logging_formatters (SIEMJSONFormatter, AuditLogFormatter, ComplianceLogFormatter, AuditContextFilter, RequestIDFilter) — pure Python formatter tests |
| audit/test_audit_management.py | audit views + services (management_dashboard, search, integrity, retention, alerts, export) — enterprise audit management UI |
| audit/test_audit_mgmt_commands.py | audit management commands (audit_compliance, generate_audit_events, run_integrity_check) — CLI subcommands |
| audit/test_audit_model_regressions.py | audit.models.AuditEvent model coverage guardrail — every concrete model must have audit signal or be in allowlist |
| audit/test_audit_notification_integration.py | audit.tasks (_send_integrity_escalation_alert, _create_file_integrity_alert) — notification wiring for integrity alerts |
| audit/test_audit_services.py | audit.services (BillingAuditService, OrdersAuditService) — billing/order/proforma/payment audit event metadata, categorization |
| audit/test_audit_services_regressions.py | audit.services comprehensive — GDPR services, integrity, retention, search, security, all domain audit services (92KB) |
| audit/test_audit_siem_regressions.py | audit.siem + audit.siem_integration — formatters (CEF, LEEF, OCSF, JSON, Syslog), transports, hash chain, SIEMService, providers (60KB) |
| audit/test_audit_signal_registration.py | Signal wiring guardrail — verifies billing/orders/customers/domains/products/tickets/notifications/settings models have signal receivers |
| audit/test_audit_signals.py | audit.signals — user profile changes, membership changes, custom signals (privacy, API key, context switch), categorization mapping |
| audit/test_audit_views_regressions.py | audit.views comprehensive — all audit view endpoints, HTMX partials, permissions, filtering, export (89KB) |
| audit/test_cookie_consent_model.py | audit.models.CookieConsent — model creation, status choices, consent properties, indexes, string repr |
| audit/test_file_integrity_monitoring.py | audit.file_integrity_service (FileIntegrityMonitoringService) — baseline, change detection, critical file verification, tasks |
| audit/test_partition_retention_status.py | audit.compliance.LogRetentionService — partition table retention status |
| audit/test_siem_outbound.py | audit.siem_integration.SIEMIntegrationService — outbound HTTP uses safe_request(), private IP rejection, TLS verification |
| audit/test_uuid_serialization.py | audit.services (AuditJSONEncoder, serialize_metadata) — UUID/datetime/Decimal serialization in audit metadata |
| billing/test_billing_audit_and_workflow_regressions.py | billing.efactura.audit.EFacturaAuditService + billing.management.commands.setup_tax_rules + billing.metering_tasks — e-Factura audit, tax rules, metering task scheduling |
| billing/test_billing_models_regressions.py | billing.models (Currency, FXRate, InvoiceSequence, ProformaSequence, TaxRule, VATValidation, PaymentRetryPolicy) — model validation, constraints, cascade |
| billing/test_billing_refund_and_efactura_regressions.py | billing.services (Invoice.amount_due, update_status_from_payments), billing.gateways.stripe_gateway, billing.efactura_service, billing.refund_service — refund+efactura integration |
| billing/test_billing_signals.py | billing.signals — minimal signal handler coverage (2 tests: Invoice/Payment post_save) |
| billing/test_billing_signals_regressions.py | billing.signals — comprehensive signal handler coverage (50+ handlers: invoice issued, payment success, cache invalidation) |
| billing/test_billing_tasks.py | billing.tasks — Celery tasks (daily billing, auto payment, expired trials, payment reminders). NOTE: documents due_date→due_at bug |
| billing/test_billing_views_regressions.py | billing.views — HTTP view handlers for invoices, payments, proformas |
| billing/test_creditledger.py | billing.models.CreditLedger — customer credit accounting, overpayment conversion, chargeback handling |
| billing/test_currencies.py | billing.models (Currency, FXRate) — DUPLICATE of test_billing_models_regressions.py |
| billing/test_efactura_service.py | billing.efactura_service (EFacturaXMLGenerator, EFacturaSubmissionService) — XML generation, submission, status checking |
| billing/test_efactura_views.py | billing.views (efactura_dashboard, document_detail, submit, retry) — minimal view tests (status codes only) |
| billing/test_invoice_service.py | billing.invoice_service (BillingAnalyticsService, generate_invoice_pdf, send_invoice_email, generate_vat_summary) |
| billing/test_invoices_models.py | billing.models (Invoice, InvoiceLine) — model CRUD, FSM transitions (issue, mark_as_paid, mark_partially_refunded) |
| billing/test_invoices_views.py | billing.views (invoice_detail, proforma_to_invoice) — access control, view rendering |
| billing/test_metering_enforcement.py | billing.metering_service.UsageAlertService._take_threshold_action() — throttle, suspend, block_new, warn actions |
| billing/test_metering_gateway_regressions.py | billing.metering_service — regression edge cases, Result Ok/Err, decimal parsing, allowance helpers |
| billing/test_metering_models.py | billing metering models (UsageMeter, UsageEvent, BillingCycle, UsageAggregation, PricingTier, UsageThreshold, UsageAlert) |
| billing/test_metering_services.py | billing.metering_service (MeteringService, RatingEngine, UsageAlertService, BillingCycleManager, UsageInvoiceService) |
| billing/test_metering_tasks.py | billing.metering_tasks — background tasks (event processing, cycle workflows, alert checking, Stripe sync, Virtualmin collection) |
| billing/test_payment_service.py | billing.payment_service.PaymentService — intent creation, confirmation, subscription creation, available methods |
| billing/test_payments_allocation.py | Invoice payment allocation — partial/multiple payment reduces remaining amount |
| billing/test_payments_models.py | billing.models (Payment) — CRUD, status/method choices, Invoice-Payment relationships, indexing |
| billing/test_payments_refunds.py | billing.refund_service (RefundService, RefundQueryService) — full/partial refunds, eligibility, statistics, audit trail |
| billing/test_payments_views.py | billing.views — payment processing POST, list filtering/pagination, authorization |
| billing/test_pdf_generators.py | billing.pdf_generators.RomanianDocumentPDFGenerator — PDF initialization, company info, invoice/proforma generation |
| billing/test_pdf_generators_comprehensive.py | billing.pdf_generators — comprehensive coverage (85%+ target) |
| billing/test_proformas_models.py | billing.models (ProformaInvoice, ProformaLine) — CRUD, expiration checking |
| billing/test_proformas_views.py | billing.views — proforma CRUD views, access control |
| billing/test_refund_service_regressions.py | billing.refund_service — refund eligibility, full/partial flows, bidirectional sync, amount calculations |
| billing/test_security.py | billing.security — financial JSON validation, sensitive key detection, XSS/injection blocking, amount limits, SSRF protection |
| billing/test_sequences.py | billing.models (InvoiceSequence, ProformaSequence) — creation, uniqueness, get_next_number, padding format |
| billing/test_sequences_concurrency.py | billing.models.InvoiceSequence — sequential access only (NOT true concurrency despite name) |
| billing/test_services.py | billing.refund_service (RefundService, RefundQueryService) — SIGNIFICANT OVERLAP with test_refund_service_regressions.py |
| billing/test_stripe_metering.py | billing.stripe_metering (StripeMeterService, StripeMeterEventService, StripeUsageSyncService) — meter CRUD, usage reporting, webhook handling |
| billing/test_subscription_models_regressions.py | billing.subscription_models — lifecycle (activate, trial, cancel, pause, resume, renew), proration, grandfathering, retries (66KB) |
| billing/test_subscription_resume.py | billing.subscription_models.Subscription.resume() — period extension, validation, edge cases |
| billing/test_subscription_service.py | billing.subscription_service (ProrationService, SubscriptionService, GrandfatheringService, RecurringBillingService) (60KB) |
| billing/test_tax_configuration.py | billing.config (VAT helpers), billing.tax_models.TaxRule, billing.services.TaxService, orders.vat_rules.OrderVATCalculator |
| billing/test_usage_billing_redteam.py | billing.config + metering_models + metering_service + stripe_metering — red team: config validation, idempotency, overflow, negative usage |
| billing/test_validators_financial.py | billing.validators — financial amount/JSON/text validation, dangerous patterns, sensitive keys |
| billing/test_webhooks.py | integrations.webhooks.stripe.StripeWebhookProcessor — event extraction, signature verification (minimal: 4 tests) |
| billing/efactura/test_b2c.py | billing.efactura.b2c (CNPValidator, B2CDetector, B2CXMLBuilder) — Romanian personal ID validation, B2C detection |
| billing/efactura/test_client.py | billing.efactura.client (EFacturaClient) — OAuth2, upload with retry, status polling, PDF download |
| billing/efactura/test_metrics.py | billing.efactura.metrics (EFacturaMetrics, NoOpMetric, timed_operation) — Prometheus wrapper, graceful fallback |
| billing/efactura/test_models.py | billing.efactura.models (EFacturaDocument) — FSM transitions, retry scheduling, deadline calculations, query filters |
| billing/efactura/test_quota.py | billing.efactura.quota (ANAFQuotaTracker) — per-endpoint rate limits, cache tracking, midnight reset |
| billing/efactura/test_sandbox_integration.py | billing.efactura.client (integration) — real ANAF sandbox API tests (always skipped without env vars) |
| billing/efactura/test_security.py | Multiple efactura modules — XXE/XML attacks, path traversal, token security, quota bypass, boundary conditions |
| billing/efactura/test_service.py | billing.efactura.service (EFacturaService) — submission/status orchestrator, SubmissionResult/StatusCheckResult dataclasses |
| billing/efactura/test_settings.py | billing.efactura.settings (EFacturaSettings, VATRateConfig) — config retrieval, VAT rates, timezone, deadline calculations |
| billing/efactura/test_startup_scheduling.py | billing.apps.BillingConfig.ready() — task scheduling on/off with EFACTURA_ENABLED setting |
| billing/efactura/test_tasks.py | billing.efactura.tasks — async tasks (submit, poll status, deadline checks, retries, batch polling) |
| billing/efactura/test_token_storage.py | billing.efactura.token_storage (OAuthToken, TokenStorageService) — token lifecycle, encryption, cache integration |
| billing/efactura/test_validator.py | billing.efactura.validator (CIUSROValidator) — CIUS-RO XML validation, malformed rejection |
| billing/efactura/test_webhook_integration.py | integrations.webhooks.efactura (EFacturaWebhookProcessor) — event extraction, type mapping, deduplication |
| billing/efactura/test_xml_builder.py | billing.efactura.xml_builder (UBLInvoiceBuilder, UBLCreditNoteBuilder) — UBL 2.1 XML generation |
| billing/efactura/test_xsd_validator.py | billing.efactura.xsd_validator (XSDValidator, CanonicalXMLGenerator) — XSD schema validation |

## Findings

### api/ (10 files)

#### test_api_auth_regressions.py — 🟢 clean
- **Placement**: ✅ correct — tests API URL resolver for auth coverage
- **Naming**: ⚠️ slightly misleading — name says "regressions" but it's a structural CI guardrail, not regression tests. Better name: `test_api_auth_coverage_guardrail.py`
- **Duplicates**: ✅ none
- **Mocking**: ✅ no mocks — uses live URL resolver introspection
- **Dead tests**: ✅ none — uses `get_resolver()` which always reflects current URL config
- **Speed**: ✅ `SimpleTestCase` (no DB) — optimal
- **Severity**: 🟢 clean (naming is cosmetic)

#### test_api_users_security.py — 🟡 minor
- **Placement**: ⚠️ borderline — tests API endpoints in `api.users.views` but also tests `common.middleware._is_auth_exempt`. The HMAC exempt tests (L283-313) could arguably be in `test_hmac_middleware.py`. However, they're grouped with auth security by issue number (#61), so the grouping is reasonable.
- **Naming**: ✅ accurate
- **Duplicates**: ⚠️ `AccountLockoutTokenTests` (L116) tests lockout on `/api/users/token/`, while `PortalLoginAPILockoutTests` (L321) tests lockout on `/api/users/login/`. These are different endpoints but the test patterns (increment, locked-returns-401, reset-on-success) are nearly identical. Could use a shared mixin or parameterized base. Not a true duplicate since they test different views.
- **Mocking**: ✅ no mocks — all integration tests hitting real views
- **Dead tests**: ✅ none — all endpoints verified to exist
- **Speed**: ✅ `TestCase` — appropriate. `setUp` creates 1 user per class — clean.
- **Severity**: 🟡 minor — the repeated lockout pattern across 2 classes is verbose but tests different endpoints. Also, this file overlaps with `users/test_security_lockout.py` which tests the same lockout *model methods* via web login. Different layers, so not duplicate — but worth noting.

#### test_customer_details_api.py — 🟡 minor
- **Placement**: ✅ correct — tests API customer details endpoint
- **Naming**: ✅ accurate
- **Duplicates**: ✅ none
- **Mocking**: ✅ correct — no mocks, full integration with HMAC signing
- **Dead tests**: ✅ none
- **Speed**: ⚠️ `@override_settings(MIDDLEWARE=[...])` repeated 3 times with identical middleware list (L72-86, L112-125, L146-159). Should be a class-level decorator instead. Also, the `_sign()` helper (L39-60) duplicates the same logic in `test_hmac_middleware.py` (L32-54). Both files implement HMAC signing from scratch. Should use a shared helper (note: `tests/helpers/hmac.py` exists — check if it provides this).
- **Severity**: 🟡 minor — duplicated HMAC signing helper and repeated override_settings

#### test_gdpr_api.py — 🟢 clean
- **Placement**: ✅ correct — tests `api.gdpr.views`
- **Naming**: ✅ accurate
- **Duplicates**: ✅ none
- **Mocking**: ✅ uses `_portal_authenticated = True` to simulate HMAC — lightweight and correct
- **Dead tests**: ✅ none — all three GDPR views verified to exist
- **Speed**: ✅ `TestCase` with `@override_settings(DISABLE_AUDIT_SIGNALS=True)` — good practice to avoid slow signal processing
- **Severity**: 🟢 clean

#### test_hmac_billing_staff_bypass.py — 🟡 minor
- **Placement**: ✅ correct — tests HMAC middleware billing path handling
- **Naming**: ✅ accurate and descriptive
- **Duplicates**: ⚠️ `test_staff_can_access_billing_invoices`, `test_staff_can_access_billing_proformas`, etc. (L56-87) are 8 near-identical tests that only differ in the URL path. These are prime candidates for `subTest` or parameterized tests.
- **Mocking**: ✅ correct — `MagicMock` for user object is appropriate since testing middleware in isolation
- **Dead tests**: ✅ none
- **Speed**: ✅ `TestCase` without DB access — fast
- **Severity**: 🟡 minor — 8 repetitive path tests could be collapsed to 1 parameterized test

#### test_hmac_middleware.py — 🟢 clean
- **Placement**: ✅ correct — tests `common.middleware.PortalServiceHMACMiddleware`
- **Naming**: ✅ accurate
- **Duplicates**: ✅ none — each test covers a distinct behavior
- **Mocking**: ✅ `patch("apps.common.middleware.time.time")` in L221 patches where it's USED — correct
- **Dead tests**: ✅ `test_legacy_auth_middleware_removed` (L168) is a valuable guardrail, not dead
- **Speed**: ✅ `TestCase` with LocMemCache — fast. `_sign()` helper duplicated from `test_customer_details_api.py` (see above).
- **Severity**: 🟢 clean

#### test_secure_auth.py — 🟢 clean
- **Placement**: ✅ correct — tests `api.secure_auth` and `api.services.views` parameter order
- **Naming**: ✅ accurate
- **Duplicates**: ✅ none
- **Mocking**: ✅ no mocks — direct function calls and AST parsing
- **Dead tests**: ✅ none — `validate_hmac_authenticated_request` exists at `apps/api/secure_auth.py:41`, `api.services.views` exists
- **Speed**: ✅ `TestCase` for validation, `SimpleTestCase` for AST check — appropriate
- **Severity**: 🟢 clean

#### test_security_linter.py — 🟢 clean
- **Placement**: ✅ correct — tests `api.security_linter.OutboundHTTPVisitor`
- **Naming**: ✅ accurate
- **Duplicates**: ✅ none
- **Mocking**: ✅ no mocks — direct class instantiation
- **Dead tests**: ✅ none — `OutboundHTTPVisitor` exists at `apps/api/security_linter.py:62`
- **Speed**: ✅ `SimpleTestCase` — optimal
- **Severity**: 🟢 clean

#### test_throttle_architecture_guardrails.py — 🟡 minor
- **Placement**: ✅ correct — tests throttle architecture consistency
- **Naming**: ✅ accurate
- **Duplicates**: 🔴 `test_users_module_uses_canonical_auth_throttle` (L67-68) is **IDENTICAL** to the same test in `test_throttle_exception_handler.py` (L64-65). Exact same assertion: `self.assertIs(users_views.AuthThrottle, AuthThrottle)`. One should be removed.
- **Mocking**: ✅ no mocks
- **Dead tests**: ✅ none — all throttle classes verified to exist
- **Speed**: ✅ `SimpleTestCase` — optimal
- **Severity**: 🟡 minor (one exact duplicate test)

#### test_throttle_exception_handler.py — 🟡 minor
- **Placement**: ✅ correct — tests exception handler + throttle config
- **Naming**: ⚠️ slightly misleading — name says "exception handler" but also contains `ThrottleConfigurationTests` (L46) and `PortalHMACThrottleTests` (L68). The exception handler tests are only L24-43.
- **Duplicates**: 🔴 `test_users_module_uses_canonical_auth_throttle` (L64-65) is **IDENTICAL** to `test_throttle_architecture_guardrails.py` (L67-68). Also, `ThrottleConfigurationTests.test_api_core_throttles_use_scopes_from_throttle_rates` (L59-62) partially overlaps with `test_throttle_architecture_guardrails.py:test_per_view_throttle_classes_have_scopes_in_settings` — both verify scope config, though the guardrails test is more comprehensive.
- **Mocking**: ✅ correct
- **Dead tests**: ✅ none
- **Speed**: ✅ `SimpleTestCase` — optimal
- **Severity**: 🟡 minor (duplicate test, naming could be clearer)

### Cross-file: api/
1. **DUPLICATE**: `test_users_module_uses_canonical_auth_throttle` exists identically in both `test_throttle_architecture_guardrails.py:L67` and `test_throttle_exception_handler.py:L64`. → Remove from one file.
2. **DUPLICATE HELPER**: HMAC `_sign()` method duplicated in `test_hmac_middleware.py:L32-54` and `test_customer_details_api.py:L39-60`. `tests/helpers/hmac.py` exists — should use shared helper.
3. **OVERLAP**: `test_throttle_exception_handler.py` contains 3 unrelated test classes (exception handler, config, HMAC throttles). Consider splitting: keep `PlatformExceptionHandlerTests` in its own file, merge `ThrottleConfigurationTests` into `test_throttle_architecture_guardrails.py`.
4. **OVERLAP with users/**: `api/test_api_users_security.py` tests lockout via API endpoints (`/api/users/token/`, `/api/users/login/`), while `users/test_security_lockout.py` tests lockout via web login. Different layers — NOT duplicates, but worth noting for future consolidation.
5. **VERBOSE**: `test_hmac_billing_staff_bypass.py` has 8 near-identical staff UI path tests → collapse to parameterized.
6. **REPEATED OVERRIDE**: `test_customer_details_api.py` repeats `@override_settings(MIDDLEWARE=[...])` 3 times → move to class level.

### api/ Summary
| Metric | Count |
|--------|-------|
| 🔴 Needs action | 0 |
| 🟡 Minor | 5 (test_api_users_security, test_customer_details_api, test_hmac_billing_staff_bypass, test_throttle_architecture_guardrails, test_throttle_exception_handler) |
| 🟢 Clean | 5 (test_api_auth_regressions, test_gdpr_api, test_hmac_middleware, test_secure_auth, test_security_linter) |
| Duplicate tests | 1 (test_users_module_uses_canonical_auth_throttle) |
| Duplicate helpers | 1 (HMAC _sign() in 2 files) |
| Dead tests | 0 |
| Mock issues | 0 |
| Speed optimizations | 2 (parameterize billing bypass paths, class-level override_settings) |

### audit/ (23 files)

#### test_audit_authentication.py — 🟡 minor
- **Placement**: ✅ correct
- **Naming**: ✅ accurate
- **Duplicates**: ⚠️ `AuthenticationAuditQueryPerformanceTest.test_audit_indexes_exist` (L447) always skips on SQLite — effectively dead. Same pattern in `test_audit_categorization.py:test_audit_event_indexes_exist`. Both are dead on SQLite test runner.
- **Mocking**: ✅ correct — `Mock()` for session, `patch.object` for `is_account_locked`
- **Dead tests**: ⚠️ `test_audit_indexes_exist` (L447) — always skips with `self.skipTest("Index verification skipped for SQLite")`. Platform tests use SQLite.
- **Speed**: ⚠️ `if __name__ == '__main__': pytest.main()` at bottom is unnecessary for Django test runner
- **Severity**: 🟡 minor

#### test_audit_categorization.py — 🟡 minor
- **Placement**: ✅ correct
- **Naming**: ✅ accurate
- **Duplicates**: 🔴 `TestAuditServiceCategorization` (L142-302) tests `_get_action_category`, `_get_action_severity`, `_is_action_sensitive`, `_requires_review` for ~50 action types. **DUPLICATED** by `test_audit_signals.py:TestAuditServiceCategorization` (L554-603) which tests the same static methods with overlapping inputs (~30 action types).
- **Mocking**: ✅ no mocks
- **Dead tests**: ⚠️ `test_audit_event_indexes_exist` (L92-139) — skips on SQLite OR hardcodes expected indexes as the answer (the `else` branch at L113 assigns the expected list as the actual list — always passes trivially). Misleading test.
- **Speed**: ⚠️ `pytestmark = pytest.mark.django_db` on classes that inherit `TestCase` — redundant, harmless but confusing
- **Severity**: 🟡 minor (duplicate categorization tests, dead index test)

#### test_audit_compliance.py — 🟢 clean
- **Placement**: ✅ correct
- **Naming**: ✅ accurate
- **Duplicates**: ✅ none — this is the most comprehensive compliance test (56KB), covers rules, reports, retention
- **Mocking**: ✅ correct — uses `MagicMock` for external services, `patch` for storage
- **Dead tests**: ✅ none
- **Speed**: ✅ appropriate use of `TestCase`
- **Severity**: 🟢 clean (large but well-organized)

#### test_audit_e2e.py — 🟡 minor
- **Placement**: ✅ correct
- **Naming**: ✅ accurate — "e2e" means HTTP → signal → AuditEvent pipeline
- **Duplicates**: 🔴 `TestModelSaveAuditTrail.test_system_setting_create_produces_audit_event` (L66) is **DUPLICATED** by `test_audit_event_creation.py:TestSystemSettingAuditEvent.test_create_system_setting_produces_audit_event` (L35). Both test the exact same thing: SystemSetting.create → AuditEvent. Also, `test_invoice_create_produces_audit_event` (L110) overlaps with `test_audit_event_creation.py:TestInvoiceAuditEvent.test_create_invoice_produces_audit_event` (L170).
- **Mocking**: ✅ no mocks — real signal pipeline
- **Dead tests**: ✅ none
- **Speed**: ✅ appropriate
- **Severity**: 🟡 minor (2 duplicate tests with test_audit_event_creation.py)

#### test_audit_event_creation.py — 🟡 minor
- **Placement**: ✅ correct
- **Naming**: ✅ accurate
- **Duplicates**: 🔴 See above — overlaps with `test_audit_e2e.py` for SystemSetting and Invoice creation. Consider merging these two files or deduplicating.
- **Mocking**: ✅ no mocks — real signal pipeline
- **Dead tests**: ✅ none
- **Speed**: ✅ appropriate
- **Severity**: 🟡 minor (duplicates with test_audit_e2e.py)

#### test_audit_gdpr.py — 🟡 minor
- **Placement**: ✅ correct
- **Naming**: ✅ accurate
- **Duplicates**: 🔴 **SIGNIFICANT OVERLAP** with `test_audit_gdpr_regressions.py`. Both test:
  - `gdpr_export_service.create_data_export_request` (creation, expiration)
  - `gdpr_consent_service.withdraw_consent` (marketing consent)
  - `gdpr_deletion_service.create_deletion_request` (anonymization request)
  - GDPR dashboard view access
  - Unauthenticated redirect to login
  - Compliance logging
  The "regressions" file is actually a simpler/basic version of the same tests. One should be removed.
- **Mocking**: ✅ correct — `patch('apps.audit.services.default_storage.save')` for storage failure
- **Dead tests**: ⚠️ L332-336: Two `# NOTE:` comments about removed test classes. These are just comments, not dead code, but indicate prior cleanup.
- **Speed**: ✅ appropriate
- **Severity**: 🟡 minor (significant overlap with regressions file)

#### test_audit_gdpr_regressions.py — 🔴 needs action
- **Placement**: ✅ correct
- **Naming**: 🔴 **MISLEADING** — name says "regressions" but content is labeled "Basic GDPR tests". These are NOT regression tests — they're a simplified subset of `test_audit_gdpr.py`. The "basic" tests add no value beyond what the comprehensive file already covers.
- **Duplicates**: 🔴 Almost entirely duplicated by `test_audit_gdpr.py`. Every test class here has a more comprehensive counterpart:
  - `GDPRExportBasicTestCase` → `GDPRExportServiceTestCase`
  - `GDPRConsentBasicTestCase` → `GDPRConsentServiceTest`
  - `GDPRDeletionBasicTestCase` → `GDPRDeletionServiceTest`
  - `GDPRViewsBasicTestCase` → `GDPRSecurityTest` (views portion)
  - `GDPRComplianceBasicTestCase` → already covered by comprehensive file
  The "service exists" tests (`test_export_service_exists`, `test_consent_service_exists`, `test_deletion_service_exists`) are trivial `hasattr` checks that add zero value — if the service didn't exist, the import at the top of the file would fail.
- **Mocking**: ✅ no mocks
- **Dead tests**: 🔴 3 "service exists" tests are effectively dead — `hasattr` on already-imported functions
- **Speed**: N/A — recommend deletion of entire file
- **Severity**: 🔴 needs action — DELETE this file, it's entirely superseded by `test_audit_gdpr.py`

#### test_audit_logging_formatters.py — 🟢 clean
- **Placement**: ✅ correct
- **Naming**: ✅ accurate
- **Duplicates**: ✅ none
- **Mocking**: ✅ minimal — `patch("apps.audit.logging_formatters.settings")` is correct target
- **Dead tests**: ✅ none
- **Speed**: ✅ excellent — `SimpleTestCase` throughout (no DB), pure Python tests
- **Severity**: 🟢 clean — well-structured, good use of helpers

#### test_audit_management.py — 🟡 minor
- **Placement**: ✅ correct
- **Naming**: ✅ accurate
- **Duplicates**: ⚠️ Overlaps with `test_audit_views_regressions.py`:
  - Both test management dashboard access/permissions
  - Both test alert dashboard and status updates
  - Both test retention dashboard
  - Both test integrity dashboard
  - `test_audit_views_regressions.py` (89KB) is much more comprehensive
  This file could potentially be merged into or replaced by the views regressions file.
- **Mocking**: ✅ no mocks — integration tests with real views
- **Dead tests**: ✅ none
- **Speed**: ⚠️ `EnterpriseAuditManagementTestCase.setUp` creates 3 users + 15 audit events for EVERY test class that inherits it. Could use `setUpTestData` for the shared data.
- **Severity**: 🟡 minor (overlap with views_regressions, setUp optimization)

#### test_audit_mgmt_commands.py — 🟢 clean
- **Placement**: ✅ correct
- **Naming**: ✅ accurate
- **Duplicates**: ✅ none
- **Mocking**: ✅ correct — patches `ComplianceReportService`, `get_siem_service`, `LogRetentionService` at the right import locations
- **Dead tests**: ✅ none
- **Speed**: ✅ appropriate — mix of mocked and real DB tests
- **Severity**: 🟢 clean — well-organized by subcommand

#### test_audit_model_regressions.py — 🟢 clean
- **Placement**: ✅ correct — despite name, this is a structural guardrail (like `api/test_api_auth_regressions.py`)
- **Naming**: ⚠️ slightly misleading — "regressions" but actually a CI guardrail for audit signal coverage. Better name: `test_audit_model_coverage_guardrail.py`
- **Duplicates**: ✅ none — unique introspection-based guardrail
- **Mocking**: ✅ no mocks — introspects live signal receivers
- **Dead tests**: ✅ none
- **Speed**: ✅ `SimpleTestCase` — optimal
- **Severity**: 🟢 clean

#### test_audit_notification_integration.py — 🟢 clean
- **Placement**: ✅ correct — tests audit → notification integration
- **Naming**: ✅ accurate
- **Duplicates**: ✅ none
- **Mocking**: ✅ correct — patches `NotificationService` and `SettingsService` at correct locations
- **Dead tests**: ✅ none
- **Speed**: ✅ appropriate
- **Severity**: 🟢 clean

#### test_audit_services.py — 🟡 minor
- **Placement**: ✅ correct
- **Naming**: ✅ accurate
- **Duplicates**: ⚠️ `TestAuditEventCategorization` (L405-551) uses extensive mocks to test billing/order event categorization. This overlaps with `test_audit_categorization.py` which tests `AuditService._get_action_severity` directly. The mock-heavy approach here is fragile — mocking ~20 attributes per object when the categorization logic only looks at the action string.
- **Mocking**: ⚠️ `TestAuditEventCategorization` (L405-551) creates massive Mock objects with 20+ attributes to test categorization. This is testing the mock setup more than the categorization logic. The `BillingAuditService.log_invoice_event(event_type=..., invoice=mock_invoice)` call needs all those mock attributes because it extracts metadata from the invoice object — but the categorization being tested only depends on the event_type string.
- **Dead tests**: ⚠️ `TestAuditEventPerformance.test_audit_logging_minimal_queries` (L557) uses `django_assert_max_num_queries` which is a pytest fixture — this won't work with Django's `TestCase`. This class uses `pytest.mark.django_db` and class-style, which should work with pytest but is inconsistent with the rest of the codebase using Django TestCase.
- **Speed**: ⚠️ Mixed Django TestCase and pytest classes in same file — could cause confusion
- **Severity**: 🟡 minor

#### test_audit_services_regressions.py — 🟢 clean
- **Placement**: ✅ correct
- **Naming**: ⚠️ "regressions" but actually comprehensive coverage tests (92KB). Better name: `test_audit_services_comprehensive.py`
- **Duplicates**: ⚠️ Some overlap with `test_audit_services.py` (both test BillingAuditService, OrdersAuditService), but this file is much more comprehensive and covers GDPR, integrity, retention, search, security, domain-specific services that `test_audit_services.py` does not.
- **Mocking**: ✅ correct — extensive but appropriate use of mocks for covering all service paths
- **Dead tests**: ✅ none
- **Speed**: ⚠️ 92KB file — consider splitting by service domain (GDPR, integrity, retention, search, etc.)
- **Severity**: 🟢 clean (large but comprehensive)

#### test_audit_siem_regressions.py — 🟢 clean
- **Placement**: ✅ correct
- **Naming**: ⚠️ "regressions" but actually comprehensive SIEM tests (60KB)
- **Duplicates**: ✅ none — only file testing `audit.siem` formatters/transports in depth
- **Mocking**: ✅ correct
- **Dead tests**: ✅ none
- **Speed**: ✅ appropriate
- **Severity**: 🟢 clean

#### test_audit_signal_registration.py — 🟢 clean
- **Placement**: ✅ correct — structural guardrail
- **Naming**: ✅ accurate
- **Duplicates**: ✅ none — unique guardrail complementing `test_audit_model_regressions.py` (allowlist-based vs signal-based)
- **Mocking**: ✅ no mocks — introspects live signal receivers
- **Dead tests**: ✅ none
- **Speed**: ✅ `SimpleTestCase` — optimal
- **Severity**: 🟢 clean

#### test_audit_signals.py — 🟡 minor
- **Placement**: ✅ correct
- **Naming**: ✅ accurate
- **Duplicates**: 🔴 `TestAuditServiceCategorization` (L554-603) tests `_get_action_category`, `_get_action_severity`, `_is_action_sensitive`, `_requires_review` — **DUPLICATED** by `test_audit_categorization.py:TestAuditServiceCategorization` (L142-302). The categorization file is more comprehensive (~50 actions vs ~30 here). Remove the duplicate from this file.
- **Mocking**: ✅ correct
- **Dead tests**: ✅ none — signal integration tests are all live
- **Speed**: ✅ appropriate
- **Severity**: 🟡 minor (duplicate categorization class)

#### test_audit_views_regressions.py — 🟢 clean
- **Placement**: ✅ correct
- **Naming**: ⚠️ "regressions" but actually comprehensive view tests (89KB)
- **Duplicates**: ⚠️ Overlaps with `test_audit_management.py` for dashboard/alert/retention views, but this file is much more comprehensive
- **Mocking**: ✅ correct — patches `Ok`/`Err` for service returns
- **Dead tests**: ✅ none
- **Speed**: ⚠️ 89KB — consider splitting by view group (management, GDPR, alerts, retention, integrity)
- **Severity**: 🟢 clean (comprehensive but large)

#### test_cookie_consent_model.py — 🟢 clean
- **Placement**: ✅ correct — CookieConsent is an audit model
- **Naming**: ✅ accurate
- **Duplicates**: ✅ none
- **Mocking**: ✅ no mocks
- **Dead tests**: ✅ none
- **Speed**: ✅ `@override_settings(DISABLE_AUDIT_SIGNALS=True)` — good optimization
- **Severity**: 🟢 clean

#### test_file_integrity_monitoring.py — 🟢 clean
- **Placement**: ✅ correct
- **Naming**: ✅ accurate
- **Duplicates**: ✅ none
- **Mocking**: ✅ correct — `patch("apps.audit.file_integrity_service.settings")` for BASE_DIR
- **Dead tests**: ✅ none
- **Speed**: ✅ uses tempfile properly, cleans up
- **Severity**: 🟢 clean

#### test_partition_retention_status.py — 🟢 clean
- **Placement**: ✅ correct
- **Naming**: ✅ accurate
- **Duplicates**: ✅ none
- **Mocking**: ✅ correct — patches `EventPartitionService` class
- **Dead tests**: ✅ none
- **Speed**: ✅ `SimpleTestCase` — optimal
- **Severity**: 🟢 clean

#### test_siem_outbound.py — 🟢 clean
- **Placement**: ✅ correct
- **Naming**: ✅ accurate — focuses on outbound HTTP security migration
- **Duplicates**: ✅ none
- **Mocking**: ✅ correct — patches `safe_request` at the right import path
- **Dead tests**: ✅ none
- **Speed**: ✅ `TestCase` — appropriate
- **Severity**: 🟢 clean

#### test_uuid_serialization.py — 🟡 minor
- **Placement**: ✅ correct
- **Naming**: ✅ accurate
- **Duplicates**: ⚠️ `test_audit_json_encoder_handles_complex_types` (L34) overlaps with `test_audit_authentication.py:test_metadata_serialization_safety` (L218) — both test UUID/datetime/Decimal serialization. Also, `test_serialize_metadata_function` (L68) overlaps with `test_audit_services.py:test_metadata_serialization_performance` (L585).
- **Mocking**: ✅ no mocks
- **Dead tests**: ✅ none
- **Speed**: ✅ `TestCase` — appropriate (needs DB for AuditService.log_event)
- **Severity**: 🟡 minor (overlapping serialization tests)

### Cross-file: audit/
1. **DUPLICATE — DELETE FILE**: `test_audit_gdpr_regressions.py` is entirely superseded by `test_audit_gdpr.py`. Every test class has a more comprehensive counterpart. The 3 "service exists" hasattr tests are trivially dead. **Recommend: delete file.**
2. **DUPLICATE — CATEGORIZATION**: `test_audit_signals.py:TestAuditServiceCategorization` (L554-603) duplicates `test_audit_categorization.py:TestAuditServiceCategorization` (L142-302). **Recommend: remove from test_audit_signals.py.**
3. **DUPLICATE — SIGNAL PIPELINE**: `test_audit_e2e.py` and `test_audit_event_creation.py` both test SystemSetting.create → AuditEvent and Invoice.create → AuditEvent. **Recommend: merge into test_audit_event_creation.py** (which covers more models), rename `test_audit_e2e.py` to focus on HTTP→signal pipeline only.
4. **OVERLAP — MANAGEMENT VIEWS**: `test_audit_management.py` (773L) overlaps with `test_audit_views_regressions.py` (89KB). The views file is far more comprehensive. **Recommend: merge unique tests from management.py into views file, delete management.py.**
5. **OVERLAP — SERIALIZATION**: UUID/datetime serialization tested in 3 files: `test_uuid_serialization.py`, `test_audit_authentication.py`, `test_audit_services.py`. **Recommend: consolidate into test_uuid_serialization.py.**
6. **DEAD INDEX TESTS**: Both `test_audit_authentication.py:test_audit_indexes_exist` and `test_audit_categorization.py:test_audit_event_indexes_exist` always skip on SQLite. The categorization one cheats by hardcoding expected indexes as the answer. **Recommend: remove both or gate behind PostgreSQL-only CI.**
7. **NAMING**: 5 files use "regressions" suffix but aren't regression tests: `test_audit_gdpr_regressions.py` (basic tests), `test_audit_services_regressions.py` (comprehensive coverage), `test_audit_siem_regressions.py` (comprehensive SIEM), `test_audit_views_regressions.py` (comprehensive views), `test_audit_model_regressions.py` (structural guardrail).
8. **SPEED — LARGE FILES**: `test_audit_services_regressions.py` (92KB), `test_audit_views_regressions.py` (89KB), `test_audit_siem_regressions.py` (60KB), `test_audit_compliance.py` (56KB) are very large. Consider splitting by domain.
9. **SPEED — setUp**: `test_audit_management.py:EnterpriseAuditManagementTestCase.setUp` creates 3 users + 15 audit events per test class. Use `setUpTestData` for shared fixtures.

### audit/ Summary
| Metric | Count |
|--------|-------|
| 🔴 Needs action | 1 (test_audit_gdpr_regressions.py — delete, entirely superseded) |
| 🟡 Minor | 9 (test_audit_authentication, test_audit_categorization, test_audit_e2e, test_audit_event_creation, test_audit_gdpr, test_audit_management, test_audit_services, test_audit_signals, test_uuid_serialization) |
| 🟢 Clean | 13 |
| Duplicate test classes | 3 (categorization in 2 files, SystemSetting pipeline in 2 files, GDPR basic/comprehensive) |
| Dead tests | 4 (2 index tests always skip, 3 hasattr service-exists tests, 1 cheating index test) |
| Mock issues | 1 (test_audit_services.py over-mocking for categorization) |
| Speed optimizations | 3 (setUpTestData in management, split large files, remove dead index tests) |

### billing/ (41 files) + billing/efactura/ (16 files) = 57 files total

#### CRITICAL FINDINGS — billing/

##### test_currencies.py — 🔴 needs action
- **Duplicates**: 🔴 **ENTIRE FILE IS DUPLICATE** — `CurrencyTestCase` and `FXRateTestCase` are exact duplicates of tests in `test_billing_models_regressions.py`. Example: `test_currency_code_primary_key` appears in both files.
- **Dead tests**: ⚠️ `test_currency_protect_on_delete` accepts both CASCADE and PROTECT behaviors (try/except with pass) — tests nothing definitive
- **Recommendation**: DELETE entire file

##### test_billing_signals.py — 🔴 needs action
- **Duplicates**: 🔴 Only 2 tests covering post_save signals. Entirely superseded by `test_billing_signals_regressions.py` (50+ handlers, 2400+ lines). Doesn't verify signal arguments, only that handler was called.
- **Recommendation**: DELETE file, merge any unique tests into regressions file

##### test_services.py — 🔴 needs action
- **Duplicates**: 🔴 ~20+ tests duplicated with `test_refund_service_regressions.py` (exact copies: `test_refund_order_order_not_found`, `test_refund_order_eligibility_check_failed`, `test_refund_invoice_invoice_not_found`, etc.)
- **Mocking**: 🔴 **WRONG PATCH TARGET** — `patch('apps.orders.models.Order.objects.select_related')` patches model class, not where it's imported in `refund_service.py`. Should be `patch('apps.billing.refund_service.Order.objects.select_related')`. Affects 15+ tests — tests pass but don't exercise the actual code path.
- **Recommendation**: Deduplicate with refund_service_regressions.py, fix all patch targets

##### test_invoices_views.py — 🟡 minor
- **Dead tests**: 🔴 `test_invoice_send_success` (L365) is a **placeholder** — only asserts `self.assertTrue(True)`, never calls the view. DELETE or implement.

##### test_billing_tasks.py — 🟡 minor
- **Dead/legacy**: ⚠️ Module docstring documents a known **production bug**: `invoice.due_date` should be `invoice.due_at`. Tests lock in broken behavior (tasks return error dict on AttributeError caught by generic except handler).
- **Speed**: ⚠️ Uses TransactionTestCase but could be TestCase. Creates 10+ Payment objects in setUp — should use setUpTestData for read-only tests.

##### test_sequences_concurrency.py — 🟡 minor
- **Naming**: 🔴 **MISLEADING** — "concurrency" but only calls `get_next_number()` 10 times sequentially in a single test. NOT testing actual concurrent access (no threading, no TransactionTestCase, no multiple DB connections).
- **Duplicates**: ⚠️ `test_sequential_numbers_unique_and_incrementing` duplicates `test_sequences.py` tests.
- **Recommendation**: Merge into test_sequences.py or implement real concurrency tests

##### test_refund_service_regressions.py — 🟡 minor
- **Mocking**: ⚠️ Same wrong patch target issue as test_services.py — `patch('apps.orders.models.Order.objects.select_related')` should patch at import point in refund_service.py
- **Speed**: ⚠️ Heavy setUp with 5 object creation calls per test — use setUpTestData

##### test_metering_services.py — 🟡 minor
- **Mocking**: ⚠️ L119 patches `MeteringService` class but then uses real instance from setUp — patch doesn't affect real instance
- **Speed**: 🔴 `MeteringServiceTransactionTests(TransactionTestCase)` L230 doesn't need transactions — tests sequential idempotency. Downgrade to TestCase.
- **Duplicates**: ⚠️ `check_thresholds` tested in both AlertTasksTestCase and UsageAlertServiceTestCase

##### test_payment_service.py — 🟡 minor
- **Mocking**: ⚠️ Tests mock gateway to return hardcoded results, then assert mock behavior — testing the mock, not PaymentService logic (service just passes through to gateway)
- **Dead**: ⚠️ L413-417 comments about "REMOVED" webhook methods — cleanup needed

##### test_metering_gateway_regressions.py — 🟡 minor
- **Duplicates**: ⚠️ `TestResult` and `_parse_decimal()` tests (L122-149) duplicate `test_common_types.py`
- **Mocking**: ⚠️ Uses `SimpleNamespace` for mock objects instead of real model instances — attribute access patterns differ from production

#### NOTABLE CLEAN FILES — billing/

##### test_creditledger.py — 🟢 clean
- Well-structured, comprehensive model tests with aggregation queries, good integration scenarios

##### test_efactura_service.py — 🟢 clean
- Excellent XML structure validation with namespace handling, comprehensive header/line item/tax tests

##### test_security.py — 🟢 clean
- Strong security coverage: JSON validation, sensitive key detection, XSS blocking, SSRF protection, amount limits

##### test_tax_configuration.py — 🟢 clean
- ADR-compliant (references ADR-0005, ADR-0015), tests config resolution 4-tier chain

##### test_usage_billing_redteam.py — 🟡 minor (good quality)
- Excellent red team documentation with "RED TEAM FINDING" comments. Minor: 3 tests use TransactionTestCase for idempotency — could extract to separate file.

##### test_validators_financial.py — 🟢 clean
- Clean pytest organization. Minor: some tests verify constant values rather than validation behavior

#### CRITICAL FINDINGS — billing/efactura/

##### efactura/test_service.py — 🟡 minor
- **Duplicates**: ⚠️ Potential HIGH overlap with parent `billing/test_efactura_service.py` — both test `EFacturaService` submission/status workflows

##### efactura/test_xsd_validator.py — 🟡 minor
- **Duplicates**: ⚠️ Overlap with `efactura/test_security.py` which already tests XXE, billion laughs, null bytes against XSDValidator

##### efactura/test_metrics.py — 🟡 minor
- **Dead**: ⚠️ `test_creates_real_metrics_when_available` (L308-315) is empty — does nothing. Mark @skip or remove.

##### efactura/test_sandbox_integration.py — 🟢 clean (integration)
- Properly marked `@pytest.mark.integration @pytest.mark.slow`, always skipped without env vars. Tests real ANAF API — correct for integration suite.

##### efactura/test_b2c.py — 🟡 minor
- **Dead**: ⚠️ `test_february_29_non_leap_year` (L457) has conditional assertion (`if result.is_valid is False: pass`) — tests nothing
- **Dead**: ⚠️ `test_valid_cnp_male_1900s` (L28) — no actual validation performed

##### efactura/test_token_storage.py — 🟢 clean
- Comprehensive token lifecycle tests, proper cache isolation, minimal mocking

##### efactura/test_quota.py — 🟢 clean
- Excellent quota logic coverage, real in-memory cache, proper endpoint rate limits

##### efactura/test_security.py — 🟢 clean
- Excellent red-team security tests: XXE, path traversal, token leaking, quota bypass, concurrency

#### LARGE FILE WARNING — billing/
- `test_subscription_models_regressions.py` (66KB) — consider splitting by feature
- `test_subscription_service.py` (60KB) — consider splitting by service domain
- `test_billing_signals_regressions.py` (2400+ lines) — large but organized by handler

### Cross-file: billing/
1. **DELETE FILE**: `test_currencies.py` — entirely duplicated by `test_billing_models_regressions.py`
2. **DELETE FILE**: `test_billing_signals.py` (2 tests) — entirely superseded by `test_billing_signals_regressions.py` (50+ handlers)
3. **DEDUPLICATE**: `test_services.py` and `test_refund_service_regressions.py` share ~20+ duplicate tests. Keep regressions for edge cases, consolidate happy-path into one file.
4. **FIX MOCK TARGETS**: 15+ refund tests across `test_services.py` and `test_refund_service_regressions.py` patch at wrong location (`apps.orders.models.Order.objects` vs `apps.billing.refund_service.Order`)
5. **MERGE**: `test_sequences_concurrency.py` into `test_sequences.py` — "concurrency" file doesn't test concurrency
6. **OVERLAP CHECK**: `billing/efactura/test_service.py` vs `billing/test_efactura_service.py` — likely 30-50% overlap
7. **OVERLAP CHECK**: `billing/efactura/test_xsd_validator.py` vs `billing/efactura/test_security.py` — XXE/attack tests in both
8. **PLACEHOLDER**: `test_invoices_views.py:test_invoice_send_success` — DELETE (asserts True, never calls view)
9. **PRODUCTION BUG**: `test_billing_tasks.py` documents `invoice.due_date` should be `invoice.due_at` — tests lock in broken behavior
10. **DEAD TESTS**: 4 tests in efactura/ have no-op assertions (conditional pass, empty test body)

### billing/ Summary
| Metric | Count |
|--------|-------|
| 🔴 Needs action | 3 files (test_currencies.py DELETE, test_billing_signals.py DELETE, test_services.py fix mocks + deduplicate) |
| 🟡 Minor | 14 files |
| 🟢 Clean | 40 files |
| Duplicate test files | 2 (test_currencies.py, test_billing_signals.py) |
| Duplicate test groups | 3 (refund ~20 tests, sequences ~5 tests, efactura service overlap) |
| Dead tests | 6 (1 placeholder, 1 empty, 4 no-op assertions in efactura/) |
| Mock issues | 15+ (wrong patch target in refund tests, testing mocks not code) |
| Speed optimizations | 5 (TransactionTestCase downgrades, setUpTestData, split large files) |
| Production bug documented | 1 (due_date→due_at in billing.tasks) |

### common/ (31 files) — 🟢 EXCELLENT

All 31 files are clean. Highlights:
- Well-structured test suite covering validators, encryption, outbound HTTP, rate limiting, FSM transitions
- All use `TestCase` or `SimpleTestCase` (no `TransactionTestCase`)
- No duplicate tests, no dead tests, no mock issues
- `test_fsm_transitions.py` has 25 method name duplicates across 6+ model classes — these are **intentional** (same test pattern applied to Order, Service, Domain, Ticket, Invoice, Subscription, Refund)

Only minor note:
- `test_code_health_scan.py` — referenced in skip grep but no actual skip decorators found

### customers/ (16 files) — 🟢 EXCELLENT

All 16 files are clean. Highlights:
- Comprehensive model, service, API, and security tests
- Good Romanian compliance coverage (CUI, VAT)
- No `TransactionTestCase`, no dead tests

Only minor notes:
- `test_profile_service.py` — duplicate method names `test_unsafe_field_id_is_silently_dropped` across TestProfileServiceTaxProfileAllowlist and TestProfileServiceBillingProfileAllowlist. These are **intentional** (same pattern, different profile types) but could be suffixed for clarity.

### domains/ (2 files) — 🟢 CLEAN
- `test_api_client_outbound.py` — outbound HTTP security migration to safe_request()
- `test_domains_security.py` — registrar form encryption, race conditions, admin authorization

### infrastructure/ (20 files) — 🟢 EXCELLENT

All 20 files clean. Highlights:
- Comprehensive cloud provider testing (Hetzner, AWS, DigitalOcean, Vultr)
- FSM deployment state machine with 100% STATUS_CHOICES coverage
- Drift scanning, remediation, credential vault integration
- All mock targets correct, no `TransactionTestCase`

### integrations/ (2 files) — 🟢 CLEAN
- `test_integrations_security.py` — webhook signature, retry timing, SSRF protection
- `test_integrations_webhooks.py` — signature verification, rate limiting, hash collision resistance

### mocks/ (1 file) — 🟢 CLEAN
- `test_virtualmin_mock.py` — MockVirtualminGateway state management, call logging, failure injection

### notifications/ (9 files) — 🟢 EXCELLENT

All 9 files clean. Highlights:
- Full email lifecycle testing (send→deliver→open→click)
- Red team security findings (timing-safe tokens, SSRF, TOCTOU)
- Template key consistency via AST parsing
- GDPR Art. 5(1)(c) data minimization in unsubscribe tokens

### orders/ (16 files) — 🟢 EXCELLENT

All 16 files clean. Highlights:
- Comprehensive order flow hardening (BUG-10/11/12 fixes)
- Romanian VAT calculation (21%) extensively tested
- Order numbering, FSM transitions, preflight validation
- Search injection prevention, price tampering validation

### performance/ (1 file) — 🟡 minor
- `test_n1_query_optimization.py` — User model prefetch_related optimization
- **Issue**: Print statements in tests (10+ instances) — should use logging or be removed

### products/ (4 files) — 🟢 CLEAN
- Models, views, security, ProductPrice auth — all well-structured

### promotions/ (3 files) — 🟢 CLEAN
- Models, services, advanced scenarios (multi-currency, redemption limits)

### provisioning/ (16 files) — 🟡 minor

Mostly clean with a few issues:

#### test_cross_app_integration.py — 🟡 minor
- **Dead code**: `_removed_test_payment_provisioning_trigger_query_efficiency` (L630) — disabled test with orphaned mock parameter, still in code. DELETE.

#### test_provisioning_services.py — 🟡 minor
- **Weak assertion**: L237 has `self.assertTrue(True)` placeholder — no real check on service activation

#### test_provisioning_signals.py — 🟡 minor
- **Duplicate**: `test_provisioning_completion_notification` also exists in `test_cross_app_integration.py` with different patch paths — may indicate signal import inconsistency

### security/ (4 files) — 🟢 CLEAN
- Comprehensive access control, enhanced validation, file upload security, simple access control

### settings/ (6 files) — 🟢 EXCELLENT
- Billing terms, logging config, secret key resolution, settings import/integration/security
- Excellent structural validation and encryption testing

### tickets/ (6 files) — 🟢 CLEAN
- Status service, API stats, attachments, comments, file scanning, security

### tracing/ (1 file) — 🟢 CLEAN
- `test_trace_analysis.py` — RequestIDFilter, PerformanceProfiler, QueryTracer

### ui/ (1 file) — 🟢 CLEAN
- `test_ui_security.py` — Button/icon component XSS prevention

### users/ (14 files) — 🟡 minor

Mostly clean with a few issues:

#### test_authentication_views.py — 🟡 minor
- **Weak assertion**: L508 has `self.assertTrue(True)` placeholder — "View handled POST without error"

#### test_session_management.py — 🟡 minor
- **Weak assertion**: L297 has `self.assertTrue(True)` in try-except — no real validation

### root (1 file) — 🟢 CLEAN
- `test_platform_core_functionality.py` — smoke test (user creation, timezone, DB ops, messages)

---

## Cross-Folder Duplicate Analysis

### 1. Refund tests spread across billing/ and orders/
- `billing/test_services.py` and `billing/test_refund_service_regressions.py` — ~20 duplicate refund tests
- `billing/test_payments_refunds.py` — refund service tests
- `orders/test_orders_refund.py` — order refund workflows
- **Assessment**: orders/ tests different layer (order-level refund), billing/ tests service-level. The billing/ internal duplication is the real issue.

### 2. Signal tests across audit/ and provisioning/
- `audit/test_audit_signal_registration.py` — structural guardrail for signal wiring
- `provisioning/test_provisioning_signals.py` — signal behavior tests
- `provisioning/test_cross_app_integration.py` — cross-app signal integration
- **Assessment**: `test_provisioning_completion_notification` duplicated between signals and cross_app files

### 3. Security validation tested in multiple folders
- `common/test_common_security.py` and `common/test_common_security_checks.py` — system checks
- `security/test_enhanced_validation.py` — input validation
- `billing/test_security.py` — financial validation
- `products/test_products_security.py` — product validation
- **Assessment**: Appropriate — each tests domain-specific security at different layers. NOT duplicates.

### 4. HMAC middleware tested in api/ and used in orders/customers
- `api/test_hmac_middleware.py` — unit tests for middleware
- `api/test_hmac_billing_staff_bypass.py` — billing path bypass
- `orders/test_order_flow_hardening.py` — HMAC verification in order flow
- `customers/test_billing_address_api.py` — HMAC in customer API
- **Assessment**: Appropriate — testing at different integration points. The shared `_sign()` helper duplication (api/ files) should use `tests/helpers/hmac.py`.

## Summary

| Metric | Count |
|--------|-------|
| **Total files audited** | **244** |
| 🔴 Needs action (DELETE file) | **4** (test_currencies.py, test_billing_signals.py, test_audit_gdpr_regressions.py, plus fix test_services.py mocks) |
| 🟡 Minor issues | **~30** files with cosmetic/minor issues |
| 🟢 Clean | **~210** files |
| **Duplicate test files** | **3** (currencies, billing_signals, audit_gdpr_regressions) |
| **Duplicate test groups** | **5** (refund ~20 tests, categorization 2 files, SystemSetting pipeline 2 files, sequences, efactura service overlap) |
| **Dead tests** | **~15** (placeholders, no-op assertions, always-skipped index tests, removed-but-kept code) |
| **Mock issues** | **~20** (15+ wrong patch targets in refund tests, 3 testing-mock-not-code, 2 broad mocks) |
| **Speed optimizations** | **~10** (TransactionTestCase downgrades, setUpTestData migrations, large file splits) |
| **Production bugs documented** | **1** (billing.tasks due_date→due_at) |
| **Weak assertions (assertTrue(True))** | **4** (provisioning services, auth views, session management, invoices views) |
| **Print statements to remove** | **10+** (performance/test_n1_query_optimization.py) |

### Top 10 Action Items (Priority Order)

1. **DELETE** `billing/test_currencies.py` — entirely duplicated by test_billing_models_regressions.py
2. **DELETE** `billing/test_billing_signals.py` — 2 tests superseded by regressions file (50+ tests)
3. **DELETE** `audit/test_audit_gdpr_regressions.py` — entirely superseded by test_audit_gdpr.py
4. **FIX** 15+ wrong mock patch targets in `billing/test_services.py` and `test_refund_service_regressions.py` — currently testing mocks, not code
5. **DEDUPLICATE** `billing/test_services.py` vs `billing/test_refund_service_regressions.py` — ~20 identical tests
6. **REMOVE** `audit/test_audit_signals.py:TestAuditServiceCategorization` — duplicated by test_audit_categorization.py
7. **FIX** 4 placeholder `self.assertTrue(True)` assertions — implement real checks or delete
8. **MERGE** `billing/test_sequences_concurrency.py` into `test_sequences.py` — doesn't test concurrency
9. **FIX** production bug: `billing/tasks.py` uses `invoice.due_date` instead of `invoice.due_at`
10. **REMOVE** dead code: `provisioning/test_cross_app_integration.py:_removed_test_*` and audit index tests that always skip
