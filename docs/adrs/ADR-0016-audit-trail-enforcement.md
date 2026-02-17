# ADR-0016: Audit Trail Enforcement

**Status:** Accepted
**Date:** 2026-02-15
**Authors:** Development Team
**Supersedes:** N/A
**Related:** ADR-0005 (Single Constants File Architecture), ADR-0015 (Configuration Resolution Order)

## Context

PRAHO's audit module (`apps.audit`) provides comprehensive audit trail capabilities — immutable event logging, SIEM export, compliance reporting, and GDPR data export. However, enforcement of audit coverage was entirely manual: nothing prevented a developer from adding a new model without wiring it to audit signals.

A codex review revealed concrete gaps:

1. **Dead signal registration** — `billing`, `orders`, `customers`, and `domains` apps had empty `ready()` methods (or no `AppConfig` at all), meaning `@receiver` decorators in their `signals.py` files were never registered at runtime.
2. **No structural enforcement** — no lint or test verified that every business model was either wired to audit signals or explicitly exempted.
3. **Inconsistent audit paths** — some signals used `AuditService.log_simple_event()` directly, others used the `log_security_event()` helper (which delegates to `AuditService` internally). Both are valid but the inconsistency made coverage scanning harder.

Without enforcement, audit gaps silently accumulate as the codebase grows.

## Decision

PRAHO adopts a **three-tier audit trail enforcement** strategy:

### Tier 1: Static Lint (`scripts/audit_coverage_scan.py`)

A static analysis script that runs during `make lint` and pre-commit hooks. It performs two categories of checks:

**Structural coverage checks:**

1. **Model-to-signal coverage** — cross-references models defined in `models*.py` files against signal senders in `*signal*.py` files. Models not in the allowlist and not referenced as a signal sender are flagged (high severity for critical apps, medium otherwise).
2. **Signal audit imports** — checks that signal files in app directories import `apps.audit` or `log_security_event` (medium severity).
3. **Service audit imports** — checks that `services.py` / `*_service.py` files in critical app directories import audit modules (low severity, advisory).
4. **Event type coverage** — one-directional check that event names documented in `BUSINESS_AUDIT_EVENTS.md` appear somewhere in code (info severity).

**Anti-pattern detection (AST-based):**

5. **Placeholder audit functions** — detects `log_security_event()` with empty/stub bodies outside canonical files (critical severity).
6. **Placeholder validation functions** — detects `validate_financial_*()` with empty/stub bodies outside canonical files (high severity).
7. **Commented-out audit decorators** — flags `# @audit_service_call(` patterns (high severity).
8. **Deprecated audit API** — flags calls to `log_event_legacy()` (medium severity).
9. **Direct audit model access** — flags `AuditEvent.objects.create()` outside `apps/audit/` (medium severity).

### Tier 2: Django Introspection Test (`tests/audit/test_audit_model_coverage.py`)

A Django test that uses `django.apps.apps.get_models()` to introspect all registered models at runtime. Every concrete, non-proxy model in `apps.*` must either:

1. Have a `post_save`, `pre_save`, `post_delete`, or `pre_delete` signal connected, OR
2. Be listed in the allowlist with a documented justification comment

Additional checks: stale allowlist entries (entries that don't match any installed model) and uncommented entries (missing justification) also cause test failures.

This catches models that static analysis might miss (e.g., dynamically registered models, models in third-party apps).

### Tier 3: Allowlist Governance (`scripts/audit_model_allowlist.txt`)

A centralized allowlist of models exempt from audit signal requirements. Every entry must include a justification comment. Categories:

1. **Audit infrastructure** — self-referential (auditing audit models is circular)
2. **Append-only history/log models** — these ARE the audit trail
3. **Reference/configuration data** — read-mostly, no business state changes
4. **Detail/child models** — audited via parent signal
5. **Virtualmin integration internals** — audited via Service parent
6. **Usage metering** — high-volume operational data
7. **Common app models** — credential access logs and encrypted credentials with service-layer auditing

### Model Registry Contract

Every new Django model MUST be either:

1. Wired to audit signals (via `@receiver` in `signals.py` calling `AuditService`), OR
2. Added to `scripts/audit_model_allowlist.txt` with a justification comment

Failure to do either will cause both lint and test failures.

### Accepted Audit Paths

Both of the following are valid audit logging paths:

1. **Direct**: `from apps.audit.services import AuditService` → `AuditService.log_simple_event()`
2. **Indirect**: `from apps.common.validators import log_security_event` → delegates to `AuditService.log_simple_event()` internally

The enforcement tooling accepts both patterns.

## Known Limitations

### QuerySet Bulk Operations Bypass Signals

Django's `QuerySet.update()`, `bulk_create()`, `bulk_update()`, and `QuerySet.delete()` bypass Django signals entirely. Audit enforcement based on signals cannot catch these operations.

**Mitigation:** Critical-path code using bulk operations should include explicit `AuditService` calls nearby. Code reviewers should flag bulk operations on auditable models that lack explicit audit logging.

### Signal-Based Audit Is Eventually Consistent

Signal handlers run in the same database transaction by default but after the model save. If the transaction rolls back, the audit event is also rolled back. This is generally the desired behavior (no phantom audit entries), but means audit trails reflect committed state only.

## Consequences

### Positive

1. **New models without audit classification fail both lint and tests** — gaps cannot silently accumulate
2. **Allowlist provides documentation** — every exemption has a visible justification
3. **Three-tier defense in depth** — static analysis catches structural issues, runtime tests catch registration issues, allowlist catches policy issues
4. **Signal registration bugs fixed** — four apps now properly register their signals at startup

### Trade-offs

1. **Allowlist maintenance burden** — every new model requires a conscious decision about audit coverage
2. **Bulk operation blind spot** — signals cannot enforce audit coverage for `QuerySet.update()` and similar operations
3. **Additional CI time** — introspection test adds a small amount of test suite runtime

## References

1. [Django Signals Documentation](https://docs.djangoproject.com/en/5.2/topics/signals/)
2. [OWASP Logging Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html)
3. GDPR Article 30 — Records of processing activities
4. Romanian Law 190/2018 — GDPR implementation
