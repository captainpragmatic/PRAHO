# PRAHO Codebase Archaeology Report

**Analysis Date:** March 1, 2026
**Author:** PRAHO Development Team
**Project Version:** 0.20.0 (Alpha)

---

## Executive Summary

This archaeological analysis reveals a codebase undergoing rapid, intentional evolution over approximately 7 months (August 2025 - March 2026). The PRAHO platform shows evidence of at least **four distinct development eras** with clear architectural migrations, abandoned experiments, and cultural artifacts that reveal the team's evolving philosophy.

---

## Timeline of Architectural Evolution

### Era 1: "Monolithic Django" (Pre-August 2025)
**Evidence:** Migration files, legacy patterns, commented code

**Characteristics:**
- Single Django project with standard admin interface
- Celery + Redis for task processing
- Monolithic `models.py`, `views.py` files per app
- Integer primary keys for all models
- Direct function signatures with many parameters (`PLR0913` violations)

**Fossil Evidence:**
- `celery_task_id` field renamed to `task_id` in migration `0007_rename_celery_task_id_to_task_id.py`
- `django-rq` commented out in `config/urls.py:62`
- `.env.example` still contains `REDIS_URL=redis://localhost:6379/0`
- Tests explicitly check Redis is NOT present (`test_docker_services.py:94`)

---

### Era 2: "Security Hardening & Refactoring" (August 2025)
**Evidence:** Commit history, ADRs, migration patterns

**Major Events:**
1. **Django Admin Removal** (commit `85cb433`, Aug 28)
   - Complete removal of Django's built-in admin
   - Custom admin interfaces built instead
   - `# DjangoAdmin removed - Django admin disabled` comments left in `types.py`

2. **Celery to Django-Q2 Migration** (commit `55d0fe9`, Sept 2)
   - Eliminated Redis dependency
   - Database-backed task queue
   - Migration `0007_rename_celery_task_id_to_task_id.py` preserved transition

3. **Integer to String Object IDs** (migration `0006_convert_object_id_to_string.py`, Aug 28)
   - Changed from `PositiveIntegerField` to `CharField(max_length=36)`
   - Enabled UUID support for future scalability
   - Careful reverse migration validation for non-numeric IDs

4. **BackupCode Model Lifecycle** (Aug 31 - Sept 2)
   - Created in `0007_create_backup_code_model.py`
   - Migrated existing codes in `0008_migrate_existing_backup_codes.py`
   - **Deleted in `0009_delete_backupcode.py`**
   - Evidence of abandoned feature or consolidated into User model

---

### Era 3: "Feature-Based Organization & Type Safety" (September - December 2025)
**Evidence:** ADR-0012, file structure, type annotations

**Major Events:**
1. **Feature-Based File Split** (commit `6bf250e`, Sept)
   - Customers app split: `customer_*.py`, `contact_*.py`, `profile_*.py`
   - Billing app split: `invoice_*.py`, `payment_*.py`, `refund_*.py`
   - Root `models.py` became import aggregator

2. **Services Architecture** (PR #1, commit `cbc795c`)
   - Split into `platform/` (full Django) and `portal/` (API-only)
   - Portal explicitly excludes database drivers for security isolation
   - Requirements explicitly state: "NO psycopg2, NO redis"

3. **Result Pattern Adoption**
   - Rust-inspired `Ok()/Err()` pattern introduced
   - Multiple implementations coexist (proper `result` library vs. local `Result` class)
   - `virtualmin_auth_manager.py` has local Result implementation (line 24-60)

---

### Era 4: "Business Logic Maturity & Portal Buildout" (January - March 2026)
**Evidence:** CHANGELOG, commit history, new ADRs

**Major Events:**
1. **VAT Architecture Consolidation** (v0.14.0-v0.15.0, Feb 2026)
   - Eliminated all hardcoded `ROMANIAN_VAT_RATE` constants from business logic
   - Centralized to `TaxService` with cache → DB → settings → defaults cascade (ADR-0015)
   - Per-customer VAT overrides via `CustomerTaxProfile`

2. **Billing System Implementation** (v0.19.0-v0.20.0, Feb-Mar 2026)
   - 27 TODO stubs implemented in billing app (commit c341d403)
   - Subscription service, payment processing, credit ledger
   - RefundService integration with orders completed

3. **Portal Service Buildout** (v0.18.0-v0.20.0, Feb 2026)
   - E2E test suite for portal checkout flow
   - Portal auth fail-open strategy documented (ADR-0017)
   - HMAC-signed inter-service communication hardened

4. **Security Hardening Sprint** (v0.19.1, Feb 28 2026)
   - P1-P3 security audit findings addressed (commit 879e04e2)
   - Race conditions in webhook/refund processing fixed
   - Template injection and exception leak prevention

5. **Documentation Restructuring** (v0.20.0, Mar 2026)
   - docs/ reorganized into 7 domain folders
   - 25 ADRs consolidated with consistent naming
   - Fresh dependency analysis generated

---

## Fossil Code Catalog

### 1. Legacy Wrapper Functions
**Location:** Multiple service files
**Pattern:** `*_legacy()` function suffixes

```python
# apps/audit/services.py:1013-1106
def log_event_legacy(...)       # 34 lines
def log_2fa_event_legacy(...)   # 22 lines
def log_compliance_event_legacy(...) # 21 lines

# apps/users/services.py:737-783
def create_user_for_customer_legacy(...)
def link_existing_user_legacy(...)
def invite_user_to_customer_legacy(...)

# apps/common/credential_vault.py:341, 538
def store_credential_legacy(...)
def rotate_credential_legacy(...)

# apps/common/security_decorators.py:121
def secure_service_method_legacy(...)
```

**Purpose:** Backward compatibility bridges during API migration
**Assessment:** Active fossils - still used but intended for eventual removal

### 2. Type Compatibility Aliases
**Location:** `apps/common/types.py:684-700`

```python
# LEGACY COMPATIBILITY ALIASES
DjangoUser = AbstractUser
DjangoModel = models.Model
DjangoForm = Form
# DjangoAdmin removed - Django admin disabled  <- FOSSIL COMMENT
DjangoRequest = HttpRequest
DjangoResponse = HttpResponse
DjangoQuerySet = QuerySet

# Backward compatibility for older naming conventions
UserModel = AbstractUser
BaseModel = models.Model
BaseForm = Form
# BaseAdmin removed - Django admin disabled  <- FOSSIL COMMENT
```

### 3. Commented-Out Code (ERA001 violations kept)
**Location:** Multiple files with `# noqa: ERA001`

```python
# config/urls.py:62
# path('django-rq/', include('django_rq.urls')),  # noqa: ERA001

# integrations/webhooks/base.py:496-497
# from .virtualmin import VirtualminWebhookProcessor  # TODO: Implement  # noqa: ERA001
# from .paypal import PayPalWebhookProcessor  # TODO: Implement  # noqa: ERA001
```

### 4. Legacy View Redirects
**Location:** `apps/audit/views.py:1460-1470`

```python
# ===============================================================================
# LEGACY/ADMIN VIEWS
# ===============================================================================

# Legacy export endpoint - redirect to new GDPR system
@login_required
def export_data(request: HttpRequest) -> HttpResponse:
    """Legacy data export endpoint - redirect to GDPR dashboard"""
    messages.info(request, _("Data export has moved to the GDPR Privacy Dashboard."))
    return redirect("audit:gdpr_dashboard")
```

---

## Abandoned Experiments

### 1. Week 3 & Week 4 Virtualmin Implementation
**Location:** `apps/provisioning/TODO_WEEK3_RECOVERY.md`, `TODO_WEEK4_VERIFICATION.md`

**Planned but not implemented:**
- Immutable backup infrastructure with S3
- Disaster recovery automation
- Red team security testing framework
- Recovery time measurement tools

**Evidence of partial implementation:**
- `virtualmin_backup_service.py` has 6 bare `# TODO` comments (lines 559, 618, 657, 678, 697)
- `virtualmin_disaster_recovery.py` exists but with placeholder logic

### 2. Virtualmin Webhook Processors
**Location:** `apps/integrations/webhooks/base.py:496-497`

```python
# from .virtualmin import VirtualminWebhookProcessor  # TODO: Implement
# from .paypal import PayPalWebhookProcessor  # TODO: Implement
```

### 3. RefundService in Orders — RESOLVED
**Location:** `apps/orders/views.py`

**Original State:** RefundService integration was pending with TODO stubs returning error messages ("Refund functionality temporarily disabled").

**Resolution:** RefundService was fully implemented in v0.20.0 (commit c341d403). The `orders/views.py` now properly imports and uses `RefundService.refund_order()`. The 27 billing TODO stubs were completed in the same release, including the refund pipeline.

---

## Cultural Artifacts

### 1. Emoji-Based Logging Convention
**649 occurrences across 103 files**

Emoji vocabulary reveals team communication style:
- `🔧` - Fixes/maintenance (most common)
- `🚨` - Security warnings/critical issues
- `🎯` - Targeting/goals
- `🔒` - Security features
- `📊` - Statistics/analytics
- `🗑️` - Cleanup/deletion
- `🌐` - Domain/network operations
- `🎫` - Ticket system
- `🔄` - Sync/update operations
- `🔥` - Error/failure conditions

### 2. Romanian Business Context
**Evidence throughout codebase:**

```python
# Phone validation: +40.XX.XXX.XXXX format
# VAT: Romanian VAT compliance (CUI validation)
# Language: Natural Language :: Romanian in pyproject.toml
# Invoicing: e-Factura integration for Romanian electronic invoicing
# Registrar: ROTLD integration for .ro domains
```

### 3. Comment Header Styles
**Three distinct patterns identified:**

**Style A - ASCII Box (older)**
```python
# ===============================================================================
# SECTION NAME
# ===============================================================================
```

**Style B - Emoji Headers (newer)**
```python
# 🎯 FEATURE NAME
# 🔒 SECURITY SECTION
```

**Style C - ADR References (newest)**
```python
# See ADR-0012 for architecture decision
# Per ADR-0007 function-level imports
```

### 4. Result Pattern Inconsistency
**Three implementations coexist:**

1. **Local Result class** (`virtualmin_auth_manager.py:30-60`)
2. **TypedDict approach** (`AddressValidationResult`)
3. **Imported `Ok`/`Err`** from result library (most common)

---

## Evolution Patterns

### Pattern 1: Monolithic → Feature-Based Split
```
Old: apps/billing/models.py (1250+ lines, 15+ models)
New: apps/billing/
     ├── invoice_models.py
     ├── payment_models.py
     ├── refund_models.py
     ├── proforma_models.py
     ├── tax_models.py
     ├── currency_models.py
     └── models.py (import aggregator)
```

### Pattern 2: Signals Overflow
```
Old: apps/orders/signals.py
New: apps/orders/
     ├── signals.py (base signals)
     └── signals_extended.py (cross-app integration)
```

### Pattern 3: Service Layer Extraction
```
Old: Business logic in models/views
New: Dedicated *_service.py files per feature
     ├── invoice_service.py
     ├── refund_service.py
     └── provisioning_service.py
```

### Pattern 4: Legacy → DataClass API Migration
```python
# Old (many positional params):
def log_event_legacy(event_type, user=None, content_object=None,
                     old_values=None, new_values=None, description="", ...)

# New (structured dataclasses):
@dataclass
class AuditEventData:
    event_type: str
    content_object: Any | None = None
    old_values: dict | None = None
    ...

def log_event(event_data: AuditEventData, context: AuditContext) -> AuditEvent:
```

---

## Dependency Archaeology

### Removed Dependencies (Fossils in docs/tests)
| Dependency | Removed When | Evidence Location |
|------------|--------------|-------------------|
| Celery | Sept 2025 | migration.md, migrations |
| Redis | Sept 2025 | test_docker_services.py |
| django-rq | Sept 2025 | urls.py (commented) |
| django-admin | Aug 2025 | types.py comments |
| pytest (CI) | Dec 2025 | bbf5100 commit |

### Current Stack Evolution
- **Task Queue:** Celery → Django-Q2 (database backend)
- **Session:** Redis → Database/Cookie
- **Admin:** Django Admin → Custom HTMX interfaces
- **Testing:** pytest → Django test runner (CI only)
- **Package Manager:** pip/requirements.txt → uv workspace (ADR-0013)
- **VAT Handling:** Hardcoded constants → TaxService cascade (ADR-0015)

---

## Architecture Decision Records (ADRs)

25 ADRs (ADR-0001 through ADR-0025) document key decisions.

See [ADR Index](../ADRs/README.md) for the complete list of 25 architecture decision records.

---

## Conclusions

### Development Velocity
- ~100 commits in 7 months
- Major architectural changes every 2-3 weeks
- Active refactoring alongside feature development

### Technical Debt Status
- **Healthy:** Legacy wrappers are intentional, documented
- **Concerning:** 6+ bare `# TODO` in backup service
- **Risk:** Multiple Result pattern implementations

### Recommendations for Future Archaeologists
1. Look for `_legacy` suffix to understand API evolution
2. Check ADRs before making architectural changes
3. `# noqa: ERA001` marks intentionally preserved comments
4. Emoji logging is the canonical team communication style
5. Portal service isolation is intentional security architecture

---

*"In the ruins of monolithic Django, we found the seeds of microservices."*
