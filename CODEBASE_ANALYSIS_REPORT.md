# PRAHO Codebase Pattern Analysis Report

**Date:** 2025-12-27
**Scope:** Full codebase analysis across all branches
**Scope:** Full codebase pattern analysis

---

## Executive Summary

This analysis identified **7 major pattern categories** with significant issues:

| Category | Severity | Impact |
|----------|----------|--------|
| Duplicate Result Type Implementations | **CRITICAL** | API incompatibility, test failures |
| N+1 Query Patterns | **CRITICAL** | 50x query multiplication in billing |
| Signal Circular Dependencies | **HIGH** | Potential infinite loops, race conditions |
| Validation Inconsistencies | **HIGH** | Same data validates differently |
| Error Handling Fragmentation | **MEDIUM** | Unpredictable failure behavior |
| Duplicate Utility Implementations | **MEDIUM** | Maintenance burden |
| Placeholder Code in Production | **HIGH** | Validators doing nothing |

---

## 1. RECURRING PATTERNS (Undocumented)

### 1.1 Pre-Save/Post-Save State Tracking Pattern

**Location:** All signal files (`apps/*/signals.py`)

A consistent but undocumented pattern exists where pre-save signals capture original values for comparison in post-save:

```python
# Pre-save: Capture state (14 models use this)
@receiver(pre_save, sender=Invoice)
def store_original_invoice_values(sender, instance, **kwargs):
    if instance.pk:
        original = Invoice.objects.get(pk=instance.pk)
        instance._original_invoice_values = {...}

# Post-save: Compare and act
@receiver(post_save, sender=Invoice)
def handle_invoice_created_or_updated(sender, instance, created, **kwargs):
    old_values = getattr(instance, "_original_invoice_values", {})
```

**Assessment:** BENEFICIAL - but needs documentation. The pattern is correctly used for audit trails and change detection. However:
- Uses underscore-prefixed instance attributes (convention issue)
- No type hints for these temporary attributes
- Risk of data loss if transaction rolls back after pre-save

### 1.2 Service Hub Re-Export Pattern

**Location:** `apps/billing/services.py`, `apps/customers/services.py`, `apps/provisioning/services.py`

Services.py files act as central import hubs, re-exporting from feature modules:

```python
# apps/billing/services.py - Re-export pattern
from .invoice_service import InvoiceService, generate_invoice_pdf
from .refund_service import RefundService, Result
from .proforma_service import ProformaService
```

**Assessment:** BENEFICIAL - follows ADR-0012. Good for maintainability and import simplicity.

### 1.3 Parameter Object Pattern

**Location:** `apps/orders/services.py:79-106`, `apps/users/services.py:85-119`

Dataclasses used as structured parameter containers:

```python
@dataclass
class OrderCreateData:
    customer: Customer
    items: list[OrderItemData]
    billing_address: BillingAddressData
    currency: str = "RON"
```

**Assessment:** BENEFICIAL - improves type safety and readability. Should be standardized as the default pattern for service methods with >3 parameters.

---

## 2. IMPLICIT ARCHITECTURAL DECISIONS

### 2.1 Signals as Business Logic Layer

**Discovery:** Signal handlers contain significant business logic, not just event notification.

**Evidence:**
- `billing/signals.py`: 1,569 lines with 150+ helper functions
- Invoice post-save handler performs 7 distinct operations (lines 79-149)
- Cross-app orchestration happens in signals rather than services

**Why it exists:** Organically grew from simple audit logging to complex workflows.

**Assessment:** PROBLEMATIC
- Makes testing difficult (signals fire on every save)
- Unclear execution order between multiple handlers on same model
- Debugging requires tracing across multiple files

**Recommendation:** Extract business logic to service layer, use signals only for:
- Audit logging
- Async task triggering
- Cache invalidation

### 2.2 Two Competing Type Systems

**Discovery:** Two incompatible Result type implementations coexist.

**File 1:** `apps/common/types.py` (lines 46-119)
```python
@dataclass(frozen=True)
class Ok(Generic[T]):
    value: T

@dataclass(frozen=True)
class Err(Generic[E]):
    error: E

Result = Ok[T] | Err[E]
```

**File 2:** `apps/billing/refund_service.py` (lines 24-76)
```python
class Result(Generic[T, E]):
    def __init__(self, value: T | E, is_success: bool = True):
        ...

    @classmethod
    def ok(cls, value: T) -> Result[T, E]:
        return cls(value, True)
```

**Why it exists:** `refund_service.py` was likely written before the common types module, or by a different developer unaware of existing patterns.

**Assessment:** CRITICAL PROBLEM
- `Ok(value)` vs `Result.ok(value)` - incompatible APIs
- Type checkers may accept one but reject the other
- Tests importing from different sources will behave differently

### 2.3 Emoji-Based Logging Categories

**Discovery:** Inconsistent emoji prefixes used as informal log categories.

| Service | Pattern | Example |
|---------|---------|---------|
| Domains | Extensive | `🆕 [Domain]`, `🔥 [Domain]`, `✅ [Registrar]` |
| Users | Moderate | `✅ [Secure Registration]`, `🔥 [Secure Registration]` |
| Settings | Moderate | `⚙️ [Settings]`, `🔍 [Settings]` |
| Orders | None | Clean format: `Failed to create order: {e}` |
| Billing | Minimal | `🔒 [Billing Security]` |

**Why it exists:** No logging standard defined; individual developers adopted personal preferences.

**Assessment:** PROBLEMATIC - makes log parsing and monitoring difficult.

---

## 3. ANTI-PATTERNS MASQUERADING AS VALID SOLUTIONS

### 3.1 Placeholder Validators Imported into Models

**Location:** `apps/billing/invoice_models.py:28-37`, `apps/billing/proforma_models.py:35-44`

```python
# invoice_models.py - PLACEHOLDER that does nothing
def validate_financial_amount(value: int) -> None:
    """Validate financial amount - placeholder for now."""
    pass

def validate_financial_json(data: dict) -> None:
    """Validate financial JSON - placeholder for now."""
    pass
```

Meanwhile, full implementations exist in `apps/billing/validators.py:67-119`.

**Why it exists:** Models were created with stubs for "future implementation" but the real validators were added to a different file. Imports were never updated.

**Assessment:** CRITICAL - validators called by models do nothing. Financial data validation is bypassed.

### 3.2 Catch-All Exception Handlers Hiding Real Errors

**Location:** `apps/billing/views.py:331-356`

```python
except Exception as e:
    logger = logging.getLogger(__name__)  # NEW logger instance inside except!
    logger.error(f"Database error in billing_list: {e}")
    messages.error(request, _("Unable to load billing data."))
```

**Problems:**
1. Creating logger inside exception handler is inefficient
2. Catches ALL exceptions including programming errors
3. User sees generic message regardless of error type

**Why it exists:** Quick fix for production errors that wasn't refactored.

**Assessment:** PROBLEMATIC - hides real bugs, inefficient, inconsistent with rest of codebase.

### 3.3 Email Enumeration Vulnerability Disguised as Validation

**Location:** `apps/users/forms.py:362-366`

```python
def clean_email(self) -> str:
    email = self.cleaned_data.get("email")
    if email and not User.objects.filter(email=email).exists():
        raise ValidationError("There is no account with this email address.")
    return email
```

Meanwhile, `apps/common/validators.py:173-210` has timing-safe email validation specifically to PREVENT enumeration attacks.

**Why it exists:** Developed independently without awareness of security validator.

**Assessment:** SECURITY VULNERABILITY - reveals which emails are registered.

### 3.4 Silent Exception Suppression

**Location:** `apps/billing/views.py:172-173`, `apps/customers/customer_views.py:46-47`

```python
with suppress(Exception):
    login_url += f"?{REDIRECT_FIELD_NAME}={request.get_full_path()}"
```

**Why it exists:** "Safe" failure when MessageMiddleware might not be installed.

**Assessment:** PROBLEMATIC - failures are invisible, no logging, debugging impossible.

---

## 4. SAME PROBLEM, DIFFERENT SOLUTIONS

### 4.1 VAT Number Validation (4 Different Implementations)

| Location | Pattern | Min Digits |
|----------|---------|------------|
| `common/validators.py:258` | `^RO[0-9]{2,10}$` | 2 |
| `users/forms.py:598` | Regex with auto-prepend | 6 |
| `customers/forms.py:208` | `^RO\d{6,10}$` | 6 |
| `customers/forms.py:674` (inline) | `^RO\d{6,10}$` | 6 |

**Impact:** Same VAT number "RO12345" validates in common/ but fails in forms.

### 4.2 Phone Number Validation (Duplicated)

**Location:** `apps/users/forms.py:171-180` and `apps/users/forms.py:272-281`

Identical regex pattern copied in same file:
```python
ROMANIAN_PHONE_PATTERN = r"^(\+40[\.\s]*[0-9][\.\s0-9]{8,11}[0-9]|0[0-9]{9})$"
```

### 4.3 Bank Details Schema (Incompatible)

| Location | Unique Fields |
|----------|---------------|
| `customers/customer_models.py:41-49` | `notes` (allowed) |
| `common/validators.py:440-449` | `currency` (allowed, no notes) |

**Impact:** Valid bank_details in one validator rejected by another.

### 4.4 Pagination (Two Approaches)

**Location:** `apps/common/mixins.py:28-87` (function) vs `apps/common/mixins.py:137-164` (class mixin)

Both implementations exist, with code duplication in context building.

### 4.5 Date Formatting (Three Approaches)

| Location | Approach |
|----------|----------|
| `common/utils.py:158-170` | Simple `strftime()` |
| `ui/templatetags/formatting.py:157-188` | Registry pattern |
| `ui/templatetags/formatting.py:265-292` | Relative dates with constants |

---

## 5. CRITICAL DATABASE QUERY ISSUES

### 5.1 N+1 Queries in Payment Processing

**Location:** `apps/billing/signals.py:629-637`

```python
for order in payment.invoice.orders.all():  # Query 1
    for item in order.items.filter(service__isnull=False):  # Query 2 PER ORDER
        if item.service and item.service.status in [...]:  # Query 3 PER ITEM
```

**Impact:** 10 orders × 5 items = 50+ queries instead of 2-3.

### 5.2 Profile Methods Triggering Queries

**Location:** `apps/customers/customer_models.py:296-321`

```python
def get_tax_profile(self) -> CustomerTaxProfile | None:
    return CustomerTaxProfile.objects.get(customer=self)  # QUERY

def get_billing_profile(self) -> CustomerBillingProfile | None:
    return CustomerBillingProfile.objects.get(customer=self)  # QUERY
```

Called in loops from `customer_service.py:100-114`, multiplies queries per customer.

### 5.3 Missing Transaction Boundaries in Signals

**Location:** `apps/billing/signals.py:603-641`

```python
for order in invoice.orders.all():
    result = OrderService.update_order_status(order, status_change)
    # What if one fails? Previous orders already modified!
```

**Impact:** Partial state updates if any order fails mid-loop.

---

## 6. SIGNAL ARCHITECTURE ISSUES

### 6.1 Circular Dependency Risk

**Chain:** Payment → Invoice → Order → (back to Billing?)

1. `billing/signals.py:880` - Payment saves Invoice
2. `billing/signals.py:588` - Invoice modifies Orders
3. `orders/signals_extended.py:79` - Order may trigger Billing operations

### 6.2 Multiple Handlers on Same Model

**Invoice model has:**
1. `handle_invoice_created_or_updated` (70+ lines)
2. `handle_invoice_number_generation` (calls save() again)

No execution order guarantee - both fire, potentially re-triggering each other.

### 6.3 Missing Idempotency

**Location:** Most signal handlers lack duplicate detection.

Compare:
- **BAD:** `billing/signals.py` - no idempotency checks
- **GOOD:** `provisioning/signals.py:559-576` - uses `IdempotencyManager`

---

## 7. OTHER BRANCH ANALYSIS

**Scope:** Performance and scalability optimization

Added 3,152 lines of performance infrastructure:

| File | Purpose |
|------|---------|
| `common/performance/__init__.py` | Module initialization |
| `common/performance/async_tasks.py` | Async task utilities |
| `common/performance/cache.py` | Caching layer |
| `common/performance/connection_pool.py` | DB connection pooling |
| `common/performance/query_optimization.py` | Query helpers |
| `common/performance/rate_limiting.py` | Rate limiting |
| `common/performance/resource_quotas.py` | Resource management |

**Observation:** This branch addresses some N+1 issues but introduces more infrastructure that may conflict with existing patterns.

---

## 8. PRIORITIZED RECOMMENDATIONS

### CRITICAL (Fix Immediately)

1. **Unify Result Type** - Remove `billing/refund_service.py` Result class, use `common/types.py`
2. **Fix Placeholder Validators** - Replace placeholders in invoice_models.py with imports from validators.py
3. **Fix Email Enumeration** - Use timing-safe validation in PasswordResetRequestForm
4. **Add Transaction Boundaries** - Wrap signal loops in `transaction.atomic()`

### HIGH (Fix This Sprint)

5. **Unify VAT Validation** - Create single validator, use everywhere
6. **Add N+1 Query Protection** - Add `prefetch_related` to order/item queries
7. **Document Signal Pattern** - Create ADR for pre-save/post-save state tracking
8. **Add Idempotency** - Use IdempotencyManager in billing signals

### MEDIUM (Plan for Next Quarter)

9. **Extract Signal Business Logic** - Move to service layer
10. **Consolidate Logging** - Standardize format, remove emojis from production logs
11. **Merge Duplicate Utilities** - Phone regex, date formatters, pagination

### LOW (Technical Debt Backlog)

12. **Consolidate Bank Details Schema**
13. **Standardize HTTP Error Responses**
14. **Add Type Hints to Instance Attributes**

---

## Appendix: File Reference

| Pattern/Issue | Primary Files |
|--------------|---------------|
| Result types | `common/types.py`, `billing/refund_service.py` |
| Signal patterns | `billing/signals.py`, `orders/signals.py` |
| Validators | `common/validators.py`, `billing/validators.py`, `users/forms.py` |
| Error handling | `billing/views.py`, `customers/customer_views.py` |
| N+1 queries | `billing/signals.py:629-637`, `billing/signals.py:1290-1310` |
| Placeholder validators | `billing/invoice_models.py:28-37` |
| Email enumeration | `users/forms.py:362-366` |
