# Customers TODO Flush — Implementation Design

**Date:** 2026-03-07
**Branch:** `feat/customers-todo-flush`
**Target:** Implement all 6 customer TODOs, 70%+ test coverage, integration tests

## TODOs to Implement

### TODO 1: Feedback Analysis (`tasks.py:73`)
**Current:** Logs note content, does nothing.
**Implementation:** Keyword-based category tagging + simple sentiment.

- Extract keywords from `CustomerNote.content` using a predefined keyword→category map
- Categories: `billing`, `technical`, `praise`, `complaint`, `feature_request`, `general`
- Sentiment: count positive/negative indicator words → tag as `positive`, `negative`, `neutral`
- Store results in `note.meta` JSON field (if exists) or as audit metadata
- No external dependencies (no ML, no textblob)

```python
FEEDBACK_CATEGORIES = {
    "billing": ["invoice", "payment", "charge", "refund", "price", "factura", "plata"],
    "technical": ["server", "down", "error", "slow", "dns", "ssl", "email", "hosting"],
    "praise": ["great", "excellent", "thank", "awesome", "happy", "multumesc", "excelent"],
    "complaint": ["bad", "terrible", "worst", "angry", "disappointed", "nemultumit"],
    "feature_request": ["wish", "would be nice", "suggest", "feature", "add", "implement"],
}
```

**DRY:** Reuses existing `AuditService.log_simple_event()` pattern already in the function.

### TODO 2 & 3: Onboarding Steps (`tasks.py:124, 154`)
**Current:** Lists steps, logs them, doesn't execute.
**Implementation:** Schedule each step as a Django-Q2 async task with delays.

Steps (executed sequentially via chained tasks):
1. `welcome_email` — immediate: call `send_customer_welcome_email()` (TODO 5)
2. `verify_contact_details` — immediate: check customer has phone + address, log gaps
3. `setup_billing_profile` — immediate: check tax profile + billing profile exist, log gaps
4. `complete_tax_information` — immediate: check CUI/VAT populated for business customers

Each step updates `customer.meta["onboarding"]` with step status:
```python
{"onboarding": {"welcome_email": "completed", "verify_contact": "incomplete", ...}}
```

**DRY:** Delegates email to `send_customer_welcome_email()`. Uses existing `customer.get_tax_profile()`, `customer.get_billing_profile()` model methods.

### TODO 4: Inactive Customer Processing (`tasks.py:280`)
**Current:** Identifies inactive customers, logs them, does nothing.
**Implementation:** Send reactivation check-in email. NO status change.

Criteria for "truly inactive" (all must be true):
- No login in 12+ months
- No active services (`Service.objects.filter(customer=c, status="active").count() == 0`)
- No orders in 12 months
- No open tickets

Actions:
1. Query for qualifying customers (already done in existing code)
2. Add active-services and open-tickets filters
3. Send `customer_reactivation` email via `EmailService.send_template_email()`
4. Log outreach in audit trail
5. Track in `customer.meta["last_reactivation_email"]` to avoid spam (max 1 per 90 days)

**DRY:** Reuses `EmailService.send_template_email()` from notifications app.
**New template needed:** `customer_reactivation` (RO + EN) in `setup_email_templates.py`.

### TODO 5: Welcome Email (`tasks.py:330`)
**Current:** Logs "would send", does nothing.
**Implementation:** Direct delegation to EmailService.

```python
from apps.notifications.services import EmailService
result = EmailService.send_template_email(
    template_key="customer_welcome",
    recipient=customer.email,
    context={"customer_name": customer.get_display_name(), ...},
    locale=_get_customer_locale(customer),
    customer=customer,
    async_send=False,  # Already in async task
)
```

**DRY:** Template `customer_welcome` already exists in both RO and EN.
**Helper:** Extract `_get_customer_locale(customer)` as shared utility (checks membership user's preferred_language).

### TODO 6: Customer Services API (`customer_views.py:709`)
**Current:** Returns empty `[]`.
**Implementation:** Query Service model directly (same pattern as API version).

```python
services = Service.objects.filter(
    customer_id=customer_id
).values("id", "service_name", "status", "service_plan__name")
return JsonResponse(list(services), safe=False)
```

**DRY:** Mirrors the proven query in `apps/api/services/views.py:72` but simplified for the internal dropdown use case (ticket form). No pagination needed — it's a dropdown.

## Portal Impact Assessment

**No portal changes needed.** All 6 TODOs are Platform-only:
- Portal doesn't import from `apps.customers.tasks`
- Portal doesn't call `customer_services_api` from `customer_views.py` (it uses the API version)
- Email sending is Platform-side via notifications app
- Portal is stateless — customer status/meta changes are transparent

## Shared Utilities to Extract

### `_get_customer_locale(customer) -> str`
Returns `"ro"` or `"en"` based on customer's primary user preferred_language.
Location: `apps/customers/tasks.py` (private, used by multiple task functions).

### No new service classes needed
All logic fits within existing task functions. Creating a `CustomerLifecycleService` would be premature abstraction — YAGNI.

## New Email Template

Add `customer_reactivation` template (RO + EN) to `setup_email_templates.py`:
- Subject: "We miss you! Is everything OK with your account?"
- Body: Check-in message, link to login, support contact
- Romanian version with appropriate tone

## Test Plan (70%+ coverage target)

### Unit Tests (`tests/customers/test_customers_tasks.py`) — NEW
- `test_feedback_analysis_categorizes_billing_keywords`
- `test_feedback_analysis_categorizes_technical_keywords`
- `test_feedback_analysis_neutral_sentiment`
- `test_feedback_analysis_negative_sentiment`
- `test_feedback_analysis_nonexistent_note`
- `test_onboarding_schedules_all_steps`
- `test_onboarding_marks_steps_completed`
- `test_onboarding_detects_missing_billing_profile`
- `test_onboarding_detects_missing_tax_info_business`
- `test_onboarding_skips_tax_check_individual`
- `test_onboarding_nonexistent_customer`
- `test_inactive_cleanup_skips_customers_with_active_services`
- `test_inactive_cleanup_skips_customers_with_open_tickets`
- `test_inactive_cleanup_sends_reactivation_email`
- `test_inactive_cleanup_respects_90_day_cooldown`
- `test_inactive_cleanup_lock_prevents_concurrent_runs`
- `test_welcome_email_sends_via_email_service`
- `test_welcome_email_uses_customer_locale`
- `test_welcome_email_nonexistent_customer`
- `test_get_customer_locale_returns_ro`
- `test_get_customer_locale_defaults_en`

### Unit Tests (`tests/customers/test_customers_services_api.py`) — EXTEND
- `test_services_api_returns_customer_services`
- `test_services_api_returns_empty_for_no_services`
- `test_services_api_rate_limited`
- `test_services_api_denies_access_to_other_customer`

### Integration Tests (`tests/customers/test_customers_integration.py`) — NEW
- `test_onboarding_full_flow_creates_meta_entries`
- `test_inactive_cleanup_end_to_end_with_email_mock`
- `test_feedback_analysis_with_real_note_object`
- `test_services_api_with_provisioned_services`

**Estimated: ~25 new tests + 4 extended = ~29 tests**
Combined with existing 134 tests = 163 total, well above 70% target.

## Files Modified

| File | Change |
|------|--------|
| `apps/customers/tasks.py` | Implement TODOs 1-5 |
| `apps/customers/customer_views.py` | Implement TODO 6 |
| `apps/notifications/management/commands/setup_email_templates.py` | Add reactivation template |
| `tests/customers/test_customers_tasks.py` | NEW — 21 tests |
| `tests/customers/test_customers_services_api.py` | EXTEND — 4 tests |
| `tests/customers/test_customers_integration.py` | NEW — 4 integration tests |
