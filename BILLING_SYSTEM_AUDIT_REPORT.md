# PRAHO Billing & Payment System Audit Report

**Audit Date:** 2025-12-27
**Auditor:** Claude Code
**Branches Scanned:** master, claude/usage-based-billing-GD3fy, claude/promotions-coupons-system-RK7WI, feat/services-architecture

---

## Executive Summary

The PRAHO billing system is **well-architected** with comprehensive coverage for most billing requirements. The system demonstrates production-ready patterns for Romanian regulatory compliance (e-Factura, VAT/VIES). However, several areas need attention before going live.

| Category | Status | Best Practice Score |
|----------|--------|---------------------|
| Invoice Generation | ✅ Implemented | 8/10 |
| Recurring Payments | ⚠️ Partial | 6/10 |
| Refunds & Credits | ✅ Implemented | 9/10 |
| Payment Gateway | ✅ Implemented | 8/10 |
| Pricing Changes | ❌ Missing | 2/10 |

---

## 1. Invoice Generation

### ✅ PRESENT - Tax Calculations

**Location:** `services/platform/apps/billing/tax_models.py`

| Feature | Status | Notes |
|---------|--------|-------|
| EU VAT rates by country | ✅ | `TaxRule` model with temporal validity |
| Reduced rate support | ✅ | `reduced_rate` field for specific categories |
| B2B vs B2C handling | ✅ | `applies_to_b2b`, `applies_to_b2c` flags |
| Reverse charge mechanism | ✅ | `reverse_charge_eligible` for EU B2B |
| VIES validation | ✅ | `VATValidation` model with caching |
| Date-based rate lookup | ✅ | `valid_from`, `valid_to` with `get_active_rate()` |

**Best Practice:** Tax rate decimal stored with 4 decimal places (0.0000) - supports complex rates.

### ✅ PRESENT - Romanian Regulatory Compliance

**Location:** `services/platform/apps/billing/invoice_models.py:157-165`

| Feature | Status | Notes |
|---------|--------|-------|
| e-Factura integration | ✅ | Fields: `efactura_id`, `efactura_sent`, `efactura_response` |
| Sequential numbering | ✅ | `InvoiceSequence` with atomic F() operations |
| Immutable ledger | ✅ | `locked_at` field with validation |
| Address snapshots | ✅ | `bill_to_*` fields frozen at invoice time |
| Void vs Delete | ✅ | Signal prevents deletion of issued invoices |

**Code Evidence (invoice_models.py:63-89):**
```python
def get_next_number(self, prefix: str = "INV", user_email: str | None = None) -> str:
    with transaction.atomic():
        # Atomic increment using F() expression to prevent race conditions
        InvoiceSequence.objects.filter(pk=self.pk).update(last_value=F("last_value") + 1)
        self.refresh_from_db()
        # Comprehensive security logging for audit trail
        log_security_event(event_type="invoice_number_generated", ...)
```

### ⚠️ GAPS

| Issue | Severity | Recommendation |
|-------|----------|----------------|
| PDF generation is TODO stub | Medium | Implement using WeasyPrint or ReportLab |
| e-Factura submission is TODO stub | High | Integrate with ANAF SPV API |
| XML generation is TODO stub | High | Required for e-Factura UBL 2.1 format |

---

## 2. Recurring Payments

### ⚠️ PARTIAL - Automated Subscription Handling

**Location:** `services/platform/apps/billing/payment_models.py:144-214`

| Feature | Status | Notes |
|---------|--------|-------|
| Subscription model | ❌ Missing | No `Subscription` or `RecurringBillingPlan` model |
| Billing cycle tracking | ❌ Missing | No `billing_period`, `next_billing_date` fields |
| Payment retry policy | ✅ | `PaymentRetryPolicy` model with configurable intervals |
| Dunning schedules | ✅ | `retry_intervals_days` JSON field [1, 3, 7, 14, 30] |
| Service suspension rules | ✅ | `suspend_service_after_days`, `terminate_service_after_days` |
| Dunning emails | ✅ | `send_dunning_emails`, `email_template_prefix` |

### ✅ PRESENT - Failed Payment Retry Logic

**Location:** `services/platform/apps/billing/payment_models.py:216-282`

| Feature | Status | Notes |
|---------|--------|-------|
| `PaymentRetryAttempt` model | ✅ | Tracks individual retry attempts |
| Status tracking | ✅ | pending, processing, success, failed, skipped, cancelled |
| Gateway response logging | ✅ | `gateway_response` JSON field |
| Email tracking | ✅ | `dunning_email_sent`, `dunning_email_sent_at` |
| Collection runs | ✅ | `PaymentCollectionRun` for batch processing |

**Code Evidence (payment_models.py:207-213):**
```python
def get_next_retry_date(self, failure_date: datetime, attempt_number: int) -> datetime | None:
    if attempt_number >= len(self.retry_intervals_days):
        return None
    days_to_wait = self.retry_intervals_days[attempt_number]
    return failure_date + timedelta(days=days_to_wait)
```

### 🔴 CRITICAL GAPS

| Issue | Severity | Recommendation |
|-------|----------|----------------|
| No Subscription model | Critical | Create `Subscription` model with billing cycle, next_renewal_date |
| No recurring charge scheduler | Critical | Implement Django-Q2 scheduled task for daily billing runs |
| No proration logic | High | Implement mid-cycle upgrades/downgrades with prorated amounts |
| Auto-payment processing is TODO | High | Implement `process_auto_payment()` in tasks.py |

### ✅ Usage-Based Billing (Branch: claude/usage-based-billing-GD3fy)

| Feature | Status | Notes |
|---------|--------|-------|
| `UsageMeter` model | ✅ | Comprehensive metering definitions |
| Aggregation types | ✅ | sum, count, max, last, unique |
| Stripe Meter integration | ✅ | `stripe_meter_id`, `stripe_meter_event_name` |
| Rounding modes | ✅ | up, down, nearest, none |
| Hosting-specific meters | ✅ | storage, bandwidth, compute, email categories |

---

## 3. Refunds & Credits

### ✅ EXCELLENT - Proper Accounting and Audit Trails

**Location:** `services/platform/apps/billing/refund_models.py`, `refund_service.py`

| Feature | Status | Notes |
|---------|--------|-------|
| Refund model | ✅ | Comprehensive with full/partial types |
| Multiple reasons | ✅ | customer_request, error_correction, dispute, fraud, etc. |
| Status workflow | ✅ | pending → processing → approved → completed |
| Status history | ✅ | `RefundStatusHistory` with full audit trail |
| Refund notes | ✅ | `RefundNote` model for internal/customer/gateway notes |
| Unique reference numbers | ✅ | Auto-generated `REF-YYYYMMDD-XXXXXXXX` format |

### ✅ Bidirectional Synchronization

**Location:** `services/platform/apps/billing/refund_service.py:683-836`

| Feature | Status | Notes |
|---------|--------|-------|
| Order ↔ Invoice sync | ✅ | `_process_bidirectional_refund()` updates both entities |
| Payment status updates | ✅ | `refunded`, `partially_refunded` states |
| Atomic transactions | ✅ | All refund operations wrapped in `transaction.atomic()` |
| Eligibility checks | ✅ | Validates refundable status before processing |
| Max refund validation | ✅ | Prevents over-refunding with `max_refund_amount_cents` |

### ✅ Credit Ledger

**Location:** `services/platform/apps/billing/payment_models.py:105-137`

```python
class CreditLedger(models.Model):
    """Customer credit/balance tracking ledger."""
    customer = models.ForeignKey("customers.Customer", ...)
    delta_cents = models.BigIntegerField()  # +ve = credit added, -ve = used
    reason = models.CharField(max_length=255)
    created_by = models.ForeignKey("users.User", ...)
```

### ✅ Security Logging

All refund operations log to security audit:
```python
log_security_event(
    event_type="refund_processed",
    details={
        "refund_id": str(refund_id),
        "entity_type": "order",
        "critical_financial_operation": True,
    },
)
```

---

## 4. Payment Gateway Integration

### ✅ PRESENT - Error Handling

**Location:** `services/platform/apps/integrations/webhooks/stripe.py`

| Feature | Status | Notes |
|---------|--------|-------|
| Event handler registry | ✅ | Maps event prefixes to handler methods |
| Failure reason capture | ✅ | Stores `stripe_failure_reason` in payment meta |
| Graceful unknown events | ✅ | Logs and skips unknown event types |
| Exception handling | ✅ | Catches all exceptions, returns proper status |

### ✅ PRESENT - Webhook Verification

**Location:** `services/platform/apps/integrations/webhooks/base.py:308-356`

| Feature | Status | Notes |
|---------|--------|-------|
| HMAC signature verification | ✅ | Stripe's t=timestamp,v1=signature format |
| Timestamp validation | ✅ | 5-minute tolerance for replay attack prevention |
| Timing-safe comparison | ✅ | Uses `hmac.compare_digest()` |
| Fail-secure mode | ✅ | Returns False if secret not configured |

**Code Evidence (base.py:286-306):**
```python
def verify_hmac_signature(payload_body: bytes, signature: str, secret: str, algorithm: str = "sha256") -> bool:
    if not signature or not secret:
        return False
    mac = hmac.new(secret.encode("utf-8"), payload_body, getattr(hashlib, algorithm))
    expected_signature = mac.hexdigest()
    return hmac.compare_digest(signature, expected_signature)  # Timing-safe
```

### ✅ PRESENT - Idempotency / Deduplication

**Location:** `services/platform/apps/integrations/webhooks/base.py:164-175`

| Feature | Status | Notes |
|---------|--------|-------|
| Event ID extraction | ✅ | `extract_event_id()` abstract method |
| Duplicate detection | ✅ | `WebhookEvent.is_duplicate(source, event_id)` |
| Atomic event creation | ✅ | Creates `WebhookEvent` in transaction |
| Retry mechanism | ✅ | Exponential backoff: 5m, 15m, 1h, 2h, 6h |

**Code Evidence (base.py:164-175):**
```python
def _check_duplicates(self, event_info: dict[str, str]) -> Result[dict[str, str], str]:
    event_id = event_info["event_id"]
    if WebhookEvent.is_duplicate(self.source_name, event_id):
        logger.info(f"🔄 Duplicate webhook {self.source_name}:{event_id} - skipping")
        return Err(f"DUPLICATE:{event_id}")
    return Ok(event_info)
```

### ⚠️ GAPS

| Issue | Severity | Recommendation |
|-------|----------|----------------|
| PayPal processor TODO | Medium | Implement PayPal webhook handler |
| Virtualmin processor TODO | Low | Implement if needed for server events |
| No payment idempotency key | Medium | Add `idempotency_key` to Payment model for create operations |

---

## 5. Pricing Changes

### 🔴 CRITICAL - Migration Logic for Existing Customers

**Status: NOT IMPLEMENTED**

| Feature | Status | Notes |
|---------|--------|-------|
| Price change detection | ❌ Missing | No signal/hook when product prices change |
| Customer notification | ❌ Missing | No email templates for price changes |
| Effective date tracking | ❌ Missing | No `price_effective_from` field |
| Migration batch jobs | ❌ Missing | No task for updating existing subscriptions |

### 🔴 CRITICAL - Grandfathering Policies

**Status: NOT IMPLEMENTED**

| Feature | Status | Notes |
|---------|--------|-------|
| Grandfathering model | ❌ Missing | No `PriceGrandfathering` or `LegacyPricing` model |
| Customer-specific pricing | ❌ Missing | No override mechanism for locked prices |
| Expiration rules | ❌ Missing | No logic for when grandfather pricing ends |
| Audit trail | ❌ Missing | No logging of grandfather assignments |

### ✅ Promotions System (Branch: claude/promotions-coupons-system-RK7WI)

The promotions branch has:
- `PromotionCampaign` model with date ranges
- `Coupon` model with usage limits
- Discount types (percentage, fixed, BOGO)
- Customer segmentation

**But this is NOT grandfathering** - it's promotional discounts, not legacy pricing protection.

---

## Recommendations

### Priority 1 - Critical (Before Production)

1. **Implement Subscription Model**
   ```python
   class Subscription(models.Model):
       customer = models.ForeignKey("customers.Customer", ...)
       product = models.ForeignKey("products.Product", ...)
       status = models.CharField(choices=[("active", "trialing", "past_due", "cancelled")])
       billing_cycle = models.CharField(choices=[("monthly", "yearly", "custom")])
       current_period_start = models.DateTimeField()
       current_period_end = models.DateTimeField()
       next_billing_date = models.DateTimeField()
       locked_price_cents = models.BigIntegerField(null=True)  # Grandfathered price
   ```

2. **Implement e-Factura Integration**
   - Generate UBL 2.1 XML format
   - Submit to ANAF SPV API
   - Handle validation responses
   - Store e-Factura IDs

3. **Add Recurring Billing Scheduler**
   ```python
   # In billing/tasks.py
   @register_task("billing.run_daily_billing")
   def run_daily_billing():
       today = timezone.now().date()
       subscriptions = Subscription.objects.filter(
           next_billing_date__lte=today,
           status="active"
       )
       for sub in subscriptions:
           process_subscription_renewal(sub)
   ```

4. **Add Price Grandfathering**
   ```python
   class PriceGrandfathering(models.Model):
       customer = models.ForeignKey("customers.Customer", ...)
       product = models.ForeignKey("products.Product", ...)
       locked_price_cents = models.BigIntegerField()
       locked_at = models.DateTimeField(auto_now_add=True)
       expires_at = models.DateTimeField(null=True)
       reason = models.CharField(max_length=200)
   ```

### Priority 2 - High (First Month)

5. **Add Payment Idempotency Keys**
   ```python
   class Payment(models.Model):
       idempotency_key = models.CharField(max_length=64, unique=True, null=True)
   ```

6. **Implement PDF Generation**
   - Use WeasyPrint for proper PDF rendering
   - Include Romanian fiscal requirements (CUI, reg. com., IBAN)

7. **Add Proration Service**
   ```python
   class ProrationService:
       @staticmethod
       def calculate_proration(old_price_cents, new_price_cents, days_remaining, days_total):
           unused_credit = (old_price_cents * days_remaining) / days_total
           new_charge = (new_price_cents * days_remaining) / days_total
           return new_charge - unused_credit
   ```

### Priority 3 - Medium (First Quarter)

8. **Add Price Change Notification System**
9. **Implement PayPal Webhook Handler**
10. **Add Usage Alerts** (from usage-based-billing branch)
11. **Merge Promotions System** (from promotions branch)

---

## Security Assessment

### ✅ Strengths

| Area | Implementation |
|------|----------------|
| Input validation | `validators.py` with pattern matching, size limits |
| Financial amount bounds | ±100M cents limit prevents overflow |
| JSON security | Depth limit, pattern scanning, sensitive key detection |
| Webhook signatures | HMAC with timing-safe comparison |
| Audit logging | Comprehensive `log_security_event()` throughout |
| Race conditions | Atomic F() operations for sequence numbers |
| SQL injection | Django ORM throughout, no raw SQL |

### ⚠️ Areas for Review

| Area | Concern | Recommendation |
|------|---------|----------------|
| Stripe secret in settings | Ensure not in version control | Use environment variables |
| Payment meta field | Could store PII | Review what's logged |
| Webhook replay | 5-minute tolerance might be too long | Consider 2-3 minutes |

---

## File Index

| Component | Primary Files |
|-----------|---------------|
| Invoice Generation | `invoice_models.py`, `invoice_service.py` |
| Tax System | `tax_models.py` |
| Payments | `payment_models.py`, `signals.py` |
| Refunds | `refund_models.py`, `refund_service.py` |
| Webhooks | `integrations/webhooks/base.py`, `stripe.py` |
| Tasks | `tasks.py` |
| Validators | `validators.py` |
| Usage Metering | Branch: `metering_models.py`, `metering_service.py` |
| Promotions | Branch: `promotions/models.py` |

---

## Conclusion

The PRAHO billing system has a **solid foundation** with excellent implementations for:
- Romanian regulatory compliance (e-Factura fields, VAT/VIES)
- Refund management with full audit trails
- Payment gateway webhook processing with idempotency
- Failed payment retry with configurable dunning

**Critical gaps** that must be addressed:
1. **Subscription/recurring billing model** - fundamental for a hosting business
2. **e-Factura actual integration** - required for Romanian compliance
3. **Price grandfathering** - essential for customer retention during price changes

The usage-based billing and promotions branches contain valuable features that should be merged after stabilizing the core subscription billing.

---

*Report generated by Claude Code audit system*
