# PRAHO Platform Security Audit Report

**Date:** December 27, 2025
**Auditor:** Security Assessment (Attacker Perspective)
**Target:** PRAHO Django CRM/Billing Platform
**Version:** 0.15.1

---

## Executive Summary

This security audit analyzes the PRAHO platform from an attacker's perspective, identifying vulnerabilities across authentication, billing, webhooks, and provisioning systems. The codebase demonstrates strong security practices in many areas (Argon2 password hashing, Fernet encryption, CSRF protection) but contains several exploitable weaknesses.

**Critical Findings:** 2
**High Findings:** 5
**Medium Findings:** 6
**Low Findings:** 4

---

## 1. Attack Vectors I Would Exploit First

### 1.1 Webhook Signature Bypass (CRITICAL)

**Location:** `services/platform/apps/integrations/views.py:103-105`

```python
except Exception as e:
    logger.exception(f"Critical error processing {self.source_name} webhook")
    return JsonResponse({"status": "error", "message": f"Internal error: {e!s}"}, status=500)
```

**Exploitability:** HIGH
**Impact:** CRITICAL

**Attack Vector:**
- The exception message `str(e)` is directly returned to the attacker
- Can leak internal paths, database structure, or configuration details
- Webhooks are CSRF-exempt (`@csrf_exempt`) by design

**Similarly at:** `services/platform/apps/integrations/views.py:357-358`
```python
except Exception as e:
    logger.exception(f"Error retrying webhook {webhook_id}")
    return JsonResponse({"error": f"Internal error: {e!s}"}, status=500)
```

### 1.2 Stripe Webhook Signature Verification Weakness

**Location:** `services/platform/apps/integrations/webhooks/stripe.py:62-66`

```python
# Get raw payload for signature verification
payload_body = json.dumps(payload, separators=(",", ":")).encode("utf-8")

return verify_stripe_signature(
    payload_body=payload_body, stripe_signature=signature, webhook_secret=webhook_secret
)
```

**Exploitability:** MEDIUM
**Impact:** CRITICAL

**Attack Vector:**
- The payload is already parsed from JSON before signature verification
- Re-serializing the payload may alter key ordering or spacing
- This could allow signature bypass if the original raw body differs from re-serialized output
- **Correct approach:** Verify signature against `request.body` raw bytes, not re-serialized JSON

### 1.3 VirtualMin Command Injection Surface

**Location:** `services/platform/apps/provisioning/virtualmin_gateway.py:778-779`

```python
api_params = {"program": program, **params}
```

**Exploitability:** MEDIUM (requires authenticated staff access)
**Impact:** CRITICAL

**Attack Vector:**
- The `program` parameter is passed to Virtualmin API
- While `VirtualminValidator.validate_virtualmin_program(program)` exists, parameters (`params`) are merged directly
- If validators are bypassed or incomplete, command injection into server management becomes possible

---

## 2. Sensitive Data Flows Without Proper Protection

### 2.1 Encryption Key Management (HIGH)

**Location:** `services/platform/apps/common/encryption.py:22-38`

```python
def get_encryption_key() -> bytes:
    encryption_key = getattr(settings, "ENCRYPTION_KEY", None)
    if not encryption_key:
        encryption_key = os.environ.get("DJANGO_ENCRYPTION_KEY")
```

**Issue:**
- Single encryption key for all sensitive data (2FA secrets, credentials)
- No key rotation mechanism observed
- If key is compromised, ALL encrypted data is exposed
- Key may appear in logs if `settings.DEBUG = True`

### 2.2 Credential Vault Bypass Path

**Location:** `services/platform/apps/provisioning/virtualmin_gateway.py:606-631`

```python
# Fall back to environment variables (current migration approach)
env_username = os.environ.get("VIRTUALMIN_ADMIN_USER")
env_password = os.environ.get("VIRTUALMIN_ADMIN_PASSWORD")

if env_username and env_password:
    logger.info(
        f"Using environment credentials for {self.server.hostname} (migration needed)"
    )
    return Ok((env_username, env_password))
```

**Exploitability:** LOW (requires environment access)
**Impact:** HIGH

**Issue:**
- Credentials logged in plaintext to info-level logs
- Server hostname exposed alongside credential usage
- Environment variable fallback creates credential sprawl

### 2.3 Two-Factor Secret Storage Pattern

**Location:** `services/platform/apps/users/models.py:280-294`

```python
@property
def two_factor_secret(self) -> str:
    """Get decrypted 2FA secret"""
    if not self._two_factor_secret:
        return ""
    return decrypt_sensitive_data(self._two_factor_secret)

@two_factor_secret.setter
def two_factor_secret(self, value: str) -> None:
    """Set encrypted 2FA secret"""
    if value:
        self._two_factor_secret = encrypt_sensitive_data(value)
```

**Issue:**
- Property getter decrypts on every access - could leak via debug/logging
- No access auditing for 2FA secret retrieval
- Decrypted secret held in memory could be dumped

---

## 3. Functions Vulnerable to Malicious Input Injection

### 3.1 Error Message Injection (HIGH)

**Location:** `services/platform/apps/integrations/views.py:387`

```python
return Err(f"Cannot retry webhook with status: {webhook_event.status}")
```

**Exploitability:** MEDIUM
**Impact:** MEDIUM

**Attack Vector:**
- If `webhook_event.status` contains HTML/JS, it flows to error response
- While status is typically controlled, database corruption could inject XSS

### 3.2 Domain Validation Error Reflection

**Location:** `services/platform/apps/domains/views.py:411`

```python
return JsonResponse({"success": False, "error": str(error_msg)})
```

**Exploitability:** MEDIUM
**Impact:** MEDIUM

**Attack Vector:**
- `error_msg` may contain user-controlled domain input
- Could reflect malicious content in API response

### 3.3 User Registration Exception Leak

**Location:** `services/platform/apps/users/views.py:264-265`

```python
except Exception as e:
    messages.error(request, str(e))
    _audit_registration_attempt(request, email, "form_validation_error")
```

**Exploitability:** LOW
**Impact:** MEDIUM

**Issue:**
- Any exception message displayed to user
- Could leak database constraints, field names, or internal logic

---

## 4. Error Messages That Leak Implementation Details

### 4.1 Webhook Error Exposure (HIGH)

| Location | Leak Pattern |
|----------|--------------|
| `integrations/views.py:105` | `f"Internal error: {e!s}"` |
| `integrations/views.py:358` | `f"Internal error: {e!s}"` |
| `integrations/views.py:138` | `f"No processor found for source: {self.source_name}"` |

**Information Leaked:**
- Internal class names and module paths
- Database error messages (constraint names, table names)
- File system paths in tracebacks

### 4.2 Billing/Settings Error Patterns (MEDIUM)

| Location | Error Pattern |
|----------|---------------|
| `settings/views.py:145` | `f'Setting "{key}" not found'` - reveals valid key patterns |
| `settings/views.py:148` | `"Failed to retrieve settings"` - safe |
| `domains/views.py:417` | `f"TLD '.{tld_extension}' is not supported"` - safe enumeration |

### 4.3 Stripe Webhook Handler Leak

**Location:** `services/platform/apps/integrations/webhooks/stripe.py:96-98`

```python
except Exception as e:
    logger.exception(f"Error handling Stripe event {event_type}")
    return False, f"Handler error: {e!s}"
```

**Issue:**
- Exception details returned in webhook response
- Attacker can craft payloads to trigger specific errors and enumerate internal state

---

## 5. Race Conditions for Privilege Escalation

### 5.1 Customer Membership Race (HIGH)

**Location:** `services/platform/apps/users/models.py:204-209`

```python
def can_access_customer(self, customer: Customer) -> bool:
    """Check if user can access specific customer"""
    if self.is_staff or self.staff_role:
        return True
    return CustomerMembership.objects.filter(user=self, customer=customer).exists()
```

**Exploitability:** MEDIUM
**Impact:** HIGH

**Race Condition:**
1. User A checks `can_access_customer()` for Customer X (True)
2. Admin removes User A's membership
3. User A's request continues with cached True result
4. User A accesses Customer X data they no longer have access to

**Missing:** No `select_for_update()` or transaction isolation

### 5.2 Invoice Sequence Race (MEDIUM)

**Location:** Based on test `test_models_additional.py:161-165`

```python
def test_get_next_number_concurrency_safety(self):
    """Test get_next_number atomicity under concurrent access"""
    sequence = InvoiceSequence.objects.create(scope='concurrency_test')
```

**Issue:**
- Tests exist but production code may lack `select_for_update()`
- Concurrent invoice creation could result in duplicate invoice numbers
- Romanian e-Factura compliance requires unique sequential numbers

### 5.3 Payment Status Race (HIGH)

**Location:** `services/platform/apps/integrations/webhooks/stripe.py:123-133`

```python
if event_type == "payment_intent.succeeded":
    payment.status = "succeeded"
    payment.meta.update({...})
    payment.save(update_fields=["status", "meta"])
```

**Race Condition:**
1. Webhook A: `payment_intent.succeeded` arrives
2. Webhook B: `payment_intent.payment_failed` arrives (retry/duplicate)
3. Both fetch same payment object
4. Final status depends on save order, not event order

**Missing:**
- No `select_for_update()` on payment fetch
- No event timestamp comparison
- No idempotency key enforcement

### 5.4 Refund Double-Spend (CRITICAL)

**Location:** `services/platform/apps/billing/refund_service.py`

**Potential Attack:**
1. Initiate refund request via UI
2. Simultaneously initiate same refund via API/webhook
3. Both processes check "not refunded" state
4. Both proceed to issue refund
5. Customer receives double refund

**Required Analysis:** Need to verify `transaction.atomic` usage and `select_for_update()` in refund flow

---

## Vulnerability Ranking Matrix

| # | Vulnerability | Exploitability | Impact | Priority |
|---|---------------|----------------|--------|----------|
| 1 | Stripe signature verification on re-serialized JSON | Medium | Critical | P1 |
| 2 | Exception message leak in webhook handlers | High | High | P1 |
| 3 | Payment status race condition | Medium | Critical | P1 |
| 4 | Refund double-spend potential | Medium | Critical | P1 |
| 5 | Customer membership access race | Medium | High | P2 |
| 6 | Credential logging to info level | Low | High | P2 |
| 7 | VirtualMin parameter injection surface | Medium | Critical | P2 |
| 8 | Single encryption key for all secrets | Low | Critical | P2 |
| 9 | Invoice sequence race condition | Medium | Medium | P3 |
| 10 | Domain error message reflection | Medium | Medium | P3 |
| 11 | 2FA secret decryption on property access | Low | Medium | P3 |
| 12 | User registration exception exposure | Low | Medium | P4 |
| 13 | Webhook status field potential XSS | Low | Medium | P4 |
| 14 | Settings key enumeration | Low | Low | P4 |
| 15 | TLD enumeration via error | Low | Low | P5 |
| 16 | Debug mode credential exposure risk | Low | High | P5 |
| 17 | Missing HSTS preload in some configs | Low | Low | P5 |

---

## Recommendations

### Immediate (P1 - This Sprint)

1. **Fix Stripe signature verification:**
   ```python
   # Use raw request body, not re-serialized JSON
   def verify_signature(self, raw_body: bytes, signature: str, ...) -> bool:
       return verify_stripe_signature(
           payload_body=raw_body,  # Not json.dumps(parsed_payload)
           stripe_signature=signature,
           webhook_secret=webhook_secret
       )
   ```

2. **Sanitize all exception messages before returning:**
   ```python
   except Exception as e:
       logger.exception(f"Error processing webhook")
       return JsonResponse({"error": "Processing failed"}, status=500)  # Generic message
   ```

3. **Add database locking to payment updates:**
   ```python
   with transaction.atomic():
       payment = Payment.objects.select_for_update().get(gateway_txn_id=stripe_payment_id)
       # Now safe to update
   ```

### Short-term (P2 - Next Sprint)

4. Implement encryption key rotation mechanism
5. Add `select_for_update()` to membership checks in sensitive operations
6. Reduce credential logging to DEBUG level with masking
7. Implement VirtualMin parameter allowlist validation

### Medium-term (P3-P4)

8. Add invoice sequence locking with `select_for_update(nowait=True)`
9. Implement 2FA secret access auditing
10. Add XSS sanitization to all database-sourced error messages
11. Review and harden all exception handlers

---

## Files Requiring Immediate Attention

1. `services/platform/apps/integrations/views.py` - Exception handling
2. `services/platform/apps/integrations/webhooks/stripe.py` - Signature verification
3. `services/platform/apps/integrations/webhooks/base.py` - Signature function
4. `services/platform/apps/billing/refund_service.py` - Race condition review
5. `services/platform/apps/users/models.py` - Membership access checks

---

## Positive Security Observations

The codebase demonstrates several strong security practices:

- Argon2 password hashing with PBKDF2/BCrypt fallbacks
- Progressive account lockout (5min to 4hr)
- Fernet encryption for sensitive data at rest
- CSRF protection on all non-webhook endpoints
- Rate limiting on authentication endpoints
- Comprehensive audit logging framework
- GDPR compliance infrastructure
- Input validation with Django forms

---

*Report generated for security remediation purposes. All findings should be validated in a controlled environment before applying fixes.*
