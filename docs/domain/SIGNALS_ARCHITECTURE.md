# Django Signals Architecture - PRAHO Platform

## Overview

The PRAHO platform uses Django signals for event-driven architecture, enabling decoupled communication between apps and automatic business logic execution. This document outlines the signal system implemented across the orders and billing apps.

## Signal Categories

### 1. Core Lifecycle Signals
**Location**: `apps/orders/signals.py`, `apps/billing/signals.py`

**Purpose**: Handle entity lifecycle events (create, update, delete) and cross-app communication.

**Key Signals**:
- Order creation/updates → Audit logging, email notifications
- Invoice status changes → Payment tracking, e-Factura submission
- Payment processing → Invoice status updates, service activation
- Status transitions → Cross-app notifications, compliance logging

> **Note**: `apps/orders/signals_extended.py` no longer exists. All active cross-app receivers (billing signal subscriptions, order/item cleanup) live in `apps/orders/signals.py`. Receivers for non-existent services were removed rather than stubbed.

## Detailed Signal Implementation

### Orders App Signals (`apps/orders/signals.py`)

```python
# Order lifecycle management
@receiver(post_save, sender=Order)
def handle_order_created_or_updated()
    # → Audit logging
    # → Status change handling
    # → Email notifications

# Order status transitions
def _handle_order_status_change()
    # awaiting_payment → Proforma creation
    # paid            → OrderPaymentConfirmationService.confirm_order()
    # provisioning    → Service provisioning queue
    # cancelled       → _handle_order_cancellation()
    # completed       → Completion logging

# Order cancellation — differentiates by service state
def _handle_order_cancellation()
    # pending services     → hard-delete (never provisioned)
    # provisioning services → fail_provisioning() then delete
    # active services      → suspend(reason=...) — do NOT delete real infrastructure
    # terminal states      → clear FK only

# Cross-app billing signal subscription
def _handle_proforma_payment_received()
    # Received via apps.billing.custom_signals.proforma_payment_received
    # → OrderPaymentConfirmationService.confirm_order()

def _handle_invoice_refunded()
    # Received via apps.billing.custom_signals.invoice_refunded
    # Full refund   → suspend active services
    # Partial refund → log for manual review

# Data maintenance (post_delete)
@receiver(post_delete, sender=Order)
def handle_order_cleanup()
    # → Cache invalidation
    # → File cleanup
    # → Webhook cancellation

@receiver(post_delete, sender=OrderItem)
def handle_order_item_service_cleanup()
    # → Mark orphaned service for review via ServiceManagementService
```

### Billing App Signals (`apps/billing/signals.py`)

```python
# Invoice lifecycle
@receiver(post_save, sender=Invoice)
def handle_invoice_created_or_updated()
    # → Sequential numbering (Romanian compliance)
    # → e-Factura submission
    # → Payment reminder scheduling
    # → Status change notifications

# Payment processing
@receiver(post_save, sender=Payment)
def handle_payment_created_or_updated()
    # → Invoice status updates
    # → Customer notifications
    # → Retry scheduling

# Romanian compliance
@receiver(post_save, sender=TaxRule)
def handle_tax_rule_changes()
    # → Cache invalidation
    # → Compliance logging
    # → VAT validation updates
```

### Custom Billing Signals (`apps/billing/custom_signals.py`)

These signals enable unidirectional coupling — Billing EMITS, other apps LISTEN. Billing never imports from Orders or Provisioning.

| Signal | Emitted when | Receivers |
|--------|-------------|-----------|
| `proforma_payment_received` | Proforma paid + converted to invoice | Orders (`_handle_proforma_payment_received`) |
| `invoice_refunded` | Invoice refund completed (full or partial) | Orders (`_handle_invoice_refunded`) |
| `invoice_refund_completed` | Refund fully settled by gateway | **Not yet implemented** — planned for post-refund service hard-delete after refund window expires |

Signal connections are registered in `orders/signals.py::_connect_billing_signals()`, called from `OrdersConfig.ready()`.

## App Configuration

```python
# apps/orders/apps.py
class OrdersConfig(AppConfig):
    def ready(self) -> None:
        from . import signals  # noqa: PLC0415
        # signals.py registers both Django model signals and
        # cross-app billing signal subscriptions via _connect_billing_signals()
```

`signals_extended.py` was removed in the `feat/order-proforma-lifecycle` branch. All active logic was either merged into `signals.py` or deleted (receivers that called non-existent services: `DomainRegistrationService`, `CustomerStatsService`, `ServiceGroupService`, `TicketService`, `ExternalSyncService`).

## Cross-App Integration Points

### 1. Orders ↔ Billing (via custom signals — unidirectional)
- **Proforma payment received** → Order confirmation + provisioning start
- **Invoice refunded** → Service suspension (full) or manual review flag (partial)

### 2. Orders ↔ Provisioning (via direct service calls)
- **Order in `provisioning` state** → Service provisioning queue
- **Order cancellation** → Service FSM transitions (suspend/fail) based on service state

### 3. Billing — Romanian Compliance
- **Invoice issued** → Automatic e-Factura submission
- **Sequential numbering** → Romanian law requirement (generated on `issued` transition)

## Signal Best Practices

### Error Isolation
- Each signal handler has try/except blocks
- Failures are logged but do not break the originating transaction
- Signal emission deferred to `transaction.on_commit()` to prevent ghost side-effects on rollback

### Idempotency
- State checking before actions (e.g., skip if service already suspended)
- `dispatch_uid` on all `connect()` calls to prevent duplicate registration

### Lock Ordering (F4)
- Services that handle both Proforma and Payment: always lock Proforma first, then Payment
- Prevents deadlocks on concurrent payment attempts

## Romanian Business Compliance

### e-Factura Integration
```python
# Automatic e-Factura submission
@receiver(post_save, sender=Invoice)
def handle_invoice_issued():
    if _requires_efactura_submission(invoice):
        _trigger_efactura_submission(invoice)
```

### Sequential Invoice Numbering
```python
# Romanian law compliance — number generated only when invoice transitions to 'issued'
@receiver(post_save, sender=Invoice)
def handle_invoice_number_generation():
    if instance.status == 'issued' and instance.number.startswith('TMP-'):
        # Generate sequential number
```

## Monitoring and Debugging

### Logging Strategy
- Structured logging with emoji tags: `✅ [Signal] ...`, `⚠️ [Signal] ...`, `🔥 [Signal] ...`
- Security-relevant events use `log_security_event()`

### Error Tracking
```python
logger.exception("🔥 [Order Signal] Failed to handle: %s", e)
log_security_event("critical_failure", details)
```

## Testing

- Unit tests for individual signal handlers in `tests/orders/test_orders_signals.py`
- Integration tests for cross-app flows (proforma payment → order confirm) in `tests/orders/test_orders_services.py`
- Use `disconnect()` / `@override_settings` to isolate signals in unit tests
- `dispatch_uid` makes signal connections idempotent across test runs
