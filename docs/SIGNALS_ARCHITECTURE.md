# Django Signals Architecture - PRAHO Platform

## Overview

The PRAHO platform uses Django signals for event-driven architecture, enabling decoupled communication between apps and automatic business logic execution. This document outlines the comprehensive signal system implemented across orders and billing apps.

## Signal Categories

### 1. Core Lifecycle Signals (existing)
**Location**: `apps/orders/signals.py`, `apps/billing/signals.py`

**Purpose**: Handle basic entity lifecycle events (create, update, delete)

**Key Signals**:
- Order creation/updates → Audit logging, email notifications
- Invoice status changes → Payment tracking, e-Factura submission  
- Payment processing → Invoice status updates, service activation
- Status transitions → Cross-app notifications, compliance logging

### 2. Extended Integration Signals (new)
**Location**: `apps/orders/signals_extended.py`, `apps/billing/signals_extended.py`

**Purpose**: Advanced cross-app integration and business logic

**Key Features**:
- Cross-app data synchronization
- Automated service provisioning
- Data cleanup and maintenance
- External system integration
- Business analytics updates

## Detailed Signal Implementation

### Orders App Signals

#### Core Signals (`signals.py`)
```python
# Order lifecycle management
@receiver(post_save, sender=Order)
def handle_order_created_or_updated()
    # → Audit logging
    # → Status change handling
    # → Email notifications

# Order status transitions
def _handle_order_status_change()
    # processing → Invoice generation
    # completed → Service provisioning  
    # cancelled → Cleanup operations
    # refunded → Service management
```

#### Extended Signals (`signals_extended.py`)
```python
# Cross-app integrations
@receiver(post_save, sender=Order)
def handle_order_domain_provisioning()
    # → Domain registration for domain products
    # → Bridges orders → domains app

@receiver(post_save, sender=Order)  
def handle_customer_credit_limit_update()
    # → Customer credit score updates
    # → Bridges orders → customers app

@receiver(post_save, sender=OrderItem)
def handle_service_group_management()
    # → Service bundle/group creation
    # → Bridges orders → provisioning app

# Automated support
@receiver(post_save, sender=OrderItem)
def handle_failed_provisioning_ticket_creation()
    # → Auto-create tickets for failures
    # → Bridges orders → tickets app

# Data maintenance
@receiver(post_delete, sender=Order)
def handle_order_cleanup()
    # → Cache invalidation
    # → File cleanup
    # → Webhook cancellation
```

### Billing App Signals

#### Core Signals (`signals.py`)
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
    # → Credit updates

# Romanian compliance
@receiver(post_save, sender=TaxRule)
def handle_tax_rule_changes()
    # → Cache invalidation
    # → Compliance logging
    # → VAT validation updates
```

#### Extended Signals (`signals_extended.py`)
```python
# Invoice-Order synchronization
@receiver(post_save, sender=Invoice)
def handle_invoice_order_synchronization()
    # → Order status updates when invoice changes
    # → Cross-app state management

@receiver(m2m_changed, sender=Invoice.orders.through)  
def handle_invoice_order_linking()
    # → Many-to-many relationship management
    # → Bidirectional synchronization

# Service activation
@receiver(post_save, sender=Payment)
def handle_payment_service_activation()
    # → Auto-activate services on payment
    # → Bridges billing → provisioning

# Proforma conversion
@receiver(post_save, sender=ProformaInvoice)
def handle_proforma_invoice_conversion()
    # → Auto-convert proformas to invoices
    # → Romanian business compliance

# Analytics and reporting
@receiver(post_save, sender=Invoice)
def handle_billing_analytics_update()
    # → Real-time dashboard updates
    # → KPI calculation
    # → Cache management
```

## Cross-App Integration Points

### 1. Orders ↔ Billing
- **Order completion** → Invoice generation
- **Invoice payment** → Order status progression  
- **Refund processing** → Bidirectional status sync

### 2. Orders ↔ Provisioning  
- **Order completion** → Service provisioning queue
- **Service bundles** → Service group creation
- **Order cancellation** → Service suspension

### 3. Orders ↔ Domains
- **Domain products** → Automatic domain registration
- **Order completion** → Domain activation

### 4. Billing ↔ Customers
- **Payment history** → Credit score updates
- **Invoice patterns** → Customer risk assessment

### 5. All Apps ↔ Tickets
- **Failed operations** → Automatic ticket creation
- **Critical issues** → Support escalation

### 6. All Apps ↔ Integrations
- **Business events** → External system sync
- **Webhook delivery** → Third-party notifications

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
# Romanian law compliance
@receiver(post_save, sender=Invoice) 
def handle_invoice_number_generation():
    if instance.status == 'issued' and instance.number.startswith('TMP-'):
        # Generate sequential number only for issued invoices
```

### VAT Validation
```python
# EU VAT validation and compliance logging
@receiver(post_save, sender=VATValidation)
def handle_vat_validation_result():
    # VIES validation results
    # Customer profile updates
```

## Signal Best Practices Implemented

### 1. Error Isolation
- Each signal handler has try/except blocks
- Failures don't break the main transaction
- Comprehensive error logging

### 2. Performance Optimization
- Async task queuing where possible
- Cache invalidation strategies
- Selective signal execution

### 3. Audit Compliance
- All business events logged
- Security event tracking
- GDPR compliance considerations

### 4. Idempotency
- Signals can be safely re-executed  
- State checking before actions
- Duplicate prevention logic

## Configuration and Registration

### App Configuration
```python
# apps/orders/apps.py & apps/billing/apps.py
class OrdersConfig(AppConfig):
    def ready(self) -> None:
        from . import signals
        from . import signals_extended
```

### Signal Registration
- Automatic registration on Django startup
- Both core and extended signals loaded
- Proper import isolation to prevent circular imports

## Monitoring and Debugging

### Logging Strategy
- Structured logging with emojis for easy identification
- Different log levels for different event types
- Security events logged separately

### Error Tracking
```python
logger.exception(f"🔥 [Order Signal] Failed to handle: {e}")
log_security_event('critical_failure', details)
```

### Performance Monitoring
- Signal execution time tracking
- Failed signal retry mechanisms
- Queue monitoring for async tasks

## Testing Strategy

### Signal Testing
- Unit tests for individual signal handlers
- Integration tests for cross-app workflows
- Mock external dependencies (email, webhooks)

### Test Isolation
- Signals disabled in specific tests when needed
- Test-specific signal configurations
- Database rollback handling

## Future Enhancements

### 1. Signal Analytics
- Signal execution metrics
- Performance bottleneck identification
- Business event analytics

### 2. Enhanced Integration
- More external system connectors
- Real-time synchronization improvements
- Event sourcing implementation

### 3. Business Rule Engine
- Dynamic signal configuration
- Rule-based event handling
- Customer-specific business logic

## Conclusion

The signal architecture provides a robust, scalable foundation for event-driven business logic in the PRAHO platform. It ensures:

- **Decoupled architecture** - Apps can communicate without tight coupling
- **Romanian compliance** - Automatic handling of legal requirements
- **Business automation** - Reduced manual intervention
- **Data consistency** - Cross-app state synchronization
- **Audit compliance** - Comprehensive event logging
- **Performance optimization** - Efficient resource usage

This implementation follows Django best practices while meeting the specific needs of a Romanian hosting platform business.