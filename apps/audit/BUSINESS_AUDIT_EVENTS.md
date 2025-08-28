# PRAHO Business Transaction Audit Events

This document describes the comprehensive business transaction audit system implemented for the PRAHO platform, covering all critical financial and order management events with Romanian business compliance requirements.

## Overview

The business audit system captures detailed audit trails for all financial transactions, order lifecycle events, and provisioning activities. This ensures complete traceability for business operations, regulatory compliance (GDPR, Romanian e-Factura), and financial reporting requirements.

## Architecture

### Domain-Specific Audit Services

- **`BillingAuditService`** - Specialized service for billing, invoicing, and payment events
- **`OrdersAuditService`** - Specialized service for order lifecycle and provisioning events
- **Signal-based Integration** - Automatic event capture through Django model signals
- **Rich Metadata Capture** - Comprehensive business context for each event

## Billing & Invoice Events

### Invoice Lifecycle Events

| Event Type | Description | Metadata Captured |
|------------|-------------|-------------------|
| `invoice_created` | Invoice initially created in draft status | Invoice details, customer info, amounts |
| `invoice_issued` | Invoice officially issued to customer | Sequential number, issue date, due date |
| `invoice_sent` | Invoice sent to customer via email | Recipient, send timestamp, delivery status |
| `invoice_paid` | Invoice fully paid by customer | Payment date, amount, payment method |
| `invoice_partially_paid` | Partial payment received | Remaining balance, payment details |
| `invoice_overdue` | Invoice past due date | Days overdue, dunning status |
| `invoice_voided` | Invoice cancelled/voided | Void reason, compliance notes |
| `invoice_refunded` | Invoice refunded to customer | Refund amount, refund date, reason |
| `invoice_status_changed` | General status change event | Old status, new status, change reason |

### Romanian e-Factura Compliance Events

| Event Type | Description | Business Context |
|------------|-------------|------------------|
| `efactura_submitted` | Invoice submitted to ANAF e-Factura | Submission ID, XML details |
| `efactura_accepted` | e-Factura submission accepted | Acceptance timestamp, reference |
| `efactura_rejected` | e-Factura submission rejected | Rejection reason, error codes |
| `invoice_number_generated` | Sequential number assigned | Compliance with Romanian law |
| `invoice_xml_generated` | e-Factura XML created | File path, validation status |
| `vat_calculation_applied` | VAT calculation performed | Rate used, amount calculated |

### ProformaInvoice Events

| Event Type | Description | Business Context |
|------------|-------------|------------------|
| `proforma_created` | Proforma invoice created | Validity period, amounts, customer |
| `proforma_converted` | Converted to final invoice | Conversion timestamp, reason |
| `proforma_expired` | Proforma validity expired | Expiry date, cleanup actions |

## Payment Processing Events

### Core Payment Events

| Event Type | Description | Metadata Captured |
|------------|-------------|-------------------|
| `payment_initiated` | Payment process started | Gateway details, amount, method |
| `payment_processing` | Payment being processed | Gateway transaction ID |
| `payment_succeeded` | Payment completed successfully | Confirmation details, receipt |
| `payment_failed` | Payment processing failed | Failure reason, error codes |
| `payment_refunded` | Payment refunded | Refund amount, refund reason |
| `payment_partially_refunded` | Partial refund processed | Remaining balance |

### Payment Retry & Dunning Events

| Event Type | Description | Business Context |
|------------|-------------|------------------|
| `payment_retry_scheduled` | Retry scheduled per policy | Retry attempt number, schedule |
| `payment_retry_attempted` | Retry attempt made | Attempt details, outcome |
| `payment_retry_succeeded` | Retry attempt successful | Success after N attempts |
| `payment_retry_failed` | Retry attempt failed | Failure details |
| `payment_retry_exhausted` | All retries exhausted | Escalation triggered |
| `dunning_email_sent` | Dunning notification sent | Email details, escalation level |

### Payment Compliance & Security

| Event Type | Description | Business Context |
|------------|-------------|------------------|
| `payment_fraud_detected` | Fraudulent payment detected | Risk score, blocking reason |
| `payment_chargeback_received` | Chargeback initiated | Chargeback reason, dispute ID |
| `payment_method_changed` | Customer changed payment method | Old/new method details |
| `payment_gateway_error` | Gateway processing error | Error details, retry status |

## Credit & Balance Management

### Credit Ledger Events

| Event Type | Description | Business Context |
|------------|-------------|------------------|
| `credit_added` | Credit added to account | Amount, reason, expiry |
| `credit_used` | Credit applied to payment | Amount used, remaining balance |
| `credit_adjusted` | Manual credit adjustment | Adjustment reason, amount |
| `credit_expired` | Credit balance expired | Expired amount, cleanup |
| `credit_limit_changed` | Credit limit modified | Old/new limit, approval |
| `credit_hold_applied` | Account placed on credit hold | Hold reason, restrictions |
| `credit_hold_released` | Credit hold removed | Release reason, timestamp |

### Balance Monitoring Events

| Event Type | Description | Business Context |
|------------|-------------|------------------|
| `balance_low_warning` | Account balance below threshold | Current balance, threshold |
| `balance_insufficient` | Insufficient funds for transaction | Required vs available |

## Order Management Events

### Order Lifecycle Events

| Event Type | Description | Metadata Captured |
|------------|-------------|-------------------|
| `order_created` | New order placed | Customer details, items, amounts |
| `order_updated` | Order details modified | Changed fields, reason |
| `order_status_changed` | Order status transition | Old/new status, trigger |
| `order_submitted` | Order submitted for processing | Submission timestamp |
| `order_confirmed` | Order confirmed by customer | Confirmation details |
| `order_processing` | Order being processed | Processing stage |
| `order_completed` | Order fulfillment complete | Completion timestamp |
| `order_cancelled_customer` | Customer cancelled order | Cancellation reason |
| `order_cancelled_admin` | Admin cancelled order | Internal reason, refund status |
| `order_failed` | Order processing failed | Failure reason, recovery actions |

### Order Item Management

| Event Type | Description | Business Context |
|------------|-------------|------------------|
| `order_item_added` | Item added to order | Product details, pricing |
| `order_item_removed` | Item removed from order | Removal reason |
| `order_item_updated` | Item details changed | Changed attributes |
| `order_quantity_changed` | Item quantity modified | Old/new quantity |
| `order_pricing_updated` | Item pricing changed | Price change details |

### Order Financial Events

| Event Type | Description | Business Context |
|------------|-------------|------------------|
| `order_discount_applied` | Discount applied to order | Discount type, amount |
| `order_discount_removed` | Discount removed | Removal reason |
| `order_tax_calculated` | Tax calculation performed | Tax rules applied |
| `order_shipping_updated` | Shipping details changed | Address, method changes |

### Order Refund Events

| Event Type | Description | Business Context |
|------------|-------------|------------------|
| `order_refund_requested` | Customer requested refund | Request details, reason |
| `order_refund_approved` | Refund request approved | Approval details |
| `order_refund_processed` | Refund completed | Processing details |

## Provisioning & Service Events

### Provisioning Lifecycle

| Event Type | Description | Metadata Captured |
|------------|-------------|-------------------|
| `provisioning_started` | Service provisioning begun | Order item, service details |
| `provisioning_in_progress` | Provisioning in progress | Progress status, stage |
| `provisioning_completed` | Service successfully provisioned | Service details, credentials |
| `provisioning_failed` | Provisioning failed | Error details, retry status |
| `provisioning_retried` | Provisioning retry attempted | Retry count, outcome |

### Service Management

| Event Type | Description | Business Context |
|------------|-------------|------------------|
| `service_activated` | Service activated for customer | Activation details |
| `service_suspended` | Service suspended | Suspension reason |
| `service_configuration_updated` | Service config changed | Configuration changes |
| `service_credentials_generated` | Access credentials created | Credential type |
| `service_access_granted` | Customer access granted | Access level, permissions |
| `service_access_revoked` | Customer access removed | Revocation reason |

### Domain & Resource Events

| Event Type | Description | Business Context |
|------------|-------------|------------------|
| `domain_associated` | Domain linked to service | Domain details |
| `domain_dissociated` | Domain unlinked from service | Unlinking reason |

## Audit Metadata Structure

### Common Metadata Fields

All business audit events include these common metadata fields:

```json
{
  "timestamp": "2024-12-01T10:30:00Z",
  "actor_type": "system|user|admin",
  "request_id": "req_abc123",
  "ip_address": "192.168.1.100",
  "user_agent": "Mozilla/5.0...",
  "session_key": "session123"
}
```

### Billing Event Metadata

Invoice events include:

```json
{
  "invoice_number": "INV-240001",
  "invoice_status": "issued",
  "customer_id": "uuid",
  "customer_name": "Company SRL",
  "currency": "RON",
  "total_amount": "1000.00",
  "total_cents": 100000,
  "vat_amount": "190.00",
  "vat_cents": 19000,
  "due_date": "2024-12-31T23:59:59Z",
  "is_overdue": false,
  "romanian_compliance": {
    "efactura_id": "EF123",
    "efactura_sent": true,
    "efactura_sent_date": "2024-12-01T11:00:00Z"
  }
}
```

Payment events include:

```json
{
  "payment_id": "uuid",
  "customer_id": "uuid",
  "amount": "1000.00",
  "amount_cents": 100000,
  "currency": "RON",
  "payment_method": "stripe",
  "gateway_txn_id": "txn_123456",
  "reference_number": "REF123",
  "invoice_id": "uuid",
  "invoice_number": "INV-240001",
  "financial_impact": true
}
```

### Order Event Metadata

Order events include:

```json
{
  "order_number": "ORD-20241201-000001",
  "order_status": "processing",
  "customer_id": "uuid",
  "customer_email": "customer@company.com",
  "customer_company": "Company SRL",
  "customer_vat_id": "RO12345678",
  "currency": "RON",
  "total_amount": "500.00",
  "total_cents": 50000,
  "subtotal_cents": 42017,
  "tax_cents": 7983,
  "payment_method": "card",
  "is_paid": true,
  "source_tracking": {
    "source_ip": "192.168.1.100",
    "user_agent": "Mozilla/5.0...",
    "utm_source": "google",
    "utm_medium": "organic"
  },
  "items_count": 3
}
```

## Usage Examples

### Logging Invoice Events

```python
from apps.audit.services import BillingAuditService, AuditContext

# Log invoice creation
BillingAuditService.log_invoice_event(
    event_type='invoice_created',
    invoice=invoice,
    user=request.user,
    context=AuditContext(
        ip_address=request.META.get('REMOTE_ADDR'),
        user_agent=request.META.get('HTTP_USER_AGENT'),
        request_id=request.headers.get('X-Request-ID')
    ),
    description=f'Invoice {invoice.number} created for {invoice.customer.company_name}'
)
```

### Logging Order Events

```python
from apps.audit.services import OrdersAuditService

# Log order status change
OrdersAuditService.log_order_event(
    event_type='order_status_changed',
    order=order,
    old_values={'status': 'pending'},
    new_values={'status': 'processing'},
    context=AuditContext(actor_type='system'),
    description=f'Order {order.order_number} advanced to processing'
)
```

### Logging Provisioning Events

```python
# Log service provisioning completion
OrdersAuditService.log_provisioning_event(
    event_type='provisioning_completed',
    order_item=order_item,
    service=provisioned_service,
    context=AuditContext(actor_type='system'),
    description=f'Service {provisioned_service.id} provisioned for {order_item.product_name}'
)
```

## Querying Business Audit Events

### Common Business Queries

```python
from apps.audit.models import AuditEvent

# Get all invoice events for a customer
invoice_events = AuditEvent.objects.filter(
    action__startswith='invoice_',
    metadata__customer_id=str(customer.id)
).order_by('-timestamp')

# Get payment processing events for analysis
payment_events = AuditEvent.objects.filter(
    action__startswith='payment_',
    timestamp__gte=start_date,
    severity='high'
)

# Get order-to-cash audit trail
order_to_cash = AuditEvent.objects.filter(
    models.Q(metadata__order_number=order_number) |
    models.Q(metadata__invoice_number=invoice_number)
).order_by('timestamp')

# Get provisioning failures for monitoring
provisioning_failures = AuditEvent.objects.filter(
    action='provisioning_failed',
    timestamp__gte=timezone.now() - timedelta(hours=24)
)
```

### Financial Compliance Queries

```python
# Get all VAT-related events for Romanian compliance
vat_events = AuditEvent.objects.filter(
    action__startswith='vat_',
    timestamp__range=(start_date, end_date)
)

# Get e-Factura submission audit trail
efactura_events = AuditEvent.objects.filter(
    action__startswith='efactura_',
    metadata__has_key='efactura_id'
)

# Get financial events requiring review
financial_review = AuditEvent.objects.filter(
    category='business_operation',
    is_sensitive=True,
    requires_review=True
)
```

## Performance Considerations

### Database Indexes

The system includes specialized indexes for business queries:

- `idx_audit_billing_events` - Fast billing event queries
- `idx_audit_financial_compliance` - Financial compliance reporting
- `idx_audit_romanian_compliance` - Romanian regulatory queries
- `idx_audit_order_lifecycle` - Order lifecycle tracking
- `idx_audit_provisioning` - Service provisioning queries
- `idx_audit_revenue_events` - Revenue recognition queries

### Query Optimization

1. **Use specific event types** - Filter by `action` field for best performance
2. **Include time ranges** - Always specify timestamp ranges for large datasets
3. **Leverage metadata indexes** - Use JSON operators for metadata queries
4. **Batch operations** - Use bulk queries for reporting and analytics

## Security & Compliance

### Data Sensitivity

Business audit events are automatically marked as:
- **Sensitive**: Payment, billing, customer data events
- **High Severity**: Fraud detection, chargebacks, provisioning failures
- **Review Required**: Financial compliance violations

### Retention Policies

- **Financial Events**: 7 years (Romanian legal requirement)
- **Order Events**: 5 years
- **Provisioning Events**: 3 years
- **General Business Events**: 2 years

### Access Controls

- **Finance Team**: Full access to billing and payment events
- **Operations Team**: Access to order and provisioning events
- **Compliance Team**: Access to regulatory and audit events
- **Customers**: Limited access to their own transaction events

## Monitoring & Alerting

### Key Business Metrics

The audit system supports monitoring of:
- Payment success/failure rates
- Order completion times
- Provisioning success rates
- Invoice collection efficiency
- Compliance event tracking

### Alert Conditions

- Multiple payment failures for a customer
- Provisioning failures above threshold
- e-Factura submission failures
- High-value refunds requiring review
- Unusual order patterns or fraud indicators

## Integration Points

### Signal-Based Automation

The business audit system automatically captures events through:
- Django model signals (post_save, pre_save, post_delete)
- Service layer integration points
- Webhook processing events
- Background task completions

### External System Integration

- **Accounting Software**: Export audit trails for external reconciliation
- **Business Intelligence**: Feed audit data to BI tools for analytics
- **Compliance Tools**: Integration with Romanian e-Factura systems
- **Monitoring Systems**: Real-time event streaming for alerts

---

*This documentation covers the comprehensive business transaction audit system implemented for PRAHO Platform. For technical implementation details, see the source code in `apps/audit/services.py` and related signal handlers.*