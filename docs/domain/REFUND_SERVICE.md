# RefundService Documentation

## Overview

The **RefundService** is PRAHO's authoritative refund ledger and Stripe refund
orchestrator. Refunds may be initiated from either an order or an invoice, but
their monetary state converges through the authoritative `Payment`. PRAHO
updates `Payment` and `Invoice` balances only after the gateway reports that
funds have settled.

## 🚨 Critical Safety Features

- **Atomic Transactions**: All refund operations use `@transaction.atomic` to prevent partial refunds
- **Canonical Lock Order**: Refund paths lock Payment → Invoice → Order → Refund to avoid cross-flow deadlocks
- **Double Refund Prevention**: Pending and settled refund reservations both reduce the available refundable amount
- **Amount Validation**: Ensures refund amounts don't exceed available amounts
- **Gateway Convergence**: Stripe webhooks and the scheduled sweep share one idempotent convergence service
- **Gateway Identity Integrity**: A non-empty gateway refund ID is unique in the PRAHO ledger
- **Fail-Closed Linkage**: Gateway facts must match PRAHO's Payment, customer, amount, and currency
- **Comprehensive Audit Logging**: All operations are logged for regulatory compliance
- **Strong Typing**: TypedDict and Enums prevent runtime errors
- **Result Pattern**: Explicit error handling with `Result[T, E]` types

## Architecture

### Domain Models

```python
class RefundType(Enum):
    FULL = "full"      # Refund entire amount
    PARTIAL = "partial" # Refund specific amount

class RefundReason(Enum):
    CUSTOMER_REQUEST = "customer_request"
    ERROR_CORRECTION = "error_correction"
    DISPUTE_RESOLUTION = "dispute"
    SERVICE_FAILURE = "service_failure"
    DUPLICATE_PAYMENT = "duplicate_payment"
    FRAUD_PREVENTION = "fraud"
    CANCELLATION = "cancellation"
    # ... more reasons

class RefundData(TypedDict):
    refund_type: RefundType
    amount_cents: int                    # Required for partial refunds
    reason: RefundReason
    notes: str
    initiated_by: User | None
    external_refund_id: str | None      # Payment gateway refund ID
    process_payment_refund: bool        # Actually process payment refund
```

### Core Services

#### RefundService
Main service handling all refund operations:

- `refund_order(order_id, refund_data)` - Refund order and associated invoices
- `refund_invoice(invoice_id, refund_data)` - Refund invoice and associated orders
- `get_refund_eligibility(entity_type, entity_id, amount?)` - Check refund eligibility

#### RefundQueryService
Service for querying refund data:

- `get_entity_refunds(entity_type, entity_id)` - Get refund history
- `get_refund_statistics(customer_id?, date_range?)` - Generate refund reports

#### RefundConvergenceService

The only service allowed to project Stripe refund facts into PRAHO:

- imports a Stripe-created refund when it can be linked unambiguously to a PRAHO Payment
- advances existing refunds through the local FSM
- ignores stale gateway events using an event-time watermark
- treats duplicate webhook delivery and scheduled discovery as idempotent
- projects only completed refund totals onto Payment and Invoice

Stripe `refund.created`, `refund.updated`, `refund.failed`,
`charge.refund.updated`, and legacy `charge.refunded` events route through
this service. The scheduled reconciliation task also retrieves all known
non-terminal refunds and discovers recent Stripe refunds, covering lost
webhooks and dashboard-created refunds.

## Usage Examples

### Full Order Refund

```python
from apps.billing.services import RefundService, RefundData, RefundType, RefundReason

refund_data: RefundData = {
    'refund_type': RefundType.FULL,
    'amount_cents': 0,  # Ignored for full refunds
    'reason': RefundReason.CUSTOMER_REQUEST,
    'notes': 'Customer dissatisfied with service',
    'initiated_by': request.user,
    'external_refund_id': 'stripe_re_1234567890',
    'process_payment_refund': True
}

result = RefundService.refund_order(order.id, refund_data)

if result.is_ok():
    refund_result = result.unwrap()
    print(f"Refunded {refund_result['amount_refunded_cents']/100:.2f} RON")
    print(f"Order status updated: {refund_result['order_status_updated']}")
    print(f"Invoice status updated: {refund_result['invoice_status_updated']}")
else:
    print(f"Refund failed: {result.error}")
```

### Partial Invoice Refund

```python
refund_data: RefundData = {
    'refund_type': RefundType.PARTIAL,
    'amount_cents': 5000,  # 50.00 RON
    'reason': RefundReason.SERVICE_FAILURE,
    'notes': 'Server downtime compensation',
    'initiated_by': request.user,
    'external_refund_id': None,
    'process_payment_refund': False  # Credit note only
}

result = RefundService.refund_invoice(invoice.id, refund_data)
```

### Check Eligibility Before Refunding

```python
# Check if order can be fully refunded
result = RefundService.get_refund_eligibility('order', order.id)

if result.is_ok():
    eligibility = result.unwrap()
    if eligibility['is_eligible']:
        max_amount = eligibility['max_refund_amount_cents'] / 100
        print(f"Can refund up to {max_amount:.2f} RON")
    else:
        print(f"Cannot refund: {eligibility['reason']}")

# Check specific partial amount
result = RefundService.get_refund_eligibility('order', order.id, 5000)
```

## Business Rules

### Refund Eligibility

**Orders can be refunded if:**
- Status is `paid`, `completed`, or `partially_refunded`
- Not already fully refunded
- Order total > 0

**Orders CANNOT be refunded if:**
- Status is `draft`, `pending`, `awaiting_payment`, `cancelled`, or `failed`
- Already fully refunded
- Invalid or missing order

> **Note:** Settlement status (`refunded`, `partially_refunded`) is tracked
> on **Invoice** and **Payment**, not on the Order FSM. The Refund row records
> the gateway lifecycle and retains its order or invoice ownership.

**Invoices can be refunded if:**
- Status is `paid` or `completed`
- Not already fully refunded
- Invoice total > 0

**Invoices CANNOT be refunded if:**
- Status is `draft`, `issued`, `overdue`, `void`, or another non-settled state
- Already fully refunded
- Invalid or missing invoice

### Status Updates

Refund status is tracked on Invoice (not Order). The table below reflects Invoice FSM transitions:

| Original Invoice Status | Refund Type | New Invoice Status |
|------------------------|-------------|-------------------|
| `paid` | Full | `refunded` |
| `paid` | Partial | `partially_refunded` |
| `partially_refunded` | Full | `refunded` |
| `partially_refunded` | Partial | `partially_refunded` |

### Gateway Lifecycle and Settlement

When refunding an **order**:
1. Resolve the authoritative Payment and its invoice/proforma linkage
2. Lock Payment, then Invoice, then Order
3. Reserve the amount against pending and settled refunds
4. Submit the exact cent amount and currency to the gateway with an idempotency key
5. Create a Refund ledger row with the gateway refund ID
6. Project Payment and Invoice status only when the gateway status is `succeeded`

When refunding an **invoice**:
1. Resolve and lock its authoritative Payment before the Invoice
2. Perform the same reservation, gateway submission, ledger, and settlement flow

Gateway `pending` and `requires_action` results remain non-terminal and do
not reduce the settled Payment or Invoice balance. Gateway `failed`,
`canceled`, and locally rejected refunds release the reservation. A later
webhook or reconciliation sweep can advance the same Refund without creating a
second ledger entry.

## Error Handling

The service uses the `Result[T, E]` pattern for explicit error handling:

```python
result = RefundService.refund_order(order_id, refund_data)

if result.is_ok():
    # Success case
    refund_result = result.unwrap()
    # Handle success...
else:
    # Error case
    error_message = result.error
    # Handle error...
```

### Common Error Cases

- **Entity Not Found**: `"Order {id} not found"`
- **Not Eligible**: `"Order not eligible for refund: already fully refunded"`
- **Invalid Amount**: `"Refund amount exceeds maximum refundable amount"`
- **Transaction Failure**: `"Failed to process bidirectional refund: {details}"`

## Data Storage

The `Refund` model is the source of truth. Each row has exactly one owning
document (`order` or `invoice`), may link to the authoritative `payment`, and
stores amount, currency, reason, local FSM status, the unique
`gateway_refund_id`, and gateway metadata.

Migration `billing.0037_refund_gateway_id_unique` fails closed if existing
non-empty gateway IDs are duplicated. Operators must reconcile those ledger
rows before deploying the constraint.

### Legacy Order Metadata

Historical refund information may remain in `Order.meta['refunds']`, but it is
audit data rather than the source for availability or settlement:

```json
{
  "refunds": [
    {
      "refund_id": "uuid",
      "amount_cents": 5000,
      "reason": "service_failure",
      "notes": "Server downtime compensation",
      "refunded_at": "2024-01-15T10:30:00Z",
      "initiated_by": "user_id"
    }
  ]
}
```

### Legacy Invoice Metadata

Historical `Invoice.meta['refunds']` entries have the same legacy structure.
New refund calculations use Refund rows.

## Security & Compliance

### Audit Logging
All refund operations generate security events:

```python
log_security_event(
    'order_refunded',
    {
        'refund_id': str(refund_id),
        'order_id': str(order_id),
        'customer_id': str(customer_id),
        'amount_refunded_cents': amount,
        'reason': reason,
        'initiated_by': user_id
    }
)
```

### GDPR Compliance
- All refund data includes user identification
- Audit trails are immutable
- Personal data handling follows GDPR requirements

### Romanian Compliance
- VAT handling for refunds
- Sequential numbering preservation
- Legal refund documentation

## Performance Considerations

### Database Queries
- Uses `select_related()` to minimize database queries
- Uses row locks in the canonical Payment → Invoice → Order → Refund order
- Indexes order, invoice, payment, status, and gateway refund lookups
- Uses one conditional unique constraint for non-empty gateway refund IDs
- Eligibility check: ~2 queries (entity + related data)

## Integration Points

### Payment Processors
The service integrates with payment processors via:

```python
# Process actual payment refund
if refund_data['process_payment_refund']:
    payment_result = RefundService._process_payment_refund(
        order=order,
        invoice=invoice,
        refund_amount_cents=amount,
        refund_data=refund_data
    )
```

### Order Management
Integrates with `OrderService` for status updates:

```python
from apps.orders.services import OrderService, StatusChangeData

status_change = StatusChangeData(
    new_status='refunded',
    notes=f"Refund processed: {reason}",
    changed_by=user
)

OrderService.update_order_status(order, status_change)
```

## Testing

Comprehensive test suite covers:

- ✅ Full and partial refunds
- ✅ Bidirectional synchronization
- ✅ Error cases and validation
- ✅ Double refund prevention
- ✅ Edge cases (no invoice, no order)
- ✅ Atomic transaction rollback
- ✅ Concurrent access scenarios

Run tests:
```bash
python manage.py test tests.billing.test_refund_service
```

## Migration Guide

### From Manual Refunds
If you currently handle refunds manually:

1. **Check Eligibility First**:
   ```python
   result = RefundService.get_refund_eligibility('order', order_id)
   ```

2. **Use Structured Data**:
   ```python
   refund_data: RefundData = {
       'refund_type': RefundType.FULL,
       # ... other fields
   }
   ```

3. **Handle Results Properly**:
   ```python
   if result.is_ok():
       # Success
   else:
       # Handle error
   ```

### Integration with Views
```python
def refund_order_view(request, order_id):
    refund_data: RefundData = {
        'refund_type': RefundType(request.POST['refund_type']),
        'amount_cents': int(request.POST.get('amount_cents', 0)),
        'reason': RefundReason(request.POST['reason']),
        'notes': request.POST['notes'],
        'initiated_by': request.user,
        'external_refund_id': request.POST.get('external_refund_id'),
        'process_payment_refund': request.POST.get('process_payment') == 'true'
    }

    result = RefundService.refund_order(UUID(order_id), refund_data)

    if result.is_ok():
        messages.success(request, "Refund processed successfully")
        return redirect('order_detail', order_id=order_id)
    else:
        messages.error(request, f"Refund failed: {result.error}")
        return redirect('refund_form', order_id=order_id)
```

## API Reference

### RefundService

#### `refund_order(order_id: UUID, refund_data: RefundData) -> Result[RefundResult, str]`
Process refund for an order and associated invoices.

**Parameters:**
- `order_id`: UUID of the order to refund
- `refund_data`: RefundData with refund parameters

**Returns:**
- `Ok(RefundResult)` on success
- `Err(str)` on failure

#### `refund_invoice(invoice_id: UUID, refund_data: RefundData) -> Result[RefundResult, str]`
Process refund for an invoice and associated orders.

#### `get_refund_eligibility(entity_type: str, entity_id: UUID, amount?: int) -> Result[RefundEligibility, str]`
Check if entity can be refunded.

**Parameters:**
- `entity_type`: `'order'` or `'invoice'`
- `entity_id`: UUID of the entity
- `amount`: Optional amount for partial refund validation

### RefundQueryService

#### `get_entity_refunds(entity_type: str, entity_id: UUID) -> Result[list[dict], str]`
Get refund history for an entity.

#### `get_refund_statistics(customer_id?: UUID, date_from?: str, date_to?: str) -> Result[dict, str]`
Generate refund statistics and reports.

## Troubleshooting

### Common Issues

1. **"Order not eligible for refund"**
   - Check order status (must be `completed` or `provisioning`)
   - Verify order hasn't been fully refunded already (check linked invoice status)

2. **"Refund amount exceeds maximum"**
   - Check available refund amount with `get_refund_eligibility()`
   - Account for previous partial refunds

3. **"Transaction failed"**
   - Check database constraints
   - Verify related entities exist (customer, currency)
   - Check for concurrent refund attempts

4. **Payment refund failed but records updated**
   - This is by design - financial records are always updated
   - Payment refund failures are logged but don't rollback the refund
   - Manually process payment refund through gateway

### Debug Mode
Enable debug logging:

```python
import logging
logging.getLogger('apps.billing.services').setLevel(logging.DEBUG)
```

## Contributing

When extending the RefundService:

1. **Maintain Type Safety**: Use TypedDict and proper typing
2. **Follow Result Pattern**: Return `Result[T, E]` from all methods
3. **Add Comprehensive Tests**: Test success and failure cases
4. **Update Documentation**: Keep this document current
5. **Audit Logging**: Log all financial operations
6. **Transaction Safety**: Use `@transaction.atomic` for data consistency

---

**⚠️ Important**: This service handles financial data. Any changes must be thoroughly tested and reviewed for compliance and data integrity.
