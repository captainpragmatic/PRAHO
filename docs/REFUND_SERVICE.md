# RefundService Documentation

## Overview

The **RefundService** is a critical financial component of the PRAHO Platform that handles bidirectional refund synchronization between orders and invoices. It ensures that refunding either an order OR an invoice automatically refunds the other, maintaining data integrity across the financial system.

## 🚨 Critical Safety Features

- **Atomic Transactions**: All refund operations use `@transaction.atomic` to prevent partial refunds
- **Double Refund Prevention**: Validates that entities haven't already been fully refunded  
- **Amount Validation**: Ensures refund amounts don't exceed available amounts
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
- Status is `completed`, `processing`, or `partially_refunded`
- Not already fully refunded  
- Order total > 0

**Orders CANNOT be refunded if:**
- Status is `draft`, `cancelled`, or `failed`
- Already fully refunded
- Invalid or missing order

**Invoices can be refunded if:**
- Status is `issued`, `paid`, or `overdue`
- Not already fully refunded
- Invoice total > 0

**Invoices CANNOT be refunded if:**  
- Status is `draft` or `void`
- Already fully refunded
- Invalid or missing invoice

### Status Updates

| Original Status | Refund Type | New Status |
|----------------|-------------|------------|
| `completed` | Full | `refunded` |
| `completed` | Partial | `partially_refunded` |
| `partially_refunded` | Full | `refunded` |
| `partially_refunded` | Partial | `partially_refunded` |

### Bidirectional Synchronization

When refunding an **order**:
1. Find associated invoice(s)
2. Update order status
3. Update invoice status and metadata
4. Process payment refunds if requested
5. Create audit trail

When refunding an **invoice**:
1. Find associated order(s)
2. Update invoice status and metadata
3. Update order status  
4. Process payment refunds if requested
5. Create audit trail

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

### Order Metadata
Refund information is stored in `Order.meta['refunds']`:

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

### Invoice Metadata
Refund information is stored in `Invoice.meta['refunds']` with the same structure.

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
- Atomic transactions prevent race conditions
- Indexes on order/invoice lookups

### Query Budget
- Order refund: ~3-5 queries (order, invoice, payments)
- Invoice refund: ~3-5 queries (invoice, orders, payments)
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
   - Check order status (must be completed/processing)
   - Verify order hasn't been fully refunded already

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