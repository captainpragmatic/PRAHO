# ADR-0025: Store Monetary Amounts in Cents

## Status

**Accepted** - 2025-08-19

## Context

PRAHO Platform handles financial transactions for Romanian hosting providers, including invoices, payments, billing, and currency conversions. The system needs to store and process monetary amounts with high precision while avoiding common floating-point arithmetic issues that can lead to financial discrepancies.

### Romanian Business Requirements

- Support for multiple currencies (RON, EUR, USD)
- VAT calculations (19% standard rate in Romania)
- Integration with Romanian e-Factura system
- Payment processing through Stripe and bank transfers
- Financial reporting and auditing compliance

### Technical Challenges

1. **Floating-point precision errors**: Standard decimal arithmetic can introduce rounding errors
2. **Currency conversion**: Need precise calculations when converting between currencies
3. **API integrations**: Payment providers (Stripe, PayPal) use cent-based amounts
4. **Database storage**: Efficient storage and indexing of monetary values
5. **Romanian formatting**: Display amounts in Romanian number format (1.234,56 RON)

## Decision

**We will store all monetary amounts as integers representing the smallest currency unit (cents/bani) in the database.**

### Implementation Details

#### Database Schema
```sql
-- Invoice amounts stored in cents
CREATE TABLE invoice (
    subtotal_cents BIGINT NOT NULL,  -- 11900 = 119.00 EUR
    tax_cents BIGINT NOT NULL,       -- 2261 = 22.61 EUR
    total_cents BIGINT NOT NULL,     -- 14161 = 141.61 EUR
    currency_id VARCHAR(3) NOT NULL  -- 'EUR', 'RON', 'USD'
);

-- Payment amounts stored in cents
CREATE TABLE payment (
    amount_cents BIGINT NOT NULL,
    currency_id VARCHAR(3) NOT NULL
);
```

#### Django Model Implementation
```python
class Invoice(models.Model):
    subtotal_cents = models.BigIntegerField()
    tax_cents = models.BigIntegerField()
    total_cents = models.BigIntegerField()
    currency = models.ForeignKey(Currency, on_delete=models.RESTRICT)

    @property
    def subtotal(self):
        """Convert cents to currency units"""
        return Decimal(self.subtotal_cents) / 100
```

#### Template Display
```django
{% load formatting %}
{{ invoice.total_cents|cents_to_currency|romanian_currency:invoice.currency.code }}
<!-- Outputs: 119,00 EUR -->
```

## Rationale

### Advantages

1. **Precision**: Integer arithmetic eliminates floating-point rounding errors
2. **Performance**: Integer operations are faster than decimal arithmetic
3. **Storage Efficiency**: BIGINT (8 bytes) vs DECIMAL(10,2) (varies, typically more)
4. **API Compatibility**: Direct compatibility with Stripe, PayPal APIs
5. **Atomic Operations**: Database operations on integers are atomic
6. **Indexing**: Better database index performance on integers

### Conversion Rules

- **1 EUR = 100 cents**
- **1 RON = 100 bani**
- **Maximum amount**: 922,337,203,685,477.05 (BIGINT limit)
- **Precision**: Always 2 decimal places for display

### Romanian Specific Benefits

- **e-Factura compliance**: Exact amounts without rounding errors
- **VAT calculations**: Precise 19% VAT computation (amount * 19 / 100)
- **Bank integration**: Romanian banks expect precise amounts
- **Audit trail**: Exact monetary tracking for Romanian tax compliance

## Consequences

### Positive

✅ **Financial accuracy**: No rounding errors in calculations
✅ **API integration**: Direct compatibility with payment providers
✅ **Performance**: Faster arithmetic operations
✅ **Romanian compliance**: Meets e-Factura precision requirements
✅ **Audit friendly**: Clear monetary trail for tax authorities

### Negative

❌ **Developer complexity**: Must remember to convert cents ↔ currency units
❌ **Template complexity**: Need formatting filters for display
❌ **Migration effort**: Existing decimal amounts need conversion
❌ **Query complexity**: Aggregations require careful handling

### Mitigation Strategies

1. **Template filters**: Comprehensive formatting filters for display
2. **Model properties**: Convenient properties for currency unit access
3. **Validation**: Input validation to ensure cent amounts are valid
4. **Documentation**: Clear guidelines for developers
5. **Testing**: Extensive test coverage for monetary calculations

## Implementation Examples

### Creating Invoices
```python
# Service costs 119.00 EUR
invoice = Invoice.objects.create(
    subtotal_cents=11900,  # 119.00 EUR in cents
    tax_cents=2261,        # 19% VAT = 22.61 EUR
    total_cents=14161,     # Total = 141.61 EUR
    currency_id='EUR'
)
```

### Template Display
```django
<!-- Romanian currency formatting -->
{{ invoice.total_cents|cents_to_currency|romanian_currency:'EUR' }}
<!-- Output: 141,61 EUR -->

<!-- Simple conversion -->
{{ invoice.total_cents|cents_to_currency }}
<!-- Output: 141.61 -->
```

### API Responses
```json
{
  "invoice_id": 123,
  "subtotal_cents": 11900,
  "tax_cents": 2261,
  "total_cents": 14161,
  "currency": "EUR",
  "display": {
    "subtotal": "119,00 EUR",
    "tax": "22,61 EUR",
    "total": "141,61 EUR"
  }
}
```

## Alternatives Considered

### 1. Django DecimalField
- **Pros**: Built-in decimal support, human-readable in DB
- **Cons**: Slower, potential precision issues, more storage
- **Rejected**: Performance and precision concerns

### 2. Python Money Libraries (django-money)
- **Pros**: Abstraction, currency handling
- **Cons**: Additional dependency, learning curve
- **Rejected**: Adds complexity, cents approach is simpler

### 3. Floating Point (FloatField)
- **Pros**: Simple, direct
- **Cons**: Precision errors, unsuitable for financial data
- **Rejected**: Unacceptable for financial applications

## Monitoring and Success Metrics

- **Financial accuracy**: Zero monetary discrepancies in reports
- **Performance**: Query response times under 100ms for financial aggregations
- **API compatibility**: 100% success rate with Stripe/PayPal integration
- **e-Factura compliance**: No rejection due to amount precision issues
- **Developer satisfaction**: Reduced monetary calculation bugs

## References

- [Stripe API Documentation](https://stripe.com/docs/api) - Uses cents for all amounts
- [Romanian e-Factura Specification](https://anaf.ro) - Precision requirements
- [PostgreSQL Numeric Types](https://www.postgresql.org/docs/current/datatype-numeric.html)
- Martin Fowler's ["Money"](https://martinfowler.com/eaaCatalog/money.html) pattern

---
**Decision made by**: Development Team
**Approved by**: Technical Lead
**Implementation date**: August 2025
**Review date**: February 2026
