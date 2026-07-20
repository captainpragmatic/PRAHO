# ADR-0041: Foreign-currency e-Factura accounting

## Status

**Accepted** - July 2026

## Context

PRAHO stores invoice amounts in the document currency, but its dormant FX-rate
table did not record provenance and accepted zero, negative, and self-pair
rates. Invoice rows had only an optional `exchange_to_ron` value that no
production issuance path populated. A foreign-currency invoice could therefore
not prove which legally valid rate was used to calculate its RON VAT amount.

Romanian Fiscal Code article 290(2) permits the latest BNR, ECB, or settlement
bank rate valid on the VAT exigibility date. CIUS-RO BR-RO-030 and EN16931 BR-53
require a non-RON invoice to carry RON as its VAT accounting currency and a
separate RON tax total. The UBL invoice must not carry `cac:TaxExchangeRate`
under Peppol UBL-CR-490.

## Decision

### Exact-direction, provenanced rates

An FX row means exactly `1 base currency = rate quote currency`. Issuance looks
up only the requested direction; it never silently inverts a rate. Every new
rate used for issuance records its effective date, approved source, source
reference, and acquisition time. Historical rows migrate as `legacy_unknown`
and cannot be consumed for new issuance until an operator supplies trustworthy
provenance.

The database rejects non-finite or non-positive rates and pairs whose base and quote currency
are equal. A migration fails closed when invalid historical data exists rather
than deleting or rewriting it.

### Immutable invoice snapshot

The tax point is the rate-selection boundary. Issuing a non-RON invoice stores
the selected rate, effective date, source, and reference on that invoice before
its lifecycle transition. Those fields and the document currency are immutable
after issue. Later changes to the rate table cannot alter the accounting record.

Current invoice paths use the Romanian local issue date as the tax point. A
workflow with a legally distinct tax point must supply it explicitly; advances
and fiscal corrections are not inferred.

### UBL representation

RON invoices retain one document-currency `TaxTotal`. Non-RON invoices emit:

- `TaxCurrencyCode` equal to `RON`;
- one document-currency `TaxTotal` with tax subtotals; and
- one RON `TaxTotal` without tax subtotals, calculated from the immutable
  snapshot and rounded to two decimals.

The FX rate remains in PRAHO's audit record and is not emitted as
`cac:TaxExchangeRate`.

### Operational boundary

Invoice issuance performs no network I/O. Operators may ingest an approved
rate through an audited management command. Automatic BNR ingestion can be
added later as a separate scheduler concern without changing the lookup or
invoice-snapshot contract.

## Consequences

### Positive

- Foreign-currency VAT is reproducible from an immutable, provenanced record.
- Missing or dubious FX data blocks issuance instead of silently defaulting to
  RON or inventing provenance.
- Weekend and holiday issuance can use the last published rate valid on the tax
  point date.
- The XML representation follows the accounting-currency rules without adding
  a prohibited UBL exchange-rate element.

### Negative

- Operators must provision trustworthy rates before foreign-currency issuance.
- Existing issued foreign-currency invoices without provenance require explicit
  reconciliation before e-Factura generation.
- The native validator remains a partial business-rule validator until official
  XSD/Schematron artifacts are introduced and governed.

## Rejected alternatives

1. **Fetch BNR during invoice issue** - couples a fiscal transition to network
   availability and makes retries non-deterministic.
2. **Silently invert a reverse pair** - hides data-direction mistakes and weakens
   the audit trail.
3. **Backfill historical provenance as BNR** - invents evidence not present in
   the database.
4. **Emit `cac:TaxExchangeRate`** - conflicts with the applicable Peppol UBL
   constraint.

## Related

- [ADR-0025](ADR-0025-monetary-amounts-in-cents.md) - monetary storage
- [ADR-0038](ADR-0038-proforma-payment-convergence.md) - invoice convergence
- GitHub issues #103, #123, and #195
- [Romanian Fiscal Code, article 290(2)](https://legislatie.just.ro/Public/DetaliiDocumentAfis/189763)
- [CIUS-RO BR-RO-030 (OMF 4092/2022)](https://static.anaf.ro/static/10/Anaf/legislatie/OMF_4092_2022.pdf)
- [Peppol EN16931 BR-53](https://docs.peppol.eu/poacc/billing/3.0/2024-Q2/rules/ubl-tc434/BR-53/)
- [Peppol UBL-CR-490](https://docs.peppol.eu/poacc/billing/3.0/rules/ubl-tc434/UBL-CR-490/)
