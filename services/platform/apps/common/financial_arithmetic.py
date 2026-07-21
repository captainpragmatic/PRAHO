"""
Financial arithmetic utilities for PRAHO Platform.

Pure functions for calculating line totals and document totals with
Romanian VAT-compliant banker's rounding. Extracted from identical logic
in Order.calculate_totals(), InvoiceLine.calculate_totals(), and
ProformaInvoiceLine.calculate_totals().

All monetary values are integers in cents to avoid floating-point issues (ADR-0025).
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from decimal import ROUND_HALF_EVEN, Decimal
from typing import Protocol


class HasLineTotals(Protocol):
    """Protocol for line items with taxable amounts and their explicit VAT rate."""

    @property
    def subtotal_cents(self) -> int: ...

    @property
    def tax_cents(self) -> int: ...

    @property
    def tax_rate(self) -> Decimal: ...


@dataclass(frozen=True, slots=True)
class LineTotals:
    """Result of a line-level total calculation."""

    tax_cents: int
    line_total_cents: int


@dataclass(frozen=True, slots=True)
class DocumentTotals:
    """Result of a document-level total calculation."""

    subtotal_cents: int
    tax_cents: int
    total_cents: int


def calculate_line_totals(subtotal_cents: int, tax_rate: Decimal | str) -> LineTotals:
    """Calculate tax and line total for a single line item.

    Uses banker's rounding (ROUND_HALF_EVEN) for Romanian VAT compliance.

    Args:
        subtotal_cents: Pre-tax amount in cents (quantity * unit_price_cents).
        tax_rate: Tax rate as a decimal (e.g. Decimal("0.21") for 21%).

    Returns:
        LineTotals with computed tax_cents and line_total_cents.
    """
    vat_amount = Decimal(subtotal_cents) * Decimal(str(tax_rate))
    tax_cents = int(vat_amount.quantize(Decimal("1"), rounding=ROUND_HALF_EVEN))
    return LineTotals(tax_cents=tax_cents, line_total_cents=subtotal_cents + tax_cents)


def allocate_document_discount(
    taxable_bases_cents: list[int],
    discount_cents: int,
) -> tuple[int, ...]:
    """Allocate a document discount exactly using the largest-remainder method."""
    if discount_cents < 0:
        raise ValueError("Document discount cannot be negative")
    if any(base < 0 for base in taxable_bases_cents):
        raise ValueError("Taxable bases cannot be negative")

    total_base = sum(taxable_bases_cents)
    if total_base == 0:
        return tuple(0 for _base in taxable_bases_cents)

    effective_discount = min(discount_cents, total_base)
    allocations: list[int] = []
    remainders: list[int] = []
    for base in taxable_bases_cents:
        allocation, remainder = divmod(effective_discount * base, total_base)
        allocations.append(allocation)
        remainders.append(remainder)

    residual = effective_discount - sum(allocations)
    allocation_order = sorted(
        range(len(allocations)),
        key=lambda index: (-remainders[index], index),
    )
    for index in allocation_order[:residual]:
        allocations[index] += 1
    return tuple(allocations)


def reconcile_document_discount(
    *,
    line_gross_cents: int,
    net_subtotal_cents: int,
    stored_discount_cents: int,
) -> int:
    """Return the evidenced document discount or reject a contradictory ledger.

    Historical invoices predate ``discount_cents`` and legitimately store zero while
    their gross lines and net header evidence a discount. Newer documents must persist
    the exact derived value. This narrow legacy bridge keeps old fiscal records
    renderable without allowing a non-zero stored discount to disagree with the ledger.
    """
    if min(line_gross_cents, net_subtotal_cents, stored_discount_cents) < 0:
        raise ValueError("Document discount reconciliation requires non-negative amounts")
    if line_gross_cents == 0:
        if stored_discount_cents:
            raise ValueError("Stored document discount cannot be evidenced without line amounts")
        return 0
    if net_subtotal_cents > line_gross_cents:
        raise ValueError("Document net subtotal exceeds line gross")

    derived_discount = line_gross_cents - net_subtotal_cents
    if stored_discount_cents not in {0, derived_discount}:
        raise ValueError("Stored document discount does not reconcile with line gross and net subtotal")
    return derived_discount


def calculate_document_totals(
    items: Sequence[HasLineTotals],
    discount_cents: int = 0,
) -> DocumentTotals:
    """Calculate totals with document discounts applied before VAT.

    The returned subtotal remains the gross line subtotal because callers store the
    document allowance separately. Tax and total are based on each line's allocated
    net taxable amount.
    """
    if discount_cents < 0:
        raise ValueError("Document discount cannot be negative")

    subtotal_cents = sum(item.subtotal_cents for item in items)
    effective_discount = min(discount_cents, subtotal_cents)
    if effective_discount == 0:
        tax_cents = sum(item.tax_cents for item in items)
    else:
        allocations = allocate_document_discount(
            [item.subtotal_cents for item in items],
            effective_discount,
        )
        taxable_by_rate_cents: dict[Decimal, int] = {}
        for item, allocation in zip(items, allocations, strict=True):
            tax_rate = Decimal(str(item.tax_rate))
            net_taxable_cents = item.subtotal_cents - allocation
            taxable_by_rate_cents[tax_rate] = taxable_by_rate_cents.get(tax_rate, 0) + net_taxable_cents
        tax_cents = sum(
            calculate_line_totals(taxable_cents, tax_rate).tax_cents
            for tax_rate, taxable_cents in taxable_by_rate_cents.items()
        )

    total_cents = subtotal_cents - effective_discount + tax_cents
    return DocumentTotals(
        subtotal_cents=subtotal_cents,
        tax_cents=tax_cents,
        total_cents=total_cents,
    )
