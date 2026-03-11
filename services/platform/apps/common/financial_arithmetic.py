"""
Financial arithmetic utilities for PRAHO Platform.

Pure functions for calculating line totals and document totals with
Romanian VAT-compliant banker's rounding. Extracted from identical logic
in Order.calculate_totals(), InvoiceLine.calculate_totals(), and
ProformaInvoiceLine.calculate_totals().

All monetary values are integers in cents to avoid floating-point issues (ADR-0025).
"""

from __future__ import annotations

from dataclasses import dataclass
from decimal import ROUND_HALF_EVEN, Decimal
from typing import Protocol


class HasLineTotals(Protocol):
    """Protocol for line items with subtotal_cents and tax_cents."""

    @property
    def subtotal_cents(self) -> int: ...

    @property
    def tax_cents(self) -> int: ...


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


def calculate_document_totals(
    items: list[HasLineTotals],
    discount_cents: int = 0,
) -> DocumentTotals:
    """Calculate totals for a document (order, invoice, proforma) from its line items.

    Args:
        items: Line items implementing HasLineTotals protocol.
        discount_cents: Document-level discount in cents (default 0).

    Returns:
        DocumentTotals with subtotal_cents, tax_cents, and total_cents (floored at 0).
    """
    subtotal_cents = sum(item.subtotal_cents for item in items)
    tax_cents = sum(item.tax_cents for item in items)
    total_cents = max(0, subtotal_cents + tax_cents - discount_cents)
    return DocumentTotals(
        subtotal_cents=subtotal_cents,
        tax_cents=tax_cents,
        total_cents=total_cents,
    )
