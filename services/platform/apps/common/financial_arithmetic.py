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
from decimal import ROUND_HALF_EVEN, Decimal, InvalidOperation
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


def calculate_document_totals(
    items: Sequence[HasLineTotals],
    discount_cents: int = 0,
) -> DocumentTotals:
    """Calculate document totals, applying an allowance before VAT.

    Undiscounted documents preserve the persisted per-line tax sum. Discounted
    orders currently support one explicit tax rate, matching PRAHO's order VAT
    scenario and the single BG-20 allowance emitted downstream. Mixed-rate
    allowances must fail closed until their per-category ledger is represented.

    Args:
        items: Line items implementing HasLineTotals protocol.
        discount_cents: Document-level discount in cents (default 0).

    Returns:
        Gross subtotal, tax on the allowance-reduced base, and payable total.
    """
    if discount_cents < 0:
        raise ValueError("Document discount cannot be negative")

    subtotal_cents = sum(item.subtotal_cents for item in items)
    effective_discount_cents = min(discount_cents, subtotal_cents)

    if effective_discount_cents:
        tax_rates = {Decimal(str(item.tax_rate)) for item in items}
        if len(tax_rates) != 1:
            raise ValueError("A discounted document must use a single tax rate")
        taxable_subtotal_cents = subtotal_cents - effective_discount_cents
        tax_cents = calculate_line_totals(taxable_subtotal_cents, tax_rates.pop()).tax_cents
    else:
        tax_cents = sum(item.tax_cents for item in items)

    total_cents = subtotal_cents - effective_discount_cents + tax_cents
    return DocumentTotals(
        subtotal_cents=subtotal_cents,
        tax_cents=tax_cents,
        total_cents=total_cents,
    )


# Largest amount a refund form may name: a signed 64-bit integer of cents, the column's ceiling.
MAX_AMOUNT_CENTS = 2**63 - 1
_MAX_MAJOR_UNIT_DIGITS = 17  # 10**17 major units = 10**19 cents, already past MAX_AMOUNT_CENTS
_CENT_DECIMAL_PLACES = 2
_ONE_CENT = Decimal("0.01")


def parse_major_units_to_cents(text: str) -> int:
    """Parse an operator-typed amount such as ``"60.50"`` into exact, positive cents.

    Refuses rather than rounds: more than two decimal places, a non-positive or non-finite value,
    and anything out of range all raise ``ValueError``. ``int(Decimal(text) * 100)`` truncated
    ``"10.999"`` to 1,099 cents and let ``"100.009"`` pass a 100.00 limit as exactly 10,000.
    """
    try:
        value = Decimal(text.strip())
    except InvalidOperation as error:
        raise ValueError(f"Not an amount: {text!r}") from error
    if not value.is_finite() or value <= 0:
        raise ValueError(f"Not a positive amount: {text!r}")
    # Range first: quantize/scaleb on an exponent like 1E+999999 is slow or overflows.
    if value.adjusted() >= _MAX_MAJOR_UNIT_DIGITS:
        raise ValueError(f"Amount out of range: {text!r}")
    # "10.500" names an exact cent amount; "10.505" does not.
    if value != value.quantize(_ONE_CENT):
        raise ValueError(f"Not a whole number of cents: {text!r}")
    cents = int(value.scaleb(_CENT_DECIMAL_PLACES))
    if cents > MAX_AMOUNT_CENTS:
        raise ValueError(f"Amount out of range: {text!r}")
    return cents
