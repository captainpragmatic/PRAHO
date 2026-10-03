"""How much a refund credits, and how that amount splits into base, VAT and discount (ADR-0053).

Pure arithmetic, in cents and magnitudes, so every rule here is tested without a database. The
worker reads the ledger, calls these, and writes what they return.

Two questions, answered in order:

1. **How much is owed** (`owed_reduction`). What the refund causes, not what is unpaid. A refund
   that returns money the invoice never needed - an overpayment, a duplicate payment - reduces
   nothing, because what is still held covers everything not yet credited.
2. **How it splits** (`allocate`). The gross is kept exact; the base is derived from it at the
   invoice's single rate and the VAT is the difference, clamped jointly so no correction ever
   credits more base, VAT or discount than the original has left. The amount is then checked
   against e-Factura's own BR-CO-14 rule, so a note PRAHO numbers is one ANAF accepts.
"""

from __future__ import annotations

from dataclasses import dataclass
from decimal import ROUND_HALF_EVEN, Decimal

from .efactura.validator import br_co_14_holds

# Refusal codes. Each leaves the correction `failed` with no allocation written, for a person.
REFUSED_MULTI_RATE_PARTIAL = "multi_rate_partial"
REFUSED_EXCEEDS_REMAINING = "exceeds_remaining"
REFUSED_VAT_ROUNDING = "vat_outside_br_co_14"


class AllocationRefusedError(ValueError):
    """The amount cannot be allocated within what the original has left, or not acceptably."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class Components:
    """A document's base, VAT and discount as magnitudes; the gross is base plus VAT."""

    base_cents: int
    tax_cents: int
    discount_cents: int

    @property
    def total_cents(self) -> int:
        return self.base_cents + self.tax_cents

    def minus(self, other: Components) -> Components:
        return Components(
            self.base_cents - other.base_cents,
            self.tax_cents - other.tax_cents,
            self.discount_cents - other.discount_cents,
        )


@dataclass(frozen=True)
class Allocation:
    """What one credit note credits. `mirrors_original` means the note copies its lines."""

    base_cents: int
    tax_cents: int
    discount_cents: int
    mirrors_original: bool

    @property
    def total_cents(self) -> int:
        return self.base_cents + self.tax_cents


def owed_reduction(*, refund_cents: int, net_collected_before_cents: int, remaining_total_cents: int) -> int:
    """The gross this refund takes off the invoice, given what was held just before it.

    `slack` is what was held above what the invoice still asks for (its total less the credits
    already decided). A refund first returns that slack, which changes nothing fiscal; only the
    rest reduces the invoice, and never by more than remains to credit.
    """
    remaining = max(0, remaining_total_cents)
    slack = max(0, net_collected_before_cents - remaining)
    return min(max(0, refund_cents - slack), remaining)


def _accepted(base_cents: int, tax_cents: int, rate: Decimal) -> bool:
    """BR-CO-14 at the given rate. A zero rate is acceptable only with zero VAT."""
    if rate == 0:
        return tax_cents == 0
    return br_co_14_holds(Decimal(base_cents) / 100, Decimal(tax_cents) / 100, rate * 100)


def allocate(
    *,
    gross_cents: int,
    remaining: Components,
    rate: Decimal | None,
    untouched: bool,
) -> Allocation:
    """Split `gross_cents` into the base, VAT and discount one credit note credits.

    * **The whole remainder** takes exactly what is left of each component, so the corrections of
      one invoice always add up to it. An original never credited before is mirrored line by line.
    * **Anything less** is one line at the invoice's single rate `rate`: the base is
      `round_half_even(G / (1 + r))` and the VAT is `G - base`, so the gross is exact. If either
      part exceeds what is left of it, that part takes exactly what is left and the other is the
      difference; if the other then exceeds its own remainder, the amount cannot be credited and is
      refused. A partial credit carries no discount: the last correction takes the discount left.

    Every allocation except a mirror is checked against BR-CO-14. A mirror restates the original
    line by line, so it is exactly as acceptable as the original was.
    """
    if gross_cents <= 0:
        raise AllocationRefusedError(REFUSED_EXCEEDS_REMAINING, "A correction credits a positive amount.")
    if gross_cents > remaining.total_cents:
        raise AllocationRefusedError(
            REFUSED_EXCEEDS_REMAINING,
            f"{gross_cents} cents exceed the {remaining.total_cents} cents the original has left to credit.",
        )

    if gross_cents == remaining.total_cents:
        allocation = Allocation(remaining.base_cents, remaining.tax_cents, remaining.discount_cents, untouched)
        if not untouched and rate is not None and not _accepted(allocation.base_cents, allocation.tax_cents, rate):
            raise AllocationRefusedError(
                REFUSED_VAT_ROUNDING,
                f"The remaining VAT {allocation.tax_cents} is outside BR-CO-14 for the remaining base "
                f"{allocation.base_cents} at {rate}; earlier partial credits left a residue ANAF would refuse.",
            )
        return allocation

    if rate is None:
        raise AllocationRefusedError(
            REFUSED_MULTI_RATE_PARTIAL,
            "A partial correction needs one VAT rate; this original has several (or no lines).",
        )

    base = int((Decimal(gross_cents) / (1 + rate)).quantize(Decimal(1), rounding=ROUND_HALF_EVEN))
    tax = gross_cents - base
    if base > remaining.base_cents:
        base = remaining.base_cents
        tax = gross_cents - base
    elif tax > remaining.tax_cents:
        tax = remaining.tax_cents
        base = gross_cents - tax
    if not (0 <= base <= remaining.base_cents and 0 <= tax <= remaining.tax_cents):
        raise AllocationRefusedError(
            REFUSED_EXCEEDS_REMAINING,
            f"{gross_cents} cents cannot be split within the remaining base {remaining.base_cents} "
            f"and VAT {remaining.tax_cents}.",
        )
    if not _accepted(base, tax, rate):
        raise AllocationRefusedError(
            REFUSED_VAT_ROUNDING,
            f"VAT {tax} on base {base} at {rate} is outside BR-CO-14 after clamping to what remains.",
        )
    return Allocation(base, tax, 0, mirrors_original=False)
