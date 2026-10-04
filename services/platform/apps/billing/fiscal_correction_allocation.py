"""How much a refund credits, and how that amount splits into base, VAT and discount (ADR-0053).

Pure arithmetic, in cents and magnitudes, so every rule here is tested without a database. The
worker reads the ledger, calls these, and writes what they return.

Two questions, answered in order:

1. **How much is owed** (`owed_reduction`). What the refund causes, not what is unpaid. A refund
   that returns money the invoice never needed - an overpayment, a duplicate payment - reduces
   nothing, because what is still held covers everything not yet credited.
2. **How it splits** (`allocate`). The gross is kept exact; the base is derived from it at the
   invoice's single rate from the running total credited so far, and the VAT is the difference,
   clamped jointly so no partial ever credits more base, VAT or discount than the original has
   left. Every split satisfies e-Factura's own BR-CO-14 rule, so a note PRAHO numbers is one ANAF
   accepts; a final remainder that cannot be both exact and valid is made valid, and the cent or
   two of VAT that costs is recorded.
"""

from __future__ import annotations

from dataclasses import dataclass
from decimal import ROUND_HALF_EVEN, Decimal

from .efactura.validator import br_co_14_holds

# Refusal codes. Each leaves the correction `failed` with no allocation written, for a person.
REFUSED_MULTI_RATE_PARTIAL = "multi_rate_partial"
REFUSED_EXCEEDS_REMAINING = "exceeds_remaining"
# How far from the preferred VAT a valid split is looked for, in cents.
_RESIDUE_SEARCH_CENTS = 3


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
    # VAT of the original this correction leaves un-reversed (negative: reverses beyond it). Non-zero
    # only for a final remainder that could not be credited exactly within BR-CO-14.
    vat_residue_cents: int = 0

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


def _nearest_valid_tax(
    gross_cents: int, preferred_tax: int, rate: Decimal, *, max_base: int, max_tax: int
) -> int | None:
    """The VAT closest to `preferred_tax` whose split of `gross_cents` satisfies BR-CO-14.

    Searched outwards a few cents at a time: a valid split always lies within a cent or two of
    `G x r / (1 + r)`, so a wider search would only ever return the same answer later.
    """
    for distance in range(_RESIDUE_SEARCH_CENTS + 1):
        for tax in dict.fromkeys((preferred_tax - distance, preferred_tax + distance)):
            base = gross_cents - tax
            if 0 <= tax <= max_tax and 0 <= base <= max_base and _accepted(base, tax, rate):
                return tax
    return None


def _running_base(credited_gross: int, credited_base: int, gross_cents: int, rate: Decimal) -> int:
    """This correction's base, from the running total of everything credited including it.

    `round_half_even(C / (1 + r))` is taken over the cumulative gross C and the base already
    credited is subtracted, so each note's rounding corrects the one before instead of adding to
    it. Split step by step, the half-cent errors pile up and the rest of the invoice eventually
    states a VAT ANAF refuses.
    """
    cumulative = credited_gross + gross_cents
    return int((Decimal(cumulative) / (1 + rate)).quantize(Decimal(1), rounding=ROUND_HALF_EVEN)) - credited_base


def allocate(
    *,
    gross_cents: int,
    remaining: Components,
    credited: Components,
    rate: Decimal | None,
) -> Allocation:
    """Split `gross_cents` into the base, VAT and discount one credit note credits.

    `credited` is what earlier corrections of the same original already credit, and `remaining`
    what is left of the original.

    * **The whole remainder** takes exactly what is left of each component, so the corrections of
      one invoice add up to it. An original never credited before is mirrored line by line. If what
      is left would state a VAT outside BR-CO-14, the gross is split at the valid VAT nearest to what
      is left instead, and the difference is recorded as `vat_residue_cents` (owner decision,
      ADR-0053): every document stays valid, and the cent or two it costs is visible.
    * **Anything less** is one line at the invoice's single rate, split from the running total
      (`_running_base`); the VAT is the difference, so the gross is exact. Neither part may exceed
      its remainder. A partial carries no discount: the last correction takes the discount left.
    """
    if gross_cents <= 0:
        raise AllocationRefusedError(REFUSED_EXCEEDS_REMAINING, "A correction credits a positive amount.")
    if gross_cents > remaining.total_cents:
        raise AllocationRefusedError(
            REFUSED_EXCEEDS_REMAINING,
            f"{gross_cents} cents exceed the {remaining.total_cents} cents the original has left to credit.",
        )
    untouched = credited == Components(0, 0, 0)

    if gross_cents == remaining.total_cents:
        if untouched or rate is None or _accepted(remaining.base_cents, remaining.tax_cents, rate):
            return Allocation(remaining.base_cents, remaining.tax_cents, remaining.discount_cents, untouched)
        tax = _nearest_valid_tax(gross_cents, remaining.tax_cents, rate, max_base=gross_cents, max_tax=gross_cents)
        if tax is None:  # pragma: no cover - a valid split exists for any positive gross
            raise AllocationRefusedError(REFUSED_EXCEEDS_REMAINING, f"No valid split of {gross_cents} cents.")
        return Allocation(
            gross_cents - tax,
            tax,
            remaining.discount_cents,
            mirrors_original=False,
            vat_residue_cents=remaining.tax_cents - tax,
        )

    if rate is None:
        raise AllocationRefusedError(
            REFUSED_MULTI_RATE_PARTIAL,
            "A partial correction needs one VAT rate; this original has several (or no lines).",
        )

    base = _running_base(credited.total_cents, credited.base_cents, gross_cents, rate)
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
        # Only reachable after a clamp; the running split itself is always within BR-CO-14.
        valid = _nearest_valid_tax(gross_cents, tax, rate, max_base=remaining.base_cents, max_tax=remaining.tax_cents)
        if valid is None:
            raise AllocationRefusedError(
                REFUSED_EXCEEDS_REMAINING,
                f"{gross_cents} cents have no BR-CO-14 split within the remaining base and VAT.",
            )
        tax, base = valid, gross_cents - valid
    return Allocation(base, tax, 0, mirrors_original=False)
