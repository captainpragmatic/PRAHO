"""The arithmetic of a built-in credit note: how much a refund credits, and how it splits.

Pure functions, so each rule is pinned without a ledger. The worked examples and sequences are the
ones ADR-0053 (plan v3, items 1 and 4) was reviewed against.
"""

from __future__ import annotations

from decimal import Decimal

from django.test import SimpleTestCase

from apps.billing.efactura.validator import br_co_14_holds
from apps.billing.fiscal_correction_allocation import (
    REFUSED_EXCEEDS_REMAINING,
    REFUSED_MULTI_RATE_PARTIAL,
    REFUSED_VAT_ROUNDING,
    Allocation,
    AllocationRefusedError,
    Components,
    allocate,
    owed_reduction,
)

RATE = Decimal("0.21")
# 121.00 gross at 21%: base 100.00, VAT 21.00.
INVOICE_121 = Components(base_cents=10000, tax_cents=2100, discount_cents=0)


def _sequence(original: Components, grosses: list[int]) -> tuple[list[Allocation], Components]:
    """Allocate each gross in turn against what the previous ones left."""
    remaining = original
    allocations = []
    for gross in grosses:
        allocation = allocate(gross_cents=gross, remaining=remaining, rate=RATE, untouched=remaining == original)
        allocations.append(allocation)
        remaining = remaining.minus(Components(allocation.base_cents, allocation.tax_cents, allocation.discount_cents))
    return allocations, remaining


class OwedReductionTests(SimpleTestCase):
    """The amount owed is caused by the refund, not by whatever is unpaid (plan v3 item 1)."""

    def test_a_refund_of_money_actually_kept_credits_all_of_it(self) -> None:
        # Invoice 100, 40 collected, 10 refunded: 10.
        self.assertEqual(
            owed_reduction(refund_cents=1000, net_collected_before_cents=4000, remaining_total_cents=10000), 1000
        )

    def test_returning_an_overpayment_credits_nothing(self) -> None:
        # Invoice 100, 120 collected, 20 refunded: 0.
        self.assertEqual(
            owed_reduction(refund_cents=2000, net_collected_before_cents=12000, remaining_total_cents=10000), 0
        )

    def test_only_what_goes_beyond_the_overpayment_is_credited(self) -> None:
        # Invoice 100, 120 collected, 30 refunded: 10.
        self.assertEqual(
            owed_reduction(refund_cents=3000, net_collected_before_cents=12000, remaining_total_cents=10000), 1000
        )

    def test_nothing_is_credited_past_what_remains(self) -> None:
        self.assertEqual(
            owed_reduction(refund_cents=5000, net_collected_before_cents=3000, remaining_total_cents=3000), 3000
        )


class AllocationTests(SimpleTestCase):
    def test_an_unrepresentable_gross_stays_exact(self) -> None:
        """10.00 at 21%: no base yields exactly 10.00 through `base x 1.21`, so the VAT is the
        difference. A line recomputed from the base (826 -> 173) would credit 9.99."""
        allocation = allocate(gross_cents=1000, remaining=INVOICE_121, rate=RATE, untouched=True)

        self.assertEqual((allocation.base_cents, allocation.tax_cents, allocation.total_cents), (826, 174, 1000))
        self.assertTrue(br_co_14_holds(Decimal("8.26"), Decimal("1.74"), Decimal("21")))

    def test_three_partials_never_credit_more_vat_than_the_original_holds(self) -> None:
        """30.00, 40.02, 50.97 against 121.00. The third's own split (4212 + 885) would take one
        cent more VAT than is left (884), so the VAT takes exactly what is left and the base is the
        difference: the clamp works in both directions."""
        allocations, remaining = _sequence(INVOICE_121, [3000, 4002, 5097])

        self.assertEqual(
            [(a.base_cents, a.tax_cents) for a in allocations],
            [(2479, 521), (3307, 695), (4213, 884)],
        )
        self.assertEqual([a.total_cents for a in allocations], [3000, 4002, 5097])
        self.assertEqual(remaining, Components(base_cents=1, tax_cents=0, discount_cents=0))
        for allocation in allocations:
            self.assertTrue(
                br_co_14_holds(Decimal(allocation.base_cents) / 100, Decimal(allocation.tax_cents) / 100, Decimal(21))
            )

    def test_four_partials_clamp_the_base_and_leave_a_creditable_cent(self) -> None:
        """31.43, 31.43, 29.01, 29.12 against 121.00. The fourth's own split (2407 + 505) would take
        one cent more base than is left (2406), so the base takes exactly what is left."""
        allocations, remaining = _sequence(INVOICE_121, [3143, 3143, 2901, 2912])

        self.assertEqual(
            [(a.base_cents, a.tax_cents) for a in allocations],
            [(2598, 545), (2598, 545), (2398, 503), (2406, 506)],
        )
        self.assertEqual(remaining, Components(base_cents=0, tax_cents=1, discount_cents=0))
        last = allocate(gross_cents=1, remaining=remaining, rate=RATE, untouched=False)
        self.assertEqual((last.base_cents, last.tax_cents), (0, 1))

    def test_a_remainder_left_outside_br_co_14_is_refused_rather_than_issued(self) -> None:
        """After 31.43, 31.43 and 29.01, the whole remainder is base 24.06 with VAT 5.07, two cents
        from 24.06 x 21% = 5.05. ANAF would refuse that 381, so it is refused here, before a number
        is spent. The partial formula of plan v3 leaves this residue; whether to steer earlier
        partials away from it is an owner decision, recorded in ADR-0053."""
        _allocations, remaining = _sequence(INVOICE_121, [3143, 3143, 2901])
        self.assertEqual(remaining, Components(base_cents=2406, tax_cents=507, discount_cents=0))

        with self.assertRaises(AllocationRefusedError) as refused:
            allocate(gross_cents=remaining.total_cents, remaining=remaining, rate=RATE, untouched=False)
        self.assertEqual(refused.exception.code, REFUSED_VAT_ROUNDING)

    def test_a_later_full_refund_takes_exactly_what_is_left(self) -> None:
        """30 then 91 against 121: the second is -91, never another -121."""
        first = allocate(gross_cents=3000, remaining=INVOICE_121, rate=RATE, untouched=True)
        remaining = INVOICE_121.minus(Components(first.base_cents, first.tax_cents, 0))
        second_gross = owed_reduction(
            refund_cents=9100, net_collected_before_cents=12100 - 3000, remaining_total_cents=remaining.total_cents
        )

        second = allocate(gross_cents=second_gross, remaining=remaining, rate=RATE, untouched=False)

        self.assertEqual((first.total_cents, second.total_cents), (3000, 9100))
        self.assertEqual((first.base_cents + second.base_cents, first.tax_cents + second.tax_cents), (10000, 2100))
        self.assertFalse(second.mirrors_original)

    def test_a_discounted_original_keeps_its_discount_for_the_last_correction(self) -> None:
        """Lines 100.00, discount 10.00, base 90.00, VAT 18.90. A partial carries no discount; the
        remainder takes the whole of it, so the notes add up to the original component by component."""
        original = Components(base_cents=9000, tax_cents=1890, discount_cents=1000)

        partial = allocate(gross_cents=5000, remaining=original, rate=RATE, untouched=True)
        remaining = original.minus(Components(partial.base_cents, partial.tax_cents, partial.discount_cents))
        rest = allocate(gross_cents=remaining.total_cents, remaining=remaining, rate=RATE, untouched=False)

        self.assertEqual((partial.base_cents, partial.tax_cents, partial.discount_cents), (4132, 868, 0))
        self.assertEqual((rest.base_cents, rest.tax_cents, rest.discount_cents), (4868, 1022, 1000))

    def test_vat_summed_from_rounded_lines_is_credited_exactly(self) -> None:
        """Three lines of 33.33 at 21% each round to 7.00, so the header VAT (21.00) is not 21% of the
        header base (99.99 -> 20.9979). The corrections still sum to the header's own components."""
        original = Components(base_cents=9999, tax_cents=2100, discount_cents=0)

        allocations, remaining = _sequence(original, [5000, 7099])

        self.assertEqual(remaining, Components(0, 0, 0))
        self.assertEqual(sum(a.tax_cents for a in allocations), 2100)
        self.assertEqual(sum(a.base_cents for a in allocations), 9999)

    def test_an_untouched_original_corrected_in_full_is_mirrored(self) -> None:
        allocation = allocate(gross_cents=12100, remaining=INVOICE_121, rate=RATE, untouched=True)

        self.assertTrue(allocation.mirrors_original)
        self.assertEqual((allocation.base_cents, allocation.tax_cents), (10000, 2100))

    def test_a_partial_of_a_multi_rate_original_is_refused_but_a_full_one_is_mirrored(self) -> None:
        with self.assertRaises(AllocationRefusedError) as refused:
            allocate(gross_cents=1000, remaining=INVOICE_121, rate=None, untouched=True)
        self.assertEqual(refused.exception.code, REFUSED_MULTI_RATE_PARTIAL)

        self.assertTrue(allocate(gross_cents=12100, remaining=INVOICE_121, rate=None, untouched=True).mirrors_original)

    def test_more_than_remains_is_refused(self) -> None:
        with self.assertRaises(AllocationRefusedError) as refused:
            allocate(gross_cents=12101, remaining=INVOICE_121, rate=RATE, untouched=True)
        self.assertEqual(refused.exception.code, REFUSED_EXCEEDS_REMAINING)
