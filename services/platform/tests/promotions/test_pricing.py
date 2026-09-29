"""Exact financial examples for the shared promotion evaluator."""

from decimal import Decimal

from django.test import SimpleTestCase

from apps.promotions.pricing import Offer, PriceLine, evaluate_offers


class PromotionPricingTests(SimpleTestCase):
    def test_bogo_stacks_on_remaining_unit_value(self) -> None:
        result = evaluate_offers(
            [PriceLine("a", 2, 1000, 0, "monthly")],
            [
                Offer("half", "percent", percent=Decimal(50), stackable=True, priority=1),
                Offer("bogo", "bogo", stackable=True, priority=2),
            ],
        )
        self.assertEqual([offer.discount_cents for offer in result.offers], [1000, 500])

    def test_bogo_discounts_cheapest_units_and_keeps_setup_fees(self) -> None:
        lines = [PriceLine("a", 3, 1000, 500, "monthly"), PriceLine("b", 1, 2000, 400, "monthly")]
        result = evaluate_offers(lines, [Offer("bogo", "bogo")])
        self.assertEqual(result.discount_cents, 2000)
        self.assertEqual(result.offers[0].allocations, {"a": 2000})

    def test_tiers_choose_highest_eligible_tier_using_restricted_quantity(self) -> None:
        lines = [PriceLine("a", 4, 1000, 0, "monthly"), PriceLine("b", 20, 1000, 0, "monthly")]
        offer = Offer(
            "tier",
            "tiered",
            eligible_ids=frozenset({"a"}),
            tiers=(
                {"threshold": 2, "threshold_type": "quantity", "percent": "10"},
                {"threshold": 4, "threshold_type": "quantity", "percent": "25"},
                {"threshold": 5, "threshold_type": "quantity", "percent": "50"},
            ),
        )
        result = evaluate_offers(lines, [offer])
        self.assertEqual(result.discount_cents, 1000)
        self.assertEqual(result.offers[0].allocations, {"a": 1000})

    def test_overlapping_stackable_offers_use_remaining_line_amounts(self) -> None:
        lines = [PriceLine("a", 1, 1000, 0, "monthly"), PriceLine("b", 1, 1000, 0, "monthly")]
        result = evaluate_offers(
            lines,
            [
                Offer("one", "percent", percent=Decimal(60), stackable=True, priority=1, eligible_ids=frozenset({"a"})),
                Offer("two", "percent", percent=Decimal(50), stackable=True, priority=2),
            ],
        )
        self.assertEqual([offer.discount_cents for offer in result.offers], [600, 700])
        self.assertEqual(result.offers[1].allocations, {"a": 200, "b": 500})

    def test_entered_nonstackable_coupon_replaces_automatic_offer(self) -> None:
        lines = [PriceLine("a", 1, 1000, 0, "monthly")]
        result = evaluate_offers(
            lines,
            [
                Offer("auto", "percent", percent=Decimal(50), priority=1),
                Offer("code", "percent", percent=Decimal(10), entered=True, priority=100),
            ],
        )
        self.assertEqual([offer.key for offer in result.offers], ["code"])
        self.assertEqual(result.discount_cents, 100)

    def test_free_months_keep_original_value_for_later_renewals(self) -> None:
        lines = [PriceLine("a", 2, 1001, 600, "monthly")]
        result = evaluate_offers(lines, [Offer("months", "free_months", months=3)])
        self.assertEqual(result.discount_cents, 2002)
        self.assertEqual(
            result.offers[0].renewals["a"], {"remaining_cents": 4004, "monthly_cents": "2002", "months": 2}
        )
        self.assertEqual(result.offers[0].committed_cents, 6006)

    def test_offer_over_budget_is_unavailable_instead_of_silently_shrunk(self) -> None:
        result = evaluate_offers(
            [PriceLine("a", 1, 1000, 0, "monthly")],
            [Offer("sale", "fixed", amount_cents=500, budget_available_cents=499)],
        )
        self.assertEqual(result.discount_cents, 0)
        self.assertEqual(result.unavailable, ["sale"])

    def test_rounding_reconciles_to_cents_deterministically(self) -> None:
        lines = [PriceLine(key, 1, 1, 0, "monthly") for key in ("a", "b", "c")]
        result = evaluate_offers(lines, [Offer("half", "percent", percent=Decimal(50))])
        self.assertEqual(result.discount_cents, 2)
        self.assertEqual(sum(result.offers[0].allocations.values()), 2)
