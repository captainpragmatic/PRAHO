"""
Tests for the promotions money defects in #231 and #232.

Both let a customer take more value off an order than the promotion was worth.
"""

from __future__ import annotations

from decimal import Decimal

from django.db import IntegrityError, transaction
from django.test import TestCase
from django.utils import timezone

from apps.billing.models import Currency
from apps.customers.models import Customer
from apps.orders.models import Order, OrderItem
from apps.products.models import Product
from apps.promotions.models import Coupon, CouponRedemption, GiftCard
from apps.promotions.services import CouponService, GiftCardService


class PromotionsMoneyTestCase(TestCase):
    """Shared fixture: a 100.00 RON order with one line item."""

    def setUp(self) -> None:
        self.currency, _ = Currency.objects.get_or_create(
            code="RON", defaults={"name": "Romanian Leu", "symbol": "lei"}
        )
        self.eur, _ = Currency.objects.get_or_create(code="EUR", defaults={"name": "Euro", "symbol": "€"})
        self.customer = Customer.objects.create(
            name="Test Customer",
            customer_type="individual",
            status="active",
        )
        self.product = Product.objects.create(
            slug="shared-hosting",
            name="Shared Hosting",
            product_type="shared_hosting",
        )
        self.order = Order.objects.create(
            customer=self.customer,
            currency=self.currency,
            customer_email="test@example.com",
            customer_name="Test Customer",
            subtotal_cents=10000,  # 100.00 RON
            total_cents=10000,
        )
        self.item = OrderItem.objects.create(
            order=self.order,
            product=self.product,
            product_name="Shared Hosting",
            product_type="shared_hosting",
            billing_period="monthly",
            quantity=1,
            unit_price_cents=10000,
            setup_cents=0,
            line_total_cents=10000,
        )

    def _coupon(self, code: str, percent: str) -> Coupon:
        return Coupon.objects.create(
            code=code,
            name=f"Coupon {code}",
            discount_type="percent",
            discount_percent=Decimal(percent),
            status="active",
            is_active=True,
            is_stackable=True,
            valid_from=timezone.now() - timezone.timedelta(days=1),
        )

    def _prior_redemption(self, *, discount_cents: int, item_ids: list[str]) -> CouponRedemption:
        """Record an already-applied discount on specific items — the state the stacking cap
        reads. #311: the cap measures headroom against prior discounts on the SAME items, so a
        prior discount must be expressed as a redemption tied to those items, not a bare
        order.discount_cents total."""
        prior = self._coupon(f"PRIOR{discount_cents}", "0.00")
        redemption = CouponRedemption.objects.create(
            coupon=prior,
            order=self.order,
            customer=self.customer,
            status="applied",
            discount_type="percent",
            discount_value=Decimal("0"),
            discount_cents=discount_cents,
            currency_code=self.currency.code,
            order_subtotal_cents=self.order.subtotal_cents,
            order_total_cents=self.order.total_cents,
            applied_to_items=item_ids,
        )
        # Mirror onto the order total the way apply_coupon does, but keep it within the
        # non-negative CHECK constraint (a corrupt-negative redemption is exercised in isolation).
        self.order.discount_cents = max(0, (self.order.discount_cents or 0) + discount_cents)
        self.order.save(update_fields=["discount_cents"])
        return redemption


class StackedCouponDiscountTestCase(PromotionsMoneyTestCase):
    """#231: stacked coupons must not discount more than the order is worth.

    Each coupon's discount was computed against the FULL subtotal and capped against the FULL
    subtotal, then accumulated onto order.discount_cents. Two stackable 60% coupons therefore
    summed to 120% of the order — the customer paid nothing and campaign spend was overstated.
    """

    def test_a_single_coupon_discounts_its_own_percentage(self) -> None:
        """Non-regression: the ordinary case is unaffected."""
        result = CouponService.calculate_discount(self._coupon("TEST20", "20.00"), self.order)

        self.assertEqual(result.discount_cents, 2000)

    def test_second_stacked_coupon_is_capped_by_what_is_left(self) -> None:
        """A 60% coupon on the SAME item already 60% discounted can only take the remaining 40%."""
        self._prior_redemption(discount_cents=6000, item_ids=[str(self.item.id)])

        result = CouponService.calculate_discount(self._coupon("SECOND60", "60.00"), self.order)

        self.assertEqual(result.discount_cents, 4000)

    def test_two_stacked_coupons_through_the_real_apply_path(self) -> None:
        """#303 review: the unit tests hand-set discount_cents; this drives apply_coupon
        twice sequentially — lock, calculate, accumulate, persist — and asserts the PERSISTED
        sum through the real path (it is an integration test of the sequential flow, not a
        concurrency test; the lost-update race is tracked separately)."""
        self._coupon("STACK60A", "60.00")
        self._coupon("STACK60B", "60.00")

        first = CouponService.apply_coupon(code="STACK60A", order=self.order, customer=self.customer)
        second = CouponService.apply_coupon(code="STACK60B", order=self.order, customer=self.customer)

        self.assertTrue(first.success, f"first apply failed: {first.error_message}")
        self.assertTrue(second.success, f"second apply failed: {second.error_message}")
        self.order.refresh_from_db()
        self.assertEqual(self.order.discount_cents, 10000)

    def test_negative_stored_discount_is_impossible_and_clamped_in_memory(self) -> None:
        """#303 review: a corrupt negative discount would inflate the cap's headroom past the
        base. The order-level total is DB-excluded (order_discount_non_negative CHECK), and the
        per-redemption subset sum additionally clamps a corrupt negative discount_cents as
        defense-in-depth (#311 moved the cap's input from order.discount_cents to redemptions)."""
        with self.assertRaises(IntegrityError), transaction.atomic():
            Order.objects.filter(pk=self.order.pk).update(discount_cents=-5000)

        # A corrupt negative redemption on this item still must not inflate the cap. A percent
        # coupon cannot exceed its base by construction, so only an oversized FIXED coupon
        # discriminates the clamp: without it, remaining = 10000 - (-5000) = 15000 and the
        # 20000 fixed coupon yields 15000 — over-discounting the base by half.
        self._prior_redemption(discount_cents=-5000, item_ids=[str(self.item.id)])
        oversized = Coupon.objects.create(
            code="FIXED200",
            name="Fixed 200",
            discount_type="fixed",
            discount_amount_cents=20000,
            currency=self.currency,
            status="active",
            is_active=True,
            is_stackable=True,
            valid_from=timezone.now() - timezone.timedelta(days=1),
        )
        result = CouponService.calculate_discount(oversized, self.order)
        self.assertEqual(result.discount_cents, 10000)

    def test_stacked_coupons_never_exceed_the_order_value(self) -> None:
        """The sum of stacked discounts on the same item is bounded by its value — no free order."""
        self._prior_redemption(discount_cents=10000, item_ids=[str(self.item.id)])

        result = CouponService.calculate_discount(self._coupon("EXTRA50", "50.00"), self.order)

        self.assertEqual(result.discount_cents, 0)


class RedemptionOrderTotalTestCase(PromotionsMoneyTestCase):
    """#233: order_total_cents on a redemption must record the total AFTER the discount.

    apply_coupon creates the row with the pre-discount total, then recalculates the order and
    reassigns redemption.order_total_cents to the post-discount total before mark_applied().
    mark_applied() originally omitted order_total_cents from update_fields, so the reassignment
    was never persisted and the row kept the pre-discount total, contradicting the field's
    documented meaning ("Order total after discount").
    """

    def test_order_total_cents_persists_post_discount_total(self) -> None:
        """A 20% coupon on a 100.00 order must store 80.00 as the redemption's order total."""
        self._coupon("SAVE20", "20.00")

        result = CouponService.apply_coupon(code="SAVE20", order=self.order, customer=self.customer)

        self.assertTrue(result.success, f"apply failed: {result.error_message}")
        redemption = CouponRedemption.objects.get(id=result.redemption_id)
        self.order.refresh_from_db()
        # Post-discount total: 10000 - 2000 = 8000. The value must be the PERSISTED one.
        self.assertEqual(redemption.order_total_cents, 8000)
        self.assertEqual(redemption.order_total_cents, self.order.total_cents)


class DisjointCouponStackingTestCase(TestCase):
    """#311: the stacking cap must measure each coupon's headroom against prior discounts on
    ITS OWN targeted items, not the order-wide discount total.

    The #303 cap subtracted the full order.discount_cents from a coupon's targeted-subset base.
    When two coupons target disjoint items (A -> X, B -> Y), B's headroom was
    max(0, Y_base - A_discount_on_X) and B was wrongly zeroed, even though X and Y don't overlap.
    """

    def setUp(self) -> None:
        self.currency, _ = Currency.objects.get_or_create(
            code="RON", defaults={"name": "Romanian Leu", "symbol": "lei"}
        )
        self.customer = Customer.objects.create(
            name="Disjoint Customer",
            customer_type="individual",
            status="active",
        )
        self.product_x = Product.objects.create(slug="prod-x", name="Product X", product_type="shared_hosting")
        self.product_y = Product.objects.create(slug="prod-y", name="Product Y", product_type="vps")
        # 200.00 RON order: item X = 100.00, item Y = 100.00.
        self.order = Order.objects.create(
            customer=self.customer,
            currency=self.currency,
            customer_email="disjoint@example.com",
            customer_name="Disjoint Customer",
            subtotal_cents=20000,
            total_cents=20000,
        )
        self.item_x = OrderItem.objects.create(
            order=self.order,
            product=self.product_x,
            product_name="Product X",
            product_type="shared_hosting",
            billing_period="monthly",
            quantity=1,
            unit_price_cents=10000,
            setup_cents=0,
            line_total_cents=10000,
        )
        self.item_y = OrderItem.objects.create(
            order=self.order,
            product=self.product_y,
            product_name="Product Y",
            product_type="vps",
            billing_period="monthly",
            quantity=1,
            unit_price_cents=10000,
            setup_cents=0,
            line_total_cents=10000,
        )

    def _restricted_coupon(self, code: str, percent: str, product_ids: list[str]) -> Coupon:
        return Coupon.objects.create(
            code=code,
            name=f"Coupon {code}",
            discount_type="percent",
            discount_percent=Decimal(percent),
            status="active",
            is_active=True,
            is_stackable=True,
            applies_to_all_products=False,
            product_restrictions={"product_ids": product_ids},
            valid_from=timezone.now() - timezone.timedelta(days=1),
        )

    def test_disjoint_product_coupons_each_keep_full_value(self) -> None:
        """The #311 bug: A (100% off X) then B (100% off Y) must each discount their own 100.00.

        On unfixed code B's base (Y = 10000) minus the order-wide 10000 from A yields 0, so B is
        wrongly zeroed and the persisted total is 10000 instead of 20000.
        """
        self._restricted_coupon("XONLY", "100.00", [str(self.product_x.id)])
        self._restricted_coupon("YONLY", "100.00", [str(self.product_y.id)])

        first = CouponService.apply_coupon(code="XONLY", order=self.order, customer=self.customer)
        second = CouponService.apply_coupon(code="YONLY", order=self.order, customer=self.customer)

        self.assertTrue(first.success, f"first apply failed: {first.error_message}")
        self.assertTrue(second.success, f"second apply failed: {second.error_message}")
        self.assertEqual(second.discount_cents, 10000, "the disjoint Y coupon must keep its full value")
        self.order.refresh_from_db()
        self.assertEqual(self.order.discount_cents, 20000)

    def test_overlapping_product_coupons_are_still_capped(self) -> None:
        """#303 non-regression: two coupons on the SAME item still can't exceed its value."""
        self._restricted_coupon("X60A", "60.00", [str(self.product_x.id)])
        self._restricted_coupon("X60B", "60.00", [str(self.product_x.id)])

        first = CouponService.apply_coupon(code="X60A", order=self.order, customer=self.customer)
        second = CouponService.apply_coupon(code="X60B", order=self.order, customer=self.customer)

        self.assertTrue(first.success, f"first apply failed: {first.error_message}")
        self.assertTrue(second.success, f"second apply failed: {second.error_message}")
        # X is worth 10000; A took 6000, so B on X is capped to the remaining 4000.
        self.assertEqual(second.discount_cents, 4000)
        self.order.refresh_from_db()
        self.assertEqual(self.order.discount_cents, 10000)

    def test_partial_overlap_only_subtracts_shared_items(self) -> None:
        """A targets {X}; B targets {X, Y}. B can't re-discount X but keeps full Y."""
        self._restricted_coupon("XONLY", "100.00", [str(self.product_x.id)])
        b = self._restricted_coupon("XANDY", "100.00", [str(self.product_x.id), str(self.product_y.id)])

        CouponService.apply_coupon(code="XONLY", order=self.order, customer=self.customer)
        result = CouponService.calculate_discount(b, self.order)

        # B's base = X + Y = 20000; A already took 10000 on X -> B limited to 10000 (the Y value).
        self.assertEqual(result.discount_cents, 10000)

    def test_already_discounted_in_subset_ignores_disjoint_redemptions(self) -> None:
        """Helper-level: a prior redemption on disjoint items consumes no headroom; an
        overlapping one consumes its full discount."""
        CouponRedemption.objects.create(
            coupon=self._restricted_coupon("PX", "0.00", [str(self.product_x.id)]),
            order=self.order,
            customer=self.customer,
            status="applied",
            discount_type="percent",
            discount_value=Decimal("0"),
            discount_cents=7000,
            currency_code="RON",
            order_subtotal_cents=self.order.subtotal_cents,
            order_total_cents=self.order.total_cents,
            applied_to_items=[str(self.item_x.id)],
        )

        disjoint = CouponService._already_discounted_in_subset(self.order, [self.item_y])
        overlapping = CouponService._already_discounted_in_subset(self.order, [self.item_x])

        self.assertEqual(disjoint, 0)
        self.assertEqual(overlapping, 7000)


class GiftCardCurrencyTestCase(PromotionsMoneyTestCase):
    """#232: a gift card must not be redeemed against an order in another currency.

    redeem_gift_card did a bare min() on cents with no currency comparison, so a 100 EUR card
    took 10,000 cents off a RON order — roughly a fifth of its worth. There is no FX conversion
    on this path, so a mismatch is refused rather than guessed. The coupon path already rejects
    exactly this for fixed-amount coupons.
    """

    def _gift_card(self, currency: Currency, balance_cents: int = 10000) -> GiftCard:
        return GiftCard.objects.create(
            code=f"GIFT-{currency.code}",
            initial_value_cents=balance_cents,
            current_balance_cents=balance_cents,
            currency=currency,
            status="active",
        )

    def test_same_currency_gift_card_redeems(self) -> None:
        """Non-regression: a RON card still works on a RON order — and for exact amounts:
        the full 10,000-cent balance covers the 10,000-cent order and is debited once."""
        card = self._gift_card(self.currency)

        result = GiftCardService.redeem_gift_card(code=card.code, order=self.order, customer=self.customer)

        self.assertTrue(result.success, f"redemption failed: {result.error_message}")
        card.refresh_from_db()
        self.assertEqual(card.current_balance_cents, 0)

    def test_foreign_currency_gift_card_is_refused(self) -> None:
        """A EUR card against a RON order applied foreign cents 1:1 — now refused."""
        card = self._gift_card(self.eur)

        result = GiftCardService.redeem_gift_card(code=card.code, order=self.order, customer=self.customer)

        self.assertFalse(result.success)
        self.assertIn("EUR", result.error_message or "")

    def test_refused_redemption_leaves_the_card_balance_untouched(self) -> None:
        """The card must not be debited by a redemption that was refused."""
        card = self._gift_card(self.eur)

        GiftCardService.redeem_gift_card(code=card.code, order=self.order, customer=self.customer)

        card.refresh_from_db()
        self.assertEqual(card.current_balance_cents, 10000)
        self.assertEqual(card.status, "active")
        # The order is equally untouched: no discount, no total change.
        self.order.refresh_from_db()
        self.assertEqual(self.order.total_cents, 10000)


class GiftCardCouponHeadroomTestCase(PromotionsMoneyTestCase):
    """Gift-card redemptions are order-wide value: they must consume headroom
    from EVERY coupon subset (review of #387). The subset-scoped cap read only
    CouponRedemption rows, so a coupon applied AFTER a gift card regained the
    full base and recorded an inflated redemption."""

    def _gift_card(self, balance_cents: int) -> GiftCard:
        return GiftCard.objects.create(
            code=f"GC{balance_cents}",
            initial_value_cents=balance_cents,
            current_balance_cents=balance_cents,
            currency=self.currency,
            status="active",
        )

    def test_coupon_after_gift_card_only_gets_the_remaining_headroom(self) -> None:
        card = self._gift_card(5000)
        redeemed = GiftCardService.redeem_gift_card(code=card.code, order=self.order, customer=self.customer)
        self.assertTrue(redeemed.success, f"gift card redemption failed: {redeemed.error_message}")
        self.order.refresh_from_db()
        self.assertEqual(self.order.discount_cents, 5000)

        coupon = self._coupon("FULLAFTERGC", "100.00")
        result = CouponService.calculate_discount(coupon, self.order, items=[self.item])

        self.assertEqual(
            result.discount_cents,
            5000,
            "a coupon after a gift card must only get the headroom the gift card left",
        )
