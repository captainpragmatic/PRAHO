"""
Tests for the promotions money defects in #231 and #232.

Both let a customer take more value off an order than the promotion was worth.
"""

from __future__ import annotations

from decimal import Decimal

from django.test import TestCase
from django.utils import timezone

from apps.billing.models import Currency
from apps.customers.models import Customer
from apps.orders.models import Order, OrderItem
from apps.products.models import Product
from apps.promotions.models import Coupon, GiftCard
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
        OrderItem.objects.create(
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
        """A 60% coupon on an order already 60% discounted can only take the remaining 40%."""
        self.order.discount_cents = 6000  # a 60% coupon already applied
        self.order.save(update_fields=["discount_cents"])

        result = CouponService.calculate_discount(self._coupon("SECOND60", "60.00"), self.order)

        self.assertEqual(result.discount_cents, 4000)

    def test_stacked_coupons_never_exceed_the_order_value(self) -> None:
        """The sum of stacked discounts is bounded by the subtotal — no free order."""
        self.order.discount_cents = 10000  # fully discounted already
        self.order.save(update_fields=["discount_cents"])

        result = CouponService.calculate_discount(self._coupon("EXTRA50", "50.00"), self.order)

        self.assertEqual(result.discount_cents, 0)


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
        """Non-regression: a RON card still works on a RON order."""
        card = self._gift_card(self.currency)

        result = GiftCardService.redeem_gift_card(code=card.code, order=self.order, customer=self.customer)

        self.assertTrue(result.success, f"redemption failed: {result.error_message}")

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
