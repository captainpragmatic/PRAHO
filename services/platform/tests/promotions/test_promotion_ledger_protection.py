"""Regression tests ensuring promotion ledger rows protect their order."""

from __future__ import annotations

from datetime import timedelta
from decimal import Decimal

from django.db.models import ProtectedError
from django.test import TestCase
from django.utils import timezone

from apps.billing.models import Currency
from apps.customers.models import Customer
from apps.orders.models import Order, OrderItem
from apps.products.models import Product
from apps.promotions.models import (
    Coupon,
    CouponRedemption,
    GiftCard,
    GiftCardTransaction,
    PromotionCampaign,
)
from apps.promotions.services import CouponService, GiftCardService
from tests.helpers.fsm_helpers import force_status


class PromotionLedgerProtectionTest(TestCase):
    """Promotion ledger history must be removed explicitly before an Order purge."""

    def setUp(self) -> None:
        self.currency, _ = Currency.objects.get_or_create(
            code="RON",
            defaults={"name": "Romanian Leu", "symbol": "lei", "decimals": 2},
        )
        self.customer = Customer.objects.create(
            name="Promotion Ledger Protection SRL",
            customer_type="company",
            status="active",
            primary_email="promotion-ledger-protection@test.ro",
        )
        self.product = Product.objects.create(
            name="Promotion Ledger Hosting",
            slug="promotion-ledger-hosting",
            product_type="shared_hosting",
            is_active=True,
        )
        self.order = Order.objects.create(
            customer=self.customer,
            currency=self.currency,
            customer_email=self.customer.primary_email,
            customer_name=self.customer.name,
            subtotal_cents=10000,
            tax_cents=0,
            total_cents=10000,
            billing_address={},
        )
        OrderItem.objects.create(
            order=self.order,
            product=self.product,
            product_name=self.product.name,
            product_type=self.product.product_type,
            quantity=1,
            unit_price_cents=10000,
            setup_cents=0,
            tax_cents=0,
            line_total_cents=10000,
            config={"billing_period": "monthly"},
        )
        self.campaign = PromotionCampaign.objects.create(
            name="Promotion Ledger Campaign",
            slug="promotion-ledger-campaign",
            campaign_type="seasonal",
            start_date=timezone.now() - timedelta(days=1),
            budget_cents=100000,
            spent_cents=0,
            status="active",
            is_active=True,
        )
        self.coupon = Coupon.objects.create(
            code="LEDGER-PROTECT",
            name="Promotion Ledger Protection",
            discount_type="percent",
            discount_percent=Decimal("20.00"),
            status="active",
            is_active=True,
            valid_from=timezone.now(),
            campaign=self.campaign,
        )
        self.card = GiftCard.objects.create(
            code="LEDGER-PROTECT-CARD",
            initial_value_cents=10000,
            current_balance_cents=10000,
            currency=self.currency,
            status="active",
            is_active=True,
        )

    def _apply_coupon(self) -> CouponRedemption:
        result = CouponService.apply_coupon(
            code=self.coupon.code,
            order=self.order,
            customer=self.customer,
        )
        self.assertTrue(result.success, result.error_message)
        self.assertIsNotNone(result.redemption_id)
        return CouponRedemption.objects.get(pk=result.redemption_id)

    def _redeem_gift_card(self, amount_cents: int = 3000) -> GiftCardTransaction:
        result = GiftCardService.redeem_gift_card(
            code=self.card.code,
            order=self.order,
            amount_cents=amount_cents,
            customer=self.customer,
        )
        self.assertTrue(result.success, result.error_message)
        return GiftCardTransaction.objects.get(
            gift_card=self.card,
            order=self.order,
            transaction_type="redemption",
        )

    def test_applied_coupon_redemption_protects_order_and_preserves_counters(self) -> None:
        redemption = self._apply_coupon()
        self.coupon.refresh_from_db()
        self.campaign.refresh_from_db()
        self.assertEqual(self.coupon.total_uses, 1)
        self.assertEqual(self.campaign.spent_cents, 2000)

        with self.assertRaises(ProtectedError):
            self.order.delete()

        self.assertTrue(Order.objects.filter(pk=self.order.pk).exists())
        self.coupon.refresh_from_db()
        self.campaign.refresh_from_db()
        redemption.refresh_from_db()
        self.assertEqual(self.coupon.total_uses, 1)
        self.assertEqual(self.campaign.spent_cents, 2000)
        self.assertEqual(redemption.status, "applied")
        self.assertEqual(redemption.order_id, self.order.pk)

    def test_reversed_coupon_redemption_still_protects_order(self) -> None:
        redemption = self._apply_coupon()
        reversed_count = CouponService.remove_coupon(
            order=self.order,
            redemption_id=str(redemption.pk),
        )
        self.assertEqual(reversed_count, 1)
        redemption.refresh_from_db()
        self.assertEqual(redemption.status, "reversed")

        with self.assertRaises(ProtectedError):
            self.order.delete()

        self.assertTrue(Order.objects.filter(pk=self.order.pk).exists())
        redemption.refresh_from_db()
        self.assertEqual(redemption.status, "reversed")
        self.assertEqual(redemption.order_id, self.order.pk)

    def test_gift_card_transactions_protect_order_and_preserve_balance(self) -> None:
        transaction = self._redeem_gift_card()
        self.card.refresh_from_db()
        self.assertEqual(self.card.current_balance_cents, 7000)

        with self.assertRaises(ProtectedError):
            self.order.delete()

        self.assertTrue(Order.objects.filter(pk=self.order.pk).exists())
        transaction.refresh_from_db()
        self.card.refresh_from_db()
        self.assertEqual(transaction.order_id, self.order.pk)
        self.assertEqual(self.card.current_balance_cents, 7000)
        self.assertEqual(GiftCardTransaction.objects.filter(order=self.order).count(), 1)

    def test_bulk_order_deletion_is_protected_by_both_ledgers(self) -> None:
        redemption = self._apply_coupon()
        transaction = self._redeem_gift_card()

        with self.assertRaises(ProtectedError):
            Order.objects.filter(pk=self.order.pk).delete()

        self.assertTrue(Order.objects.filter(pk=self.order.pk).exists())
        self.assertTrue(CouponRedemption.objects.filter(pk=redemption.pk, order=self.order).exists())
        self.assertTrue(GiftCardTransaction.objects.filter(pk=transaction.pk, order=self.order).exists())

    def test_explicit_ledger_cleanup_allows_order_purge(self) -> None:
        """The escape hatch future purge code must take: reverse, release, then
        delete the ledger rows explicitly, and only then delete the order."""
        redemption = self._apply_coupon()
        self._redeem_gift_card()

        reversed_count = CouponService.remove_coupon(
            order=self.order,
            redemption_id=str(redemption.pk),
        )
        self.assertEqual(reversed_count, 1)
        force_status(self.order, "cancelled")
        self.assertEqual(GiftCardService.release_for_order(self.order), 3000)

        self.coupon.refresh_from_db()
        self.campaign.refresh_from_db()
        self.card.refresh_from_db()
        self.assertEqual(self.coupon.total_uses, 0)
        self.assertEqual(self.campaign.spent_cents, 0)
        self.assertEqual(self.card.current_balance_cents, 10000)

        self.order.coupon_redemptions.all().delete()
        self.order.gift_card_transactions.all().delete()
        order_pk = self.order.pk

        self.order.delete()

        self.assertFalse(Order.objects.filter(pk=order_pk).exists())
