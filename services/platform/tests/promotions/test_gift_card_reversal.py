"""Regression tests for releasing gift-card value from cancelled orders."""

from unittest.mock import MagicMock

from django.contrib import admin
from django.test import TestCase

from apps.billing.models import Currency
from apps.customers.models import Customer
from apps.orders.models import Order, OrderItem
from apps.products.models import Product
from apps.promotions.admin import GiftCardAdmin
from apps.promotions.models import GiftCard, GiftCardTransaction
from apps.promotions.services import GiftCardService
from tests.helpers.fsm_helpers import force_status


class GiftCardReversalTest(TestCase):
    """Gift-card reversals restore ledger-backed outstanding value exactly once."""

    def setUp(self) -> None:
        self.currency, _ = Currency.objects.get_or_create(
            code="RON",
            defaults={"name": "Romanian Leu", "symbol": "lei", "decimals": 2},
        )
        self.customer = Customer.objects.create(
            name="Gift Card Reversal SRL",
            customer_type="company",
            status="active",
            primary_email="gift-card-reversal@test.ro",
        )
        self.product = Product.objects.create(
            name="Gift Card Hosting",
            slug="gift-card-reversal-hosting",
            product_type="shared_hosting",
            is_active=True,
        )
        self.order = self._create_order()
        self.card = self._create_card("REVERSAL-CARD")

    def _create_order(self) -> Order:
        order = Order.objects.create(
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
            order=order,
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
        return order

    def _create_card(self, code: str, initial_value_cents: int = 10000) -> GiftCard:
        return GiftCard.objects.create(
            code=code,
            initial_value_cents=initial_value_cents,
            current_balance_cents=initial_value_cents,
            currency=self.currency,
            status="active",
            is_active=True,
        )

    def _redeem(self, card: GiftCard, order: Order, amount_cents: int) -> None:
        result = GiftCardService.redeem_gift_card(
            code=card.code,
            order=order,
            amount_cents=amount_cents,
            customer=self.customer,
        )
        self.assertTrue(result.success, result.error_message)

    def test_release_restores_balance_records_refund_and_recomputes_partial_status(self) -> None:
        prior_order = self._create_order()
        self._redeem(self.card, prior_order, 6000)
        self._redeem(self.card, self.order, 4000)
        self.card.refresh_from_db()
        self.order.refresh_from_db()
        self.assertEqual(self.card.status, "depleted")
        self.assertEqual(self.order.discount_cents, 4000)
        force_status(self.order, "cancelled")

        restored = GiftCardService.release_for_order(self.order)

        self.assertEqual(restored, 4000)
        self.card.refresh_from_db()
        self.order.refresh_from_db()
        self.assertEqual(self.card.current_balance_cents, 4000)
        self.assertEqual(self.card.status, "partially_used")
        self.assertEqual(self.order.discount_cents, 0)

        refunds = GiftCardTransaction.objects.filter(
            gift_card=self.card,
            order=self.order,
            transaction_type="refund",
        )
        self.assertEqual(refunds.count(), 1)
        refund = refunds.get()
        self.assertEqual(refund.amount_cents, 4000)
        self.assertEqual(refund.balance_after_cents, 4000)
        self.assertEqual(refund.order, self.order)
        self.assertEqual(refund.customer, self.customer)
        self.assertEqual(
            refund.description,
            f"Refunded on cancellation of order {self.order.order_number}",
        )

    def test_release_replay_is_a_noop(self) -> None:
        self._redeem(self.card, self.order, 5000)
        force_status(self.order, "cancelled")

        first_restored = GiftCardService.release_for_order(self.order)
        self.card.refresh_from_db()
        balance_after_first_release = self.card.current_balance_cents
        second_restored = GiftCardService.release_for_order(self.order)

        self.assertEqual(first_restored, 5000)
        self.assertEqual(second_restored, 0)
        self.card.refresh_from_db()
        self.assertEqual(self.card.current_balance_cents, balance_after_first_release)
        self.assertEqual(
            GiftCardTransaction.objects.filter(
                gift_card=self.card,
                order=self.order,
                transaction_type="refund",
            ).count(),
            1,
        )

    def test_release_nets_an_existing_partial_refund(self) -> None:
        self._redeem(self.card, self.order, 5000)

        # redeem_gift_card wrote balance 5000 through ITS OWN locked instance —
        # refresh before mutating, or this write resurrects the stale 10000.
        self.card.refresh_from_db()
        self.card.current_balance_cents += 2000
        self.card.save(update_fields=["current_balance_cents", "updated_at"])
        GiftCardTransaction.objects.create(
            gift_card=self.card,
            transaction_type="refund",
            amount_cents=2000,
            balance_after_cents=self.card.current_balance_cents,
            order=self.order,
            customer=self.customer,
            description="Existing partial refund",
        )
        self.order.discount_cents = 3000
        self.order.save(update_fields=["discount_cents"])
        self.order.calculate_totals()
        force_status(self.order, "cancelled")

        restored = GiftCardService.release_for_order(self.order)

        self.assertEqual(restored, 3000)
        self.card.refresh_from_db()
        self.order.refresh_from_db()
        self.assertEqual(self.card.current_balance_cents, 10000)
        self.assertEqual(self.order.discount_cents, 0)
        refunds = GiftCardTransaction.objects.filter(
            gift_card=self.card,
            order=self.order,
            transaction_type="refund",
        )
        self.assertEqual(refunds.count(), 2)
        self.assertEqual(refunds.filter(amount_cents=3000).count(), 1)

    def test_release_restores_each_card_on_a_multi_card_order(self) -> None:
        second_card = self._create_card("REVERSAL-CARD-TWO", initial_value_cents=7000)
        self._redeem(self.card, self.order, 3000)
        self._redeem(second_card, self.order, 2000)
        force_status(self.order, "cancelled")

        restored = GiftCardService.release_for_order(self.order)

        self.assertEqual(restored, 5000)
        self.card.refresh_from_db()
        second_card.refresh_from_db()
        self.order.refresh_from_db()
        self.assertEqual(self.card.current_balance_cents, 10000)
        self.assertEqual(second_card.current_balance_cents, 7000)
        self.assertEqual(self.order.discount_cents, 0)

        refunds = {
            transaction.gift_card_id: transaction
            for transaction in GiftCardTransaction.objects.filter(
                order=self.order,
                transaction_type="refund",
            )
        }
        self.assertEqual(len(refunds), 2)
        self.assertEqual(refunds[self.card.id].amount_cents, 3000)
        self.assertEqual(refunds[self.card.id].balance_after_cents, 10000)
        self.assertEqual(refunds[second_card.id].amount_cents, 2000)
        self.assertEqual(refunds[second_card.id].balance_after_cents, 7000)

    def test_release_restores_expired_card_balance_without_changing_status(self) -> None:
        self._redeem(self.card, self.order, 5000)
        self.card.status = "expired"
        self.card.save(update_fields=["status", "updated_at"])
        force_status(self.order, "cancelled")

        restored = GiftCardService.release_for_order(self.order)

        self.assertEqual(restored, 5000)
        self.card.refresh_from_db()
        self.assertEqual(self.card.current_balance_cents, 10000)
        self.assertEqual(self.card.status, "expired")

    def test_full_restore_returns_depleted_card_to_active(self) -> None:
        self._redeem(self.card, self.order, 10000)
        self.card.refresh_from_db()
        self.assertEqual(self.card.status, "depleted")
        force_status(self.order, "cancelled")

        restored = GiftCardService.release_for_order(self.order)

        self.assertEqual(restored, 10000)
        self.card.refresh_from_db()
        self.assertEqual(self.card.current_balance_cents, self.card.initial_value_cents)
        self.assertEqual(self.card.status, "active")

    def test_malformed_negative_refund_cannot_inflate_restoration(self) -> None:
        self._redeem(self.card, self.order, 5000)
        self.card.refresh_from_db()
        GiftCardTransaction.objects.create(
            gift_card=self.card,
            transaction_type="refund",
            amount_cents=-2000,
            balance_after_cents=self.card.current_balance_cents,
            order=self.order,
            customer=self.customer,
            description="Malformed legacy refund",
        )
        force_status(self.order, "cancelled")

        restored = GiftCardService.release_for_order(self.order)

        self.assertEqual(restored, 5000)
        self.card.refresh_from_db()
        self.assertEqual(self.card.current_balance_cents, 10000)
        self.assertEqual(
            GiftCardTransaction.objects.filter(
                gift_card=self.card,
                order=self.order,
                transaction_type="refund",
                amount_cents=5000,
            ).count(),
            1,
        )

    def test_release_attributes_refund_to_this_orders_redeemer(self) -> None:
        order_customer = Customer.objects.create(
            name="Second Gift Card Customer SRL",
            customer_type="company",
            status="active",
            primary_email="second-gift-card-customer@test.ro",
        )
        self.order.customer = order_customer
        self.order.customer_email = order_customer.primary_email
        self.order.customer_name = order_customer.name
        self.order.save(update_fields=["customer", "customer_email", "customer_name"])
        self.card.redeemed_by = self.customer
        self.card.save(update_fields=["redeemed_by", "updated_at"])

        result = GiftCardService.redeem_gift_card(
            code=self.card.code,
            order=self.order,
            amount_cents=5000,
            customer=order_customer,
        )
        self.assertTrue(result.success, result.error_message)
        force_status(self.order, "cancelled")

        restored = GiftCardService.release_for_order(self.order)

        self.assertEqual(restored, 5000)
        refund = GiftCardTransaction.objects.get(
            gift_card=self.card,
            order=self.order,
            transaction_type="refund",
        )
        self.assertEqual(refund.customer, order_customer)

    def test_release_on_live_order_is_a_noop(self) -> None:
        self._redeem(self.card, self.order, 5000)

        restored = GiftCardService.release_for_order(self.order)

        self.assertEqual(restored, 0)
        self.card.refresh_from_db()
        self.order.refresh_from_db()
        self.assertEqual(self.card.current_balance_cents, 5000)
        self.assertEqual(self.order.discount_cents, 5000)
        self.assertFalse(
            GiftCardTransaction.objects.filter(
                gift_card=self.card,
                order=self.order,
                transaction_type="refund",
            ).exists()
        )

    def test_full_restore_returns_card_to_active_after_initial_value_is_lowered(self) -> None:
        self._redeem(self.card, self.order, 10000)
        GiftCard.objects.filter(pk=self.card.pk).update(initial_value_cents=8000)
        force_status(self.order, "cancelled")

        restored = GiftCardService.release_for_order(self.order)

        self.assertEqual(restored, 10000)
        self.card.refresh_from_db()
        self.assertEqual(self.card.current_balance_cents, 10000)
        self.assertEqual(self.card.initial_value_cents, 8000)
        self.assertEqual(self.card.status, "active")

    def test_admin_change_does_not_overwrite_concurrent_balance_update(self) -> None:
        stale_card = GiftCard.objects.get(pk=self.card.pk)
        GiftCard.objects.filter(pk=self.card.pk).update(current_balance_cents=7000)
        stale_card.status = "cancelled"
        form = MagicMock()
        form.changed_data = ["status"]

        GiftCardAdmin(GiftCard, admin.site).save_model(
            request=MagicMock(),
            obj=stale_card,
            form=form,
            change=True,
        )

        stale_card.refresh_from_db()
        self.assertEqual(stale_card.status, "cancelled")
        self.assertEqual(stale_card.current_balance_cents, 7000)

    def test_redeem_gift_card_is_rejected_on_cancelled_order(self) -> None:
        force_status(self.order, "cancelled")

        result = GiftCardService.redeem_gift_card(
            code=self.card.code,
            order=self.order,
            amount_cents=5000,
            customer=self.customer,
        )

        self.assertFalse(result.success)
        self.assertEqual(result.error_message, "This order can no longer accept gift cards")
        self.card.refresh_from_db()
        self.order.refresh_from_db()
        self.assertEqual(self.card.current_balance_cents, 10000)
        self.assertEqual(self.card.status, "active")
        self.assertEqual(self.order.discount_cents, 0)
        self.assertEqual(self.order.total_cents, 10000)
        self.assertFalse(
            GiftCardTransaction.objects.filter(
                gift_card=self.card,
                order=self.order,
            ).exists()
        )
