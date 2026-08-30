"""Promotion release when refund settlement proves a full refund."""

from __future__ import annotations

import uuid
from datetime import timedelta
from decimal import Decimal
from unittest.mock import patch

from django.db import transaction
from django.test import TestCase
from django.utils import timezone

from apps.billing.models import Currency, Invoice, Payment, Refund
from apps.billing.refund_service import (
    RefundConvergenceService,
    RefundData,
    RefundGatewayFacts,
    RefundService,
)
from apps.customers.models import Customer
from apps.orders.models import Order, OrderItem
from apps.orders.services import OrderService, StatusChangeData
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


class PromotionReleaseOnRefundTest(TestCase):
    """Full settlement releases promotions once, without weakening partial refunds."""

    def setUp(self) -> None:
        self.currency, _ = Currency.objects.get_or_create(
            code="RON",
            defaults={"name": "Romanian Leu", "symbol": "lei", "decimals": 2},
        )
        self.customer = Customer.objects.create(
            name="Refund Promotion SRL",
            customer_type="company",
            company_name="Refund Promotion SRL",
            status="active",
            primary_email="refund-promotion@example.test",
        )
        self.product = Product.objects.create(
            name="Refund Promotion Hosting",
            slug="refund-promotion-hosting",
            product_type="shared_hosting",
            is_active=True,
        )
        self.campaign = PromotionCampaign.objects.create(
            name="Refund Promotion Campaign",
            slug="refund-promotion-campaign",
            campaign_type="seasonal",
            start_date=timezone.now() - timedelta(days=1),
            budget_cents=100_000,
            spent_cents=0,
            status="active",
            is_active=True,
        )
        self.coupon = Coupon.objects.create(
            code="REFUND-PROMO",
            name="Refund Promotion Coupon",
            discount_type="percent",
            discount_percent=Decimal("20.00"),
            usage_limit_type="unlimited",
            status="active",
            is_active=True,
            valid_from=timezone.now() - timedelta(minutes=1),
            campaign=self.campaign,
        )
        self.card = GiftCard.objects.create(
            code="REFUND-GIFT-CARD",
            initial_value_cents=10_000,
            current_balance_cents=10_000,
            currency=self.currency,
            status="active",
            is_active=True,
        )

    def _make_order(self, *, invoice: Invoice | None = None) -> Order:
        order = Order.objects.create(
            customer=self.customer,
            currency=self.currency,
            invoice=invoice,
            customer_email=self.customer.primary_email,
            customer_name=self.customer.name,
            subtotal_cents=10_000,
            tax_cents=0,
            total_cents=10_000,
            billing_address={},
        )
        OrderItem.objects.create(
            order=order,
            product=self.product,
            product_name=self.product.name,
            product_type=self.product.product_type,
            billing_period="monthly",
            quantity=1,
            unit_price_cents=10_000,
            setup_cents=0,
            tax_cents=0,
            line_total_cents=10_000,
            config={"billing_period": "monthly"},
        )
        return order

    def _make_invoice(self, *, total_cents: int) -> Invoice:
        return Invoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number=f"INV-{uuid.uuid4().hex[:10]}",
            status="paid",
            subtotal_cents=total_cents,
            tax_cents=0,
            total_cents=total_cents,
            due_at=timezone.now() + timedelta(days=14),
            bill_to_name=self.customer.company_name,
        )

    def _make_payment(
        self,
        *,
        amount_cents: int,
        order: Order | None = None,
        invoice: Invoice | None = None,
        payment_method: str = "bank",
        transaction_id: str | None = None,
    ) -> Payment:
        return Payment.objects.create(
            customer=self.customer,
            currency=self.currency,
            invoice=invoice,
            payment_method=payment_method,
            amount_cents=amount_cents,
            status="succeeded",
            gateway_txn_id=transaction_id,
            meta={"order_id": str(order.pk)} if order is not None else {},
        )

    def _completed_refund(
        self,
        payment: Payment,
        *,
        amount_cents: int,
        reference: str,
        order: Order | None = None,
        invoice: Invoice | None = None,
    ) -> Refund:
        return Refund.objects.create(
            customer=self.customer,
            order=order,
            invoice=invoice,
            payment=payment,
            amount_cents=amount_cents,
            currency=self.currency,
            original_amount_cents=payment.amount_cents,
            refund_type="full" if amount_cents >= payment.amount_cents else "partial",
            status="completed",
            reference_number=reference,
        )

    def _apply_coupon(self, order: Order) -> CouponRedemption:
        result = CouponService.apply_coupon(
            code=self.coupon.code,
            order=order,
            customer=self.customer,
        )
        self.assertTrue(result.success, result.error_message)
        self.assertIsNotNone(result.redemption_id)
        return CouponRedemption.objects.get(pk=result.redemption_id)

    def _redeem_card(self, order: Order, *, amount_cents: int = 3_000) -> None:
        # redeem_gift_card writes through its own locked instance. Refresh first
        # so this fixture never carries a stale balance into a later mutation.
        self.card.refresh_from_db()
        result = GiftCardService.redeem_gift_card(
            code=self.card.code,
            order=order,
            amount_cents=amount_cents,
            customer=self.customer,
        )
        self.assertTrue(result.success, result.error_message)

    @staticmethod
    def _refund_data(amount_cents: int, *, refund_type: str = "full") -> RefundData:
        return {
            "refund_type": refund_type,
            "amount_cents": amount_cents,
            "reason": "customer_request",
            "notes": "Promotion release regression",
        }

    @staticmethod
    def _gateway_facts(payment: Payment, *, refund_id: str) -> RefundGatewayFacts:
        return {
            "refund_id": refund_id,
            "payment_intent_id": str(payment.gateway_txn_id),
            "amount_cents": payment.amount_cents,
            "currency": payment.currency.code.lower(),
            "status": "succeeded",
        }

    def test_full_refund_order_releases_coupon(self) -> None:
        """1. A full order refund reverses coupon and campaign counters."""
        order = self._make_order()
        redemption = self._apply_coupon(order)
        force_status(order, "paid")
        order.refresh_from_db()
        self._make_payment(amount_cents=order.total_cents, order=order)

        result = RefundService.refund_order(
            order.pk,
            self._refund_data(order.total_cents),
        )

        self.assertTrue(result.is_ok(), result.unwrap_err() if result.is_err() else "")
        self.coupon.refresh_from_db()
        self.campaign.refresh_from_db()
        redemption.refresh_from_db()
        self.assertEqual(self.coupon.total_uses, 0)
        self.assertEqual(self.campaign.spent_cents, 0)
        self.assertEqual(redemption.status, "reversed")

    def test_full_refund_order_restores_gift_card(self) -> None:
        """2. A full order refund restores gift-card value and strips its discount."""
        order = self._make_order()
        self._redeem_card(order)
        force_status(order, "paid")
        order.refresh_from_db()
        self._make_payment(amount_cents=order.total_cents, order=order)

        result = RefundService.refund_order(
            order.pk,
            self._refund_data(order.total_cents),
        )

        self.assertTrue(result.is_ok(), result.unwrap_err() if result.is_err() else "")
        self.card.refresh_from_db()
        order.refresh_from_db()
        self.assertEqual(self.card.current_balance_cents, 10_000)
        self.assertEqual(order.discount_cents, 0)
        refund = GiftCardTransaction.objects.get(
            gift_card=self.card,
            order=order,
            transaction_type="refund",
        )
        self.assertEqual(refund.amount_cents, 3_000)
        self.assertEqual(
            refund.description,
            f"Refunded on full refund of order {order.order_number}",
        )

    def test_partial_refund_does_not_release_promotions(self) -> None:
        """3. A partial settlement leaves both promotion ledgers consumed."""
        order = self._make_order()
        redemption = self._apply_coupon(order)
        self._redeem_card(order)
        force_status(order, "paid")
        order.refresh_from_db()
        self._make_payment(amount_cents=order.total_cents, order=order)

        result = RefundService.refund_order(
            order.pk,
            self._refund_data(2_000, refund_type="partial"),
        )

        self.assertTrue(result.is_ok(), result.unwrap_err() if result.is_err() else "")
        self.coupon.refresh_from_db()
        self.campaign.refresh_from_db()
        self.card.refresh_from_db()
        order.refresh_from_db()
        redemption.refresh_from_db()
        self.assertEqual(redemption.status, "applied")
        self.assertEqual(self.coupon.total_uses, 1)
        self.assertEqual(self.campaign.spent_cents, 2_000)
        self.assertEqual(self.card.current_balance_cents, 7_000)
        self.assertEqual(order.discount_cents, 5_000)
        self.assertFalse(
            GiftCardTransaction.objects.filter(
                gift_card=self.card,
                order=order,
                transaction_type="refund",
            ).exists()
        )

    def test_two_partials_release_once_at_full_settlement_flip(self) -> None:
        """4. Two partials summing to the payment release once at the full flip."""
        order = self._make_order()
        self._redeem_card(order)
        force_status(order, "paid")
        order.refresh_from_db()
        payment = self._make_payment(amount_cents=order.total_cents, order=order)

        first = RefundService.refund_order(
            order.pk,
            self._refund_data(2_000, refund_type="partial"),
        )

        self.assertTrue(first.is_ok(), first.unwrap_err() if first.is_err() else "")
        self.card.refresh_from_db()
        self.assertEqual(self.card.current_balance_cents, 7_000)
        self.assertFalse(
            GiftCardTransaction.objects.filter(
                gift_card=self.card,
                order=order,
                transaction_type="refund",
            ).exists()
        )

        second = RefundService.refund_order(
            order.pk,
            self._refund_data(payment.amount_cents - 2_000, refund_type="partial"),
        )

        self.assertTrue(second.is_ok(), second.unwrap_err() if second.is_err() else "")
        self.card.refresh_from_db()
        self.assertEqual(self.card.current_balance_cents, 10_000)
        self.assertEqual(
            GiftCardTransaction.objects.filter(
                gift_card=self.card,
                order=order,
                transaction_type="refund",
            ).count(),
            1,
        )

        payment.refresh_from_db()
        replay = RefundService._project_settled_refunds(payment, None)
        self.assertTrue(replay.is_ok(), replay.unwrap_err() if replay.is_err() else "")
        self.assertEqual(
            GiftCardTransaction.objects.filter(
                gift_card=self.card,
                order=order,
                transaction_type="refund",
            ).count(),
            1,
        )

    def test_gateway_convergence_full_refund_releases_coupon(self) -> None:
        """5. Gateway facts reaching full settlement release invoice promotions."""
        order = self._make_order()
        redemption = self._apply_coupon(order)
        force_status(order, "paid")
        order.refresh_from_db()
        invoice = self._make_invoice(total_cents=order.total_cents)
        order.invoice = invoice
        order.save(update_fields=["invoice", "updated_at"])
        payment = self._make_payment(
            amount_cents=invoice.total_cents,
            invoice=invoice,
            payment_method="stripe",
            transaction_id="pi_promotion_convergence",
        )

        result = RefundConvergenceService.converge_gateway_refund(
            self._gateway_facts(payment, refund_id="re_promotion_convergence")
        )

        self.assertTrue(result.is_ok(), result.unwrap_err() if result.is_err() else "")
        self.coupon.refresh_from_db()
        self.campaign.refresh_from_db()
        redemption.refresh_from_db()
        self.assertEqual(self.coupon.total_uses, 0)
        self.assertEqual(self.campaign.spent_cents, 0)
        self.assertEqual(redemption.status, "reversed")

    def test_duplicate_convergence_replay_does_not_double_credit(self) -> None:
        """6. Replaying identical gateway facts cannot restore gift value twice."""
        order = self._make_order()
        self._redeem_card(order)
        force_status(order, "paid")
        order.refresh_from_db()
        invoice = self._make_invoice(total_cents=order.total_cents)
        order.invoice = invoice
        order.save(update_fields=["invoice", "updated_at"])
        payment = self._make_payment(
            amount_cents=invoice.total_cents,
            invoice=invoice,
            payment_method="stripe",
            transaction_id="pi_promotion_replay",
        )
        facts = self._gateway_facts(payment, refund_id="re_promotion_replay")

        first = RefundConvergenceService.converge_gateway_refund(facts)
        second = RefundConvergenceService.converge_gateway_refund(facts)

        self.assertTrue(first.is_ok(), first.unwrap_err() if first.is_err() else "")
        self.assertTrue(second.is_ok(), second.unwrap_err() if second.is_err() else "")
        self.card.refresh_from_db()
        self.assertEqual(self.card.current_balance_cents, 10_000)
        refunds = GiftCardTransaction.objects.filter(
            gift_card=self.card,
            order=order,
            transaction_type="refund",
        )
        self.assertEqual(refunds.count(), 1)
        self.assertEqual(refunds.get().amount_cents, 3_000)

    def test_refund_then_cancel_does_not_restore_twice(self) -> None:
        """7. Cancellation after refund nets the already-restored ledger to zero."""
        order = self._make_order()
        self._redeem_card(order)
        force_status(order, "paid")
        order.refresh_from_db()
        self._make_payment(amount_cents=order.total_cents, order=order)

        refunded = RefundService.refund_order(
            order.pk,
            self._refund_data(order.total_cents),
        )
        self.assertTrue(refunded.is_ok(), refunded.unwrap_err() if refunded.is_err() else "")
        self.card.refresh_from_db()
        self.assertEqual(self.card.current_balance_cents, 10_000)
        self.assertEqual(
            GiftCardTransaction.objects.filter(
                gift_card=self.card,
                order=order,
                transaction_type="refund",
            ).count(),
            1,
        )
        order.refresh_from_db()

        cancelled = OrderService.update_order_status(
            order,
            StatusChangeData(new_status="cancelled"),
        )

        self.assertTrue(cancelled.is_ok(), cancelled.unwrap_err() if cancelled.is_err() else "")
        self.card.refresh_from_db()
        self.assertEqual(self.card.current_balance_cents, 10_000)
        self.assertEqual(
            GiftCardTransaction.objects.filter(
                gift_card=self.card,
                order=order,
                transaction_type="refund",
            ).count(),
            1,
        )

    def test_coupon_failure_is_contained_and_gift_card_still_releases(self) -> None:
        """8. Coupon failure neither poisons settlement nor skips gift-card release."""
        order = self._make_order()
        redemption = self._apply_coupon(order)
        self._redeem_card(order)
        force_status(order, "paid")
        order.refresh_from_db()
        payment = self._make_payment(amount_cents=order.total_cents, order=order)

        with (
            patch(
                "apps.promotions.services.CouponService.remove_coupon",
                side_effect=RuntimeError("coupon reversal exploded"),
            ),
            patch("apps.audit.services.AuditService.log_simple_event") as audit_log,
        ):
            result = RefundService.refund_order(
                order.pk,
                self._refund_data(order.total_cents),
            )

        self.assertTrue(result.is_ok(), result.unwrap_err() if result.is_err() else "")
        refund = Refund.objects.get(order=order, payment=payment)
        payment.refresh_from_db()
        redemption.refresh_from_db()
        self.card.refresh_from_db()
        order.refresh_from_db()
        self.assertEqual(refund.status, "completed")
        self.assertEqual(payment.status, "refunded")
        self.assertEqual(redemption.status, "applied")
        self.assertEqual(self.card.current_balance_cents, 10_000)
        self.assertEqual(order.discount_cents, 2_000)
        recorded_actions = [
            call.args[0] if call.args else call.kwargs.get("event_type")
            for call in audit_log.call_args_list
        ]
        self.assertIn("coupon_reversal_failed_on_refund", recorded_actions)

    def test_retained_sibling_keeps_invoice_partial_and_promotions_consumed(self) -> None:
        """9. Refunding one of two face-value components cannot release promotions."""
        order = self._make_order()
        redemption = self._apply_coupon(order)
        force_status(order, "paid")
        order.refresh_from_db()
        invoice = self._make_invoice(total_cents=order.total_cents)
        order.invoice = invoice
        order.save(update_fields=["invoice", "updated_at"])
        first_payment = self._make_payment(
            amount_cents=invoice.total_cents // 2,
            invoice=invoice,
        )
        self._make_payment(
            amount_cents=invoice.total_cents // 2,
            invoice=invoice,
        )
        self._completed_refund(
            first_payment,
            amount_cents=first_payment.amount_cents,
            reference="REF-SIBLING-PARTIAL",
            order=order,
        )

        result = RefundService._project_settled_refunds(first_payment, invoice)

        self.assertTrue(result.is_ok(), result.unwrap_err() if result.is_err() else "")
        first_payment.refresh_from_db()
        invoice.refresh_from_db()
        redemption.refresh_from_db()
        self.coupon.refresh_from_db()
        self.assertEqual(first_payment.status, "refunded")
        self.assertEqual(invoice.status, "partially_refunded")
        self.assertEqual(redemption.status, "applied")
        self.assertEqual(self.coupon.total_uses, 1)

    def test_multi_order_invoice_releases_every_order(self) -> None:
        """10. A fully refunded multi-order invoice releases both orders."""
        first_order = self._make_order()
        first_redemption = self._apply_coupon(first_order)
        force_status(first_order, "paid")
        first_order.refresh_from_db()

        second_order = self._make_order()
        second_redemption = self._apply_coupon(second_order)
        force_status(second_order, "paid")
        second_order.refresh_from_db()

        invoice = self._make_invoice(
            total_cents=first_order.total_cents + second_order.total_cents
        )
        for order in (first_order, second_order):
            order.invoice = invoice
            order.save(update_fields=["invoice", "updated_at"])

        payment = self._make_payment(
            amount_cents=invoice.total_cents,
            invoice=invoice,
        )
        self._completed_refund(
            payment,
            amount_cents=payment.amount_cents,
            reference="REF-MULTI-ORDER",
            invoice=invoice,
        )

        result = RefundService._project_settled_refunds(payment, invoice)

        self.assertTrue(result.is_ok(), result.unwrap_err() if result.is_err() else "")
        first_redemption.refresh_from_db()
        second_redemption.refresh_from_db()
        self.coupon.refresh_from_db()
        self.campaign.refresh_from_db()
        self.assertEqual(first_redemption.status, "reversed")
        self.assertEqual(second_redemption.status, "reversed")
        self.assertEqual(self.coupon.total_uses, 0)
        self.assertEqual(self.campaign.spent_cents, 0)

    def test_invoiceless_meta_linked_convergence_releases_exact_order(self) -> None:
        """11. NULL-document convergence uses the order-owned Refund fallback."""
        target_order = self._make_order()
        target_redemption = self._apply_coupon(target_order)
        force_status(target_order, "paid")
        target_order.refresh_from_db()

        unrelated_order = self._make_order()
        unrelated_redemption = self._apply_coupon(unrelated_order)
        force_status(unrelated_order, "paid")

        payment = self._make_payment(
            amount_cents=target_order.total_cents,
            order=target_order,
            payment_method="stripe",
            transaction_id="pi_invoiceless_promotion",
        )

        result = RefundConvergenceService.converge_gateway_refund(
            self._gateway_facts(payment, refund_id="re_invoiceless_promotion")
        )

        self.assertTrue(result.is_ok(), result.unwrap_err() if result.is_err() else "")
        refund = Refund.objects.get(gateway_refund_id="re_invoiceless_promotion")
        target_redemption.refresh_from_db()
        unrelated_redemption.refresh_from_db()
        self.coupon.refresh_from_db()
        self.assertEqual(refund.order_id, target_order.pk)
        self.assertIsNone(refund.invoice_id)
        self.assertEqual(target_redemption.status, "reversed")
        self.assertEqual(unrelated_redemption.status, "applied")
        self.assertEqual(self.coupon.total_uses, 1)

    def test_refund_invoice_releases_linked_order(self) -> None:
        """12. The public invoice refund releases promotions on its linked order."""
        order = self._make_order()
        self._redeem_card(order)
        force_status(order, "paid")
        order.refresh_from_db()
        invoice = self._make_invoice(total_cents=order.total_cents)
        order.invoice = invoice
        order.save(update_fields=["invoice", "updated_at"])
        self._make_payment(amount_cents=invoice.total_cents, invoice=invoice)

        result = RefundService.refund_invoice(
            invoice.pk,
            self._refund_data(invoice.total_cents),
        )

        self.assertTrue(result.is_ok(), result.unwrap_err() if result.is_err() else "")
        self.card.refresh_from_db()
        order.refresh_from_db()
        self.assertEqual(self.card.current_balance_cents, 10_000)
        self.assertEqual(order.discount_cents, 0)
        self.assertEqual(
            GiftCardTransaction.objects.filter(
                gift_card=self.card,
                order=order,
                transaction_type="refund",
            ).count(),
            1,
        )

    def test_settlement_and_release_roll_back_together(self) -> None:
        """13. An outer rollback removes both projection and promotion release."""
        order = self._make_order()
        redemption = self._apply_coupon(order)
        force_status(order, "paid")
        order.refresh_from_db()
        invoice = self._make_invoice(total_cents=order.total_cents)
        order.invoice = invoice
        order.save(update_fields=["invoice", "updated_at"])
        payment = self._make_payment(
            amount_cents=invoice.total_cents,
            invoice=invoice,
        )
        self._completed_refund(
            payment,
            amount_cents=payment.amount_cents,
            reference="REF-ROLLBACK-COUPLING",
            invoice=invoice,
        )

        with transaction.atomic():
            result = RefundService._project_settled_refunds(payment, invoice)
            self.assertTrue(result.is_ok(), result.unwrap_err() if result.is_err() else "")
            redemption.refresh_from_db()
            self.coupon.refresh_from_db()
            self.assertEqual(redemption.status, "reversed")
            self.assertEqual(self.coupon.total_uses, 0)
            transaction.set_rollback(True)

        payment.refresh_from_db()
        invoice.refresh_from_db()
        redemption.refresh_from_db()
        self.coupon.refresh_from_db()
        self.campaign.refresh_from_db()
        self.assertEqual(payment.status, "succeeded")
        self.assertEqual(invoice.status, "paid")
        self.assertEqual(redemption.status, "applied")
        self.assertEqual(self.coupon.total_uses, 1)
        self.assertEqual(self.campaign.spent_cents, 2_000)

    def test_full_refund_composite_rejects_draft_and_cancellation_guard_rejects_live_order(
        self,
    ) -> None:
        """14. Both trigger-specific live-order guards retain promotion value."""
        from apps.promotions.services import release_promotions_for_order  # noqa: PLC0415

        order = self._make_order()
        redemption = self._apply_coupon(order)
        self._redeem_card(order)

        release_promotions_for_order(order, trigger="full_refund")
        cancellation_restored = GiftCardService.release_for_order(
            order,
            trigger="cancellation",
        )

        redemption.refresh_from_db()
        self.coupon.refresh_from_db()
        self.card.refresh_from_db()
        order.refresh_from_db()
        self.assertEqual(cancellation_restored, 0)
        self.assertEqual(redemption.status, "applied")
        self.assertEqual(self.coupon.total_uses, 1)
        self.assertEqual(self.card.current_balance_cents, 7_000)
        self.assertEqual(order.discount_cents, 5_000)
        with self.assertRaises(ValueError):
            release_promotions_for_order(order, trigger="misspelled")

    def test_overpayment_guard_blocks_release_and_audits(self) -> None:
        """15. A retained duplicate payment blocks a face-value invoice release."""
        order = self._make_order()
        redemption = self._apply_coupon(order)
        force_status(order, "paid")
        order.refresh_from_db()
        invoice = self._make_invoice(total_cents=order.total_cents)
        order.invoice = invoice
        order.save(update_fields=["invoice", "updated_at"])
        refunded_payment = self._make_payment(
            amount_cents=invoice.total_cents,
            invoice=invoice,
        )
        sibling = self._make_payment(
            amount_cents=invoice.total_cents,
            invoice=invoice,
        )
        self._completed_refund(
            refunded_payment,
            amount_cents=refunded_payment.amount_cents,
            reference="REF-OVERPAYMENT-GUARD",
            order=order,
        )

        with patch("apps.audit.services.AuditService.log_simple_event") as audit_log:
            result = RefundService._project_settled_refunds(
                refunded_payment,
                invoice,
            )

        self.assertTrue(result.is_ok(), result.unwrap_err() if result.is_err() else "")
        invoice.refresh_from_db()
        redemption.refresh_from_db()
        self.coupon.refresh_from_db()
        self.assertEqual(invoice.status, "refunded")
        self.assertEqual(redemption.status, "applied")
        self.assertEqual(self.coupon.total_uses, 1)
        blocked_calls = [
            call
            for call in audit_log.call_args_list
            if (call.args[0] if call.args else call.kwargs.get("event_type"))
            == "promotion_release_blocked_anomalous_payments"
        ]
        self.assertEqual(len(blocked_calls), 1)
        metadata = blocked_calls[0].kwargs["metadata"]
        self.assertEqual(metadata["payment_id"], str(refunded_payment.pk))
        self.assertEqual(metadata["invoice_id"], str(invoice.pk))
        self.assertEqual(metadata["sibling_payment_ids"], [str(sibling.pk)])
        self.assertTrue(metadata["requires_review"])

    def test_invoice_refund_row_fallback_releases_unlinked_order(self) -> None:
        """16. An order-owned Refund survives the order.invoice linking crash window."""
        order = self._make_order()
        self._redeem_card(order)
        force_status(order, "paid")
        order.refresh_from_db()
        self.assertIsNone(order.invoice_id)
        invoice = self._make_invoice(total_cents=order.total_cents)
        payment = self._make_payment(
            amount_cents=invoice.total_cents,
            invoice=invoice,
        )
        self._completed_refund(
            payment,
            amount_cents=payment.amount_cents,
            reference="REF-ORDER-FALLBACK",
            order=order,
        )

        result = RefundService._project_settled_refunds(payment, invoice)

        self.assertTrue(result.is_ok(), result.unwrap_err() if result.is_err() else "")
        invoice.refresh_from_db()
        order.refresh_from_db()
        self.card.refresh_from_db()
        self.assertEqual(invoice.status, "refunded")
        self.assertIsNone(order.invoice_id)
        self.assertEqual(self.card.current_balance_cents, 10_000)
        self.assertEqual(order.discount_cents, 0)

    def test_single_overpaying_payment_blocks_release_and_audits(self) -> None:
        """17. A partially retained trigger payment blocks promotion release."""
        order = self._make_order()
        redemption = self._apply_coupon(order)
        force_status(order, "paid")
        order.refresh_from_db()
        invoice = self._make_invoice(total_cents=order.total_cents)
        order.invoice = invoice
        order.save(update_fields=["invoice", "updated_at"])
        payment = self._make_payment(
            amount_cents=invoice.total_cents + 5_000,
            invoice=invoice,
        )
        self._completed_refund(
            payment,
            amount_cents=invoice.total_cents,
            reference="REF-OVERPAYING-TRIGGER",
            invoice=invoice,
        )

        with patch("apps.audit.services.AuditService.log_simple_event") as audit_log:
            result = RefundService._project_settled_refunds(payment, invoice)

        self.assertTrue(result.is_ok(), result.unwrap_err() if result.is_err() else "")
        payment.refresh_from_db()
        invoice.refresh_from_db()
        redemption.refresh_from_db()
        self.coupon.refresh_from_db()
        self.assertEqual(payment.status, "partially_refunded")
        self.assertEqual(invoice.status, "refunded")
        self.assertEqual(redemption.status, "applied")
        self.assertEqual(self.coupon.total_uses, 1)
        blocked_calls = [
            call
            for call in audit_log.call_args_list
            if (call.args[0] if call.args else call.kwargs.get("event_type"))
            == "promotion_release_blocked_anomalous_payments"
        ]
        self.assertEqual(len(blocked_calls), 1)
        metadata = blocked_calls[0].kwargs["metadata"]
        self.assertEqual(metadata["sibling_payment_ids"], [str(payment.pk)])
        self.assertTrue(metadata["requires_review"])

    def test_cross_linkage_retained_sibling_blocks_release_and_audits(self) -> None:
        """18. The invoice prong also sees payments linked through order metadata."""
        order = self._make_order()
        redemption = self._apply_coupon(order)
        force_status(order, "paid")
        order.refresh_from_db()
        invoice = self._make_invoice(total_cents=order.total_cents)
        order.invoice = invoice
        order.save(update_fields=["invoice", "updated_at"])
        refunded_payment = self._make_payment(
            amount_cents=invoice.total_cents,
            invoice=invoice,
        )
        retained_payment = self._make_payment(
            amount_cents=5_000,
            order=order,
        )
        self._completed_refund(
            refunded_payment,
            amount_cents=invoice.total_cents,
            reference="REF-CROSS-LINKAGE-GUARD",
            invoice=invoice,
        )

        with patch("apps.audit.services.AuditService.log_simple_event") as audit_log:
            result = RefundService._project_settled_refunds(
                refunded_payment,
                invoice,
            )

        self.assertTrue(result.is_ok(), result.unwrap_err() if result.is_err() else "")
        invoice.refresh_from_db()
        redemption.refresh_from_db()
        self.coupon.refresh_from_db()
        self.assertEqual(invoice.status, "refunded")
        self.assertEqual(redemption.status, "applied")
        self.assertEqual(self.coupon.total_uses, 1)
        blocked_calls = [
            call
            for call in audit_log.call_args_list
            if (call.args[0] if call.args else call.kwargs.get("event_type"))
            == "promotion_release_blocked_anomalous_payments"
        ]
        self.assertEqual(len(blocked_calls), 1)
        metadata = blocked_calls[0].kwargs["metadata"]
        self.assertEqual(metadata["sibling_payment_ids"], [str(retained_payment.pk)])
        self.assertTrue(metadata["requires_review"])

    def test_disputed_payment_blocks_release_and_audits(self) -> None:
        """19. Disputed invoice money blocks promotion release conservatively."""
        order = self._make_order()
        redemption = self._apply_coupon(order)
        force_status(order, "paid")
        order.refresh_from_db()
        invoice = self._make_invoice(total_cents=order.total_cents)
        order.invoice = invoice
        order.save(update_fields=["invoice", "updated_at"])
        refunded_payment = self._make_payment(
            amount_cents=invoice.total_cents,
            invoice=invoice,
        )
        disputed_payment = self._make_payment(
            amount_cents=5_000,
            invoice=invoice,
        )
        force_status(disputed_payment, "disputed")
        self._completed_refund(
            refunded_payment,
            amount_cents=invoice.total_cents,
            reference="REF-DISPUTED-GUARD",
            invoice=invoice,
        )

        with patch("apps.audit.services.AuditService.log_simple_event") as audit_log:
            result = RefundService._project_settled_refunds(
                refunded_payment,
                invoice,
            )

        self.assertTrue(result.is_ok(), result.unwrap_err() if result.is_err() else "")
        invoice.refresh_from_db()
        redemption.refresh_from_db()
        self.coupon.refresh_from_db()
        self.assertEqual(invoice.status, "refunded")
        self.assertEqual(redemption.status, "applied")
        self.assertEqual(self.coupon.total_uses, 1)
        blocked_calls = [
            call
            for call in audit_log.call_args_list
            if (call.args[0] if call.args else call.kwargs.get("event_type"))
            == "promotion_release_blocked_anomalous_payments"
        ]
        self.assertEqual(len(blocked_calls), 1)
        metadata = blocked_calls[0].kwargs["metadata"]
        self.assertEqual(metadata["sibling_payment_ids"], [str(disputed_payment.pk)])
        self.assertTrue(metadata["requires_review"])

    def test_release_retries_when_retained_sibling_later_settles(self) -> None:
        """20. A guard-blocked release fires once every retained payment settles.

        The invoice flips to "refunded" on the first projection and never
        changes again — the sibling's later settlement changes only the
        PAYMENT, so an invoice-flip-only trigger would skip the release
        forever despite all payments ultimately being refunded.
        """
        order = self._make_order()
        redemption = self._apply_coupon(order)
        force_status(order, "paid")
        order.refresh_from_db()
        invoice = self._make_invoice(total_cents=order.total_cents)
        order.invoice = invoice
        order.save(update_fields=["invoice", "updated_at"])
        refunded_payment = self._make_payment(
            amount_cents=invoice.total_cents,
            invoice=invoice,
        )
        sibling = self._make_payment(
            amount_cents=5_000,
            invoice=invoice,
        )
        self._completed_refund(
            refunded_payment,
            amount_cents=invoice.total_cents,
            reference="REF-RETRY-FIRST",
            invoice=invoice,
        )

        blocked = RefundService._project_settled_refunds(refunded_payment, invoice)

        self.assertTrue(blocked.is_ok(), blocked.unwrap_err() if blocked.is_err() else "")
        invoice.refresh_from_db()
        redemption.refresh_from_db()
        self.assertEqual(invoice.status, "refunded")
        self.assertEqual(redemption.status, "applied")

        self._completed_refund(
            sibling,
            amount_cents=sibling.amount_cents,
            reference="REF-RETRY-SIBLING",
            invoice=invoice,
        )

        retried = RefundService._project_settled_refunds(sibling, invoice)

        self.assertTrue(retried.is_ok(), retried.unwrap_err() if retried.is_err() else "")
        sibling.refresh_from_db()
        redemption.refresh_from_db()
        self.coupon.refresh_from_db()
        self.campaign.refresh_from_db()
        self.assertEqual(sibling.status, "refunded")
        self.assertEqual(redemption.status, "reversed")
        self.assertEqual(self.coupon.total_uses, 0)
        self.assertEqual(self.campaign.spent_cents, 0)
