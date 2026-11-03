"""A real pending order refund invalidates the original coverage before settlement."""

import logging
from types import SimpleNamespace
from unittest.mock import MagicMock, patch
from uuid import uuid4

import stripe
from django.core.exceptions import ValidationError
from django.test import TransactionTestCase

from apps.billing.gateways.stripe_gateway import StripeGateway
from apps.billing.plan_change_coverage import invoice_has_paid_coverage
from apps.billing.plan_change_review_models import PlanChangeReviewEvent
from apps.billing.plan_change_review_service import sweep_financial_reviews
from apps.billing.refund_models import Refund
from apps.billing.refund_service import RefundService
from apps.orders.models import Order
from tests.helpers.plan_change_checkout import VerifiedPlanChangeCheckoutFixture


class OrderRefundPlanCoverageTests(VerifiedPlanChangeCheckoutFixture, TransactionTestCase):
    def pending_order_refund(self):
        change = self.quote()
        invoice = self.subscription.billing_cycles.get().invoice
        self.assertTrue(invoice_has_paid_coverage(invoice))
        order = Order.objects.create(
            order_number=f"ORD-REVIEW-{uuid4().hex}",
            customer=self.customer,
            currency=self.currency,
            invoice=invoice,
            status="completed",
            subtotal_cents=invoice.total_cents,
            total_cents=invoice.total_cents,
            customer_email="billing@example.test",
            customer_name=self.customer.company_name,
        )
        payment = invoice.payments.get()
        payment.payment_method, payment.gateway_txn_id = "stripe", "pi_original_order"
        payment.save(update_fields=["payment_method", "gateway_txn_id"])
        sdk = MagicMock()
        sdk.error = stripe.error
        sdk.Refund.create.return_value = SimpleNamespace(id="re_order_pending", amount=1000, status="pending")
        gateway = StripeGateway.__new__(StripeGateway)
        gateway._stripe, gateway.logger = sdk, logging.getLogger("test.plan-refund")
        with patch("apps.billing.gateways.base.PaymentGatewayFactory.create_gateway", return_value=gateway):
            result = RefundService.refund_order(
                order.pk,
                {"refund_type": "partial", "amount_cents": 1000, "reason": "customer_request"},
                actor=self.actor,
            )
        self.assertTrue(result.is_ok(), result)
        sdk.Refund.create.assert_called_once()
        refund = Refund.objects.get(order_id=order.pk)
        self.assertIsNone(refund.invoice_id)
        self.assertEqual(refund.status, "processing")
        payment.refresh_from_db()
        invoice.refresh_from_db()
        self.assertEqual((payment.status, invoice.status), ("succeeded", "paid"))
        return change, invoice, refund

    def test_pending_order_refund_refuses_coverage_before_payment_projection_changes(self) -> None:
        _change, invoice, _refund = self.pending_order_refund()
        with self.assertRaisesRegex(ValidationError, "refund"):
            invoice_has_paid_coverage(invoice)

    def test_pending_refund_journal_reviews_the_change_using_original_interval_evidence(self) -> None:
        change, invoice, refund = self.pending_order_refund()
        event = PlanChangeReviewEvent.objects.get(source_kind="refund", source_id=str(refund.pk))
        self.assertEqual(event.invoice_id, invoice.pk)
        self.assertEqual(sweep_financial_reviews(), 1)
        change.refresh_from_db()
        self.assertEqual(change.status, "paid_review")
        self.assertIn("refund", change.review_reason)
        self.subscription.refresh_from_db()
        self.assertEqual(self.subscription.product_id, self.product.pk)
        self.assertEqual(self.subscription.unit_price_cents, 8000)
