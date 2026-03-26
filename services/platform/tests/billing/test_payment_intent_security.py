"""H18+H19: Payment intent creation must validate order status and enforce idempotency."""
from unittest.mock import MagicMock, patch

from django.test import TestCase

from apps.billing.currency_models import Currency
from apps.billing.models import Payment
from apps.billing.payment_service import PaymentService
from apps.customers.models import Customer
from apps.orders.models import Order


def _create_order(
    customer: Customer, status: str = "draft", total_cents: int = 15000
) -> Order:
    currency, _ = Currency.objects.get_or_create(
        code="RON",
        defaults={"name": "Romanian Leu", "symbol": "lei", "decimals": 2},
    )
    order = Order.objects.create(
        customer=customer,
        currency=currency,
        total_cents=total_cents,
        subtotal_cents=total_cents,
        customer_email="test@example.com",
        customer_name="Test Co",
    )
    # Force status bypassing FSM for test setup
    Order.objects.filter(id=order.id).update(status=status)
    order.refresh_from_db()
    return order


class PaymentIntentStatusGuardTests(TestCase):
    """H18: Payment intents must only be created for payable orders."""

    def setUp(self) -> None:
        self.customer = Customer.objects.create(
            name="PayGuard Co",
            customer_type="company",
            status="active",
            primary_email="pay@test.ro",
        )

    def test_completed_order_rejected(self) -> None:
        order = _create_order(self.customer, status="completed")
        result = PaymentService.create_payment_intent_direct(
            order_id=str(order.id),
            customer_id=str(self.customer.id),
        )
        self.assertFalse(result["success"])
        self.assertIn("completed", result["error"] or "")

    def test_cancelled_order_rejected(self) -> None:
        order = _create_order(self.customer, status="cancelled")
        result = PaymentService.create_payment_intent_direct(
            order_id=str(order.id),
            customer_id=str(self.customer.id),
        )
        self.assertFalse(result["success"])
        self.assertIn("cancelled", result["error"] or "")

    @patch("apps.billing.payment_service.log_security_event", MagicMock())
    @patch("apps.billing.payment_service.PaymentGatewayFactory")
    def test_awaiting_payment_allowed(self, mock_gw_factory: MagicMock) -> None:
        mock_gw = MagicMock()
        mock_gw.create_payment_intent.return_value = {
            "success": True,
            "payment_intent_id": "pi_ok",
            "client_secret": "sec_ok",
        }
        mock_gw_factory.create_gateway.return_value = mock_gw

        order = _create_order(self.customer, status="awaiting_payment", total_cents=25000)
        result = PaymentService.create_payment_intent_direct(
            order_id=str(order.id),
            customer_id=str(self.customer.id),
        )
        self.assertTrue(result["success"])


class PaymentIntentIdempotencyTests(TestCase):
    """H19: Duplicate payment intent creation must be prevented."""

    def setUp(self) -> None:
        self.customer = Customer.objects.create(
            name="Idem Co",
            customer_type="company",
            status="active",
            primary_email="idem@test.ro",
        )

    @patch("apps.billing.payment_service.log_security_event", MagicMock())
    @patch("apps.billing.payment_service.PaymentGatewayFactory")
    def test_duplicate_call_returns_existing_not_new(self, mock_gw_factory: MagicMock) -> None:
        mock_gw = MagicMock()
        mock_gw.create_payment_intent.return_value = {
            "success": True,
            "payment_intent_id": "pi_first",
            "client_secret": "sec_first",
        }
        mock_gw_factory.create_gateway.return_value = mock_gw

        order = _create_order(self.customer, status="awaiting_payment", total_cents=25000)

        result1 = PaymentService.create_payment_intent_direct(
            order_id=str(order.id),
            customer_id=str(self.customer.id),
        )
        self.assertTrue(result1["success"])

        result2 = PaymentService.create_payment_intent_direct(
            order_id=str(order.id),
            customer_id=str(self.customer.id),
        )
        # Second call should also succeed (returning the cached intent)
        self.assertTrue(result2["success"])

        # Should have exactly 1 pending payment, not 2
        pending_count = Payment.objects.filter(
            customer=self.customer,
            status="pending",
        ).count()
        self.assertEqual(
            pending_count,
            1,
            "Should have exactly 1 pending payment, not duplicates",
        )
