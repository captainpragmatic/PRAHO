"""
Tests for apps.billing.payment_service.PaymentService

Covers all static methods with success, failure, and edge-case branches.
"""

from __future__ import annotations

import uuid
from typing import Any
from unittest.mock import MagicMock, patch

from django.test import TestCase, override_settings

from apps.billing.currency_models import Currency
from apps.billing.gateways.base import PaymentConfirmResult, PaymentIntentResult, SubscriptionResult
from apps.billing.models import Payment
from apps.billing.payment_service import PaymentService
from apps.orders.models import Order
from tests.factories.billing_factories import create_currency, create_customer

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _pi_result(
    success: bool = True,
    pi_id: str = "pi_test123",
    client_secret: str | None = "tok_xyz",  # noqa: S107 - not a real credential
    error: str | None = None,
) -> PaymentIntentResult:
    return PaymentIntentResult(success=success, payment_intent_id=pi_id, client_secret=client_secret, error=error)


def _confirm_result(
    success: bool = True, status: str = "succeeded", error: str | None = None
) -> PaymentConfirmResult:
    return PaymentConfirmResult(success=success, status=status, error=error)


def _sub_result(
    success: bool = True,
    sub_id: str | None = "sub_abc",
    status: str | None = "active",
    error: str | None = None,
) -> SubscriptionResult:
    return SubscriptionResult(success=success, subscription_id=sub_id, status=status, error=error)


def _make_mock_gateway(
    pi_result: PaymentIntentResult | None = None,
    confirm_result: PaymentConfirmResult | None = None,
    sub_result: SubscriptionResult | None = None,
) -> MagicMock:
    gw = MagicMock()
    gw.create_payment_intent.return_value = pi_result if pi_result is not None else _pi_result()
    gw.confirm_payment.return_value = confirm_result if confirm_result is not None else _confirm_result()
    gw.create_subscription.return_value = sub_result if sub_result is not None else _sub_result()
    return gw


def _make_order(customer: Any, currency_code: str = "RON", total_cents: int = 15000) -> Order:
    """Create a minimal Order for testing."""
    currency, _ = Currency.objects.get_or_create(
        code=currency_code,
        defaults={"name": currency_code, "symbol": currency_code, "decimals": 2},
    )
    return Order.objects.create(
        customer=customer,
        currency=currency,
        total_cents=total_cents,
        subtotal_cents=total_cents,
        customer_email=customer.name.lower().replace(" ", "") + "@example.com",
        customer_name=customer.name,
    )


# ---------------------------------------------------------------------------
# create_payment_intent
# ---------------------------------------------------------------------------


class CreatePaymentIntentTests(TestCase):
    """Tests for PaymentService.create_payment_intent."""

    def setUp(self) -> None:
        self.customer = create_customer("Intent Co SRL")
        self.order = _make_order(self.customer)

    @patch("apps.billing.payment_service.log_security_event")
    @patch("apps.billing.payment_service.PaymentGatewayFactory.create_gateway")
    def test_success_creates_payment_record(self, mock_create_gw: MagicMock, mock_log: MagicMock) -> None:
        mock_create_gw.return_value = _make_mock_gateway()

        result = PaymentService.create_payment_intent(str(self.order.id))

        self.assertTrue(result["success"])
        self.assertEqual(result["payment_intent_id"], "pi_test123")

        payment = Payment.objects.get(gateway_txn_id="pi_test123")
        self.assertEqual(payment.status, "pending")
        self.assertEqual(payment.amount_cents, self.order.total_cents)
        self.assertEqual(payment.customer, self.customer)
        mock_log.assert_called_once()

    @patch("apps.billing.payment_service.PaymentGatewayFactory.create_gateway")
    def test_order_does_not_exist_returns_failure(self, mock_create_gw: MagicMock) -> None:
        missing_id = str(uuid.uuid4())

        result = PaymentService.create_payment_intent(missing_id)

        self.assertFalse(result["success"])
        self.assertIn(missing_id, result["error"])
        mock_create_gw.assert_not_called()

    @patch("apps.billing.payment_service.PaymentGatewayFactory.create_gateway")
    def test_gateway_returns_failure_no_payment_created(self, mock_create_gw: MagicMock) -> None:
        mock_create_gw.return_value = _make_mock_gateway(
            pi_result=_pi_result(success=False, pi_id="", client_secret=None, error="Card declined")
        )

        result = PaymentService.create_payment_intent(str(self.order.id))

        self.assertFalse(result["success"])
        self.assertEqual(Payment.objects.count(), 0)

    @patch("apps.billing.payment_service.PaymentGatewayFactory.create_gateway")
    def test_generic_exception_returns_failure(self, mock_create_gw: MagicMock) -> None:
        mock_create_gw.side_effect = RuntimeError("Network timeout")

        result = PaymentService.create_payment_intent(str(self.order.id))

        self.assertFalse(result["success"])
        self.assertIn("Payment creation failed", result["error"])

    @patch("apps.billing.payment_service.log_security_event")
    @patch("apps.billing.payment_service.PaymentGatewayFactory.create_gateway")
    def test_passes_metadata_to_gateway(self, mock_create_gw: MagicMock, mock_log: MagicMock) -> None:
        gw = _make_mock_gateway()
        mock_create_gw.return_value = gw

        PaymentService.create_payment_intent(
            str(self.order.id), gateway="stripe", metadata={"custom_key": "custom_value"}
        )

        call_kwargs = gw.create_payment_intent.call_args[1]
        self.assertIn("custom_key", call_kwargs["metadata"])
        self.assertEqual(call_kwargs["metadata"]["platform"], "PRAHO")


# ---------------------------------------------------------------------------
# create_payment_intent_direct
# ---------------------------------------------------------------------------


class CreatePaymentIntentDirectTests(TestCase):
    """Tests for PaymentService.create_payment_intent_direct."""

    def setUp(self) -> None:
        self.customer = create_customer("Direct Co SRL")
        self.order = _make_order(self.customer, total_cents=5000)

    @patch("apps.billing.payment_service.log_security_event")
    @patch("apps.billing.payment_service.PaymentGatewayFactory.create_gateway")
    def test_success_with_known_customer(self, mock_create_gw: MagicMock, mock_log: MagicMock) -> None:
        mock_create_gw.return_value = _make_mock_gateway()
        create_currency("RON")

        result = PaymentService.create_payment_intent_direct(
            order_id=str(self.order.id),
            amount_cents=self.order.total_cents,
            currency="RON",
            customer_id=str(self.customer.id),
            order_number="ORD-DIRECT-001",
        )

        self.assertTrue(result["success"])
        payment = Payment.objects.get(gateway_txn_id="pi_test123")
        self.assertEqual(payment.customer, self.customer)
        self.assertEqual(payment.amount_cents, 5000)
        mock_log.assert_called_once()

    @patch("apps.billing.payment_service.PaymentGatewayFactory.create_gateway")
    def test_missing_customer_id_returns_failure(self, mock_create_gw: MagicMock) -> None:
        mock_create_gw.return_value = _make_mock_gateway()

        result = PaymentService.create_payment_intent_direct(
            order_id=str(self.order.id),
            amount_cents=3000,
            currency="EUR",
            customer_id=None,
        )

        self.assertFalse(result["success"])
        self.assertEqual(result["error"], "customer_id is required")
        self.assertEqual(Payment.objects.count(), 0)

    @patch("apps.billing.payment_service.PaymentGatewayFactory.create_gateway")
    def test_invalid_customer_id_returns_failure(self, mock_create_gw: MagicMock) -> None:
        mock_create_gw.return_value = _make_mock_gateway()
        missing_customer_id = str(uuid.uuid4())

        result = PaymentService.create_payment_intent_direct(
            order_id=str(self.order.id),
            amount_cents=2500,
            currency="RON",
            customer_id=missing_customer_id,
        )

        self.assertFalse(result["success"])
        self.assertEqual(result["error"], "customer_id must be a valid integer")
        self.assertEqual(Payment.objects.count(), 0)

    @patch("apps.billing.payment_service.PaymentGatewayFactory.create_gateway")
    def test_gateway_failure_no_payment_created(self, mock_create_gw: MagicMock) -> None:
        mock_create_gw.return_value = _make_mock_gateway(
            pi_result=_pi_result(success=False, pi_id="", client_secret=None, error="Stripe error")
        )

        result = PaymentService.create_payment_intent_direct(
            order_id=str(self.order.id),
            amount_cents=self.order.total_cents,
            currency="RON",
            customer_id=str(self.customer.id),
        )

        self.assertFalse(result["success"])
        self.assertEqual(Payment.objects.count(), 0)

    @patch("apps.billing.payment_service.PaymentGatewayFactory.create_gateway")
    def test_generic_exception_returns_failure(self, mock_create_gw: MagicMock) -> None:
        mock_create_gw.side_effect = Exception("Unexpected failure")

        result = PaymentService.create_payment_intent_direct(
            order_id=str(self.order.id),
            amount_cents=self.order.total_cents,
            currency="RON",
            customer_id=str(self.customer.id),
        )

        self.assertFalse(result["success"])
        self.assertIn("Payment creation failed", result["error"])


# ---------------------------------------------------------------------------
# confirm_payment
# ---------------------------------------------------------------------------


class ConfirmPaymentTests(TestCase):
    """Tests for PaymentService.confirm_payment."""

    def setUp(self) -> None:
        self.customer = create_customer("Confirm Co SRL")
        currency = create_currency("RON")
        self.payment = Payment.objects.create(
            customer=self.customer,
            payment_method="stripe",
            amount_cents=10000,
            currency=currency,
            status="pending",
            gateway_txn_id="pi_confirm_test",
        )

    @patch("apps.billing.payment_service.log_security_event")
    @patch("apps.billing.payment_service.PaymentGatewayFactory.create_gateway")
    def test_succeeded_status_updates_payment(self, mock_create_gw: MagicMock, mock_log: MagicMock) -> None:
        mock_create_gw.return_value = _make_mock_gateway(
            confirm_result=_confirm_result(success=True, status="succeeded")
        )

        result = PaymentService.confirm_payment("pi_confirm_test")

        self.assertTrue(result["success"])
        self.payment.refresh_from_db()
        self.assertEqual(self.payment.status, "succeeded")
        mock_log.assert_called_once()

    @patch("apps.billing.payment_service.log_security_event")
    @patch("apps.billing.payment_service.PaymentGatewayFactory.create_gateway")
    def test_canceled_maps_to_failed(self, mock_create_gw: MagicMock, mock_log: MagicMock) -> None:
        mock_create_gw.return_value = _make_mock_gateway(
            confirm_result=_confirm_result(success=True, status="canceled")
        )

        result = PaymentService.confirm_payment("pi_confirm_test")

        self.assertTrue(result["success"])
        self.payment.refresh_from_db()
        self.assertEqual(self.payment.status, "failed")

    @patch("apps.billing.payment_service.log_security_event")
    @patch("apps.billing.payment_service.PaymentGatewayFactory.create_gateway")
    def test_requires_action_maps_to_pending(self, mock_create_gw: MagicMock, mock_log: MagicMock) -> None:
        mock_create_gw.return_value = _make_mock_gateway(
            confirm_result=_confirm_result(success=True, status="requires_action")
        )

        PaymentService.confirm_payment("pi_confirm_test")

        self.payment.refresh_from_db()
        self.assertEqual(self.payment.status, "pending")

    @patch("apps.billing.payment_service.log_security_event")
    @patch("apps.billing.payment_service.PaymentGatewayFactory.create_gateway")
    def test_no_status_change_skips_log(self, mock_create_gw: MagicMock, mock_log: MagicMock) -> None:
        # Payment is already pending; requires_payment_method → still pending
        mock_create_gw.return_value = _make_mock_gateway(
            confirm_result=_confirm_result(success=True, status="requires_payment_method")
        )

        PaymentService.confirm_payment("pi_confirm_test")

        mock_log.assert_not_called()

    @patch("apps.billing.payment_service.PaymentGatewayFactory.create_gateway")
    def test_payment_does_not_exist_is_handled(self, mock_create_gw: MagicMock) -> None:
        mock_create_gw.return_value = _make_mock_gateway(
            confirm_result=_confirm_result(success=True, status="succeeded")
        )

        result = PaymentService.confirm_payment("pi_nonexistent_999")

        self.assertTrue(result["success"])

    @patch("apps.billing.payment_service.PaymentGatewayFactory.create_gateway")
    def test_generic_exception_returns_failure(self, mock_create_gw: MagicMock) -> None:
        mock_create_gw.side_effect = RuntimeError("Gateway down")

        result = PaymentService.confirm_payment("pi_confirm_test")

        self.assertFalse(result["success"])
        self.assertIn("Payment confirmation failed", result["error"])

    @patch("apps.billing.payment_service.PaymentGatewayFactory.create_gateway")
    def test_gateway_returns_failure_no_update(self, mock_create_gw: MagicMock) -> None:
        mock_create_gw.return_value = _make_mock_gateway(
            confirm_result=_confirm_result(success=False, status="error", error="Gateway error")
        )

        result = PaymentService.confirm_payment("pi_confirm_test")

        self.assertFalse(result["success"])
        self.payment.refresh_from_db()
        self.assertEqual(self.payment.status, "pending")  # unchanged


# ---------------------------------------------------------------------------
# create_subscription
# ---------------------------------------------------------------------------


class CreateSubscriptionTests(TestCase):
    """Tests for PaymentService.create_subscription."""

    def setUp(self) -> None:
        self.customer = create_customer("Subscription Co SRL")

    @patch("apps.billing.payment_service.log_security_event")
    @patch("apps.billing.payment_service.PaymentGatewayFactory.create_gateway")
    def test_success_calls_gateway_and_logs(self, mock_create_gw: MagicMock, mock_log: MagicMock) -> None:
        mock_create_gw.return_value = _make_mock_gateway()

        result = PaymentService.create_subscription(
            customer_id=str(self.customer.id),
            price_id="price_monthly_ron",
        )

        self.assertTrue(result["success"])
        self.assertEqual(result["subscription_id"], "sub_abc")
        mock_log.assert_called_once()

    @patch("apps.billing.payment_service.PaymentGatewayFactory.create_gateway")
    def test_customer_does_not_exist_returns_failure(self, mock_create_gw: MagicMock) -> None:
        missing_id = str(uuid.uuid4())

        result = PaymentService.create_subscription(customer_id=missing_id, price_id="price_monthly_ron")

        self.assertFalse(result["success"])
        self.assertIn(missing_id, result["error"])
        mock_create_gw.assert_not_called()

    @patch("apps.billing.payment_service.PaymentGatewayFactory.create_gateway")
    def test_generic_exception_returns_failure(self, mock_create_gw: MagicMock) -> None:
        mock_create_gw.side_effect = Exception("Stripe API error")

        result = PaymentService.create_subscription(
            customer_id=str(self.customer.id),
            price_id="price_monthly_ron",
        )

        self.assertFalse(result["success"])
        self.assertIn("Subscription creation failed", result["error"])

    @patch("apps.billing.payment_service.log_security_event")
    @patch("apps.billing.payment_service.PaymentGatewayFactory.create_gateway")
    def test_gateway_failure_no_log(self, mock_create_gw: MagicMock, mock_log: MagicMock) -> None:
        mock_create_gw.return_value = _make_mock_gateway(
            sub_result=_sub_result(success=False, sub_id=None, status=None, error="Stripe rejected")
        )

        result = PaymentService.create_subscription(
            customer_id=str(self.customer.id),
            price_id="price_monthly_ron",
        )

        self.assertFalse(result["success"])
        mock_log.assert_not_called()


# ---------------------------------------------------------------------------
# handle_webhook_payment / _handle_stripe_payment_intent
# REMOVED: These methods were deleted from PaymentService.
# Stripe webhook handling is now in apps.integrations.webhooks.stripe.StripeWebhookProcessor.
# Tests for the new handler live in tests/integrations/test_stripe_webhook.py.
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# get_available_payment_methods
# ---------------------------------------------------------------------------


class GetAvailablePaymentMethodsTests(TestCase):
    """Tests for PaymentService.get_available_payment_methods."""

    def test_default_includes_stripe_card_only(self) -> None:
        methods = PaymentService.get_available_payment_methods()

        self.assertEqual(len(methods), 1)
        self.assertEqual(methods[0]["gateway"], "stripe")
        self.assertTrue(methods[0]["enabled"])

    @override_settings(ENABLE_BANK_TRANSFER=True)
    def test_with_bank_transfer_enabled_returns_two_methods(self) -> None:
        methods = PaymentService.get_available_payment_methods()

        gateways = {m["gateway"] for m in methods}
        self.assertIn("stripe", gateways)
        self.assertIn("bank", gateways)
        self.assertEqual(len(methods), 2)

    @override_settings(ENABLE_BANK_TRANSFER=False)
    def test_with_bank_transfer_disabled_returns_one_method(self) -> None:
        methods = PaymentService.get_available_payment_methods()

        self.assertEqual(len(methods), 1)

    def test_accepts_customer_id_parameter(self) -> None:
        # customer_id is optional and currently unused; must not raise
        methods = PaymentService.get_available_payment_methods(customer_id="some-uuid")

        self.assertIsInstance(methods, list)

    def test_stripe_supports_recurring(self) -> None:
        methods = PaymentService.get_available_payment_methods()

        stripe_method = next(m for m in methods if m["gateway"] == "stripe")
        self.assertTrue(stripe_method["supports_recurring"])

    @override_settings(ENABLE_BANK_TRANSFER=True)
    def test_bank_transfer_does_not_support_recurring(self) -> None:
        methods = PaymentService.get_available_payment_methods()

        bank_method = next(m for m in methods if m["gateway"] == "bank")
        self.assertFalse(bank_method["supports_recurring"])


# ---------------------------------------------------------------------------
# process_recurring_billing
# ---------------------------------------------------------------------------


class ProcessRecurringBillingTests(TestCase):
    """Tests for PaymentService.process_recurring_billing."""

    def test_stub_returns_empty_results(self) -> None:
        results = PaymentService.process_recurring_billing()

        self.assertIsInstance(results, dict)
        self.assertEqual(results["processed"], 0)
        self.assertEqual(results["succeeded"], 0)
        self.assertEqual(results["failed"], 0)
        self.assertEqual(results["suspended"], 0)
        self.assertEqual(results["errors"], [])

    def test_exception_appends_to_errors_and_returns(self) -> None:
        with patch("apps.billing.payment_service.logger") as mock_logger:
            mock_logger.info.side_effect = [None, Exception("Log failure")]

            results = PaymentService.process_recurring_billing()

        self.assertIsInstance(results, dict)
        self.assertIn("errors", results)
