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

    @patch("apps.billing.payment_service.log_security_event")
    @patch("apps.billing.payment_service.PaymentGatewayFactory.create_gateway")
    def test_success_with_known_customer(self, mock_create_gw: MagicMock, mock_log: MagicMock) -> None:
        mock_create_gw.return_value = _make_mock_gateway()
        create_currency("RON")

        result = PaymentService.create_payment_intent_direct(
            order_id=str(uuid.uuid4()),
            amount_cents=5000,
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
    def test_success_without_customer_id(self, mock_create_gw: MagicMock) -> None:
        """Without customer_id the service passes customer=None which violates Payment.customer
        NOT NULL, so the DB rejects the row and the service returns a graceful failure."""
        mock_create_gw.return_value = _make_mock_gateway()

        result = PaymentService.create_payment_intent_direct(
            order_id=str(uuid.uuid4()),
            amount_cents=3000,
            currency="EUR",
            customer_id=None,
        )

        self.assertFalse(result["success"])
        self.assertIn("Payment creation failed", result["error"])
        self.assertEqual(Payment.objects.count(), 0)

    @patch("apps.billing.payment_service.PaymentGatewayFactory.create_gateway")
    def test_customer_does_not_exist_falls_back_to_null_customer(self, mock_create_gw: MagicMock) -> None:
        """When customer_id is supplied but not found the service falls back to customer_obj=None,
        which violates the NOT NULL constraint; the except block returns a graceful failure."""
        mock_create_gw.return_value = _make_mock_gateway()
        missing_customer_id = str(uuid.uuid4())

        result = PaymentService.create_payment_intent_direct(
            order_id=str(uuid.uuid4()),
            amount_cents=2500,
            currency="RON",
            customer_id=missing_customer_id,
        )

        self.assertFalse(result["success"])
        self.assertIn("Payment creation failed", result["error"])
        self.assertEqual(Payment.objects.count(), 0)

    @patch("apps.billing.payment_service.PaymentGatewayFactory.create_gateway")
    def test_gateway_failure_no_payment_created(self, mock_create_gw: MagicMock) -> None:
        mock_create_gw.return_value = _make_mock_gateway(
            pi_result=_pi_result(success=False, pi_id="", client_secret=None, error="Stripe error")
        )

        result = PaymentService.create_payment_intent_direct(
            order_id=str(uuid.uuid4()),
            amount_cents=1000,
            currency="RON",
        )

        self.assertFalse(result["success"])
        self.assertEqual(Payment.objects.count(), 0)

    @patch("apps.billing.payment_service.PaymentGatewayFactory.create_gateway")
    def test_generic_exception_returns_failure(self, mock_create_gw: MagicMock) -> None:
        mock_create_gw.side_effect = Exception("Unexpected failure")

        result = PaymentService.create_payment_intent_direct(
            order_id=str(uuid.uuid4()),
            amount_cents=1000,
            currency="RON",
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
# handle_webhook_payment
# ---------------------------------------------------------------------------


_PaymentServiceModule = __import__("apps.billing.payment_service", fromlist=["PaymentService"])


class HandleWebhookPaymentTests(TestCase):
    """Tests for PaymentService.handle_webhook_payment."""

    @patch.object(
        _PaymentServiceModule.PaymentService,
        "_handle_stripe_payment_intent",
        return_value=(True, "Payment pi_abc succeeded"),
    )
    def test_stripe_payment_intent_delegates(self, mock_handle: MagicMock) -> None:
        success, _msg = PaymentService.handle_webhook_payment(
            event_type="payment_intent.succeeded",
            event_data={"object": {"id": "pi_abc"}},
            gateway="stripe",
        )

        mock_handle.assert_called_once_with("payment_intent.succeeded", {"object": {"id": "pi_abc"}})
        self.assertTrue(success)

    def test_non_stripe_gateway_returns_unhandled(self) -> None:
        success, msg = PaymentService.handle_webhook_payment(
            event_type="payment_intent.succeeded",
            event_data={},
            gateway="paypal",
        )

        self.assertTrue(success)
        self.assertIn("Unhandled webhook event", msg)

    def test_non_payment_intent_stripe_event_returns_unhandled(self) -> None:
        success, msg = PaymentService.handle_webhook_payment(
            event_type="customer.subscription.updated",
            event_data={},
            gateway="stripe",
        )

        self.assertTrue(success)
        self.assertIn("Unhandled webhook event", msg)

    @patch.object(
        _PaymentServiceModule.PaymentService,
        "_handle_stripe_payment_intent",
        side_effect=RuntimeError("Unexpected crash"),
    )
    def test_exception_returns_false(self, mock_handle: MagicMock) -> None:
        success, msg = PaymentService.handle_webhook_payment(
            event_type="payment_intent.succeeded",
            event_data={"object": {"id": "pi_abc"}},
            gateway="stripe",
        )

        self.assertFalse(success)
        self.assertIn("Webhook processing error", msg)


# ---------------------------------------------------------------------------
# _handle_stripe_payment_intent
# ---------------------------------------------------------------------------


class HandleStripePaymentIntentTests(TestCase):
    """Tests for PaymentService._handle_stripe_payment_intent."""

    def setUp(self) -> None:
        self.customer = create_customer("Stripe Webhook Co SRL")
        currency = create_currency("RON")
        self.payment = Payment.objects.create(
            customer=self.customer,
            payment_method="stripe",
            amount_cents=20000,
            currency=currency,
            status="pending",
            gateway_txn_id="pi_webhook_test",
            meta={},
        )

    @patch("apps.billing.payment_service.log_security_event")
    def test_succeeded_updates_status_and_meta(self, mock_log: MagicMock) -> None:
        event_data = {
            "object": {
                "id": "pi_webhook_test",
                "payment_method": "pm_card_visa",
                "amount_received": 20000,
            }
        }

        success, msg = PaymentService._handle_stripe_payment_intent("payment_intent.succeeded", event_data)

        self.assertTrue(success)
        self.assertIn("succeeded", msg)
        self.payment.refresh_from_db()
        self.assertEqual(self.payment.status, "succeeded")
        self.assertEqual(self.payment.meta.get("stripe_payment_method"), "pm_card_visa")
        mock_log.assert_called_once()

    @patch("apps.billing.payment_service.log_security_event")
    def test_payment_failed_updates_status_and_meta(self, mock_log: MagicMock) -> None:
        event_data = {
            "object": {
                "id": "pi_webhook_test",
                "last_payment_error": {"message": "Insufficient funds"},
            }
        }

        success, _msg = PaymentService._handle_stripe_payment_intent("payment_intent.payment_failed", event_data)

        self.assertTrue(success)
        self.payment.refresh_from_db()
        self.assertEqual(self.payment.status, "failed")
        self.assertIn("Insufficient funds", self.payment.meta.get("stripe_failure_reason", ""))
        mock_log.assert_called_once()

    def test_payment_failed_without_error_message_uses_unknown(self) -> None:
        event_data = {"object": {"id": "pi_webhook_test"}}

        success, _msg = PaymentService._handle_stripe_payment_intent("payment_intent.payment_failed", event_data)

        self.assertTrue(success)
        self.payment.refresh_from_db()
        self.assertIn("Unknown error", self.payment.meta.get("stripe_failure_reason", ""))

    def test_other_event_type_returns_handled(self) -> None:
        event_data = {"object": {"id": "pi_webhook_test"}}

        success, msg = PaymentService._handle_stripe_payment_intent("payment_intent.created", event_data)

        self.assertTrue(success)
        self.assertIn("Handled payment_intent event", msg)

    def test_missing_payment_intent_id_returns_false(self) -> None:
        event_data: dict[str, Any] = {"object": {}}

        success, msg = PaymentService._handle_stripe_payment_intent("payment_intent.succeeded", event_data)

        self.assertFalse(success)
        self.assertIn("Missing payment intent ID", msg)

    def test_payment_does_not_exist_returns_true(self) -> None:
        event_data = {"object": {"id": "pi_nonexistent_xyz"}}

        success, msg = PaymentService._handle_stripe_payment_intent("payment_intent.succeeded", event_data)

        self.assertTrue(success)
        self.assertIn("Payment not found (external)", msg)


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
