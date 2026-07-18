"""
Tests for apps.billing.payment_service.PaymentService

Covers all static methods with success, failure, and edge-case branches.
"""

from __future__ import annotations

import uuid
from datetime import timedelta
from typing import Any
from unittest.mock import MagicMock, patch

from django.test import TestCase
from django.utils import timezone

from apps.billing.currency_models import Currency
from apps.billing.gateways.base import PaymentConfirmResult, PaymentIntentResult
from apps.billing.models import Payment
from apps.billing.payment_service import PaymentService
from apps.billing.proforma_models import ProformaInvoice
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


def _confirm_result(success: bool = True, status: str = "succeeded", error: str | None = None) -> PaymentConfirmResult:
    result = PaymentConfirmResult(success=success, status=status, error=error)
    if success and status == "succeeded":
        result["amount_received"] = 10_000
        result["currency"] = "ron"
    return result


def _make_mock_gateway(
    pi_result: PaymentIntentResult | None = None,
    confirm_result: PaymentConfirmResult | None = None,
) -> MagicMock:
    gw = MagicMock()
    gw.create_payment_intent.return_value = pi_result if pi_result is not None else _pi_result()
    gw.confirm_payment.return_value = confirm_result if confirm_result is not None else _confirm_result()
    return gw


def _make_order(customer: Any, currency_code: str = "RON", total_cents: int = 15000) -> Order:
    """Create a minimal Order for testing."""
    currency, _ = Currency.objects.get_or_create(
        code=currency_code,
        defaults={"name": currency_code, "symbol": currency_code, "decimals": 2},
    )
    order = Order.objects.create(
        customer=customer,
        currency=currency,
        total_cents=total_cents,
        subtotal_cents=total_cents,
        customer_email=customer.name.lower().replace(" ", "") + "@example.com",
        customer_name=customer.name,
    )
    proforma = ProformaInvoice.objects.create(
        customer=customer,
        currency=currency,
        number=f"PRO-PAY-{order.id}",
        subtotal_cents=total_cents,
        total_cents=total_cents,
        valid_until=timezone.now() + timedelta(days=30),
    )
    order.proforma = proforma
    order.save(update_fields=["proforma", "updated_at"])
    return order


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
    def test_gateway_failure_preserves_resumable_payment_attempt(self, mock_create_gw: MagicMock) -> None:
        mock_create_gw.return_value = _make_mock_gateway(
            pi_result=_pi_result(success=False, pi_id="", client_secret=None, error="Card declined")
        )

        result = PaymentService.create_payment_intent(str(self.order.id))

        self.assertFalse(result["success"])
        payment = Payment.objects.get()
        self.assertEqual(payment.status, "pending")
        self.assertIsNone(payment.gateway_txn_id)

    @patch("apps.billing.payment_service.PaymentGatewayFactory.create_gateway")
    def test_generic_exception_returns_failure(self, mock_create_gw: MagicMock) -> None:
        mock_create_gw.side_effect = RuntimeError("Network timeout")

        result = PaymentService.create_payment_intent(str(self.order.id))

        self.assertFalse(result["success"])
        self.assertIn("Payment creation failed", result["error"])

    def test_resumed_attempt_replays_its_original_metadata(self) -> None:
        """#240/#294 replay safety under the snapshot contract: caller metadata reaches the
        gateway, but a RESUMED attempt (pending, no gateway id) must replay the ORIGINAL
        attempt's metadata with its original idempotency key — a retry passing different
        caller metadata would otherwise be rejected by Stripe as a mismatched key reuse."""
        order = _make_order(self.customer, total_cents=11900)
        gateway = _make_mock_gateway()
        with (
            patch("apps.billing.payment_service.log_security_event", MagicMock()),
            patch("apps.billing.payment_service.PaymentGatewayFactory.create_gateway", return_value=gateway),
        ):
            gateway.create_payment_intent.return_value = {
                "success": False,
                "payment_intent_id": None,
                "client_secret": None,
                "error": "network interruption",
            }
            PaymentService.create_payment_intent_direct(
                order_id=str(order.id),
                customer_id=str(self.customer.id),
                metadata={"campaign": "original-value"},
            )
            gateway.create_payment_intent.return_value = {
                "success": True,
                "payment_intent_id": "pi_replayed",
                "client_secret": "cs_replayed",
            }
            PaymentService.create_payment_intent_direct(
                order_id=str(order.id),
                customer_id=str(self.customer.id),
                metadata={"campaign": "CHANGED-value"},
            )

        replay_kwargs = gateway.create_payment_intent.call_args.kwargs
        self.assertEqual(replay_kwargs["metadata"].get("campaign"), "original-value")

    @patch("apps.billing.payment_service.log_security_event")
    @patch("apps.billing.payment_service.PaymentGatewayFactory.create_gateway")
    def test_repeated_compatibility_calls_reuse_one_keyed_payment(
        self, mock_create_gw: MagicMock, mock_log: MagicMock
    ) -> None:
        gateway = _make_mock_gateway()
        gateway.create_payment_intent.side_effect = [
            _pi_result(pi_id="pi_legacy_first", client_secret="sec_legacy_first"),
            _pi_result(pi_id="pi_legacy_duplicate", client_secret="sec_legacy_duplicate"),
        ]
        mock_create_gw.return_value = gateway

        first = PaymentService.create_payment_intent(str(self.order.id))
        second = PaymentService.create_payment_intent(str(self.order.id))

        self.assertTrue(first["success"])
        self.assertTrue(second["success"])
        self.assertEqual(first["payment_intent_id"], "pi_legacy_first")
        self.assertEqual(second["payment_intent_id"], "pi_legacy_first")
        gateway.create_payment_intent.assert_called_once()
        payment = Payment.objects.get(gateway_txn_id="pi_legacy_first")
        self.assertIsNotNone(payment.idempotency_key)
        self.assertEqual(Payment.objects.filter(meta__order_id=str(self.order.id)).count(), 1)


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
            order_number=self.order.order_number,
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
    def test_bank_transfer_cannot_enter_payment_intent_path(self, mock_create_gw: MagicMock) -> None:
        result = PaymentService.create_payment_intent_direct(
            order_id=str(self.order.id),
            customer_id=str(self.customer.id),
            gateway="bank",
        )

        self.assertFalse(result["success"])
        self.assertIn("gateway", result["error"] or "")
        self.assertFalse(Payment.objects.exists())
        mock_create_gw.assert_not_called()

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
    def test_gateway_failure_preserves_one_resumable_local_attempt(self, mock_create_gw: MagicMock) -> None:
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
        payment = Payment.objects.get()
        self.assertEqual(payment.status, "pending")
        self.assertIsNone(payment.gateway_txn_id)
        self.assertTrue(payment.idempotency_key)

    @patch("apps.billing.payment_service.PaymentGatewayFactory.create_gateway")
    def test_gateway_success_without_transaction_id_fails_closed(self, mock_create_gw: MagicMock) -> None:
        mock_create_gw.return_value = _make_mock_gateway(
            pi_result=_pi_result(success=True, pi_id="", client_secret="unexpected-secret", error=None)
        )

        result = PaymentService.create_payment_intent_direct(
            order_id=str(self.order.id),
            amount_cents=self.order.total_cents,
            currency="RON",
            customer_id=str(self.customer.id),
        )

        self.assertFalse(result["success"])
        self.assertIn("transaction ID", result["error"] or "")
        payment = Payment.objects.get()
        self.assertEqual(payment.status, "pending")
        self.assertIsNone(payment.gateway_txn_id)

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

    @patch("apps.billing.payment_convergence.log_security_event")
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

        self.assertFalse(result["success"])
        self.assertEqual(result["status"], "payment_not_found")

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

    @patch("apps.billing.payment_service.PaymentGatewayFactory.create_gateway")
    def test_terminal_state_idempotency_guard(self, mock_create_gw: MagicMock) -> None:
        """C2 regression: confirm_payment must handle terminal state idempotently."""
        from tests.helpers.fsm_helpers import force_status  # noqa: PLC0415

        # Put payment in terminal state "succeeded" — FSM cannot transition succeeded→succeeded
        force_status(self.payment, "succeeded")

        # Gateway still reports success (Stripe idempotency can replay old events)
        mock_create_gw.return_value = _make_mock_gateway(
            confirm_result=_confirm_result(success=True, status="succeeded")
        )

        PaymentService.confirm_payment("pi_confirm_test")

        # Should be short-circuited by idempotency guard (already terminal)
        self.payment.refresh_from_db()
        self.assertEqual(self.payment.status, "succeeded")

    @patch("apps.billing.payment_service.log_security_event")
    @patch("apps.billing.payment_service.PaymentGatewayFactory.create_gateway")
    def test_fsm_transition_blocked_returns_failure(self, mock_create_gw: MagicMock, mock_log: MagicMock) -> None:
        """C2 regression: when FSM blocks a transition (e.g. race condition), result must be success=False."""
        from django_fsm import TransitionNotAllowed  # noqa: PLC0415

        # Payment stays in "pending" (non-terminal). Gateway says "succeeded".
        mock_create_gw.return_value = _make_mock_gateway(
            confirm_result=_confirm_result(success=True, status="succeeded")
        )

        # Simulate a race condition: another process already transitioned this payment,
        # so the FSM method raises TransitionNotAllowed.
        with patch.object(type(self.payment), "succeed", side_effect=TransitionNotAllowed("blocked")):
            result = PaymentService.confirm_payment("pi_confirm_test")

        # Must surface the FSM conflict as a failure
        self.assertFalse(result["success"])
        self.assertEqual(result["status"], "fsm_conflict")
        self.assertIn("transition", result.get("error", "").lower())
        # Payment must remain in "pending" state (transition was blocked)
        self.payment.refresh_from_db()
        self.assertEqual(self.payment.status, "pending")

    @patch("apps.billing.payment_service.PaymentGatewayFactory.create_gateway")
    def test_confirm_payment_handles_concurrent_transition(self, mock_create_gw: MagicMock) -> None:
        """ADR-0034: ConcurrentTransition must be caught alongside TransitionNotAllowed."""
        from django_fsm import ConcurrentTransition  # noqa: PLC0415

        # Gateway reports success — the transition should fire but a concurrent
        # process has already modified the row (optimistic locking conflict).
        mock_create_gw.return_value = _make_mock_gateway(
            confirm_result=_confirm_result(success=True, status="succeeded")
        )

        with patch.object(type(self.payment), "succeed", side_effect=ConcurrentTransition("concurrent write")):
            result = PaymentService.confirm_payment("pi_confirm_test")

        # The handler must NOT re-raise — it returns a structured fsm_conflict result.
        self.assertFalse(result["success"])
        self.assertEqual(result["status"], "fsm_conflict")
        self.assertIn("transition", result.get("error", "").lower())
        # Payment status is unchanged (transition was blocked by optimistic lock).
        self.payment.refresh_from_db()
        self.assertEqual(self.payment.status, "pending")


# ---------------------------------------------------------------------------
# handle_webhook_payment / _handle_stripe_payment_intent
# REMOVED: These methods were deleted from PaymentService.
# Stripe webhook handling is now in apps.integrations.webhooks.stripe.StripeWebhookProcessor.
# Tests for the new handler live in tests/integrations/test_stripe_webhook.py.
# ---------------------------------------------------------------------------
