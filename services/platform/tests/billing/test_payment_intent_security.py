"""H18+H19: Payment intent creation must validate order status and enforce idempotency."""
import json
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from typing import Any
from unittest.mock import MagicMock, patch

from django.db import close_old_connections, connection
from django.test import TestCase, TransactionTestCase
from django.utils import timezone

from apps.billing.currency_models import Currency
from apps.billing.models import Payment
from apps.billing.payment_service import PaymentService
from apps.billing.proforma_models import ProformaInvoice
from apps.customers.models import Customer
from apps.orders.models import Order
from apps.orders.services import OrderService, StatusChangeData


class _IdempotentFakeGateway:
    """Thread-safe fake that models Stripe's idempotency behavior."""

    def __init__(
        self,
        barrier: threading.Barrier | None = None,
        *,
        conflict_on_duplicate: bool = False,
    ) -> None:
        self.barrier = barrier
        self.conflict_on_duplicate = conflict_on_duplicate
        self.lock = threading.Lock()
        self.calls: list[str] = []
        self.results: dict[str, dict[str, Any]] = {}
        self.request_fingerprints: dict[str, str] = {}
        self.remote_creations = 0

    def create_payment_intent(  # noqa: PLR0913
        self,
        order_id: str,
        amount_cents: int,
        currency: str = "RON",
        customer_id: str | None = None,
        metadata: dict[str, Any] | None = None,
        *,
        idempotency_key: str | None = None,
    ) -> dict[str, Any]:
        if not idempotency_key:
            raise AssertionError("idempotency_key is required")
        request_fingerprint = json.dumps(
            {
                "order_id": order_id,
                "amount_cents": amount_cents,
                "currency": currency,
                "customer_id": customer_id,
                "metadata": metadata,
            },
            sort_keys=True,
        )
        if self.barrier is not None:
            self.barrier.wait(timeout=10)
        with self.lock:
            self.calls.append(idempotency_key)
            if idempotency_key in self.results:
                if self.request_fingerprints[idempotency_key] != request_fingerprint:
                    return {
                        "success": False,
                        "payment_intent_id": "",
                        "client_secret": None,
                        "error": "idempotency key reused with different parameters",
                    }
                if self.conflict_on_duplicate:
                    return {
                        "success": False,
                        "payment_intent_id": "",
                        "client_secret": None,
                        "error": "idempotency key is currently in use",
                    }
                return dict(self.results[idempotency_key])

            self.remote_creations += 1
            self.request_fingerprints[idempotency_key] = request_fingerprint
            self.results[idempotency_key] = {
                "success": True,
                "payment_intent_id": f"pi_fake_{self.remote_creations}",
                "client_secret": f"sec_fake_{self.remote_creations}",
                "error": None,
            }
            return dict(self.results[idempotency_key])


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
    if status in {"draft", "awaiting_payment"}:
        proforma = ProformaInvoice.objects.create(
            customer=customer,
            currency=currency,
            number=f"PRO-PAY-{order.id}",
            subtotal_cents=total_cents,
            total_cents=total_cents,
            valid_until=timezone.now() + timedelta(days=7),
        )
        order.proforma = proforma
        order.save(update_fields=["proforma", "updated_at"])
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

    @patch("apps.billing.payment_service.PaymentGatewayFactory")
    def test_positive_order_without_proforma_is_rejected(self, mock_gw_factory: MagicMock) -> None:
        mock_gw_factory.create_gateway.return_value.create_payment_intent.return_value = {
            "success": False,
            "payment_intent_id": "",
            "client_secret": None,
            "error": "gateway should not be called",
        }
        order = _create_order(self.customer, status="awaiting_payment", total_cents=25000)
        order.proforma = None
        order.save(update_fields=["proforma", "updated_at"])

        result = PaymentService.create_payment_intent_direct(
            order_id=str(order.id),
            customer_id=str(self.customer.id),
        )

        self.assertFalse(result["success"])
        self.assertIn("proforma", result["error"] or "")
        self.assertFalse(Payment.objects.exists())
        mock_gw_factory.create_gateway.assert_not_called()

    @patch("apps.billing.payment_service.log_security_event", MagicMock())
    @patch("apps.billing.payment_service.PaymentGatewayFactory")
    def test_order_intent_uses_frozen_proforma_total_after_order_drift(self, mock_gw_factory: MagicMock) -> None:
        gateway = MagicMock()
        gateway.create_payment_intent.return_value = {
            "success": True,
            "payment_intent_id": "pi_frozen_proforma",
            "client_secret": "sec_frozen_proforma",
        }
        mock_gw_factory.create_gateway.return_value = gateway
        order = _create_order(self.customer, status="awaiting_payment", total_cents=25000)
        assert order.proforma is not None
        order.proforma.total_cents = 24999
        order.proforma.save(update_fields=["total_cents"])

        result = PaymentService.create_payment_intent_direct(
            order_id=str(order.id),
            customer_id=str(self.customer.id),
        )

        self.assertTrue(result["success"])
        gateway.create_payment_intent.assert_called_once()
        self.assertEqual(gateway.create_payment_intent.call_args.kwargs["amount_cents"], 24999)
        self.assertEqual(Payment.objects.get().amount_cents, 24999)

    @patch("apps.billing.payment_service.log_security_event", MagicMock())
    @patch("apps.billing.payment_service.PaymentGatewayFactory.create_gateway")
    def test_order_total_drift_during_reservation_does_not_override_proforma(
        self,
        mock_create_gateway: MagicMock,
    ) -> None:
        order = _create_order(self.customer, status="awaiting_payment", total_cents=25000)
        assert order.proforma is not None
        gateway = MagicMock()
        gateway.create_payment_intent.return_value = {
            "success": True,
            "payment_intent_id": "pi_order_drift",
            "client_secret": "sec_order_drift",
        }

        def drift_order_before_gateway(_gateway_name: str) -> MagicMock:
            Order.objects.filter(pk=order.pk).update(total_cents=26000)
            return gateway

        mock_create_gateway.side_effect = drift_order_before_gateway

        result = PaymentService.create_payment_intent_direct(
            order_id=str(order.id),
            customer_id=str(self.customer.id),
        )

        self.assertTrue(result["success"])
        self.assertEqual(gateway.create_payment_intent.call_args.kwargs["amount_cents"], 25000)

    @patch("apps.billing.payment_service.PaymentGatewayFactory.create_gateway")
    def test_order_intent_aborts_when_proforma_changes_before_gateway_call(
        self,
        mock_create_gateway: MagicMock,
    ) -> None:
        order = _create_order(self.customer, status="awaiting_payment", total_cents=25000)
        assert order.proforma is not None
        gateway = MagicMock()
        gateway.create_payment_intent.return_value = {
            "success": True,
            "payment_intent_id": "pi_must_not_charge_converted_order",
            "client_secret": "sec_must_not_charge_converted_order",
        }

        def convert_proforma_before_gateway(_gateway_name: str) -> MagicMock:
            ProformaInvoice.objects.filter(pk=order.proforma_id).update(status="converted")
            return gateway

        mock_create_gateway.side_effect = convert_proforma_before_gateway

        result = PaymentService.create_payment_intent_direct(
            order_id=str(order.id),
            customer_id=str(self.customer.id),
        )

        self.assertFalse(result["success"])
        self.assertIn("document changed", result["error"].lower())
        gateway.create_payment_intent.assert_not_called()
        attempt = Payment.objects.get(meta__order_id=str(order.id))
        self.assertEqual(attempt.status, "failed")

    def test_order_cancellation_rejects_unresolved_card_attempt(self) -> None:
        order = _create_order(self.customer, status="awaiting_payment", total_cents=25000)
        assert order.proforma is not None
        pending = Payment.objects.create(
            proforma=order.proforma,
            customer=self.customer,
            currency=order.currency,
            amount_cents=order.total_cents,
            payment_method="stripe",
            meta={"order_id": str(order.id), "source": "portal_api"},
        )

        result = OrderService.update_order_status(
            order,
            StatusChangeData(new_status="cancelled", notes="Customer requested cancellation"),
        )

        self.assertTrue(result.is_err())
        self.assertIn("unresolved card payment", result.unwrap_err().lower())
        order.refresh_from_db()
        self.assertEqual(order.status, "awaiting_payment")
        pending.refresh_from_db()
        self.assertEqual(pending.status, "pending")

    @patch("apps.billing.payment_service.log_security_event", MagicMock())
    @patch("apps.billing.payment_service.PaymentGatewayFactory")
    def test_caller_metadata_cannot_override_authoritative_payment_identity(
        self, mock_gw_factory: MagicMock
    ) -> None:
        mock_gw = MagicMock()
        mock_gw.create_payment_intent.return_value = {
            "success": True,
            "payment_intent_id": "pi_metadata_guard",
            "client_secret": "sec_metadata_guard",
        }
        mock_gw_factory.create_gateway.return_value = mock_gw
        order = _create_order(self.customer, status="awaiting_payment", total_cents=25000)

        result = PaymentService.create_payment_intent_direct(
            order_id=str(order.id),
            customer_id=str(self.customer.id),
            order_number="SPOOFED-ORDER",
            metadata={
                "customer_id": "999999",
                "order_number": "SPOOFED-METADATA",
                "platform": "attacker",
                "source": "recurring_billing",
                "campaign": "retained-value",
            },
        )

        self.assertTrue(result["success"])
        gateway_metadata = mock_gw.create_payment_intent.call_args.kwargs["metadata"]
        self.assertEqual(gateway_metadata["customer_id"], str(self.customer.id))
        self.assertEqual(gateway_metadata["order_number"], order.order_number)
        self.assertEqual(gateway_metadata["platform"], "PRAHO")
        self.assertEqual(gateway_metadata["source"], "portal_api")
        self.assertEqual(gateway_metadata["campaign"], "retained-value")


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

    @patch("apps.billing.payment_service.log_security_event", MagicMock())
    @patch("apps.billing.payment_service.PaymentGatewayFactory")
    def test_other_pending_payment_cannot_hide_existing_order_intent(self, mock_gw_factory: MagicMock) -> None:
        mock_gw = MagicMock()
        mock_gw.create_payment_intent.return_value = {
            "success": True,
            "payment_intent_id": "pi_order_specific",
            "client_secret": "sec_order_specific",
        }
        mock_gw_factory.create_gateway.return_value = mock_gw
        order = _create_order(self.customer, status="awaiting_payment", total_cents=25000)

        first = PaymentService.create_payment_intent_direct(
            order_id=str(order.id),
            customer_id=str(self.customer.id),
        )
        other_order = _create_order(self.customer, status="awaiting_payment", total_cents=10000)
        Payment.objects.create(
            customer=self.customer,
            currency=other_order.currency,
            amount_cents=other_order.total_cents,
            payment_method="stripe",
            gateway_txn_id="pi_newer_other_order",
            meta={"order_id": str(other_order.id), "client_secret": "sec_other"},
        )

        second = PaymentService.create_payment_intent_direct(
            order_id=str(order.id),
            customer_id=str(self.customer.id),
        )

        self.assertEqual(second["payment_intent_id"], first["payment_intent_id"])
        self.assertEqual(second["client_secret"], first["client_secret"])
        self.assertTrue(second["success"])
        mock_gw.create_payment_intent.assert_called_once()

    @patch("apps.billing.payment_service.PaymentGatewayFactory")
    def test_gateway_bound_attempt_wins_over_newer_unbound_duplicate(self, mock_gw_factory: MagicMock) -> None:
        order = _create_order(self.customer, status="awaiting_payment", total_cents=25000)
        assert order.proforma is not None
        bound = Payment.objects.create(
            proforma=order.proforma,
            customer=self.customer,
            currency=order.currency,
            amount_cents=order.total_cents,
            payment_method="stripe",
            status="pending",
            gateway_txn_id="pi_already_created",
            idempotency_key=f"order:{order.id}:stripe:1",
            meta={
                "order_id": str(order.id),
                "proforma_id": str(order.proforma_id),
                "client_secret": "sec_already_created",
            },
        )
        Payment.objects.create(
            proforma=order.proforma,
            customer=self.customer,
            currency=order.currency,
            amount_cents=order.total_cents,
            payment_method="stripe",
            status="pending",
            idempotency_key=f"order:{order.id}:stripe:2",
            meta={"order_id": str(order.id), "proforma_id": str(order.proforma_id)},
        )

        result = PaymentService.create_payment_intent_direct(
            order_id=str(order.id),
            customer_id=str(self.customer.id),
        )

        self.assertTrue(result["success"])
        self.assertEqual(result["payment_intent_id"], bound.gateway_txn_id)
        self.assertEqual(result["client_secret"], "sec_already_created")
        mock_gw_factory.create_gateway.assert_not_called()

    @patch("apps.billing.payment_service.PaymentGatewayFactory")
    def test_mismatched_gateway_bound_attempt_fails_closed(self, mock_gw_factory: MagicMock) -> None:
        order = _create_order(self.customer, status="awaiting_payment", total_cents=25000)
        assert order.proforma is not None
        Payment.objects.create(
            proforma=order.proforma,
            customer=self.customer,
            currency=order.currency,
            amount_cents=1,
            payment_method="stripe",
            status="pending",
            gateway_txn_id="pi_wrong_amount",
            idempotency_key=f"order:{order.id}:stripe:1",
            meta={"order_id": str(order.id), "proforma_id": str(order.proforma_id)},
        )

        result = PaymentService.create_payment_intent_direct(
            order_id=str(order.id),
            customer_id=str(self.customer.id),
        )

        self.assertFalse(result["success"])
        self.assertIn("not a resumable attempt", result["error"] or "")
        mock_gw_factory.create_gateway.assert_not_called()

    @patch("apps.billing.payment_service.log_security_event", MagicMock())
    @patch("apps.billing.payment_service.PaymentGatewayFactory")
    def test_gateway_receives_order_attempt_idempotency_key(self, mock_gw_factory: MagicMock) -> None:
        mock_gw = MagicMock()
        mock_gw.create_payment_intent.return_value = {
            "success": True,
            "payment_intent_id": "pi_idempotency_contract",
            "client_secret": "sec_idempotency_contract",
        }
        mock_gw_factory.create_gateway.return_value = mock_gw
        order = _create_order(self.customer, status="awaiting_payment", total_cents=25000)

        result = PaymentService.create_payment_intent_direct(
            order_id=str(order.id),
            customer_id=str(self.customer.id),
        )

        self.assertTrue(result["success"])
        self.assertEqual(
            mock_gw.create_payment_intent.call_args.kwargs["idempotency_key"],
            f"order:{order.id}:stripe:1",
        )

    @patch("apps.billing.payment_service.log_security_event", MagicMock())
    @patch("apps.billing.payment_service.PaymentGatewayFactory")
    def test_local_attempt_exists_before_gateway_network_call(self, mock_gw_factory: MagicMock) -> None:
        order = _create_order(self.customer, status="awaiting_payment", total_cents=25000)

        def gateway_create(**kwargs: object) -> dict[str, object]:
            pending = Payment.objects.get(meta__order_id=str(order.id))
            self.assertEqual(pending.status, "pending")
            self.assertIsNone(pending.gateway_txn_id)
            self.assertEqual(pending.idempotency_key, f"order:{order.id}:stripe:1")
            return {
                "success": True,
                "payment_intent_id": "pi_precreated_local",
                "client_secret": "sec_precreated_local",
            }

        mock_gw = MagicMock()
        mock_gw.create_payment_intent.side_effect = gateway_create
        mock_gw_factory.create_gateway.return_value = mock_gw

        result = PaymentService.create_payment_intent_direct(
            order_id=str(order.id),
            customer_id=str(self.customer.id),
        )

        self.assertTrue(result["success"])
        payment = Payment.objects.get(meta__order_id=str(order.id))
        self.assertEqual(payment.gateway_txn_id, "pi_precreated_local")


class DirectPaymentIntentPostgresConcurrencyTests(TransactionTestCase):
    reset_sequences = True

    def setUp(self) -> None:
        self.customer = Customer.objects.create(
            name="Concurrent Idem Co",
            customer_type="company",
            status="active",
            primary_email="concurrent-idem@test.ro",
        )
        self.order = _create_order(self.customer, status="awaiting_payment", total_cents=25000)

    @patch("apps.billing.payment_service.log_security_event", MagicMock())
    @patch("apps.billing.payment_service.PaymentGatewayFactory")
    def test_same_order_concurrent_calls_create_one_remote_intent_and_one_payment(
        self, mock_gw_factory: MagicMock
    ) -> None:
        if connection.vendor != "postgresql":
            self.skipTest("PostgreSQL row and unique-constraint behavior required")

        fake_gateway = _IdempotentFakeGateway(
            barrier=threading.Barrier(2),
            conflict_on_duplicate=True,
        )
        mock_gw_factory.create_gateway.return_value = fake_gateway

        def create_intent() -> dict[str, Any]:
            close_old_connections()
            try:
                return PaymentService.create_payment_intent_direct(
                    order_id=str(self.order.id),
                    customer_id=str(self.customer.id),
                )
            finally:
                connection.close()

        with ThreadPoolExecutor(max_workers=2) as executor:
            results = list(executor.map(lambda _index: create_intent(), range(2)))

        self.assertEqual(sum(result["success"] for result in results), 1)
        successful_result = next(result for result in results if result["success"])
        failed_result = next(result for result in results if not result["success"])
        self.assertEqual(successful_result["payment_intent_id"], "pi_fake_1")
        self.assertEqual(failed_result["error"], "idempotency key is currently in use")
        self.assertEqual(len(fake_gateway.calls), 2)
        self.assertEqual(fake_gateway.calls[0], fake_gateway.calls[1])
        self.assertEqual(fake_gateway.remote_creations, 1)
        self.assertEqual(Payment.objects.filter(meta__order_id=str(self.order.id)).count(), 1)

        retry_result = create_intent()
        self.assertTrue(retry_result["success"])
        self.assertEqual(retry_result["payment_intent_id"], "pi_fake_1")
        self.assertEqual(len(fake_gateway.calls), 2)

    @patch("apps.billing.payment_service.log_security_event", MagicMock())
    @patch("apps.billing.payment_service.PaymentGatewayFactory")
    def test_successful_remote_replays_converge_on_one_payment(
        self, mock_gw_factory: MagicMock
    ) -> None:
        if connection.vendor != "postgresql":
            self.skipTest("PostgreSQL unique-constraint behavior required")

        fake_gateway = _IdempotentFakeGateway(barrier=threading.Barrier(2))
        mock_gw_factory.create_gateway.return_value = fake_gateway

        def create_intent() -> dict[str, Any]:
            close_old_connections()
            try:
                return PaymentService.create_payment_intent_direct(
                    order_id=str(self.order.id),
                    customer_id=str(self.customer.id),
                )
            finally:
                connection.close()

        with ThreadPoolExecutor(max_workers=2) as executor:
            results = list(executor.map(lambda _index: create_intent(), range(2)))

        self.assertTrue(all(result["success"] for result in results))
        self.assertEqual({result["payment_intent_id"] for result in results}, {"pi_fake_1"})
        self.assertEqual(len(fake_gateway.calls), 2)
        self.assertEqual(fake_gateway.calls[0], fake_gateway.calls[1])
        self.assertEqual(fake_gateway.remote_creations, 1)
        self.assertEqual(Payment.objects.filter(meta__order_id=str(self.order.id)).count(), 1)
