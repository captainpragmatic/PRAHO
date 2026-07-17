"""H18+H19: Payment intent creation must validate order status and enforce idempotency."""
import json
import threading
from concurrent.futures import ThreadPoolExecutor
from typing import Any
from unittest.mock import MagicMock, patch

from django.db import close_old_connections, connection
from django.test import TestCase, TransactionTestCase

from apps.billing.currency_models import Currency
from apps.billing.models import Payment
from apps.billing.payment_service import PaymentService
from apps.customers.models import Customer
from apps.orders.models import Order


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

    @patch("apps.billing.payment_service.PaymentGatewayFactory")
    def test_succeeded_payment_is_reused_without_new_intent(self, mock_gw_factory: MagicMock) -> None:
        order = _create_order(self.customer, status="awaiting_payment", total_cents=25000)
        succeeded_payment = Payment.objects.create(
            customer=self.customer,
            payment_method="stripe",
            amount_cents=order.total_cents,
            currency=order.currency,
            status="succeeded",
            gateway_txn_id="pi_already_succeeded",
            meta={"order_id": str(order.id), "client_secret": "sec_already_succeeded"},
        )
        mock_gateway = MagicMock()
        mock_gateway.create_payment_intent.return_value = {
            "success": True,
            "payment_intent_id": "pi_duplicate",
            "client_secret": "sec_duplicate",
        }
        mock_gw_factory.create_gateway.return_value = mock_gateway

        result = PaymentService.create_payment_intent_direct(
            order_id=str(order.id),
            customer_id=str(self.customer.id),
            gateway="stripe",
        )

        self.assertTrue(result["success"])
        self.assertEqual(result["payment_intent_id"], succeeded_payment.gateway_txn_id)
        self.assertEqual(result["client_secret"], "sec_already_succeeded")
        mock_gw_factory.create_gateway.assert_not_called()
        self.assertEqual(Payment.objects.filter(meta__order_id=str(order.id)).count(), 1)

    @patch("apps.billing.payment_service.PaymentGatewayFactory")
    def test_succeeded_payment_takes_precedence_over_newer_pending_payment(
        self, mock_gw_factory: MagicMock
    ) -> None:
        order = _create_order(self.customer, status="awaiting_payment", total_cents=25000)
        succeeded_payment = Payment.objects.create(
            customer=self.customer,
            payment_method="stripe",
            amount_cents=order.total_cents,
            currency=order.currency,
            status="succeeded",
            gateway_txn_id="pi_succeeded_winner",
            meta={"order_id": str(order.id), "client_secret": "sec_succeeded_winner"},
        )
        Payment.objects.create(
            customer=self.customer,
            payment_method="stripe",
            amount_cents=order.total_cents,
            currency=order.currency,
            status="pending",
            gateway_txn_id="pi_newer_pending",
            meta={"order_id": str(order.id), "client_secret": "sec_newer_pending"},
        )

        result = PaymentService.create_payment_intent_direct(
            order_id=str(order.id),
            customer_id=str(self.customer.id),
            gateway="stripe",
        )

        self.assertTrue(result["success"])
        self.assertEqual(result["payment_intent_id"], succeeded_payment.gateway_txn_id)
        self.assertEqual(result["client_secret"], "sec_succeeded_winner")
        mock_gw_factory.create_gateway.assert_not_called()

    @patch("apps.billing.payment_service.log_security_event", MagicMock())
    @patch("apps.billing.payment_service.PaymentGatewayFactory")
    def test_pending_lookup_is_scoped_to_order_and_gateway(self, mock_gw_factory: MagicMock) -> None:
        order_a = _create_order(self.customer, status="awaiting_payment", total_cents=25000)
        order_b = _create_order(self.customer, status="awaiting_payment", total_cents=35000)
        payment_a = Payment.objects.create(
            customer=self.customer,
            payment_method="stripe",
            amount_cents=order_a.total_cents,
            currency=order_a.currency,
            status="pending",
            gateway_txn_id="pi_order_a",
            meta={"order_id": str(order_a.id), "client_secret": "sec_order_a"},
        )
        Payment.objects.create(
            customer=self.customer,
            payment_method="stripe",
            amount_cents=order_b.total_cents,
            currency=order_b.currency,
            status="pending",
            gateway_txn_id="pi_order_b",
            meta={"order_id": str(order_b.id), "client_secret": "sec_order_b"},
        )
        Payment.objects.create(
            customer=self.customer,
            payment_method="bank",
            amount_cents=order_a.total_cents,
            currency=order_a.currency,
            status="pending",
            gateway_txn_id="bank_order_a",
            meta={"order_id": str(order_a.id)},
        )
        mock_gateway = MagicMock()
        mock_gw_factory.create_gateway.return_value = mock_gateway

        result = PaymentService.create_payment_intent_direct(
            order_id=str(order_a.id),
            customer_id=str(self.customer.id),
            gateway="stripe",
        )

        self.assertTrue(result["success"])
        self.assertEqual(result["payment_intent_id"], payment_a.gateway_txn_id)
        self.assertEqual(result["client_secret"], "sec_order_a")
        mock_gateway.create_payment_intent.assert_not_called()

    @patch("apps.billing.payment_service.PaymentGatewayFactory")
    def test_stale_pending_payment_is_rejected_without_new_gateway_call(
        self, mock_gw_factory: MagicMock
    ) -> None:
        ron, _ = Currency.objects.get_or_create(
            code="RON",
            defaults={"name": "Romanian Leu", "symbol": "lei", "decimals": 2},
        )
        eur, _ = Currency.objects.get_or_create(
            code="EUR",
            defaults={"name": "Euro", "symbol": "EUR", "decimals": 2},
        )
        scenarios = (
            ("amount", 35000, ron),
            ("currency", 25000, eur),
        )

        for index, (scenario, current_total_cents, current_currency) in enumerate(scenarios, start=1):
            with self.subTest(scenario=scenario):
                order = _create_order(self.customer, status="draft", total_cents=25000)
                Payment.objects.create(
                    customer=self.customer,
                    payment_method="stripe",
                    amount_cents=25000,
                    currency=ron,
                    status="pending",
                    gateway_txn_id=f"pi_stale_{scenario}_{index}",
                    meta={"order_id": str(order.id), "client_secret": f"sec_stale_{scenario}"},
                )
                Order.objects.filter(pk=order.pk).update(
                    subtotal_cents=current_total_cents,
                    total_cents=current_total_cents,
                    currency=current_currency,
                )

                result = PaymentService.create_payment_intent_direct(
                    order_id=str(order.id),
                    customer_id=str(self.customer.id),
                    gateway="stripe",
                )

                self.assertFalse(result["success"])
                self.assertIn("does not match", result["error"] or "")

        mock_gw_factory.create_gateway.assert_not_called()
        self.assertEqual(Payment.objects.filter(customer=self.customer).count(), 2)

    @patch("apps.billing.payment_service.log_security_event", MagicMock())
    @patch("apps.billing.payment_service.PaymentGatewayFactory")
    def test_key_is_forwarded_stored_and_metadata_identity_is_authoritative(
        self, mock_gw_factory: MagicMock
    ) -> None:
        order = _create_order(self.customer, status="awaiting_payment", total_cents=25000)
        mock_gateway = MagicMock()
        mock_gateway.create_payment_intent.return_value = {
            "success": True,
            "payment_intent_id": "pi_keyed",
            "client_secret": "sec_keyed",
        }
        mock_gw_factory.create_gateway.return_value = mock_gateway

        result = PaymentService.create_payment_intent_direct(
            order_id=str(order.id),
            customer_id=str(self.customer.id),
            gateway="stripe",
            metadata={
                "order_id": "attacker-order",
                "customer_id": "attacker-customer",
                "gateway": "attacker-gateway",
                "platform": "attacker-platform",
            },
        )

        self.assertTrue(result["success"])
        gateway_kwargs = mock_gateway.create_payment_intent.call_args.kwargs
        idempotency_key = gateway_kwargs["idempotency_key"]
        self.assertTrue(idempotency_key)
        self.assertLessEqual(len(idempotency_key), 64)
        self.assertEqual(gateway_kwargs["metadata"]["customer_id"], str(self.customer.id))
        self.assertEqual(gateway_kwargs["metadata"]["platform"], "PRAHO")

        payment = Payment.objects.get(gateway_txn_id="pi_keyed")
        self.assertEqual(payment.idempotency_key, idempotency_key)
        self.assertEqual(payment.meta["order_id"], str(order.id))
        self.assertEqual(payment.meta["customer_id"], str(self.customer.id))
        self.assertEqual(payment.meta["gateway"], "stripe")

    @patch("apps.billing.payment_service.log_security_event", MagicMock())
    @patch("apps.billing.payment_service.PaymentGatewayFactory")
    def test_failed_payment_advances_attempt_key(self, mock_gw_factory: MagicMock) -> None:
        order = _create_order(self.customer, status="awaiting_payment", total_cents=25000)
        mock_gateway = MagicMock()
        mock_gateway.create_payment_intent.side_effect = [
            {"success": True, "payment_intent_id": "pi_attempt_1", "client_secret": "sec_attempt_1"},
            {"success": True, "payment_intent_id": "pi_attempt_2", "client_secret": "sec_attempt_2"},
        ]
        mock_gw_factory.create_gateway.return_value = mock_gateway

        first_result = PaymentService.create_payment_intent_direct(
            order_id=str(order.id),
            customer_id=str(self.customer.id),
        )
        self.assertTrue(first_result["success"])
        Payment.objects.filter(gateway_txn_id="pi_attempt_1").update(status="failed")

        second_result = PaymentService.create_payment_intent_direct(
            order_id=str(order.id),
            customer_id=str(self.customer.id),
        )

        self.assertTrue(second_result["success"])
        first_key = mock_gateway.create_payment_intent.call_args_list[0].kwargs["idempotency_key"]
        second_key = mock_gateway.create_payment_intent.call_args_list[1].kwargs["idempotency_key"]
        self.assertNotEqual(first_key, second_key)
        self.assertEqual(Payment.objects.filter(meta__order_id=str(order.id)).count(), 2)

    @patch("apps.billing.payment_service.PaymentGatewayFactory")
    def test_legacy_pending_payment_without_key_is_reused(self, mock_gw_factory: MagicMock) -> None:
        order = _create_order(self.customer, status="awaiting_payment", total_cents=25000)
        legacy_payment = Payment.objects.create(
            customer=self.customer,
            payment_method="stripe",
            amount_cents=order.total_cents,
            currency=order.currency,
            status="pending",
            gateway_txn_id="pi_legacy",
            idempotency_key=None,
            meta={"order_id": str(order.id), "client_secret": "sec_legacy"},
        )

        result = PaymentService.create_payment_intent_direct(
            order_id=str(order.id),
            customer_id=str(self.customer.id),
        )

        self.assertTrue(result["success"])
        self.assertEqual(result["payment_intent_id"], legacy_payment.gateway_txn_id)
        mock_gw_factory.create_gateway.assert_not_called()

    @patch("apps.billing.payment_service.log_security_event", MagicMock())
    @patch("apps.billing.payment_service.PaymentGatewayFactory")
    def test_retry_after_local_insert_failure_reuses_same_gateway_intent(
        self, mock_gw_factory: MagicMock
    ) -> None:
        order = _create_order(self.customer, status="awaiting_payment", total_cents=25000)
        fake_gateway = _IdempotentFakeGateway()
        mock_gw_factory.create_gateway.return_value = fake_gateway
        original_get_or_create = Payment.objects.get_or_create
        persistence_attempts = 0

        def fail_first_persistence(*args: Any, **kwargs: Any):
            nonlocal persistence_attempts
            persistence_attempts += 1
            if persistence_attempts == 1:
                raise RuntimeError("database insert failed")
            return original_get_or_create(*args, **kwargs)

        with patch.object(Payment.objects, "get_or_create", side_effect=fail_first_persistence):
            first_result = PaymentService.create_payment_intent_direct(
                order_id=str(order.id),
                customer_id=str(self.customer.id),
                metadata={"request_marker": "first"},
            )
            second_result = PaymentService.create_payment_intent_direct(
                order_id=str(order.id),
                customer_id=str(self.customer.id),
                metadata={"request_marker": "second"},
            )

        self.assertFalse(first_result["success"])
        self.assertTrue(second_result["success"])
        self.assertEqual(second_result["payment_intent_id"], "pi_fake_1")
        self.assertEqual(len(fake_gateway.calls), 2)
        self.assertEqual(fake_gateway.calls[0], fake_gateway.calls[1])
        self.assertEqual(fake_gateway.remote_creations, 1)
        payment = Payment.objects.get(meta__order_id=str(order.id))
        self.assertEqual(payment.meta["request_marker"], "second")
        self.assertNotIn("request_marker", fake_gateway.request_fingerprints[fake_gateway.calls[0]])

    @patch("apps.billing.payment_service.log_security_event", MagicMock())
    @patch("apps.billing.payment_service.PaymentGatewayFactory")
    def test_draft_total_change_after_local_failure_uses_new_request_key(
        self, mock_gw_factory: MagicMock
    ) -> None:
        order = _create_order(self.customer, status="draft", total_cents=25000)
        fake_gateway = _IdempotentFakeGateway()
        mock_gw_factory.create_gateway.return_value = fake_gateway
        original_get_or_create = Payment.objects.get_or_create
        persistence_attempts = 0

        def fail_first_persistence(*args: Any, **kwargs: Any):
            nonlocal persistence_attempts
            persistence_attempts += 1
            if persistence_attempts == 1:
                raise RuntimeError("database insert failed")
            return original_get_or_create(*args, **kwargs)

        with patch.object(Payment.objects, "get_or_create", side_effect=fail_first_persistence):
            first_result = PaymentService.create_payment_intent_direct(
                order_id=str(order.id),
                customer_id=str(self.customer.id),
            )
            Order.objects.filter(pk=order.pk).update(
                subtotal_cents=35000,
                total_cents=35000,
            )
            second_result = PaymentService.create_payment_intent_direct(
                order_id=str(order.id),
                customer_id=str(self.customer.id),
            )

        self.assertFalse(first_result["success"])
        self.assertTrue(second_result["success"])
        self.assertNotEqual(fake_gateway.calls[0], fake_gateway.calls[1])
        self.assertEqual(fake_gateway.remote_creations, 2)
        payment = Payment.objects.get(meta__order_id=str(order.id))
        self.assertEqual(payment.amount_cents, 35000)

    @patch("apps.billing.payment_service.log_security_event", MagicMock())
    @patch("apps.billing.payment_service.PaymentGatewayFactory")
    def test_failed_concurrent_winner_is_not_returned_as_success(self, mock_gw_factory: MagicMock) -> None:
        order = _create_order(self.customer, status="awaiting_payment", total_cents=25000)
        mock_gateway = MagicMock()
        mock_gateway.create_payment_intent.side_effect = [
            {
                "success": True,
                "payment_intent_id": "pi_race_attempt_1",
                "client_secret": "sec_race_attempt_1",
            },
            {
                "success": True,
                "payment_intent_id": "pi_race_attempt_2",
                "client_secret": "sec_race_attempt_2",
            },
        ]
        mock_gw_factory.create_gateway.return_value = mock_gateway

        def insert_failed_winner(*, idempotency_key: str, defaults: dict[str, Any]):
            failed_defaults = {**defaults, "status": "failed"}
            payment = Payment.objects.create(idempotency_key=idempotency_key, **failed_defaults)
            return payment, False

        with patch.object(Payment.objects, "get_or_create", side_effect=insert_failed_winner):
            first_result = PaymentService.create_payment_intent_direct(
                order_id=str(order.id),
                customer_id=str(self.customer.id),
            )

        second_result = PaymentService.create_payment_intent_direct(
            order_id=str(order.id),
            customer_id=str(self.customer.id),
        )

        self.assertFalse(first_result["success"])
        self.assertIn("failed", first_result["error"] or "")
        self.assertTrue(second_result["success"])
        first_key = mock_gateway.create_payment_intent.call_args_list[0].kwargs["idempotency_key"]
        second_key = mock_gateway.create_payment_intent.call_args_list[1].kwargs["idempotency_key"]
        self.assertNotEqual(first_key, second_key)
        self.assertEqual(Payment.objects.filter(meta__order_id=str(order.id)).count(), 2)


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
