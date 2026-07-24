"""Behavior tests for refund gateway and local-ledger integrity (issue #212)."""

from __future__ import annotations

import uuid
from datetime import timedelta
from typing import Any
from unittest import mock
from unittest.mock import MagicMock, patch

from django.db import IntegrityError, OperationalError, transaction
from django.test import TestCase
from django.utils import timezone

from apps.billing.models import Currency, Invoice, Payment, ProformaInvoice, Refund, RefundStatusHistory
from apps.billing.refund_service import Err, RefundConvergenceService, RefundData, RefundService
from apps.common.types import Retriability
from apps.customers.models import Customer
from apps.orders.models import Order


class RefundGatewayIntegrityTests(TestCase):
    """Exercise the public refund service with only the gateway boundary mocked."""

    def setUp(self) -> None:
        self.currency, _ = Currency.objects.get_or_create(
            code="RON",
            defaults={"name": "Romanian Leu", "symbol": "lei", "decimals": 2},
        )
        self.customer = Customer.objects.create(
            name="Refund Integrity SRL",
            customer_type="company",
            company_name="Refund Integrity SRL",
            status="active",
        )

    def _make_invoice(self, *, total_cents: int = 10_000) -> Invoice:
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

    def _make_order(self, invoice: Invoice, *, total_cents: int = 10_000) -> Order:
        return Order.objects.create(
            order_number=f"ORD-{uuid.uuid4().hex[:10]}",
            customer=self.customer,
            currency=self.currency,
            invoice=invoice,
            status="completed",
            subtotal_cents=total_cents,
            tax_cents=0,
            total_cents=total_cents,
            customer_email="billing@example.test",
            customer_name=self.customer.company_name,
        )

    def _make_payment(self, invoice: Invoice, *, transaction_id: str) -> Payment:
        return Payment.objects.create(
            customer=self.customer,
            invoice=invoice,
            currency=self.currency,
            status="succeeded",
            payment_method="stripe",
            amount_cents=invoice.total_cents,
            gateway_txn_id=transaction_id,
        )

    @staticmethod
    def _refund_data(amount_cents: int = 10_000) -> RefundData:
        return {
            "refund_type": "full",
            "amount_cents": amount_cents,
            "reason": "customer_request",
            "notes": "Issue #212 regression",
        }

    def test_invoice_gateway_failure_preserves_durable_refund_intent(self) -> None:
        invoice = self._make_invoice()
        payment = self._make_payment(invoice, transaction_id="pi_gateway_failure")
        gateway = MagicMock()
        gateway.refund_payment.return_value = {
            "success": False,
            "refund_id": None,
            "amount_refunded_cents": 0,
            "status": "error",
            "error": "temporary provider failure",
        }

        with patch("apps.billing.gateways.base.PaymentGatewayFactory.create_gateway", return_value=gateway):
            result = RefundService.refund_invoice(invoice.id, self._refund_data())

        self.assertTrue(result.is_err())
        self.assertIn("Gateway refund failed: temporary provider failure", result.unwrap_err())
        gateway.refund_payment.assert_called_once_with(
            gateway_txn_id="pi_gateway_failure",
            amount_cents=10_000,
            idempotency_key=mock.ANY,
        )

        invoice.refresh_from_db()
        payment.refresh_from_db()
        self.assertEqual(invoice.status, "paid")
        self.assertEqual(payment.status, "succeeded")
        self.assertEqual(payment.meta, {})
        refund = Refund.objects.get(invoice=invoice, payment=payment)
        self.assertEqual(refund.status, "pending")
        self.assertEqual(refund.amount_cents, 10_000)
        self.assertEqual(refund.gateway_refund_id, "")
        self.assertEqual(gateway.refund_payment.call_args.kwargs["idempotency_key"], f"refund:{refund.id}")

    def test_immediate_terminal_gateway_failure_is_persisted_but_reported_as_failure(self) -> None:
        invoice = self._make_invoice()
        payment = self._make_payment(invoice, transaction_id="pi_terminal_failure")
        gateway = MagicMock()
        gateway.refund_payment.return_value = {
            "success": True,
            "refund_id": "re_terminal_failure",
            "amount_refunded_cents": 10_000,
            "status": "failed",
            "error": None,
        }

        with patch("apps.billing.gateways.base.PaymentGatewayFactory.create_gateway", return_value=gateway):
            result = RefundService.refund_invoice(invoice.id, self._refund_data())

        self.assertTrue(result.is_err())
        self.assertIn("failed", result.unwrap_err().lower())
        refund = Refund.objects.get(gateway_refund_id="re_terminal_failure")
        self.assertEqual(refund.status, "failed")
        payment.refresh_from_db()
        invoice.refresh_from_db()
        self.assertEqual(payment.status, "succeeded")
        self.assertEqual(invoice.status, "paid")

    def test_order_refund_uses_invoice_payment_and_persists_gateway_reference(self) -> None:
        invoice = self._make_invoice()
        order = self._make_order(invoice)
        payment = self._make_payment(invoice, transaction_id="pi_order_refund")
        gateway = MagicMock()
        gateway.refund_payment.return_value = {
            "success": True,
            "refund_id": "re_order_refund",
            "amount_refunded_cents": 10_000,
            "status": "succeeded",
            "error": None,
        }

        with patch("apps.billing.gateways.base.PaymentGatewayFactory.create_gateway", return_value=gateway):
            result = RefundService.refund_order(order.id, self._refund_data())

        self.assertTrue(result.is_ok(), result.unwrap_err() if result.is_err() else "")
        self.assertTrue(result.unwrap()["payment_refund_processed"])
        gateway.refund_payment.assert_called_once_with(
            gateway_txn_id="pi_order_refund",
            amount_cents=10_000,
            idempotency_key=mock.ANY,
        )

        payment.refresh_from_db()
        self.assertEqual(payment.status, "refunded")
        self.assertEqual(payment.meta["refund_id"], "re_order_refund")

        refund = Refund.objects.get(order=order)
        self.assertEqual(refund.payment_id, payment.id)
        self.assertEqual(refund.gateway_refund_id, "re_order_refund")

    def test_full_invoice_refund_without_amount_materializes_exact_gateway_and_ledger_amount(self) -> None:
        invoice = self._make_invoice()
        payment = self._make_payment(invoice, transaction_id="pi_full_without_amount")
        gateway = MagicMock()
        gateway.refund_payment.return_value = {
            "success": True,
            "refund_id": "re_full_without_amount",
            "amount_refunded_cents": 10_000,
            "status": "succeeded",
            "error": None,
        }
        refund_data: RefundData = {
            "refund_type": "full",
            "reason": "customer_request",
            "notes": "Full refund amount must be materialized before the gateway call",
        }

        with patch("apps.billing.gateways.base.PaymentGatewayFactory.create_gateway", return_value=gateway):
            result = RefundService.refund_invoice(invoice.id, refund_data)

        self.assertTrue(result.is_ok(), result.unwrap_err() if result.is_err() else "")
        self.assertEqual(result.unwrap()["amount_refunded_cents"], 10_000)
        gateway.refund_payment.assert_called_once_with(
            gateway_txn_id="pi_full_without_amount",
            amount_cents=10_000,
            idempotency_key=mock.ANY,
        )

        payment.refresh_from_db()
        invoice.refresh_from_db()
        refund = Refund.objects.get(invoice=invoice)
        self.assertEqual(refund.amount_cents, 10_000)
        self.assertEqual(payment.status, "refunded")
        self.assertEqual(invoice.status, "refunded")

    def test_direct_order_orchestration_locks_linked_invoice_before_gateway(self) -> None:
        invoice = self._make_invoice()
        order = self._make_order(invoice)
        payment = self._make_payment(invoice, transaction_id="pi_direct_order_lock")
        refund_intent = Refund.objects.create(
            customer=self.customer,
            order=order,
            payment=payment,
            amount_cents=10_000,
            currency=self.currency,
            original_amount_cents=10_000,
            refund_type="full",
            status="pending",
            gateway_refund_id="",
        )
        order._state.fields_cache.pop("invoice", None)
        gateway = MagicMock()
        gateway_response = {
            "success": True,
            "refund_id": "re_direct_order_lock",
            "amount_refunded_cents": 10_000,
            "status": "succeeded",
            "error": None,
        }

        with (
            patch.object(Invoice.objects, "select_for_update", wraps=Invoice.objects.select_for_update) as lock_invoice,
            patch("apps.billing.gateways.base.PaymentGatewayFactory.create_gateway", return_value=gateway),
        ):
            def refund_after_invoice_lock(**_kwargs: object) -> dict[str, object]:
                lock_invoice.assert_called_once_with(of=("self",))
                return gateway_response

            gateway.refund_payment.side_effect = refund_after_invoice_lock
            result = RefundService._process_bidirectional_refund(
                order=order,
                refund_id=refund_intent.id,
                refund_data=self._refund_data(),
                reserved_refund=refund_intent,
            )

        self.assertTrue(result.is_ok(), result.unwrap_err() if result.is_err() else "")
        lock_invoice.assert_called_once_with(of=("self",))
        gateway.refund_payment.assert_called_once()

    def test_invoice_refund_locks_payment_before_invoice(self) -> None:
        invoice = self._make_invoice()
        self._make_payment(invoice, transaction_id="pi_payment_before_invoice")
        gateway = MagicMock()
        gateway.refund_payment.return_value = {
            "success": True,
            "refund_id": "re_payment_before_invoice",
            "amount_refunded_cents": 10_000,
            "status": "succeeded",
            "error": None,
        }
        lock_order: list[str] = []
        payment_select_for_update = Payment.objects.select_for_update
        invoice_select_for_update = Invoice.objects.select_for_update

        def track_payment_lock(*args: object, **kwargs: object) -> Any:
            lock_order.append("payment")
            return payment_select_for_update(*args, **kwargs)

        def track_invoice_lock(*args: object, **kwargs: object) -> Any:
            lock_order.append("invoice")
            return invoice_select_for_update(*args, **kwargs)

        with (
            patch.object(Payment.objects, "select_for_update", side_effect=track_payment_lock),
            patch.object(Invoice.objects, "select_for_update", side_effect=track_invoice_lock),
            patch("apps.billing.gateways.base.PaymentGatewayFactory.create_gateway", return_value=gateway),
        ):
            result = RefundService.refund_invoice(invoice.id, self._refund_data())

        self.assertTrue(result.is_ok(), result.unwrap_err() if result.is_err() else "")
        self.assertIn("payment", lock_order)
        self.assertIn("invoice", lock_order)
        self.assertLess(lock_order.index("payment"), lock_order.index("invoice"))

    def test_order_refund_finds_payment_linked_only_by_order_metadata(self) -> None:
        invoice = self._make_invoice()
        order = self._make_order(invoice)
        payment = Payment.objects.create(
            customer=self.customer,
            currency=self.currency,
            status="succeeded",
            payment_method="stripe",
            amount_cents=order.total_cents,
            gateway_txn_id="pi_order_metadata_only",
            meta={"order_id": str(order.id)},
        )
        gateway = MagicMock()
        gateway.refund_payment.return_value = {
            "success": True,
            "refund_id": "re_order_metadata_only",
            "amount_refunded_cents": 10_000,
            "status": "succeeded",
            "error": None,
        }

        with patch("apps.billing.gateways.base.PaymentGatewayFactory.create_gateway", return_value=gateway):
            result = RefundService.refund_order(order.id, self._refund_data())

        self.assertTrue(result.is_ok(), result.unwrap_err() if result.is_err() else "")
        self.assertEqual(Refund.objects.get(order=order).payment_id, payment.id)

    def test_order_refund_finds_payment_linked_only_by_proforma(self) -> None:
        invoice = self._make_invoice()
        proforma = ProformaInvoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number=f"PRO-{uuid.uuid4().hex[:10]}",
            subtotal_cents=10_000,
            tax_cents=0,
            total_cents=10_000,
            valid_until=timezone.now() + timedelta(days=7),
        )
        order = self._make_order(invoice)
        order.proforma = proforma
        order.save(update_fields=["proforma", "updated_at"])
        payment = Payment.objects.create(
            customer=self.customer,
            proforma=proforma,
            currency=self.currency,
            status="succeeded",
            payment_method="stripe",
            amount_cents=order.total_cents,
            gateway_txn_id="pi_order_proforma_only",
        )
        gateway = MagicMock()
        gateway.refund_payment.return_value = {
            "success": True,
            "refund_id": "re_order_proforma_only",
            "amount_refunded_cents": 10_000,
            "status": "succeeded",
            "error": None,
        }

        with patch("apps.billing.gateways.base.PaymentGatewayFactory.create_gateway", return_value=gateway):
            result = RefundService.refund_order(order.id, self._refund_data())

        self.assertTrue(result.is_ok(), result.unwrap_err() if result.is_err() else "")
        self.assertEqual(Refund.objects.get(order=order).payment_id, payment.id)

    def test_pending_gateway_refund_reserves_amount_without_settling_documents(self) -> None:
        invoice = self._make_invoice()
        payment = self._make_payment(invoice, transaction_id="pi_pending_refund")
        gateway = MagicMock()
        gateway.refund_payment.return_value = {
            "success": True,
            "refund_id": "re_pending_refund",
            "amount_refunded_cents": 10_000,
            "status": "pending",
            "error": None,
        }

        with patch("apps.billing.gateways.base.PaymentGatewayFactory.create_gateway", return_value=gateway):
            result = RefundService.refund_invoice(invoice.id, self._refund_data())

        self.assertTrue(result.is_ok(), result.unwrap_err() if result.is_err() else "")
        refund = Refund.objects.get(gateway_refund_id="re_pending_refund")
        self.assertEqual(refund.status, "processing")
        self.assertEqual(refund.metadata["gateway_status"], "pending")
        self.assertIsNone(refund.processed_at)
        self.assertEqual(
            list(refund.status_history.order_by("changed_at").values_list("new_status", flat=True)),
            ["pending", "processing"],
        )
        payment.refresh_from_db()
        invoice.refresh_from_db()
        self.assertEqual(payment.status, "succeeded")
        self.assertEqual(invoice.status, "paid")

        eligibility = RefundService._validate_invoice_refund_eligibility(invoice, self._refund_data())
        self.assertTrue(eligibility.is_ok())
        self.assertFalse(eligibility.unwrap()["is_eligible"])

    def test_succeeded_gateway_refund_completes_fsm_and_documents(self) -> None:
        invoice = self._make_invoice()
        payment = self._make_payment(invoice, transaction_id="pi_completed_fsm")
        gateway = MagicMock()
        gateway.refund_payment.return_value = {
            "success": True,
            "refund_id": "re_completed_fsm",
            "amount_refunded_cents": 10_000,
            "status": "succeeded",
            "error": None,
        }

        with patch("apps.billing.gateways.base.PaymentGatewayFactory.create_gateway", return_value=gateway):
            result = RefundService.refund_invoice(invoice.id, self._refund_data())

        self.assertTrue(result.is_ok(), result.unwrap_err() if result.is_err() else "")
        refund = Refund.objects.get(gateway_refund_id="re_completed_fsm")
        self.assertEqual(refund.status, "completed")
        self.assertIsNotNone(refund.processed_at)
        self.assertIsNotNone(refund.gateway_processed_at)
        self.assertEqual(
            list(refund.status_history.order_by("changed_at").values_list("new_status", flat=True)),
            ["pending", "processing", "approved", "completed"],
        )
        payment.refresh_from_db()
        invoice.refresh_from_db()
        self.assertEqual(payment.status, "refunded")
        self.assertEqual(invoice.status, "refunded")

    def test_completed_remaining_balance_does_not_settle_an_earlier_pending_refund(self) -> None:
        invoice = self._make_invoice()
        payment = self._make_payment(invoice, transaction_id="pi_mixed_refund_states")
        Refund.objects.create(
            customer=self.customer,
            invoice=invoice,
            payment=payment,
            amount_cents=4_000,
            currency=self.currency,
            original_amount_cents=10_000,
            status="processing",
            gateway_refund_id="re_still_pending",
            reference_number="REF-STILL-PENDING",
        )
        gateway = MagicMock()
        gateway.refund_payment.return_value = {
            "success": True,
            "refund_id": "re_completed_remaining",
            "amount_refunded_cents": 6_000,
            "status": "succeeded",
            "error": None,
        }

        with patch("apps.billing.gateways.base.PaymentGatewayFactory.create_gateway", return_value=gateway):
            result = RefundService.refund_invoice(invoice.id, {"refund_type": "full"})

        self.assertTrue(result.is_ok(), result.unwrap_err() if result.is_err() else "")
        gateway.refund_payment.assert_called_once_with(
            gateway_txn_id="pi_mixed_refund_states",
            amount_cents=6_000,
            idempotency_key=mock.ANY,
        )
        payment.refresh_from_db()
        invoice.refresh_from_db()
        self.assertEqual(payment.status, "partially_refunded")
        self.assertEqual(invoice.status, "partially_refunded")

    def test_modern_refund_webhook_settles_pending_refund_idempotently(self) -> None:
        invoice = self._make_invoice()
        payment = self._make_payment(invoice, transaction_id="pi_webhook_settlement")
        gateway = MagicMock()
        gateway.refund_payment.return_value = {
            "success": True,
            "refund_id": "re_webhook_settlement",
            "amount_refunded_cents": 10_000,
            "status": "pending",
            "error": None,
        }
        with patch("apps.billing.gateways.base.PaymentGatewayFactory.create_gateway", return_value=gateway):
            initiated = RefundService.refund_invoice(invoice.id, self._refund_data())
        self.assertTrue(initiated.is_ok())

        payload = {
            "id": "evt_refund_settled",
            "created": 1_784_500_000,
            "data": {
                "object": {
                    "id": "re_webhook_settlement",
                    "payment_intent": "pi_webhook_settlement",
                    "amount": 10_000,
                    "currency": "ron",
                    "status": "succeeded",
                }
            },
        }
        from apps.integrations.webhooks.stripe import StripeWebhookProcessor  # noqa: PLC0415

        processor = StripeWebhookProcessor()
        accepted, message = processor.handle_refund_event("refund.updated", payload)
        self.assertTrue(accepted, message)
        refund = Refund.objects.get(gateway_refund_id="re_webhook_settlement")
        payment.refresh_from_db()
        invoice.refresh_from_db()
        self.assertEqual(refund.status, "completed")
        self.assertEqual(payment.status, "refunded")
        self.assertEqual(invoice.status, "refunded")
        history_count = RefundStatusHistory.objects.filter(refund=refund).count()

        duplicate_accepted, duplicate_message = processor.handle_refund_event("refund.updated", payload)
        self.assertTrue(duplicate_accepted, duplicate_message)
        self.assertEqual(RefundStatusHistory.objects.filter(refund=refund).count(), history_count)

    def test_reconciliation_preserves_event_watermark_and_ignores_older_webhook(self) -> None:
        invoice = self._make_invoice()
        payment = self._make_payment(invoice, transaction_id="pi_refund_ordering")
        Refund.objects.create(
            customer=self.customer,
            invoice=invoice,
            payment=payment,
            amount_cents=10_000,
            currency=self.currency,
            original_amount_cents=10_000,
            status="processing",
            gateway_refund_id="re_refund_ordering",
            reference_number="REF-ORDERING",
        )
        payload = {
            "id": "evt_refund_newer",
            "created": 200,
            "data": {"object": {
                "id": "re_refund_ordering",
                "payment_intent": "pi_refund_ordering",
                "amount": 10_000,
                "currency": "ron",
                "status": "succeeded",
            }},
        }
        from apps.billing.refund_service import RefundConvergenceService  # noqa: PLC0415
        from apps.integrations.webhooks.stripe import StripeWebhookProcessor  # noqa: PLC0415

        accepted, message = StripeWebhookProcessor().handle_refund_event("refund.updated", payload)
        self.assertTrue(accepted, message)
        sweep = RefundConvergenceService.converge_gateway_refund(
            {
                "refund_id": "re_refund_ordering",
                "payment_intent_id": "pi_refund_ordering",
                "amount_cents": 10_000,
                "currency": "ron",
                "status": "succeeded",
            }
        )
        self.assertTrue(sweep.is_ok())
        older_payload = {
            **payload,
            "id": "evt_refund_older",
            "created": 100,
            "data": {"object": {**payload["data"]["object"], "status": "pending"}},
        }
        older_accepted, older_message = StripeWebhookProcessor().handle_refund_event(
            "refund.updated",
            older_payload,
        )
        self.assertTrue(older_accepted, older_message)

        refund = Refund.objects.get(gateway_refund_id="re_refund_ordering")
        self.assertEqual(refund.status, "completed")
        self.assertEqual(refund.metadata["gateway_event_id"], "evt_refund_newer")
        self.assertEqual(refund.metadata["gateway_event_created"], 200)

    def test_refund_webhook_acknowledges_amount_mismatch_without_mutation(self) -> None:
        invoice = self._make_invoice()
        payment = self._make_payment(invoice, transaction_id="pi_refund_mismatch")
        refund = Refund.objects.create(
            customer=self.customer,
            invoice=invoice,
            payment=payment,
            amount_cents=10_000,
            currency=self.currency,
            original_amount_cents=10_000,
            status="processing",
            gateway_refund_id="re_refund_mismatch",
            reference_number="REF-MISMATCH",
        )
        payload = {
            "id": "evt_refund_mismatch",
            "created": 1_784_500_001,
            "data": {"object": {
                "id": "re_refund_mismatch",
                "payment_intent": "pi_refund_mismatch",
                "amount": 9_999,
                "currency": "ron",
                "status": "succeeded",
            }},
        }
        from apps.integrations.webhooks.stripe import StripeWebhookProcessor  # noqa: PLC0415

        with self.assertLogs("apps.integrations.webhooks.stripe", level="CRITICAL") as logs:
            accepted, message = StripeWebhookProcessor().handle_refund_event("refund.updated", payload)

        self.assertTrue(accepted)
        self.assertIn("amount mismatch", message.lower())
        self.assertIn("manual reconciliation required", logs.output[0])
        refund.refresh_from_db()
        payment.refresh_from_db()
        invoice.refresh_from_db()
        self.assertEqual(refund.status, "processing")
        self.assertEqual(payment.status, "succeeded")
        self.assertEqual(invoice.status, "paid")

    def test_refund_webhook_imports_dashboard_refund_for_known_payment(self) -> None:
        invoice = self._make_invoice()
        payment = self._make_payment(invoice, transaction_id="pi_dashboard_refund")
        payload = {
            "id": "evt_dashboard_refund",
            "created": 1_784_500_002,
            "data": {"object": {
                "id": "re_dashboard_refund",
                "payment_intent": "pi_dashboard_refund",
                "amount": 2_500,
                "currency": "ron",
                "status": "succeeded",
                "reason": "requested_by_customer",
            }},
        }
        from apps.integrations.webhooks.stripe import StripeWebhookProcessor  # noqa: PLC0415

        accepted, message = StripeWebhookProcessor().handle_refund_event("refund.created", payload)

        self.assertTrue(accepted, message)
        refund = Refund.objects.get(gateway_refund_id="re_dashboard_refund")
        self.assertEqual(refund.payment_id, payment.id)
        self.assertEqual(refund.invoice_id, invoice.id)
        self.assertEqual(refund.amount_cents, 2_500)
        self.assertEqual(refund.status, "completed")
        self.assertEqual(refund.refund_type, "partial")
        payment.refresh_from_db()
        invoice.refresh_from_db()
        self.assertEqual(payment.status, "partially_refunded")
        self.assertEqual(invoice.status, "partially_refunded")

    def test_dashboard_refund_imports_for_proforma_only_order_payment(self) -> None:
        proforma = ProformaInvoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number=f"PRO-{uuid.uuid4().hex[:10]}",
            subtotal_cents=10_000,
            tax_cents=0,
            total_cents=10_000,
            valid_until=timezone.now() + timedelta(days=7),
        )
        order = Order.objects.create(
            order_number=f"ORD-{uuid.uuid4().hex[:10]}",
            customer=self.customer,
            currency=self.currency,
            proforma=proforma,
            status="completed",
            subtotal_cents=10_000,
            tax_cents=0,
            total_cents=10_000,
            customer_email="billing@example.test",
            customer_name=self.customer.company_name,
        )
        payment = Payment.objects.create(
            customer=self.customer,
            proforma=proforma,
            currency=self.currency,
            status="succeeded",
            payment_method="stripe",
            amount_cents=10_000,
            gateway_txn_id="pi_dashboard_order",
            meta={"order_id": str(order.id)},
        )
        payload = {
            "id": "evt_dashboard_order",
            "created": 1_784_500_005,
            "data": {"object": {
                "id": "re_dashboard_order",
                "payment_intent": "pi_dashboard_order",
                "amount": 10_000,
                "currency": "ron",
                "status": "succeeded",
            }},
        }
        from apps.integrations.webhooks.stripe import StripeWebhookProcessor  # noqa: PLC0415

        accepted, message = StripeWebhookProcessor().handle_refund_event("refund.created", payload)

        self.assertTrue(accepted, message)
        refund = Refund.objects.get(gateway_refund_id="re_dashboard_order")
        self.assertEqual(refund.order_id, order.id)
        self.assertIsNone(refund.invoice_id)
        self.assertEqual(refund.payment_id, payment.id)
        payment.refresh_from_db()
        self.assertEqual(payment.status, "refunded")

    def test_webhook_links_legacy_refund_to_payment_before_projection(self) -> None:
        invoice = self._make_invoice()
        payment = self._make_payment(invoice, transaction_id="pi_legacy_unlinked")
        refund = Refund.objects.create(
            customer=self.customer,
            invoice=invoice,
            amount_cents=10_000,
            currency=self.currency,
            original_amount_cents=10_000,
            status="processing",
            gateway_refund_id="re_legacy_unlinked",
            reference_number="REF-LEGACY-UNLINKED",
        )
        payload = {
            "id": "evt_legacy_unlinked",
            "created": 1_784_500_006,
            "data": {"object": {
                "id": "re_legacy_unlinked",
                "payment_intent": "pi_legacy_unlinked",
                "amount": 10_000,
                "currency": "ron",
                "status": "succeeded",
            }},
        }
        from apps.integrations.webhooks.stripe import StripeWebhookProcessor  # noqa: PLC0415

        accepted, message = StripeWebhookProcessor().handle_refund_event("refund.updated", payload)

        self.assertTrue(accepted, message)
        refund.refresh_from_db()
        payment.refresh_from_db()
        self.assertEqual(refund.payment_id, payment.id)
        self.assertEqual(payment.status, "refunded")

    def test_settlement_projection_counts_legacy_unlinked_invoice_refunds(self) -> None:
        invoice = self._make_invoice()
        payment = self._make_payment(invoice, transaction_id="pi_legacy_projection")
        payment.partially_refund()
        payment.save(update_fields=["status", "updated_at"])
        Refund.objects.create(
            customer=self.customer,
            invoice=invoice,
            amount_cents=2_500,
            currency=self.currency,
            original_amount_cents=10_000,
            status="completed",
            reference_number="REF-LEGACY-PROJECTION",
        )
        Refund.objects.create(
            customer=self.customer,
            invoice=invoice,
            payment=payment,
            amount_cents=7_500,
            currency=self.currency,
            original_amount_cents=10_000,
            status="completed",
            reference_number="REF-LINKED-PROJECTION",
        )

        result = RefundService._project_settled_refunds(payment, invoice)

        self.assertTrue(result.is_ok(), result.unwrap_err() if result.is_err() else "")
        payment.refresh_from_db()
        invoice.refresh_from_db()
        self.assertEqual(payment.status, "refunded")
        self.assertEqual(invoice.status, "refunded")

    def test_legacy_charge_refunded_event_converges_embedded_refund(self) -> None:
        invoice = self._make_invoice()
        payment = self._make_payment(invoice, transaction_id="pi_legacy_refund")
        gateway = MagicMock()
        gateway.refund_payment.return_value = {
            "success": True,
            "refund_id": "re_legacy_refund",
            "amount_refunded_cents": 10_000,
            "status": "pending",
            "error": None,
        }
        with patch("apps.billing.gateways.base.PaymentGatewayFactory.create_gateway", return_value=gateway):
            initiated = RefundService.refund_invoice(invoice.id, self._refund_data())
        self.assertTrue(initiated.is_ok())

        payload = {
            "id": "evt_legacy_charge_refunded",
            "created": 1_784_500_003,
            "data": {"object": {
                "id": "ch_legacy_refund",
                "payment_intent": "pi_legacy_refund",
                "currency": "ron",
                "refunds": {"data": [{
                    "id": "re_legacy_refund",
                    "amount": 10_000,
                    "currency": "ron",
                    "status": "succeeded",
                    "payment_intent": "pi_legacy_refund",
                }]},
            }},
        }
        from apps.integrations.webhooks.stripe import StripeWebhookProcessor  # noqa: PLC0415

        accepted, message = StripeWebhookProcessor().handle_charge_event("charge.refunded", payload)

        self.assertTrue(accepted, message)
        self.assertEqual(Refund.objects.get(gateway_refund_id="re_legacy_refund").status, "completed")
        payment.refresh_from_db()
        invoice.refresh_from_db()
        self.assertEqual(payment.status, "refunded")
        self.assertEqual(invoice.status, "refunded")

    def test_failed_refund_webhook_releases_stale_document_projection(self) -> None:
        invoice = self._make_invoice()
        payment = self._make_payment(invoice, transaction_id="pi_failed_refund")
        refund = Refund.objects.create(
            customer=self.customer,
            invoice=invoice,
            payment=payment,
            amount_cents=10_000,
            currency=self.currency,
            original_amount_cents=10_000,
            status="processing",
            gateway_refund_id="re_failed_refund",
            reference_number="REF-FAILED-WEBHOOK",
        )
        Payment.objects.filter(pk=payment.pk).update(status="refunded")
        Invoice.objects.filter(pk=invoice.pk).update(status="refunded")
        payload = {
            "id": "evt_failed_refund",
            "created": 1_784_500_004,
            "data": {"object": {
                "id": "re_failed_refund",
                "payment_intent": "pi_failed_refund",
                "amount": 10_000,
                "currency": "ron",
                "status": "failed",
                "failure_reason": "lost_or_stolen_card",
            }},
        }
        from apps.integrations.webhooks.stripe import StripeWebhookProcessor  # noqa: PLC0415

        with (
            patch("apps.billing.signals._handle_payment_success") as payment_success,
            patch("apps.billing.signals._activate_payment_services") as activate_services,
            patch("apps.customers.services.CustomerCreditService.update_credit_score") as update_credit,
        ):
            accepted, message = StripeWebhookProcessor().handle_refund_event("refund.failed", payload)

        self.assertTrue(accepted, message)
        payment_success.assert_not_called()
        activate_services.assert_not_called()
        update_credit.assert_not_called()
        refund.refresh_from_db()
        payment.refresh_from_db()
        invoice.refresh_from_db()
        self.assertEqual(refund.status, "failed")
        self.assertEqual(refund.metadata["gateway_failure_reason"], "lost_or_stolen_card")
        self.assertEqual(payment.status, "succeeded")
        self.assertEqual(invoice.status, "paid")
        self.assertEqual(RefundService._get_invoice_refunded_amount(invoice), 0)

    def test_failed_gateway_fact_releases_an_approved_refund_reservation(self) -> None:
        invoice = self._make_invoice()
        payment = self._make_payment(invoice, transaction_id="pi_approved_failure")
        refund = Refund.objects.create(
            customer=self.customer, invoice=invoice, payment=payment,
            amount_cents=10_000, currency=self.currency, original_amount_cents=10_000,
            status="approved", gateway_refund_id="re_approved_failure",
            reference_number="REF-APPROVED-FAILURE",
        )
        from apps.billing.refund_service import RefundConvergenceService  # noqa: PLC0415

        result = RefundConvergenceService.converge_gateway_refund({
            "refund_id": "re_approved_failure",
            "payment_intent_id": "pi_approved_failure",
            "amount_cents": 10_000,
            "currency": "ron",
            "status": "failed",
        })

        self.assertTrue(result.is_ok(), result.unwrap_err() if result.is_err() else "")
        refund.refresh_from_db()
        self.assertEqual(refund.status, "failed")
        self.assertEqual(RefundService._get_invoice_refunded_amount(invoice), 0)

    def test_refund_reconciliation_sweep_retrieves_pending_and_discovers_recent(self) -> None:
        invoice = self._make_invoice()
        payment = self._make_payment(invoice, transaction_id="pi_refund_sweep")
        refund = Refund.objects.create(
            customer=self.customer,
            invoice=invoice,
            payment=payment,
            amount_cents=5_000,
            currency=self.currency,
            original_amount_cents=10_000,
            status="processing",
            gateway_refund_id="re_pending_sweep",
            reference_number="REF-PENDING-SWEEP",
        )
        local_facts = {
            "success": True,
            "refund_id": "re_pending_sweep",
            "payment_intent_id": "pi_refund_sweep",
            "amount_cents": 5_000,
            "currency": "ron",
            "status": "pending",
            "reason": "requested_by_customer",
            "error": None,
        }
        discovered_facts = {
            **local_facts,
            "refund_id": "re_dashboard_recent",
            "amount_cents": 2_000,
            "status": "succeeded",
        }
        gateway = MagicMock()
        gateway.retrieve_refund.return_value = local_facts
        gateway.list_refunds.return_value = {
            "success": True,
            "refunds": [local_facts, discovered_facts],
            "error": None,
        }
        from apps.billing import tasks as billing_tasks  # noqa: PLC0415
        from apps.common.types import Ok  # noqa: PLC0415

        with (
            patch("apps.billing.gateways.base.PaymentGatewayFactory.create_gateway", return_value=gateway),
            patch(
                "apps.billing.refund_service.RefundConvergenceService.converge_gateway_refund",
                return_value=Ok(refund),
            ) as converge,
        ):
            result = billing_tasks.reconcile_stripe_refunds()

        self.assertTrue(result["success"])
        self.assertEqual(result["refunds_checked"], 2)
        self.assertEqual(result["refunds_converged"], 2)
        gateway.retrieve_refund.assert_not_called()
        gateway.list_refunds.assert_called_once()
        self.assertEqual(converge.call_count, 2)

    def test_refund_sweep_rotates_pending_selection_across_sweeps(self) -> None:
        """With more non-terminal refunds than the budget, consecutive sweeps must
        rotate through the backlog instead of re-selecting the same head forever."""
        invoice = self._make_invoice()
        payment = self._make_payment(invoice, transaction_id="pi_rotation_sweep")
        for suffix in ("a", "b"):
            Refund.objects.create(
                customer=self.customer,
                invoice=invoice,
                payment=payment,
                amount_cents=1_000,
                currency=self.currency,
                original_amount_cents=10_000,
                status="processing",
                gateway_refund_id=f"re_rot_{suffix}",
                reference_number=f"REF-ROT-{suffix.upper()}",
            )

        def _still_pending(refund_id: str) -> dict[str, Any]:
            return {
                "success": True,
                "refund_id": refund_id,
                "payment_intent_id": "pi_rotation_sweep",
                "amount_cents": 1_000,
                "currency": "ron",
                "status": "pending",
                "reason": "requested_by_customer",
                "error": None,
            }

        gateway = MagicMock()
        gateway.retrieve_refund.side_effect = _still_pending
        gateway.list_refunds.return_value = {"success": True, "refunds": [], "error": None}
        from apps.billing import tasks as billing_tasks  # noqa: PLC0415
        from apps.common.types import Ok  # noqa: PLC0415

        with (
            patch("apps.billing.gateways.base.PaymentGatewayFactory.create_gateway", return_value=gateway),
            patch(
                "apps.billing.refund_service.RefundConvergenceService.converge_gateway_refund",
                side_effect=lambda facts: Ok(MagicMock()),
            ),
        ):
            first = billing_tasks.reconcile_stripe_refunds(max_refunds=1)
            second = billing_tasks.reconcile_stripe_refunds(max_refunds=1)

        self.assertTrue(first["work_remaining"])
        self.assertTrue(second["work_remaining"])
        retrieved_ids = {call.args[0] if call.args else call.kwargs["refund_id"] for call in gateway.retrieve_refund.call_args_list}
        self.assertEqual(
            retrieved_ids,
            {"re_rot_a", "re_rot_b"},
            "consecutive budget-limited sweeps must cover the whole pending backlog",
        )

    def test_refund_reconciliation_skips_when_distributed_lease_is_held(self) -> None:
        from apps.billing import tasks as billing_tasks  # noqa: PLC0415

        with (
            patch("apps.common.performance.async_tasks.DistributedLock.acquire", return_value=False),
            patch("apps.billing.gateways.base.PaymentGatewayFactory.create_gateway") as gateway_factory,
        ):
            result = billing_tasks.reconcile_stripe_refunds()

        self.assertTrue(result["success"])
        self.assertTrue(result["skipped_locked"])
        self.assertEqual(result["refunds_checked"], 0)
        gateway_factory.assert_not_called()

    def test_refund_reconciliation_caps_convergence_and_reports_remaining_work(self) -> None:
        from apps.billing import tasks as billing_tasks  # noqa: PLC0415
        from apps.common.types import Ok  # noqa: PLC0415

        facts = [
            {
                "success": True,
                "refund_id": f"re_budget_{index}",
                "payment_intent_id": f"pi_budget_{index}",
                "amount_cents": 100,
                "currency": "ron",
                "status": "succeeded",
                "reason": None,
                "failure_reason": None,
                "error": None,
            }
            for index in range(3)
        ]
        gateway = MagicMock()
        gateway.list_refunds.return_value = {
            "success": True,
            "refunds": facts[:2],
            "truncated": True,
            "error": None,
        }

        with (
            patch("apps.billing.gateways.base.PaymentGatewayFactory.create_gateway", return_value=gateway),
            patch(
                "apps.billing.refund_service.RefundConvergenceService.converge_gateway_refund",
                return_value=Ok(None),
            ) as converge,
        ):
            result = billing_tasks.reconcile_stripe_refunds(max_refunds=2)

        self.assertTrue(result["success"])
        self.assertEqual(result["refunds_checked"], 2)
        self.assertTrue(result["work_remaining"])
        self.assertEqual(converge.call_count, 2)
        gateway.list_refunds.assert_called_once_with(
            created_gte=mock.ANY,
            page_size=100,
            max_records=2,
        )

    def test_refund_reconciliation_reports_remaining_work_when_discovery_fails(self) -> None:
        from apps.billing import tasks as billing_tasks  # noqa: PLC0415

        gateway = MagicMock()
        gateway.list_refunds.return_value = {
            "success": False,
            "refunds": [],
            "truncated": False,
            "error": "Stripe unavailable",
        }

        with patch(
            "apps.billing.gateways.base.PaymentGatewayFactory.create_gateway",
            return_value=gateway,
        ):
            result = billing_tasks.reconcile_stripe_refunds(max_refunds=2)

        self.assertFalse(result["success"])
        self.assertTrue(result["work_remaining"])
        self.assertEqual(result["refunds_checked"], 0)

    def test_gateway_refund_id_is_unique_when_present_but_blank_is_reusable(self) -> None:
        invoice = self._make_invoice()
        common = {
            "customer": self.customer,
            "invoice": invoice,
            "amount_cents": 1_000,
            "currency": self.currency,
            "original_amount_cents": invoice.total_cents,
            "status": "failed",
        }
        Refund.objects.create(**common, gateway_refund_id="", reference_number="REF-BLANK-ONE")
        Refund.objects.create(**common, gateway_refund_id="", reference_number="REF-BLANK-TWO")
        Refund.objects.create(
            **common,
            gateway_refund_id="re_unique_gateway",
            reference_number="REF-GATEWAY-ONE",
        )

        with self.assertRaises(IntegrityError), transaction.atomic():
            Refund.objects.create(
                **common,
                gateway_refund_id="re_unique_gateway",
                reference_number="REF-GATEWAY-TWO",
            )

    def test_gateway_refund_requires_and_reuses_durable_intent_identity(self) -> None:
        invoice = self._make_invoice()
        payment = self._make_payment(invoice, transaction_id="pi_retry_keys")
        gateway = MagicMock()
        gateway.refund_payment.return_value = {
            "success": True,
            "refund_id": "re_retry_key",
            "amount_refunded_cents": 1_000,
            "status": "pending",
            "error": None,
        }
        first_intent = Refund.objects.create(
            customer=self.customer,
            invoice=invoice,
            payment=payment,
            amount_cents=1_000,
            currency=self.currency,
            original_amount_cents=payment.amount_cents,
            refund_type="partial",
            status="pending",
            gateway_refund_id="",
            reference_number="REF-FIRST-INTENT",
        )
        second_intent = Refund.objects.create(
            customer=self.customer,
            invoice=invoice,
            payment=payment,
            amount_cents=1_000,
            currency=self.currency,
            original_amount_cents=payment.amount_cents,
            refund_type="partial",
            status="pending",
            gateway_refund_id="",
            reference_number="REF-SECOND-INTENT",
        )
        unpersisted_intent_id = uuid.uuid4()

        with patch("apps.billing.refund_service.PaymentGatewayFactory.create_gateway", return_value=gateway):
            missing_intent = RefundService._execute_gateway_refund(payment, 1_000, 1_000)
            unpersisted_intent = RefundService._execute_gateway_refund(
                payment, 1_000, 1_000, refund_intent_id=unpersisted_intent_id
            )
            first = RefundService._execute_gateway_refund(
                payment, 1_000, 1_000, refund_intent_id=first_intent.id
            )
            unknown_retry = RefundService._execute_gateway_refund(
                payment, 1_000, 1_000, refund_intent_id=first_intent.id
            )
            distinct_refund = RefundService._execute_gateway_refund(
                payment, 1_000, 1_000, refund_intent_id=second_intent.id
            )

        self.assertTrue(missing_intent.is_err())
        self.assertIn("durable Refund intent", missing_intent.unwrap_err())
        self.assertTrue(unpersisted_intent.is_err())
        self.assertIn("durable Refund intent", unpersisted_intent.unwrap_err())
        self.assertTrue(first.is_ok())
        self.assertTrue(unknown_retry.is_ok())
        self.assertTrue(distinct_refund.is_ok())
        keys = [call.kwargs["idempotency_key"] for call in gateway.refund_payment.call_args_list]
        self.assertEqual(
            keys,
            [f"refund:{first_intent.id}", f"refund:{first_intent.id}", f"refund:{second_intent.id}"],
        )

    def test_retry_after_local_rollback_reuses_durable_intent_despite_intervening_refund(self) -> None:
        """A response-loss retry must keep A's identity after refund B changes the ledger."""
        invoice = self._make_invoice(total_cents=10_000)
        payment = self._make_payment(invoice, transaction_id="pi_durable_refund_intent")
        gateway = MagicMock()
        gateway.refund_payment.return_value = {
            "success": True,
            "refund_id": "re_durable_refund_a",
            "amount_refunded_cents": 5_000,
            "status": "succeeded",
            "error": None,
        }
        partial: RefundData = {
            "refund_type": "partial",
            "amount_cents": 5_000,
            "reason": "customer_request",
        }

        with patch("apps.billing.gateways.base.PaymentGatewayFactory.create_gateway", return_value=gateway):
            with patch.object(RefundService, "_advance_refund_status", return_value=Err("local settlement failed")):
                first = RefundService.refund_invoice(invoice.id, dict(partial))

            self.assertTrue(first.is_err())
            intent = Refund.objects.get(
                invoice=invoice,
                payment=payment,
                amount_cents=5_000,
                gateway_refund_id="",
                status="pending",
            )

            Refund.objects.create(
                customer=self.customer,
                invoice=invoice,
                payment=payment,
                amount_cents=2_500,
                currency=self.currency,
                original_amount_cents=payment.amount_cents,
                status="completed",
                gateway_refund_id="re_intervening_refund_b",
                reference_number="REF-INTERVENING-B",
            )

            retried = RefundService.refund_invoice(invoice.id, dict(partial))

        self.assertTrue(retried.is_ok(), retried.unwrap_err() if retried.is_err() else "")
        self.assertEqual(Refund.objects.get(gateway_refund_id="re_durable_refund_a").id, intent.id)
        keys = [call.kwargs["idempotency_key"] for call in gateway.refund_payment.call_args_list]
        self.assertEqual(keys, [f"refund:{intent.id}", f"refund:{intent.id}"])

    def test_gateway_discovery_attaches_response_loss_fact_to_durable_intent(self) -> None:
        invoice = self._make_invoice(total_cents=10_000)
        payment = self._make_payment(invoice, transaction_id="pi_discovered_intent")
        intent = Refund.objects.create(
            customer=self.customer,
            invoice=invoice,
            payment=payment,
            amount_cents=4_000,
            currency=self.currency,
            original_amount_cents=payment.amount_cents,
            refund_type="partial",
            status="pending",
            gateway_refund_id="",
            reference_number="REF-DISCOVERED-INTENT",
        )

        result = RefundConvergenceService.converge_gateway_refund(
            {
                "refund_id": "re_discovered_intent",
                "payment_intent_id": "pi_discovered_intent",
                "amount_cents": 4_000,
                "currency": "ron",
                "status": "succeeded",
            }
        )

        self.assertTrue(result.is_ok(), result.unwrap_err() if result.is_err() else "")
        recovered = result.unwrap()
        self.assertIsNotNone(recovered)
        self.assertEqual(recovered.id, intent.id)
        self.assertEqual(Refund.objects.filter(payment=payment).count(), 1)
        intent.refresh_from_db()
        payment.refresh_from_db()
        invoice.refresh_from_db()
        self.assertEqual(intent.gateway_refund_id, "re_discovered_intent")
        self.assertEqual(intent.status, "completed")
        self.assertEqual(payment.status, "partially_refunded")
        self.assertEqual(invoice.status, "partially_refunded")

    def test_stale_unknown_outcome_fails_closed_before_gateway_retry(self) -> None:
        invoice = self._make_invoice(total_cents=10_000)
        payment = self._make_payment(invoice, transaction_id="pi_stale_intent")
        intent = Refund.objects.create(
            customer=self.customer,
            invoice=invoice,
            payment=payment,
            amount_cents=4_000,
            currency=self.currency,
            original_amount_cents=payment.amount_cents,
            refund_type="partial",
            status="pending",
            gateway_refund_id="",
            reference_number="REF-STALE-INTENT",
        )
        Refund.objects.filter(pk=intent.pk).update(created_at=timezone.now() - timedelta(hours=24))

        with patch("apps.billing.gateways.base.PaymentGatewayFactory.create_gateway") as gateway_factory:
            result = RefundService.refund_invoice(
                invoice.id,
                {"refund_type": "partial", "amount_cents": 4_000, "reason": "customer_request"},
            )

        self.assertTrue(result.is_err())
        self.assertIn("manual reconciliation", result.unwrap_err().lower())
        gateway_factory.assert_not_called()

    def test_refund_eligibility_counts_only_live_or_completed_attempts(self) -> None:
        invoice = self._make_invoice()
        for index, status in enumerate(
            ("pending", "processing", "approved", "completed", "failed", "cancelled", "rejected"),
            start=1,
        ):
            Refund.objects.create(
                customer=self.customer,
                invoice=invoice,
                amount_cents=100,
                currency=self.currency,
                original_amount_cents=invoice.total_cents,
                status=status,
                reference_number=f"REF-STATUS-{index}",
            )

        self.assertEqual(RefundService._get_invoice_refunded_amount(invoice), 400)

    def test_partial_payment_refund_without_amount_fails_before_gateway(self) -> None:
        invoice = self._make_invoice()
        payment = self._make_payment(invoice, transaction_id="pi_partial_without_amount")

        with patch("apps.billing.gateways.base.PaymentGatewayFactory.create_gateway") as gateway_factory:
            result = RefundService._process_payment_refund(payment, {"refund_type": "partial"})

        self.assertTrue(result.is_err())
        self.assertIn("positive amount is required", result.unwrap_err())
        gateway_factory.assert_not_called()
        payment.refresh_from_db()
        self.assertEqual(payment.status, "succeeded")

    def test_prelocked_nonrefundable_payment_still_fails_before_gateway(self) -> None:
        invoice = self._make_invoice()
        payment = self._make_payment(invoice, transaction_id="pi_prelocked_failed")
        Payment.objects.filter(pk=payment.pk).update(status="failed")
        payment.refresh_from_db()

        with patch("apps.billing.gateways.base.PaymentGatewayFactory.create_gateway") as gateway_factory:
            result = RefundService._process_payment_refund(
                payment,
                {"refund_type": "full"},
                payment_locked=True,
            )

        self.assertTrue(result.is_err())
        self.assertIn("not refundable", result.unwrap_err())
        gateway_factory.assert_not_called()

    def test_partial_order_refund_sends_exact_amount_and_keeps_documents_partial(self) -> None:
        invoice = self._make_invoice()
        order = self._make_order(invoice)
        payment = self._make_payment(invoice, transaction_id="pi_partial_order_refund")
        gateway = MagicMock()
        gateway.refund_payment.return_value = {
            "success": True,
            "refund_id": "re_partial_order_refund",
            "amount_refunded_cents": 2_500,
            "status": "succeeded",
            "error": None,
        }
        refund_data = self._refund_data(amount_cents=2_500)
        refund_data["refund_type"] = "partial"

        with patch("apps.billing.gateways.base.PaymentGatewayFactory.create_gateway", return_value=gateway):
            result = RefundService.refund_order(order.id, refund_data)

        self.assertTrue(result.is_ok(), result.unwrap_err() if result.is_err() else "")
        gateway.refund_payment.assert_called_once_with(
            gateway_txn_id="pi_partial_order_refund",
            amount_cents=2_500,
            idempotency_key=mock.ANY,
        )

        payment.refresh_from_db()
        invoice.refresh_from_db()
        self.assertEqual(payment.status, "partially_refunded")
        self.assertEqual(invoice.status, "partially_refunded")
        self.assertEqual(invoice.get_remaining_amount(), 2_500)
        refund = Refund.objects.get(order=order)
        self.assertEqual(refund.amount_cents, 2_500)
        self.assertEqual(refund.payment_id, payment.id)

    def test_sequential_partial_refunds_complete_payment_and_invoice(self) -> None:
        invoice = self._make_invoice()
        order = self._make_order(invoice)
        payment = self._make_payment(invoice, transaction_id="pi_sequential_refunds")
        gateway = MagicMock()
        gateway.refund_payment.side_effect = [
            {
                "success": True,
                "refund_id": "re_partial_one",
                "amount_refunded_cents": 4_000,
                "status": "succeeded",
                "error": None,
            },
            {
                "success": True,
                "refund_id": "re_partial_two",
                "amount_refunded_cents": 6_000,
                "status": "succeeded",
                "error": None,
            },
        ]
        first_refund = self._refund_data(amount_cents=4_000)
        first_refund["refund_type"] = "partial"
        second_refund = self._refund_data(amount_cents=6_000)
        second_refund["refund_type"] = "partial"

        with patch("apps.billing.gateways.base.PaymentGatewayFactory.create_gateway", return_value=gateway):
            first_result = RefundService.refund_order(order.id, first_refund)
            second_result = RefundService.refund_order(order.id, second_refund)

        self.assertTrue(first_result.is_ok(), first_result.unwrap_err() if first_result.is_err() else "")
        self.assertTrue(second_result.is_ok(), second_result.unwrap_err() if second_result.is_err() else "")
        self.assertEqual(
            [call.kwargs["amount_cents"] for call in gateway.refund_payment.call_args_list],
            [4_000, 6_000],
        )

        payment.refresh_from_db()
        invoice.refresh_from_db()
        self.assertEqual(payment.status, "refunded")
        self.assertEqual(invoice.status, "refunded")
        self.assertEqual(Refund.objects.filter(order=order, payment=payment).count(), 2)

    def test_full_order_refund_after_partial_uses_remaining_payment_balance(self) -> None:
        invoice = self._make_invoice()
        order = self._make_order(invoice)
        payment = self._make_payment(invoice, transaction_id="pi_partial_then_full")
        gateway = MagicMock()
        gateway.refund_payment.side_effect = [
            {
                "success": True,
                "refund_id": "re_initial_partial",
                "amount_refunded_cents": 4_000,
                "status": "succeeded",
                "error": None,
            },
            {
                "success": True,
                "refund_id": "re_remaining_full",
                "amount_refunded_cents": 6_000,
                "status": "succeeded",
                "error": None,
            },
        ]
        partial_refund = self._refund_data(amount_cents=4_000)
        partial_refund["refund_type"] = "partial"
        full_refund = self._refund_data(amount_cents=10_000)

        with patch("apps.billing.gateways.base.PaymentGatewayFactory.create_gateway", return_value=gateway):
            partial_result = RefundService.refund_order(order.id, partial_refund)
            full_result = RefundService.refund_order(order.id, full_refund)

        self.assertTrue(partial_result.is_ok(), partial_result.unwrap_err() if partial_result.is_err() else "")
        self.assertTrue(full_result.is_ok(), full_result.unwrap_err() if full_result.is_err() else "")
        self.assertEqual(full_result.unwrap()["amount_refunded_cents"], 6_000)
        self.assertEqual(
            [call.kwargs["amount_cents"] for call in gateway.refund_payment.call_args_list],
            [4_000, 6_000],
        )

        payment.refresh_from_db()
        invoice.refresh_from_db()
        self.assertEqual(payment.status, "refunded")
        self.assertEqual(invoice.status, "refunded")
        self.assertEqual(
            list(Refund.objects.filter(order=order).order_by("created_at").values_list("amount_cents", flat=True)),
            [4_000, 6_000],
        )

    def test_invoice_without_refundable_payment_fails_without_local_mutation(self) -> None:
        invoice = self._make_invoice()

        result = RefundService.refund_invoice(invoice.id, self._refund_data())

        self.assertTrue(result.is_err())
        self.assertIn("No successful payments found to refund", result.unwrap_err())
        invoice.refresh_from_db()
        self.assertEqual(invoice.status, "paid")
        self.assertFalse(Refund.objects.filter(invoice=invoice).exists())

    def test_multiple_refundable_payments_fail_closed(self) -> None:
        invoice = self._make_invoice()
        first_payment = self._make_payment(invoice, transaction_id="pi_duplicate_one")
        second_payment = self._make_payment(invoice, transaction_id="pi_duplicate_two")

        with patch("apps.billing.gateways.base.PaymentGatewayFactory.create_gateway") as gateway_factory:
            result = RefundService.refund_invoice(invoice.id, self._refund_data())

        self.assertTrue(result.is_err())
        self.assertIn("Multiple successful payments found", result.unwrap_err())
        gateway_factory.assert_not_called()
        invoice.refresh_from_db()
        first_payment.refresh_from_db()
        second_payment.refresh_from_db()
        self.assertEqual(invoice.status, "paid")
        self.assertEqual(first_payment.status, "succeeded")
        self.assertEqual(second_payment.status, "succeeded")
        self.assertFalse(Refund.objects.filter(invoice=invoice).exists())

    def test_post_gateway_exception_rolls_back_payment_and_invoice_status(self) -> None:
        """A settlement crash preserves the command but rolls back projections."""
        invoice = self._make_invoice()
        payment = self._make_payment(invoice, transaction_id="pi_post_gateway_crash")
        gateway = MagicMock()
        gateway.refund_payment.return_value = {
            "success": True,
            "refund_id": "re_post_gateway_crash",
            "amount_refunded_cents": 10_000,
            "status": "succeeded",
            "error": None,
        }

        with (
            patch("apps.billing.gateways.base.PaymentGatewayFactory.create_gateway", return_value=gateway),
            patch.object(RefundService, "_advance_refund_status", side_effect=RuntimeError("post-gateway crash")),
        ):
            result = RefundService.refund_invoice(invoice.id, self._refund_data())

        self.assertTrue(result.is_err())
        invoice.refresh_from_db()
        payment.refresh_from_db()
        self.assertEqual(invoice.status, "paid")
        self.assertEqual(payment.status, "succeeded")
        self.assertEqual(payment.meta, {})
        intent = Refund.objects.get(invoice=invoice, payment=payment)
        self.assertEqual(intent.status, "pending")
        self.assertEqual(intent.gateway_refund_id, "")
        self.assertEqual(gateway.refund_payment.call_args.kwargs["idempotency_key"], f"refund:{intent.id}")

    def test_post_gateway_err_return_rolls_back_payment_and_invoice_status(self) -> None:
        """An Err RETURN (not an exception) after gateway success must also roll back."""
        invoice = self._make_invoice()
        payment = self._make_payment(invoice, transaction_id="pi_post_gateway_err")
        gateway = MagicMock()
        gateway.refund_payment.return_value = {
            "success": True,
            "refund_id": "re_post_gateway_err",
            "amount_refunded_cents": 10_000,
            "status": "succeeded",
            "error": None,
        }

        with (
            patch("apps.billing.gateways.base.PaymentGatewayFactory.create_gateway", return_value=gateway),
            patch.object(RefundService, "_advance_refund_status", return_value=Err("simulated status failure")),
        ):
            result = RefundService.refund_invoice(invoice.id, self._refund_data())

        self.assertTrue(result.is_err())
        invoice.refresh_from_db()
        payment.refresh_from_db()
        self.assertEqual(invoice.status, "paid")
        self.assertEqual(payment.status, "succeeded")
        intent = Refund.objects.get(invoice=invoice, payment=payment)
        self.assertEqual(intent.status, "pending")
        self.assertEqual(intent.gateway_refund_id, "")


class RefundConvergenceHardeningTests(TestCase):
    """Discriminating regressions for the #339 convergence-hardening fixes.

    Each test fails against the pre-#339 code and passes after the fix. Factory
    helpers are duplicated (not inherited) so this class does not re-run the
    RefundGatewayIntegrityTests suite under a second class name.
    """

    def setUp(self) -> None:
        self.currency, _ = Currency.objects.get_or_create(
            code="RON",
            defaults={"name": "Romanian Leu", "symbol": "lei", "decimals": 2},
        )
        self.customer = Customer.objects.create(
            name="Refund Convergence SRL",
            customer_type="company",
            company_name="Refund Convergence SRL",
            status="active",
        )

    def _make_invoice(self, *, total_cents: int = 10_000) -> Invoice:
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

    def _make_order(self, invoice: Invoice, *, total_cents: int = 10_000) -> Order:
        return Order.objects.create(
            order_number=f"ORD-{uuid.uuid4().hex[:10]}",
            customer=self.customer,
            currency=self.currency,
            invoice=invoice,
            status="completed",
            subtotal_cents=total_cents,
            tax_cents=0,
            total_cents=total_cents,
            customer_email="billing@example.test",
            customer_name=self.customer.company_name,
        )

    def _make_payment(self, invoice: Invoice, *, transaction_id: str) -> Payment:
        return Payment.objects.create(
            customer=self.customer,
            invoice=invoice,
            currency=self.currency,
            status="succeeded",
            payment_method="stripe",
            amount_cents=invoice.total_cents,
            gateway_txn_id=transaction_id,
        )

    def test_convergence_rolls_back_new_refund_when_projection_fails(self) -> None:
        """Fix 1: a post-write Err in converge must roll back, not commit a half state.

        Before the fix, converge_gateway_refund returned Err after creating the Refund
        row and advancing its FSM without set_rollback(True), committing a completed
        ledger row whose Payment/Invoice projection never ran.
        """
        invoice = self._make_invoice()
        payment = self._make_payment(invoice, transaction_id="pi_projection_rollback")
        from apps.billing.refund_service import RefundConvergenceService  # noqa: PLC0415

        with patch.object(RefundService, "_project_settled_refunds", return_value=Err("forced projection failure")):
            result = RefundConvergenceService.converge_gateway_refund(
                {
                    "refund_id": "re_projection_rollback",
                    "payment_intent_id": "pi_projection_rollback",
                    "amount_cents": 10_000,
                    "currency": "ron",
                    "status": "succeeded",
                }
            )

        self.assertTrue(result.is_err())
        self.assertFalse(Refund.objects.filter(gateway_refund_id="re_projection_rollback").exists())
        payment.refresh_from_db()
        invoice.refresh_from_db()
        self.assertEqual(payment.status, "succeeded")
        self.assertEqual(invoice.status, "paid")

    def test_convergence_rolls_back_disputed_payment_refund_with_no_projection_path(self) -> None:
        """Fix 1 (unmocked, real production trigger): dispute-then-refund has no FSM path.

        A charge disputed then refunded to resolve it reaches Payment.status='disputed'
        via the real dispute_payment() transition. _apply_payment_refund_projection has no
        ('disputed', 'refunded') edge, so convergence returns Err AFTER creating the Refund
        row. Without set_rollback this permanently commits a 'completed' ledger row against a
        'disputed' payment — the daily reconcile sweep then hits the identical dead end
        forever. Rolling back keeps the ledger and Payment consistent.
        """
        invoice = self._make_invoice()
        payment = self._make_payment(invoice, transaction_id="pi_disputed_refund")
        payment.dispute_payment()
        payment.save(update_fields=["status", "updated_at"])
        from apps.billing.refund_service import RefundConvergenceService  # noqa: PLC0415

        result = RefundConvergenceService.converge_gateway_refund(
            {
                "refund_id": "re_disputed_refund",
                "payment_intent_id": "pi_disputed_refund",
                "amount_cents": 10_000,
                "currency": "ron",
                "status": "succeeded",
            }
        )

        self.assertTrue(result.is_err())
        self.assertIn("disputed", result.unwrap_err().lower())
        self.assertFalse(Refund.objects.filter(gateway_refund_id="re_disputed_refund").exists())
        payment.refresh_from_db()
        self.assertEqual(payment.status, "disputed")

    def test_partially_refunded_invoice_accepts_second_partial_refund(self) -> None:
        """Fix 2: refund_invoice must allow a second partial while balance remains.

        Before the fix, the invoice eligibility gates excluded 'partially_refunded'
        (unlike refund_order), rejecting a legitimate second partial refund.
        """
        invoice = self._make_invoice(total_cents=10_000)
        self._make_payment(invoice, transaction_id="pi_two_partials")
        gateway = MagicMock()
        gateway.refund_payment.return_value = {
            "success": True,
            "refund_id": "",
            "amount_refunded_cents": 3_000,
            "status": "succeeded",
            "error": None,
        }
        partial: RefundData = {"refund_type": "partial", "amount_cents": 3_000, "reason": "customer_request"}

        with patch("apps.billing.gateways.base.PaymentGatewayFactory.create_gateway", return_value=gateway):
            first = RefundService.refund_invoice(invoice.id, dict(partial))
            self.assertTrue(first.is_ok(), first.unwrap_err() if first.is_err() else "")
            invoice.refresh_from_db()
            self.assertEqual(invoice.status, "partially_refunded")
            second = RefundService.refund_invoice(invoice.id, dict(partial))

        self.assertTrue(second.is_ok(), second.unwrap_err() if second.is_err() else "")
        self.assertEqual(RefundService._get_invoice_refunded_amount(invoice), 6_000)

    def test_legacy_proforma_refund_counted_when_payment_has_invoice_and_proforma(self) -> None:
        """Fix 4: legacy refund scope must OR invoice_id and order.proforma_id.

        A payment can carry both links; the if/elif dropped the proforma-linked legacy
        refund whenever invoice_id was set, under-counting the reserved balance.
        """
        invoice = self._make_invoice()
        proforma = ProformaInvoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number=f"PRO-{uuid.uuid4().hex[:10]}",
            subtotal_cents=10_000,
            tax_cents=0,
            total_cents=10_000,
            valid_until=timezone.now() + timedelta(days=7),
        )
        order = self._make_order(invoice)
        order.proforma = proforma
        order.save(update_fields=["proforma", "updated_at"])
        payment = Payment.objects.create(
            customer=self.customer,
            invoice=invoice,
            proforma=proforma,
            currency=self.currency,
            status="succeeded",
            payment_method="stripe",
            amount_cents=10_000,
            gateway_txn_id="pi_both_links",
        )
        # Legacy (pre-Refund.payment) refund, order-linked via the shared proforma.
        Refund.objects.create(
            customer=self.customer,
            order=order,
            payment=None,
            amount_cents=4_000,
            currency=self.currency,
            original_amount_cents=10_000,
            status="completed",
            gateway_refund_id="",
            reference_number="REF-LEGACY-PROFORMA",
        )

        # 10_000 - 4_000 legacy = 6_000. The if/elif bug ignored the legacy refund → 10_000.
        self.assertEqual(RefundService._get_remaining_payment_refund_amount(payment), 6_000)

    def test_terminal_refund_ignores_stale_nonterminal_gateway_event(self) -> None:
        """Fix 5: a reordered non-terminal status on a terminal refund is a no-op.

        Before the fix, a same-second 'pending' arriving after 'succeeded' hit the
        terminal-mismatch branch and returned Err, forcing endless webhook retries.
        """
        invoice = self._make_invoice()
        payment = self._make_payment(invoice, transaction_id="pi_stale_pending")
        refund = Refund.objects.create(
            customer=self.customer,
            invoice=invoice,
            payment=payment,
            amount_cents=10_000,
            currency=self.currency,
            original_amount_cents=10_000,
            status="completed",
            gateway_refund_id="re_stale_pending",
            reference_number="REF-STALE-PENDING",
            gateway_processed_at=timezone.now(),
        )

        result = RefundService._advance_refund_status(refund, "pending")

        self.assertTrue(result.is_ok(), result.unwrap_err() if result.is_err() else "")
        refund.refresh_from_db()
        self.assertEqual(refund.status, "completed")

    def test_reconcile_counts_external_skips_separately_from_converged(self) -> None:
        """Fix 7: Ok(None) external skips must not be counted as converged."""
        invoice = self._make_invoice()
        payment = self._make_payment(invoice, transaction_id="pi_sweep_counts")
        refund = Refund.objects.create(
            customer=self.customer,
            invoice=invoice,
            payment=payment,
            amount_cents=5_000,
            currency=self.currency,
            original_amount_cents=10_000,
            status="processing",
            gateway_refund_id="re_local_counts",
            reference_number="REF-LOCAL-COUNTS",
        )
        local_facts = {
            "success": True,
            "refund_id": "re_local_counts",
            "payment_intent_id": "pi_sweep_counts",
            "amount_cents": 5_000,
            "currency": "ron",
            "status": "succeeded",
            "reason": None,
            "error": None,
        }
        external_facts = {**local_facts, "refund_id": "re_external", "payment_intent_id": "pi_not_in_db"}
        gateway = MagicMock()
        gateway.retrieve_refund.return_value = local_facts
        gateway.list_refunds.return_value = {"success": True, "refunds": [local_facts, external_facts], "error": None}
        from apps.billing import tasks as billing_tasks  # noqa: PLC0415
        from apps.common.types import Ok  # noqa: PLC0415

        def fake_converge(facts: dict[str, Any]) -> Any:
            return Ok(None) if facts["refund_id"] == "re_external" else Ok(refund)

        with (
            patch("apps.billing.gateways.base.PaymentGatewayFactory.create_gateway", return_value=gateway),
            patch(
                "apps.billing.refund_service.RefundConvergenceService.converge_gateway_refund",
                side_effect=fake_converge,
            ),
        ):
            result = billing_tasks.reconcile_stripe_refunds()

        self.assertTrue(result["success"])
        self.assertEqual(result["refunds_checked"], 2)
        self.assertEqual(result["refunds_converged"], 1)
        self.assertEqual(result["refunds_external_skipped"], 1)

    def test_charge_refunded_converges_all_embedded_refunds_despite_a_bad_sibling(self) -> None:
        """Fix 8: a bad embedded refund must not starve its valid siblings."""
        from apps.integrations.webhooks.stripe import StripeWebhookProcessor  # noqa: PLC0415

        processor = StripeWebhookProcessor()
        charge = {
            "id": "ch_multi",
            "payment_intent": "pi_multi",
            "currency": "ron",
            "refunds": {
                "data": [
                    {"id": "re_ok_1", "payment_intent": "pi_multi", "amount": 100, "currency": "ron", "status": "succeeded"},
                    "not-a-dict",
                    {"id": "re_ok_2", "payment_intent": "pi_multi", "amount": 200, "currency": "ron", "status": "succeeded"},
                ]
            },
        }
        payload = {"id": "evt_multi", "created": 1_700_000_000, "data": {"object": charge}}
        seen: list[str] = []

        def fake_handle(event_type: str, normalized_payload: dict[str, Any]) -> tuple[bool, str]:
            seen.append(normalized_payload["data"]["object"]["id"])
            return True, "ok"

        with patch.object(processor, "handle_refund_event", side_effect=fake_handle):
            accepted, message = processor._handle_charge_refunded("charge.refunded", payload, charge)

        # Both valid siblings are processed even though the middle entry is malformed.
        self.assertEqual(seen, ["re_ok_1", "re_ok_2"])
        self.assertTrue(accepted)
        self.assertIn("handled", message)

    def test_convergence_marks_validation_failure_not_retriable(self) -> None:
        from apps.billing.refund_service import RefundConvergenceService  # noqa: PLC0415

        result = RefundConvergenceService.converge_gateway_refund({})

        self.assertIsInstance(result, Err)
        self.assertEqual(result.retriability, Retriability.NOT_RETRIABLE)

    def test_convergence_marks_transactional_failure_retriable(self) -> None:
        from apps.billing.refund_service import RefundConvergenceService  # noqa: PLC0415

        with patch(
            "apps.billing.refund_service.Payment.objects.select_for_update",
            side_effect=OperationalError("deadlock detected"),
        ):
            result = RefundConvergenceService.converge_gateway_refund(
                {
                    "refund_id": "re_retryable_failure",
                    "payment_intent_id": "pi_retryable_failure",
                    "amount_cents": 1_000,
                    "currency": "ron",
                    "status": "succeeded",
                }
            )

        self.assertIsInstance(result, Err)
        self.assertEqual(result.retriability, Retriability.RETRIABLE)

    def test_convergence_leaves_unexpected_failure_unclassified_for_safe_replay(self) -> None:
        from apps.billing.refund_service import RefundConvergenceService  # noqa: PLC0415

        with patch(
            "apps.billing.refund_service.Payment.objects.select_for_update",
            side_effect=RuntimeError("unexpected convergence failure"),
        ):
            result = RefundConvergenceService.converge_gateway_refund(
                {
                    "refund_id": "re_unknown_failure",
                    "payment_intent_id": "pi_unknown_failure",
                    "amount_cents": 1_000,
                    "currency": "ron",
                    "status": "succeeded",
                }
            )

        self.assertIsInstance(result, Err)
        self.assertEqual(result.retriability, Retriability.UNKNOWN)

    def test_refund_webhook_rejects_retryable_convergence_failure(self) -> None:
        from apps.integrations.webhooks.stripe import StripeWebhookProcessor  # noqa: PLC0415

        payload = {
            "id": "evt_retryable_failure",
            "created": 1_700_000_000,
            "data": {
                "object": {
                    "id": "re_retryable_failure",
                    "payment_intent": "pi_retryable_failure",
                    "amount": 1_000,
                    "currency": "ron",
                    "status": "succeeded",
                }
            },
        }
        with patch(
            "apps.billing.refund_service.RefundConvergenceService.converge_gateway_refund",
            return_value=Err("deadlock detected", retriability=Retriability.RETRIABLE),
        ):
            accepted, message = StripeWebhookProcessor().handle_refund_event("refund.updated", payload)

        self.assertFalse(accepted)
        self.assertIn("deadlock", message)

    def test_refund_webhook_acknowledges_malformed_object(self) -> None:
        from apps.integrations.webhooks.stripe import StripeWebhookProcessor  # noqa: PLC0415

        malformed_payloads: tuple[dict[str, Any], ...] = (
            {"data": {"object": "not-a-refund"}},
            {"data": "not-an-event-data-object"},
        )
        for payload in malformed_payloads:
            with self.subTest(payload=payload), self.assertLogs(
                "apps.integrations.webhooks.stripe", level="CRITICAL"
            ) as logs:
                accepted, message = StripeWebhookProcessor().handle_refund_event("refund.updated", payload)

            self.assertTrue(accepted)
            self.assertIn("permanent", message.lower())
            self.assertIn("manual reconciliation required", logs.output[0])

    def test_refund_webhook_rejects_unclassified_convergence_failure(self) -> None:
        from apps.integrations.webhooks.stripe import StripeWebhookProcessor  # noqa: PLC0415

        payload = {
            "data": {
                "object": {
                    "id": "re_unknown_failure",
                    "payment_intent": "pi_unknown_failure",
                    "amount": 1_000,
                    "currency": "ron",
                    "status": "succeeded",
                }
            }
        }
        with patch(
            "apps.billing.refund_service.RefundConvergenceService.converge_gateway_refund",
            return_value=Err("unclassified failure"),
        ):
            accepted, message = StripeWebhookProcessor().handle_refund_event("refund.updated", payload)

        self.assertFalse(accepted)
        self.assertIn("unclassified", message)

    def test_concurrent_refund_transition_is_retriable(self) -> None:
        from django_fsm import ConcurrentTransition  # noqa: PLC0415

        invoice = self._make_invoice()
        payment = self._make_payment(invoice, transaction_id="pi_concurrent_transition")
        refund = Refund.objects.create(
            customer=self.customer,
            invoice=invoice,
            payment=payment,
            amount_cents=1_000,
            currency=self.currency,
            original_amount_cents=10_000,
            status="pending",
            reference_number="REF-CONCURRENT-TRANSITION",
        )
        with patch.object(refund, "start_processing", side_effect=ConcurrentTransition("stale refund")):
            result = RefundService._advance_refund_status(refund, "pending")

        self.assertIsInstance(result, Err)
        self.assertEqual(result.retriability, Retriability.RETRIABLE)

    def test_charge_refunded_acknowledges_malformed_charge_object(self) -> None:
        from apps.integrations.webhooks.stripe import StripeWebhookProcessor  # noqa: PLC0415

        with self.assertLogs("apps.integrations.webhooks.stripe", level="CRITICAL") as logs:
            accepted, message = StripeWebhookProcessor().handle_charge_event("charge.refunded", {"data": "bad"})

        self.assertTrue(accepted)
        self.assertIn("permanent", message.lower())
        self.assertIn("manual reconciliation required", logs.output[0])


class RefundErrorMessageHygieneTests(TestCase):
    """Err messages from refund convergence flow into webhook HTTP responses
    (integrations/views.py), so raw exception text — DB internals included —
    must stay in the logs, never in the returned message (review of #374)."""

    def setUp(self) -> None:
        self.currency, _ = Currency.objects.get_or_create(
            code="RON",
            defaults={"name": "Romanian Leu", "symbol": "lei", "decimals": 2},
        )
        self.customer = Customer.objects.create(
            name="Message Hygiene SRL",
            customer_type="company",
            company_name="Message Hygiene SRL",
            status="active",
        )
        invoice = Invoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number=f"INV-{uuid.uuid4().hex[:10]}",
            status="paid",
            subtotal_cents=1_000,
            tax_cents=0,
            total_cents=1_000,
            due_at=timezone.now() + timedelta(days=14),
            bill_to_name=self.customer.company_name,
        )
        Payment.objects.create(
            customer=self.customer,
            invoice=invoice,
            currency=self.currency,
            status="succeeded",
            payment_method="stripe",
            amount_cents=1_000,
            gateway_txn_id="pi_leak_check",
        )

    def test_transient_db_failure_message_carries_no_exception_detail(self) -> None:
        from apps.billing.refund_service import RefundConvergenceService  # noqa: PLC0415

        with patch.object(
            RefundConvergenceService,
            "_lock_related_order",
            side_effect=OperationalError("connection reset by peer at 10.0.0.5:5432"),
        ):
            result = RefundConvergenceService.converge_gateway_refund(
                {
                    "refund_id": "re_leak_check",
                    "payment_intent_id": "pi_leak_check",
                    "amount_cents": 1_000,
                    "currency": "ron",
                    "status": "succeeded",
                }
            )

        self.assertTrue(result.is_err())
        message = result.unwrap_err()
        self.assertNotIn("10.0.0.5", message, "DB exception detail must not reach the webhook response")
        self.assertNotIn("connection reset", message)

    def test_unexpected_failure_message_carries_no_exception_detail(self) -> None:
        from apps.billing.refund_service import RefundConvergenceService  # noqa: PLC0415

        with patch.object(
            RefundConvergenceService,
            "_lock_related_order",
            side_effect=RuntimeError("secret internal state: /etc/praho/key"),
        ):
            result = RefundConvergenceService.converge_gateway_refund(
                {
                    "refund_id": "re_leak_check_2",
                    "payment_intent_id": "pi_leak_check",
                    "amount_cents": 1_000,
                    "currency": "ron",
                    "status": "succeeded",
                }
            )

        self.assertTrue(result.is_err())
        self.assertNotIn("/etc/praho/key", result.unwrap_err())
