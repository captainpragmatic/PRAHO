"""Behavior tests for refund gateway and local-ledger integrity (issue #212)."""

from __future__ import annotations

import uuid
from datetime import timedelta
from unittest import mock
from unittest.mock import MagicMock, patch

from django.test import TestCase
from django.utils import timezone

from apps.billing.models import Currency, Invoice, Payment, Refund
from apps.billing.refund_service import RefundData, RefundService
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

    def test_invoice_gateway_failure_rolls_back_every_local_refund_change(self) -> None:
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
        self.assertFalse(Refund.objects.filter(invoice=invoice).exists())

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
        self._make_payment(invoice, transaction_id="pi_direct_order_lock")
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
                refund_id=uuid.uuid4(),
                refund_data=self._refund_data(),
            )

        self.assertTrue(result.is_ok(), result.unwrap_err() if result.is_err() else "")
        lock_invoice.assert_called_once_with(of=("self",))
        gateway.refund_payment.assert_called_once()

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
