"""A refund that completes records the fiscal correction it owes, and nothing else changes.

PR A1 is passive: no document is issued here. These tests pin what is recorded, when, and
that recording can never cost a refund its settlement.
"""

from __future__ import annotations

import uuid
from typing import Any
from unittest.mock import MagicMock, patch

from django.test import TestCase

from apps.billing.fiscal_correction_models import (
    REASON_NO_FISCAL_DOCUMENT,
    STATE_NOT_REQUIRED,
    STATE_PENDING,
    FiscalCorrection,
)
from apps.billing.models import Payment, Refund
from apps.billing.refund_service import RefundService
from apps.orders.models import Order
from apps.promotions.gift_cards import pay_document
from apps.promotions.models import GiftCard
from apps.promotions.tender_refunds import refund_document
from tests.billing import _fiscal_correction_helpers as h

HOOK_LOGGER = "apps.billing.signals"


def _gateway(amount_cents: int, refund_id: str | None = None) -> MagicMock:
    gateway = MagicMock()
    gateway.refund_payment.return_value = {
        "success": True,
        "refund_id": refund_id or f"re_{uuid.uuid4().hex[:10]}",
        "amount_refunded_cents": amount_cents,
        "status": "succeeded",
        "error": None,
    }
    return gateway


def _full(amount_cents: int) -> dict[str, Any]:
    return {"refund_type": "full", "amount_cents": amount_cents, "reason": "customer_request", "notes": "test"}


class CompletionRecordsTheObligationTests(TestCase):
    def setUp(self) -> None:
        self.owner = h.customer()

    def test_a_completed_invoice_refund_records_one_pending_obligation(self) -> None:
        invoice = h.issued_invoice(self.owner)
        h.paid(invoice)

        with patch("apps.billing.gateways.base.PaymentGatewayFactory.create_gateway", return_value=_gateway(12100)):
            result = RefundService.refund_invoice(invoice.pk, _full(12100))

        self.assertTrue(result.is_ok(), result)
        refund = Refund.objects.get(invoice=invoice)
        correction = FiscalCorrection.objects.get()
        self.assertEqual(correction.source_refund_id, refund.pk)
        self.assertIsNone(correction.source_command_id)
        self.assertEqual(correction.original_id, invoice.pk)
        self.assertEqual(correction.state, STATE_PENDING)

    def test_an_order_refund_is_recorded_against_the_orders_invoice(self) -> None:
        """The order path leaves the refund's own invoice NULL by schema."""
        invoice = h.issued_invoice(self.owner)
        order = Order.objects.create(
            order_number=f"ORD-{uuid.uuid4().hex[:8]}",
            customer=self.owner,
            currency=invoice.currency,
            invoice=invoice,
            status="completed",
            subtotal_cents=invoice.subtotal_cents,
            tax_cents=invoice.tax_cents,
            total_cents=invoice.total_cents,
            customer_email="billing@example.test",
            customer_name="Fiscal Correction SRL",
        )
        refund = h.pending_refund(order=order)

        h.complete(refund)

        correction = FiscalCorrection.objects.get(source_refund=refund)
        self.assertEqual(correction.original_id, invoice.pk)
        self.assertEqual(correction.state, STATE_PENDING)

    def test_a_refund_with_no_issued_invoice_owes_no_correction(self) -> None:
        draft = h.issued_invoice(self.owner, issue=False)
        refund = h.pending_refund(invoice=draft)

        h.complete(refund)

        correction = FiscalCorrection.objects.get(source_refund=refund)
        self.assertEqual(correction.state, STATE_NOT_REQUIRED)
        self.assertEqual(correction.not_required_reason, REASON_NO_FISCAL_DOCUMENT)
        self.assertIsNone(correction.original_id)

    def test_an_order_refund_with_no_invoice_at_all_owes_no_correction(self) -> None:
        order = Order.objects.create(
            order_number=f"ORD-{uuid.uuid4().hex[:8]}",
            customer=self.owner,
            currency=h.ron(),
            status="completed",
            subtotal_cents=10000,
            tax_cents=2100,
            total_cents=12100,
            customer_email="billing@example.test",
            customer_name="Fiscal Correction SRL",
        )
        refund = h.pending_refund(order=order)

        h.complete(refund)

        correction = FiscalCorrection.objects.get(source_refund=refund)
        self.assertEqual(correction.state, STATE_NOT_REQUIRED)
        self.assertEqual(correction.not_required_reason, REASON_NO_FISCAL_DOCUMENT)

    def test_a_refund_that_has_not_completed_owes_nothing_yet(self) -> None:
        invoice = h.issued_invoice(self.owner)
        refund = h.pending_refund(invoice=invoice)

        refund.start_processing()
        refund.save(update_fields=["status", "updated_at"])

        self.assertFalse(FiscalCorrection.objects.exists())

    def test_saving_a_completed_refund_again_records_nothing_new(self) -> None:
        invoice = h.issued_invoice(self.owner)
        refund = h.complete(h.pending_refund(invoice=invoice))
        first = FiscalCorrection.objects.get()

        refund.metadata = {"touched": True}
        refund.save(update_fields=["metadata", "updated_at"])
        refund.save()

        self.assertEqual(list(FiscalCorrection.objects.values_list("pk", flat=True)), [first.pk])

    def test_a_tender_command_owes_one_correction_for_all_its_legs(self) -> None:
        invoice = h.issued_invoice(self.owner)
        card = GiftCard.objects.create(
            code="FISCAL-SPLIT",
            currency=invoice.currency,
            initial_value_cents=5000,
            current_balance_cents=5000,
            status="active",
            ledger_version=2,
        )
        pay_document(card.code, invoice, self.owner, "fiscal-gift", 5000)
        Payment.objects.create(
            customer=self.owner,
            invoice=invoice,
            currency=invoice.currency,
            amount_cents=7100,
            payment_method="stripe",
            gateway_txn_id="pi_fiscal_cash",
            status="succeeded",
        )
        invoice.mark_as_paid()
        invoice.save()

        with patch("apps.promotions.tender_refunds.PaymentGatewayFactory.create_gateway") as factory:
            factory.return_value.refund_payment.return_value = {
                "success": True,
                "refund_id": "re_fiscal_split",
                "status": "succeeded",
                "amount_refunded_cents": 7100,
            }
            command = refund_document(invoice.pk, 12100, "fiscal-split", reason="customer_request")

        self.assertEqual(command.status, "completed")
        legs = list(command.legs.values_list("refund_id", flat=True))
        self.assertEqual(len(legs), 2)
        self.assertEqual(Refund.objects.filter(pk__in=legs, status="completed").count(), 2)
        correction = FiscalCorrection.objects.get()
        self.assertEqual(correction.source_command_id, command.pk)
        self.assertIsNone(correction.source_refund_id)
        self.assertEqual(correction.original_id, invoice.pk)
        self.assertEqual(correction.state, STATE_PENDING)


class RecordingNeverCostsSettlementTests(TestCase):
    def test_a_failing_obligation_hook_leaves_the_refund_settled_and_says_so(self) -> None:
        owner = h.customer()
        invoice = h.issued_invoice(owner)
        payment = h.paid(invoice)

        with (
            patch("apps.billing.gateways.base.PaymentGatewayFactory.create_gateway", return_value=_gateway(12100)),
            patch(
                "apps.billing.fiscal_correction_service.record_obligation",
                side_effect=RuntimeError("obligation store unavailable"),
            ),
            self.assertLogs(HOOK_LOGGER, level="ERROR") as logs,
        ):
            result = RefundService.refund_invoice(invoice.pk, _full(12100))

        self.assertTrue(result.is_ok(), result)
        refund = Refund.objects.get(invoice=invoice)
        self.assertEqual(refund.status, "completed")
        invoice.refresh_from_db()
        payment.refresh_from_db()
        self.assertEqual(invoice.status, "refunded")
        self.assertEqual(payment.status, "refunded")
        self.assertFalse(FiscalCorrection.objects.exists())
        self.assertTrue(any(str(refund.pk) in line for line in logs.output), logs.output)
