"""A refund that completes records the fiscal correction it owes, and nothing else changes.

PR A1 is passive: no document is issued here. These tests pin what is recorded, when, and
that recording can never cost a refund its settlement.
"""

from __future__ import annotations

import uuid
from typing import Any
from unittest.mock import MagicMock, patch

from django.test import TestCase, TransactionTestCase

from apps.billing.fiscal_correction_models import (
    REASON_NO_FISCAL_DOCUMENT,
    STATE_ATTACHED,
    STATE_NOT_REQUIRED,
    STATE_PENDING,
    FiscalCorrection,
)
from apps.billing.invoice_models import DOCUMENT_KIND_CREDIT_NOTE, ISSUER_SMARTBILL, Invoice
from apps.billing.issuers.base import Ambiguous, Issued, PreparedDocument
from apps.billing.issuers.models import IssuanceState, ProviderIssuance
from apps.billing.issuers.service import issue_storno_for_invoice, reconcile_confirmed_issued
from apps.billing.models import Payment, Refund
from apps.billing.refund_service import RefundService
from apps.common.types import Ok
from apps.orders.models import Order
from apps.promotions.gift_cards import pay_document
from apps.promotions.models import GiftCard
from apps.promotions.tender_refunds import refund_document
from tests.billing import _fiscal_correction_helpers as h
from tests.helpers.fsm_helpers import force_status

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


class ProviderStornoSettlesTheObligationTests(TransactionTestCase):
    """The existing SmartBill storno flow keeps running, and now says which obligation it settled."""

    def setUp(self) -> None:
        self.owner = h.customer()
        self.invoice = h.issued_invoice(self.owner, issuer=ISSUER_SMARTBILL, number="FCT-000700")
        h.paid(self.invoice)
        self.refund = h.complete(h.pending_refund(invoice=self.invoice))
        force_status(self.invoice, "refunded")
        self.correction = FiscalCorrection.objects.get(source_refund=self.refund)

    def _storno(self, outcome: object) -> Any:
        with (
            patch(
                "apps.billing.issuers.smartbill.issuer.SmartBillIssuer.prepare_storno",
                return_value=Ok(PreparedDocument(payload={"number": "000700"}, digest="d")),
            ),
            patch("apps.billing.issuers.smartbill.issuer.SmartBillIssuer.submit_storno", return_value=outcome),
        ):
            return issue_storno_for_invoice(self.invoice.pk)

    def test_an_issued_storno_settles_the_refunds_obligation(self) -> None:
        result = self._storno(Issued(number="000701", series="STORNO"))

        self.assertTrue(result.is_ok(), getattr(result, "error", ""))
        credit_note = Invoice.objects.get(document_kind=DOCUMENT_KIND_CREDIT_NOTE)
        self.correction.refresh_from_db()
        self.assertEqual(self.correction.state, STATE_ATTACHED)
        self.assertEqual(self.correction.credit_note_id, credit_note.pk)

    def test_a_storno_adopted_by_an_operator_settles_the_obligation_too(self) -> None:
        self.assertTrue(self._storno(Ambiguous(reason="read timeout after POST")).is_err())
        credit_note = Invoice.objects.get(document_kind=DOCUMENT_KIND_CREDIT_NOTE)
        self.correction.refresh_from_db()
        self.assertEqual(self.correction.state, STATE_PENDING, "an unknown outcome settles nothing")

        issuance = ProviderIssuance.objects.get(invoice=credit_note)
        adopted = reconcile_confirmed_issued(
            issuance.pk, series="STORNO", number="000702", operator_note="Found in the SmartBill console"
        )

        self.assertTrue(adopted.is_ok(), getattr(adopted, "error", ""))
        self.correction.refresh_from_db()
        self.assertEqual(self.correction.state, STATE_ATTACHED)
        self.assertEqual(self.correction.credit_note_id, credit_note.pk)

    def test_a_failure_to_attach_never_unwinds_the_issued_storno(self) -> None:
        with (
            patch(
                "apps.billing.fiscal_correction_service.attach_provider_credit_note",
                side_effect=RuntimeError("obligation store unavailable"),
            ),
            self.assertLogs("apps.billing.issuers.service", level="ERROR") as logs,
        ):
            result = self._storno(Issued(number="000703", series="STORNO"))

        self.assertTrue(result.is_ok(), getattr(result, "error", ""))
        credit_note = Invoice.objects.get(document_kind=DOCUMENT_KIND_CREDIT_NOTE)
        self.assertEqual(credit_note.number, "STORNO-000703")
        self.assertEqual(ProviderIssuance.objects.get(invoice=credit_note).state, IssuanceState.ISSUED.value)
        self.correction.refresh_from_db()
        self.assertEqual(self.correction.state, STATE_PENDING)
        self.assertTrue(any(str(credit_note.pk) in line for line in logs.output), logs.output)
