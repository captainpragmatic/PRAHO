"""A refund that completes records the fiscal correction it owes, and nothing else changes.

PR A1 is passive: no document is issued here. These tests pin what is recorded, when, and
that recording can never cost a refund its settlement.
"""

from __future__ import annotations

import uuid
from datetime import timedelta
from typing import Any
from unittest.mock import MagicMock, patch

from django.core.cache import cache
from django.test import TestCase, TransactionTestCase, override_settings

from apps.billing.fiscal_correction_models import (
    REASON_NO_FISCAL_DOCUMENT,
    STATE_ALLOCATED,
    STATE_ISSUED,
    STATE_NOT_REQUIRED,
    STATE_PENDING,
    FiscalCorrection,
)
from apps.billing.fiscal_correction_service import (
    record_obligation,
    sweep_fiscal_corrections,
)
from apps.billing.fiscal_correction_worker import sweep_fiscal_correction_issuance
from apps.billing.invoice_models import DOCUMENT_KIND_CREDIT_NOTE, ISSUER_SMARTBILL, Invoice
from apps.billing.issuers.base import Ambiguous, Issued, PreparedDocument
from apps.billing.issuers.models import IssuanceState, ProviderIssuance
from apps.billing.issuers.service import _record_issued_for, issue_storno_for_correction, reconcile_confirmed_issued
from apps.billing.models import Payment, Refund
from apps.billing.refund_service import RefundService, RefundType
from apps.common.types import Ok
from apps.orders.models import Order
from apps.promotions.gift_cards import pay_document
from apps.promotions.models import GiftCard, TenderRefundCommand, TenderRefundLeg
from apps.promotions.tender_refunds import refund_document
from config.settings.test import LOCMEM_TEST_CACHE
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
        """Two guards, each pinned: the hook never asks, and the recorder refuses if asked."""
        from apps.billing import fiscal_correction_service  # noqa: PLC0415

        invoice = h.issued_invoice(self.owner)
        refund = h.pending_refund(invoice=invoice)

        with patch(
            "apps.billing.fiscal_correction_service.record_obligation",
            wraps=fiscal_correction_service.record_obligation,
        ) as recorder:
            refund.start_processing()
            refund.save(update_fields=["status", "updated_at"])
            refund.approve()
            refund.save(update_fields=["status", "updated_at"])
            refund.save()

        recorder.assert_not_called()
        self.assertIsNone(fiscal_correction_service.record_obligation(refund))
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
    """A SmartBill storno is issued for one correction, and its outcome settles exactly that one."""

    def setUp(self) -> None:
        self.owner = h.customer()
        self.invoice = h.issued_invoice(self.owner, issuer=ISSUER_SMARTBILL, number="FCT-000700")
        h.paid(self.invoice)
        self.refund = h.complete(h.pending_refund(invoice=self.invoice))
        force_status(self.invoice, "refunded")
        self.correction = h.allocated(
            FiscalCorrection.objects.get(source_refund=self.refund), base_cents=10000, tax_cents=2100
        )

    def _storno(self, outcome: object) -> Any:
        with (
            patch(
                "apps.billing.issuers.smartbill.issuer.SmartBillIssuer.prepare_storno",
                return_value=Ok(PreparedDocument(payload={"number": "000700"}, digest="d")),
            ),
            patch("apps.billing.issuers.smartbill.issuer.SmartBillIssuer.submit_storno", return_value=outcome),
        ):
            return issue_storno_for_correction(self.correction.pk)

    def test_an_issued_storno_settles_its_correction(self) -> None:
        result = self._storno(Issued(number="000701", series="STORNO"))

        self.assertTrue(result.is_ok(), getattr(result, "error", ""))
        credit_note = Invoice.objects.get(document_kind=DOCUMENT_KIND_CREDIT_NOTE)
        self.correction.refresh_from_db()
        self.assertEqual(self.correction.state, STATE_ISSUED)
        self.assertEqual(self.correction.credit_note_id, credit_note.pk)

    def test_a_storno_adopted_by_an_operator_settles_the_correction_too(self) -> None:
        self.assertTrue(self._storno(Ambiguous(reason="read timeout after POST")).is_err())
        credit_note = Invoice.objects.get(document_kind=DOCUMENT_KIND_CREDIT_NOTE)
        self.correction.refresh_from_db()
        self.assertEqual(self.correction.state, STATE_ALLOCATED, "an unknown outcome settles nothing")

        issuance = ProviderIssuance.objects.get(invoice=credit_note)
        adopted = reconcile_confirmed_issued(
            issuance.pk, series="STORNO", number="000702", operator_note="Found in the SmartBill console"
        )

        self.assertTrue(adopted.is_ok(), getattr(adopted, "error", ""))
        self.correction.refresh_from_db()
        self.assertEqual(self.correction.state, STATE_ISSUED)
        self.assertEqual(self.correction.credit_note_id, credit_note.pk)

    def test_a_failure_to_settle_never_unwinds_the_issued_storno(self) -> None:
        with (
            patch("apps.billing.issuers.service._record_issued_for", side_effect=RuntimeError("store unavailable")),
            self.assertLogs("apps.billing.issuers.service", level="ERROR") as logs,
        ):
            result = self._storno(Issued(number="000703", series="STORNO"))

        self.assertTrue(result.is_ok(), getattr(result, "error", ""))
        credit_note = Invoice.objects.get(document_kind=DOCUMENT_KIND_CREDIT_NOTE)
        self.assertEqual(credit_note.number, "STORNO-000703")
        self.assertEqual(ProviderIssuance.objects.get(invoice=credit_note).state, IssuanceState.ISSUED.value)
        self.correction.refresh_from_db()
        self.assertEqual(self.correction.state, STATE_ALLOCATED)
        self.assertTrue(any(str(credit_note.pk) in line for line in logs.output), logs.output)

    def test_the_sweep_settles_an_issued_storno_without_calling_the_provider_again(self) -> None:
        """The provider issued it and only the settling failed: the next run settles it from the
        issuance record. Calling `/invoice/reverse` again would be refused, or reverse twice."""
        with (
            patch("apps.billing.issuers.service._record_issued_for", side_effect=RuntimeError("store unavailable")),
            self.assertLogs("apps.billing.issuers.service", level="ERROR"),
        ):
            self._storno(Issued(number="000704", series="STORNO"))

        with (
            patch("apps.billing.issuers.smartbill.issuer.SmartBillIssuer.submit_storno") as submit,
            patch("apps.billing.fiscal_correction_worker.deliver_credit_note"),
        ):
            sweep_fiscal_correction_issuance()

        self.correction.refresh_from_db()
        self.assertEqual(self.correction.state, STATE_ISSUED)
        self.assertEqual(self.correction.credit_note.number, "STORNO-000704")
        submit.assert_not_called()


def _born_completed(**fields: Any) -> Refund:
    """A completed refund that never transitioned, so the completion hook never saw it."""
    return h.pending_refund(status="completed", **fields)


@override_settings(CACHES=LOCMEM_TEST_CACHE)
class RecoverySweepTests(TestCase):
    def setUp(self) -> None:
        cache.clear()
        self.owner = h.customer()

    def test_the_sweep_records_what_the_hook_missed_and_only_once(self) -> None:
        invoice = h.issued_invoice(self.owner)
        refund = _born_completed(invoice=invoice)
        self.assertFalse(FiscalCorrection.objects.exists())

        first = sweep_fiscal_corrections()
        second = sweep_fiscal_corrections()

        correction = FiscalCorrection.objects.get()
        self.assertEqual(correction.source_refund_id, refund.pk)
        self.assertEqual(correction.original_id, invoice.pk)
        self.assertEqual(correction.state, STATE_PENDING)
        self.assertEqual(first["recorded"], 1)
        self.assertEqual(second["examined"], 0, "a recorded refund is no longer a candidate")

    def test_a_refund_still_in_flight_is_not_swept(self) -> None:
        invoice = h.issued_invoice(self.owner)
        h.pending_refund(invoice=invoice)

        report = sweep_fiscal_corrections()

        # `examined`, not just the absence of a row: the recorder would refuse an unsettled
        # refund anyway, so only the count shows the sweep never selected it.
        self.assertEqual(report["examined"], 0)
        self.assertFalse(FiscalCorrection.objects.exists())

    def test_legs_of_one_command_whose_hook_failed_converge_on_one_correction(self) -> None:
        """Completion commits, recording fails: the sweep still owes the command ONE correction."""
        invoice = h.issued_invoice(self.owner)
        cash = h.paid(invoice, amount_cents=7100)
        card = Payment.objects.create(
            customer=self.owner,
            invoice=invoice,
            currency=invoice.currency,
            status="succeeded",
            payment_method="bank_transfer",
            amount_cents=5000,
        )
        command = TenderRefundCommand.objects.create(
            invoice=invoice,
            customer=self.owner,
            amount_cents=12100,
            operation_key="fiscal-sweep-command",
            reason="test",
        )
        for payment in (cash, card):
            refund = h.pending_refund(invoice=invoice, payment=payment, amount_cents=payment.amount_cents)
            TenderRefundLeg.objects.create(
                command=command, payment=payment, refund=refund, amount_cents=refund.amount_cents
            )
            with (
                patch(
                    "apps.billing.fiscal_correction_service.record_obligation",
                    side_effect=RuntimeError("obligation store unavailable"),
                ),
                self.assertLogs(HOOK_LOGGER, level="ERROR"),
            ):
                h.complete(refund)
        self.assertFalse(FiscalCorrection.objects.exists())

        report = sweep_fiscal_corrections()

        correction = FiscalCorrection.objects.get()
        self.assertEqual(correction.source_command_id, command.pk)
        self.assertEqual(correction.original_id, invoice.pk)
        self.assertEqual(report["recorded"], 2, "both legs resolve, to the same correction")
        self.assertEqual(sweep_fiscal_corrections()["examined"], 0)

    def test_a_refund_that_keeps_failing_does_not_hold_up_the_rest(self) -> None:
        """A refund whose recording fails every run stays a candidate; the rotation reaches the others."""
        from apps.billing import fiscal_correction_service  # noqa: PLC0415

        stuck = _born_completed(invoice=h.issued_invoice(self.owner))
        good = _born_completed(invoice=h.issued_invoice(self.owner))
        Refund.objects.filter(pk=stuck.pk).update(created_at=good.created_at - timedelta(minutes=5))
        real_record = fiscal_correction_service.record_obligation

        def failing_for_stuck(refund: Refund) -> Any:
            if refund.pk == stuck.pk:
                raise RuntimeError("this refund cannot be recorded")
            return real_record(refund)

        with patch("apps.billing.fiscal_correction_service.record_obligation", side_effect=failing_for_stuck):
            with self.assertLogs("apps.billing.fiscal_correction_service", level="ERROR"):
                first = sweep_fiscal_corrections(limit=1)
            sweep_fiscal_corrections(limit=1)

        self.assertEqual(first["unresolved"], 1)
        self.assertFalse(FiscalCorrection.objects.filter(source_refund=stuck).exists())
        self.assertTrue(FiscalCorrection.objects.filter(source_refund=good).exists())

    def test_corrections_that_keep_failing_do_not_starve_a_recoverable_one(self) -> None:
        """The issuance sweep rotates like the recording sweep: a few corrections whose worker keeps
        failing cannot hold every run while one that would succeed waits behind them."""
        from apps.billing import fiscal_correction_worker  # noqa: PLC0415

        corrections = [record_obligation(_born_completed(invoice=h.issued_invoice(self.owner))) for _ in range(4)]
        failing_ids = {str(correction.pk) for correction in corrections[:3]}
        reached: list[str] = []

        def process_or_fail(correction_id: str) -> dict[str, str]:
            if correction_id in failing_ids:
                raise RuntimeError("this correction cannot be advanced")
            reached.append(correction_id)
            return {}

        with (
            patch.object(fiscal_correction_worker, "process_fiscal_correction", side_effect=process_or_fail),
            self.assertLogs("apps.billing.fiscal_correction_worker", level="ERROR"),
        ):
            for _run in range(len(corrections)):
                sweep_fiscal_correction_issuance(limit=1)

        self.assertEqual(reached, [str(corrections[3].pk)])


class AReversedInvoiceIsNeverRestoredTests(TestCase):
    """An issued credit note is a legal document; no refund bookkeeping may quietly undo it."""

    def setUp(self) -> None:
        self.owner = h.customer()
        self.invoice = h.issued_invoice(self.owner, issuer=ISSUER_SMARTBILL, number="FCT-000900")
        h.paid(self.invoice)
        self.refund = h.complete(h.pending_refund(invoice=self.invoice))
        force_status(self.invoice, "refunded")
        self.credit_note = Invoice.objects.create(
            customer=self.owner,
            currency=self.invoice.currency,
            number="STORNO-000901",
            status="issued",
            document_kind=DOCUMENT_KIND_CREDIT_NOTE,
            reverses_invoice=self.invoice,
            issuer_provider=ISSUER_SMARTBILL,
            subtotal_cents=-self.invoice.subtotal_cents,
            tax_cents=-self.invoice.tax_cents,
            total_cents=-self.invoice.total_cents,
            bill_to_name=self.invoice.bill_to_name,
        )

    def test_the_projection_refuses_to_restore_a_reversed_invoice_to_paid(self) -> None:
        with self.assertLogs("apps.billing.refund_service", level="ERROR") as logs:
            result = RefundService._apply_invoice_refund_projection(self.invoice, "paid")

        self.assertTrue(result.is_err())
        self.assertIn("STORNO-000901", result.unwrap_err())
        self.invoice.refresh_from_db()
        self.assertEqual(self.invoice.status, "refunded")
        self.assertTrue(any("STORNO-000901" in line for line in logs.output), logs.output)

    def test_the_projection_refuses_a_partial_restore_of_a_reversed_invoice(self) -> None:
        with self.assertLogs("apps.billing.refund_service", level="ERROR"):
            result = RefundService._apply_invoice_refund_projection(self.invoice, "partially_refunded")

        self.assertTrue(result.is_err())
        self.invoice.refresh_from_db()
        self.assertEqual(self.invoice.status, "refunded")

    def test_an_unreversed_invoice_is_still_restored(self) -> None:
        """The guard is about the credit note, not about restoring as such."""
        Invoice.objects.filter(pk=self.credit_note.pk).update(number=None, locked_at=None)

        result = RefundService._apply_invoice_refund_projection(self.invoice, "paid")

        self.assertTrue(result.is_ok(), result)
        self.invoice.refresh_from_db()
        self.assertEqual(self.invoice.status, "paid")

    def test_a_failure_reported_after_success_is_refused_loudly(self) -> None:
        """The gateway saying `failed` about a completed refund is refused, and a human is told."""
        with self.assertLogs("apps.billing.refund_service", level="ERROR") as logs:
            result = RefundService._advance_refund_status(self.refund, "failed")

        self.assertTrue(result.is_err())
        self.refund.refresh_from_db()
        self.assertEqual(self.refund.status, "completed")
        self.assertTrue(
            any(str(self.refund.pk) in line and "STORNO-000901" in line for line in logs.output), logs.output
        )


TWO_RATES = ((10000, "0.21"), (5000, "0.11"))


class PartialRefundOfAMultiRateInvoiceIsRefusedTests(TestCase):
    """A partial correction of a multi-rate invoice has no single rate to allocate VAT by."""

    def setUp(self) -> None:
        self.owner = h.customer()

    def _refund_invoice(self, invoice: Invoice, data: dict[str, Any]) -> tuple[Any, MagicMock]:
        gateway = _gateway(int(data.get("amount_cents") or invoice.total_cents))
        with patch("apps.billing.gateways.base.PaymentGatewayFactory.create_gateway", return_value=gateway):
            result = RefundService.refund_invoice(invoice.pk, data)
        return result, gateway

    def test_a_partial_invoice_refund_is_refused_before_any_money_moves(self) -> None:
        invoice = h.issued_invoice(self.owner, lines=TWO_RATES)
        h.paid(invoice)

        for refund_type in ("partial", RefundType.PARTIAL):
            with self.subTest(refund_type=refund_type):
                result, gateway = self._refund_invoice(
                    invoice, {"refund_type": refund_type, "amount_cents": 3000, "reason": "customer_request"}
                )

                self.assertTrue(result.is_err())
                self.assertIn("more than one VAT rate", result.unwrap_err())
                gateway.refund_payment.assert_not_called()
        self.assertFalse(Refund.objects.exists())

    def test_an_amount_without_a_type_is_judged_as_the_partial_refund_it_is(self) -> None:
        """No `refund_type` reads as full at the door, but the service refunds exactly the amount."""
        invoice = h.issued_invoice(self.owner, lines=TWO_RATES)
        h.paid(invoice)

        result, gateway = self._refund_invoice(invoice, {"amount_cents": 3000, "reason": "customer_request"})

        self.assertTrue(result.is_err())
        self.assertIn("more than one VAT rate", result.unwrap_err())
        gateway.refund_payment.assert_not_called()
        self.assertFalse(Refund.objects.exists())

    def test_an_order_amount_without_a_type_is_refused_the_same_way(self) -> None:
        invoice = h.issued_invoice(self.owner, lines=TWO_RATES)
        h.paid(invoice)
        order = h.order_for(invoice)
        gateway = _gateway(3000)

        with patch("apps.billing.gateways.base.PaymentGatewayFactory.create_gateway", return_value=gateway):
            result = RefundService.refund_order(order.pk, {"amount_cents": 3000, "reason": "customer_request"})

        self.assertTrue(result.is_err())
        self.assertIn("more than one VAT rate", result.unwrap_err())
        gateway.refund_payment.assert_not_called()
        self.assertFalse(Refund.objects.exists())

    def test_a_full_refund_of_a_multi_rate_invoice_still_proceeds(self) -> None:
        invoice = h.issued_invoice(self.owner, lines=TWO_RATES)
        h.paid(invoice)

        result, gateway = self._refund_invoice(invoice, _full(invoice.total_cents))

        self.assertTrue(result.is_ok(), result)
        gateway.refund_payment.assert_called_once()

    def test_a_partial_refund_of_a_single_rate_invoice_still_proceeds(self) -> None:
        invoice = h.issued_invoice(self.owner)
        h.paid(invoice)

        result, gateway = self._refund_invoice(
            invoice, {"refund_type": "partial", "amount_cents": 3000, "reason": "customer_request"}
        )

        self.assertTrue(result.is_ok(), result)
        gateway.refund_payment.assert_called_once()

    def test_a_partial_order_refund_is_refused_the_same_way(self) -> None:
        invoice = h.issued_invoice(self.owner, lines=TWO_RATES)
        h.paid(invoice)
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
        gateway = _gateway(3000)

        with patch("apps.billing.gateways.base.PaymentGatewayFactory.create_gateway", return_value=gateway):
            result = RefundService.refund_order(
                order.pk, {"refund_type": "partial", "amount_cents": 3000, "reason": "customer_request"}
            )

        self.assertTrue(result.is_err())
        self.assertIn("more than one VAT rate", result.unwrap_err())
        gateway.refund_payment.assert_not_called()
        self.assertFalse(Refund.objects.exists())

    def test_the_tender_path_is_refused_for_a_partial_but_not_for_a_full_refund(self) -> None:
        """Its legs are always `partial` internally, so the check must read the CALLER's request."""
        invoice = h.issued_invoice(self.owner, lines=TWO_RATES)
        card = GiftCard.objects.create(
            code="FISCAL-MULTI",
            currency=invoice.currency,
            initial_value_cents=5000,
            current_balance_cents=5000,
            status="active",
            ledger_version=2,
        )
        pay_document(card.code, invoice, self.owner, "fiscal-multi-gift", 5000)
        Payment.objects.create(
            customer=self.owner,
            invoice=invoice,
            currency=invoice.currency,
            amount_cents=invoice.total_cents - 5000,
            payment_method="stripe",
            gateway_txn_id="pi_fiscal_multi",
            status="succeeded",
        )
        invoice.mark_as_paid()
        invoice.save()

        with patch("apps.promotions.tender_refunds.PaymentGatewayFactory.create_gateway") as factory:
            factory.return_value.refund_payment.return_value = {
                "success": True,
                "refund_id": "re_fiscal_multi",
                "status": "succeeded",
                "amount_refunded_cents": invoice.total_cents - 5000,
            }
            partial = RefundService.refund_invoice(
                invoice.pk,
                {"refund_type": "partial", "amount_cents": 3000, "reason": "customer_request", "idempotency_key": "p1"},
            )
            self.assertTrue(partial.is_err())
            self.assertIn("more than one VAT rate", partial.unwrap_err())
            self.assertFalse(Refund.objects.exists())

            # An amount with no type is a partial refund on the tender path too.
            untyped = RefundService.refund_invoice(
                invoice.pk, {"amount_cents": 3000, "reason": "customer_request", "idempotency_key": "u1"}
            )
            self.assertTrue(untyped.is_err())
            self.assertIn("more than one VAT rate", untyped.unwrap_err())
            self.assertFalse(Refund.objects.exists())

            full = RefundService.refund_invoice(
                invoice.pk, {"refund_type": "full", "reason": "customer_request", "idempotency_key": "f1"}
            )

        self.assertTrue(full.is_ok(), full)
        invoice.refresh_from_db()
        self.assertEqual(invoice.status, "refunded")


class AProviderNoteIsNeverLinkedByGuessworkTests(TestCase):
    """A provider credit note settles the correction it was issued for, named by its issuance.

    Nothing infers it from amounts any more: a note that answers to no correction is left alone
    for an operator, and an unrelated correction on the same invoice is never touched.
    """

    def setUp(self) -> None:
        self.owner = h.customer()
        self.invoice = h.issued_invoice(self.owner, issuer=ISSUER_SMARTBILL, number="FCT-003000")
        self.credit_note = Invoice.objects.create(
            customer=self.owner,
            currency=self.invoice.currency,
            number="STORNO-003001",
            status="issued",
            document_kind=DOCUMENT_KIND_CREDIT_NOTE,
            reverses_invoice=self.invoice,
            issuer_provider=ISSUER_SMARTBILL,
            subtotal_cents=-self.invoice.subtotal_cents,
            tax_cents=-self.invoice.tax_cents,
            total_cents=-self.invoice.total_cents,
            bill_to_name=self.invoice.bill_to_name,
        )
        self.matching = record_obligation(_born_completed(invoice=self.invoice))

    def test_a_note_that_answers_to_no_correction_settles_none(self) -> None:
        ProviderIssuance.objects.create(invoice=self.credit_note, provider=ISSUER_SMARTBILL)

        with self.assertLogs("apps.billing.issuers.service", level="ERROR"):
            settled = _record_issued_for(self.credit_note)

        self.assertIsNone(settled)
        self.matching.refresh_from_db()
        self.assertEqual(self.matching.state, STATE_PENDING, "the amounts match, and that is not a link")
