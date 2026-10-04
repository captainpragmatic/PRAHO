"""The worker issues the built-in storno a recorded fiscal correction owes (ADR-0053).

Each test drives a real refund through completion, so the correction under test is the one the
completion hook recorded, then runs the worker with its after-commit delivery executed.
"""

from __future__ import annotations

from datetime import datetime
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.utils import timezone
from lxml import etree

from apps.billing.efactura.validator import CIUSROValidator
from apps.billing.efactura.xml_builder import NAMESPACES, builder_for
from apps.billing.fiscal_correction_models import (
    FAILURE_ISSUANCE_ERROR,
    FAILURE_SECOND_CREDIT_NOTE,
    REASON_COVERED_BY_COLLECTIONS,
    STATE_COMMUNICATED,
    STATE_FAILED,
    STATE_NOT_REQUIRED,
    STATE_PENDING,
    FiscalCorrection,
)
from apps.billing.fiscal_correction_worker import TASK_PATH, process_fiscal_correction
from apps.billing.invoice_models import (
    DOCUMENT_KIND_CREDIT_NOTE,
    ISSUER_SMARTBILL,
    Invoice,
    InvoiceSequence,
)
from apps.billing.issuers.models import ProviderIssuance
from apps.billing.issuers.tasks import sweep_owed_reversals, sweep_pending_issuances
from apps.billing.operator_controls import BillingControlActor, rotate_invoice_series
from apps.promotions.models import TenderRefundCommand, TenderRefundLeg
from tests.billing import _fiscal_correction_helpers as h
from tests.billing._storno_helpers import SELLER, StornoTestCase


def _sequence_value() -> int:
    return InvoiceSequence.objects.get(scope="default").last_value


@SELLER
class BuiltinStornoIssuanceTests(StornoTestCase):
    def test_a_full_refund_of_an_untouched_invoice_mirrors_it(self) -> None:
        original = self.original(lines=((6000, "0.21"), (4000, "0.21")))
        payment = self.collected(original, original.total_cents)
        before = _sequence_value()

        correction = self.process(self.refund(original, payment, original.total_cents))

        note = correction.credit_note
        self.assertEqual(correction.state, STATE_COMMUNICATED)
        self.assertEqual(note.document_kind, DOCUMENT_KIND_CREDIT_NOTE)
        self.assertEqual(note.reverses_invoice_id, original.pk)
        self.assertEqual((note.subtotal_cents, note.tax_cents, note.total_cents), (-10000, -2100, -12100))
        self.assertEqual(
            list(note.lines.order_by("sort_order").values_list("unit_price_cents", "tax_cents")),
            [(-6000, -1260), (-4000, -840)],
        )
        self.assertEqual(note.number, f"INV-{before + 1:06d}")
        self.assertEqual(note.sequence_scope, "default")
        self.assertEqual(note.status, "issued")
        self.assertIsNotNone(note.locked_at)

    def test_a_gross_no_base_can_represent_is_credited_exactly_everywhere(self) -> None:
        """10.00 at 21%: base 8.26, VAT 1.74. A line saved through `InvoiceLine.save()` recomputes
        the VAT from the base (1.73) and would credit 9.99, so the line, the header, the PDF and the
        XML are all checked against the one gross."""
        original = self.original()
        payment = self.collected(original, original.total_cents)

        correction = self.process(self.refund(original, payment, 1000))

        note = correction.credit_note
        line = note.lines.get()
        self.assertEqual((line.unit_price_cents, line.tax_cents, line.line_total_cents), (-826, -174, -1000))
        self.assertEqual((note.subtotal_cents, note.tax_cents, note.total_cents), (-826, -174, -1000))
        self.assertEqual((correction.base_cents, correction.tax_cents, correction.total_cents), (-826, -174, -1000))

        from tests.billing.test_builtin_storno_delivery import pdf_rows  # noqa: PLC0415

        self.assertIn("Total creditat / Total credited: -10.00 RON", pdf_rows(note))
        xml = builder_for(note).build()
        doc = etree.fromstring(xml.encode())
        self.assertEqual(doc.findtext("cac:LegalMonetaryTotal/cbc:PayableAmount", namespaces=NAMESPACES), "10.00")
        self.assertEqual(doc.findtext("cac:TaxTotal/cbc:TaxAmount", namespaces=NAMESPACES), "1.74")
        self.assertEqual(doc.findtext("cac:TaxTotal/cac:TaxSubtotal/cbc:TaxableAmount", namespaces=NAMESPACES), "8.26")
        result = CIUSROValidator().validate(xml)
        self.assertTrue(result.is_valid, [(error.code, error.message) for error in result.errors])

    def test_a_discounted_original_partially_credited_validates(self) -> None:
        original = self.original(lines=((10000, "0.21"),), discount_cents=1000, tax_cents=1890)
        payment = self.collected(original, original.total_cents)

        correction = self.process(self.refund(original, payment, 5000))

        note = correction.credit_note
        self.assertEqual((note.subtotal_cents, note.tax_cents, note.discount_cents), (-4132, -868, 0))
        result = CIUSROValidator().validate(builder_for(note).build())
        self.assertTrue(result.is_valid, [(error.code, error.message) for error in result.errors])

    def test_a_refund_of_money_actually_held_is_credited_in_full(self) -> None:
        """Invoice 100, 40 collected, 10 refunded: a credit of 10."""
        original = self.original(lines=((10000, "0.00"),))
        payment = self.collected(original, 4000, mark_paid=False)

        correction = self.process(self.refund(original, payment, 1000))

        self.assertEqual(correction.total_cents, -1000)

    def test_returning_an_overpayment_needs_no_credit_note(self) -> None:
        """Invoice 100, 120 collected, 20 refunded: nothing fiscal changed, so no note and no VAT moves."""
        original = self.original(lines=((10000, "0.00"),))
        payment = self.collected(original, 12000)

        correction = self.process(self.refund(original, payment, 2000))

        self.assertEqual(correction.state, STATE_NOT_REQUIRED)
        self.assertEqual(correction.not_required_reason, REASON_COVERED_BY_COLLECTIONS)
        self.assertIsNone(correction.credit_note_id)
        self.assertFalse(Invoice.objects.filter(reverses_invoice=original).exists())

    def test_only_what_goes_beyond_the_overpayment_is_credited(self) -> None:
        """Invoice 100, 120 collected, 30 refunded: a credit of 10."""
        original = self.original(lines=((10000, "0.00"),))
        payment = self.collected(original, 12000)

        correction = self.process(self.refund(original, payment, 3000))

        self.assertEqual(correction.credit_note.total_cents, -1000)

    def test_a_later_refund_credits_only_what_is_left_and_waits_for_a3(self) -> None:
        """30 then 91 against 121. The second correction is allocated exactly -91, never another
        -121, and is parked rather than writing a second note the A2 schema cannot hold."""
        original = self.original()
        payment = self.collected(original, original.total_cents)
        first = self.process(self.refund(original, payment, 3000))

        with self.assertLogs("apps.billing.fiscal_correction_worker", level="WARNING") as logs:
            second = self.process(self.refund(original, payment, 9100))

        self.assertEqual(first.credit_note.total_cents, -3000)
        self.assertEqual(second.state, STATE_FAILED)
        self.assertEqual(second.failure_code, FAILURE_SECOND_CREDIT_NOTE)
        self.assertEqual((second.base_cents, second.tax_cents, second.total_cents), (-7521, -1579, -9100))
        self.assertIsNone(second.credit_note_id)
        self.assertEqual(Invoice.objects.filter(reverses_invoice=original).count(), 1)
        self.assertIn("one-reversal-per-original", "\n".join(logs.output))

        # Retried by the sweep, still parked, the allocation untouched.
        self.sweep()
        second.refresh_from_db()
        self.assertEqual((second.state, second.total_cents), (STATE_FAILED, -9100))

    def test_a_worker_failure_after_numbering_leaves_no_draft_and_no_gap(self) -> None:
        original = self.original()
        payment = self.collected(original, original.total_cents)
        correction = self.refund(original, payment, 1000)
        before = _sequence_value()

        with patch.object(Invoice, "issue", side_effect=RuntimeError("issue failed after numbering")):
            failed = self.process(correction)

        self.assertEqual(failed.state, STATE_FAILED)
        self.assertEqual(failed.failure_code, FAILURE_ISSUANCE_ERROR)
        self.assertEqual(failed.total_cents, -1000)
        self.assertFalse(Invoice.objects.filter(reverses_invoice=original).exists())
        self.assertEqual(_sequence_value(), before)

        allocated_at = failed.allocated_at
        issued = self.process(failed)

        self.assertEqual(issued.credit_note.number, f"INV-{before + 1:06d}")
        self.assertEqual((issued.allocated_at, issued.total_cents), (allocated_at, -1000))

    def test_replaying_the_worker_issues_one_note_and_never_renumbers(self) -> None:
        from django.core import mail  # noqa: PLC0415

        original = self.original()
        payment = self.collected(original, original.total_cents)
        correction = self.refund(original, payment, original.total_cents)

        first = self.process(correction)
        number, sent_at = first.credit_note.number, first.communicated_at
        replayed = self.process(correction)
        self.sweep()

        self.assertEqual(Invoice.objects.filter(reverses_invoice=original).count(), 1)
        self.assertEqual(replayed.credit_note.number, number)
        self.assertEqual(replayed.communicated_at, sent_at)
        self.assertEqual(_sequence_value(), int(number.split("-")[1]))
        self.assertEqual(len(mail.outbox), 1)

    def test_a_builtin_note_has_no_provider_issuance_and_no_provider_sweep_touches_it(self) -> None:
        original = self.original()
        payment = self.collected(original, original.total_cents)
        note = self.process(self.refund(original, payment, original.total_cents)).credit_note

        sweep_pending_issuances()
        sweep_owed_reversals()

        self.assertFalse(ProviderIssuance.objects.exists())
        note.refresh_from_db()
        self.assertEqual((note.status, note.issuer_provider), ("issued", "builtin"))
        self.assertEqual(Invoice.objects.filter(reverses_invoice=original).count(), 1)

    def test_a_note_is_numbered_from_its_originals_family_when_that_series_was_rotated(self) -> None:
        original = self.original()
        payment = self.collected(original, original.total_cents)
        current = InvoiceSequence.objects.get(scope="default")
        user = get_user_model().objects.create_user(email="ops@example.test", password="x")
        rotate_invoice_series(
            prefix="FAC",
            baseline=f"{current.prefix}:{current.last_value}",
            actor=BillingControlActor(user=user, reason="New fiscal year", ip_address=None),
        )

        note = self.process(self.refund(original, payment, original.total_cents)).credit_note

        self.assertTrue(original.number.startswith("INV-"))
        self.assertEqual(note.number, "FAC-000001")
        self.assertEqual(note.sequence_scope, "default")

    def test_a_foreign_currency_note_keeps_the_originals_rate_and_identity(self) -> None:
        """The original's FX snapshot, all four fields, so `issue()` consumes it rather than resolving
        today's rate; and every `bill_to_*` field, because a correction restates its original."""
        original = self.original(currency_code="EUR")
        payment = self.collected(original, original.total_cents)

        note = self.process(self.refund(original, payment, 1000)).credit_note

        snapshot = ("exchange_to_ron", "exchange_rate_as_of", "exchange_rate_source", "exchange_rate_source_reference")
        self.assertEqual([getattr(note, f) for f in snapshot], [getattr(original, f) for f in snapshot])
        for field in sorted(Invoice._BILLING_SNAPSHOT_FIELDS):
            self.assertEqual(getattr(note, field), getattr(original, field), field)
        result = CIUSROValidator().validate(builder_for(note).build())
        self.assertTrue(result.is_valid, [(error.code, error.message) for error in result.errors])

    def test_a_remainder_carrying_the_discount_is_one_line_and_an_allowance(self) -> None:
        """The last correction of a discounted original takes the discount left. In A2 it can only
        follow a credit that is not a note, so the allocation is written directly here."""
        original = self.original(lines=((10000, "0.21"),), discount_cents=1000, tax_cents=1890)
        payment = self.collected(original, original.total_cents)
        correction = self.refund(original, payment, 5890)
        correction.allocate(base_cents=4868, tax_cents=1022, discount_cents=1000, at=timezone.now())
        correction.save()

        note = self.process(correction).credit_note

        line = note.lines.get()
        self.assertEqual((line.unit_price_cents, line.tax_cents, line.discount_amount_cents), (-5868, -1022, 0))
        self.assertEqual((note.subtotal_cents, note.discount_cents, note.total_cents), (-4868, -1000, -5890))
        xml = builder_for(note).build()
        self.assertEqual(
            etree.fromstring(xml.encode()).findtext(
                "cac:LegalMonetaryTotal/cbc:AllowanceTotalAmount", namespaces=NAMESPACES
            ),
            "10.00",
        )
        result = CIUSROValidator().validate(xml)
        self.assertTrue(result.is_valid, [(error.code, error.message) for error in result.errors])

    def test_a_v1_originals_proof_keeps_its_version_on_the_note(self) -> None:
        original = self.original(evidence_version=1)
        payment = self.collected(original, original.total_cents)

        note = self.process(self.refund(original, payment, 1000)).credit_note

        self.assertEqual(note.vat_evidence["version"], 3)
        self.assertEqual(note.vat_evidence["original_version"], 1)
        self.assertEqual(note.vat_evidence["reverses_number"], original.number)
        self.assertEqual(note.vat_evidence["total_cents"], note.total_cents)
        self.assertLessEqual(datetime.fromisoformat(note.vat_evidence["calculated_at"]), note.issued_at)

    def test_a_provider_originals_correction_is_left_for_the_provider_path(self) -> None:
        original = h.issued_invoice(self.owner, issuer=ISSUER_SMARTBILL)
        payment = h.paid(original)

        correction = self.process(self.refund(original, payment, original.total_cents))

        self.assertEqual(correction.state, STATE_PENDING)
        self.assertIsNone(correction.allocated_at)

    def test_corrections_are_decided_in_refund_completion_order(self) -> None:
        original = self.original()
        payment = self.collected(original, original.total_cents)
        earlier = self.refund(original, payment, 3000)
        later = self.refund(original, payment, 2000)

        self.assertEqual(self.process(later).state, STATE_PENDING)
        self.assertEqual(self.process(earlier).credit_note.total_cents, -3000)
        self.assertEqual(self.process(later).total_cents, -2000)

    def test_a_tender_command_waits_until_it_has_completed(self) -> None:
        original = self.original()
        payment = self.collected(original, original.total_cents)
        command = TenderRefundCommand.objects.create(
            invoice=original,
            customer=self.owner,
            amount_cents=original.total_cents,
            operation_key="storno-tender",
            reason="test",
            status="failed",
        )
        refund = h.pending_refund(invoice=original, payment=payment, amount_cents=5000, refund_type="partial")
        TenderRefundLeg.objects.create(command=command, payment=payment, refund=refund, amount_cents=5000)
        h.complete(refund)
        correction = FiscalCorrection.objects.get(source_command=command)

        self.assertEqual(self.process(correction).state, STATE_PENDING)

        TenderRefundCommand.objects.filter(pk=command.pk).update(status="completed")
        self.assertEqual(self.process(correction).total_cents, -5000)

    def test_running_partials_each_give_a_valid_document(self) -> None:
        """31.43, 31.43, 29.01, 29.12 against 121.00, allocated in turn from the running total.

        Until A3 an original can carry one credit note, so the later three are parked with their
        allocations. Each allocation is then issued against an identical twin original, through the
        same worker, to prove the document it describes passes the validator.
        """
        original = self.original()
        payment = self.collected(original, original.total_cents)
        corrections = []
        for amount in (3143, 3143, 2901, 2912):
            correction = self.refund(original, payment, amount)
            with self.captureOnCommitCallbacks(execute=True):
                process_fiscal_correction(str(correction.pk))
            correction.refresh_from_db()
            corrections.append(correction)

        allocations = [(c.base_cents, c.tax_cents, c.vat_residue_cents) for c in corrections]
        self.assertEqual(allocations, [(-2598, -545, 0), (-2597, -546, 0), (-2398, -503, 0), (-2406, -506, 0)])
        for base, tax, _residue in allocations:
            twin = self.original()
            twin_correction = self.refund(twin, self.collected(twin, twin.total_cents), -(base + tax))
            twin_correction.allocate(base_cents=-base, tax_cents=-tax, discount_cents=0, at=timezone.now())
            twin_correction.save()
            note = self.process(twin_correction).credit_note
            result = CIUSROValidator().validate(builder_for(note).build())
            self.assertTrue(result.is_valid, [(error.code, error.message) for error in result.errors])

    def test_a_remainder_split_for_validity_records_its_vat_residue(self) -> None:
        """Three lines of 1.02 at 21% (VAT 0.63 on 3.06). After a 0.03 refund the rest would be base
        3.04 with VAT 0.62, outside BR-CO-14; it is credited as 3.03 + 0.63 and the cent recorded."""
        original = self.original(lines=((102, "0.21"), (102, "0.21"), (102, "0.21")))
        payment = self.collected(original, original.total_cents)
        self.process(self.refund(original, payment, 3))

        with self.assertLogs("apps.billing.fiscal_correction_worker", level="WARNING") as logs:
            rest = self.process(self.refund(original, payment, 366))

        self.assertEqual((rest.base_cents, rest.tax_cents, rest.total_cents), (-303, -63, -366))
        self.assertEqual(rest.vat_residue_cents, -1)
        self.assertTrue(any("un-reversed" in line for line in logs.output), logs.output)

    def test_completing_a_refund_queues_the_worker_after_commit(self) -> None:
        original = self.original()
        payment = self.collected(original, original.total_cents)

        with patch("django_q.tasks.async_task") as queued, self.captureOnCommitCallbacks(execute=True):
            correction = self.refund(original, payment, 1000)

        worker_calls = [call for call in queued.call_args_list if call.args[0] == TASK_PATH]
        self.assertEqual(len(worker_calls), 1)
        self.assertEqual(worker_calls[0].args[1], str(correction.pk))


class AllocationAmountsTests(StornoTestCase):
    """The sequences of plan v3, at the allocation layer: one note per original until A3."""

    def test_sequential_allocations_never_exceed_the_original(self) -> None:
        original = self.original()
        payment = self.collected(original, original.total_cents)
        totals = []
        for amount in (3000, 4002, 5097):
            correction = self.refund(original, payment, amount)
            with self.captureOnCommitCallbacks(execute=True):
                process_fiscal_correction(str(correction.pk))
            correction.refresh_from_db()
            totals.append((correction.base_cents, correction.tax_cents, correction.total_cents))

        self.assertEqual(totals, [(-2479, -521, -3000), (-3308, -694, -4002), (-4212, -885, -5097)])
        self.assertLessEqual(-sum(tax for _base, tax, _total in totals), original.tax_cents)
        self.assertEqual(sum(base for base, _tax, _total in totals), -9999)
