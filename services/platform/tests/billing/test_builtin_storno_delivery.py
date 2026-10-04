"""After a built-in storno is issued: the customer's copy, the email that dates it, and e-Factura.

None of these can undo the note, so each is retried until it succeeds and never repeated once it has:
the first successful send sets the communication date once, and a 381 is filed only after ANAF
accepted the invoice it corrects.
"""

from __future__ import annotations

from datetime import timedelta
from typing import Any
from unittest.mock import MagicMock, patch

from django.core import mail
from django.test import override_settings
from django.utils import timezone

from apps.billing.efactura.client import UploadResponse
from apps.billing.efactura.models import EFacturaDocument, EFacturaDocumentType, EFacturaStatus
from apps.billing.efactura.service import (
    GATE_NOT_APPLICABLE,
    GATE_ORIGINAL_REJECTED,
    GATE_WAITING_FOR_ORIGINAL,
    EFacturaService,
    SubmissionResult,
)
from apps.billing.efactura.settings import ro_local_date
from apps.billing.fiscal_correction_models import (
    EFACTURA_FAILED,
    EFACTURA_NOT_APPLICABLE,
    EFACTURA_PENDING,
    EFACTURA_SUBMITTED,
    EFACTURA_WAITING_FOR_ORIGINAL,
    STATE_COMMUNICATED,
    STATE_ISSUED,
    FiscalCorrection,
)
from apps.billing.fiscal_correction_worker import (
    EFACTURA_MAX_BACKOFF,
    _advance_efactura,
    deliver_credit_note,
    efactura_backoff,
)
from apps.billing.invoice_models import Invoice
from apps.billing.pdf_generators import RomanianInvoicePDFGenerator
from apps.notifications.services import EmailResult
from tests.billing._storno_helpers import SELLER, StornoTestCase


def pdf_rows(document: Invoice) -> list[str]:
    """Every string the PDF draws, in order."""
    generator = RomanianInvoicePDFGenerator(document)
    with patch.object(generator.canvas, "drawString") as drawn:
        generator._create_pdf_document()
    return [str(call.args[2]) for call in drawn.call_args_list]


def _anaf_document(invoice: Invoice, status: str) -> EFacturaDocument:
    document = EFacturaDocument.objects.create(
        invoice=invoice, document_type=EFacturaDocumentType.INVOICE.value, environment="test"
    )
    EFacturaDocument.objects.filter(pk=document.pk).update(status=status)
    return EFacturaDocument.objects.get(pk=document.pk)


def _back_off_elapsed(correction: Any) -> None:
    """Move the next filing attempt into the past, as if its backoff had run out."""
    FiscalCorrection.objects.filter(pk=correction.pk).update(
        efactura_next_attempt_at=timezone.now() - timedelta(seconds=1)
    )


def _accepting_client() -> MagicMock:
    client = MagicMock()
    client.upload_credit_note.return_value = UploadResponse(success=True, upload_index="5001")
    client.upload_b2c.return_value = UploadResponse(success=True, upload_index="5001")
    return client


@SELLER
class StornoDocumentTests(StornoTestCase):
    def test_the_pdf_is_titled_a_storno_names_its_original_and_totals_the_credit(self) -> None:
        original = self.original()
        payment = self.collected(original, original.total_cents)

        note = self.process(self.refund(original, payment, 1000)).credit_note
        rows = pdf_rows(note)

        self.assertIn("FACTURĂ STORNO / CREDIT NOTE", rows)
        issued_on = timezone.localtime(original.issued_at).strftime("%d.%m.%Y")
        self.assertIn(f"Storno la factura {original.number} din {issued_on}", rows)
        self.assertIn("Total creditat / Total credited: -10.00 RON", rows)
        self.assertNotIn("FISCAL INVOICE", rows)
        self.assertFalse(any(row.startswith("TOTAL TO PAY") for row in rows))

    def test_an_ordinary_invoice_keeps_its_title_and_total(self) -> None:
        rows = pdf_rows(self.original())

        self.assertIn("FISCAL INVOICE", rows)
        self.assertIn("TOTAL TO PAY: 121.00 RON", rows)


@SELLER
class StornoCommunicationTests(StornoTestCase):
    def test_the_note_is_emailed_with_its_pdf_and_dated_by_the_send(self) -> None:
        original = self.original()
        payment = self.collected(original, original.total_cents)

        correction = self.process(self.refund(original, payment, 1000))

        self.assertEqual(correction.state, STATE_COMMUNICATED)
        self.assertEqual(correction.fiscal_date, ro_local_date(correction.communicated_at))
        self.assertEqual(len(mail.outbox), 1)
        message = mail.outbox[0]
        self.assertEqual(message.to, ["billing@customer.test"])
        self.assertIn(correction.credit_note.number, message.subject)
        (name, content, mimetype) = message.attachments[0]
        self.assertEqual((name, mimetype), (f"storno_{correction.credit_note.number}.pdf", "application/pdf"))
        self.assertTrue(content.startswith(b"%PDF"))

    def test_a_customer_without_a_language_preference_gets_the_romanian_email(self) -> None:
        original = self.original()
        payment = self.collected(original, original.total_cents)

        number = self.process(self.refund(original, payment, 1000)).credit_note.number

        self.assertEqual(mail.outbox[0].subject, f"Factură storno {number} - PragmaticHost")

    def test_a_failed_send_stays_visible_and_the_sweep_sends_it_once(self) -> None:
        original = self.original()
        payment = self.collected(original, original.total_cents)
        correction = self.refund(original, payment, 1000)
        down = EmailResult(success=False, error="SMTP unavailable")

        with patch("apps.notifications.services.EmailService.send_template_email", return_value=down):
            failed = self.process(correction)

        self.assertEqual(failed.state, STATE_ISSUED)
        self.assertEqual((failed.communication_attempts, failed.communication_error), (1, "SMTP unavailable"))
        self.assertIsNone(failed.communicated_at)

        self.sweep()
        failed.refresh_from_db()
        self.assertEqual(failed.state, STATE_COMMUNICATED)
        first_sent = failed.communicated_at

        with self.captureOnCommitCallbacks(execute=True):
            deliver_credit_note(str(failed.pk))
        self.sweep()
        failed.refresh_from_db()
        self.assertEqual(failed.communicated_at, first_sent)
        self.assertEqual(failed.communication_attempts, 2)
        self.assertEqual(len(mail.outbox), 1)


@SELLER
class StornoCommunicationClaimTests(StornoTestCase):
    def _unsent(self) -> FiscalCorrection:
        original = self.original()
        payment = self.collected(original, original.total_cents)
        down = EmailResult(success=False, error="SMTP unavailable")
        with patch("apps.notifications.services.EmailService.send_template_email", return_value=down):
            return self.process(self.refund(original, payment, 1000))

    def test_a_live_claim_keeps_a_second_sender_out(self) -> None:
        correction = self._unsent()
        FiscalCorrection.objects.filter(pk=correction.pk).update(
            communication_claimed_at=timezone.now() - timedelta(minutes=1)
        )

        self.sweep()

        correction.refresh_from_db()
        self.assertEqual((correction.state, len(mail.outbox)), (STATE_ISSUED, 0))

    def test_a_stale_claim_is_retaken_and_the_note_sent_once(self) -> None:
        """A sender that died after claiming leaves a claim older than the lease; it is retaken."""
        correction = self._unsent()
        FiscalCorrection.objects.filter(pk=correction.pk).update(
            communication_claimed_at=timezone.now() - timedelta(minutes=10)
        )

        self.sweep()
        self.sweep()

        correction.refresh_from_db()
        self.assertEqual(correction.state, STATE_COMMUNICATED)
        self.assertIsNone(correction.communication_claimed_at)
        self.assertEqual(len(mail.outbox), 1)


@SELLER
class StornoEFacturaDisabledTests(StornoTestCase):
    def test_a_note_is_not_held_for_an_efactura_that_is_switched_off(self) -> None:
        """EFACTURA_ENABLED is the switch `submit_invoice` obeys; with it off nothing is ever filed,
        so a Romanian note is not applicable rather than waiting forever for its original."""
        original = self.original()
        payment = self.collected(original, original.total_cents)

        correction = self.process(self.refund(original, payment, 1000))

        self.assertEqual(correction.efactura_status, EFACTURA_NOT_APPLICABLE)
        self.assertIsNone(correction.efactura_next_attempt_at)


@SELLER
@override_settings(EFACTURA_ENABLED=True)
class StornoEFacturaGateTests(StornoTestCase):
    def _issued_note(self, **original_fields: Any) -> tuple[Invoice, Invoice]:
        original = self.original(**original_fields)
        payment = self.collected(original, original.total_cents)
        with patch("apps.billing.efactura.service.EFacturaClient", return_value=_accepting_client()):
            note = self.process(self.refund(original, payment, 1000)).credit_note
        return original, note

    def test_the_service_holds_a_381_until_its_original_is_accepted(self) -> None:
        """Called directly, past the worker: the gate lives in the service every path goes through."""
        original, note = self._issued_note()
        for status, gate in (
            (EFacturaStatus.SUBMITTED.value, GATE_WAITING_FOR_ORIGINAL),
            (EFacturaStatus.REJECTED.value, GATE_ORIGINAL_REJECTED),
        ):
            with self.subTest(original_status=status):
                EFacturaDocument.objects.filter(invoice=original).delete()
                _anaf_document(original, status)
                client = _accepting_client()

                result = EFacturaService(client=client).submit_invoice(note)

                self.assertFalse(result.success)
                self.assertEqual(result.gate, gate)
                client.upload_credit_note.assert_not_called()
                self.assertFalse(EFacturaDocument.objects.filter(invoice=note).exists())

        EFacturaDocument.objects.filter(invoice=original).delete()
        _anaf_document(original, EFacturaStatus.ACCEPTED.value)
        client = _accepting_client()

        result = EFacturaService(client=client).submit_invoice(note)

        self.assertTrue(result.success, result.error_message)
        client.upload_credit_note.assert_called_once()

    def test_the_worker_files_the_note_once_the_original_is_accepted(self) -> None:
        original, note = self._issued_note()
        correction = note.settled_fiscal_correction
        self.assertEqual(correction.efactura_status, EFACTURA_WAITING_FOR_ORIGINAL)

        _anaf_document(original, EFacturaStatus.ACCEPTED.value)
        _back_off_elapsed(correction)
        with patch("apps.billing.efactura.service.EFacturaClient", return_value=_accepting_client()):
            self.sweep()

        correction.refresh_from_db()
        self.assertEqual(correction.efactura_status, EFACTURA_SUBMITTED)
        self.assertIsNone(correction.efactura_next_attempt_at)
        self.assertEqual(EFacturaDocument.objects.get(invoice=note).status, EFacturaStatus.SUBMITTED.value)

    def test_a_held_note_is_rechecked_with_backoff_not_every_sweep(self) -> None:
        _original, note = self._issued_note()
        correction = note.settled_fiscal_correction
        first_retry = correction.efactura_next_attempt_at
        self.assertEqual((correction.efactura_status, correction.efactura_attempts), (EFACTURA_WAITING_FOR_ORIGINAL, 1))
        self.assertAlmostEqual(first_retry - timezone.now(), timedelta(hours=1), delta=timedelta(minutes=1))

        self.sweep()
        correction.refresh_from_db()
        self.assertEqual(correction.efactura_attempts, 1, "re-checked before its backoff elapsed")

        _back_off_elapsed(correction)
        self.sweep()
        correction.refresh_from_db()
        self.assertEqual((correction.efactura_status, correction.efactura_attempts), (EFACTURA_WAITING_FOR_ORIGINAL, 2))
        self.assertAlmostEqual(
            correction.efactura_next_attempt_at - timezone.now(), timedelta(hours=2), delta=timedelta(minutes=1)
        )

    def test_a_failed_filing_is_retried_by_the_sweep(self) -> None:
        original = self.original()
        payment = self.collected(original, original.total_cents)
        _anaf_document(original, EFacturaStatus.ACCEPTED.value)
        refused = MagicMock()
        refused.upload_credit_note.return_value = UploadResponse(success=False, message="ANAF refused the upload")
        with patch("apps.billing.efactura.service.EFacturaClient", return_value=refused):
            correction = self.process(self.refund(original, payment, 1000))

        self.assertEqual(correction.efactura_status, EFACTURA_FAILED)
        self.assertIn("ANAF refused the upload", correction.efactura_error)
        note_document = EFacturaDocument.objects.get(invoice=correction.credit_note)
        self.assertEqual(note_document.status, EFacturaStatus.ERROR.value)

        _back_off_elapsed(correction)
        with patch("apps.billing.efactura.service.EFacturaClient", return_value=_accepting_client()):
            self.sweep()

        correction.refresh_from_db()
        self.assertEqual(correction.efactura_status, EFACTURA_SUBMITTED)
        note_document.refresh_from_db()
        self.assertEqual(note_document.status, EFacturaStatus.SUBMITTED.value)

    def test_a_note_outside_romania_is_never_filed(self) -> None:
        _original, note = self._issued_note(country="DE")

        self.assertEqual(note.settled_fiscal_correction.efactura_status, EFACTURA_NOT_APPLICABLE)
        result = EFacturaService(client=_accepting_client()).submit_invoice(note)
        self.assertEqual(result.gate, GATE_NOT_APPLICABLE)


@SELLER
@override_settings(EFACTURA_ENABLED=True)
class InFlightUploadTests(StornoTestCase):
    def test_another_workers_live_upload_is_not_recorded_as_submitted(self) -> None:
        original = self.original()
        payment = self.collected(original, original.total_cents)
        correction = self.process(self.refund(original, payment, 1000))
        EFacturaDocument.objects.create(
            invoice=original, document_type=EFacturaDocumentType.INVOICE.value, environment="test"
        )
        EFacturaDocument.objects.filter(invoice=original).update(status=EFacturaStatus.ACCEPTED.value)
        uploading = EFacturaDocument(status=EFacturaStatus.UPLOADING.value)
        FiscalCorrection.objects.filter(pk=correction.pk).update(
            efactura_status=EFACTURA_PENDING, efactura_next_attempt_at=None
        )

        with patch(
            "apps.billing.efactura.service.EFacturaService.submit_invoice",
            return_value=SubmissionResult.ok(uploading),
        ):
            _advance_efactura(str(correction.pk))

        correction.refresh_from_db()
        self.assertNotEqual(correction.efactura_status, EFACTURA_SUBMITTED)
        self.assertEqual(correction.efactura_status, EFACTURA_PENDING)
        self.assertIsNotNone(correction.efactura_next_attempt_at)


class BackoffCapTests(StornoTestCase):
    def test_a_long_failing_filing_backs_off_a_week_without_overflowing(self) -> None:
        self.assertEqual(efactura_backoff(100), EFACTURA_MAX_BACKOFF)
        self.assertEqual(efactura_backoff(10_000), timedelta(days=7))
        self.assertEqual(efactura_backoff(1), timedelta(hours=1))
