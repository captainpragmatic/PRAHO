"""After a built-in storno is issued: the customer's copy, the email that dates it, and e-Factura.

None of these can undo the note, so each is retried until it succeeds and never repeated once it has:
the first successful send sets the communication date once, and a 381 is filed only after ANAF
accepted the invoice it corrects.
"""

from __future__ import annotations

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
)
from apps.billing.efactura.settings import ro_local_date
from apps.billing.fiscal_correction_models import (
    EFACTURA_NOT_APPLICABLE,
    EFACTURA_SUBMITTED,
    EFACTURA_WAITING_FOR_ORIGINAL,
    STATE_COMMUNICATED,
    STATE_ISSUED,
)
from apps.billing.fiscal_correction_worker import deliver_credit_note
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
        with patch("apps.billing.efactura.service.EFacturaClient", return_value=_accepting_client()):
            self.sweep()

        correction.refresh_from_db()
        self.assertEqual(correction.efactura_status, EFACTURA_SUBMITTED)
        self.assertEqual(EFacturaDocument.objects.get(invoice=note).status, EFacturaStatus.SUBMITTED.value)

    def test_a_note_outside_romania_is_never_filed(self) -> None:
        _original, note = self._issued_note(country="DE")

        self.assertEqual(note.settled_fiscal_correction.efactura_status, EFACTURA_NOT_APPLICABLE)
        result = EFacturaService(client=_accepting_client()).submit_invoice(note)
        self.assertEqual(result.gate, GATE_NOT_APPLICABLE)
