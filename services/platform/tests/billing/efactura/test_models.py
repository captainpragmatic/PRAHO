"""
Tests for EFacturaDocument model.
"""

from datetime import timedelta
from unittest.mock import MagicMock, patch

import pytest
from django.test import TestCase, override_settings
from django.utils import timezone

from apps.billing.efactura.models import EFacturaDocument, EFacturaDocumentType, EFacturaStatus


class EFacturaDocumentModelTestCase(TestCase):
    """Test EFacturaDocument model."""

    @classmethod
    def setUpTestData(cls):
        """Set up test data."""
        from tests.factories import CurrencyFactory, CustomerFactory, InvoiceFactory

        cls.currency = CurrencyFactory(code="RON")
        cls.customer = CustomerFactory()
        cls.invoice = InvoiceFactory(
            customer=cls.customer,
            currency=cls.currency,
            number="INV-2024-001",
            bill_to_country="RO",
            bill_to_tax_id="RO12345678",
            status="issued",
        )

    def test_create_efactura_document(self):
        """Test creating e-Factura document."""
        document = EFacturaDocument.objects.create(
            invoice=self.invoice,
            document_type=EFacturaDocumentType.INVOICE.value,
        )

        self.assertIsNotNone(document.id)
        self.assertEqual(document.status, EFacturaStatus.DRAFT.value)
        self.assertEqual(document.invoice, self.invoice)
        self.assertEqual(document.retry_count, 0)

    def test_xml_hash_computed_on_save(self):
        """Test XML hash is computed when XML content is saved."""
        document = EFacturaDocument.objects.create(
            invoice=self.invoice,
            xml_content="<Invoice>Test</Invoice>",
        )

        self.assertNotEqual(document.xml_hash, "")
        self.assertEqual(len(document.xml_hash), 64)  # SHA-256

    def test_verify_xml_integrity(self):
        """Test XML integrity verification."""
        document = EFacturaDocument.objects.create(
            invoice=self.invoice,
            xml_content="<Invoice>Test</Invoice>",
        )

        self.assertTrue(document.verify_xml_integrity())

        # Tamper with content
        document.xml_content = "<Invoice>Tampered</Invoice>"
        self.assertFalse(document.verify_xml_integrity())

    def test_mark_queued(self):
        """Test marking document as queued."""
        document = EFacturaDocument.objects.create(invoice=self.invoice)
        document.mark_queued()

        document.refresh_from_db()
        self.assertEqual(document.status, EFacturaStatus.QUEUED.value)

    def test_mark_submitted(self):
        """Test marking document as submitted."""
        document = EFacturaDocument.objects.create(invoice=self.invoice)
        document.mark_submitted("12345")

        document.refresh_from_db()
        self.assertEqual(document.status, EFacturaStatus.SUBMITTED.value)
        self.assertEqual(document.anaf_upload_index, "12345")
        self.assertIsNotNone(document.submitted_at)

    def test_mark_accepted(self):
        """Test marking document as accepted."""
        document = EFacturaDocument.objects.create(
            invoice=self.invoice,
            anaf_upload_index="12345",
        )
        document.mark_accepted("download-123", {"result": "ok"})

        document.refresh_from_db()
        self.assertEqual(document.status, EFacturaStatus.ACCEPTED.value)
        self.assertEqual(document.anaf_download_id, "download-123")
        self.assertIsNotNone(document.response_at)
        self.assertEqual(document.anaf_response, {"result": "ok"})

        # Check invoice was updated
        self.invoice.refresh_from_db()
        self.assertTrue(self.invoice.efactura_sent)
        self.assertEqual(self.invoice.efactura_id, "12345")

    def test_mark_rejected(self):
        """Test marking document as rejected."""
        document = EFacturaDocument.objects.create(invoice=self.invoice)
        errors = [{"code": "BR-01", "message": "ID missing"}]
        document.mark_rejected(errors)

        document.refresh_from_db()
        self.assertEqual(document.status, EFacturaStatus.REJECTED.value)
        self.assertEqual(document.validation_errors, errors)

    def test_mark_error_with_retry(self):
        """Test marking document as error with retry scheduling."""
        document = EFacturaDocument.objects.create(invoice=self.invoice)
        document.mark_error("Network timeout")

        document.refresh_from_db()
        self.assertEqual(document.status, EFacturaStatus.ERROR.value)
        self.assertEqual(document.retry_count, 1)
        self.assertIsNotNone(document.next_retry_at)
        self.assertEqual(document.last_error, "Network timeout")

    def test_max_retries_exceeded(self):
        """Test that next_retry_at is None after max retries."""
        document = EFacturaDocument.objects.create(
            invoice=self.invoice,
            retry_count=EFacturaDocument.MAX_RETRIES,
        )
        document.mark_error("Final error")

        document.refresh_from_db()
        self.assertIsNone(document.next_retry_at)

    def test_is_terminal(self):
        """Test terminal status detection."""
        document = EFacturaDocument.objects.create(invoice=self.invoice)

        document.status = EFacturaStatus.DRAFT.value
        self.assertFalse(document.is_terminal)

        document.status = EFacturaStatus.ACCEPTED.value
        self.assertTrue(document.is_terminal)

        document.status = EFacturaStatus.REJECTED.value
        self.assertTrue(document.is_terminal)

    def test_can_retry(self):
        """Test retry eligibility check."""
        document = EFacturaDocument.objects.create(invoice=self.invoice)

        document.status = EFacturaStatus.DRAFT.value
        self.assertFalse(document.can_retry)

        document.status = EFacturaStatus.ERROR.value
        self.assertTrue(document.can_retry)

        document.retry_count = EFacturaDocument.MAX_RETRIES
        self.assertFalse(document.can_retry)

    def test_submission_deadline(self):
        """Test submission deadline calculation."""
        self.invoice.issued_at = timezone.now() - timedelta(days=3)
        self.invoice.save()

        document = EFacturaDocument.objects.create(invoice=self.invoice)

        deadline = document.submission_deadline
        self.assertIsNotNone(deadline)
        expected = self.invoice.issued_at + timedelta(days=5)
        self.assertEqual(deadline, expected)

    def test_is_deadline_approaching(self):
        """Test deadline approaching detection."""
        self.invoice.issued_at = timezone.now() - timedelta(days=4, hours=12)
        self.invoice.save()

        document = EFacturaDocument.objects.create(invoice=self.invoice)
        self.assertTrue(document.is_deadline_approaching)

    def test_is_deadline_passed(self):
        """Test deadline passed detection."""
        self.invoice.issued_at = timezone.now() - timedelta(days=6)
        self.invoice.save()

        document = EFacturaDocument.objects.create(invoice=self.invoice)
        self.assertTrue(document.is_deadline_passed)

    def test_get_pending_submissions(self):
        """Test querying pending submissions."""
        doc1 = EFacturaDocument.objects.create(
            invoice=self.invoice,
            status=EFacturaStatus.QUEUED.value,
        )

        pending = EFacturaDocument.get_pending_submissions()
        self.assertEqual(pending.count(), 1)
        self.assertEqual(pending.first(), doc1)

    def test_get_awaiting_response(self):
        """Test querying documents awaiting response."""
        EFacturaDocument.objects.create(
            invoice=self.invoice,
            status=EFacturaStatus.SUBMITTED.value,
            submitted_at=timezone.now(),
        )

        awaiting = EFacturaDocument.get_awaiting_response()
        self.assertEqual(awaiting.count(), 1)

    def test_get_ready_for_retry(self):
        """Test querying documents ready for retry."""
        document = EFacturaDocument.objects.create(
            invoice=self.invoice,
            status=EFacturaStatus.ERROR.value,
            next_retry_at=timezone.now() - timedelta(minutes=5),
        )

        ready = EFacturaDocument.get_ready_for_retry()
        self.assertEqual(ready.count(), 1)
        self.assertEqual(ready.first(), document)

    def test_unique_document_per_invoice(self):
        """Test that only one document can exist per invoice."""
        EFacturaDocument.objects.create(invoice=self.invoice)

        with self.assertRaises(Exception):  # IntegrityError
            EFacturaDocument.objects.create(invoice=self.invoice)


class EFacturaStatusEnumTestCase(TestCase):
    """Test EFacturaStatus enum."""

    def test_choices(self):
        """Test choices method returns valid Django choices."""
        choices = EFacturaStatus.choices()
        self.assertIsInstance(choices, list)
        self.assertTrue(all(len(c) == 2 for c in choices))

    def test_terminal_statuses(self):
        """Test terminal statuses set."""
        terminal = EFacturaStatus.terminal_statuses()
        self.assertIn("accepted", terminal)
        self.assertIn("rejected", terminal)
        self.assertNotIn("submitted", terminal)

    def test_retryable_statuses(self):
        """Test retryable statuses set."""
        retryable = EFacturaStatus.retryable_statuses()
        self.assertIn("error", retryable)
        self.assertIn("queued", retryable)
        self.assertNotIn("accepted", retryable)
