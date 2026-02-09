"""
Tests for e-Factura service.
"""

from datetime import timedelta
from unittest.mock import MagicMock, Mock, patch, PropertyMock
from uuid import uuid4

from django.test import TestCase, override_settings
from django.utils import timezone

from apps.billing.efactura.client import (
    AuthenticationError,
    EFacturaClient,
    NetworkError,
    StatusResponse,
    UploadResponse,
)
from apps.billing.efactura.models import EFacturaDocument, EFacturaDocumentType, EFacturaStatus
from apps.billing.efactura.service import (
    EFacturaService,
    StatusCheckResult,
    SubmissionResult,
    submit_invoice_to_efactura,
)
from apps.billing.efactura.validator import ValidationResult, ValidationError as ValidatorError
from apps.billing.efactura.xml_builder import XMLBuilderError


class SubmissionResultTestCase(TestCase):
    """Test SubmissionResult dataclass."""

    def test_ok_result(self):
        """Test successful result."""
        mock_doc = Mock(spec=EFacturaDocument)
        result = SubmissionResult.ok(mock_doc)
        self.assertTrue(result.success)
        self.assertEqual(result.document, mock_doc)
        self.assertEqual(result.errors, [])

    def test_error_result(self):
        """Test error result."""
        result = SubmissionResult.error("Test error", [{"code": "E001"}])
        self.assertFalse(result.success)
        self.assertEqual(result.error_message, "Test error")
        self.assertEqual(len(result.errors), 1)

    def test_error_default_empty_errors(self):
        """Test error result defaults to empty errors list."""
        result = SubmissionResult.error("Test error")
        self.assertEqual(result.errors, [])


class StatusCheckResultTestCase(TestCase):
    """Test StatusCheckResult dataclass."""

    def test_status_result(self):
        """Test status check result."""
        result = StatusCheckResult(
            status="accepted",
            is_terminal=True,
            download_id="12345",
        )
        self.assertEqual(result.status, "accepted")
        self.assertTrue(result.is_terminal)
        self.assertEqual(result.download_id, "12345")

    def test_default_errors(self):
        """Test default empty errors list."""
        result = StatusCheckResult(status="processing")
        self.assertEqual(result.errors, [])


class MockInvoice:
    """Mock Invoice object for testing."""

    def __init__(
        self,
        id=None,
        number="INV-001",
        bill_to_country="RO",
        bill_to_tax_id="RO12345678",
        total_cents=100000,
        status="issued",
    ):
        self.id = id or uuid4()
        self.number = number
        self.bill_to_country = bill_to_country
        self.bill_to_tax_id = bill_to_tax_id
        self.total_cents = total_cents
        self.status = status
        self.issued_at = timezone.now()
        self._efactura_document = None

    @property
    def efactura_document(self):
        if self._efactura_document is None:
            raise EFacturaDocument.DoesNotExist()
        return self._efactura_document

    @efactura_document.setter
    def efactura_document(self, value):
        self._efactura_document = value


@override_settings(
    EFACTURA_ENABLED=True,
    EFACTURA_ENVIRONMENT="test",
    EFACTURA_B2C_ENABLED=False,
    EFACTURA_MINIMUM_AMOUNT_CENTS=0,
)
class EFacturaServiceTestCase(TestCase):
    """Test EFacturaService."""

    def setUp(self):
        self.mock_client = Mock(spec=EFacturaClient)
        self.service = EFacturaService(client=self.mock_client)
        self.invoice = MockInvoice()

    def test_init_with_default_client(self):
        """Test service creates default client if none provided."""
        with patch("apps.billing.efactura.service.EFacturaClient") as mock_client_class:
            service = EFacturaService()
            mock_client_class.assert_called_once()

    @override_settings(EFACTURA_ENABLED=False)
    def test_submit_disabled(self):
        """Test submission when e-Factura is disabled."""
        result = self.service.submit_invoice(self.invoice)
        self.assertFalse(result.success)
        self.assertIn("disabled", result.error_message.lower())

    def test_submit_non_romanian_invoice(self):
        """Test submission skipped for non-Romanian invoice."""
        self.invoice.bill_to_country = "US"
        result = self.service.submit_invoice(self.invoice)
        self.assertFalse(result.success)
        self.assertIn("does not require", result.error_message.lower())

    @patch("apps.billing.efactura.service.EFacturaDocument.objects")
    @patch.object(EFacturaService, "_generate_xml")
    def test_submit_success(self, mock_generate, mock_objects):
        """Test successful submission."""
        mock_doc = Mock(spec=EFacturaDocument)
        mock_doc.status = EFacturaStatus.DRAFT.value
        mock_objects.get_or_create.return_value = (mock_doc, True)

        mock_generate.return_value = "<Invoice/>"

        self.mock_client.upload_invoice.return_value = UploadResponse(
            success=True,
            upload_index="12345",
        )

        with patch.object(self.service, "_log_audit_event"):
            result = self.service.submit_invoice(self.invoice)

        self.assertTrue(result.success)
        self.assertEqual(result.document, mock_doc)
        mock_doc.mark_submitted.assert_called_once_with("12345")

    @patch("apps.billing.efactura.service.EFacturaDocument.objects")
    @patch.object(EFacturaService, "_generate_xml")
    @patch.object(EFacturaService, "_validate_xml")
    def test_submit_validation_failure(self, mock_validate, mock_generate, mock_objects):
        """Test submission with validation failure."""
        mock_doc = Mock(spec=EFacturaDocument)
        mock_doc.status = EFacturaStatus.DRAFT.value
        mock_objects.get_or_create.return_value = (mock_doc, True)

        mock_generate.return_value = "<Invoice/>"

        validation_result = ValidationResult(is_valid=False)
        validation_result.add_error("BR-01", "Missing ID")
        mock_validate.return_value = validation_result

        with patch.object(self.service, "_log_audit_event"):
            result = self.service.submit_invoice(self.invoice, validate_first=True)

        self.assertFalse(result.success)
        self.assertIn("validation failed", result.error_message.lower())
        mock_doc.mark_rejected.assert_called_once()

    @patch("apps.billing.efactura.service.EFacturaDocument.objects")
    @patch.object(EFacturaService, "_generate_xml")
    def test_submit_upload_failure(self, mock_generate, mock_objects):
        """Test submission with upload failure."""
        mock_doc = Mock(spec=EFacturaDocument)
        mock_doc.status = EFacturaStatus.DRAFT.value
        mock_objects.get_or_create.return_value = (mock_doc, True)

        mock_generate.return_value = "<Invoice/>"

        self.mock_client.upload_invoice.return_value = UploadResponse(
            success=False,
            message="Invalid XML",
            errors=["Schema validation error"],
        )

        with patch.object(self.service, "_log_audit_event"):
            result = self.service.submit_invoice(self.invoice, validate_first=False)

        self.assertFalse(result.success)
        mock_doc.mark_error.assert_called_once()

    @patch.object(EFacturaService, "_get_existing_document")
    def test_submit_already_accepted(self, mock_get_existing):
        """Test submission when already accepted."""
        mock_doc = Mock(spec=EFacturaDocument)
        mock_doc.status = EFacturaStatus.ACCEPTED.value
        mock_get_existing.return_value = mock_doc

        result = self.service.submit_invoice(self.invoice)

        self.assertTrue(result.success)
        self.assertEqual(result.document, mock_doc)
        # Should not attempt re-submission
        self.mock_client.upload_invoice.assert_not_called()

    @patch("apps.billing.efactura.service.EFacturaDocument.objects")
    @patch.object(EFacturaService, "_generate_xml")
    def test_submit_authentication_error(self, mock_generate, mock_objects):
        """Test submission with authentication error."""
        mock_doc = Mock(spec=EFacturaDocument)
        mock_doc.status = EFacturaStatus.DRAFT.value
        mock_objects.get_or_create.return_value = (mock_doc, True)

        mock_generate.return_value = "<Invoice/>"
        self.mock_client.upload_invoice.side_effect = AuthenticationError("Token expired")

        with patch.object(self.service, "_get_existing_document", return_value=mock_doc):
            result = self.service.submit_invoice(self.invoice, validate_first=False)

        self.assertFalse(result.success)
        self.assertIn("Authentication", result.error_message)

    @patch("apps.billing.efactura.service.EFacturaDocument.objects")
    @patch.object(EFacturaService, "_generate_xml")
    def test_submit_network_error(self, mock_generate, mock_objects):
        """Test submission with network error."""
        mock_doc = Mock(spec=EFacturaDocument)
        mock_doc.status = EFacturaStatus.DRAFT.value
        mock_objects.get_or_create.return_value = (mock_doc, True)

        mock_generate.return_value = "<Invoice/>"
        self.mock_client.upload_invoice.side_effect = NetworkError("Connection refused")

        with patch.object(self.service, "_get_existing_document", return_value=mock_doc):
            result = self.service.submit_invoice(self.invoice, validate_first=False)

        self.assertFalse(result.success)
        self.assertIn("Network", result.error_message)


@override_settings(EFACTURA_ENABLED=True)
class EFacturaStatusCheckTestCase(TestCase):
    """Test status checking functionality."""

    def setUp(self):
        self.mock_client = Mock(spec=EFacturaClient)
        self.service = EFacturaService(client=self.mock_client)

    def test_check_status_no_upload_index(self):
        """Test status check without upload index."""
        mock_doc = Mock(spec=EFacturaDocument)
        mock_doc.anaf_upload_index = ""

        result = self.service.check_status(mock_doc)

        self.assertEqual(result.status, "error")
        self.assertTrue(len(result.errors) > 0)

    def test_check_status_accepted(self):
        """Test status check returns accepted."""
        mock_doc = Mock(spec=EFacturaDocument)
        mock_doc.anaf_upload_index = "12345"
        mock_doc.invoice = Mock()

        mock_response = Mock()
        mock_response.is_accepted = True
        mock_response.is_rejected = False
        mock_response.is_processing = False
        mock_response.download_id = "67890"
        mock_response.raw_response = {}
        self.mock_client.get_upload_status.return_value = mock_response

        with patch.object(self.service, "_log_audit_event"):
            result = self.service.check_status(mock_doc)

        self.assertEqual(result.status, "accepted")
        self.assertTrue(result.is_terminal)
        self.assertEqual(result.download_id, "67890")
        mock_doc.mark_accepted.assert_called_once()

    def test_check_status_rejected(self):
        """Test status check returns rejected."""
        mock_doc = Mock(spec=EFacturaDocument)
        mock_doc.anaf_upload_index = "12345"
        mock_doc.invoice = Mock()

        mock_response = Mock()
        mock_response.is_accepted = False
        mock_response.is_rejected = True
        mock_response.is_processing = False
        mock_response.errors = [{"message": "Invalid CUI"}]
        mock_response.raw_response = {}
        self.mock_client.get_upload_status.return_value = mock_response

        with patch.object(self.service, "_log_audit_event"):
            result = self.service.check_status(mock_doc)

        self.assertEqual(result.status, "rejected")
        self.assertTrue(result.is_terminal)
        self.assertEqual(len(result.errors), 1)
        mock_doc.mark_rejected.assert_called_once()

    def test_check_status_processing(self):
        """Test status check returns processing."""
        mock_doc = Mock(spec=EFacturaDocument)
        mock_doc.anaf_upload_index = "12345"

        mock_response = Mock()
        mock_response.is_accepted = False
        mock_response.is_rejected = False
        mock_response.is_processing = True
        self.mock_client.get_upload_status.return_value = mock_response

        result = self.service.check_status(mock_doc)

        self.assertEqual(result.status, "processing")
        self.assertFalse(result.is_terminal)
        mock_doc.mark_processing.assert_called_once()


@override_settings(EFACTURA_ENABLED=True)
class EFacturaDownloadTestCase(TestCase):
    """Test download functionality."""

    def setUp(self):
        self.mock_client = Mock(spec=EFacturaClient)
        self.service = EFacturaService(client=self.mock_client)

    def test_download_no_download_id(self):
        """Test download without download ID."""
        mock_doc = Mock(spec=EFacturaDocument)
        mock_doc.anaf_download_id = ""

        result = self.service.download_response(mock_doc)
        self.assertIsNone(result)

    def test_download_success(self):
        """Test successful download."""
        mock_doc = Mock(spec=EFacturaDocument)
        mock_doc.anaf_download_id = "67890"
        mock_doc.invoice = Mock(number="INV-001")
        mock_doc.signed_pdf = Mock()

        pdf_content = b"%PDF-1.4 test content"
        self.mock_client.download_response.return_value = pdf_content

        result = self.service.download_response(mock_doc)

        self.assertEqual(result, pdf_content)
        mock_doc.signed_pdf.save.assert_called_once()

    def test_download_failure(self):
        """Test download failure."""
        mock_doc = Mock(spec=EFacturaDocument)
        mock_doc.anaf_download_id = "67890"
        mock_doc.id = uuid4()

        self.mock_client.download_response.side_effect = NetworkError("Download failed")

        result = self.service.download_response(mock_doc)
        self.assertIsNone(result)


@override_settings(EFACTURA_ENABLED=True)
class EFacturaRetryTestCase(TestCase):
    """Test retry functionality."""

    def setUp(self):
        self.mock_client = Mock(spec=EFacturaClient)
        self.service = EFacturaService(client=self.mock_client)

    def test_retry_cannot_retry(self):
        """Test retry when document cannot be retried."""
        mock_doc = Mock(spec=EFacturaDocument)
        mock_doc.can_retry = False

        result = self.service.retry_failed_submission(mock_doc)

        self.assertFalse(result.success)
        self.assertIn("cannot be retried", result.error_message.lower())

    @patch.object(EFacturaService, "submit_invoice")
    def test_retry_success(self, mock_submit):
        """Test successful retry."""
        mock_doc = Mock(spec=EFacturaDocument)
        mock_doc.can_retry = True
        mock_doc.invoice = Mock()

        mock_submit.return_value = SubmissionResult.ok(mock_doc)

        result = self.service.retry_failed_submission(mock_doc)

        self.assertTrue(result.success)
        self.assertEqual(mock_doc.status, EFacturaStatus.QUEUED.value)
        mock_doc.save.assert_called_once()


@override_settings(EFACTURA_ENABLED=True)
class EFacturaBatchOperationsTestCase(TestCase):
    """Test batch operations."""

    def setUp(self):
        self.mock_client = Mock(spec=EFacturaClient)
        self.service = EFacturaService(client=self.mock_client)

    @patch("apps.billing.efactura.service.EFacturaDocument.get_pending_submissions")
    @patch.object(EFacturaService, "submit_invoice")
    def test_process_pending_submissions(self, mock_submit, mock_get_pending):
        """Test processing pending submissions."""
        mock_doc1 = Mock(spec=EFacturaDocument)
        mock_doc1.invoice = Mock()
        mock_doc2 = Mock(spec=EFacturaDocument)
        mock_doc2.invoice = Mock()
        mock_get_pending.return_value = [mock_doc1, mock_doc2]

        mock_submit.side_effect = [
            SubmissionResult.ok(mock_doc1),
            SubmissionResult.error("Failed"),
        ]

        results = self.service.process_pending_submissions()

        self.assertEqual(results["submitted"], 1)
        self.assertEqual(results["failed"], 1)

    @patch("apps.billing.efactura.service.EFacturaDocument.get_awaiting_response")
    @patch.object(EFacturaService, "check_status")
    def test_poll_awaiting_documents(self, mock_check, mock_get_awaiting):
        """Test polling awaiting documents."""
        mock_doc1 = Mock(spec=EFacturaDocument)
        mock_doc2 = Mock(spec=EFacturaDocument)
        mock_get_awaiting.return_value = [mock_doc1, mock_doc2]

        mock_check.side_effect = [
            StatusCheckResult(status="accepted", is_terminal=True),
            StatusCheckResult(status="processing", is_terminal=False),
        ]

        results = self.service.poll_awaiting_documents()

        self.assertEqual(results["accepted"], 1)
        self.assertEqual(results["processing"], 1)

    @patch("apps.billing.efactura.service.EFacturaDocument.get_ready_for_retry")
    @patch.object(EFacturaService, "retry_failed_submission")
    def test_process_retries(self, mock_retry, mock_get_ready):
        """Test processing retries."""
        mock_doc = Mock(spec=EFacturaDocument)
        mock_get_ready.return_value = [mock_doc]

        mock_retry.return_value = SubmissionResult.ok(mock_doc)

        results = self.service.process_retries()

        self.assertEqual(results["retried"], 1)
        self.assertEqual(results["failed"], 0)


class EFacturaHelperMethodsTestCase(TestCase):
    """Test helper methods."""

    def setUp(self):
        self.mock_client = Mock(spec=EFacturaClient)
        self.service = EFacturaService(client=self.mock_client)

    @override_settings(EFACTURA_ENABLED=True)
    def test_is_efactura_enabled_true(self):
        """Test e-Factura enabled check."""
        self.assertTrue(self.service._is_efactura_enabled())

    @override_settings(EFACTURA_ENABLED=False)
    def test_is_efactura_enabled_false(self):
        """Test e-Factura disabled check."""
        self.assertFalse(self.service._is_efactura_enabled())

    @override_settings(EFACTURA_B2C_ENABLED=False, EFACTURA_MINIMUM_AMOUNT_CENTS=0)
    def test_requires_efactura_b2b_romanian(self):
        """Test B2B Romanian invoice requires e-Factura."""
        invoice = MockInvoice(
            bill_to_country="RO",
            bill_to_tax_id="RO12345678",
        )
        self.assertTrue(self.service._requires_efactura(invoice))

    def test_requires_efactura_non_romanian(self):
        """Test non-Romanian invoice does not require e-Factura."""
        invoice = MockInvoice(bill_to_country="DE")
        self.assertFalse(self.service._requires_efactura(invoice))

    @override_settings(EFACTURA_B2C_ENABLED=False)
    def test_requires_efactura_b2c_disabled(self):
        """Test B2C invoice when B2C disabled."""
        invoice = MockInvoice(
            bill_to_country="RO",
            bill_to_tax_id=None,  # B2C - no tax ID
        )
        self.assertFalse(self.service._requires_efactura(invoice))

    @override_settings(EFACTURA_B2C_ENABLED=True)
    def test_requires_efactura_b2c_enabled(self):
        """Test B2C invoice when B2C enabled."""
        invoice = MockInvoice(
            bill_to_country="RO",
            bill_to_tax_id=None,  # B2C
        )
        self.assertTrue(self.service._requires_efactura(invoice))

    @override_settings(EFACTURA_MINIMUM_AMOUNT_CENTS=10000)
    def test_requires_efactura_below_minimum(self):
        """Test invoice below minimum amount."""
        invoice = MockInvoice(
            bill_to_country="RO",
            bill_to_tax_id="RO12345678",
            total_cents=5000,  # Below 10000
        )
        self.assertFalse(self.service._requires_efactura(invoice))


class SubmitInvoiceConvenienceFunctionTestCase(TestCase):
    """Test convenience function."""

    @patch("apps.billing.efactura.service.EFacturaService")
    def test_submit_invoice_to_efactura(self, mock_service_class):
        """Test convenience function creates service and submits."""
        mock_service = Mock()
        mock_service_class.return_value = mock_service
        mock_service.submit_invoice.return_value = SubmissionResult.ok(Mock())

        invoice = MockInvoice()
        result = submit_invoice_to_efactura(invoice)

        mock_service.submit_invoice.assert_called_once_with(invoice)
        self.assertTrue(result.success)
