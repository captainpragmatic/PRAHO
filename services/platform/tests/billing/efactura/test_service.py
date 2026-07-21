"""
Tests for e-Factura service.
"""

from unittest.mock import Mock, patch
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
    SubmissionClaim,
    SubmissionResult,
    submit_invoice_to_efactura,
)
from apps.billing.efactura.validator import ValidationResult
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
)
class EFacturaServiceTestCase(TestCase):
    """Test EFacturaService."""

    def setUp(self):
        self.mock_client = Mock(spec=EFacturaClient)
        self.service = EFacturaService(client=self.mock_client)
        self.service._validator = Mock()
        self.service._validator.validate.return_value = ValidationResult(is_valid=True)
        self.invoice = MockInvoice()

    @staticmethod
    def _claim() -> SubmissionClaim:
        return SubmissionClaim(
            document_id=uuid4(),
            token=uuid4(),
            xml_content="<Invoice/>",
            xml_hash="frozen-hash",
            is_b2c=False,
            is_credit_note=False,
        )

    def test_init_with_default_client(self):
        """Test service creates default client if none provided."""
        with patch("apps.billing.efactura.service.EFacturaClient") as mock_client_class:
            EFacturaService()
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

    def test_submit_success(self):
        """Test successful submission."""
        mock_doc = Mock(spec=EFacturaDocument)
        claim = self._claim()
        self.mock_client.upload_invoice.return_value = UploadResponse(
            success=True,
            upload_index="12345",
        )

        with (
            patch.object(self.service, "_prepare_and_claim_submission", return_value=claim),
            patch.object(self.service, "_finalize_success", return_value=SubmissionResult.ok(mock_doc)) as finalize,
        ):
            result = self.service.submit_invoice(self.invoice)

        self.assertTrue(result.success)
        self.assertEqual(result.document, mock_doc)
        self.mock_client.upload_invoice.assert_called_once_with("<Invoice/>")
        finalize.assert_called_once_with(claim, "12345")

    def test_submit_validation_failure(self):
        """Test submission with validation failure."""
        validation_result = ValidationResult(is_valid=False)
        validation_result.add_error("BR-01", "Missing ID")
        preparation_result = SubmissionResult.error(
            "XML validation failed: 1 errors",
            [error.to_dict() for error in validation_result.errors],
        )

        with patch.object(self.service, "_prepare_and_claim_submission", return_value=preparation_result):
            result = self.service.submit_invoice(self.invoice)

        self.assertFalse(result.success)
        self.assertIn("validation failed", result.error_message.lower())
        self.mock_client.upload_invoice.assert_not_called()

    def test_submit_upload_failure(self):
        """Test submission with upload failure."""
        claim = self._claim()
        self.mock_client.upload_invoice.return_value = UploadResponse(
            success=False,
            message="Invalid XML",
            errors=["Schema validation error"],
        )

        with (
            patch.object(self.service, "_prepare_and_claim_submission", return_value=claim),
            patch.object(
                self.service,
                "_finalize_safe_failure",
                return_value=SubmissionResult.error("Invalid XML", [{"message": "Schema validation error"}]),
            ) as finalize,
        ):
            result = self.service.submit_invoice(self.invoice)

        self.assertFalse(result.success)
        finalize.assert_called_once_with(
            claim,
            "Invalid XML",
            errors=[{"message": "Schema validation error"}],
        )

    def test_submit_already_accepted(self):
        """Test submission when already accepted."""
        mock_doc = Mock(spec=EFacturaDocument)
        mock_doc.status = EFacturaStatus.ACCEPTED.value

        with patch.object(
            self.service,
            "_prepare_and_claim_submission",
            return_value=SubmissionResult.ok(mock_doc),
        ):
            result = self.service.submit_invoice(self.invoice)

        self.assertTrue(result.success)
        self.assertEqual(result.document, mock_doc)
        # Should not attempt re-submission
        self.mock_client.upload_invoice.assert_not_called()

    def test_submit_authentication_error(self):
        """Test submission with authentication error."""
        claim = self._claim()
        self.mock_client.upload_invoice.side_effect = AuthenticationError("Token expired")

        with (
            patch.object(self.service, "_prepare_and_claim_submission", return_value=claim),
            patch.object(
                self.service,
                "_finalize_safe_failure",
                return_value=SubmissionResult.error("Authentication failed: Token expired"),
            ) as finalize,
        ):
            result = self.service.submit_invoice(self.invoice)

        self.assertFalse(result.success)
        self.assertIn("Authentication", result.error_message)
        finalize.assert_called_once_with(claim, "Authentication failed: Token expired")

    def test_submit_network_error(self):
        """Test submission with network error."""
        claim = self._claim()
        self.mock_client.upload_invoice.side_effect = NetworkError("Connection refused")

        with (
            patch.object(self.service, "_prepare_and_claim_submission", return_value=claim),
            patch.object(
                self.service,
                "_finalize_unknown_outcome",
                return_value=SubmissionResult.error("ANAF upload outcome unknown: Connection refused"),
            ) as finalize,
        ):
            result = self.service.submit_invoice(self.invoice)

        self.assertFalse(result.success)
        self.assertIn("outcome unknown", result.error_message)
        finalize.assert_called_once_with(claim, "ANAF upload outcome unknown: Connection refused")


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

    @patch("apps.billing.efactura.service.transaction.atomic")
    def test_check_status_accepted_uses_transaction_atomic(self, mock_atomic):
        """Accepted status branch must be atomic with invoice update."""
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

        with patch.object(self.service, "_log_audit_event"), patch.object(self.service, "_record_webhook_event"):
            self.service.check_status(mock_doc)

        mock_atomic.assert_called_once()

    @patch("apps.billing.efactura.service.transaction.atomic")
    def test_check_status_rejected_uses_transaction_atomic(self, mock_atomic):
        """Rejected status branch must be atomic for status persistence consistency."""
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

        with patch.object(self.service, "_log_audit_event"), patch.object(self.service, "_record_webhook_event"):
            self.service.check_status(mock_doc)

        mock_atomic.assert_called_once()


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
        mock_submit.assert_called_once_with(mock_doc.invoice)
        mock_doc.mark_queued.assert_not_called()
        mock_doc.save.assert_not_called()

    @patch("apps.billing.efactura.service.transaction.atomic")
    @patch.object(EFacturaService, "submit_invoice")
    def test_retry_failed_submission_does_not_wrap_remote_io_in_outer_atomic(self, mock_submit, mock_atomic):
        """The short claim transaction lives inside submit_invoice; retry adds no outer lock."""
        mock_doc = Mock(spec=EFacturaDocument)
        mock_doc.can_retry = True
        mock_doc.invoice = Mock()
        mock_submit.return_value = SubmissionResult.ok(mock_doc)

        self.service.retry_failed_submission(mock_doc)

        mock_atomic.assert_not_called()


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
        mock_doc1.status = EFacturaStatus.SUBMITTED.value
        mock_doc2 = Mock(spec=EFacturaDocument)
        mock_doc2.invoice = Mock()
        mock_doc3 = Mock(spec=EFacturaDocument)
        mock_doc3.invoice = Mock()
        mock_doc3.status = EFacturaStatus.UPLOADING.value
        mock_get_pending.return_value = [mock_doc1, mock_doc2, mock_doc3]

        mock_submit.side_effect = [
            SubmissionResult.ok(mock_doc1),
            SubmissionResult.error("Failed"),
            SubmissionResult.ok(mock_doc3),
        ]

        results = self.service.process_pending_submissions()

        self.assertEqual(results["submitted"], 1)
        self.assertEqual(results["failed"], 1)
        self.assertEqual(results["skipped"], 1)

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

    def test_requires_efactura_normalizes_lowercase_romanian_country_code(self):
        invoice = MockInvoice(bill_to_country="ro")

        self.assertTrue(self.service._requires_efactura(invoice))

    @override_settings(EFACTURA_B2C_ENABLED=False)
    def test_legacy_b2c_disable_flag_cannot_override_mandatory_submission(self):
        invoice = MockInvoice(
            bill_to_country="RO",
            bill_to_tax_id=None,  # B2C - no tax ID
        )
        self.assertTrue(self.service._requires_efactura(invoice))

    @override_settings(EFACTURA_B2C_ENABLED=True)
    def test_requires_efactura_b2c_enabled(self):
        """Test B2C invoice when B2C enabled."""
        invoice = MockInvoice(
            bill_to_country="RO",
            bill_to_tax_id=None,  # B2C
        )
        self.assertTrue(self.service._requires_efactura(invoice))

    @override_settings(EFACTURA_MINIMUM_AMOUNT_CENTS=10000)
    def test_legacy_minimum_cannot_exempt_a_small_romanian_invoice(self):
        invoice = MockInvoice(
            bill_to_country="RO",
            bill_to_tax_id="RO12345678",
            total_cents=5000,  # Below 10000
        )
        self.assertTrue(self.service._requires_efactura(invoice))

    @patch("apps.billing.efactura.b2c.B2CDetector.is_b2c_required", side_effect=TypeError("invalid snapshot"))
    def test_b2c_detection_failure_does_not_silently_route_to_b2b(self, _detector):
        invoice = MockInvoice(bill_to_country="RO", bill_to_tax_id=None)

        with self.assertRaises(TypeError):
            self.service._is_b2c(invoice)

    @patch("apps.billing.invoice_models.Invoice.objects.filter")
    def test_deadline_monitor_covers_paid_invoices_and_recovers_a_missing_document(self, invoice_filter):
        paid_invoice = MockInvoice(status="paid")
        queryset = Mock()
        queryset.exclude.return_value = [paid_invoice]
        invoice_filter.return_value = queryset
        recovered_document = Mock(spec=EFacturaDocument)
        recovered_document.submission_deadline = timezone.now() + timezone.timedelta(hours=36)

        with (
            patch.object(self.service, "_get_existing_document", return_value=None),
            patch.object(
                self.service,
                "_get_or_create_document",
                return_value=recovered_document,
            ) as get_or_create,
        ):
            approaching = self.service.check_approaching_deadlines(hours=48)

        self.assertEqual(approaching, [recovered_document])
        get_or_create.assert_called_once_with(paid_invoice)
        statuses = set(invoice_filter.call_args.kwargs["status__in"])
        self.assertEqual(
            statuses,
            {"issued", "paid", "overdue", "void", "refunded", "partially_refunded"},
        )
        self.assertEqual(invoice_filter.call_args.kwargs["bill_to_country__iexact"], "RO")


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


@override_settings(
    EFACTURA_ENABLED=True,
    EFACTURA_ENVIRONMENT="test",
)
class SubmissionLifecycleTests(TestCase):
    """DB-backed FSM trajectory tests for the e-Factura submission lifecycle (Phase 0, #123).

    These use a REAL Invoice + EFacturaDocument (not Mock(spec=...)), so the django-fsm
    `source` constraints are actually enforced. The prior mock-based tests (e.g.
    test_submit_success) mocked `mark_submitted`, which hid two TransitionNotAllowed bugs that
    corrupt local state AFTER a successful ANAF upload — the double-send / lost-index risk.
    """

    @classmethod
    def setUpTestData(cls):
        from tests.factories import CurrencyFactory, CustomerFactory  # noqa: PLC0415

        cls.currency = CurrencyFactory(code="RON")
        cls.customer = CustomerFactory()

    def _ro_invoice(self, number: str, *, bill_to_tax_id: str = "RO12345678"):
        from tests.factories import InvoiceFactory  # noqa: PLC0415

        return InvoiceFactory(
            customer=self.customer,
            currency=self.currency,
            number=number,
            bill_to_country="RO",
            bill_to_tax_id=bill_to_tax_id,
            status="issued",
        )

    def _submitted_doc(self, invoice, upload_index: str) -> EFacturaDocument:
        """Build an EFacturaDocument in SUBMITTED state via the real FSM transitions."""
        doc = EFacturaDocument.objects.create(invoice=invoice, document_type=EFacturaDocumentType.INVOICE.value)
        doc.mark_queued()
        doc.save()
        claimed_at = timezone.now()
        doc.mark_uploading(
            claim_token=uuid4(),
            claimed_at=claimed_at,
            claim_expires_at=claimed_at + timezone.timedelta(minutes=10),
        )
        doc.save()
        doc.mark_submitted(upload_index)
        doc.save()
        return doc

    @staticmethod
    def _service(client: EFacturaClient) -> EFacturaService:
        """Build a service whose validator accepts the deliberately minimal lifecycle XML."""
        service = EFacturaService(client=client)
        service._validator = Mock()
        service._validator.validate.return_value = ValidationResult(is_valid=True)
        return service

    def test_xml_builder_failure_persists_a_non_retrying_local_error(self):
        """A deterministic pre-POST failure remains visible instead of rolling back the document."""
        invoice = self._ro_invoice("INV-LC-BUILDER-ERROR")
        client = Mock(spec=EFacturaClient)
        service = self._service(client)

        with (
            patch.object(service, "_generate_xml", side_effect=XMLBuilderError("invalid fiscal snapshot")),
            patch.object(service, "_log_audit_event"),
        ):
            result = service.submit_invoice(invoice)

        self.assertFalse(result.success)
        self.assertIn("invalid fiscal snapshot", result.error_message)
        client.upload_invoice.assert_not_called()
        document = EFacturaDocument.objects.get(invoice=invoice)
        self.assertEqual(document.status, EFacturaStatus.ERROR.value)
        self.assertEqual(document.last_error, "invalid fiscal snapshot")
        self.assertIsNone(document.next_retry_at)

    def test_submit_drives_new_doc_to_submitted_and_persists_index(self):
        """A fresh (draft) document must reach SUBMITTED with the upload_index persisted.

        RED on master: submit creates a `draft` doc, uploads, then mark_submitted() (source
        QUEUED) raises TransitionNotAllowed -> caught by the generic except -> first submission
        has existing=None -> nothing persisted -> ANAF has it, we lost the index.
        """
        invoice = self._ro_invoice("INV-LC-1")
        client = Mock(spec=EFacturaClient)
        client.upload_invoice.return_value = UploadResponse(success=True, upload_index="IDX-1")
        service = self._service(client)

        with (
            patch.object(service, "_generate_xml", return_value="<Invoice/>"),
            patch.object(service, "_log_audit_event"),
        ):
            result = service.submit_invoice(invoice)

        self.assertTrue(result.success, msg=f"submit failed: {result.error_message}")
        doc = EFacturaDocument.objects.get(invoice=invoice)
        self.assertEqual(doc.status, EFacturaStatus.SUBMITTED.value)
        self.assertEqual(doc.anaf_upload_index, "IDX-1")

    def test_first_status_poll_can_accept_a_submitted_doc(self):
        """ANAF can return 'ok' on the FIRST poll while the doc is still SUBMITTED.

        RED on master: mark_accepted source is only PROCESSING, so check_status raises
        TransitionNotAllowed (uncaught) on a SUBMITTED doc.
        """
        from tests.factories import InvoiceFactory  # noqa: PLC0415

        invoice = InvoiceFactory(
            customer=self.customer,
            currency=self.currency,
            number="INV-LC-2",
            bill_to_country="RO",
            bill_to_tax_id="RO12345678",
            status="issued",
        )
        doc = self._submitted_doc(invoice, "IDX-2")
        client = Mock(spec=EFacturaClient)
        client.get_upload_status.return_value = StatusResponse(status="ok", download_id="DL-2")
        service = self._service(client)

        with patch.object(service, "_log_audit_event"), patch.object(service, "_record_webhook_event"):
            result = service.check_status(doc)

        self.assertEqual(result.status, "accepted")
        doc.refresh_from_db()
        self.assertEqual(doc.status, EFacturaStatus.ACCEPTED.value)
        self.assertEqual(doc.anaf_download_id, "DL-2")

    def test_first_status_poll_can_reject_a_submitted_doc(self):
        """ANAF can return 'nok' on the FIRST poll while the doc is still SUBMITTED."""
        invoice = self._ro_invoice("INV-LC-3")
        doc = self._submitted_doc(invoice, "IDX-3")
        client = Mock(spec=EFacturaClient)
        client.get_upload_status.return_value = StatusResponse(status="nok", download_id="")
        service = self._service(client)

        with patch.object(service, "_log_audit_event"), patch.object(service, "_record_webhook_event"):
            result = service.check_status(doc)

        self.assertEqual(result.status, "rejected")
        doc.refresh_from_db()
        self.assertEqual(doc.status, EFacturaStatus.REJECTED.value)

    def test_resubmitting_an_in_flight_doc_does_not_re_upload(self):
        """A second submit() on an already-SUBMITTED doc must be an idempotent no-op.

        RED on master: only ACCEPTED short-circuits, so a SUBMITTED doc re-generates XML and
        calls upload_invoice() again = duplicate fiscal submission.
        """
        invoice = self._ro_invoice("INV-LC-4")
        self._submitted_doc(invoice, "IDX-4")
        client = Mock(spec=EFacturaClient)
        service = self._service(client)

        with (
            patch.object(service, "_generate_xml", return_value="<Invoice/>"),
            patch.object(service, "_log_audit_event"),
        ):
            result = service.submit_invoice(invoice)

        self.assertTrue(result.success)
        client.upload_invoice.assert_not_called()
        doc = EFacturaDocument.objects.get(invoice=invoice)
        self.assertEqual(doc.status, EFacturaStatus.SUBMITTED.value)
        self.assertEqual(doc.anaf_upload_index, "IDX-4")

    def test_b2c_invoice_is_submitted_to_consumer_endpoint(self):
        """Romanian consumer invoices use /uploadb2c and never fall through to the B2B endpoint."""
        invoice = self._ro_invoice("INV-B2C-1", bill_to_tax_id="")
        client = Mock(spec=EFacturaClient)
        client.upload_b2c.return_value = UploadResponse(success=True, upload_index="B2C-1")
        service = self._service(client)

        with (
            patch.object(service, "_generate_xml", return_value="<Invoice/>"),
            patch.object(service, "_log_audit_event"),
        ):
            result = service.submit_invoice(invoice)

        self.assertTrue(result.success, msg=result.error_message)
        client.upload_b2c.assert_called_once_with("<Invoice/>")
        client.upload_invoice.assert_not_called()
        document = EFacturaDocument.objects.get(invoice=invoice)
        self.assertEqual(document.anaf_upload_index, "B2C-1")

    def test_b2b_credit_note_is_submitted_with_credit_note_standard(self):
        invoice = self._ro_invoice("CN-B2B-1")
        EFacturaDocument.objects.create(
            invoice=invoice,
            document_type=EFacturaDocumentType.CREDIT_NOTE.value,
        )
        client = Mock(spec=EFacturaClient)
        client.upload_credit_note.return_value = UploadResponse(success=True, upload_index="CN-B2B-1")
        service = self._service(client)

        with (
            patch.object(service, "_generate_xml", return_value="<CreditNote/>"),
            patch.object(service, "_log_audit_event"),
        ):
            result = service.submit_invoice(invoice)

        self.assertTrue(result.success, msg=result.error_message)
        client.upload_credit_note.assert_called_once_with("<CreditNote/>")
        client.upload_invoice.assert_not_called()
        client.upload_b2c.assert_not_called()

    def test_b2c_credit_note_is_submitted_to_consumer_endpoint_with_credit_note_standard(self):
        invoice = self._ro_invoice("CN-B2C-1", bill_to_tax_id="")
        EFacturaDocument.objects.create(
            invoice=invoice,
            document_type=EFacturaDocumentType.CREDIT_NOTE.value,
        )
        client = Mock(spec=EFacturaClient)
        client.upload_b2c.return_value = UploadResponse(success=True, upload_index="CN-B2C-1")
        service = self._service(client)

        with (
            patch.object(service, "_generate_xml", return_value="<CreditNote/>"),
            patch.object(service, "_log_audit_event"),
        ):
            result = service.submit_invoice(invoice)

        self.assertTrue(result.success, msg=result.error_message)
        client.upload_b2c.assert_called_once_with("<CreditNote/>", standard="CN")
        client.upload_invoice.assert_not_called()
        client.upload_credit_note.assert_not_called()

    def test_fresh_ambiguous_failure_is_quarantined_not_retried(self):
        """A lost upload response is not proof that ANAF refused the document.

        The claim must be quarantined for reconciliation instead of entering the
        automatic retry queue, where it could create a duplicate fiscal upload.
        """
        invoice = self._ro_invoice("INV-FAIL-1")
        client = Mock(spec=EFacturaClient)
        client.upload_invoice.side_effect = NetworkError("boom")
        service = self._service(client)

        with (
            patch.object(service, "_generate_xml", return_value="<Invoice/>"),
            patch.object(service, "_log_audit_event"),
            patch.object(service, "_is_b2c", return_value=False),
        ):
            result = service.submit_invoice(invoice)

        self.assertFalse(result.success)
        doc = EFacturaDocument.objects.get(invoice=invoice)
        self.assertEqual(doc.status, EFacturaStatus.OUTCOME_UNKNOWN.value)
        self.assertEqual(doc.retry_count, 0)
        self.assertIsNone(doc.next_retry_at)
        self.assertFalse(doc.can_retry)

    def test_rejected_document_is_not_resubmitted(self):
        """#202 review (copilot): submit_invoice on an ANAF-rejected doc must NOT re-POST (duplicate
        submission) — it returns a clear error directing a corrected resubmission."""
        invoice = self._ro_invoice("INV-REJ-1")
        doc = EFacturaDocument.objects.create(invoice=invoice, document_type=EFacturaDocumentType.INVOICE.value)
        doc.mark_queued()
        doc.save()
        claimed_at = timezone.now()
        doc.mark_uploading(
            claim_token=uuid4(),
            claimed_at=claimed_at,
            claim_expires_at=claimed_at + timezone.timedelta(minutes=10),
        )
        doc.save()
        doc.mark_submitted("IDX-R")
        doc.save()
        doc.mark_rejected([{"message": "bad"}])
        doc.save()
        client = Mock(spec=EFacturaClient)
        service = self._service(client)

        with (
            patch.object(service, "_generate_xml", return_value="<Invoice/>"),
            patch.object(service, "_log_audit_event"),
        ):
            result = service.submit_invoice(invoice)

        self.assertFalse(result.success)
        client.upload_invoice.assert_not_called()
        client.upload_b2c.assert_not_called()

    def test_submit_routes_b2b_invoice_to_upload(self):
        """A B2B invoice (the default) goes to upload_invoice(), not upload_b2c()."""
        invoice = self._ro_invoice("INV-B2B-1")
        client = Mock(spec=EFacturaClient)
        client.upload_invoice.return_value = UploadResponse(success=True, upload_index="B2B-1")
        service = self._service(client)

        with (
            patch.object(service, "_generate_xml", return_value="<Invoice/>"),
            patch.object(service, "_log_audit_event"),
            patch.object(service, "_is_b2c", return_value=False),
        ):
            result = service.submit_invoice(invoice)

        self.assertTrue(result.success, msg=result.error_message)
        client.upload_invoice.assert_called_once()
        client.upload_b2c.assert_not_called()
