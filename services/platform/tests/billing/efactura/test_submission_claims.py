"""Submission-claim and ambiguous-outcome regressions for e-Factura (#351)."""

from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from unittest.mock import Mock, patch
from uuid import uuid4

from django.db import close_old_connections, connection
from django.test import TestCase, TransactionTestCase, override_settings
from django.utils import timezone

from apps.billing.efactura.client import EFacturaClient, NetworkError, UploadResponse
from apps.billing.efactura.models import EFacturaDocument, EFacturaStatus
from apps.billing.efactura.service import EFacturaService
from apps.billing.efactura.validator import ValidationResult


class _SubmissionClaimFixture:
    def create_invoice(self, number: str):
        from tests.factories import CurrencyFactory, CustomerFactory, InvoiceFactory  # noqa: PLC0415

        currency = CurrencyFactory(code="RON")
        customer = CustomerFactory()
        return InvoiceFactory(
            customer=customer,
            currency=currency,
            number=number,
            bill_to_country="RO",
            bill_to_tax_id="RO12345678",
            status="issued",
        )

    @staticmethod
    def service(client: EFacturaClient) -> EFacturaService:
        service = EFacturaService(client=client)
        service._validator = Mock()
        service._validator.validate.return_value = ValidationResult(is_valid=True)
        return service

    @staticmethod
    def mark_uploading(document: EFacturaDocument, *, expired: bool = False) -> None:
        claimed_at = timezone.now() - timedelta(minutes=20) if expired else timezone.now()
        document.mark_queued()
        document.save()
        document.mark_uploading(
            claim_token=uuid4(),
            claimed_at=claimed_at,
            claim_expires_at=claimed_at + timedelta(minutes=10),
        )
        document.save()


@override_settings(EFACTURA_ENABLED=True, EFACTURA_ENVIRONMENT="test")
class SubmissionClaimLifecycleTests(_SubmissionClaimFixture, TestCase):
    def test_active_upload_claim_is_an_idempotent_noop(self):
        invoice = self.create_invoice("INV-CLAIM-ACTIVE")
        document = EFacturaDocument.objects.create(invoice=invoice, xml_content="<Invoice/>")
        self.mark_uploading(document)
        client = Mock(spec=EFacturaClient)

        result = self.service(client).submit_invoice(invoice)

        self.assertTrue(result.success)
        client.upload_invoice.assert_not_called()
        document.refresh_from_db()
        self.assertEqual(document.status, EFacturaStatus.UPLOADING.value)

    def test_expired_upload_claim_becomes_outcome_unknown_without_repost(self):
        invoice = self.create_invoice("INV-CLAIM-EXPIRED")
        document = EFacturaDocument.objects.create(invoice=invoice, xml_content="<Invoice/>")
        self.mark_uploading(document, expired=True)
        client = Mock(spec=EFacturaClient)

        result = self.service(client).submit_invoice(invoice)

        self.assertFalse(result.success)
        self.assertEqual(
            result.error_message,
            "ANAF upload outcome is unknown; reconcile ANAF messages before any resubmission",
        )
        client.upload_invoice.assert_not_called()
        document.refresh_from_db()
        self.assertEqual(document.status, EFacturaStatus.OUTCOME_UNKNOWN.value)
        self.assertIsNone(document.submission_claim_token)
        self.assertIsNotNone(document.submission_claimed_at)
        self.assertIsNotNone(document.submission_claim_expires_at)
        self.assertFalse(document.can_retry)

    def test_network_failure_after_claim_is_quarantined_and_never_replayed(self):
        invoice = self.create_invoice("INV-CLAIM-NETWORK")
        EFacturaDocument.objects.create(invoice=invoice, xml_content="<Invoice/>")
        client = Mock(spec=EFacturaClient)
        client.upload_invoice.side_effect = NetworkError("response lost")
        service = self.service(client)

        with (
            patch.object(service, "_generate_xml", return_value="<Invoice/>"),
            patch.object(service, "_is_b2c", return_value=False),
            patch.object(service, "_log_audit_event"),
        ):
            first = service.submit_invoice(invoice)
            second = service.submit_invoice(invoice)

        self.assertFalse(first.success)
        self.assertFalse(second.success)
        self.assertEqual(client.upload_invoice.call_count, 1)
        document = EFacturaDocument.objects.get(invoice=invoice)
        self.assertEqual(document.status, EFacturaStatus.OUTCOME_UNKNOWN.value)
        self.assertIsNone(document.next_retry_at)
        self.assertIsNone(document.submission_claim_token)
        self.assertIsNotNone(document.submission_claimed_at)
        self.assertIsNotNone(document.submission_claim_expires_at)
        self.assertFalse(document.can_retry)

    def test_safe_retry_reuses_frozen_xml_byte_for_byte(self):
        invoice = self.create_invoice("INV-CLAIM-RETRY")
        frozen_xml = "<Invoice>frozen fiscal bytes</Invoice>"
        document = EFacturaDocument.objects.create(invoice=invoice, xml_content=frozen_xml)
        self.mark_uploading(document)
        document.mark_error("ANAF explicitly refused before accepting the upload")
        document.save()
        client = Mock(spec=EFacturaClient)
        client.upload_invoice.return_value = UploadResponse(success=True, upload_index="IDX-FROZEN")
        service = self.service(client)

        with (
            patch.object(service, "_generate_xml", side_effect=AssertionError("must reuse frozen XML")),
            patch.object(service, "_is_b2c", return_value=False),
            patch.object(service, "_log_audit_event"),
        ):
            result = service.submit_invoice(invoice)

        self.assertTrue(result.success, result.error_message)
        client.upload_invoice.assert_called_once_with(frozen_xml)
        document.refresh_from_db()
        self.assertEqual(document.xml_content, frozen_xml)
        self.assertTrue(document.verify_xml_integrity())
        self.assertEqual(document.anaf_upload_index, "IDX-FROZEN")


@override_settings(EFACTURA_ENABLED=True, EFACTURA_ENVIRONMENT="test")
class SubmissionClaimPostgresConcurrencyTests(_SubmissionClaimFixture, TransactionTestCase):
    reset_sequences = True

    def setUp(self) -> None:
        if connection.vendor != "postgresql":
            self.skipTest("PostgreSQL row-lock behavior required")
        self.invoice = self.create_invoice("INV-CLAIM-CONCURRENT")
        EFacturaDocument.objects.create(invoice=self.invoice, xml_content="<Invoice/>")

    def test_concurrent_second_caller_never_reaches_anaf(self):
        remote_started = threading.Event()
        release_remote = threading.Event()
        client = Mock(spec=EFacturaClient)

        def upload(_xml: str) -> UploadResponse:
            remote_started.set()
            if not release_remote.wait(timeout=10):
                raise AssertionError("Timed out releasing ANAF upload")
            return UploadResponse(success=True, upload_index="IDX-CONCURRENT")

        client.upload_invoice.side_effect = upload

        def submit():
            close_old_connections()
            try:
                service = self.service(client)
                with patch.object(service, "_is_b2c", return_value=False), patch.object(
                    service, "_log_audit_event"
                ):
                    return service.submit_invoice(type(self.invoice).objects.get(pk=self.invoice.pk))
            finally:
                connection.close()

        with ThreadPoolExecutor(max_workers=2) as executor:
            first = executor.submit(submit)
            self.assertTrue(remote_started.wait(timeout=5), "First caller never reached ANAF")
            second = executor.submit(submit)
            second_result = second.result(timeout=5)
            self.assertTrue(second_result.success)
            self.assertEqual(client.upload_invoice.call_count, 1)
            release_remote.set()
            first_result = first.result(timeout=10)

        self.assertTrue(first_result.success)
        document = EFacturaDocument.objects.get(invoice=self.invoice)
        self.assertEqual(document.status, EFacturaStatus.SUBMITTED.value)
        self.assertEqual(document.anaf_upload_index, "IDX-CONCURRENT")
