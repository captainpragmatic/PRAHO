"""Public duplicate submissions must not deadlock the worker recording ANAF's result."""

from collections.abc import Callable
from concurrent.futures import Future, ThreadPoolExecutor
from datetime import timedelta
from decimal import Decimal
from tempfile import TemporaryDirectory
from threading import Event
from time import monotonic
from typing import Any
from unittest import skipUnless
from unittest.mock import Mock

from django.core.cache import cache
from django.db import close_old_connections, connection, connections
from django.test import TransactionTestCase, override_settings
from django.utils import timezone

from apps.billing.efactura.client import EFacturaClient, NetworkError, UploadResponse
from apps.billing.efactura.models import EFacturaDocument, EFacturaStatus
from apps.billing.efactura.service import EFacturaService, SubmissionResult
from apps.billing.efactura.validator import CIUSROValidator
from apps.billing.efactura.xml_builder import UBLInvoiceBuilder
from apps.billing.invoice_models import Invoice
from tests.factories import CurrencyFactory, CustomerFactory, InvoiceFactory, InvoiceLineFactory


@skipUnless(connection.vendor == "postgresql", "PostgreSQL row-lock ordering is required")
@override_settings(
    EFACTURA_ENABLED=True,
    EFACTURA_ENVIRONMENT="test",
    COMPANY_NAME="Test Company SRL",
    EFACTURA_COMPANY_CUI="12345678",
    COMPANY_REGISTRATION_NUMBER="J40/1234/2020",
    COMPANY_STREET="Test Street 123",
    COMPANY_CITY="Bucharest",
    COMPANY_POSTAL_CODE="010101",
    COMPANY_COUNTRY_CODE="RO",
    COMPANY_EMAIL="test@example.com",
    COMPANY_BANK_ACCOUNT="RO49AAAA1B31007593840000",
    COMPANY_BANK_NAME="Test Bank",
    CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}},
)
class SubmissionLockOrderConcurrencyTests(TransactionTestCase):
    def setUp(self) -> None:
        cache.clear()
        self.addCleanup(cache.clear)
        media = self.enterContext(TemporaryDirectory())
        self.enterContext(override_settings(MEDIA_ROOT=media))
        self.invoice = InvoiceFactory(
            customer=CustomerFactory(),
            currency=CurrencyFactory(code="RON"),
            number="INV-LOCK-ORDER",
            bill_to_name="Customer SRL",
            bill_to_country="RO",
            bill_to_tax_id="RO87654321",
            bill_to_street="Customer Street 456",
            bill_to_city="Cluj-Napoca",
            bill_to_postal_code="400001",
            issued_at=timezone.now(),
            due_at=timezone.now() + timedelta(days=30),
            subtotal_cents=10000,
            tax_total_cents=2100,
            total_cents=12100,
        )
        InvoiceLineFactory(invoice=self.invoice, unit_price_cents=10000, quantity=1, tax_rate=Decimal("0.2100"))
        xml = UBLInvoiceBuilder(self.invoice).build()
        validation = CIUSROValidator().validate(xml)
        self.assertTrue(validation.is_valid, validation.to_dict())
        self.document, _ = EFacturaDocument.objects.get_or_create(
            invoice=self.invoice, defaults={"environment": "test"}
        )
        self.document.xml_content = xml
        self.document.save()
        # The normal invoice-issued signal has already queued this document.
        self.assertEqual(self.document.status, EFacturaStatus.QUEUED.value)
        self.assertEqual(self.document.environment, "test")
        self.assertTrue(self.document.verify_xml_integrity())
        self.original_hash = self.document.xml_hash
        self.original_xml = xml

    def _worker(self, action: Callable[[], SubmissionResult], ready: Event, pids: list[int]) -> SubmissionResult:
        close_old_connections()
        try:
            with connection.cursor() as cursor:
                cursor.execute("SET lock_timeout = '15s'")
                cursor.execute("SET statement_timeout = '20s'")
                cursor.execute("SELECT pg_backend_pid()")
                pids.append(cursor.fetchone()[0])
            ready.set()
            return action()
        finally:
            connections.close_all()

    def _wait_for_finalizer(self, pid: int, owner_pid: int, pending: Future[SubmissionResult]) -> None:
        deadline, poll = monotonic() + 10, Event()
        while monotonic() < deadline:
            with connection.cursor() as cursor:
                cursor.execute("SELECT pg_stat_clear_snapshot()")
                cursor.execute(
                    "SELECT wait_event_type, pg_blocking_pids(pid), query FROM pg_stat_activity WHERE pid = %s", [pid]
                )
                row = cursor.fetchone()
            if row and owner_pid in row[1]:
                self.assertEqual(row[0], "Lock")
                self.assertTrue(row[2].startswith("SELECT"), row[2])
                return
            if pending.done():
                self.fail(f"Public upload finished before its finalizer waited: {pending.result()}")
            poll.wait(0.01)
        self.fail("Public finalizer did not wait on the duplicate submission's invoice lock")

    def _race(self, outcome: UploadResponse | NetworkError) -> SubmissionResult:
        upload_entered, upload_return, invoice_locked, duplicate_continue = Event(), Event(), Event(), Event()
        first_ready, second_ready, first_pids, second_pids = Event(), Event(), [], []

        def upload(*args: object, **kwargs: object) -> UploadResponse:
            self.assertFalse(connection.in_atomic_block, "ANAF requests must remain outside database transactions")
            upload_entered.set()
            self.assertTrue(upload_return.wait(10), "ANAF result was not released")
            if isinstance(outcome, NetworkError):
                raise outcome
            return outcome

        client = Mock(spec=EFacturaClient)
        client.upload_invoice.side_effect = upload
        service = EFacturaService(client=client)

        def submit() -> SubmissionResult:
            return service.submit_invoice(Invoice.objects.get(pk=self.invoice.pk))

        def pause_invoice_lock(execute: Callable[..., Any], sql: str, params: object, many: bool, context: Any) -> Any:
            result = execute(sql, params, many, context)
            if "FOR UPDATE" in sql and f'FROM "{Invoice._meta.db_table}"' in sql and not invoice_locked.is_set():
                # Pause AFTER the public preparation's own lock. Add no lock or transaction.
                self.assertTrue(connection.in_atomic_block)
                invoice_locked.set()
                self.assertTrue(duplicate_continue.wait(10), "Duplicate preparation was not released")
            return result

        def duplicate() -> SubmissionResult:
            with connection.execute_wrapper(pause_invoice_lock):
                return submit()

        with ThreadPoolExecutor(max_workers=2) as pool:
            first = pool.submit(self._worker, submit, first_ready, first_pids)
            second = None
            try:
                self.assertTrue(first_ready.wait(10))
                self.assertTrue(upload_entered.wait(10), first.result() if first.done() else "Upload not reached")
                second = pool.submit(self._worker, duplicate, second_ready, second_pids)
                self.assertTrue(second_ready.wait(10))
                self.assertTrue(invoice_locked.wait(10))
                upload_return.set()
                self._wait_for_finalizer(first_pids[0], second_pids[0], first)
            finally:
                upload_return.set()
                duplicate_continue.set()
            result = first.result(timeout=25)
            self.assertIsNotNone(second)
            duplicate_result = second.result(timeout=25)
        self.assertTrue(duplicate_result.success, duplicate_result.error_message)
        self.assertEqual(duplicate_result.document_status, EFacturaStatus.UPLOADING.value)
        self.assertFalse(duplicate_result.registered_with_anaf)
        client.upload_invoice.assert_called_once()
        client.upload_b2c.assert_not_called()
        client.upload_credit_note.assert_not_called()
        self.document = EFacturaDocument.objects.get(pk=self.document.pk)
        self.assertIsNone(self.document.submission_claim_token)
        self.assertEqual(self.document.xml_hash, self.original_hash)
        self.assertEqual(self.document.xml_content, self.original_xml)
        self.assertTrue(self.document.verify_xml_integrity())
        self.client, self.service = client, service
        return result

    def test_accepted_upload_is_recorded_while_duplicate_checks_active_claim(self) -> None:
        result = self._race(UploadResponse(success=True, upload_index="IDX-LOCK-ORDER"))
        self.assertTrue(result.success, result.error_message)
        self.assertTrue(result.registered_with_anaf)
        self.assertEqual(self.document.status, EFacturaStatus.SUBMITTED.value)
        self.assertEqual(self.document.anaf_upload_index, "IDX-LOCK-ORDER")
        self.assertEqual(self.document.last_error, "")
        self.assertIsNone(self.document.next_retry_at)
        self.assertEqual(self.document.retry_count, 0)
        self.assertTrue(self.service.submit_invoice(self.invoice).registered_with_anaf)
        self.client.upload_invoice.assert_called_once()

    def test_explicit_refusal_preserves_retry_policy_while_duplicate_checks_active_claim(self) -> None:
        result = self._race(UploadResponse(success=False, message="ANAF refused invoice", errors=["invalid field"]))
        self.assertFalse(result.success)
        self.assertEqual(result.error_message, "ANAF refused invoice")
        self.assertEqual(result.errors, [{"message": "invalid field"}])
        self.assertEqual(self.document.status, EFacturaStatus.ERROR.value)
        self.assertEqual(self.document.last_error, "ANAF refused invoice")
        self.assertEqual(self.document.retry_count, 1)
        self.assertIsNotNone(self.document.next_retry_at)

    def test_quota_deferral_keeps_attempt_count_while_duplicate_checks_active_claim(self) -> None:
        retry_at = timezone.now() + timedelta(minutes=2)
        result = self._race(UploadResponse(success=False, message="ANAF quota reached", quota_retry_at=retry_at))
        self.assertFalse(result.success)
        self.assertEqual(result.error_message, "ANAF quota reached")
        self.assertEqual(self.document.status, EFacturaStatus.QUEUED.value)
        self.assertEqual(self.document.last_error, "ANAF quota reached")
        self.assertEqual(self.document.next_retry_at, retry_at)
        self.assertEqual(self.document.retry_count, 0)

    def test_unknown_upload_is_not_replayed_while_duplicate_checks_active_claim(self) -> None:
        result = self._race(NetworkError("response lost"))
        self.assertFalse(result.success)
        self.assertEqual(result.error_message, "ANAF upload outcome unknown: response lost")
        self.assertEqual(self.document.status, EFacturaStatus.OUTCOME_UNKNOWN.value)
        self.assertEqual(self.document.last_error, "ANAF upload outcome unknown: response lost")
        self.assertEqual(self.document.retry_count, 0)
        self.assertIsNone(self.document.next_retry_at)
        replay = self.service.submit_invoice(self.invoice)
        self.assertFalse(replay.success)
        self.assertEqual(
            replay.error_message, "ANAF upload outcome is unknown; reconcile ANAF messages before any resubmission"
        )
        self.client.upload_invoice.assert_called_once()
