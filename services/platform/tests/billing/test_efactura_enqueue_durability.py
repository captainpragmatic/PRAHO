"""Durable issuance intent, sweep recovery, and explicit e-Factura registration."""

from __future__ import annotations

from datetime import datetime, timedelta
from decimal import Decimal
from io import StringIO
from unittest.mock import Mock, patch
from uuid import uuid4

from django.core.cache import cache
from django.core.management import call_command
from django.core.management.base import CommandError
from django.db import DatabaseError, IntegrityError, transaction
from django.test import TestCase, override_settings
from django.utils import timezone
from django_q.models import Schedule

from apps.audit.models import AuditAlert
from apps.billing.efactura.client import EFacturaClient, UploadResponse
from apps.billing.efactura.models import EFacturaDocument, EFacturaDocumentType, EFacturaStatus
from apps.billing.efactura.service import EFacturaService, is_efactura_enabled
from apps.billing.efactura.tasks import schedule_efactura_tasks
from apps.billing.fiscal_correction_models import EFACTURA_SUBMITTED, FiscalCorrection
from apps.billing.fiscal_correction_worker import _advance_efactura
from apps.billing.invoice_models import (
    DOCUMENT_KIND_CREDIT_NOTE,
    ISSUER_BUILTIN,
    ISSUER_SMARTBILL,
    Currency,
    Invoice,
    InvoiceLine,
    InvoiceSequence,
)
from apps.billing.numbering_service import InvoiceNumberingService
from apps.settings.models import SystemSetting
from tests.billing._fiscal_correction_helpers import correction_of
from tests.billing._storno_helpers import SELLER, v2_evidence
from tests.factories.billing_factories import CustomerFactory
from tests.helpers.task_queue import quiet_task_queue


@SELLER
@override_settings(STORAGES={"default": {"BACKEND": "django.core.files.storage.InMemoryStorage"}})
class EFacturaEnqueueDurabilityTests(TestCase):
    def setUp(self) -> None:
        cache.clear()
        self.addCleanup(cache.clear)
        self.customer = CustomerFactory()
        self.currency, _ = Currency.objects.get_or_create(code="RON", defaults={"symbol": "lei"})
        self.sequence, _ = InvoiceSequence.objects.get_or_create(scope="default", defaults={"prefix": "DUR"})
        self._enabled(True)
        quiet_task_queue(self)
        delivery = patch("apps.notifications.services.EmailService.send_template_email", return_value="test-job")
        delivery.start()
        self.addCleanup(delivery.stop)

    def _enabled(self, value: bool) -> None:
        SystemSetting.objects.update_or_create(
            key="efactura.enabled",
            defaults={"name": "e-Factura", "data_type": "boolean", "value": value, "default_value": False},
        )

    def _fields(self, number: str | None) -> dict[str, object]:
        return {
            "customer": self.customer,
            "currency": self.currency,
            "number": number,
            "issuer_provider": ISSUER_BUILTIN,
            "subtotal_cents": 10000,
            "tax_cents": 2100,
            "total_cents": 12100,
            "bill_to_name": "Customer SRL",
            "bill_to_tax_id": "RO87654321",
            "bill_to_address1": "Customer Street 456",
            "bill_to_city": "Cluj-Napoca",
            "bill_to_postal": "400001",
            "bill_to_country": "RO",
            "vat_evidence": v2_evidence(subtotal=10000, tax=2100, total=12100),
        }

    def _draft(self, **changes: object) -> Invoice:
        fields = self._fields(None) | changes
        invoice = Invoice.objects.create(**fields, status="draft")
        negative = invoice.document_kind == DOCUMENT_KIND_CREDIT_NOTE
        InvoiceLine.objects.create(
            invoice=invoice,
            kind="service",
            description="Hosting",
            quantity=Decimal("1"),
            unit_price_cents=-10000 if negative else 10000,
            tax_rate=Decimal("0.21"),
            tax_cents=-2100 if negative else 2100,
            line_total_cents=-12100 if negative else 12100,
        )
        return invoice

    def _legacy(self, *, status: str = "issued", issued_at: datetime | None = None, **changes: object) -> Invoice:
        # Historical fixtures deliberately bypass issuance signals. Assertions exercise repairs,
        # never the bulk insertion itself.
        fields = self._fields(f"LEG-{uuid4().hex}") | changes
        if fields.get("document_kind") == DOCUMENT_KIND_CREDIT_NOTE:
            fields |= {"subtotal_cents": -10000, "tax_cents": -2100, "total_cents": -12100}
            if "reverses_invoice" not in fields:
                fields["reverses_invoice"] = self._legacy(issued_at=issued_at)
        return Invoice.objects.bulk_create([Invoice(**fields, status=status, issued_at=issued_at)])[0]

    def _create_issued(self) -> Invoice:
        return Invoice.objects.create(
            **self._fields(InvoiceNumberingService.get_next_number()),
            status="issued",
            issued_at=timezone.now(),
        )

    def test_both_paths_persist_queued_intent_before_commit(self) -> None:
        SystemSetting.objects.update_or_create(
            key="efactura.environment",
            defaults={"name": "Environment", "data_type": "string", "value": "production", "default_value": "test"},
        )
        for created in (False, True):
            with self.subTest(created_already_issued=created):
                with self.captureOnCommitCallbacks(execute=False) as callbacks, transaction.atomic():
                    if created:
                        invoice = self._create_issued()
                    else:
                        invoice = self._draft()
                        invoice.issue()
                        invoice.save()
                    self.assertEqual(
                        list(EFacturaDocument.objects.filter(invoice=invoice).values_list("status", flat=True)),
                        [EFacturaStatus.QUEUED.value],
                    )
                    document = EFacturaDocument.objects.get(invoice=invoice)
                    self.assertEqual(document.document_type, EFacturaDocumentType.INVOICE.value)
                    self.assertEqual(document.environment, "production")
                    self.assertIsNone(document.submission_claim_token)
                self.assertTrue(callbacks)

    def _assert_intent_failure_rolls_back(self, error_type: type[Exception], *, database_error: bool) -> None:
        for created in (False, True):
            with self.subTest(created_already_issued=created):
                draft = None if created else self._draft()
                before_ids = set(Invoice.objects.values_list("pk", flat=True))
                before_documents = EFacturaDocument.objects.count()
                self.sequence.refresh_from_db()
                before_number = self.sequence.last_value

                def fail_intent(*, invoice: Invoice, defaults: dict[str, str]) -> None:
                    if database_error:
                        # A real intent INSERT violates efactura_valid_status on both backends.
                        EFacturaDocument.objects.create(invoice=invoice, **(defaults | {"status": "invalid"}))
                        self.fail("The invalid intent INSERT must violate efactura_valid_status")
                    raise RuntimeError("intent store unavailable")

                with (
                    patch.object(EFacturaDocument.objects, "get_or_create", side_effect=fail_intent),
                    self.captureOnCommitCallbacks(execute=False) as callbacks,
                    self.assertRaises(error_type),
                    transaction.atomic(),
                ):
                    if created:
                        self._create_issued()
                    else:
                        assert draft is not None
                        draft.issue()
                        draft.save()
                self.assertEqual(set(Invoice.objects.values_list("pk", flat=True)), before_ids)
                self.assertEqual(EFacturaDocument.objects.count(), before_documents)
                self.sequence.refresh_from_db()
                self.assertEqual(self.sequence.last_value, before_number)
                self.assertEqual(callbacks, [])
                if draft is not None:
                    persisted = Invoice.objects.get(pk=draft.pk)
                    self.assertEqual(persisted.status, "draft")
                    self.assertIsNone(persisted.number)
                    self.assertIsNone(persisted.issued_at)
                    self.assertIsNone(persisted.locked_at)

    def test_application_error_in_intent_rolls_back_both_issuance_paths(self) -> None:
        self._assert_intent_failure_rolls_back(RuntimeError, database_error=False)

    def test_real_database_error_in_intent_rolls_back_both_issuance_paths(self) -> None:
        self._assert_intent_failure_rolls_back(IntegrityError, database_error=True)

    @override_settings(COMPANY_BANK_ACCOUNT="RO49AAAA1B31007593840000", COMPANY_BANK_NAME="Test bank")
    def test_enqueue_failure_leaves_work_that_the_sweeper_submits_once(self) -> None:
        invoice = self._draft()
        with (
            patch("apps.billing.efactura.tasks.async_task", side_effect=RuntimeError("queue unavailable")),
            self.captureOnCommitCallbacks(execute=True),
            transaction.atomic(),
        ):
            invoice.issue()
            invoice.save()
            self.assertEqual(
                list(EFacturaDocument.objects.filter(invoice=invoice).values_list("status", flat=True)),
                [EFacturaStatus.QUEUED.value],
            )
        document = EFacturaDocument.objects.get(invoice=invoice)
        self.assertEqual(document.status, EFacturaStatus.QUEUED.value)
        client = Mock(spec=EFacturaClient)
        client.upload_invoice.return_value = UploadResponse(success=True, upload_index="DUR-ONCE")
        service = EFacturaService(client=client)
        self.assertEqual(service.process_pending_submissions(), {"submitted": 1, "failed": 0, "skipped": 0})
        self.assertEqual(service.process_pending_submissions(), {"submitted": 0, "failed": 0, "skipped": 0})
        document.refresh_from_db()
        self.assertEqual(document.status, EFacturaStatus.SUBMITTED.value)
        self.assertEqual(document.anaf_upload_index, "DUR-ONCE")
        self.assertIsNone(document.submission_claim_token)
        self.assertIn("<Invoice", document.xml_content)
        self.assertTrue(document.verify_xml_integrity())
        client.upload_invoice.assert_called_once()

    def test_correction_worker_still_submits_a_credit_note_through_the_service(self) -> None:
        original = self._legacy(issued_at=timezone.now())
        EFacturaDocument.objects.create(invoice=original, status=EFacturaStatus.ACCEPTED.value)
        note = self._draft(
            number=f"CN-{uuid4().hex}",
            document_kind=DOCUMENT_KIND_CREDIT_NOTE,
            reverses_invoice=original,
            subtotal_cents=-10000,
            tax_cents=-2100,
            total_cents=-12100,
        )
        note.issue()
        note.save()
        self.assertFalse(EFacturaDocument.objects.filter(invoice=note).exists())
        correction: FiscalCorrection = correction_of(original, whole=True)
        correction.record_issued(note)
        correction.owe_efactura()
        correction.save()
        client = Mock(spec=EFacturaClient)
        client.upload_credit_note.return_value = UploadResponse(success=True, upload_index="DUR-CN")
        with patch("apps.billing.efactura.service.EFacturaClient", return_value=client):
            self.assertEqual(_advance_efactura(str(correction.pk)), EFACTURA_SUBMITTED)
        correction.refresh_from_db()
        self.assertEqual(correction.efactura_status, EFACTURA_SUBMITTED)
        document = EFacturaDocument.objects.get(invoice=note)
        self.assertEqual(document.status, EFacturaStatus.SUBMITTED.value)
        self.assertEqual(document.document_type, EFacturaDocumentType.CREDIT_NOTE.value)
        self.assertIn("<CreditNote", document.xml_content)
        self.assertIn(str(original.number), document.xml_content)
        client.upload_credit_note.assert_called_once()

    def test_excluded_invoices_get_no_intent_in_either_path(self) -> None:
        # The positive control makes a no-op implementation fail this test.
        eligible = self._create_issued()
        self.assertEqual(
            list(EFacturaDocument.objects.filter(invoice=eligible).values_list("status", flat=True)), ["queued"]
        )
        self._enabled(False)
        disabled = self._create_issued()
        self.assertFalse(EFacturaDocument.objects.filter(invoice=disabled).exists())
        self._enabled(True)
        cases = (
            {"issuer_provider": ISSUER_SMARTBILL},
            {"issuer_provider": "unregistered"},
            {"bill_to_country": "DE"},
            {
                "document_kind": DOCUMENT_KIND_CREDIT_NOTE,
                "reverses_invoice": eligible,
                "subtotal_cents": -10000,
                "tax_cents": -2100,
                "total_cents": -12100,
            },
        )
        for changes in cases:
            for created in (False, True):
                with self.subTest(changes=changes, created=created):
                    fields = self._fields(f"EXC-{uuid4().hex}") | changes
                    invoice = Invoice.objects.create(**fields, status="issued" if created else "draft")
                    if not created:
                        invoice.issue()
                        invoice.save()
                    self.assertFalse(EFacturaDocument.objects.filter(invoice=invoice).exists())

    def test_more_than_100_held_rows_cannot_starve_eligible_work(self) -> None:
        now = timezone.now()
        for index in range(104):
            changes: dict[str, object] = (
                {"issuer_provider": ISSUER_SMARTBILL},
                {"issuer_provider": "unregistered"},
                {"bill_to_country": "DE"},
                {"document_kind": DOCUMENT_KIND_CREDIT_NOTE},
            )[index % 4]
            invoice = self._legacy(issued_at=now, **changes)
            EFacturaDocument.objects.create(invoice=invoice, status="queued")
        # Include a mislabeled credit-note document on an ordinary invoice.
        mislabeled = self._legacy(issued_at=now)
        EFacturaDocument.objects.create(invoice=mislabeled, status="queued", document_type="credit_note")
        eligible_invoices: list[Invoice] = [
            self._legacy(issued_at=now, bill_to_country=country) for country in ("RO", "ro")
        ]
        for eligible in eligible_invoices:
            EFacturaDocument.objects.create(invoice=eligible, status="queued")
        pending = list(EFacturaDocument.get_pending_submissions(limit=100))
        self.assertEqual(
            {document.invoice_id for document in pending},
            {invoice.pk for invoice in eligible_invoices},
        )

    def test_reconciliation_repairs_each_legal_invoice_status_and_is_idempotent(self) -> None:
        now = timezone.now()
        legal = ("issued", "paid", "overdue", "void", "refunded", "partially_refunded")
        invoices = [self._legacy(status=status, issued_at=now) for status in legal]
        excluded = [
            self._legacy(status="draft", issued_at=now),
            self._legacy(issued_at=None),
            self._legacy(issued_at=now, issuer_provider=ISSUER_SMARTBILL),
            self._legacy(issued_at=now, issuer_provider="unregistered"),
            self._legacy(issued_at=now, bill_to_country="DE"),
            self._legacy(issued_at=now, document_kind=DOCUMENT_KIND_CREDIT_NOTE),
        ]
        draft_invoice = self._legacy(issued_at=now, bill_to_country="ro")
        orphan = EFacturaDocument.objects.create(invoice=draft_invoice)
        service = EFacturaService()
        service.check_approaching_deadlines()
        self.assertEqual(
            list(EFacturaDocument.objects.filter(invoice=invoices[0]).values_list("status", flat=True)), ["queued"]
        )
        self.assertEqual(EFacturaDocument.objects.filter(invoice__in=invoices, status="queued").count(), len(legal))
        orphan.refresh_from_db()
        self.assertEqual(orphan.status, "queued")
        self.assertFalse(EFacturaDocument.objects.filter(invoice__in=excluded).exists())
        before = list(EFacturaDocument.objects.order_by("pk").values())
        alerts = list(AuditAlert.objects.order_by("pk").values())
        service.check_approaching_deadlines()
        self.assertEqual(list(EFacturaDocument.objects.order_by("pk").values()), before)
        self.assertEqual(list(AuditAlert.objects.order_by("pk").values()), alerts)

    def test_reconciliation_preserves_filed_claimed_and_unknown_rows_and_alerts_old_orphans(self) -> None:
        now = timezone.now()
        protected = []
        for status in ("accepted", "submitted", "processing", "rejected", "error", "outcome_unknown", "uploading"):
            invoice = self._legacy(issued_at=now)
            fields: dict[str, object] = {}
            if status == "uploading":
                fields = {
                    "submission_claim_token": uuid4(),
                    "submission_claimed_at": now,
                    "submission_claim_expires_at": now + timedelta(minutes=10),
                }
            document = EFacturaDocument.objects.create(
                invoice=invoice, status=status, xml_content="<Invoice/>", **fields
            )
            protected.append(document.pk)
        claimed_draft = EFacturaDocument.objects.create(
            invoice=self._legacy(issued_at=now),
            submission_claimed_at=now - timedelta(minutes=20),
            submission_claim_expires_at=now - timedelta(minutes=10),
        )
        protected.append(claimed_draft.pk)
        old_missing = self._legacy(issued_at=now - timedelta(days=40))
        old_draft = EFacturaDocument.objects.create(invoice=self._legacy(issued_at=now - timedelta(days=40)))
        held = [
            EFacturaDocument.objects.create(invoice=self._legacy(issued_at=now, **changes), status="queued")
            for changes in (
                {"issuer_provider": ISSUER_SMARTBILL},
                {"issuer_provider": "unregistered"},
                {"bill_to_country": "DE"},
                {"document_kind": DOCUMENT_KIND_CREDIT_NOTE},
            )
        ]
        before = list(EFacturaDocument.objects.filter(pk__in=protected).order_by("pk").values())
        service = EFacturaService()
        service.check_approaching_deadlines()
        for document in held:
            document.refresh_from_db()
            self.assertEqual(document.status, "error")
            self.assertIsNone(document.next_retry_at)
        self.assertFalse(EFacturaDocument.objects.filter(invoice=old_missing).exists())
        old_draft.refresh_from_db()
        self.assertEqual(old_draft.status, "draft")
        self.assertEqual(list(EFacturaDocument.objects.filter(pk__in=protected).order_by("pk").values()), before)
        self.assertEqual(AuditAlert.objects.filter(metadata__efactura_reconciliation=True).count(), 6)
        after = list(EFacturaDocument.objects.order_by("pk").values())
        alerts = list(AuditAlert.objects.order_by("pk").values())
        service.check_approaching_deadlines()
        self.assertEqual(list(EFacturaDocument.objects.order_by("pk").values()), after)
        self.assertEqual(list(AuditAlert.objects.order_by("pk").values()), alerts)

    def test_schedules_exist_before_and_after_runtime_enablement_without_duplicates(self) -> None:
        Schedule.objects.all().delete()
        self._enabled(False)
        call_command("setup_scheduled_tasks", stdout=StringIO())
        expected = {
            "efactura_poll_status",
            "efactura_process_retries",
            "efactura_process_pending",
            "efactura_check_deadlines",
            "efactura_archive_missing_responses",
            "efactura_reconcile_documents",
        }
        self.assertEqual(
            set(Schedule.objects.filter(name__startswith="efactura_").values_list("name", flat=True)), expected
        )
        self._enabled(True)
        self.assertTrue(is_efactura_enabled())
        call_command("setup_scheduled_tasks", stdout=StringIO())
        self.assertEqual(
            set(Schedule.objects.filter(name__startswith="efactura_").values_list("name", flat=True)), expected
        )
        self.assertEqual(Schedule.objects.filter(name__startswith="efactura_").count(), len(expected))
        self.assertEqual(
            Schedule.objects.get(name="efactura_reconcile_documents").func,
            "apps.billing.efactura.tasks.reconcile_efactura_documents",
        )
        self.assertEqual(Schedule.objects.get(name="efactura_reconcile_documents").schedule_type, Schedule.DAILY)
        self._enabled(False)
        self.assertFalse(is_efactura_enabled())
        self._enabled(True)
        self.assertTrue(is_efactura_enabled())

    def test_schedule_registration_database_failure_propagates(self) -> None:
        failure = DatabaseError("schedule store unavailable")
        before = list(Schedule.objects.order_by("pk").values())

        with patch.object(Schedule.objects, "update_or_create", side_effect=failure):
            with self.assertRaises(DatabaseError) as registration_error:
                schedule_efactura_tasks()
            self.assertIs(registration_error.exception, failure)
            with self.assertRaisesMessage(CommandError, "schedule store unavailable") as command_error:
                call_command("setup_scheduled_tasks", efactura_only=True, stdout=StringIO())
            self.assertIs(command_error.exception.__cause__, failure)

        self.assertEqual(list(Schedule.objects.order_by("pk").values()), before)
