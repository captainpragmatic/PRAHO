"""Stored scheduling and storage settings must change real e-Factura operations."""

from __future__ import annotations

import hashlib
from datetime import datetime, timedelta
from decimal import Decimal
from typing import cast
from unittest.mock import patch

import requests
from django.core.cache import cache
from django.test import TestCase, override_settings
from django.utils import timezone
from django_q.models import OrmQ
from django_q.signing import SignedPackage

from apps.billing.efactura.models import EFacturaDocument, EFacturaStatus
from apps.billing.efactura.service import EFacturaService
from apps.billing.efactura.tasks import (
    poll_all_pending_status_task,
    process_efactura_retries_task,
    process_pending_submissions_task,
    queue_efactura_submission,
    submit_efactura_task,
)
from apps.billing.invoice_models import ISSUER_BUILTIN, Currency, Invoice, InvoiceLine
from apps.settings.models import SystemSetting
from apps.settings.services import SettingsService
from tests.billing._storno_helpers import v2_evidence
from tests.factories.billing_factories import CustomerFactory


@override_settings(
    EFACTURA_ENABLED=True,
    EFACTURA_ENVIRONMENT="test",
    EFACTURA_CLIENT_ID="scheduling-client",
    EFACTURA_CLIENT_SECRET="scheduling-secret",
    EFACTURA_ACCESS_TOKEN="scheduling-token",
    EFACTURA_COMPANY_CUI="12345678",
    COMPANY_NAME="Scheduling Supplier SRL",
    COMPANY_REGISTRATION_NUMBER="J40/1234/2020",
    COMPANY_STREET="Supplier Street 1",
    COMPANY_CITY="Bucharest",
    COMPANY_POSTAL_CODE="010101",
    COMPANY_COUNTRY_CODE="RO",
    COMPANY_BANK_ACCOUNT="RO49AAAA1B31007593840000",
    COMPANY_BANK_NAME="Scheduling Bank",
    STORAGES={"default": {"BACKEND": "django.core.files.storage.InMemoryStorage"}},
)
class EFacturaSchedulingSettingsEffectTests(TestCase):
    def setUp(self) -> None:
        cache.clear()
        self.addCleanup(cache.clear)
        SystemSetting.objects.filter(key__startswith="efactura.").delete()
        self.customer = CustomerFactory()
        self.currency, _ = Currency.objects.get_or_create(code="RON", defaults={"symbol": "lei"})
        self.counter = 0

    def _write(self, key: str, value: str | int | bool) -> None:
        with self.captureOnCommitCallbacks(execute=True):
            result = SettingsService.update_setting(key, value)
        self.assertTrue(result.is_ok(), result)

    def _document(
        self,
        *,
        status: str = EFacturaStatus.QUEUED.value,
        submitted_at: datetime | None = None,
    ) -> EFacturaDocument:
        self.counter += 1
        # Historical fixtures bypass issuance signals; consumers below perform the real transitions.
        invoice = Invoice.objects.bulk_create(
            [
                Invoice(
                    customer=self.customer,
                    currency=self.currency,
                    number=f"SCHEDULING-{self.counter:03d}",
                    status="issued",
                    issued_at=timezone.now() - timedelta(days=1),
                    due_at=timezone.now() + timedelta(days=14),
                    issuer_provider=ISSUER_BUILTIN,
                    bill_to_name="Scheduling Customer SRL",
                    bill_to_tax_id="RO87654321",
                    bill_to_address1="Customer Street 2",
                    bill_to_city="Cluj-Napoca",
                    bill_to_postal="400001",
                    bill_to_country="RO",
                    subtotal_cents=10000,
                    tax_cents=1900,
                    total_cents=11900,
                    vat_evidence=v2_evidence(subtotal=10000, tax=1900, total=11900, rate="19"),
                )
            ]
        )[0]
        InvoiceLine.objects.create(
            invoice=invoice,
            kind="service",
            description="Hosting",
            quantity=Decimal("1"),
            unit_price_cents=10000,
            tax_rate=Decimal("0.19"),
            tax_cents=1900,
            line_total_cents=11900,
        )
        return EFacturaDocument.objects.create(
            invoice=invoice,
            status=status,
            environment="test",
            submitted_at=submitted_at,
            anaf_upload_index=f"UPLOAD-{self.counter}" if submitted_at is not None else "",
        )

    @staticmethod
    def _response(content: bytes) -> requests.Response:
        response = requests.Response()
        response.status_code = 200
        response._content = content
        return response

    def test_poll_batch_size_limits_http_requests_and_persisted_transitions(self) -> None:
        now = timezone.now()
        documents = [
            self._document(status=EFacturaStatus.SUBMITTED.value, submitted_at=now - timedelta(hours=hours))
            for hours in (4, 3, 2, 1)
        ]
        seen: list[str] = []

        def transport(method: str, url: str, **kwargs: object) -> requests.Response:
            self.assertEqual(method, "GET")
            self.assertTrue(url.endswith("/stareMesaj"), url)
            seen.append(cast(dict[str, str], kwargs["params"])["id_incarcare"])
            return self._response(b'{"stare":"nok","errors":["Scheduling refusal"]}')

        with patch("apps.billing.efactura.client.safe_request", side_effect=transport):
            self._write("efactura.polling.batch_size", 1)
            first = poll_all_pending_status_task()
            self.assertEqual(first["rejected"], 1)
            self.assertEqual(seen, [documents[0].anaf_upload_index])
            self.assertEqual(
                list(EFacturaDocument.objects.order_by("submitted_at").values_list("status", flat=True)),
                ["rejected", "submitted", "submitted", "submitted"],
            )

            seen.clear()
            self._write("efactura.polling.batch_size", 2)
            second = poll_all_pending_status_task()
            self.assertEqual(second["rejected"], 2)
            self.assertEqual(seen, [documents[1].anaf_upload_index, documents[2].anaf_upload_index])
            self.assertEqual(
                list(EFacturaDocument.objects.order_by("submitted_at").values_list("status", flat=True)),
                ["rejected", "rejected", "rejected", "submitted"],
            )

            seen.clear()
            self._write("efactura.polling.batch_size", 0)
            empty = poll_all_pending_status_task()
            self.assertEqual(empty["rejected"], 0)
            self.assertEqual(seen, [])
            self.assertEqual(EFacturaDocument.objects.get(pk=documents[3].pk).status, "submitted")

    def test_auto_submit_switch_holds_work_and_resume_reaches_anaf(self) -> None:
        document = self._document()
        invoice_id = str(document.invoice_id)
        before_queue = set(OrmQ.objects.values_list("pk", flat=True))
        self._write("efactura.submission.auto_submit_enabled", False)
        self.assertIsNone(queue_efactura_submission(invoice_id))
        self.assertSetEqual(set(OrmQ.objects.values_list("pk", flat=True)), before_queue)

        def forbidden_transport(method: str, url: str, **kwargs: object) -> requests.Response:
            self.fail(f"Disabled automatic submission reached HTTP: {method} {url}")

        with patch("apps.billing.efactura.client.safe_request", side_effect=forbidden_transport):
            pending = process_pending_submissions_task()
            self.assertEqual(
                {key: pending[key] for key in ("submitted", "failed", "skipped")},
                {"submitted": 0, "failed": 0, "skipped": 0},
            )
            worker = submit_efactura_task(invoice_id)
            self.assertFalse(worker["success"])
        held = EFacturaDocument.objects.get(pk=document.pk)
        self.assertEqual(held.status, "queued")
        self.assertEqual(held.xml_content, "")
        self.assertIsNone(held.submission_claim_token)

        # Existing retry work is held too, without changing its retry schedule or budget.
        retry = self._document(status="error")
        due = timezone.now() - timedelta(minutes=1)
        EFacturaDocument.objects.filter(pk=retry.pk).update(next_retry_at=due)
        with patch("apps.billing.efactura.client.safe_request", side_effect=forbidden_transport):
            retries = process_efactura_retries_task()
            self.assertEqual({key: retries[key] for key in ("retried", "failed")}, {"retried": 0, "failed": 0})
        retry = EFacturaDocument.objects.get(pk=retry.pk)
        self.assertEqual(retry.status, "error")
        self.assertEqual(retry.next_retry_at, due)
        self.assertEqual(retry.retry_count, 0)

        # The manual service remains permitted while automatic submission is disabled.
        manual = self._document()
        response = self._response(b'<header ExecutionStatus="0" index_incarcare="MANUAL-UPLOAD"/>')
        with patch("apps.billing.efactura.client.safe_request", return_value=response):
            result = EFacturaService().submit_invoice(manual.invoice)
        self.assertTrue(result.success, result.error_message)
        self.assertEqual(EFacturaDocument.objects.get(pk=manual.pk).anaf_upload_index, "MANUAL-UPLOAD")

        self._write("efactura.submission.auto_submit_enabled", True)
        task_id = queue_efactura_submission(invoice_id)
        self.assertIsNotNone(task_id)
        jobs = [
            cast(dict[str, object], SignedPackage.loads(row.payload))
            for row in OrmQ.objects.exclude(pk__in=before_queue)
        ]
        self.assertEqual(
            [(job["func"], job["args"]) for job in jobs],
            [("apps.billing.efactura.tasks.submit_efactura_task", (invoice_id,))],
        )
        self.assertEqual(jobs[0]["id"], task_id)
        self.assertEqual(jobs[0]["timeout"], 300)

        response = self._response(b'<header ExecutionStatus="0" index_incarcare="AUTOMATIC-UPLOAD"/>')
        with patch("apps.billing.efactura.client.safe_request", return_value=response):
            worker = submit_efactura_task(invoice_id)
        self.assertTrue(worker["success"], worker)
        submitted = EFacturaDocument.objects.get(pk=document.pk)
        self.assertEqual(submitted.status, "submitted")
        self.assertEqual(submitted.anaf_upload_index, "AUTOMATIC-UPLOAD")
        self.assertIsNone(submitted.submission_claim_token)

    def test_xml_path_changes_saved_file_and_keeps_issued_tax_rates(self) -> None:
        service = EFacturaService()
        for template in ("staff/xml/%Y/%m/", "other/xml"):
            with self.subTest(template=template):
                self._write("efactura.storage.xml_path", template)
                document = self._document()
                original_rate = document.invoice.lines.get().tax_rate
                xml = service._generate_xml(document.invoice, document)
                stored = EFacturaDocument.objects.get(pk=document.pk)
                self.assertIsNotNone(stored.xml_generated_at)
                generated_at = cast(datetime, stored.xml_generated_at)
                expected = f"{generated_at.strftime(template).rstrip('/')}/{document.invoice.number}.xml"
                self.assertEqual(stored.xml_file.name, expected)
                with stored.xml_file.open("rb") as content:
                    self.assertEqual(content.read(), xml.encode("utf-8"))
                self.assertEqual(stored.xml_hash, hashlib.sha256(xml.encode("utf-8")).hexdigest())
                self.assertEqual(document.invoice.lines.get().tax_rate, original_rate)
                self.assertIn("<cbc:Percent>19.00</cbc:Percent>", xml)
