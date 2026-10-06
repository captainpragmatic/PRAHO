"""Stored e-Factura environment takes precedence for documents and uploads."""

from __future__ import annotations

from collections.abc import Callable
from decimal import Decimal
from pathlib import Path
from unittest.mock import patch
from uuid import uuid4

import requests
from django.core.cache import cache
from django.test import TestCase, override_settings
from django.utils import timezone

from apps.billing.efactura.client import EFacturaClient, EFacturaConfig
from apps.billing.efactura.intents import ensure_efactura_intent
from apps.billing.efactura.models import EFacturaDocument, EFacturaStatus
from apps.billing.efactura.service import EFacturaService, SubmissionClaim
from apps.billing.invoice_models import ISSUER_BUILTIN, Currency, Invoice, InvoiceLine
from apps.settings.models import SystemSetting
from tests.billing._storno_helpers import SELLER, v2_evidence
from tests.factories.billing_factories import CustomerFactory


@SELLER
@override_settings(
    EFACTURA_ENABLED=True,
    EFACTURA_CLIENT_ID="environment-client",
    EFACTURA_CLIENT_SECRET="environment-secret",
    EFACTURA_ACCESS_TOKEN="environment-token",
    COMPANY_BANK_ACCOUNT="RO49AAAA1B31007593840000",
    COMPANY_BANK_NAME="Test bank",
    STORAGES={"default": {"BACKEND": "django.core.files.storage.InMemoryStorage"}},
)
class EFacturaEnvironmentConsistencyTests(TestCase):
    def setUp(self) -> None:
        cache.clear()
        self.addCleanup(cache.clear)
        SystemSetting.objects.filter(key__in=("efactura.enabled", "efactura.environment")).delete()
        self.customer = CustomerFactory()
        self.currency, _ = Currency.objects.get_or_create(code="RON", defaults={"symbol": "lei"})

    def _set_environment(self, value: str | None) -> None:
        if value is None:
            SystemSetting.objects.filter(key="efactura.environment").delete()
            return
        SystemSetting.objects.update_or_create(
            key="efactura.environment",
            defaults={"name": "Environment", "data_type": "string", "value": value, "default_value": "test"},
        )

    def _invoice(self) -> Invoice:
        # Historical issued rows let each test exercise its own document creation path.
        invoice = Invoice.objects.bulk_create(
            [
                Invoice(
                    customer=self.customer,
                    currency=self.currency,
                    number=f"ENV-{uuid4().hex}",
                    status="issued",
                    issued_at=timezone.now(),
                    issuer_provider=ISSUER_BUILTIN,
                    subtotal_cents=10000,
                    tax_cents=2100,
                    total_cents=12100,
                    bill_to_name="Customer SRL",
                    bill_to_tax_id="RO87654321",
                    bill_to_address1="Customer Street 456",
                    bill_to_city="Cluj-Napoca",
                    bill_to_postal="400001",
                    bill_to_country="RO",
                    vat_evidence=v2_evidence(subtotal=10000, tax=2100, total=12100),
                )
            ]
        )[0]
        InvoiceLine.objects.create(
            invoice=invoice,
            kind="service",
            description="Hosting",
            quantity=Decimal("1"),
            unit_price_cents=10000,
            tax_rate=Decimal("0.21"),
            tax_cents=2100,
            line_total_cents=12100,
        )
        return invoice

    def _assert_creation_matches_upload(self, create_document: Callable[[Invoice], EFacturaDocument | None]) -> None:
        cases = (
            ("production", "test", "production"),
            ("test", "production", "test"),
            (None, "production", "production"),
            (None, "test", "test"),
            ("invalid", "production", "test"),
        )
        for stored, deployment, expected in cases:
            with self.subTest(stored=stored, deployment=deployment), override_settings(EFACTURA_ENVIRONMENT=deployment):
                self._set_environment(stored)
                invoice = self._invoice()
                document = create_document(invoice)
                if document is None:
                    self.fail("An eligible issued invoice must have an e-Factura document")
                document.refresh_from_db()
                self.assertEqual(document.environment, expected)
                client = EFacturaClient()
                response = requests.Response()
                response.status_code = 200
                response._content = (Path(__file__).parent / "fixtures" / "anaf_upload_ok.xml").read_bytes()
                with patch("apps.billing.efactura.client.safe_request", return_value=response) as transport:
                    uploaded = client.upload_invoice(document.xml_content or "<Invoice/>")
                self.assertTrue(uploaded.success, uploaded.message)
                self.assertEqual(uploaded.upload_index, "3828")
                request = transport.call_args
                if request is None:
                    self.fail("The upload must reach the HTTP transport")
                self.assertEqual(request.args[1], f"{document.get_environment_base_url()}/upload")
                endpoint = "prod" if expected == "production" else "test"
                self.assertEqual(client.config.base_url, f"https://api.anaf.ro/{endpoint}/FCTEL/rest")

    def test_new_intent_matches_effective_upload_environment(self) -> None:
        self._assert_creation_matches_upload(ensure_efactura_intent)

    def test_service_document_matches_effective_upload_environment(self) -> None:
        self._assert_creation_matches_upload(lambda invoice: EFacturaService()._get_or_create_document(invoice))

    def _claim_document(self, invoice: Invoice) -> EFacturaDocument:
        service = EFacturaService()
        claim = service._prepare_and_claim_submission(invoice)
        self.assertIsInstance(claim, SubmissionClaim)
        document = EFacturaDocument.objects.get(invoice=invoice)
        self.assertEqual(document.status, EFacturaStatus.UPLOADING.value)
        self.assertTrue(document.verify_xml_integrity())
        return document

    def test_submission_claim_matches_effective_upload_environment(self) -> None:
        self._assert_creation_matches_upload(self._claim_document)

    @override_settings(EFACTURA_ENVIRONMENT="test")
    def test_client_configuration_observes_stored_changes_and_deployment_fallback(self) -> None:
        self._set_environment("production")
        self.assertEqual(EFacturaConfig.from_settings().base_url, "https://api.anaf.ro/prod/FCTEL/rest")
        self._set_environment("test")
        self.assertEqual(EFacturaConfig.from_settings().base_url, "https://api.anaf.ro/test/FCTEL/rest")
        self._set_environment(None)
        with override_settings(EFACTURA_ENVIRONMENT="production"):
            self.assertEqual(EFacturaConfig.from_settings().base_url, "https://api.anaf.ro/prod/FCTEL/rest")
