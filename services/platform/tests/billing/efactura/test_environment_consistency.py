"""Stored e-Factura environment takes precedence for documents and uploads."""

from __future__ import annotations

from collections.abc import Callable
from datetime import timedelta
from decimal import Decimal
from pathlib import Path
from typing import cast
from unittest.mock import patch
from uuid import uuid4

import requests
from django.core.cache import cache
from django.test import TestCase, override_settings
from django.utils import timezone

from apps.audit.models import AuditAlert
from apps.billing.efactura.client import EFacturaClient, EFacturaConfig, TokenResponse
from apps.billing.efactura.client import EFacturaEnvironment as ClientEnvironment
from apps.billing.efactura.intents import ensure_efactura_intent
from apps.billing.efactura.models import EFacturaDocument, EFacturaStatus
from apps.billing.efactura.service import EFacturaService, SubmissionClaim
from apps.billing.invoice_models import ISSUER_BUILTIN, Currency, Invoice, InvoiceLine
from apps.settings.models import SystemSetting
from tests.billing._storno_helpers import SELLER, v2_evidence
from tests.billing.efactura.test_response_archive import response_zip
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

    def _queued_document(self, environment: str) -> EFacturaDocument:
        self._set_environment(environment)
        document = ensure_efactura_intent(self._invoice())
        if document is None:
            self.fail("An eligible invoice must have a queued document")
        self.assertEqual(document.environment, environment)
        return document

    @staticmethod
    def _http_response(content: bytes) -> requests.Response:
        response = requests.Response()
        response.status_code = 200
        response._content = content
        return response

    def _assert_document_routes(self, recorded: str, current: str) -> None:
        with override_settings(
            CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache", "LOCATION": recorded}},
        ):
            cache.clear()
            document = self._queued_document(recorded)
            self._set_environment(current)
            for environment in (ClientEnvironment.PRODUCTION, ClientEnvironment.TEST):
                config = EFacturaConfig.from_settings()
                config.environment = environment
                EFacturaClient(config)._cache_token(
                    TokenResponse(
                        access_token=f"{environment.value}-token",
                        token_type="Bearer",
                        expires_in=3600,
                        expires_at=timezone.now() + timedelta(hours=1),
                    )
                )
            service = EFacturaService()
            # Warm the opposite environment's in-memory token before binding the document.
            service.client._get_access_token()
            content = response_zip()
            requests_seen: list[tuple[str, str, str]] = []

            def transport(method: str, url: str, **kwargs: object) -> requests.Response:
                headers = cast(dict[str, str], kwargs["headers"])
                requests_seen.append((method, url, headers["Authorization"]))
                if url.endswith("/stareMesaj"):
                    return self._http_response(b'{"stare": "ok", "id_descarcare": "DOWNLOAD-ENV"}')
                if url.endswith("/descarcare"):
                    return self._http_response(content)
                return self._http_response((Path(__file__).parent / "fixtures" / "anaf_upload_ok.xml").read_bytes())

            with patch("apps.billing.efactura.client.safe_request", side_effect=transport):
                submitted = service.submit_invoice(document.invoice)
                self.assertTrue(submitted.success, submitted.error_message)
                document.refresh_from_db()
                self.assertEqual(document.status, EFacturaStatus.SUBMITTED.value)
                polled = service.check_status(document)
                self.assertEqual(polled.status, "accepted")
                self.assertEqual(service.download_response(document), content)

            endpoint = "prod" if recorded == "production" else "test"
            base = f"https://api.anaf.ro/{endpoint}/FCTEL/rest"
            self.assertEqual(
                [(method, url) for method, url, _authorization in requests_seen],
                [("POST", f"{base}/upload"), ("GET", f"{base}/stareMesaj"), ("GET", f"{base}/descarcare")],
            )
            self.assertEqual([authorization for _, _, authorization in requests_seen], [f"Bearer {endpoint}-token"] * 3)
            document.refresh_from_db()
            self.assertEqual(document.environment, recorded)
            self.assertEqual(document.status, EFacturaStatus.ACCEPTED.value)
            self.assertTrue(document.verify_response_archive_integrity())
            self.assertEqual(service.client.config.environment.value, "prod" if current == "production" else "test")
            cache.clear()

    @override_settings(
        EFACTURA_ACCESS_TOKEN="",
        CACHES={
            "default": {
                "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
                "LOCATION": "efactura-same-environment-token",
            }
        },
    )
    def test_same_environment_token_submits_when_shared_cache_entry_is_absent(self) -> None:
        for environment in ("test", "production"):
            with self.subTest(environment=environment):
                document = self._queued_document(environment)
                client = EFacturaClient()
                token = TokenResponse(
                    access_token=f"{client.config.environment.value}-in-memory-token",
                    token_type="Bearer",
                    expires_in=3600,
                    expires_at=timezone.now() + timedelta(hours=1),
                )
                client._cache_token(token)
                cache_key = client.TOKEN_CACHE_KEY.format(env=client.config.environment.value)
                cache.delete(cache_key)
                self.assertIsNone(cache.get(cache_key))
                self.assertFalse(token.is_expired)
                service = EFacturaService(client=client)
                upload_index = f"3828-{environment}"
                response = self._http_response(
                    (Path(__file__).parent / "fixtures" / "anaf_upload_ok.xml")
                    .read_bytes()
                    .replace(b"3828", upload_index.encode())
                )

                with patch("apps.billing.efactura.client.safe_request", return_value=response) as transport:
                    result = service.submit_invoice(document.invoice)

                self.assertTrue(result.success, result.error_message)
                document.refresh_from_db()
                self.assertEqual(document.status, EFacturaStatus.SUBMITTED.value)
                self.assertEqual(document.anaf_upload_index, upload_index)
                self.assertEqual(document.environment, environment)
                self.assertIsNone(document.submission_claim_token)
                self.assertEqual(document.last_error, "")
                self.assertFalse(AuditAlert.objects.filter(metadata__document_id=str(document.pk)).exists())
                request = transport.call_args
                if request is None:
                    self.fail("The authenticated submission must reach the HTTP transport")
                self.assertEqual(request.args, ("POST", f"{document.get_environment_base_url()}/upload"))
                headers = cast(dict[str, str], request.kwargs["headers"])
                self.assertEqual(headers["Authorization"], f"Bearer {token.access_token}")
                self.assertEqual(request.kwargs["data"], document.xml_content.encode("utf-8"))
                self.assertIs(client._token, token)
                self.assertIs(service.client, client)
                self.assertIsNone(cache.get(cache_key))

    def test_production_document_keeps_production_for_upload_poll_and_download(self) -> None:
        self._assert_document_routes("production", "test")

    def test_test_document_keeps_test_for_upload_poll_and_download(self) -> None:
        self._assert_document_routes("test", "production")

    def test_claim_captures_recorded_environment_after_setting_changes(self) -> None:
        for recorded, current in (("production", "test"), ("test", "production")):
            with self.subTest(recorded=recorded):
                document = self._queued_document(recorded)
                self._set_environment(current)
                claim = EFacturaService()._prepare_and_claim_submission(document.invoice)
                if not isinstance(claim, SubmissionClaim):
                    self.fail("The queued document must be claimed")
                self.assertEqual(getattr(claim, "environment", None), recorded)

    def _assert_authentication_alert(self, document: EFacturaDocument, operation: str) -> None:
        self.assertTrue(
            AuditAlert.objects.filter(
                alert_type="compliance_violation",
                status="active",
                metadata__document_id=str(document.pk),
                metadata__environment=document.environment,
                metadata__operation=operation,
            ).exists()
        )
        alert = AuditAlert.objects.get(metadata__document_id=str(document.pk), metadata__operation=operation)
        self.assertEqual(alert.severity, "high")
        self.assertIn(document.environment, alert.description)

    def test_missing_document_token_fails_submission_without_using_current_manual_token(self) -> None:
        for recorded, current in (("production", "test"), ("test", "production")):
            with self.subTest(recorded=recorded):
                document = self._queued_document(recorded)
                self._set_environment(current)
                response = self._http_response(
                    (Path(__file__).parent / "fixtures" / "anaf_upload_ok.xml")
                    .read_bytes()
                    .replace(b"3828", recorded.encode())
                )
                with patch("apps.billing.efactura.client.safe_request", return_value=response) as transport:
                    result = EFacturaService().submit_invoice(document.invoice)
                self.assertFalse(result.success)
                document.refresh_from_db()
                self.assertEqual(document.status, EFacturaStatus.ERROR.value)
                self.assertEqual(document.anaf_upload_index, "")
                self.assertIsNone(document.submission_claim_token)
                self.assertIn(recorded, document.last_error)
                self.assertEqual(transport.call_args_list, [])
                self._assert_authentication_alert(document, "upload")

    def test_missing_client_credentials_persists_error_and_alert(self) -> None:
        document = self._queued_document("production")
        self._set_environment("test")
        with override_settings(EFACTURA_CLIENT_ID=""):
            result = EFacturaService().submit_invoice(document.invoice)
        self.assertFalse(result.success)
        document.refresh_from_db()
        self.assertEqual(document.status, EFacturaStatus.ERROR.value)
        self.assertIsNone(document.submission_claim_token)
        self._assert_authentication_alert(document, "upload")

    def test_missing_document_token_fails_poll_without_reopening_submission(self) -> None:
        for recorded, current in (("production", "test"), ("test", "production")):
            with self.subTest(recorded=recorded):
                self._set_environment(recorded)
                document = EFacturaDocument.objects.create(
                    invoice=self._invoice(),
                    environment=recorded,
                    status=EFacturaStatus.SUBMITTED.value,
                    anaf_upload_index=f"UPLOAD-{recorded}",
                )
                self._set_environment(current)
                response = self._http_response(b'{"stare": "in processing"}')
                with patch("apps.billing.efactura.client.safe_request", return_value=response) as transport:
                    result = EFacturaService().check_status(document)
                self.assertEqual(result.status, "error")
                document.refresh_from_db()
                self.assertEqual(document.status, EFacturaStatus.SUBMITTED.value)
                self.assertEqual(document.anaf_upload_index, f"UPLOAD-{recorded}")
                self.assertIn(recorded, document.last_error)
                self.assertEqual(transport.call_args_list, [])
                self._assert_authentication_alert(document, "poll")

    def test_missing_document_token_fails_download_and_preserves_acceptance(self) -> None:
        for recorded, current in (("production", "test"), ("test", "production")):
            with self.subTest(recorded=recorded):
                self._set_environment(recorded)
                document = EFacturaDocument.objects.create(
                    invoice=self._invoice(),
                    environment=recorded,
                    status=EFacturaStatus.ACCEPTED.value,
                    anaf_upload_index=f"UPLOAD-{recorded}",
                    anaf_download_id="DOWNLOAD-ENV",
                )
                self._set_environment(current)
                with patch(
                    "apps.billing.efactura.client.safe_request", return_value=self._http_response(response_zip())
                ) as transport:
                    result = EFacturaService().download_response(document)
                self.assertIsNone(result)
                document.refresh_from_db()
                self.assertEqual(document.status, EFacturaStatus.ACCEPTED.value)
                self.assertFalse(document.response_archive)
                self.assertIn(recorded, document.last_error)
                self.assertEqual(transport.call_args_list, [])
                self._assert_authentication_alert(document, "download")
