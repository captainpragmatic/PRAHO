"""Regression coverage for e-Factura supplier and OAuth dispatch boundaries."""

from __future__ import annotations

import json
from datetime import timedelta
from decimal import Decimal
from typing import cast
from unittest.mock import patch
from uuid import uuid4

import requests
from django.core.cache import cache
from django.test import TestCase, override_settings
from django.utils import timezone
from lxml import etree

from apps.billing.efactura.client import AuthenticationError, EFacturaClient, EFacturaConfig
from apps.billing.efactura.client import EFacturaEnvironment as ClientEnvironment
from apps.billing.efactura.models import EFacturaDocument, EFacturaStatus
from apps.billing.efactura.service import EFacturaService
from apps.billing.efactura.validator import CIUSROValidator
from apps.billing.efactura.xml_builder import NAMESPACES, XMLBuilderError, builder_for
from apps.billing.invoice_models import ISSUER_BUILTIN, Currency, Invoice, InvoiceLine
from apps.billing.issuers.service import _get_or_create_credit_note
from apps.settings.models import SystemSetting
from apps.settings.services import SettingsService
from tests.billing import _fiscal_correction_helpers as h
from tests.billing._storno_helpers import v2_evidence
from tests.factories.billing_factories import CustomerFactory


@override_settings(
    COMPANY_NAME="Deployment Supplier SRL",
    EFACTURA_COMPANY_CUI="12345678",
    COMPANY_REGISTRATION_NUMBER="J40/1234/2020",
    COMPANY_STREET="Deployment Street 1",
    COMPANY_CITY="Bucharest",
    COMPANY_POSTAL_CODE="010101",
    COMPANY_COUNTRY_CODE="RO",
    COMPANY_EMAIL="deployment@example.test",
    COMPANY_PHONE="+40210000000",
    COMPANY_BANK_ACCOUNT="RO49AAAA1B31007593840000",
    COMPANY_BANK_NAME="Deployment Bank",
    EFACTURA_ENABLED=True,
    EFACTURA_ENVIRONMENT="test",
    EFACTURA_CLIENT_ID="deployment-client",
    EFACTURA_CLIENT_SECRET="deployment-secret",
    EFACTURA_ACCESS_TOKEN="deployment-token",
    EFACTURA_VALIDATION_SCHEMATRON_ENABLED=True,
    EFACTURA_VALIDATION_STRICT_MODE=False,
    STORAGES={"default": {"BACKEND": "django.core.files.storage.InMemoryStorage"}},
    CACHES={
        "default": {
            "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
            "LOCATION": "efactura-deep-review",
        }
    },
)
class EFacturaDeepReviewTests(TestCase):
    def setUp(self) -> None:
        cache.clear()
        self.addCleanup(cache.clear)
        SystemSetting.objects.filter(key__startswith="efactura.").delete()
        SystemSetting.objects.filter(key="billing.bank_accounts").delete()

    def _write(self, key: str, value: str | bool) -> None:
        with self.captureOnCommitCallbacks(execute=True):
            result = SettingsService.update_setting(key, value)
        self.assertTrue(result.is_ok(), str(result))

    def _invoice(self, *, b2c: bool = False) -> Invoice:
        currency, _created = Currency.objects.get_or_create(code="RON", defaults={"symbol": "lei"})
        # Historical issued snapshots avoid enqueueing unrelated work during fixture creation.
        invoice = Invoice.objects.bulk_create(
            [
                Invoice(
                    customer=CustomerFactory(),
                    currency=currency,
                    number=f"DR-{uuid4().hex}",
                    status="issued",
                    issued_at=timezone.now(),
                    due_at=timezone.now() + timedelta(days=30),
                    issuer_provider=ISSUER_BUILTIN,
                    subtotal_cents=10000,
                    tax_cents=2100,
                    total_cents=12100,
                    bill_to_name="Customer SRL",
                    bill_to_tax_id="" if b2c else "RO87654321",
                    bill_to_address1="Customer Street 2",
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

    def _credit_note(self, original: Invoice) -> Invoice:
        note = _get_or_create_credit_note(original, h.correction_of(original))
        note.number = f"CN-{uuid4().hex}"
        note.issue()
        note.save()
        EFacturaDocument.objects.create(
            invoice=original,
            status=EFacturaStatus.ACCEPTED.value,
            environment="test",
            anaf_upload_index=f"accepted-{original.pk}",
        )
        return note

    def _xml(self, invoice: Invoice) -> str:
        try:
            return builder_for(invoice).build()
        except XMLBuilderError as exc:
            self.fail(f"Deployment fallback must produce XML: {exc}")

    @staticmethod
    def _response(content: bytes) -> requests.Response:
        response = requests.Response()
        response.status_code = 200
        response._content = content
        return response

    def _authorize(self, client: EFacturaClient, token: str) -> None:
        response = self._response(
            json.dumps(
                {
                    "access_token": token,
                    "token_type": "Bearer",
                    "expires_in": 3600,
                    "refresh_token": f"refresh-{token}",
                }
            ).encode()
        )
        with patch("apps.billing.efactura.client.safe_request", return_value=response):
            result = client.exchange_code_for_token("code", "https://callback.example.test/")
        self.assertEqual(result.access_token, token)
        # Use a live token fixture without relying on the existing timestamp default.
        result.expires_at = timezone.now() + timedelta(hours=1)
        client._cache_token(result)

    def test_cleared_supplier_fields_fall_back_in_invoice_and_credit_note_xml(self) -> None:
        original = self._invoice()
        note = self._credit_note(original)
        party = "./cac:AccountingSupplierParty/cac:Party/"
        fields = {
            "name": ("cac:PartyLegalEntity/cbc:RegistrationName", "Deployment Supplier SRL"),
            "cui": ("cac:PartyIdentification/cbc:ID", "12345678"),
            "registration_number": ("cac:PartyLegalEntity/cbc:CompanyID", "J40/1234/2020"),
            "street": ("cac:PostalAddress/cbc:StreetName", "Deployment Street 1"),
            "city": ("cac:PostalAddress/cbc:CityName", "Bucharest"),
            "postal_code": ("cac:PostalAddress/cbc:PostalZone", "010101"),
            "country_code": ("cac:PostalAddress/cac:Country/cbc:IdentificationCode", "RO"),
            "email": ("cac:Contact/cbc:ElectronicMail", "deployment@example.test"),
            "phone": ("cac:Contact/cbc:Telephone", "+40210000000"),
        }
        for key, (path, expected) in fields.items():
            self._write(f"efactura.company.{key}", "")
            invoices = (original,) if key in {"email", "phone"} else (original, note)
            for invoice in invoices:
                with self.subTest(field=key, kind=invoice.document_kind):
                    doc = etree.fromstring(self._xml(invoice).encode())
                    self.assertEqual(doc.findtext(party + path, namespaces=NAMESPACES), expected)
            SystemSetting.objects.filter(key=f"efactura.company.{key}").delete()

    def test_cleared_bank_fields_keep_deployment_payment_instructions(self) -> None:
        invoice = self._invoice()
        for key in ("bank_account", "bank_name"):
            self._write(f"efactura.company.{key}", "")
        doc = etree.fromstring(self._xml(invoice).encode())
        account = "./cac:PaymentMeans/cac:PayeeFinancialAccount/"
        self.assertEqual(doc.findtext(account + "cbc:ID", namespaces=NAMESPACES), "RO49AAAA1B31007593840000")
        self.assertEqual(
            doc.findtext(account + "cac:FinancialInstitutionBranch/cbc:Name", namespaces=NAMESPACES),
            "Deployment Bank",
        )

    def _assert_supplier_upload(self, *, b2c: bool, credit: bool, retained: bool) -> None:
        self._write("efactura.company.cui", "RO87654321")
        original = self._invoice(b2c=b2c)
        invoice = self._credit_note(original) if credit else original
        service = EFacturaService()
        if retained:
            document = service._get_or_create_document(invoice)
            document.xml_content = self._xml(invoice)
            document.retry_count = 1
            document.mark_queued()
            document.save()
            retained_xml = document.xml_content
            self._write("efactura.company.cui", "RO11223344")
        upload_index = f"DR-{invoice.pk}"
        seen: list[tuple[str, dict[str, object]]] = []

        def transport(method: str, url: str, **kwargs: object) -> requests.Response:
            self.assertEqual(method, "POST")
            seen.append((url, kwargs))
            return self._response(f'<header ExecutionStatus="0" index_incarcare="{upload_index}"/>'.encode())

        with patch("apps.billing.efactura.client.safe_request", side_effect=transport):
            result = service.submit_invoice(invoice)
        self.assertTrue(result.success, result.error_message)
        document = EFacturaDocument.objects.get(invoice=invoice)
        self.assertEqual(document.status, EFacturaStatus.SUBMITTED.value)
        self.assertEqual(document.anaf_upload_index, upload_index)
        self.assertTrue(seen, "The submission must reach the HTTP boundary")
        url, request = seen[-1]
        self.assertTrue(url.endswith("/uploadb2c" if b2c else "/upload"), url)
        params = cast(dict[str, str], request["params"])
        self.assertEqual(params["standard"], "CN" if credit else "UBL")
        self.assertEqual(params["cif"], "87654321")
        uploaded = cast(bytes, request["data"])
        doc = etree.fromstring(uploaded)
        self.assertEqual(
            doc.findtext(
                "./cac:AccountingSupplierParty/cac:Party/cac:PartyIdentification/cbc:ID", namespaces=NAMESPACES
            ),
            params["cif"],
        )
        if retained:
            self.assertEqual(uploaded, retained_xml.encode())
            self.assertEqual(document.xml_content, retained_xml)

    def test_all_upload_routes_use_the_xml_supplier_cui(self) -> None:
        for b2c in (False, True):
            for credit in (False, True):
                with self.subTest(b2c=b2c, credit=credit):
                    self._assert_supplier_upload(b2c=b2c, credit=credit, retained=False)

    @override_settings(EFACTURA_COMPANY_CUI="")
    def test_xml_supplier_cui_suffices_when_deployment_cui_is_unset(self) -> None:
        for b2c in (False, True):
            for credit in (False, True):
                with self.subTest(b2c=b2c, credit=credit):
                    self._assert_supplier_upload(b2c=b2c, credit=credit, retained=False)

    def test_queued_retries_keep_the_retained_xml_supplier_cui(self) -> None:
        for b2c in (False, True):
            for credit in (False, True):
                with self.subTest(b2c=b2c, credit=credit):
                    self._assert_supplier_upload(b2c=b2c, credit=credit, retained=True)

    def test_xml_without_supplier_cui_is_refused_before_transport(self) -> None:
        invoice = self._invoice()
        document = EFacturaService()._get_or_create_document(invoice)
        document.xml_content = "<Invoice/>"
        document.mark_queued()
        document.save()
        self._write("efactura.validation.schematron_enabled", False)
        seen: list[str] = []

        def transport(method: str, url: str, **kwargs: object) -> requests.Response:
            seen.append(url)
            return self._response(b'<header ExecutionStatus="0" index_incarcare="UNBOUND"/>')

        with patch("apps.billing.efactura.client.safe_request", side_effect=transport):
            result = EFacturaService().submit_invoice(invoice)
        self.assertFalse(result.success)
        document.refresh_from_db()
        self.assertEqual(document.status, EFacturaStatus.ERROR.value)
        self.assertIn("supplier CUI", document.last_error)
        self.assertEqual(document.anaf_upload_index, "")
        self.assertEqual(seen, [])

    def test_issued_credit_note_rejects_a_non_romanian_supplier(self) -> None:
        original = self._invoice()
        note = self._credit_note(original)
        self._write("efactura.company.country_code", "DE")
        with self.assertRaisesRegex(XMLBuilderError, "Romanian statutory format"):
            builder_for(note).build()
        self._write("efactura.company.country_code", "RO")
        with (
            override_settings(COMPANY_COUNTRY_CODE="DE"),
            self.assertRaisesRegex(XMLBuilderError, "Romanian statutory format"),
        ):
            builder_for(note).build()

    def test_issued_credit_note_passes_strict_validation_and_submission(self) -> None:
        note = self._credit_note(self._invoice())
        self._write("efactura.validation.strict_mode", True)
        xml = self._xml(note)
        validation = CIUSROValidator().validate(xml)
        self.assertTrue(validation.is_valid, validation.errors)
        self.assertEqual(validation.warnings, [])
        response = self._response(b'<header ExecutionStatus="0" index_incarcare="STRICT-CN"/>')
        with patch("apps.billing.efactura.client.safe_request", return_value=response):
            result = EFacturaService().submit_invoice(note)
        self.assertTrue(result.success, result.error_message)
        document = EFacturaDocument.objects.get(invoice=note)
        self.assertEqual(document.status, EFacturaStatus.SUBMITTED.value)
        self.assertEqual(document.anaf_upload_index, "STRICT-CN")

        # Invoice recommendations and credit-note payment-code validation still apply.
        invoice_doc = etree.fromstring(self._xml(self._invoice()).encode())
        for path in ("./cac:PaymentMeans", "./cbc:DueDate"):
            element = invoice_doc.find(path, namespaces=NAMESPACES)
            self.assertIsNotNone(element)
            if element is not None:
                invoice_doc.remove(element)
        invalid_invoice = CIUSROValidator().validate(etree.tostring(invoice_doc).decode())
        self.assertFalse(invalid_invoice.is_valid)
        self.assertEqual({error.code for error in invalid_invoice.errors}, {"BR-RO-200", "BR-RO-300"})
        note_doc = etree.fromstring(xml.encode())
        payment = etree.SubElement(note_doc, etree.QName(NAMESPACES["cac"], "PaymentMeans"))
        etree.SubElement(payment, etree.QName(NAMESPACES["cbc"], "PaymentMeansCode")).text = "INVALID"
        invalid_note = CIUSROValidator().validate(etree.tostring(note_doc).decode())
        self.assertFalse(invalid_note.is_valid)
        self.assertIn("BR-CL-16", {error.code for error in invalid_note.errors})

    @override_settings(EFACTURA_ACCESS_TOKEN="")
    def test_cached_tokens_are_isolated_by_client_and_environment(self) -> None:
        clients: dict[tuple[ClientEnvironment, str], EFacturaClient] = {}
        for environment in (ClientEnvironment.TEST, ClientEnvironment.PRODUCTION):
            for identity in ("client-a", "client-b"):
                config = EFacturaConfig(identity, "secret", "12345678", environment=environment)
                client = EFacturaClient(config)
                clients[environment, identity] = client
                self._authorize(client, f"{environment.value}-{identity}")
        for (environment, identity), client in clients.items():
            with self.subTest(environment=environment, identity=identity):
                fresh = EFacturaClient(client.config)
                self.assertEqual(fresh._get_access_token(), f"{environment.value}-{identity}")

    @override_settings(EFACTURA_ACCESS_TOKEN="")
    def test_other_clients_cannot_read_or_refresh_another_clients_token(self) -> None:
        self._authorize(EFacturaClient(EFacturaConfig("client-a", "secret", "12345678")), "token-a")
        other = EFacturaClient(EFacturaConfig("client-b", "secret", "12345678"))
        self.assertIsNone(other._get_cached_token())
        with self.assertRaises(AuthenticationError):
            other._get_access_token()

    @override_settings(EFACTURA_ACCESS_TOKEN="")
    def test_environment_only_cache_entries_are_neither_written_nor_read(self) -> None:
        client = EFacturaClient()
        self._authorize(client, "scoped-token")
        self.assertIsNone(cache.get("efactura_token_test"))
        legacy = {
            "access_token": "legacy-token",
            "token_type": "Bearer",
            "expires_in": 3600,
            "refresh_token": "legacy-refresh",
            "scope": "",
            "expires_at": timezone.now() + timedelta(hours=1),
        }
        cache.clear()
        cache.set("efactura_token_test", legacy, timeout=3600)
        self.assertIsNone(EFacturaClient()._get_cached_token())

    @override_settings(EFACTURA_ACCESS_TOKEN="")
    def test_long_lived_default_clients_refresh_and_explicit_configs_stay_fixed(self) -> None:
        for inject_default in (False, True):
            with self.subTest(inject_default=inject_default):
                cache.clear()
                self._write("efactura.oauth.client_id", "old-client")
                self._write("efactura.oauth.client_secret", "old-secret")
                self._write("efactura.environment", "test")
                service = EFacturaService(EFacturaClient()) if inject_default else EFacturaService()
                self._authorize(service.client, "old-token")
                explicit_config = EFacturaConfig("explicit-client", "explicit-secret", "12345678")
                explicit = EFacturaService(EFacturaClient(explicit_config))
                self._authorize(explicit.client, "explicit-token")
                invoice = self._invoice()
                document = service._get_or_create_document(invoice)
                document.mark_queued()
                document.save()

                self._write("efactura.oauth.client_id", "new-client")
                self._write("efactura.oauth.client_secret", "new-secret")
                self._write("efactura.environment", "production")
                refreshed = EFacturaClient(EFacturaConfig.from_settings(environment="test"))
                self._authorize(refreshed, "new-test-token")
                self._authorize(EFacturaClient(), "new-prod-token")
                response = self._response(
                    f'<header ExecutionStatus="0" index_incarcare="FRESH-{invoice.pk}"/>'.encode()
                )
                with patch("apps.billing.efactura.client.safe_request", return_value=response) as transport:
                    result = service.submit_invoice(invoice)
                self.assertTrue(result.success, result.error_message)
                request = transport.call_args
                self.assertIsNotNone(request)
                self.assertEqual(request.args[1], "https://api.anaf.ro/test/FCTEL/rest/upload")
                headers = cast(dict[str, str], request.kwargs["headers"])
                self.assertEqual(headers["Authorization"], "Bearer new-test-token")
                document.refresh_from_db()
                self.assertEqual(document.status, EFacturaStatus.SUBMITTED.value)
                self.assertEqual(document.environment, "test")

                bound = explicit._client_for_environment("test")
                self.assertEqual(
                    (bound.config.client_id, bound.config.client_secret), ("explicit-client", "explicit-secret")
                )
                self.assertEqual(bound._get_access_token(), "explicit-token")
