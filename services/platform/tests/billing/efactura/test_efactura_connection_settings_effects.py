"""Stored connection and validation settings must change real e-Factura effects."""

from __future__ import annotations

import base64
from typing import cast
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

import requests
from django.core.cache import cache
from django.test import TestCase, override_settings
from django.utils import timezone

from apps.billing.efactura.client import EFacturaClient
from apps.billing.efactura.intents import ensure_efactura_intent
from apps.billing.efactura.metrics import timed_operation
from apps.billing.efactura.models import EFacturaDocument, EFacturaStatus
from apps.billing.efactura.validator import CIUSROValidator
from apps.billing.efactura.xsd_validator import XSDValidator
from apps.billing.invoice_models import ISSUER_BUILTIN, Currency, Invoice
from apps.settings.models import SystemSetting
from apps.settings.services import SettingsService
from tests.factories.billing_factories import CustomerFactory

VALID_XML = """<Invoice xmlns="urn:oasis:names:specification:ubl:schema:xsd:Invoice-2"
 xmlns:cac="urn:oasis:names:specification:ubl:schema:xsd:CommonAggregateComponents-2"
 xmlns:cbc="urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2">
 <cbc:CustomizationID>urn:cen.eu:en16931:2017#compliant#urn:efactura.mfinante.ro:CIUS-RO:1.0.1</cbc:CustomizationID>
 <cbc:ID>EFFECT-001</cbc:ID>
 <cbc:IssueDate>2026-10-07</cbc:IssueDate>
 <cbc:DueDate>2026-11-07</cbc:DueDate>
 <cbc:InvoiceTypeCode>380</cbc:InvoiceTypeCode>
 <cbc:DocumentCurrencyCode>RON</cbc:DocumentCurrencyCode>
 <cac:AccountingSupplierParty><cac:Party>
  <cac:PartyIdentification><cbc:ID>12345678</cbc:ID></cac:PartyIdentification>
  <cac:PostalAddress><cac:Country><cbc:IdentificationCode>RO</cbc:IdentificationCode></cac:Country></cac:PostalAddress>
  <cac:PartyLegalEntity><cbc:RegistrationName>Supplier SRL</cbc:RegistrationName></cac:PartyLegalEntity>
 </cac:Party></cac:AccountingSupplierParty>
 <cac:AccountingCustomerParty><cac:Party>
  <cac:PartyIdentification><cbc:ID>87654321</cbc:ID></cac:PartyIdentification>
  <cac:PostalAddress><cac:Country><cbc:IdentificationCode>RO</cbc:IdentificationCode></cac:Country></cac:PostalAddress>
  <cac:PartyLegalEntity><cbc:RegistrationName>Customer SRL</cbc:RegistrationName></cac:PartyLegalEntity>
 </cac:Party></cac:AccountingCustomerParty>
 <cac:PaymentMeans><cbc:PaymentMeansCode>30</cbc:PaymentMeansCode></cac:PaymentMeans>
 <cac:TaxTotal>
  <cbc:TaxAmount currencyID="RON">21.00</cbc:TaxAmount>
  <cac:TaxSubtotal>
   <cbc:TaxableAmount currencyID="RON">100.00</cbc:TaxableAmount>
   <cbc:TaxAmount currencyID="RON">21.00</cbc:TaxAmount>
   <cac:TaxCategory><cbc:ID>S</cbc:ID><cbc:Percent>21.00</cbc:Percent>
    <cac:TaxScheme><cbc:ID>VAT</cbc:ID></cac:TaxScheme>
   </cac:TaxCategory>
  </cac:TaxSubtotal>
 </cac:TaxTotal>
 <cac:LegalMonetaryTotal>
  <cbc:LineExtensionAmount currencyID="RON">100.00</cbc:LineExtensionAmount>
  <cbc:TaxExclusiveAmount currencyID="RON">100.00</cbc:TaxExclusiveAmount>
  <cbc:TaxInclusiveAmount currencyID="RON">121.00</cbc:TaxInclusiveAmount>
  <cbc:PayableAmount currencyID="RON">121.00</cbc:PayableAmount>
 </cac:LegalMonetaryTotal>
 <cac:InvoiceLine>
  <cbc:ID>1</cbc:ID><cbc:InvoicedQuantity unitCode="C62">1</cbc:InvoicedQuantity>
  <cbc:LineExtensionAmount currencyID="RON">100.00</cbc:LineExtensionAmount>
  <cac:Item><cbc:Name>Hosting</cbc:Name><cac:ClassifiedTaxCategory>
   <cbc:ID>S</cbc:ID><cbc:Percent>21.00</cbc:Percent>
   <cac:TaxScheme><cbc:ID>VAT</cbc:ID></cac:TaxScheme>
  </cac:ClassifiedTaxCategory></cac:Item>
  <cac:Price><cbc:PriceAmount currencyID="RON">100.00</cbc:PriceAmount></cac:Price>
 </cac:InvoiceLine>
</Invoice>"""


@override_settings(
    EFACTURA_ENABLED=True,
    EFACTURA_ENVIRONMENT="test",
    EFACTURA_CLIENT_ID="deployment-client",
    EFACTURA_CLIENT_SECRET="deployment-secret",
    EFACTURA_COMPANY_CUI="12345678",
    EFACTURA_ACCESS_TOKEN="deployment-token",
    EFACTURA_OAUTH_CLIENT_ID="",
    EFACTURA_OAUTH_CLIENT_SECRET="",
    EFACTURA_OAUTH_REDIRECT_URI="https://deployment.example.test/callback",
    EFACTURA_VALIDATION_SCHEMATRON_ENABLED=True,
    EFACTURA_VALIDATION_STRICT_MODE=False,
    EFACTURA_VALIDATION_XSD_ENABLED=True,
    EFACTURA_METRICS_ENABLED=True,
)
class EFacturaConnectionSettingEffectTests(TestCase):
    def setUp(self) -> None:
        cache.clear()
        self.addCleanup(cache.clear)
        SystemSetting.objects.filter(key__startswith="efactura.").delete()

    def _write(self, key: str, value: str | bool) -> None:
        with self.captureOnCommitCallbacks(execute=True):
            result = SettingsService.update_setting(key, value)
        self.assertTrue(result.is_ok(), result)

    @staticmethod
    def _response(content: bytes) -> requests.Response:
        response = requests.Response()
        response.status_code = 200
        response._content = content
        return response

    def _exchange(self, redirect_uri: str) -> dict[str, object]:
        requests_seen: list[dict[str, object]] = []

        def transport(method: str, url: str, **kwargs: object) -> requests.Response:
            self.assertEqual(method, "POST")
            self.assertEqual(url, "https://logincert.anaf.ro/anaf-oauth2/v1/token")
            requests_seen.append(kwargs)
            return self._response(b'{"access_token":"issued-token","token_type":"Bearer","expires_in":3600}')

        with patch("apps.billing.efactura.client.safe_request", side_effect=transport):
            token = EFacturaClient().exchange_code_for_token("authorization-code", redirect_uri)
        self.assertEqual(token.access_token, "issued-token")
        self.assertTrue(requests_seen, "Token exchange must reach the HTTP boundary")
        return requests_seen[-1]

    @staticmethod
    def _basic_credentials(request: dict[str, object]) -> str:
        headers = cast(dict[str, str], request["headers"])
        scheme, encoded = headers["Authorization"].split(" ", 1)
        if scheme != "Basic":
            raise AssertionError("OAuth must use HTTP Basic client authentication")
        return base64.b64decode(encoded).decode("utf-8")

    def test_enabled_controls_persisted_submission_intent(self) -> None:
        currency, _ = Currency.objects.get_or_create(code="RON", defaults={"symbol": "lei"})
        invoice = Invoice.objects.bulk_create(
            [
                Invoice(
                    customer=CustomerFactory(),
                    currency=currency,
                    number="CONNECTION-EFFECT-001",
                    status="issued",
                    issued_at=timezone.now(),
                    issuer_provider=ISSUER_BUILTIN,
                    bill_to_country="RO",
                )
            ]
        )[0]
        self._write("efactura.enabled", False)
        self.assertIsNone(ensure_efactura_intent(invoice))
        self.assertFalse(EFacturaDocument.objects.filter(invoice=invoice).exists())

        self._write("efactura.enabled", True)
        ensure_efactura_intent(invoice)
        document = EFacturaDocument.objects.get(invoice=invoice)
        self.assertEqual(document.status, EFacturaStatus.QUEUED.value)

    def test_environment_changes_the_upload_destination(self) -> None:
        self._write("efactura.environment", "production")
        response = self._response(b'<header ExecutionStatus="0" index_incarcare="EFFECT-UPLOAD"/>')
        with patch("apps.billing.efactura.client.safe_request", return_value=response) as transport:
            result = EFacturaClient().upload_invoice(VALID_XML)
        self.assertTrue(result.success, result.message)
        self.assertEqual(result.upload_index, "EFFECT-UPLOAD")
        request = transport.call_args
        self.assertIsNotNone(request)
        self.assertEqual(request.args[1], "https://api.anaf.ro/prod/FCTEL/rest/upload")

        self._write("efactura.environment", "test")
        with patch("apps.billing.efactura.client.safe_request", return_value=response) as transport:
            result = EFacturaClient().upload_invoice(VALID_XML)
        self.assertTrue(result.success, result.message)
        self.assertEqual(transport.call_args.args[1], "https://api.anaf.ro/test/FCTEL/rest/upload")

    def test_client_id_reaches_oauth_basic_authentication(self) -> None:
        self._write("efactura.oauth.client_id", "staff-client")
        self.assertEqual(
            self._basic_credentials(self._exchange("https://explicit.example.test/callback")),
            "staff-client:deployment-secret",
        )
        self._write("efactura.oauth.client_id", "")
        refused = EFacturaClient().upload_invoice(VALID_XML)
        self.assertFalse(refused.success)
        self.assertTrue(refused.configuration_error)

    def test_client_secret_reaches_oauth_basic_authentication(self) -> None:
        self._write("efactura.oauth.client_secret", "staff-secret")
        self.assertEqual(
            self._basic_credentials(self._exchange("https://explicit.example.test/callback")),
            "deployment-client:staff-secret",
        )
        row = SystemSetting.objects.get(key="efactura.oauth.client_secret")
        self.assertTrue(row.is_sensitive)
        self.assertNotEqual(row.value, "staff-secret")
        self._write("efactura.oauth.client_secret", "")
        refused = EFacturaClient().upload_invoice(VALID_XML)
        self.assertFalse(refused.success)
        self.assertTrue(refused.configuration_error)

    def test_redirect_uri_reaches_authorization_and_token_exchange(self) -> None:
        self._write("efactura.oauth.redirect_uri", "https://staff.example.test/callback")
        request = self._exchange("")
        self.assertEqual(cast(dict[str, str], request["data"])["redirect_uri"], "https://staff.example.test/callback")
        client = EFacturaClient()
        query = parse_qs(urlsplit(client.get_authorization_url("", "csrf-state")).query)
        self.assertEqual(query["redirect_uri"], ["https://staff.example.test/callback"])
        explicit = "https://explicit.example.test/callback"
        self.assertEqual(cast(dict[str, str], self._exchange(explicit)["data"])["redirect_uri"], explicit)
        query = parse_qs(urlsplit(client.get_authorization_url(explicit, "csrf-state")).query)
        self.assertEqual(query["redirect_uri"], [explicit])

    def test_schematron_toggle_controls_native_business_rule_rejection(self) -> None:
        validator = CIUSROValidator()
        self._write("efactura.validation.schematron_enabled", False)
        result = validator.validate("<Invoice/>")
        self.assertTrue(result.is_valid, result.errors)
        self.assertEqual(result.errors, [])
        self.assertFalse(validator.validate("<Invoice").is_valid)

        self._write("efactura.validation.schematron_enabled", True)
        result = validator.validate("<Invoice/>")
        self.assertFalse(result.is_valid)
        self.assertIn("BR-01", [error.code for error in result.errors])

    def test_strict_mode_refuses_warning_only_xml(self) -> None:
        validator = CIUSROValidator()
        xml = VALID_XML.replace(" <cbc:DueDate>2026-11-07</cbc:DueDate>\n", "")
        self._write("efactura.validation.strict_mode", False)
        relaxed = validator.validate(xml)
        self.assertTrue(relaxed.is_valid, relaxed.errors)
        self.assertEqual([warning.code for warning in relaxed.warnings], ["BR-RO-300"])

        self._write("efactura.validation.strict_mode", True)
        strict = validator.validate(xml)
        self.assertFalse(strict.is_valid)
        self.assertEqual([error.code for error in strict.errors], ["BR-RO-300"])
        self.assertEqual([warning.code for warning in strict.warnings], ["BR-RO-300"])

    def test_xsd_toggle_controls_structural_validation(self) -> None:
        validator = XSDValidator()
        xml = VALID_XML.replace(
            '<Invoice xmlns="urn:oasis:names:specification:ubl:schema:xsd:Invoice-2"',
            '<Unexpected xmlns="urn:connection-effects"',
        ).replace("</Invoice>", "</Unexpected>")
        self._write("efactura.validation.xsd_enabled", False)
        self.assertTrue(validator.validate(xml).is_valid)

        self._write("efactura.validation.xsd_enabled", True)
        result = validator.validate(xml)
        self.assertFalse(result.is_valid)
        self.assertEqual(len(result.errors), 1)
        self.assertIn("Unknown document type", result.errors[0].message)

    def test_metrics_enabled_controls_operation_timing_output(self) -> None:
        @timed_operation("connection-effect")
        def operation() -> str:
            return "operation-result"

        self._write("efactura.metrics.enabled", True)
        with self.assertLogs("apps.billing.efactura.metrics", level="DEBUG") as captured:
            self.assertEqual(operation(), "operation-result")
        self.assertTrue(any("connection-effect:" in message for message in captured.output))

        self._write("efactura.metrics.enabled", False)
        with self.assertNoLogs("apps.billing.efactura.metrics", level="DEBUG"):
            self.assertEqual(operation(), "operation-result")
