"""
Comprehensive tests for apps.billing.efactura_service.

Covers EFacturaXMLGenerator, EFacturaSubmissionService, and all data classes
to achieve 90%+ line coverage of efactura_service.py.
"""

from __future__ import annotations

import re
from datetime import timedelta
from decimal import Decimal
from unittest.mock import Mock, patch
from xml.etree import ElementTree as ET

from django.test import TestCase, override_settings
from django.utils import timezone

from apps.billing.efactura_service import (
    EFacturaStatus,
    EFacturaSubmissionResult,
    EFacturaSubmissionService,
    EFacturaValidationResult,
    EFacturaXMLGenerator,
    PartyInfo,
)
from tests.factories.billing_factories import (
    create_currency,
    create_customer,
    create_invoice,
    create_invoice_line,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

CBC = "urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2"
CAC = "urn:oasis:names:specification:ubl:schema:xsd:CommonAggregateComponents-2"
UBL = "urn:oasis:names:specification:ubl:schema:xsd:Invoice-2"

COMPANY_SETTINGS: dict[str, str | bool] = {
    "COMPANY_NAME": "Test SRL",
    "COMPANY_TAX_ID": "RO12345678",
    "COMPANY_REG_NO": "J40/123/2020",
    "COMPANY_ADDRESS": "Str. Test 1",
    # Names the canonical UBLInvoiceBuilder reads (the submission path delegates to it, #188)
    "EFACTURA_COMPANY_CUI": "RO12345678",
    "COMPANY_REGISTRATION_NUMBER": "J40/123/2020",
    "COMPANY_STREET": "Str. Test 1",
    "COMPANY_COUNTRY_CODE": "RO",
    "COMPANY_CITY": "Bucharest",
    "COMPANY_COUNTY": "Bucharest",
    "COMPANY_POSTAL_CODE": "010101",
    "COMPANY_COUNTRY": "RO",
    "COMPANY_EMAIL": "test@example.com",
    "COMPANY_PHONE": "+40700000000",
    "COMPANY_BANK_IBAN": "RO49AAAA1B31007593840000",
    "COMPANY_BANK_NAME": "Test Bank",
    "EFACTURA_PRODUCTION": False,
}


def _parse_xml(xml_string: str) -> ET.Element:
    """
    Parse an XML string produced by EFacturaXMLGenerator.

    The generator produces XML with duplicate namespace attributes (a known
    quirk of Python's stdlib ET when combining attrib dict xmlns entries with
    an explicit root.set("xmlns", ...)). We strip duplicate xmlns attributes
    with a regex before parsing so that the strict stdlib XML parser accepts it.
    """
    if xml_string.startswith("<?xml"):
        xml_string = xml_string[xml_string.index("?>") + 2 :].strip()

    # Remove duplicate xmlns declarations produced by the generator.
    # Keep the first occurrence of each xmlns:* attribute.
    seen: set[str] = set()

    def _dedup(m: re.Match) -> str:
        attr = m.group(1)
        if attr in seen:
            return ""
        seen.add(attr)
        return m.group(0)

    xml_string = re.sub(r'(xmlns(?::\w+)?)="[^"]*"', _dedup, xml_string)
    # Clean up extra whitespace left by removed attrs
    xml_string = re.sub(r"\s{2,}", " ", xml_string)
    # S314: using ET for test-only parsing of internally generated XML — not untrusted user input
    return ET.fromstring(xml_string)  # noqa: S314


def _find_text(root: ET.Element, *tags: str) -> str | None:
    """Walk a chain of qualified tag names and return the final element's text."""
    elem: ET.Element | None = root
    for tag in tags:
        assert elem is not None
        elem = elem.find(f"{{{CAC}}}{tag}") or elem.find(f"{{{CBC}}}{tag}")
        if elem is None:
            return None
    return elem.text if elem is not None else None


def _find_cbc(root: ET.Element, tag: str) -> ET.Element | None:
    return root.find(f".//{{{CBC}}}{tag}")


def _find_cac(root: ET.Element, tag: str) -> ET.Element | None:
    return root.find(f".//{{{CAC}}}{tag}")


# ============================================================================
# Data-class tests
# ============================================================================


class EFacturaStatusTest(TestCase):
    """Tests for EFacturaStatus StrEnum."""

    def test_status_values(self) -> None:
        self.assertEqual(EFacturaStatus.PENDING, "pending")
        self.assertEqual(EFacturaStatus.SUBMITTED, "submitted")
        self.assertEqual(EFacturaStatus.ACCEPTED, "accepted")
        self.assertEqual(EFacturaStatus.REJECTED, "rejected")
        self.assertEqual(EFacturaStatus.PROCESSING, "processing")
        self.assertEqual(EFacturaStatus.ERROR, "error")

    def test_status_is_str(self) -> None:
        self.assertIsInstance(EFacturaStatus.PENDING, str)


class EFacturaSubmissionResultTest(TestCase):
    """Tests for EFacturaSubmissionResult dataclass."""

    def test_defaults(self) -> None:
        result = EFacturaSubmissionResult(success=True)
        self.assertTrue(result.success)
        self.assertIsNone(result.efactura_id)
        self.assertIsNone(result.upload_index)
        self.assertEqual(result.status, EFacturaStatus.PENDING)
        self.assertEqual(result.message, "")
        self.assertEqual(result.errors, [])
        self.assertIsNone(result.xml_content)
        self.assertEqual(result.response_data, {})

    def test_error_result(self) -> None:
        result = EFacturaSubmissionResult(
            success=False,
            status=EFacturaStatus.ERROR,
            message="boom",
            errors=["line 1"],
        )
        self.assertFalse(result.success)
        self.assertEqual(result.status, EFacturaStatus.ERROR)
        self.assertEqual(result.errors, ["line 1"])

    def test_mutable_defaults_are_independent(self) -> None:
        r1 = EFacturaSubmissionResult(success=True)
        r2 = EFacturaSubmissionResult(success=True)
        r1.errors.append("x")
        self.assertEqual(r2.errors, [])


class EFacturaValidationResultTest(TestCase):
    """Tests for EFacturaValidationResult dataclass."""

    def test_is_valid_true_with_empty_errors(self) -> None:
        result = EFacturaValidationResult(is_valid=True)
        self.assertTrue(result.is_valid)
        self.assertEqual(result.errors, [])
        self.assertEqual(result.warnings, [])

    def test_is_valid_false_with_errors(self) -> None:
        result = EFacturaValidationResult(is_valid=False, errors=["Missing number"])
        self.assertFalse(result.is_valid)
        self.assertIn("Missing number", result.errors)

    def test_warnings_independent_of_validity(self) -> None:
        result = EFacturaValidationResult(is_valid=True, warnings=["No due date"])
        self.assertTrue(result.is_valid)
        self.assertIn("No due date", result.warnings)


class PartyInfoTest(TestCase):
    """Tests for PartyInfo dataclass."""

    def test_required_fields(self) -> None:
        party = PartyInfo(
            name="ACME SRL",
            registration_name="ACME SRL",
            tax_id="RO99999999",
            country_code="RO",
            city="Cluj",
            postal_code="400001",
            street_address="Str. Principala 1",
        )
        self.assertEqual(party.name, "ACME SRL")
        self.assertEqual(party.email, "")
        self.assertEqual(party.bank_account, "")


# ============================================================================
# EFacturaXMLGenerator — validation tests
# ============================================================================


@override_settings(**COMPANY_SETTINGS)
class EFacturaValidationTest(TestCase):
    """Tests for _validate_invoice_for_efactura."""

    def setUp(self) -> None:
        self.generator = EFacturaXMLGenerator()
        self.currency = create_currency("RON")
        self.customer = create_customer()

    def _make_invoice(self, **kwargs):
        """Create an invoice with all required fields for e-Factura validation."""
        number = kwargs.pop("number", "INV-VAL-001")
        total_cents = kwargs.pop("total_cents", 12100)
        invoice = create_invoice(
            self.customer,
            self.currency,
            number=number,
            total_cents=total_cents,
        )
        # Apply additional attributes directly on the model instance
        invoice.subtotal_cents = kwargs.pop("subtotal_cents", 10000)
        invoice.bill_to_name = kwargs.pop("bill_to_name", "Test Client SRL")
        invoice.bill_to_country = kwargs.pop("bill_to_country", "RO")
        invoice.issued_at = kwargs.pop("issued_at", timezone.now())
        for k, v in kwargs.items():
            setattr(invoice, k, v)
        invoice.save()
        create_invoice_line(invoice)
        return invoice

    def test_valid_invoice_passes(self) -> None:
        invoice = self._make_invoice()
        result = self.generator._validate_invoice_for_efactura(invoice)
        self.assertTrue(result.is_valid)
        self.assertEqual(result.errors, [])

    def test_missing_invoice_number_produces_error(self) -> None:
        invoice = self._make_invoice()
        invoice.number = ""
        result = self.generator._validate_invoice_for_efactura(invoice)
        self.assertFalse(result.is_valid)
        self.assertTrue(any("number" in e.lower() for e in result.errors))

    def test_missing_issued_at_produces_error(self) -> None:
        invoice = self._make_invoice()
        invoice.issued_at = None
        result = self.generator._validate_invoice_for_efactura(invoice)
        self.assertFalse(result.is_valid)
        self.assertTrue(any("issue date" in e.lower() for e in result.errors))

    def test_missing_bill_to_name_produces_error(self) -> None:
        invoice = self._make_invoice()
        invoice.bill_to_name = ""
        result = self.generator._validate_invoice_for_efactura(invoice)
        self.assertFalse(result.is_valid)
        self.assertTrue(any("customer name" in e.lower() for e in result.errors))

    @override_settings(COMPANY_TAX_ID="")
    def test_missing_company_tax_id_produces_error(self) -> None:
        invoice = self._make_invoice()
        result = self.generator._validate_invoice_for_efactura(invoice)
        self.assertFalse(result.is_valid)
        self.assertTrue(any("COMPANY_TAX_ID" in e for e in result.errors))

    def test_zero_total_produces_error(self) -> None:
        invoice = self._make_invoice()
        invoice.total_cents = 0
        result = self.generator._validate_invoice_for_efactura(invoice)
        self.assertFalse(result.is_valid)
        self.assertTrue(any("total" in e.lower() for e in result.errors))

    def test_negative_total_produces_error(self) -> None:
        invoice = self._make_invoice()
        invoice.total_cents = -100
        result = self.generator._validate_invoice_for_efactura(invoice)
        self.assertFalse(result.is_valid)

    def test_no_lines_produces_error(self) -> None:
        currency = create_currency("EUR")
        customer = create_customer("NoLine Co")
        invoice = create_invoice(customer, currency, number="INV-NOLINE-001", total_cents=5000)
        invoice.subtotal_cents = 5000
        invoice.bill_to_name = "NoLine Client"
        invoice.bill_to_country = "RO"
        invoice.issued_at = timezone.now()
        invoice.save()
        # No lines added
        result = self.generator._validate_invoice_for_efactura(invoice)
        self.assertFalse(result.is_valid)
        self.assertTrue(any("line" in e.lower() for e in result.errors))

    def test_missing_due_at_produces_warning(self) -> None:
        invoice = self._make_invoice()
        invoice.due_at = None
        result = self.generator._validate_invoice_for_efactura(invoice)
        self.assertTrue(result.is_valid)  # still valid
        self.assertTrue(any("due date" in w.lower() for w in result.warnings))

    def test_ro_customer_without_tax_id_produces_warning(self) -> None:
        invoice = self._make_invoice()
        invoice.bill_to_country = "RO"
        invoice.bill_to_tax_id = ""
        result = self.generator._validate_invoice_for_efactura(invoice)
        self.assertTrue(result.is_valid)
        self.assertTrue(any("tax id" in w.lower() or "cui" in w.lower() or "cif" in w.lower() for w in result.warnings))

    def test_non_ro_customer_without_tax_id_no_warning(self) -> None:
        invoice = self._make_invoice()
        invoice.bill_to_country = "DE"
        invoice.bill_to_tax_id = ""
        result = self.generator._validate_invoice_for_efactura(invoice)
        # No warning about tax ID for non-RO customer
        self.assertFalse(any("cui" in w.lower() or "cif" in w.lower() for w in result.warnings))


# ============================================================================
# EFacturaXMLGenerator — full XML generation tests
# ============================================================================


@override_settings(**COMPANY_SETTINGS)
class EFacturaXMLGeneratorTest(TestCase):
    """generate_invoice_xml delegates to the canonical UBL builder (#188)."""

    def setUp(self) -> None:
        self.generator = EFacturaXMLGenerator()
        self.currency = create_currency("RON")
        self.customer = create_customer("XML Test Co")
        now = timezone.now()
        self.invoice = create_invoice(
            self.customer, self.currency, number="INV-XML-001", total_cents=12100,
        )
        self.invoice.subtotal_cents = 10000
        self.invoice.tax_cents = 2100
        self.invoice.bill_to_name = "Client SRL"
        self.invoice.bill_to_tax_id = "RO11111111"
        self.invoice.bill_to_country = "RO"
        self.invoice.issued_at = now
        self.invoice.due_at = now + timedelta(days=30)
        self.invoice.save()
        create_invoice_line(
            self.invoice, description="Hosting Plan A", quantity=1,
            unit_price_cents=10000, tax_rate=Decimal("0.21"),
        )

    def test_generate_invoice_xml_returns_ok(self) -> None:
        result = self.generator.generate_invoice_xml(self.invoice)
        self.assertTrue(result.is_ok())

    def test_delegates_to_ubl_builder(self) -> None:
        from apps.billing.efactura.xml_builder import UBLInvoiceBuilder  # noqa: PLC0415

        result = self.generator.generate_invoice_xml(self.invoice)
        self.assertEqual(result.unwrap(), UBLInvoiceBuilder(self.invoice).build())

    def test_returns_cius_ro_ubl(self) -> None:
        xml = self.generator.generate_invoice_xml(self.invoice).unwrap()
        self.assertIn("<?xml", xml)
        self.assertIn("INV-XML-001", xml)
        self.assertIn("CustomizationID", xml)

    def test_generates_canonical_b2c_ubl_with_anonymous_buyer_identifier(self) -> None:
        """The legacy entry point must use the same compliant B2C builder as the primary service."""
        self.invoice.bill_to_tax_id = ""

        xml = self.generator.generate_invoice_xml(self.invoice).unwrap()

        self.assertIn("0000000000000", xml)
        self.assertNotIn("RO:CNP", xml)

    def test_incomplete_invoice_returns_err(self) -> None:
        bad = create_invoice(self.customer, self.currency, number="INV-BAD", total_cents=100)
        result = self.generator.generate_invoice_xml(bad)  # no lines / bill_to -> validation fails
        self.assertTrue(result.is_err())


@override_settings(**COMPANY_SETTINGS)
@override_settings(DEBUG=True)
class EFacturaSubmissionServiceTest(TestCase):
    """Tests for EFacturaSubmissionService (run with DEBUG=True for simulation mode)."""

    def setUp(self) -> None:
        self.service = EFacturaSubmissionService()
        self.currency = create_currency("RON")
        self.customer = create_customer("Submission Test Co")
        now = timezone.now()
        self.invoice = create_invoice(
            self.customer,
            self.currency,
            number="INV-SUBMIT-001",
            total_cents=12100,
        )
        self.invoice.subtotal_cents = 10000
        self.invoice.tax_cents = 2100
        self.invoice.bill_to_name = "Submission Client SRL"
        self.invoice.bill_to_country = "RO"
        self.invoice.bill_to_tax_id = "RO22222222"
        self.invoice.issued_at = now
        self.invoice.due_at = now + timedelta(days=30)
        self.invoice.save()
        self.invoice.notes = ""
        create_invoice_line(self.invoice)

    # -- __init__ / config ----------------------------------------------------

    def test_service_uses_test_endpoint_when_not_production(self) -> None:
        self.assertIn("test", self.service.api_base)
        self.assertFalse(self.service.is_production)

    @override_settings(EFACTURA_PRODUCTION=True)
    def test_service_uses_production_endpoint_when_configured(self) -> None:
        svc = EFacturaSubmissionService()
        self.assertIn("prod", svc.api_base)
        self.assertTrue(svc.is_production)

    # -- submit_invoice -------------------------------------------------------

    def test_submit_invoice_success(self) -> None:
        result = self.service.submit_invoice(self.invoice)
        self.assertTrue(result.success)
        self.assertEqual(result.status, EFacturaStatus.SUBMITTED)

    def test_submit_invoice_returns_efactura_id(self) -> None:
        result = self.service.submit_invoice(self.invoice)
        self.assertIsNotNone(result.efactura_id)
        self.assertIn("INV-SUBMIT-001", result.efactura_id)

    def test_submit_invoice_returns_upload_index(self) -> None:
        result = self.service.submit_invoice(self.invoice)
        self.assertIsNotNone(result.upload_index)
        self.assertTrue(result.upload_index.startswith("UI"))

    def test_submit_invoice_includes_xml_content(self) -> None:
        result = self.service.submit_invoice(self.invoice)
        self.assertIsNotNone(result.xml_content)
        self.assertIn("INV-SUBMIT-001", result.xml_content)

    def test_submit_invoice_includes_xml_hash(self) -> None:
        result = self.service.submit_invoice(self.invoice)
        self.assertIn("xml_hash", result.response_data)

    @override_settings(DEBUG=False)
    @patch("apps.billing.efactura.client.EFacturaClient")
    @patch("apps.billing.efactura.client.EFacturaConfig.from_settings")
    def test_submit_b2c_invoice_uses_b2c_endpoint(self, mock_from_settings, mock_client_class) -> None:
        """Every submission entry point must route a Romanian consumer invoice to /uploadb2c."""
        self.invoice.bill_to_tax_id = ""
        config = Mock()
        config.is_valid.return_value = True
        mock_from_settings.return_value = config
        client = mock_client_class.return_value
        client.upload_b2c.return_value = Mock(
            success=True,
            upload_index="B2C-LEGACY-1",
            raw_response={},
        )
        generated = Mock()
        generated.is_ok.return_value = True
        generated.unwrap.return_value = "<Invoice/>"

        with patch.object(self.service.xml_generator, "generate_invoice_xml", return_value=generated):
            result = self.service.submit_invoice(self.invoice)

        self.assertTrue(result.success)
        client.upload_b2c.assert_called_once_with("<Invoice/>")
        client.upload_invoice.assert_not_called()

    def test_submit_invoice_simulated_flag(self) -> None:
        result = self.service.submit_invoice(self.invoice)
        self.assertTrue(result.response_data.get("simulated"))

    def test_submit_invoice_invalid_invoice_returns_error(self) -> None:
        self.invoice.number = ""
        result = self.service.submit_invoice(self.invoice)
        self.assertFalse(result.success)
        self.assertEqual(result.status, EFacturaStatus.ERROR)

    def test_submit_invoice_invalid_has_errors_list(self) -> None:
        self.invoice.number = ""
        result = self.service.submit_invoice(self.invoice)
        self.assertIsInstance(result.errors, list)
        self.assertTrue(len(result.errors) > 0)

    def test_submit_invoice_message_contains_context(self) -> None:
        self.invoice.number = ""
        result = self.service.submit_invoice(self.invoice)
        self.assertIn("XML generation failed", result.message)

    # -- check_status ---------------------------------------------------------

    def test_check_status_returns_accepted(self) -> None:
        result = self.service.check_status("UI_SOME_INDEX_123")
        self.assertTrue(result.success)
        self.assertEqual(result.status, EFacturaStatus.ACCEPTED)

    def test_check_status_preserves_upload_index(self) -> None:
        result = self.service.check_status("UI_SOME_INDEX_123")
        self.assertEqual(result.upload_index, "UI_SOME_INDEX_123")

    def test_check_status_has_message(self) -> None:
        result = self.service.check_status("UI_SOME_INDEX_123")
        self.assertNotEqual(result.message, "")

    # -- download_response ----------------------------------------------------

    def test_download_response_returns_err(self) -> None:
        result = self.service.download_response("SOME_DOWNLOAD_ID")
        self.assertFalse(result.is_ok())

    def test_download_response_error_message(self) -> None:
        result = self.service.download_response("SOME_DOWNLOAD_ID")
        self.assertIn("not configured", result.error.lower())

    def test_download_response_different_ids_all_fail(self) -> None:
        for download_id in ["ID1", "ID2", "ID3"]:
            result = self.service.download_response(download_id)
            self.assertFalse(result.is_ok())
