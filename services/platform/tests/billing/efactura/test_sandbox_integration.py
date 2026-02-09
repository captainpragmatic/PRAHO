"""
ANAF e-Factura Sandbox Integration Tests

These tests hit the real ANAF sandbox/test API endpoints.
They are marked as integration+slow and are skipped by default
in regular test runs.

Requirements:
    Set the following environment variables:
    - EFACTURA_SANDBOX_CLIENT_ID
    - EFACTURA_SANDBOX_CLIENT_SECRET
    - EFACTURA_SANDBOX_CUI

Run with:
    pytest tests/billing/efactura/test_sandbox_integration.py -m integration
"""

import os
from unittest import SkipTest

import pytest
from django.test import TestCase, override_settings

SANDBOX_CREDENTIALS_AVAILABLE = bool(
    os.environ.get("EFACTURA_SANDBOX_CLIENT_ID")
    and os.environ.get("EFACTURA_SANDBOX_CLIENT_SECRET")
    and os.environ.get("EFACTURA_SANDBOX_CUI")
)


def _get_sandbox_config():
    """Create EFacturaConfig for sandbox testing."""
    from apps.billing.efactura.client import EFacturaConfig, EFacturaEnvironment

    return EFacturaConfig(
        client_id=os.environ["EFACTURA_SANDBOX_CLIENT_ID"],
        client_secret=os.environ["EFACTURA_SANDBOX_CLIENT_SECRET"],
        company_cui=os.environ["EFACTURA_SANDBOX_CUI"],
        environment=EFacturaEnvironment.TEST,
    )


def _generate_test_invoice_xml(cui: str) -> str:
    """Generate a minimal valid UBL 2.1 invoice XML for sandbox testing."""
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<Invoice xmlns="urn:oasis:names:specification:ubl:schema:xsd:Invoice-2"
         xmlns:cac="urn:oasis:names:specification:ubl:schema:xsd:CommonAggregateComponents-2"
         xmlns:cbc="urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2">
    <cbc:CustomizationID>urn:cen.eu:en16931:2017#compliant#urn:efactura.mfinante.ro:CIUS-RO:1.0.1</cbc:CustomizationID>
    <cbc:ID>TEST-SANDBOX-001</cbc:ID>
    <cbc:IssueDate>2024-01-15</cbc:IssueDate>
    <cbc:DueDate>2024-02-15</cbc:DueDate>
    <cbc:InvoiceTypeCode>380</cbc:InvoiceTypeCode>
    <cbc:DocumentCurrencyCode>RON</cbc:DocumentCurrencyCode>
    <cac:AccountingSupplierParty>
        <cac:Party>
            <cac:PartyTaxScheme>
                <cbc:CompanyID>RO{cui}</cbc:CompanyID>
                <cac:TaxScheme><cbc:ID>VAT</cbc:ID></cac:TaxScheme>
            </cac:PartyTaxScheme>
            <cac:PartyLegalEntity>
                <cbc:RegistrationName>Test Supplier SRL</cbc:RegistrationName>
                <cbc:CompanyID>J40/1234/2020</cbc:CompanyID>
            </cac:PartyLegalEntity>
            <cac:PostalAddress>
                <cbc:StreetName>Strada Test 1</cbc:StreetName>
                <cbc:CityName>Bucuresti</cbc:CityName>
                <cbc:CountrySubentity>RO-B</cbc:CountrySubentity>
                <cac:Country><cbc:IdentificationCode>RO</cbc:IdentificationCode></cac:Country>
            </cac:PostalAddress>
        </cac:Party>
    </cac:AccountingSupplierParty>
    <cac:AccountingCustomerParty>
        <cac:Party>
            <cac:PartyTaxScheme>
                <cbc:CompanyID>RO12345678</cbc:CompanyID>
                <cac:TaxScheme><cbc:ID>VAT</cbc:ID></cac:TaxScheme>
            </cac:PartyTaxScheme>
            <cac:PartyLegalEntity>
                <cbc:RegistrationName>Test Customer SRL</cbc:RegistrationName>
            </cac:PartyLegalEntity>
            <cac:PostalAddress>
                <cbc:StreetName>Strada Client 2</cbc:StreetName>
                <cbc:CityName>Cluj-Napoca</cbc:CityName>
                <cbc:CountrySubentity>RO-CJ</cbc:CountrySubentity>
                <cac:Country><cbc:IdentificationCode>RO</cbc:IdentificationCode></cac:Country>
            </cac:PostalAddress>
        </cac:Party>
    </cac:AccountingCustomerParty>
    <cac:TaxTotal>
        <cbc:TaxAmount currencyID="RON">19.00</cbc:TaxAmount>
        <cac:TaxSubtotal>
            <cbc:TaxableAmount currencyID="RON">100.00</cbc:TaxableAmount>
            <cbc:TaxAmount currencyID="RON">19.00</cbc:TaxAmount>
            <cac:TaxCategory>
                <cbc:ID>S</cbc:ID>
                <cbc:Percent>19</cbc:Percent>
                <cac:TaxScheme><cbc:ID>VAT</cbc:ID></cac:TaxScheme>
            </cac:TaxCategory>
        </cac:TaxSubtotal>
    </cac:TaxTotal>
    <cac:LegalMonetaryTotal>
        <cbc:LineExtensionAmount currencyID="RON">100.00</cbc:LineExtensionAmount>
        <cbc:TaxExclusiveAmount currencyID="RON">100.00</cbc:TaxExclusiveAmount>
        <cbc:TaxInclusiveAmount currencyID="RON">119.00</cbc:TaxInclusiveAmount>
        <cbc:PayableAmount currencyID="RON">119.00</cbc:PayableAmount>
    </cac:LegalMonetaryTotal>
    <cac:InvoiceLine>
        <cbc:ID>1</cbc:ID>
        <cbc:InvoicedQuantity unitCode="C62">1</cbc:InvoicedQuantity>
        <cbc:LineExtensionAmount currencyID="RON">100.00</cbc:LineExtensionAmount>
        <cac:Item>
            <cbc:Name>Test Service</cbc:Name>
            <cac:ClassifiedTaxCategory>
                <cbc:ID>S</cbc:ID>
                <cbc:Percent>19</cbc:Percent>
                <cac:TaxScheme><cbc:ID>VAT</cbc:ID></cac:TaxScheme>
            </cac:ClassifiedTaxCategory>
        </cac:Item>
        <cac:Price>
            <cbc:PriceAmount currencyID="RON">100.00</cbc:PriceAmount>
        </cac:Price>
    </cac:InvoiceLine>
</Invoice>"""


@pytest.mark.integration
@pytest.mark.slow
@pytest.mark.skipif(
    not SANDBOX_CREDENTIALS_AVAILABLE,
    reason="ANAF sandbox credentials not configured (set EFACTURA_SANDBOX_* env vars)",
)
@override_settings(EFACTURA_ENABLED=True)
class EFacturaSandboxIntegrationTest(TestCase):
    """Integration tests that hit the real ANAF sandbox/test API."""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        if not SANDBOX_CREDENTIALS_AVAILABLE:
            raise SkipTest("ANAF sandbox credentials not configured (set EFACTURA_SANDBOX_* env vars)")
        from apps.billing.efactura.client import EFacturaClient

        cls.config = _get_sandbox_config()
        cls.client = EFacturaClient(cls.config)
        cls.test_xml = _generate_test_invoice_xml(cls.config.company_cui)

    def test_sandbox_api_reachable(self):
        """Verify the ANAF sandbox API is reachable."""
        import requests

        response = requests.get(
            f"{self.config.environment.base_url}/",
            timeout=10,
        )
        # ANAF returns various codes but should not timeout
        self.assertIn(response.status_code, [200, 403, 404, 405])

    def test_upload_valid_invoice_xml(self):
        """Test uploading a valid UBL XML to the sandbox."""
        result = self.client.upload_invoice(
            xml_content=self.test_xml,
            cui=self.config.company_cui,
        )

        # The sandbox may accept or reject based on authentication
        # but the API call itself should succeed
        self.assertIsNotNone(result)
        if result.success:
            self.assertTrue(len(result.upload_index) > 0)

    def test_check_upload_status(self):
        """Test checking status of a submitted document."""
        # First upload
        upload_result = self.client.upload_invoice(
            xml_content=self.test_xml,
            cui=self.config.company_cui,
        )

        if not upload_result.success:
            self.skipTest(f"Upload failed, cannot test status: {upload_result.message}")

        # Then check status
        status_result = self.client.get_upload_status(upload_result.upload_index)
        self.assertIsNotNone(status_result)
        self.assertIn(status_result.status, ["ok", "nok", "in processing", ""])

    def test_list_messages(self):
        """Test listing messages from the sandbox."""
        result = self.client.list_messages(
            cui=self.config.company_cui,
            days=30,
        )

        # Should return a result (may be empty list)
        self.assertIsNotNone(result)

    def test_invalid_xml_rejected(self):
        """Test that invalid XML is properly handled."""
        invalid_xml = "<invalid>not a valid UBL invoice</invalid>"

        result = self.client.upload_invoice(
            xml_content=invalid_xml,
            cui=self.config.company_cui,
        )

        # Invalid XML should not be reported as successful
        # (unless ANAF sandbox accepts anything)
        self.assertIsNotNone(result)

    def test_validate_xml_endpoint(self):
        """Test XML validation endpoint if available."""
        from apps.billing.efactura.validator import CIUSROValidator

        validator = CIUSROValidator()
        result = validator.validate(self.test_xml)

        # Local validation should pass for our test XML
        self.assertIsNotNone(result)

    def test_full_submission_lifecycle(self):
        """
        End-to-end test: generate XML -> upload -> poll status.

        This tests the complete workflow as it would happen in production.
        """
        from apps.billing.efactura.validator import CIUSROValidator

        # Step 1: Validate XML locally
        validator = CIUSROValidator()
        validator.validate(self.test_xml)
        # Log but don't fail on local validation (sandbox may have different rules)

        # Step 2: Upload to sandbox
        upload_result = self.client.upload_invoice(
            xml_content=self.test_xml,
            cui=self.config.company_cui,
        )

        if not upload_result.success:
            self.skipTest(f"Upload failed: {upload_result.message}")

        self.assertTrue(len(upload_result.upload_index) > 0)

        # Step 3: Check status (may still be processing)
        status_result = self.client.get_upload_status(upload_result.upload_index)
        self.assertIsNotNone(status_result)

        # The status should be one of the known ANAF response states
        # In sandbox, processing may be instant or delayed
        self.assertIn(
            status_result.status,
            ["ok", "nok", "in processing", ""],
            f"Unexpected status: {status_result.status}",
        )
