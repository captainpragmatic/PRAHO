"""
Tests for CIUS-RO XML validator.
"""

from django.test import TestCase

from apps.billing.efactura.validator import CIUSROValidator, ValidationError, ValidationResult


class CIUSROValidatorTestCase(TestCase):
    """Test CIUS-RO XML validator."""

    def setUp(self):
        self.validator = CIUSROValidator()

    def _get_minimal_valid_xml(self) -> str:
        """Return minimal valid UBL 2.1 Invoice XML."""
        return """<?xml version="1.0" encoding="UTF-8"?>
<Invoice xmlns="urn:oasis:names:specification:ubl:schema:xsd:Invoice-2"
         xmlns:cac="urn:oasis:names:specification:ubl:schema:xsd:CommonAggregateComponents-2"
         xmlns:cbc="urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2">
    <cbc:CustomizationID>urn:cen.eu:en16931:2017#compliant#urn:efactura.mfinante.ro:CIUS-RO:1.0.1</cbc:CustomizationID>
    <cbc:ProfileID>urn:fdc:peppol.eu:2017:poacc:billing:01:1.0</cbc:ProfileID>
    <cbc:ID>INV-2024-001</cbc:ID>
    <cbc:IssueDate>2024-12-26</cbc:IssueDate>
    <cbc:DueDate>2025-01-26</cbc:DueDate>
    <cbc:InvoiceTypeCode>380</cbc:InvoiceTypeCode>
    <cbc:DocumentCurrencyCode>RON</cbc:DocumentCurrencyCode>
    <cac:AccountingSupplierParty>
        <cac:Party>
            <cac:PartyIdentification>
                <cbc:ID schemeID="RO:CUI">12345678</cbc:ID>
            </cac:PartyIdentification>
            <cac:PartyName>
                <cbc:Name>Supplier SRL</cbc:Name>
            </cac:PartyName>
            <cac:PostalAddress>
                <cbc:StreetName>Street 123</cbc:StreetName>
                <cbc:CityName>Bucharest</cbc:CityName>
                <cbc:PostalZone>010101</cbc:PostalZone>
                <cac:Country>
                    <cbc:IdentificationCode>RO</cbc:IdentificationCode>
                    <cbc:Name>Romania</cbc:Name>
                </cac:Country>
            </cac:PostalAddress>
            <cac:PartyTaxScheme>
                <cbc:CompanyID>RO12345678</cbc:CompanyID>
                <cac:TaxScheme>
                    <cbc:ID>VAT</cbc:ID>
                </cac:TaxScheme>
            </cac:PartyTaxScheme>
            <cac:PartyLegalEntity>
                <cbc:RegistrationName>Supplier SRL</cbc:RegistrationName>
                <cbc:CompanyID>J40/1234/2020</cbc:CompanyID>
            </cac:PartyLegalEntity>
        </cac:Party>
    </cac:AccountingSupplierParty>
    <cac:AccountingCustomerParty>
        <cac:Party>
            <cac:PartyIdentification>
                <cbc:ID schemeID="RO:CUI">87654321</cbc:ID>
            </cac:PartyIdentification>
            <cac:PartyName>
                <cbc:Name>Customer SRL</cbc:Name>
            </cac:PartyName>
            <cac:PostalAddress>
                <cbc:CityName>Cluj</cbc:CityName>
                <cac:Country>
                    <cbc:IdentificationCode>RO</cbc:IdentificationCode>
                </cac:Country>
            </cac:PostalAddress>
            <cac:PartyTaxScheme>
                <cbc:CompanyID>RO87654321</cbc:CompanyID>
                <cac:TaxScheme>
                    <cbc:ID>VAT</cbc:ID>
                </cac:TaxScheme>
            </cac:PartyTaxScheme>
            <cac:PartyLegalEntity>
                <cbc:RegistrationName>Customer SRL</cbc:RegistrationName>
            </cac:PartyLegalEntity>
        </cac:Party>
    </cac:AccountingCustomerParty>
    <cac:PaymentMeans>
        <cbc:PaymentMeansCode>30</cbc:PaymentMeansCode>
    </cac:PaymentMeans>
    <cac:TaxTotal>
        <cbc:TaxAmount currencyID="RON">190.00</cbc:TaxAmount>
        <cac:TaxSubtotal>
            <cbc:TaxableAmount currencyID="RON">1000.00</cbc:TaxableAmount>
            <cbc:TaxAmount currencyID="RON">190.00</cbc:TaxAmount>
            <cac:TaxCategory>
                <cbc:ID>S</cbc:ID>
                <cbc:Percent>19.00</cbc:Percent>
                <cac:TaxScheme>
                    <cbc:ID>VAT</cbc:ID>
                </cac:TaxScheme>
            </cac:TaxCategory>
        </cac:TaxSubtotal>
    </cac:TaxTotal>
    <cac:LegalMonetaryTotal>
        <cbc:LineExtensionAmount currencyID="RON">1000.00</cbc:LineExtensionAmount>
        <cbc:TaxExclusiveAmount currencyID="RON">1000.00</cbc:TaxExclusiveAmount>
        <cbc:TaxInclusiveAmount currencyID="RON">1190.00</cbc:TaxInclusiveAmount>
        <cbc:PayableAmount currencyID="RON">1190.00</cbc:PayableAmount>
    </cac:LegalMonetaryTotal>
    <cac:InvoiceLine>
        <cbc:ID>1</cbc:ID>
        <cbc:InvoicedQuantity unitCode="C62">1</cbc:InvoicedQuantity>
        <cbc:LineExtensionAmount currencyID="RON">1000.00</cbc:LineExtensionAmount>
        <cac:Item>
            <cbc:Description>Web Hosting Service</cbc:Description>
            <cbc:Name>Web Hosting</cbc:Name>
            <cac:ClassifiedTaxCategory>
                <cbc:ID>S</cbc:ID>
                <cbc:Percent>19.00</cbc:Percent>
                <cac:TaxScheme>
                    <cbc:ID>VAT</cbc:ID>
                </cac:TaxScheme>
            </cac:ClassifiedTaxCategory>
        </cac:Item>
        <cac:Price>
            <cbc:PriceAmount currencyID="RON">1000.00</cbc:PriceAmount>
        </cac:Price>
    </cac:InvoiceLine>
</Invoice>"""

    def test_validate_valid_xml(self):
        """Test that valid XML passes validation."""
        xml = self._get_minimal_valid_xml()
        result = self.validator.validate(xml)

        self.assertTrue(result.is_valid)
        self.assertEqual(len(result.errors), 0)

    def test_validate_malformed_xml(self):
        """Test that malformed XML fails validation."""
        xml = "<Invoice>Not closed properly"
        result = self.validator.validate(xml)

        self.assertFalse(result.is_valid)
        self.assertEqual(result.errors[0].code, "XML-SYNTAX")

    def test_validate_missing_invoice_id(self):
        """Test that missing Invoice ID is detected."""
        xml = self._get_minimal_valid_xml().replace(
            "<cbc:ID>INV-2024-001</cbc:ID>",
            "<cbc:ID></cbc:ID>"
        )
        result = self.validator.validate(xml)

        self.assertFalse(result.is_valid)
        self.assertTrue(any(e.code == "BR-01" for e in result.errors))

    def test_validate_missing_issue_date(self):
        """Test that missing Issue Date is detected."""
        xml = self._get_minimal_valid_xml().replace(
            "<cbc:IssueDate>2024-12-26</cbc:IssueDate>",
            ""
        )
        result = self.validator.validate(xml)

        self.assertFalse(result.is_valid)
        self.assertTrue(any(e.code == "BR-02" for e in result.errors))

    def test_validate_invalid_date_format(self):
        """Test that invalid date format is detected."""
        xml = self._get_minimal_valid_xml().replace(
            "<cbc:IssueDate>2024-12-26</cbc:IssueDate>",
            "<cbc:IssueDate>26/12/2024</cbc:IssueDate>"
        )
        result = self.validator.validate(xml)

        self.assertFalse(result.is_valid)
        self.assertTrue(any("BR-02" in e.code for e in result.errors))

    def test_validate_missing_invoice_type_code(self):
        """Test that missing Invoice Type Code is detected."""
        xml = self._get_minimal_valid_xml().replace(
            "<cbc:InvoiceTypeCode>380</cbc:InvoiceTypeCode>",
            ""
        )
        result = self.validator.validate(xml)

        self.assertFalse(result.is_valid)
        self.assertTrue(any(e.code == "BR-04" for e in result.errors))

    def test_validate_missing_document_currency(self):
        """Test that missing Document Currency is detected."""
        xml = self._get_minimal_valid_xml().replace(
            "<cbc:DocumentCurrencyCode>RON</cbc:DocumentCurrencyCode>",
            ""
        )
        result = self.validator.validate(xml)

        self.assertFalse(result.is_valid)
        self.assertTrue(any(e.code == "BR-05" for e in result.errors))

    def test_validate_missing_supplier_party(self):
        """Test that missing Supplier Party is detected."""
        xml = self._get_minimal_valid_xml()
        # Remove entire supplier party (simplified for test)
        xml = xml.replace("<cac:AccountingSupplierParty>", "<!--").replace(
            "</cac:AccountingSupplierParty>", "-->"
        )
        result = self.validator.validate(xml)

        self.assertFalse(result.is_valid)
        self.assertTrue(any(e.code == "BR-06" for e in result.errors))

    def test_validate_missing_customer_party(self):
        """Test that missing Customer Party is detected."""
        xml = self._get_minimal_valid_xml()
        xml = xml.replace("<cac:AccountingCustomerParty>", "<!--").replace(
            "</cac:AccountingCustomerParty>", "-->"
        )
        result = self.validator.validate(xml)

        self.assertFalse(result.is_valid)
        self.assertTrue(any(e.code == "BR-07" for e in result.errors))

    def test_validate_missing_tax_total(self):
        """Test that missing Tax Total is detected."""
        xml = self._get_minimal_valid_xml()
        xml = xml.replace("<cac:TaxTotal>", "<!--").replace(
            "</cac:TaxTotal>", "-->"
        )
        result = self.validator.validate(xml)

        self.assertFalse(result.is_valid)
        self.assertTrue(any(e.code == "BR-45" for e in result.errors))

    def test_validate_missing_monetary_total(self):
        """Test that missing Monetary Total is detected."""
        xml = self._get_minimal_valid_xml()
        xml = xml.replace("<cac:LegalMonetaryTotal>", "<!--").replace(
            "</cac:LegalMonetaryTotal>", "-->"
        )
        result = self.validator.validate(xml)

        self.assertFalse(result.is_valid)
        self.assertTrue(any(e.code == "BR-52" for e in result.errors))

    def test_validate_missing_invoice_line(self):
        """Test that missing Invoice Line is detected."""
        xml = self._get_minimal_valid_xml()
        xml = xml.replace("<cac:InvoiceLine>", "<!--").replace(
            "</cac:InvoiceLine>", "-->"
        )
        result = self.validator.validate(xml)

        self.assertFalse(result.is_valid)
        self.assertTrue(any(e.code == "BR-16" for e in result.errors))

    def test_validate_customization_id_warning(self):
        """Test that incorrect CustomizationID generates warning."""
        xml = self._get_minimal_valid_xml().replace(
            CIUS_RO_CUSTOMIZATION_ID := "urn:cen.eu:en16931:2017#compliant#urn:efactura.mfinante.ro:CIUS-RO:1.0.1",
            "urn:wrong:customization"
        )
        result = self.validator.validate(xml)

        # Still valid but with warning
        self.assertTrue(any(w.code == "BR-RO-001-VER" for w in result.warnings))

    def test_validate_romanian_cui_format(self):
        """Test Romanian CUI format validation."""
        # Valid CUI patterns
        self.assertTrue(self.validator.CUI_PATTERN.match("12345678"))
        self.assertTrue(self.validator.CUI_PATTERN.match("RO12345678"))

        # Invalid patterns
        self.assertFalse(self.validator.CUI_PATTERN.match("1"))  # Too short
        self.assertFalse(self.validator.CUI_PATTERN.match("ABC12345"))  # Contains letters

    def test_validation_result_to_dict(self):
        """Test ValidationResult serialization."""
        result = ValidationResult(is_valid=False)
        result.add_error("TEST-01", "Test error", "/Invoice/ID")
        result.add_warning("TEST-W01", "Test warning")

        data = result.to_dict()

        self.assertFalse(data["is_valid"])
        self.assertEqual(len(data["errors"]), 1)
        self.assertEqual(len(data["warnings"]), 1)
        self.assertEqual(data["errors"][0]["code"], "TEST-01")

    def test_validation_error_to_dict(self):
        """Test ValidationError serialization."""
        error = ValidationError(
            code="BR-01",
            message="ID missing",
            location="/Invoice/ID",
            severity="error"
        )

        data = error.to_dict()

        self.assertEqual(data["code"], "BR-01")
        self.assertEqual(data["message"], "ID missing")
        self.assertEqual(data["location"], "/Invoice/ID")
        self.assertEqual(data["severity"], "error")


# Use the same constant for the test
CIUS_RO_CUSTOMIZATION_ID = "urn:cen.eu:en16931:2017#compliant#urn:efactura.mfinante.ro:CIUS-RO:1.0.1"
