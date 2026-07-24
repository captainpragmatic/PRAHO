"""
Tests for CIUS-RO XML validator.
"""

from django.test import TestCase
from lxml import etree

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

    def _get_minimal_valid_eur_xml(self, *, accounting_first: bool = True) -> str:
        xml = self._get_minimal_valid_xml().replace('currencyID="RON"', 'currencyID="EUR"')
        xml = xml.replace(
            "<cbc:DocumentCurrencyCode>RON</cbc:DocumentCurrencyCode>",
            "<cbc:DocumentCurrencyCode>EUR</cbc:DocumentCurrencyCode>\n"
            "    <cbc:TaxCurrencyCode>RON</cbc:TaxCurrencyCode>",
        )
        accounting_total = (
            '    <cac:TaxTotal>\n        <cbc:TaxAmount currencyID="RON">950.00</cbc:TaxAmount>\n    </cac:TaxTotal>\n'
        )
        document_marker = "    <cac:TaxTotal>\n"
        if accounting_first:
            return xml.replace(document_marker, accounting_total + document_marker, 1)
        return xml.replace(
            "    </cac:TaxTotal>\n    <cac:LegalMonetaryTotal>",
            "    </cac:TaxTotal>\n" + accounting_total + "    <cac:LegalMonetaryTotal>",
            1,
        )

    def test_valid_foreign_currency_totals_are_selected_by_shape_not_order(self):
        for accounting_first in (True, False):
            with self.subTest(accounting_first=accounting_first):
                result = self.validator.validate(self._get_minimal_valid_eur_xml(accounting_first=accounting_first))
                self.assertTrue(result.is_valid, [str(error) for error in result.errors])

    def test_br_ro_030_requires_ron_tax_currency_for_non_ron_invoice(self):
        xml = self._get_minimal_valid_eur_xml().replace("    <cbc:TaxCurrencyCode>RON</cbc:TaxCurrencyCode>\n", "")

        result = self.validator.validate(xml)

        self.assertTrue(any(error.code == "BR-RO-030" for error in result.errors))

    def test_ron_invoice_rejects_tax_currency_and_accounting_total(self):
        xml = self._get_minimal_valid_xml().replace(
            "<cbc:DocumentCurrencyCode>RON</cbc:DocumentCurrencyCode>",
            "<cbc:DocumentCurrencyCode>RON</cbc:DocumentCurrencyCode>\n"
            "    <cbc:TaxCurrencyCode>RON</cbc:TaxCurrencyCode>",
        )

        result = self.validator.validate(xml)

        self.assertTrue(any(error.code == "BR-RO-030" for error in result.errors))

    def test_r054_rejects_duplicate_accounting_total(self):
        xml = self._get_minimal_valid_eur_xml()
        accounting = (
            '    <cac:TaxTotal>\n        <cbc:TaxAmount currencyID="RON">950.00</cbc:TaxAmount>\n    </cac:TaxTotal>\n'
        )
        xml = xml.replace(accounting, accounting + accounting, 1)

        result = self.validator.validate(xml)

        self.assertTrue(any(error.code == "R054" for error in result.errors))

    def test_r053_and_r054_reject_tax_subtotal_under_accounting_total(self):
        xml = self._get_minimal_valid_eur_xml().replace(
            '<cbc:TaxAmount currencyID="RON">950.00</cbc:TaxAmount>',
            '<cbc:TaxAmount currencyID="RON">950.00</cbc:TaxAmount><cac:TaxSubtotal/>',
            1,
        )

        result = self.validator.validate(xml)

        codes = {error.code for error in result.errors}
        self.assertIn("R053", codes)
        self.assertIn("R054", codes)

    def test_r055_rejects_opposite_tax_total_signs(self):
        xml = self._get_minimal_valid_eur_xml().replace(
            '<cbc:TaxAmount currencyID="RON">950.00</cbc:TaxAmount>',
            '<cbc:TaxAmount currencyID="RON">-950.00</cbc:TaxAmount>',
            1,
        )

        result = self.validator.validate(xml)

        self.assertTrue(any(error.code == "R055" for error in result.errors))

    def test_r051_rejects_non_document_currency_amounts(self):
        xml = self._get_minimal_valid_eur_xml().replace(
            '<cbc:PayableAmount currencyID="EUR">1190.00</cbc:PayableAmount>',
            '<cbc:PayableAmount currencyID="USD">1190.00</cbc:PayableAmount>',
        )

        result = self.validator.validate(xml)

        self.assertTrue(any(error.code == "R051" for error in result.errors))

    def test_r051_rejects_amount_when_currency_id_is_missing(self):
        xml = self._get_minimal_valid_xml().replace(
            '<cbc:PayableAmount currencyID="RON">1190.00</cbc:PayableAmount>',
            "<cbc:PayableAmount>1190.00</cbc:PayableAmount>",
        )

        result = self.validator.validate(xml)

        self.assertTrue(any(error.code == "R051" for error in result.errors))

    def test_r051_checks_every_supported_amount_context_without_exempting_missing_attributes(self):
        fragments = {
            "allowance amount": "<cac:AllowanceCharge><cbc:Amount>1.00</cbc:Amount></cac:AllowanceCharge>",
            "allowance base": "<cac:AllowanceCharge><cbc:BaseAmount>1.00</cbc:BaseAmount></cac:AllowanceCharge>",
            "price": "<cac:Price><cbc:PriceAmount>1.00</cbc:PriceAmount></cac:Price>",
            "document tax": (
                "<cac:TaxTotal><cbc:TaxAmount>1.00</cbc:TaxAmount>"
                "<cac:TaxSubtotal/></cac:TaxTotal>"
            ),
            "tax subtotal": "<cac:TaxSubtotal><cbc:TaxAmount>1.00</cbc:TaxAmount></cac:TaxSubtotal>",
            "taxable": "<cbc:TaxableAmount>1.00</cbc:TaxableAmount>",
            "line extension": "<cbc:LineExtensionAmount>1.00</cbc:LineExtensionAmount>",
            "tax exclusive": "<cbc:TaxExclusiveAmount>1.00</cbc:TaxExclusiveAmount>",
            "tax inclusive": "<cbc:TaxInclusiveAmount>1.00</cbc:TaxInclusiveAmount>",
            "allowance total": "<cbc:AllowanceTotalAmount>1.00</cbc:AllowanceTotalAmount>",
            "charge total": "<cbc:ChargeTotalAmount>1.00</cbc:ChargeTotalAmount>",
            "prepaid": "<cbc:PrepaidAmount>1.00</cbc:PrepaidAmount>",
            "rounding": "<cbc:PayableRoundingAmount>1.00</cbc:PayableRoundingAmount>",
            "payable": "<cbc:PayableAmount>1.00</cbc:PayableAmount>",
        }

        for label, fragment in fragments.items():
            with self.subTest(label=label):
                xml = (
                    '<Invoice xmlns="urn:oasis:names:specification:ubl:schema:xsd:Invoice-2" '
                    'xmlns:cac="urn:oasis:names:specification:ubl:schema:xsd:CommonAggregateComponents-2" '
                    'xmlns:cbc="urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2">'
                    "<cbc:DocumentCurrencyCode>RON</cbc:DocumentCurrencyCode>"
                    f"{fragment}</Invoice>"
                )
                result = ValidationResult(is_valid=True)
                document = etree.fromstring(xml.encode())

                self.validator._validate_currency_ids(document, "RON", result)

                self.assertEqual([error.code for error in result.errors], ["R051"])

    def test_br_53_rejects_accounting_total_with_wrong_currency(self):
        xml = self._get_minimal_valid_eur_xml().replace(
            '<cbc:TaxAmount currencyID="RON">950.00</cbc:TaxAmount>',
            '<cbc:TaxAmount currencyID="USD">950.00</cbc:TaxAmount>',
            1,
        )

        result = self.validator.validate(xml)

        self.assertTrue(any(error.code == "BR-53" for error in result.errors))

    def test_br_dec_15_rejects_bt111_over_precision(self):
        xml = self._get_minimal_valid_eur_xml().replace(
            '<cbc:TaxAmount currencyID="RON">950.00</cbc:TaxAmount>',
            '<cbc:TaxAmount currencyID="RON">950.000</cbc:TaxAmount>',
            1,
        )

        result = self.validator.validate(xml)

        self.assertTrue(any(error.code == "BR-DEC-15" for error in result.errors))

    def test_validate_valid_xml(self):
        """Test that valid XML passes validation."""
        xml = self._get_minimal_valid_xml()
        result = self.validator.validate(xml)

        self.assertTrue(result.is_valid)
        self.assertEqual(len(result.errors), 0)

    # ---- EN16931 business-rule arithmetic (native partial Schematron subset) ----

    def test_br_co_10_line_sum_must_equal_document_line_extension(self):
        """BR-CO-10: document LineExtensionAmount must equal the sum of line nets."""
        xml = self._get_minimal_valid_xml().replace(
            '<cbc:LineExtensionAmount currencyID="RON">1000.00</cbc:LineExtensionAmount>\n        <cac:Item>',
            '<cbc:LineExtensionAmount currencyID="RON">900.00</cbc:LineExtensionAmount>\n        <cac:Item>',
        )
        result = self.validator.validate(xml)
        self.assertFalse(result.is_valid)
        self.assertTrue(any(e.code == "BR-CO-10" for e in result.errors), [e.code for e in result.errors])

    def test_br_co_15_tax_inclusive_must_equal_exclusive_plus_tax(self):
        """BR-CO-15: TaxInclusiveAmount must equal TaxExclusiveAmount + tax."""
        xml = self._get_minimal_valid_xml().replace(
            ">1190.00</cbc:TaxInclusiveAmount>", ">1200.00</cbc:TaxInclusiveAmount>"
        )
        result = self.validator.validate(xml)
        self.assertFalse(result.is_valid)
        self.assertTrue(any(e.code == "BR-CO-15" for e in result.errors), [e.code for e in result.errors])

    def test_br_co_16_payable_must_equal_inclusive_minus_prepaid(self):
        """BR-CO-16: PayableAmount must equal TaxInclusiveAmount - PrepaidAmount."""
        xml = self._get_minimal_valid_xml().replace(">1190.00</cbc:PayableAmount>", ">1000.00</cbc:PayableAmount>")
        result = self.validator.validate(xml)
        self.assertFalse(result.is_valid)
        self.assertTrue(any(e.code == "BR-CO-16" for e in result.errors), [e.code for e in result.errors])

    def test_br_co_14_standard_tax_must_equal_base_times_rate(self):
        """BR-CO-14: standard-rate category tax must equal taxable base * rate."""
        xml = self._get_minimal_valid_xml().replace(
            '<cbc:TaxableAmount currencyID="RON">1000.00</cbc:TaxableAmount>\n'
            '            <cbc:TaxAmount currencyID="RON">190.00</cbc:TaxAmount>',
            '<cbc:TaxableAmount currencyID="RON">1000.00</cbc:TaxableAmount>\n'
            '            <cbc:TaxAmount currencyID="RON">150.00</cbc:TaxAmount>',
        )
        result = self.validator.validate(xml)
        self.assertFalse(result.is_valid)
        self.assertTrue(any(e.code == "BR-CO-14" for e in result.errors), [e.code for e in result.errors])

    def test_br_s_10_standard_category_must_not_carry_exemption(self):
        """BR-S-10: an S (standard) category must not carry a tax exemption code/reason."""
        xml = self._get_minimal_valid_xml().replace(
            "<cac:TaxCategory>\n                <cbc:ID>S</cbc:ID>",
            "<cac:TaxCategory>\n                <cbc:ID>S</cbc:ID>\n"
            "                <cbc:TaxExemptionReasonCode>VATEX-EU-AE</cbc:TaxExemptionReasonCode>",
        )
        result = self.validator.validate(xml)
        self.assertFalse(result.is_valid)
        self.assertTrue(any(e.code == "BR-S-10" for e in result.errors), [e.code for e in result.errors])

    def test_br_cl_16_payment_means_code_must_be_valid(self):
        """BT-81/BR-CL-16: a payment means code outside UNCL4461 must be rejected."""
        xml = self._get_minimal_valid_xml().replace(
            "<cbc:PaymentMeansCode>30</cbc:PaymentMeansCode>",
            "<cbc:PaymentMeansCode>99</cbc:PaymentMeansCode>",
        )
        result = self.validator.validate(xml)
        self.assertFalse(result.is_valid)
        self.assertTrue(any(e.code == "BR-CL-16" for e in result.errors), [e.code for e in result.errors])

    def test_payment_means_code_48_is_accepted(self):
        """Regression: code 48 (bank card) is what the builder emits for Stripe payments and is a
        valid UNCL4461 code, so the validator MUST accept it. (It previously rejected its own
        builder's output.)"""
        xml = self._get_minimal_valid_xml().replace(
            "<cbc:PaymentMeansCode>30</cbc:PaymentMeansCode>",
            "<cbc:PaymentMeansCode>48</cbc:PaymentMeansCode>",
        )
        result = self.validator.validate(xml)
        self.assertFalse(any(e.code == "BR-CL-16" for e in result.errors), [e.code for e in result.errors])
        self.assertTrue(result.is_valid, [str(e) for e in result.errors])

    def test_br_co_14_sum_document_tax_must_equal_subtotal_sum(self):
        """The document TaxTotal must equal the sum of the per-category TaxSubtotal amounts."""
        xml = self._get_minimal_valid_xml().replace(
            '<cac:TaxTotal>\n        <cbc:TaxAmount currencyID="RON">190.00</cbc:TaxAmount>',
            '<cac:TaxTotal>\n        <cbc:TaxAmount currencyID="RON">200.00</cbc:TaxAmount>',
        )
        result = self.validator.validate(xml)
        self.assertFalse(result.is_valid)
        self.assertTrue(any(e.code == "BR-CO-14-SUM" for e in result.errors), [e.code for e in result.errors])

    def test_br_cl_22_rejects_non_codelist_vatex(self):
        """BR-CL-22: an exemption code that merely starts with VATEX- but isn't in the codelist
        (e.g. VATEX-NOT-REAL) must be rejected, not accepted."""
        xml = self._get_minimal_valid_xml().replace(
            "<cac:TaxCategory>\n                <cbc:ID>S</cbc:ID>\n                <cbc:Percent>19.00</cbc:Percent>",
            "<cac:TaxCategory>\n                <cbc:ID>AE</cbc:ID>\n                <cbc:Percent>0.00</cbc:Percent>\n"
            "                <cbc:TaxExemptionReasonCode>VATEX-NOT-REAL</cbc:TaxExemptionReasonCode>",
        )
        result = self.validator.validate(xml)
        self.assertFalse(result.is_valid)
        self.assertTrue(any(e.code == "BR-CL-22" for e in result.errors), [e.code for e in result.errors])

    def test_validate_malformed_xml(self):
        """Test that malformed XML fails validation."""
        xml = "<Invoice>Not closed properly"
        result = self.validator.validate(xml)

        self.assertFalse(result.is_valid)
        self.assertEqual(result.errors[0].code, "XML-SYNTAX")

    def test_validate_missing_invoice_id(self):
        """Test that missing Invoice ID is detected."""
        xml = self._get_minimal_valid_xml().replace("<cbc:ID>INV-2024-001</cbc:ID>", "<cbc:ID></cbc:ID>")
        result = self.validator.validate(xml)

        self.assertFalse(result.is_valid)
        self.assertTrue(any(e.code == "BR-01" for e in result.errors))

    def test_validate_missing_issue_date(self):
        """Test that missing Issue Date is detected."""
        xml = self._get_minimal_valid_xml().replace("<cbc:IssueDate>2024-12-26</cbc:IssueDate>", "")
        result = self.validator.validate(xml)

        self.assertFalse(result.is_valid)
        self.assertTrue(any(e.code == "BR-02" for e in result.errors))

    def test_validate_invalid_date_format(self):
        """Test that invalid date format is detected."""
        xml = self._get_minimal_valid_xml().replace(
            "<cbc:IssueDate>2024-12-26</cbc:IssueDate>", "<cbc:IssueDate>26/12/2024</cbc:IssueDate>"
        )
        result = self.validator.validate(xml)

        self.assertFalse(result.is_valid)
        self.assertTrue(any("BR-02" in e.code for e in result.errors))

    def test_validate_missing_invoice_type_code(self):
        """Test that missing Invoice Type Code is detected."""
        xml = self._get_minimal_valid_xml().replace("<cbc:InvoiceTypeCode>380</cbc:InvoiceTypeCode>", "")
        result = self.validator.validate(xml)

        self.assertFalse(result.is_valid)
        self.assertTrue(any(e.code == "BR-04" for e in result.errors))

    def test_validate_missing_document_currency(self):
        """Test that missing Document Currency is detected."""
        xml = self._get_minimal_valid_xml().replace("<cbc:DocumentCurrencyCode>RON</cbc:DocumentCurrencyCode>", "")
        result = self.validator.validate(xml)

        self.assertFalse(result.is_valid)
        self.assertTrue(any(e.code == "BR-05" for e in result.errors))

    def test_validate_missing_supplier_party(self):
        """Test that missing Supplier Party is detected."""
        xml = self._get_minimal_valid_xml()
        # Remove entire supplier party (simplified for test)
        xml = xml.replace("<cac:AccountingSupplierParty>", "<!--").replace("</cac:AccountingSupplierParty>", "-->")
        result = self.validator.validate(xml)

        self.assertFalse(result.is_valid)
        self.assertTrue(any(e.code == "BR-06" for e in result.errors))

    def test_validate_missing_customer_party(self):
        """Test that missing Customer Party is detected."""
        xml = self._get_minimal_valid_xml()
        xml = xml.replace("<cac:AccountingCustomerParty>", "<!--").replace("</cac:AccountingCustomerParty>", "-->")
        result = self.validator.validate(xml)

        self.assertFalse(result.is_valid)
        self.assertTrue(any(e.code == "BR-07" for e in result.errors))

    def test_validate_missing_tax_total(self):
        """Test that missing Tax Total is detected."""
        xml = self._get_minimal_valid_xml()
        xml = xml.replace("<cac:TaxTotal>", "<!--").replace("</cac:TaxTotal>", "-->")
        result = self.validator.validate(xml)

        self.assertFalse(result.is_valid)
        self.assertTrue(any(e.code == "BR-45" for e in result.errors))

    def test_validate_missing_monetary_total(self):
        """Test that missing Monetary Total is detected."""
        xml = self._get_minimal_valid_xml()
        xml = xml.replace("<cac:LegalMonetaryTotal>", "<!--").replace("</cac:LegalMonetaryTotal>", "-->")
        result = self.validator.validate(xml)

        self.assertFalse(result.is_valid)
        self.assertTrue(any(e.code == "BR-52" for e in result.errors))

    def test_validate_missing_invoice_line(self):
        """Test that missing Invoice Line is detected."""
        xml = self._get_minimal_valid_xml()
        xml = xml.replace("<cac:InvoiceLine>", "<!--").replace("</cac:InvoiceLine>", "-->")
        result = self.validator.validate(xml)

        self.assertFalse(result.is_valid)
        self.assertTrue(any(e.code == "BR-16" for e in result.errors))

    def test_validate_customization_id_warning(self):
        """Test that incorrect CustomizationID generates warning."""
        xml = self._get_minimal_valid_xml().replace(
            "urn:cen.eu:en16931:2017#compliant#urn:efactura.mfinante.ro:CIUS-RO:1.0.1",
            "urn:wrong:customization",
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
        error = ValidationError(code="BR-01", message="ID missing", location="/Invoice/ID", severity="error")

        data = error.to_dict()

        self.assertEqual(data["code"], "BR-01")
        self.assertEqual(data["message"], "ID missing")
        self.assertEqual(data["location"], "/Invoice/ID")
        self.assertEqual(data["severity"], "error")


# Use the same constant for the test
CIUS_RO_CUSTOMIZATION_ID = "urn:cen.eu:en16931:2017#compliant#urn:efactura.mfinante.ro:CIUS-RO:1.0.1"
