"""
Tests for UBL 2.1 XML Builder with CIUS-RO compliance.
"""


from decimal import Decimal

from django.test import TestCase, override_settings
from django.utils import timezone
from lxml import etree

from apps.billing.efactura.xml_builder import (
    CIUS_RO_CUSTOMIZATION_ID,
    NAMESPACES,
    PEPPOL_PROFILE_ID,
    UBLCreditNoteBuilder,
    UBLInvoiceBuilder,
    XMLBuilderError,
)


@override_settings(
    COMPANY_NAME="Test Company SRL",
    EFACTURA_COMPANY_CUI="12345678",
    COMPANY_REGISTRATION_NUMBER="J40/1234/2020",
    COMPANY_STREET="Test Street 123",
    COMPANY_CITY="Bucharest",
    COMPANY_POSTAL_CODE="010101",
    COMPANY_COUNTRY_CODE="RO",
    COMPANY_EMAIL="test@example.com",
    COMPANY_BANK_ACCOUNT="RO49AAAA1B31007593840000",
    COMPANY_BANK_NAME="Test Bank",
)
class UBLInvoiceBuilderTestCase(TestCase):
    """Test UBL 2.1 Invoice XML builder."""

    @classmethod
    def setUpTestData(cls):
        """Set up test data."""
        from tests.factories import CurrencyFactory, CustomerFactory, InvoiceFactory, InvoiceLineFactory

        cls.currency = CurrencyFactory(code="RON")
        cls.customer = CustomerFactory()
        cls.invoice = InvoiceFactory(
            customer=cls.customer,
            currency=cls.currency,
            number="INV-2024-001",
            bill_to_name="Customer SRL",
            bill_to_country="RO",
            bill_to_tax_id="RO87654321",
            bill_to_street="Customer Street 456",
            bill_to_city="Cluj-Napoca",
            bill_to_postal_code="400001",
            status="issued",
            issued_at=timezone.now(),
            due_at=timezone.now() + timezone.timedelta(days=30),
            subtotal_cents=100000,
            tax_total_cents=19000,
            total_cents=119000,
        )
        cls.line = InvoiceLineFactory(
            invoice=cls.invoice,
            description="Web Hosting Service",
            unit_price_cents=100000,
            quantity=1,
            tax_rate=Decimal("0.1900"),  # Matches invoice's tax_total_cents=19000
        )

    def test_build_generates_valid_xml(self):
        """Test that build() generates well-formed XML."""
        builder = UBLInvoiceBuilder(self.invoice)
        xml = builder.build()

        self.assertIsInstance(xml, str)
        self.assertIn('<?xml version="1.0"', xml)

        # Should parse without errors
        doc = etree.fromstring(xml.encode())
        self.assertIsNotNone(doc)

    def test_build_contains_customization_id(self):
        """Test that CIUS-RO CustomizationID is present."""
        builder = UBLInvoiceBuilder(self.invoice)
        xml = builder.build()
        doc = etree.fromstring(xml.encode())

        customization = doc.find(f".//{{{NAMESPACES['cbc']}}}CustomizationID")
        self.assertIsNotNone(customization)
        self.assertEqual(customization.text, CIUS_RO_CUSTOMIZATION_ID)

    def test_build_contains_profile_id(self):
        """Test that PEPPOL ProfileID is present."""
        builder = UBLInvoiceBuilder(self.invoice)
        xml = builder.build()
        doc = etree.fromstring(xml.encode())

        profile = doc.find(f".//{{{NAMESPACES['cbc']}}}ProfileID")
        self.assertIsNotNone(profile)
        self.assertEqual(profile.text, PEPPOL_PROFILE_ID)

    def test_build_contains_invoice_id(self):
        """Test that Invoice ID is set correctly."""
        builder = UBLInvoiceBuilder(self.invoice)
        xml = builder.build()
        doc = etree.fromstring(xml.encode())

        invoice_id = doc.find(f".//{{{NAMESPACES['cbc']}}}ID")
        self.assertIsNotNone(invoice_id)
        self.assertEqual(invoice_id.text, self.invoice.number)

    def test_build_contains_issue_date(self):
        """Test that IssueDate is formatted correctly."""
        builder = UBLInvoiceBuilder(self.invoice)
        xml = builder.build()
        doc = etree.fromstring(xml.encode())

        issue_date = doc.find(f".//{{{NAMESPACES['cbc']}}}IssueDate")
        self.assertIsNotNone(issue_date)
        expected = self.invoice.issued_at.strftime("%Y-%m-%d")
        self.assertEqual(issue_date.text, expected)

    def test_build_contains_supplier_party(self):
        """Test that AccountingSupplierParty is present."""
        builder = UBLInvoiceBuilder(self.invoice)
        xml = builder.build()
        doc = etree.fromstring(xml.encode())

        supplier = doc.find(f".//{{{NAMESPACES['cac']}}}AccountingSupplierParty")
        self.assertIsNotNone(supplier)

        # Check supplier name
        name = supplier.find(f".//{{{NAMESPACES['cac']}}}PartyName/{{{NAMESPACES['cbc']}}}Name")
        self.assertIsNotNone(name)
        self.assertEqual(name.text, "Test Company SRL")

        # Check supplier CUI
        party_id = supplier.find(f".//{{{NAMESPACES['cac']}}}PartyIdentification/{{{NAMESPACES['cbc']}}}ID")
        self.assertIsNotNone(party_id)
        self.assertEqual(party_id.text, "12345678")
        self.assertEqual(party_id.get("schemeID"), "RO:CUI")

    def test_build_contains_customer_party(self):
        """Test that AccountingCustomerParty is present."""
        builder = UBLInvoiceBuilder(self.invoice)
        xml = builder.build()
        doc = etree.fromstring(xml.encode())

        customer = doc.find(f".//{{{NAMESPACES['cac']}}}AccountingCustomerParty")
        self.assertIsNotNone(customer)

        # Check customer name
        name = customer.find(f".//{{{NAMESPACES['cac']}}}PartyName/{{{NAMESPACES['cbc']}}}Name")
        self.assertIsNotNone(name)
        self.assertEqual(name.text, "Customer SRL")

    def test_build_contains_tax_total(self):
        """Test that TaxTotal is present and correct."""
        builder = UBLInvoiceBuilder(self.invoice)
        xml = builder.build()
        doc = etree.fromstring(xml.encode())

        tax_total = doc.find(f".//{{{NAMESPACES['cac']}}}TaxTotal")
        self.assertIsNotNone(tax_total)

        tax_amount = tax_total.find(f".//{{{NAMESPACES['cbc']}}}TaxAmount")
        self.assertIsNotNone(tax_amount)
        self.assertEqual(tax_amount.text, "190.00")
        self.assertEqual(tax_amount.get("currencyID"), "RON")

    def test_build_contains_legal_monetary_total(self):
        """Test that LegalMonetaryTotal is present and correct."""
        builder = UBLInvoiceBuilder(self.invoice)
        xml = builder.build()
        doc = etree.fromstring(xml.encode())

        monetary = doc.find(f".//{{{NAMESPACES['cac']}}}LegalMonetaryTotal")
        self.assertIsNotNone(monetary)

        payable = monetary.find(f".//{{{NAMESPACES['cbc']}}}PayableAmount")
        self.assertIsNotNone(payable)
        self.assertEqual(payable.text, "1190.00")

    def test_build_contains_invoice_lines(self):
        """Test that InvoiceLine elements are present."""
        builder = UBLInvoiceBuilder(self.invoice)
        xml = builder.build()
        doc = etree.fromstring(xml.encode())

        lines = doc.findall(f".//{{{NAMESPACES['cac']}}}InvoiceLine")
        self.assertEqual(len(lines), 1)

        # Check line ID
        line_id = lines[0].find(f".//{{{NAMESPACES['cbc']}}}ID")
        self.assertIsNotNone(line_id)
        self.assertEqual(line_id.text, "1")

        # Check item name
        item_name = lines[0].find(f".//{{{NAMESPACES['cac']}}}Item/{{{NAMESPACES['cbc']}}}Name")
        self.assertIsNotNone(item_name)

    def test_build_contains_payment_means(self):
        """Test that PaymentMeans is present."""
        builder = UBLInvoiceBuilder(self.invoice)
        xml = builder.build()
        doc = etree.fromstring(xml.encode())

        payment_means = doc.find(f".//{{{NAMESPACES['cac']}}}PaymentMeans")
        self.assertIsNotNone(payment_means)

        code = payment_means.find(f".//{{{NAMESPACES['cbc']}}}PaymentMeansCode")
        self.assertIsNotNone(code)
        self.assertEqual(code.text, "30")  # Bank transfer

    def test_validation_error_missing_invoice_number(self):
        """Test that validation fails for missing invoice number."""
        self.invoice.number = ""

        builder = UBLInvoiceBuilder(self.invoice)
        with self.assertRaises(XMLBuilderError) as context:
            builder.build()

        self.assertIn("Invoice number is required", str(context.exception))

    def test_validation_error_missing_issue_date(self):
        """Test that validation fails for missing issue date."""
        self.invoice.issued_at = None

        builder = UBLInvoiceBuilder(self.invoice)
        with self.assertRaises(XMLBuilderError) as context:
            builder.build()

        self.assertIn("Issue date is required", str(context.exception))

    def test_validation_error_missing_customer_name(self):
        """Test that validation fails for missing customer name."""
        self.invoice.bill_to_name = ""

        builder = UBLInvoiceBuilder(self.invoice)
        with self.assertRaises(XMLBuilderError) as context:
            builder.build()

        self.assertIn("Customer name is required", str(context.exception))

    def test_validation_error_missing_tax_id_for_romanian_b2b(self):
        """Test that validation fails for missing tax ID in Romanian B2B."""
        self.invoice.bill_to_country = "RO"
        self.invoice.bill_to_tax_id = ""

        builder = UBLInvoiceBuilder(self.invoice)
        with self.assertRaises(XMLBuilderError) as context:
            builder.build()

        self.assertIn("Romanian B2B invoice requires customer tax ID", str(context.exception))

    @override_settings(COMPANY_NAME="")
    def test_validation_error_missing_supplier_config(self):
        """Test that validation fails for missing supplier configuration."""
        builder = UBLInvoiceBuilder(self.invoice)
        with self.assertRaises(XMLBuilderError) as context:
            builder.build()

        self.assertIn("Supplier company name not configured", str(context.exception))


@override_settings(
    COMPANY_NAME="Test Company SRL",
    EFACTURA_COMPANY_CUI="12345678",
    COMPANY_REGISTRATION_NUMBER="J40/1234/2020",
    COMPANY_STREET="Test Street 123",
    COMPANY_CITY="Bucharest",
    COMPANY_POSTAL_CODE="010101",
)
class UBLCreditNoteBuilderTestCase(TestCase):
    """Test UBL 2.1 Credit Note XML builder."""

    @classmethod
    def setUpTestData(cls):
        """Set up test data."""
        from tests.factories import CurrencyFactory, CustomerFactory, InvoiceFactory, InvoiceLineFactory

        cls.currency = CurrencyFactory(code="RON")
        cls.customer = CustomerFactory()

        # Original invoice
        cls.original_invoice = InvoiceFactory(
            customer=cls.customer,
            currency=cls.currency,
            number="INV-2024-001",
            bill_to_name="Customer SRL",
            bill_to_country="RO",
            bill_to_tax_id="RO87654321",
            status="paid",
            issued_at=timezone.now() - timezone.timedelta(days=30),
        )

        # Credit note
        cls.credit_note = InvoiceFactory(
            customer=cls.customer,
            currency=cls.currency,
            number="CN-2024-001",
            bill_to_name="Customer SRL",
            bill_to_country="RO",
            bill_to_tax_id="RO87654321",
            status="issued",
            issued_at=timezone.now(),
            subtotal_cents=50000,
            tax_total_cents=9500,
            total_cents=59500,
        )
        cls.line = InvoiceLineFactory(
            invoice=cls.credit_note,
            description="Partial Refund",
            unit_price_cents=50000,
            quantity=1,
            tax_rate=Decimal("0.1900"),  # Matches credit note's tax_total_cents=9500
        )

    def test_build_credit_note_generates_valid_xml(self):
        """Test that credit note build generates valid XML."""
        builder = UBLCreditNoteBuilder(self.credit_note, self.original_invoice)
        xml = builder.build()

        self.assertIsInstance(xml, str)
        doc = etree.fromstring(xml.encode())
        self.assertIsNotNone(doc)

        # Root should be CreditNote
        self.assertTrue(doc.tag.endswith("CreditNote"))

    def test_credit_note_contains_billing_reference(self):
        """Test that credit note references original invoice."""
        builder = UBLCreditNoteBuilder(self.credit_note, self.original_invoice)
        xml = builder.build()
        doc = etree.fromstring(xml.encode())

        billing_ref = doc.find(f".//{{{NAMESPACES['cac']}}}BillingReference")
        self.assertIsNotNone(billing_ref)

        invoice_ref = billing_ref.find(f".//{{{NAMESPACES['cac']}}}InvoiceDocumentReference/{{{NAMESPACES['cbc']}}}ID")
        self.assertIsNotNone(invoice_ref)
        self.assertEqual(invoice_ref.text, "INV-2024-001")

    def test_credit_note_type_code(self):
        """Test that credit note has correct type code."""
        builder = UBLCreditNoteBuilder(self.credit_note, self.original_invoice)
        xml = builder.build()
        doc = etree.fromstring(xml.encode())

        type_code = doc.find(f".//{{{NAMESPACES['cbc']}}}CreditNoteTypeCode")
        self.assertIsNotNone(type_code)
        self.assertEqual(type_code.text, "381")

    def test_validation_error_missing_original_invoice(self):
        """Test that validation fails without original invoice reference."""
        builder = UBLCreditNoteBuilder(self.credit_note, None)
        with self.assertRaises(XMLBuilderError) as context:
            builder.build()

        self.assertIn("Original invoice reference is required", str(context.exception))
