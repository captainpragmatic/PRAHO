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
from tests.factories import CurrencyFactory, CustomerFactory, InvoiceFactory, InvoiceLineFactory


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
        # Default is the ANAF-accepted 1.0.1 BT-24 value (NOT the 1.0.9 Schematron version)
        self.assertTrue(customization.text.endswith("CIUS-RO:1.0.1"))

    def test_customization_id_is_configurable(self):
        """#123: the CIUS-RO CustomizationID (BT-24) is overridable via settings, in case
        ANAF ever changes the accepted identifier."""
        with override_settings(EFACTURA_CIUS_RO_CUSTOMIZATION_ID="urn:custom:override"):
            doc = etree.fromstring(UBLInvoiceBuilder(self.invoice).build().encode())
        self.assertEqual(doc.find(f".//{{{NAMESPACES['cbc']}}}CustomizationID").text, "urn:custom:override")

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

    # --- Tax-category regression guards (PR #160 review: 25ef21ab) ---------------

    def _tax_category_for(self, *, bill_to_country, bill_to_tax_id, tax_total_cents, line_category="S"):
        """Build a one-line invoice and return its TaxCategory (ID, Percent) from the XML."""

        total = 100000 + tax_total_cents
        invoice = InvoiceFactory(
            customer=CustomerFactory(),
            currency=self.currency,
            number="INV-2024-TAXCAT",
            bill_to_name="Buyer",
            bill_to_country=bill_to_country,
            bill_to_tax_id=bill_to_tax_id,
            bill_to_street="Street 1",
            bill_to_city="City",
            bill_to_postal_code="010101",
            status="issued",
            issued_at=timezone.now(),
            due_at=timezone.now() + timezone.timedelta(days=30),
            subtotal_cents=100000,
            tax_total_cents=tax_total_cents,
            total_cents=total,
        )
        InvoiceLineFactory(
            invoice=invoice,
            description="Web Hosting Service",
            unit_price_cents=100000,
            quantity=1,
            tax_rate=Decimal("0.1900"),  # non-zero stored rate, must be clamped for non-standard categories
            tax_category_code=line_category,
        )
        doc = etree.fromstring(UBLInvoiceBuilder(invoice).build().encode())
        category = doc.find(
            f".//{{{NAMESPACES['cac']}}}TaxTotal/{{{NAMESPACES['cac']}}}TaxSubtotal/{{{NAMESPACES['cac']}}}TaxCategory"
        )
        self.assertIsNotNone(category)
        cat_id = category.find(f"{{{NAMESPACES['cbc']}}}ID")
        percent = category.find(f"{{{NAMESPACES['cbc']}}}Percent")
        return (cat_id.text if cat_id is not None else None, percent.text if percent is not None else None)

    def test_non_standard_category_clamps_percent_to_zero(self):
        """CRITICAL (BR-AE/E/Z/K/O-05): Percent must be 0.00 for non-standard categories.

        An EU B2B customer with a VAT ID and zero tax is reverse-charge (AE); the
        document VAT breakdown must emit Percent=0.00 — ANAF rejects a non-zero rate.
        """
        cat_id, percent = self._tax_category_for(
            bill_to_country="DE", bill_to_tax_id="DE123456789", tax_total_cents=0, line_category="S"
        )
        self.assertEqual(cat_id, "AE")
        self.assertEqual(percent, "0.00")

    def test_standard_category_keeps_line_rate(self):
        """Standard category must keep the stored 19% rate (clamp only applies to non-standard)."""
        cat_id, percent = self._tax_category_for(
            bill_to_country="RO", bill_to_tax_id="RO87654321", tax_total_cents=19000, line_category="S"
        )
        self.assertEqual(cat_id, "S")
        self.assertEqual(percent, "19.00")

    def test_zero_tax_eu_customer_with_vat_id_is_reverse_charge(self):
        """EU cross-border B2B (valid VAT ID, zero tax) is reverse charge (AE / taxare
        inversa, VATEX-EU-AE), NOT zero-rated (Z). Reverse-charge is detected before the
        domestic zero-rated fallback (EN16931 / CIUS-RO).
        """
        cat_id, _ = self._tax_category_for(
            bill_to_country="DE", bill_to_tax_id="DE123456789", tax_total_cents=0, line_category="S"
        )
        self.assertEqual(cat_id, "AE")

    def test_non_eu_customer_with_tax_id_is_standard_not_reverse_charge(self):
        """HIGH: reverse charge (AE) applies only inside the EU VAT system.

        A US customer with a tax ID must classify as standard (S), not AE.
        """
        cat_id, _ = self._tax_category_for(
            bill_to_country="US", bill_to_tax_id="US-EIN-123", tax_total_cents=19000, line_category="S"
        )
        self.assertEqual(cat_id, "S")

    def _build_doc_for(self, *, bill_to_country, bill_to_tax_id, tax_total_cents):
        """Build invoice XML and return the parsed doc for the given tax profile."""

        invoice = InvoiceFactory(
            customer=CustomerFactory(), currency=self.currency, number="INV-CAT-XML",
            bill_to_name="Customer", bill_to_country=bill_to_country, bill_to_tax_id=bill_to_tax_id,
            bill_to_street="Street 1", bill_to_city="City", bill_to_postal_code="010101",
            status="issued", issued_at=timezone.now(), due_at=timezone.now() + timezone.timedelta(days=30),
            subtotal_cents=100000, tax_total_cents=tax_total_cents, total_cents=100000 + tax_total_cents,
        )
        InvoiceLineFactory(
            invoice=invoice, description="Web Hosting", unit_price_cents=100000,
            quantity=1, tax_rate=Decimal("0.1900"), tax_category_code="S",
        )
        return etree.fromstring(UBLInvoiceBuilder(invoice).build().encode())

    def _doc_tax_category(self, doc):
        return doc.find(
            f".//{{{NAMESPACES['cac']}}}TaxTotal/{{{NAMESPACES['cac']}}}TaxSubtotal/{{{NAMESPACES['cac']}}}TaxCategory"
        )

    def test_reverse_charge_emits_vatex_ae_exemption(self):
        """BR-AE-10: AE (EU reverse charge) emits TaxExemptionReasonCode=VATEX-EU-AE."""
        cat = self._doc_tax_category(
            self._build_doc_for(bill_to_country="DE", bill_to_tax_id="DE123456789", tax_total_cents=0)
        )
        self.assertEqual(cat.find(f"{{{NAMESPACES['cbc']}}}ID").text, "AE")
        code = cat.find(f"{{{NAMESPACES['cbc']}}}TaxExemptionReasonCode")
        self.assertIsNotNone(code)
        self.assertEqual(code.text, "VATEX-EU-AE")

    def test_zero_rated_emits_no_exemption_reason(self):
        """REGRESSION PROOF (BR-Z-10): zero-rated (Z) emits NEITHER reason code NOR text."""
        cat = self._doc_tax_category(
            self._build_doc_for(bill_to_country="RO", bill_to_tax_id="RO87654321", tax_total_cents=0)
        )
        self.assertEqual(cat.find(f"{{{NAMESPACES['cbc']}}}ID").text, "Z")
        self.assertIsNone(cat.find(f"{{{NAMESPACES['cbc']}}}TaxExemptionReasonCode"))
        self.assertIsNone(cat.find(f"{{{NAMESPACES['cbc']}}}TaxExemptionReason"))

    def test_standard_emits_no_exemption_reason(self):
        """BR-S-10: standard (S) emits no exemption reason code or text."""
        cat = self._doc_tax_category(
            self._build_doc_for(bill_to_country="RO", bill_to_tax_id="RO87654321", tax_total_cents=19000)
        )
        self.assertEqual(cat.find(f"{{{NAMESPACES['cbc']}}}ID").text, "S")
        self.assertIsNone(cat.find(f"{{{NAMESPACES['cbc']}}}TaxExemptionReasonCode"))
        self.assertIsNone(cat.find(f"{{{NAMESPACES['cbc']}}}TaxExemptionReason"))

    def test_out_of_scope_emits_vatex_o(self):
        """Non-RO customer without a VAT ID on a zero-tax invoice is O (VATEX-EU-O)."""
        cat = self._doc_tax_category(
            self._build_doc_for(bill_to_country="US", bill_to_tax_id="", tax_total_cents=0)
        )
        self.assertEqual(cat.find(f"{{{NAMESPACES['cbc']}}}ID").text, "O")
        self.assertEqual(cat.find(f"{{{NAMESPACES['cbc']}}}TaxExemptionReasonCode").text, "VATEX-EU-O")

    def test_reverse_charge_all_lines_coherent_ae_zero(self):
        """BR-AE-1: every invoice line is AE with Percent 0.00 when the document is AE."""
        doc = self._build_doc_for(bill_to_country="DE", bill_to_tax_id="DE123456789", tax_total_cents=0)
        lines = doc.findall(f".//{{{NAMESPACES['cac']}}}InvoiceLine")
        self.assertGreaterEqual(len(lines), 1)
        for ln in lines:
            cat = ln.find(f".//{{{NAMESPACES['cac']}}}ClassifiedTaxCategory")
            self.assertEqual(cat.find(f"{{{NAMESPACES['cbc']}}}ID").text, "AE")
            self.assertEqual(cat.find(f"{{{NAMESPACES['cbc']}}}Percent").text, "0.00")

    def _build_invoice_with_meta(self, *, meta, bill_to_country="DE", bill_to_tax_id="DE123456789", subtotal_cents=100000, tax_total_cents=0):
        """Build an invoice doc with in-memory `meta` (allowances/charges).

        The Invoice model has no `meta` field, so the document-level allowance/charge
        path is dormant in production; setting it on the instance exercises that path.
        Defaults model an AE (EU reverse-charge, tax 0) invoice; total = subtotal + tax.
        """
        invoice = InvoiceFactory(
            customer=CustomerFactory(), currency=self.currency, number="INV-LMT-META",
            bill_to_name="Customer", bill_to_country=bill_to_country, bill_to_tax_id=bill_to_tax_id,
            bill_to_street="Street 1", bill_to_city="City", bill_to_postal_code="010101",
            status="issued", issued_at=timezone.now(), due_at=timezone.now() + timezone.timedelta(days=30),
            subtotal_cents=subtotal_cents, tax_total_cents=tax_total_cents,
            total_cents=subtotal_cents + tax_total_cents,
        )
        InvoiceLineFactory(
            invoice=invoice, description="Web Hosting", unit_price_cents=subtotal_cents,
            quantity=1, tax_rate=Decimal("0.1900"), tax_category_code="S",
        )
        invoice.meta = meta
        return etree.fromstring(UBLInvoiceBuilder(invoice).build().encode())

    def _lmt_amount(self, doc, name):
        return doc.find(
            f".//{{{NAMESPACES['cac']}}}LegalMonetaryTotal/{{{NAMESPACES['cbc']}}}{name}"
        ).text

    def test_doc_allowance_reconciles_totals_and_orders_elements(self):
        """BR-CO-13/15 + UBL order: a document-level allowance nets TaxExclusiveAmount,
        TaxInclusiveAmount = TaxExclusive + tax, PayableAmount = TaxInclusive, and
        TaxExclusive/Inclusive precede the allowance/charge totals (UBL element order).
        AE (reverse charge, tax 0) so the whole chain is ANAF-conformant; the deep
        tax-value recalc for standard-rate-with-allowances stays with #177.
        """
        doc = self._build_invoice_with_meta(
            meta={"allowances": [{"amount_cents": 10000, "reason": "Loyalty discount"}]},
        )
        lmt = doc.find(f".//{{{NAMESPACES['cac']}}}LegalMonetaryTotal")
        order = [etree.QName(c).localname for c in lmt]
        self.assertLess(order.index("TaxExclusiveAmount"), order.index("AllowanceTotalAmount"))
        self.assertLess(order.index("TaxInclusiveAmount"), order.index("AllowanceTotalAmount"))
        self.assertEqual(self._lmt_amount(doc, "LineExtensionAmount"), "1000.00")
        self.assertEqual(self._lmt_amount(doc, "TaxExclusiveAmount"), "900.00")
        self.assertEqual(self._lmt_amount(doc, "TaxInclusiveAmount"), "900.00")
        self.assertEqual(self._lmt_amount(doc, "AllowanceTotalAmount"), "100.00")
        self.assertEqual(self._lmt_amount(doc, "PayableAmount"), "900.00")
        taxable = doc.find(
            f".//{{{NAMESPACES['cac']}}}TaxTotal/{{{NAMESPACES['cac']}}}TaxSubtotal/{{{NAMESPACES['cbc']}}}TaxableAmount"
        )
        self.assertEqual(taxable.text, "900.00")

    def test_doc_charge_raises_tax_exclusive_amount(self):
        """A document-level charge raises TaxExclusiveAmount; TaxInclusive stays
        TaxExclusive + tax and PayableAmount tracks it (BR-CO-13/15). AE (tax 0)."""
        doc = self._build_invoice_with_meta(
            meta={"charges": [{"amount_cents": 5000, "reason": "Handling"}]},
        )
        self.assertEqual(self._lmt_amount(doc, "TaxExclusiveAmount"), "1050.00")
        self.assertEqual(self._lmt_amount(doc, "ChargeTotalAmount"), "50.00")
        self.assertEqual(self._lmt_amount(doc, "TaxInclusiveAmount"), "1050.00")
        self.assertEqual(self._lmt_amount(doc, "PayableAmount"), "1050.00")

    def test_invalid_allowance_amount_is_skipped_not_crash(self):
        """A malformed amount_cents (None / non-numeric) is skipped (logged), not a
        crash; valid sibling entries still emit and total correctly."""
        doc = self._build_invoice_with_meta(
            meta={"allowances": [
                {"amount_cents": None, "reason": "broken"},
                {"amount_cents": "not-a-number", "reason": "also broken"},
                {"amount_cents": 5000, "reason": "valid"},
            ]},
        )
        allowances = [
            ac for ac in doc.findall(f".//{{{NAMESPACES['cac']}}}AllowanceCharge")
            if ac.find(f"{{{NAMESPACES['cbc']}}}ChargeIndicator").text == "false"
        ]
        self.assertEqual(len(allowances), 1)
        self.assertEqual(self._lmt_amount(doc, "AllowanceTotalAmount"), "50.00")
        self.assertEqual(self._lmt_amount(doc, "TaxExclusiveAmount"), "950.00")

    def test_document_discount_emits_allowance_and_reconciles(self):
        """#188: a stored document-level discount emits a BG-20 AllowanceCharge, and the
        totals reconcile — BT-106 = Σ line gross, TaxExclusive = TaxableAmount = net,
        TaxAmount = net*rate, and BT-106 = Σ line BT-131 (BR-CO-10/13/17)."""
        invoice = InvoiceFactory(
            customer=CustomerFactory(), currency=self.currency, number="INV-DOCDISC",
            bill_to_name="Customer", bill_to_country="RO", bill_to_tax_id="RO12345678",
            bill_to_street="Street 1", bill_to_city="City", bill_to_postal_code="010101",
            status="issued", issued_at=timezone.now(), due_at=timezone.now() + timezone.timedelta(days=30),
            subtotal_cents=90000, tax_total_cents=17100, total_cents=107100, discount_cents=10000,
        )
        InvoiceLineFactory(
            invoice=invoice, description="Web Hosting", unit_price_cents=100000,
            quantity=1, tax_rate=Decimal("0.1900"), tax_category_code="S",
        )
        doc = etree.fromstring(UBLInvoiceBuilder(invoice).build().encode())

        allow = doc.find(f".//{{{NAMESPACES['cac']}}}AllowanceCharge")
        self.assertIsNotNone(allow)
        self.assertEqual(allow.find(f"{{{NAMESPACES['cbc']}}}ChargeIndicator").text, "false")
        self.assertEqual(allow.find(f"{{{NAMESPACES['cbc']}}}Amount").text, "100.00")

        self.assertEqual(self._lmt_amount(doc, "LineExtensionAmount"), "1000.00")
        self.assertEqual(self._lmt_amount(doc, "AllowanceTotalAmount"), "100.00")
        self.assertEqual(self._lmt_amount(doc, "TaxExclusiveAmount"), "900.00")

        ts = doc.find(f".//{{{NAMESPACES['cac']}}}TaxTotal/{{{NAMESPACES['cac']}}}TaxSubtotal")
        self.assertEqual(ts.find(f"{{{NAMESPACES['cbc']}}}TaxableAmount").text, "900.00")
        self.assertEqual(ts.find(f"{{{NAMESPACES['cbc']}}}TaxAmount").text, "171.00")

        lines = doc.findall(f".//{{{NAMESPACES['cac']}}}InvoiceLine")
        line_sum = sum(
            (Decimal(ln.find(f"{{{NAMESPACES['cbc']}}}LineExtensionAmount").text) for ln in lines),
            Decimal(0),
        )
        self.assertEqual(line_sum, Decimal("1000.00"))

    def test_legacy_invoice_without_stored_discount_still_reconciles(self):
        """#188: a legacy invoice (net subtotal, gross lines, discount_cents=0, created
        before the field existed) still emits a reconciled e-Factura — the discount is
        derived from Σ(line gross) - subtotal, so no ledger backfill is required."""
        invoice = InvoiceFactory(
            customer=CustomerFactory(), currency=self.currency, number="INV-LEGACY-DISC",
            bill_to_name="Customer", bill_to_country="RO", bill_to_tax_id="RO12345678",
            bill_to_street="Street 1", bill_to_city="City", bill_to_postal_code="010101",
            status="issued", issued_at=timezone.now(), due_at=timezone.now() + timezone.timedelta(days=30),
            subtotal_cents=90000, tax_total_cents=17100, total_cents=107100, discount_cents=0,
        )
        InvoiceLineFactory(
            invoice=invoice, description="Web Hosting", unit_price_cents=100000,
            quantity=1, tax_rate=Decimal("0.1900"), tax_category_code="S",
        )
        doc = etree.fromstring(UBLInvoiceBuilder(invoice).build().encode())
        # derived discount = 1000 - 900 = 100 → reconciles to net 900 (not inflated to 1000)
        self.assertEqual(self._lmt_amount(doc, "LineExtensionAmount"), "1000.00")
        self.assertEqual(self._lmt_amount(doc, "AllowanceTotalAmount"), "100.00")
        self.assertEqual(self._lmt_amount(doc, "TaxExclusiveAmount"), "900.00")

    def test_payable_amount_subtracts_prepaid_payments(self):
        """#178 (correct via #189): a partially-paid invoice emits PrepaidAmount (BT-113)
        and a PayableAmount (BT-115) reduced by the net collected payments."""
        from apps.billing.payment_models import Payment  # noqa: PLC0415

        invoice = InvoiceFactory(
            customer=CustomerFactory(), currency=self.currency, number="INV-PREPAID",
            bill_to_name="Customer", bill_to_country="RO", bill_to_tax_id="RO12345678",
            bill_to_street="Street 1", bill_to_city="City", bill_to_postal_code="010101",
            status="issued", issued_at=timezone.now(), due_at=timezone.now() + timezone.timedelta(days=30),
            subtotal_cents=100000, tax_total_cents=19000, total_cents=119000,
        )
        InvoiceLineFactory(
            invoice=invoice, description="Web Hosting", unit_price_cents=100000,
            quantity=1, tax_rate=Decimal("0.1900"), tax_category_code="S",
        )
        Payment.objects.create(
            customer=invoice.customer, invoice=invoice, currency=self.currency,
            amount_cents=50000, status="succeeded",
        )
        doc = etree.fromstring(UBLInvoiceBuilder(invoice).build().encode())
        self.assertEqual(self._lmt_amount(doc, "PrepaidAmount"), "500.00")
        self.assertEqual(self._lmt_amount(doc, "PayableAmount"), "690.00")

    def test_payable_amount_omits_prepaid_when_unpaid(self):
        """An unpaid invoice emits no PrepaidAmount; PayableAmount is the full TaxInclusive."""
        invoice = InvoiceFactory(
            customer=CustomerFactory(), currency=self.currency, number="INV-UNPAID",
            bill_to_name="Customer", bill_to_country="RO", bill_to_tax_id="RO12345678",
            bill_to_street="Street 1", bill_to_city="City", bill_to_postal_code="010101",
            status="issued", issued_at=timezone.now(), due_at=timezone.now() + timezone.timedelta(days=30),
            subtotal_cents=100000, tax_total_cents=19000, total_cents=119000,
        )
        InvoiceLineFactory(
            invoice=invoice, description="Web Hosting", unit_price_cents=100000,
            quantity=1, tax_rate=Decimal("0.1900"), tax_category_code="S",
        )
        doc = etree.fromstring(UBLInvoiceBuilder(invoice).build().encode())
        lmt = doc.find(f".//{{{NAMESPACES['cac']}}}LegalMonetaryTotal")
        self.assertIsNone(lmt.find(f"{{{NAMESPACES['cbc']}}}PrepaidAmount"))
        self.assertEqual(self._lmt_amount(doc, "PayableAmount"), "1190.00")

    def test_line_extension_reconciles_with_fractional_quantity(self):
        """BR-CO-10: the document LineExtensionAmount (Σ line.subtotal_cents) and each
        line's LineExtensionAmount must agree exactly. With a fractional quantity, computing
        the line amount as unit_price*qty and rounding could differ from the cents-truncated
        line subtotal by 0.01 — which ANAF rejects. Both must derive from the same value."""
        invoice = InvoiceFactory(
            customer=CustomerFactory(), currency=self.currency, number="INV-FRACQTY",
            bill_to_name="Customer", bill_to_country="RO", bill_to_tax_id="RO12345678",
            bill_to_street="Street 1", bill_to_city="City", bill_to_postal_code="010101",
            status="issued", issued_at=timezone.now(), due_at=timezone.now() + timezone.timedelta(days=30),
            # line.subtotal_cents = int(0.333 * 10005) = 3331 (33.31); header matches it (no discount)
            subtotal_cents=3331, tax_total_cents=633, total_cents=3964,
        )
        InvoiceLineFactory(
            invoice=invoice, description="Metered service", unit_price_cents=10005,
            quantity=Decimal("0.333"), tax_rate=Decimal("0.1900"), tax_category_code="S",
        )
        doc = etree.fromstring(UBLInvoiceBuilder(invoice).build().encode())
        lines = doc.findall(f".//{{{NAMESPACES['cac']}}}InvoiceLine")
        line_sum = sum(
            (Decimal(ln.find(f"{{{NAMESPACES['cbc']}}}LineExtensionAmount").text) for ln in lines),
            Decimal(0),
        )
        # Σ line BT-131 == document BT-106 (was 33.32 vs 33.31 before the fix).
        self.assertEqual(line_sum, Decimal(self._lmt_amount(doc, "LineExtensionAmount")))
        self.assertEqual(line_sum, Decimal("33.31"))

    def test_prepaid_amount_capped_to_tax_inclusive(self):
        """BR-CO-16: PrepaidAmount must not exceed TaxInclusiveAmount. On a legacy invoice
        whose stored total_cents diverges above the line-derived tax-inclusive total, a full
        prepayment derived from total_cents could otherwise emit Prepaid > TaxInclusive."""
        from unittest.mock import patch  # noqa: PLC0415

        invoice = InvoiceFactory(
            customer=CustomerFactory(), currency=self.currency, number="INV-PREPAID-CAP",
            bill_to_name="Customer", bill_to_country="RO", bill_to_tax_id="RO12345678",
            bill_to_street="Street 1", bill_to_city="City", bill_to_postal_code="010101",
            status="issued", issued_at=timezone.now(), due_at=timezone.now() + timezone.timedelta(days=30),
            # Stored header (1190.00) diverges above the single line's gross (500.00).
            subtotal_cents=100000, tax_total_cents=19000, total_cents=119000,
        )
        InvoiceLineFactory(
            invoice=invoice, description="Web Hosting", unit_price_cents=50000,
            quantity=1, tax_rate=Decimal("0.1900"), tax_category_code="S",
        )
        # Fully paid → prepaid derives from stored total_cents (1190.00), but the XML
        # tax-inclusive is line-derived (500 net + 190 tax = 690.00).
        with patch.object(invoice, "get_remaining_amount", return_value=0):
            doc = etree.fromstring(UBLInvoiceBuilder(invoice).build().encode())
        prepaid = Decimal(self._lmt_amount(doc, "PrepaidAmount"))
        tax_inclusive = Decimal(self._lmt_amount(doc, "TaxInclusiveAmount"))
        self.assertLessEqual(prepaid, tax_inclusive)          # BR-CO-16
        self.assertEqual(prepaid, tax_inclusive)              # capped exactly
        self.assertEqual(self._lmt_amount(doc, "PayableAmount"), "0.00")

    def test_multi_rate_invoice_is_rejected(self):
        """Single-category invariant: an invoice whose lines carry multiple distinct VAT rates must
        be rejected — the builder emits ONE TaxSubtotal and cannot faithfully represent mixed rates,
        so a multi-rate document would produce a VAT breakdown that fails ANAF arithmetic."""
        invoice = InvoiceFactory(
            customer=CustomerFactory(), currency=self.currency, number="INV-MULTIRATE",
            bill_to_name="Customer", bill_to_country="RO", bill_to_tax_id="RO12345678",
            bill_to_street="Street 1", bill_to_city="City", bill_to_postal_code="010101",
            status="issued", issued_at=timezone.now(), due_at=timezone.now() + timezone.timedelta(days=30),
            subtotal_cents=15000, tax_total_cents=2550, total_cents=17550,
        )
        InvoiceLineFactory(invoice=invoice, description="Standard", unit_price_cents=10000,
                           quantity=1, tax_rate=Decimal("0.1900"), tax_category_code="S")
        InvoiceLineFactory(invoice=invoice, description="Reduced", unit_price_cents=5000,
                           quantity=1, tax_rate=Decimal("0.0900"), tax_category_code="S")
        with self.assertRaises(XMLBuilderError):
            UBLInvoiceBuilder(invoice).build()

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

    def test_payment_means_unmapped_method_falls_back_to_credit_transfer(self):
        """#177 cleanup: 'card'/'direct_debit' are not valid Payment methods (the system
        normalizes 'card' to 'stripe' before storage), so they are no longer special-cased
        in PAYMENT_MEANS_CODES and fall back to credit transfer (30)."""
        invoice = InvoiceFactory(
            customer=CustomerFactory(), currency=self.currency, number="INV-PM-CARD",
            bill_to_name="Customer", bill_to_country="RO", bill_to_tax_id="RO12345678",
            bill_to_street="Street 1", bill_to_city="City", bill_to_postal_code="010101",
            status="issued", issued_at=timezone.now(), due_at=timezone.now() + timezone.timedelta(days=30),
            subtotal_cents=100000, tax_total_cents=19000, total_cents=119000,
            meta={"payment_method": "card"},
        )
        InvoiceLineFactory(
            invoice=invoice, description="Web Hosting", unit_price_cents=100000,
            quantity=1, tax_rate=Decimal("0.1900"), tax_category_code="S",
        )
        doc = etree.fromstring(UBLInvoiceBuilder(invoice).build().encode())
        code = doc.find(
            f".//{{{NAMESPACES['cac']}}}PaymentMeans//{{{NAMESPACES['cbc']}}}PaymentMeansCode"
        )
        self.assertEqual(code.text, "30")

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

    def test_credit_note_document_discount_emits_allowance_and_reconciles(self):
        """#188: a discounted credit note emits a BG-20 AllowanceCharge and reconciles —
        BT-106 = Σ line gross, TaxExclusive = TaxableAmount = net, Σ line = BT-106."""
        cn = InvoiceFactory(
            customer=self.customer, currency=self.currency, number="CN-DISC-001",
            bill_to_name="Customer SRL", bill_to_country="RO", bill_to_tax_id="RO87654321",
            status="issued", issued_at=timezone.now(),
            subtotal_cents=90000, tax_total_cents=17100, total_cents=107100, discount_cents=10000,
        )
        InvoiceLineFactory(
            invoice=cn, description="Refund", unit_price_cents=100000, quantity=1,
            tax_rate=Decimal("0.1900"), tax_category_code="S",
        )
        doc = etree.fromstring(UBLCreditNoteBuilder(cn, self.original_invoice).build().encode())

        allow = doc.find(f".//{{{NAMESPACES['cac']}}}AllowanceCharge")
        self.assertIsNotNone(allow)
        self.assertEqual(allow.find(f"{{{NAMESPACES['cbc']}}}Amount").text, "100.00")

        lmt = doc.find(f".//{{{NAMESPACES['cac']}}}LegalMonetaryTotal")
        self.assertEqual(lmt.find(f"{{{NAMESPACES['cbc']}}}LineExtensionAmount").text, "1000.00")
        self.assertEqual(lmt.find(f"{{{NAMESPACES['cbc']}}}TaxExclusiveAmount").text, "900.00")
        self.assertEqual(lmt.find(f"{{{NAMESPACES['cbc']}}}AllowanceTotalAmount").text, "100.00")

        ts = doc.find(f".//{{{NAMESPACES['cac']}}}TaxTotal/{{{NAMESPACES['cac']}}}TaxSubtotal")
        self.assertEqual(ts.find(f"{{{NAMESPACES['cbc']}}}TaxableAmount").text, "900.00")

        lines = doc.findall(f".//{{{NAMESPACES['cac']}}}CreditNoteLine")
        line_sum = sum(
            (Decimal(ln.find(f"{{{NAMESPACES['cbc']}}}LineExtensionAmount").text) for ln in lines),
            Decimal(0),
        )
        self.assertEqual(line_sum, Decimal("1000.00"))

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
