"""Tests for EN16931-compliant line item fields."""
from datetime import date
from decimal import Decimal

from django.test import TestCase

from apps.billing.invoice_models import InvoiceLine
from apps.billing.models import Currency, Invoice, ProformaInvoice
from apps.billing.proforma_models import ProformaLine
from apps.billing.services import ProformaConversionService
from apps.customers.models import Customer


class LineItemFieldTests(TestCase):
    """Test EN16931 fields persist on both line models."""

    def setUp(self) -> None:
        self.customer = Customer.objects.create(name="EN16931 Co", customer_type="company")
        self.currency, _ = Currency.objects.get_or_create(
            code="RON", defaults={"name": "Romanian Leu", "symbol": "lei"},
        )

    def test_invoice_line_en16931_fields(self) -> None:
        invoice = Invoice.objects.create(
            customer=self.customer, number="INV-EN16931", currency=self.currency,
            subtotal_cents=10000, tax_cents=2100, total_cents=12100,
        )
        line = InvoiceLine.objects.create(
            invoice=invoice, kind="service", description="Web Hosting",
            quantity=Decimal("1"), unit_price_cents=10000, tax_rate=Decimal("0.2100"),
            domain_name="test.ro", period_start=date(2026, 1, 1), period_end=date(2026, 1, 31),
            unit_code="MON", tax_category_code="S", note="Monthly hosting",
            seller_item_id="WH-STARTER", sort_order=1, discount_amount_cents=0,
        )
        line.refresh_from_db()
        self.assertEqual(line.domain_name, "test.ro")
        self.assertEqual(line.unit_code, "MON")
        self.assertEqual(line.tax_category_code, "S")
        self.assertEqual(line.period_start, date(2026, 1, 1))
        self.assertEqual(line.seller_item_id, "WH-STARTER")
        self.assertEqual(line.sort_order, 1)

    def test_proforma_line_en16931_fields(self) -> None:
        proforma = ProformaInvoice.objects.create(
            customer=self.customer, number="PRO-EN16931", currency=self.currency,
            subtotal_cents=10000, tax_cents=2100, total_cents=12100,
        )
        line = ProformaLine.objects.create(
            proforma=proforma, kind="service", description="VPS Basic",
            quantity=Decimal("1"), unit_price_cents=10000, tax_rate=Decimal("0.2100"),
            domain_name="vps.test.ro", unit_code="MON", seller_item_id="VPS-BASIC",
            period_start=date(2026, 3, 1), period_end=date(2026, 3, 31),
        )
        line.refresh_from_db()
        self.assertEqual(line.domain_name, "vps.test.ro")
        self.assertEqual(line.unit_code, "MON")

    def test_conversion_copies_all_en16931_fields(self) -> None:
        proforma = ProformaInvoice.objects.create(
            customer=self.customer, number="PRO-CONV", currency=self.currency,
            subtotal_cents=10000, tax_cents=2100, total_cents=12100,
            bill_to_name="Test Co",
        )
        ProformaLine.objects.create(
            proforma=proforma, kind="setup", description="Setup Fee",
            quantity=Decimal("1"), unit_price_cents=5000, tax_rate=Decimal("0.2100"),
            tax_cents=1050, line_total_cents=6050,
            domain_name="conv.ro", period_start=date(2026, 1, 1), period_end=date(2026, 12, 31),
            unit_code="ANN", tax_category_code="S", note="Annual setup",
            seller_item_id="SETUP-ANN", sort_order=1,
        )
        result = ProformaConversionService.convert_to_invoice(str(proforma.id))
        self.assertTrue(result.is_ok())
        invoice = result.unwrap()
        inv_line = invoice.lines.first()
        self.assertEqual(inv_line.kind, "setup")  # NOT hardcoded "service"
        self.assertEqual(inv_line.tax_rate, Decimal("0.2100"))  # Was broken
        self.assertEqual(inv_line.tax_cents, 1050)  # Was broken
        self.assertEqual(inv_line.domain_name, "conv.ro")
        self.assertEqual(inv_line.unit_code, "ANN")
        self.assertEqual(inv_line.tax_category_code, "S")
        self.assertEqual(inv_line.seller_item_id, "SETUP-ANN")
        self.assertEqual(inv_line.sort_order, 1)
        self.assertEqual(inv_line.note, "Annual setup")
