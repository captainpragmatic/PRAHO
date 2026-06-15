"""
Regression tests for issue #188: line discount must be netted into the taxable
base, VAT, and document totals (EN16931 BR-CO-10 + BR-CO-17).

Before the fix, ``discount_amount_cents`` (BT-147) was stored but never
subtracted: the line ``subtotal_cents`` returned the gross
``quantity * unit_price``, so VAT was charged on the pre-discount amount and the
document totals overstated the taxable base.
"""

from __future__ import annotations

from datetime import date, timedelta
from decimal import Decimal

import pytest
from django.test import TestCase

from apps.billing.models import Currency, Invoice, InvoiceLine, ProformaInvoice
from apps.billing.proforma_models import ProformaLine
from apps.customers.models import Customer


@pytest.mark.billing
class LineDiscountNettingTests(TestCase):
    def setUp(self) -> None:
        self.currency = Currency.objects.get_or_create(
            code="RON", defaults={"symbol": "L", "decimals": 2}
        )[0]
        self.customer = Customer.objects.create(
            name="Test Co", customer_type="company", company_name="Test Co", status="active",
        )

    def _invoice(self) -> Invoice:
        return Invoice.objects.create(
            customer=self.customer, currency=self.currency,
            number="INV-DISC-001", status="issued",
            subtotal_cents=0, tax_cents=0, total_cents=0,
        )

    def test_line_subtotal_is_net_of_discount(self) -> None:
        """BT-131: taxable base = gross - discount."""
        line = InvoiceLine(
            invoice=self._invoice(), kind="service", description="Hosting",
            quantity=Decimal("1.000"), unit_price_cents=100_000,
            tax_rate=Decimal("0.1900"), discount_amount_cents=10_000,
        )
        # 1000.00 gross - 100.00 discount -> 900.00 net taxable base
        self.assertEqual(line.subtotal_cents, 90_000)

    def test_vat_computed_on_net_base(self) -> None:
        """BR-CO-17: VAT is 19% of the net base, not the gross."""
        line = InvoiceLine(
            invoice=self._invoice(), kind="service", description="Hosting",
            quantity=Decimal("1.000"), unit_price_cents=100_000,
            tax_rate=Decimal("0.1900"), discount_amount_cents=10_000,
        )
        line.calculate_totals()
        # 19% of 900.00 = 171.00 (not 190.00 on the gross)
        self.assertEqual(line.tax_cents, 17_100)
        self.assertEqual(line.line_total_cents, 90_000 + 17_100)

    def test_discount_larger_than_gross_floors_at_zero(self) -> None:
        line = InvoiceLine(
            invoice=self._invoice(), kind="service", description="Freebie",
            quantity=Decimal("1.000"), unit_price_cents=5_000,
            tax_rate=Decimal("0.1900"), discount_amount_cents=9_999,
        )
        self.assertEqual(line.subtotal_cents, 0)
        line.calculate_totals()
        self.assertEqual(line.tax_cents, 0)
        self.assertEqual(line.line_total_cents, 0)

    def test_document_totals_net_and_consistent(self) -> None:
        """BR-CO-10: document subtotal == Σ line subtotals (both net); VAT on net."""
        invoice = self._invoice()
        InvoiceLine.objects.create(
            invoice=invoice, kind="service", description="Hosting",
            quantity=Decimal("1.000"), unit_price_cents=100_000,
            tax_rate=Decimal("0.1900"), discount_amount_cents=10_000,
        )
        InvoiceLine.objects.create(
            invoice=invoice, kind="service", description="Domain",
            quantity=Decimal("2.000"), unit_price_cents=5_000,
            tax_rate=Decimal("0.1900"), discount_amount_cents=0,
        )
        invoice.recalculate_totals()

        line_subtotal_sum = sum(line.subtotal_cents for line in invoice.lines.all())
        # 90_000 (net hosting) + 10_000 (2 x 50.00 domain) = 100_000
        self.assertEqual(invoice.subtotal_cents, 100_000)
        self.assertEqual(invoice.subtotal_cents, line_subtotal_sum)
        # VAT on the net base: 19% of 1000.00 = 190.00
        self.assertEqual(invoice.tax_cents, 19_000)
        self.assertEqual(invoice.total_cents, 100_000 + 19_000)

    def test_proforma_line_mirrors_invoice_netting(self) -> None:
        proforma = ProformaInvoice.objects.create(
            customer=self.customer, currency=self.currency, number="PRO-DISC-001",
            status="draft", subtotal_cents=0, tax_cents=0, total_cents=0,
            valid_until=date.today() + timedelta(days=30),
        )
        line = ProformaLine(
            proforma=proforma, kind="service", description="Hosting",
            quantity=Decimal("1.000"), unit_price_cents=100_000,
            tax_rate=Decimal("0.1900"), discount_amount_cents=10_000,
        )
        line.calculate_totals()
        self.assertEqual(line.subtotal_cents, 90_000)
        self.assertEqual(line.tax_cents, 17_100)
