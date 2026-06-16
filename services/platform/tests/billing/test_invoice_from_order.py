"""Regression test for issue #191.

InvoiceService.create_from_order crashed because the InvoiceLine creation
passed fields that don't exist (total_cents=, tax_rate_percent=, meta=) and
read item.name/item.total_cents (OrderItem has product_name/line_total_cents).
This drives the legacy order→invoice path end-to-end so the crash can't recur.
"""

from __future__ import annotations

from decimal import Decimal

import pytest
from django.test import TestCase

from apps.billing.invoice_models import InvoiceSequence
from apps.billing.models import Currency
from apps.billing.services import InvoiceService
from apps.customers.models import Customer
from apps.orders.models import Order, OrderItem
from apps.products.models import Product


@pytest.mark.billing
class CreateInvoiceFromOrderTests(TestCase):
    def setUp(self) -> None:
        self.currency = Currency.objects.get_or_create(
            code="RON", defaults={"symbol": "lei", "decimals": 2}
        )[0]
        self.customer = Customer.objects.create(
            name="Order Co", customer_type="company", company_name="Order Co",
            status="active", primary_email="order@example.com",
        )
        self.product = Product.objects.create(
            name="Shared Hosting", slug="hosting-191", product_type="shared_hosting", is_active=True,
        )
        InvoiceSequence.objects.get_or_create(scope="default")

    def _order(self) -> Order:
        order = Order.objects.create(
            customer=self.customer, currency=self.currency,
            customer_email=self.customer.primary_email, customer_name=self.customer.name,
            subtotal_cents=10000, tax_cents=1900, total_cents=11900,
            billing_address={"company_name": "Order Co", "country": "RO"},
        )
        OrderItem.objects.create(
            order=order, product=self.product, product_name=self.product.name,
            product_type=self.product.product_type, quantity=2,
            unit_price_cents=5000, tax_rate=Decimal("0.1900"),
            tax_cents=1900, line_total_cents=11900,
        )
        return order

    def test_create_from_order_succeeds_and_maps_line_fields(self) -> None:
        result = InvoiceService().create_from_order(self._order())

        self.assertTrue(result.is_ok(), result)
        invoice = result.unwrap()

        lines = list(invoice.lines.all())
        self.assertEqual(len(lines), 1)
        line = lines[0]
        # description comes from product_name (not the non-existent item.name)
        self.assertEqual(line.description, "Shared Hosting")
        self.assertEqual(line.quantity, 2)
        self.assertEqual(line.unit_price_cents, 5000)
        # tax_rate is a decimal fraction (e.g. 0.19/0.21), not a percent
        self.assertLess(line.tax_rate, Decimal("1"))
        # save() recomputes tax/line totals from the subtotal (2 x 5000 = 10000),
        # internally consistent with whatever VAT rate the TaxService applied.
        self.assertEqual(line.subtotal_cents, 10000)
        expected_tax = int((Decimal(line.subtotal_cents) * line.tax_rate).quantize(Decimal("1")))
        self.assertEqual(line.tax_cents, expected_tax)
        self.assertEqual(line.line_total_cents, line.subtotal_cents + expected_tax)

    def test_create_from_order_does_not_double_tax_header(self) -> None:
        """The invoice header VAT must be computed on the NET base (gross line subtotal), not on
        order.total_cents (already tax-inclusive). The old code passed order.total_cents to the
        VAT engine, re-taxing an already-taxed amount. Rate-agnostic — no dependency on the
        current RO VAT rate."""
        order = self._order()  # subtotal 10000 (net), total 11900 (gross+VAT), no discount
        invoice = InvoiceService().create_from_order(order).unwrap()
        # Subtotal is the NET taxable base, NOT the gross tax-inclusive total.
        self.assertEqual(invoice.subtotal_cents, order.subtotal_cents)   # 10000, not 11900
        self.assertNotEqual(invoice.subtotal_cents, order.total_cents)   # explicitly not double-taxed
        # Internal invariant holds and VAT sits on the net base (no second VAT layer).
        self.assertEqual(invoice.subtotal_cents + invoice.tax_cents, invoice.total_cents)
        self.assertLess(invoice.tax_cents, invoice.subtotal_cents)

    def test_create_from_order_carries_discount_and_uses_net_base(self) -> None:
        """A document discount reduces the taxable base (net) and is carried onto the invoice."""
        order = Order.objects.create(
            customer=self.customer, currency=self.currency,
            customer_email=self.customer.primary_email, customer_name=self.customer.name,
            subtotal_cents=10000, discount_cents=1000, tax_cents=1710, total_cents=10710,
            billing_address={"company_name": "Order Co", "country": "RO"},
        )
        OrderItem.objects.create(
            order=order, product=self.product, product_name=self.product.name,
            product_type=self.product.product_type, quantity=2,
            unit_price_cents=5000, tax_rate=Decimal("0.1900"),
            tax_cents=1900, line_total_cents=11900,
        )
        invoice = InvoiceService().create_from_order(order).unwrap()
        self.assertEqual(invoice.discount_cents, 1000)                   # discount carried onto the invoice
        self.assertEqual(invoice.subtotal_cents, 9000)                  # net = gross(10000) - discount(1000)
        self.assertEqual(invoice.subtotal_cents + invoice.tax_cents, invoice.total_cents)
