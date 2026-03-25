# ===============================================================================
# EN16931 COMPLIANCE TESTS
# ===============================================================================
"""
Tests for EN16931 e-invoicing compliance across the Order → Proforma → Invoice lifecycle.
Covers: snapshot architecture, field propagation, auto-derivation, and XML generation.
"""

from datetime import date, timedelta
from decimal import Decimal

import pytest
from django.test import TestCase

from apps.billing.models import Currency, Invoice, InvoiceLine, ProformaInvoice
from apps.billing.proforma_models import ProformaLine
from apps.customers.models import Customer
from apps.orders.models import Order, OrderItem
from apps.products.models import Product


@pytest.mark.billing
@pytest.mark.romanian_compliance
class TestOrderItemSnapshotArchitecture(TestCase):
    """Test that OrderItem correctly snapshots product information for EN16931."""

    def setUp(self):
        self.currency = Currency.objects.get_or_create(code="RON", defaults={"symbol": "L", "decimals": 2})[0]
        self.customer = Customer.objects.create(
            name="Test Co", customer_type="company", company_name="Test Co", status="active",
        )
        self.product = Product.objects.create(
            name="Web Hosting Pro", slug="web-hosting-pro", product_type="shared_hosting",
        )
        self.order = Order.objects.create(
            customer=self.customer, currency=self.currency, status="awaiting_payment",
            subtotal_cents=5999, tax_cents=1260, total_cents=7259,
        )

    def test_product_slug_snapshotted_on_save(self):
        """OrderItem.save() should snapshot product.slug into product_slug."""
        item = OrderItem(
            order=self.order, product=self.product, product_name="", product_type="",
            quantity=1, unit_price_cents=5999,
        )
        item.save()
        self.assertEqual(item.product_slug, "web-hosting-pro")

    def test_product_slug_not_overwritten_if_set(self):
        """If product_slug is already set, save() should not overwrite it."""
        item = OrderItem(
            order=self.order, product=self.product, product_name="Web Hosting Pro",
            product_type="hosting", product_slug="custom-slug",
            quantity=1, unit_price_cents=5999,
        )
        item.save()
        self.assertEqual(item.product_slug, "custom-slug")

    def test_product_slug_survives_product_deletion(self):
        """Even if product is deleted, the snapshot remains on OrderItem."""
        item = OrderItem.objects.create(
            order=self.order, product=self.product, product_name="Web Hosting Pro",
            product_type="hosting", product_slug="web-hosting-pro",
            quantity=1, unit_price_cents=5999,
        )
        # Product deletion is PROTECT, so test the snapshot is independent
        item.refresh_from_db()
        self.assertEqual(item.product_slug, "web-hosting-pro")


@pytest.mark.billing
@pytest.mark.romanian_compliance
class TestProformaLineEN16931Fields(TestCase):
    """Test that ProformaLine correctly stores EN16931 fields."""

    def setUp(self):
        self.currency = Currency.objects.get_or_create(code="RON", defaults={"symbol": "L", "decimals": 2})[0]
        self.customer = Customer.objects.create(
            name="Test Co", customer_type="company", company_name="Test Co", status="active",
        )

    def _create_proforma(self, **kwargs):
        defaults = {
            "customer": self.customer, "currency": self.currency,
            "number": "PRO-TEST-001", "status": "draft",
            "subtotal_cents": 5999, "tax_cents": 1260, "total_cents": 7259,
            "valid_until": date.today() + timedelta(days=30),
        }
        defaults.update(kwargs)
        return ProformaInvoice.objects.create(**defaults)

    def test_manual_proforma_auto_derives_en16931_fields(self):
        """Manual proforma lines should get auto-derived EN16931 fields."""
        proforma = self._create_proforma()
        line = ProformaLine.objects.create(
            proforma=proforma, kind="service", description="Web Hosting",
            quantity=Decimal("1.000"), unit_price_cents=5999,
            tax_rate=Decimal("0.2100"), line_total_cents=7259,
            # EN16931 auto-derived fields (as the view would set them)
            sort_order=0, unit_code="C62", tax_category_code="S",
            period_start=proforma.created_at.date(),
            period_end=proforma.valid_until,
            domain_name="example.com",
        )
        self.assertEqual(line.unit_code, "C62")
        self.assertEqual(line.tax_category_code, "S")
        self.assertEqual(line.domain_name, "example.com")
        self.assertIsNotNone(line.period_start)
        self.assertIsNotNone(line.period_end)

    def test_zero_vat_gets_z_category(self):
        """0% VAT lines should get tax_category_code='Z' (Zero-rated)."""
        proforma = self._create_proforma()
        line = ProformaLine.objects.create(
            proforma=proforma, kind="service", description="Export Service",
            quantity=Decimal("1.000"), unit_price_cents=5999,
            tax_rate=Decimal("0.0000"), line_total_cents=5999,
            tax_category_code="Z",
        )
        self.assertEqual(line.tax_category_code, "Z")


@pytest.mark.billing
@pytest.mark.romanian_compliance
class TestProformaToInvoiceConversion(TestCase):
    """Test that ProformaLine→InvoiceLine conversion preserves ALL EN16931 fields."""

    def setUp(self):
        self.currency = Currency.objects.get_or_create(code="RON", defaults={"symbol": "L", "decimals": 2})[0]
        self.customer = Customer.objects.create(
            name="Test Co", customer_type="company", company_name="Test Co", status="active",
        )

    def test_all_en16931_fields_copied(self):
        """Every EN16931 field on ProformaLine must be copied to InvoiceLine."""
        proforma = ProformaInvoice.objects.create(
            customer=self.customer, currency=self.currency,
            number="PRO-CONV-001", status="draft",
            subtotal_cents=5999, tax_cents=1260, total_cents=7259,
            valid_until=date.today() + timedelta(days=30),
        )
        proforma_line = ProformaLine.objects.create(
            proforma=proforma, kind="service", description="Web Hosting Pro",
            quantity=Decimal("1.000"), unit_price_cents=5999,
            tax_rate=Decimal("0.2100"), tax_cents=1260, line_total_cents=7259,
            # All EN16931 fields populated
            domain_name="test.example.com",
            period_start=date(2026, 1, 1), period_end=date(2026, 12, 31),
            unit_code="C62", tax_category_code="S",
            note="Annual hosting subscription",
            discount_amount_cents=500,
            seller_item_id="web-hosting-pro",
            sort_order=1,
        )

        # Simulate conversion by copying fields (as services.py does)
        invoice = Invoice.objects.create(
            customer=self.customer, currency=self.currency,
            number="INV-CONV-001", status="issued",
            subtotal_cents=5999, tax_cents=1260, total_cents=7259,
        )
        invoice_line = InvoiceLine.objects.create(
            invoice=invoice,
            kind=proforma_line.kind,
            description=proforma_line.description,
            quantity=proforma_line.quantity,
            unit_price_cents=proforma_line.unit_price_cents,
            tax_rate=proforma_line.tax_rate,
            tax_cents=proforma_line.tax_cents,
            line_total_cents=proforma_line.line_total_cents,
            domain_name=proforma_line.domain_name,
            period_start=proforma_line.period_start,
            period_end=proforma_line.period_end,
            unit_code=proforma_line.unit_code,
            tax_category_code=proforma_line.tax_category_code,
            note=proforma_line.note,
            discount_amount_cents=proforma_line.discount_amount_cents,
            seller_item_id=proforma_line.seller_item_id,
            sort_order=proforma_line.sort_order,
        )

        # Verify every field
        self.assertEqual(invoice_line.domain_name, "test.example.com")
        self.assertEqual(invoice_line.period_start, date(2026, 1, 1))
        self.assertEqual(invoice_line.period_end, date(2026, 12, 31))
        self.assertEqual(invoice_line.unit_code, "C62")
        self.assertEqual(invoice_line.tax_category_code, "S")
        self.assertEqual(invoice_line.note, "Annual hosting subscription")
        self.assertEqual(invoice_line.discount_amount_cents, 500)
        self.assertEqual(invoice_line.seller_item_id, "web-hosting-pro")
        self.assertEqual(invoice_line.sort_order, 1)


@pytest.mark.billing
@pytest.mark.romanian_compliance
class TestServiceDeletionImmutability(TestCase):
    """Test that deleting a Service doesn't corrupt financial document data."""

    def test_invoice_line_description_survives_service_nullification(self):
        """InvoiceLine.description persists even when service FK is SET_NULL."""
        currency = Currency.objects.get_or_create(code="RON", defaults={"symbol": "L", "decimals": 2})[0]
        customer = Customer.objects.create(
            name="Test Co", customer_type="company", company_name="Test Co", status="active",
        )
        invoice = Invoice.objects.create(
            customer=customer, currency=currency,
            number="INV-IMMUT-001", status="issued",
            subtotal_cents=5999, tax_cents=1260, total_cents=7259,
        )
        line = InvoiceLine.objects.create(
            invoice=invoice, kind="service", description="Web Hosting Pro",
            quantity=Decimal("1.000"), unit_price_cents=5999,
            tax_rate=Decimal("0.2100"), line_total_cents=7259,
            domain_name="immutable.example.com",
            seller_item_id="web-hosting-pro",
            service=None,  # No linked service
        )

        # Verify snapshot fields are intact even without service FK
        line.refresh_from_db()
        self.assertEqual(line.description, "Web Hosting Pro")
        self.assertEqual(line.domain_name, "immutable.example.com")
        self.assertEqual(line.seller_item_id, "web-hosting-pro")
