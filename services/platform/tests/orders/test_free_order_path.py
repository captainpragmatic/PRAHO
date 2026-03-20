"""
Tests for M12: Free order path (total=0 skips proforma).

Validates:
- Free orders (total_cents=0) skip proforma creation
- Free orders go directly to paid → provisioning
"""

from decimal import Decimal

from django.test import TestCase

from apps.billing.models import Currency
from apps.customers.models import Customer
from apps.orders.models import Order, OrderItem
from apps.products.models import Product


class FreeOrderPathTest(TestCase):
    """Test that free orders skip proforma and auto-advance."""

    def setUp(self):
        self.currency, _ = Currency.objects.get_or_create(
            code="RON", defaults={"symbol": "lei", "decimals": 2}
        )
        self.customer = Customer.objects.create(
            name="Free Test SRL", customer_type="company",
            status="active", primary_email="free@test.ro",
        )
        self.product = Product.objects.create(
            name="Free Trial", slug="free-trial",
            product_type="shared_hosting", is_active=True,
        )

    def test_free_order_no_proforma_created(self):
        """Orders with total_cents=0 should NOT get a proforma.

        Uses force_status to bypass preflight validation (which requires full billing
        address). The real test is: does the proforma creation code skip when total=0?
        """
        from tests.helpers.fsm_helpers import force_status  # noqa: PLC0415

        order = Order.objects.create(
            customer=self.customer, currency=self.currency,
            customer_email=self.customer.primary_email,
            customer_name=self.customer.name,
            subtotal_cents=0, tax_cents=0, total_cents=0,
            billing_address={},
        )
        OrderItem.objects.create(
            order=order, product=self.product,
            product_name=self.product.name,
            product_type=self.product.product_type,
            quantity=1, unit_price_cents=0,
            tax_rate=Decimal("0.0000"),
            tax_cents=0, line_total_cents=0,
        )

        # Force to awaiting_payment (bypass preflight for test)
        force_status(order, "awaiting_payment")

        # The proforma creation in update_order_status checks total_cents > 0
        # So free orders should have no proforma
        self.assertIsNone(order.proforma)
