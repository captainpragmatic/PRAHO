"""
Tests for C1: Smart email timing based on payment method.

Validates:
- Bank transfer: proforma email sent immediately at awaiting_payment
- Card: no email on order creation (deferred until payment result)
"""

from unittest.mock import patch

from django.test import TestCase

from apps.billing.models import Currency
from apps.customers.models import Customer
from apps.orders.models import Order, OrderItem
from apps.products.models import Product
from tests.helpers.fsm_helpers import force_status


class EmailTimingTest(TestCase):
    """Test payment-method-aware email timing."""

    def setUp(self):
        self.currency, _ = Currency.objects.get_or_create(
            code="RON", defaults={"symbol": "lei", "decimals": 2}
        )
        self.customer = Customer.objects.create(
            name="Email Test SRL", customer_type="company",
            status="active", primary_email="email@test.ro",
        )
        self.product = Product.objects.create(
            name="Email Product", slug="email-product",
            product_type="shared_hosting", is_active=True,
        )

    def _create_order(self, payment_method="bank_transfer"):
        order = Order.objects.create(
            customer=self.customer, currency=self.currency,
            customer_email=self.customer.primary_email,
            customer_name=self.customer.name,
            subtotal_cents=10000, tax_cents=2100, total_cents=12100,
            billing_address={}, payment_method=payment_method,
        )
        OrderItem.objects.create(
            order=order, product=self.product,
            product_name=self.product.name,
            product_type=self.product.product_type,
            quantity=1, unit_price_cents=10000,
        )
        return order

    @patch("apps.orders.signals._send_proforma_email_for_order")
    def test_bank_transfer_sends_proforma_email(self, mock_send):
        """Bank transfer orders get proforma email at awaiting_payment."""
        order = self._create_order(payment_method="bank_transfer")
        force_status(order, "awaiting_payment")

        # Simulate the signal handler for awaiting_payment
        from apps.orders.signals import _handle_order_status_change  # noqa: PLC0415
        _handle_order_status_change(order, "draft", "awaiting_payment")

        mock_send.assert_called_once_with(order)

    @patch("apps.orders.signals._send_proforma_email_for_order")
    def test_card_payment_defers_email(self, mock_send):
        """Card payment orders do NOT get proforma email at awaiting_payment."""
        order = self._create_order(payment_method="card")
        force_status(order, "awaiting_payment")

        from apps.orders.signals import _handle_order_status_change  # noqa: PLC0415
        _handle_order_status_change(order, "draft", "awaiting_payment")

        mock_send.assert_not_called()
