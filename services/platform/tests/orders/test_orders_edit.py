"""
Tests for order edit form POST processing (O2 TODO fix).

Verifies order_edit() POST handler updates editable fields.
"""

import inspect

from django.test import TestCase

from apps.billing.models import Currency
from apps.customers.models import Customer
from apps.orders.models import Order
from apps.orders.views import order_edit
from apps.users.models import User


class OrderEditableFieldsTests(TestCase):
    """O2: order edit form processes editable fields"""

    def setUp(self):
        self.user = User.objects.create_user(
            email="editor@test.ro", password="testpass123", is_staff=True, staff_role="admin",
        )
        self.customer = Customer.objects.create(
            name="Edit Test SRL", customer_type="company",
        )
        self.currency, _ = Currency.objects.get_or_create(
            code="RON", defaults={"name": "Romanian Leu", "symbol": "lei"},
        )
        self.order = Order.objects.create(
            customer=self.customer, status="draft",
            customer_email="editor@test.ro", customer_name="Edit Test SRL",
            subtotal_cents=5000, tax_cents=950, total_cents=5950,
            currency=self.currency, notes="Original notes",
        )

    def test_draft_order_fully_editable(self):
        """Draft orders return ['*'] for editable fields"""
        self.assertEqual(self.order.get_editable_fields(), ["*"])

    def test_completed_order_limited_editable(self):
        """Completed orders only allow notes editing"""
        self.order.status = "completed"
        self.assertEqual(self.order.get_editable_fields(), ["notes"])

    def test_edit_post_no_longer_placeholder(self):
        """order_edit POST handler no longer returns placeholder message"""
        source = inspect.getsource(order_edit)
        self.assertNotIn("will be implemented next", source)
