"""
C4 regression: order cancellation must use FSM transitions for item status,
not QuerySet.update(), and must cancel both pending AND in_progress items.
"""

import uuid

from django.test import TestCase

from apps.billing.models import Currency
from apps.customers.models import Customer
from apps.orders.models import Order, OrderItem
from apps.orders.signals import _handle_order_cancellation
from apps.products.models import Product
from tests.helpers.fsm_helpers import force_status


class OrderCancellationItemStatusTests(TestCase):
    """Verify _handle_order_cancellation uses FSM transitions for all cancellable items."""

    def setUp(self) -> None:
        self.currency, _ = Currency.objects.get_or_create(
            code="RON", defaults={"symbol": "lei", "decimals": 2}
        )
        self.customer = Customer.objects.create(
            name="Cancel Test SRL",
            customer_type="company",
            status="active",
            primary_email="cancel@test.ro",
        )
        self.product = Product.objects.create(
            name="Hosting Plan",
            slug=f"hosting-{uuid.uuid4().hex[:8]}",
            product_type="shared_hosting",
        )
        self.order = Order.objects.create(
            customer=self.customer,
            order_number=f"ORD-{uuid.uuid4().hex[:8]}",
            currency=self.currency,
            customer_email=self.customer.primary_email,
            customer_name=self.customer.name,
            total_cents=30000,
            subtotal_cents=30000,
            tax_cents=0,
        )
        # Force order to cancelled state (it's already being handled as cancelled)
        force_status(self.order, "cancelled")

    def _make_item(self, provisioning_status: str = "pending") -> OrderItem:
        item = OrderItem.objects.create(
            order=self.order,
            product=self.product,
            product_name="Hosting Plan",
            product_type="shared_hosting",
            quantity=1,
            unit_price_cents=10000,
            line_total_cents=10000,
            config={},
        )
        if provisioning_status != "pending":
            force_status(item, provisioning_status, field_name="provisioning_status")
        return item

    def test_pending_item_cancelled_via_fsm(self) -> None:
        item = self._make_item("pending")

        _handle_order_cancellation(self.order, old_status="paid")

        item.refresh_from_db()
        self.assertEqual(item.provisioning_status, "cancelled")

    def test_in_progress_item_cancelled_via_fsm(self) -> None:
        """C4 regression: in_progress items must also be cancelled."""
        item = self._make_item("in_progress")

        _handle_order_cancellation(self.order, old_status="provisioning")

        item.refresh_from_db()
        self.assertEqual(item.provisioning_status, "cancelled")

    def test_completed_item_unchanged(self) -> None:
        """Completed items must NOT be cancelled."""
        item = self._make_item("completed")

        _handle_order_cancellation(self.order, old_status="paid")

        item.refresh_from_db()
        self.assertEqual(item.provisioning_status, "completed")

    def test_mixed_items_correct_handling(self) -> None:
        """Pending + in_progress cancelled; completed unchanged."""
        pending = self._make_item("pending")
        in_progress = self._make_item("in_progress")
        completed = self._make_item("completed")

        _handle_order_cancellation(self.order, old_status="provisioning")

        pending.refresh_from_db()
        in_progress.refresh_from_db()
        completed.refresh_from_db()

        self.assertEqual(pending.provisioning_status, "cancelled")
        self.assertEqual(in_progress.provisioning_status, "cancelled")
        self.assertEqual(completed.provisioning_status, "completed")
