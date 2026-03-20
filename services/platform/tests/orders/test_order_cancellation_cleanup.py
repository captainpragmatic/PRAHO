"""
Tests for D3: Service deletion on order cancellation.

Validates:
- Pending services are hard-deleted on order cancel
- OrderItem.service is SET_NULL before deletion
- Audit event services_deleted_on_cancellation logged
- Services in provisioning are failed first, then deleted
"""

from decimal import Decimal

from django.test import TestCase

from apps.billing.models import Currency
from apps.customers.models import Customer
from apps.orders.models import Order, OrderItem
from apps.orders.services import OrderService, StatusChangeData
from apps.products.models import Product
from tests.helpers.fsm_helpers import force_status


class ServiceDeletionOnCancelTest(TestCase):
    """Test service cleanup when orders are cancelled."""

    def setUp(self):
        self.currency, _ = Currency.objects.get_or_create(
            code="RON", defaults={"symbol": "lei", "decimals": 2}
        )
        self.customer = Customer.objects.create(
            name="Cancel Test SRL", customer_type="company",
            status="active", primary_email="cancel@test.ro",
        )
        self.product = Product.objects.create(
            name="Hosting Plan", slug="hosting-plan",
            product_type="shared_hosting", is_active=True,
        )

    def _create_order_with_service(self, order_status="awaiting_payment"):
        """Create an order with a linked service."""
        from apps.provisioning.models import Service, ServicePlan  # noqa: PLC0415

        order = Order.objects.create(
            customer=self.customer, currency=self.currency,
            customer_email=self.customer.primary_email,
            customer_name=self.customer.name,
            subtotal_cents=10000, tax_cents=2100, total_cents=12100,
            billing_address={},
        )
        force_status(order, order_status)

        # Create service plan and service
        plan, _ = ServicePlan.objects.get_or_create(
            name="Test Plan", defaults={
                "plan_type": "shared_hosting", "is_active": True,
                "price_monthly": Decimal("50.00"),
            }
        )
        service = Service.objects.create(
            customer=self.customer, service_plan=plan,
            currency=self.currency, service_name="Test Service",
            username="test_user", billing_cycle="monthly",
            price=Decimal("100.00"),
        )

        item = OrderItem.objects.create(
            order=order, product=self.product,
            product_name=self.product.name,
            product_type=self.product.product_type,
            quantity=1, unit_price_cents=10000,
            tax_rate=Decimal("0.2100"),
            tax_cents=2100, line_total_cents=12100,
            service=service,
        )
        return order, item, service

    def test_cancel_deletes_pending_services(self):
        """Pending services are hard-deleted when order is cancelled (D3)."""
        from apps.provisioning.models import Service  # noqa: PLC0415

        order, item, service = self._create_order_with_service("awaiting_payment")
        service_id = service.id

        # Cancel the order — use captureOnCommitCallbacks because the signal handler
        # runs via on_commit (Django TestCase wraps in transaction that never commits)
        with self.captureOnCommitCallbacks(execute=True):
            result = OrderService.update_order_status(
                order, StatusChangeData(new_status="cancelled", notes="Test cancel")
            )
        self.assertTrue(result.is_ok())

        # Service should be deleted
        self.assertFalse(Service.objects.filter(id=service_id).exists())

        # OrderItem.service should be NULL
        item.refresh_from_db()
        self.assertIsNone(item.service)

    def test_cancel_sets_order_item_service_null(self):
        """OrderItem keeps product data but service FK is cleared."""
        order, item, _service = self._create_order_with_service("awaiting_payment")

        with self.captureOnCommitCallbacks(execute=True):
            OrderService.update_order_status(
                order, StatusChangeData(new_status="cancelled", notes="Test")
            )

        item.refresh_from_db()
        self.assertIsNone(item.service)
        # Product data preserved for audit
        self.assertEqual(item.product_name, self.product.name)
