"""
Tests for the nightly auto-renewal task (process_recurring_orders).

Covers #223: the task raised FieldError on every run and created nothing, so no service ever
auto-renewed and no recurring revenue was billed.
"""

from __future__ import annotations

from datetime import timedelta
from decimal import Decimal

from django.test import TestCase
from django.utils import timezone

from apps.billing.models import Currency
from apps.customers.models import Customer
from apps.orders.models import Order, OrderItem
from apps.orders.tasks import (
    _create_renewal_order_data,
    _find_services_to_renew,
    _resolve_renewal_product_id,
    process_recurring_orders,
)
from apps.products.models import Product
from apps.provisioning.models import Server, Service, ServicePlan


class RecurringOrdersTaskTestCase(TestCase):
    """#223: the nightly renewal task must actually find services and create renewal orders."""

    def setUp(self):
        self.currency, _ = Currency.objects.get_or_create(
            code="RON", defaults={"name": "Romanian Leu", "symbol": "lei", "is_active": True}
        )
        self.customer = Customer.objects.create(
            name="Ion Popescu",
            customer_type="individual",
            company_name="",
            primary_email="ion@example.ro",
            status="active",
        )
        self.plan = ServicePlan.objects.create(
            name="Basic Hosting",
            plan_type="shared_hosting",
            price_monthly=Decimal("29.99"),
            price_quarterly=Decimal("79.99"),
            price_annual=Decimal("299.99"),
        )
        self.server = Server.objects.create(
            name="Test Server",
            hostname="srv1.test.ro",
            primary_ip="10.0.0.1",
            server_type="shared",
            status="active",
            location="Bucharest",
            datacenter="M247",
            cpu_model="Xeon E5",
            cpu_cores=8,
            ram_gb=32,
            disk_type="ssd",
            disk_capacity_gb=500,
            os_type="linux",
        )

        self.product = Product.objects.create(
            slug="basic-hosting",
            name="Basic Hosting",
            product_type="shared_hosting",
            is_active=True,
            is_public=True,
        )

    def _service(self, **overrides):
        """Build a service as the real flow would: provisioned by an order item.

        Accepts expires_in_days / auto_renew / status / price / cycle / with_order_item.
        `with_order_item=False` models a service created outside an order (manual or migrated),
        which has no originating catalog product.
        """
        n = Service.objects.count() + 1
        service = Service.objects.create(
            customer=self.customer,
            service_plan=self.plan,
            server=self.server,
            currency=self.currency,
            service_name=f"svc{n}.example.com",
            username=f"user{n}",
            status=overrides.get("status", "active"),
            domain="test.example.com",
            price=Decimal(overrides.get("price", "29.99")),
            billing_cycle=overrides.get("cycle", "monthly"),
            auto_renew=overrides.get("auto_renew", True),
            expires_at=timezone.now() + timedelta(days=overrides.get("expires_in_days", 10)),
        )
        if overrides.get("with_order_item", True):
            original_order = Order.objects.create(
                order_number=f"ORD-ORIG-{Order.objects.count() + 1}",
                customer=self.customer,
                currency=self.currency,
                status="completed",
                subtotal_cents=2999,
                tax_cents=570,
                total_cents=3569,
            )
            OrderItem.objects.create(
                order=original_order,
                product=self.product,
                service=service,
                quantity=1,
                unit_price_cents=2999,
                tax_rate=Decimal("0.19"),
                line_total_cents=2999,
                product_name="Basic Hosting",
                product_type="shared_hosting",
            )
        return service

    def test_find_services_to_renew_returns_due_service(self):
        """#223: the query used select_related('plan')/prefetch_related('orders') — neither field
        exists on Service (they are service_plan / order_items), so evaluating it raised
        FieldError and the task died before doing anything."""
        service = self._service(expires_in_days=10)

        self.assertEqual(list(_find_services_to_renew()), [service])

    def test_find_services_to_renew_excludes_non_due_services(self):
        """Only active, auto_renew services inside the 30-day window are picked up."""
        self._service(expires_in_days=10, auto_renew=False)
        self._service(expires_in_days=90)
        self._service(expires_in_days=10, status="suspended")

        self.assertEqual(list(_find_services_to_renew()), [])

    def test_renewal_order_data_uses_real_service_fields(self):
        """#223: the builder read service.plan / service.name, which do not exist."""
        service = self._service(price="29.99", cycle="monthly")

        data = _create_renewal_order_data(service, self.product.id)

        self.assertEqual(data.customer, self.customer)
        self.assertEqual(len(data.items), 1)
        item = data.items[0]
        self.assertEqual(item["unit_price_cents"], 2999)
        self.assertIn(service.service_name, item["description"])
        self.assertEqual(item["meta"]["renewal_service_id"], str(service.id))

    def test_renewal_order_data_honours_the_service_billing_cycle(self):
        """#223: renewal_period was hardcoded to '1_year' regardless of the actual cycle, so a
        monthly service would have been renewed as an annual one."""
        service = self._service(price="299.99", cycle="annual")

        data = _create_renewal_order_data(service, self.product.id)

        self.assertEqual(data.items[0]["meta"]["renewal_period"], "annual")
        self.assertEqual(data.items[0]["unit_price_cents"], 29999)

    def test_renewal_product_resolves_from_the_originating_order_item(self):
        """ServicePlan has no link to Product, so the renewal product comes from the order item
        that provisioned the service."""
        service = self._service()

        self.assertEqual(_resolve_renewal_product_id(service), self.product.id)

    def test_renewal_product_is_none_without_an_originating_order_item(self):
        """A service created outside an order has no catalog product to renew against."""
        service = self._service(with_order_item=False)

        self.assertIsNone(_resolve_renewal_product_id(service))

    def test_service_without_originating_order_item_is_reported_not_silently_skipped(self):
        """A service that cannot be renewed must surface as an error, not vanish — an invisible
        non-renewing service is exactly the failure mode #223 is about."""
        self._service(with_order_item=False)

        result = process_recurring_orders()

        self.assertEqual(result["results"]["renewal_orders_created"], 0)
        self.assertEqual(result["results"]["renewal_failures"], 1)
        self.assertIn("cannot resolve renewal product", result["results"]["errors"][0])

    def test_process_recurring_orders_creates_a_renewal_order(self):
        """#223 end-to-end: a due auto_renew service must produce a renewal order.

        This is the whole point of the issue — before the fix the task raised FieldError on
        every run and created nothing, so recurring revenue was never billed.
        """
        service = self._service(expires_in_days=10)

        result = process_recurring_orders()

        self.assertEqual(result["results"]["errors"], [])
        self.assertEqual(result["results"]["renewal_orders_created"], 1)

        # create_order maps an item's `meta` onto OrderItem.config.
        renewal_item = OrderItem.objects.get(config__renewal_service_id=str(service.id))
        self.assertEqual(renewal_item.unit_price_cents, 2999)
        self.assertEqual(renewal_item.product_id, self.product.id)
        self.assertEqual(renewal_item.order.meta["auto_renewal"], True)

    def test_process_recurring_orders_is_idempotent(self):
        """A second run must not double-bill a service that already has a renewal order.

        The guard keys off the renewal marker in OrderItem.config. It previously used JSONField
        `contains`, a PostgreSQL-only lookup that this SQLite suite could not exercise at all.
        """
        service = self._service(expires_in_days=10)

        process_recurring_orders()
        from django.core.cache import cache  # noqa: PLC0415

        cache.delete("process_recurring_orders_lock")
        second = process_recurring_orders()

        self.assertEqual(second["results"]["renewal_orders_created"], 0)
        self.assertEqual(OrderItem.objects.filter(config__renewal_service_id=str(service.id)).count(), 1)
