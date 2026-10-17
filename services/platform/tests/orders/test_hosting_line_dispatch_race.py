"""Concurrent fulfilment of one line, and a cancellation racing it, under PostgreSQL row locks."""

from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor
from decimal import Decimal
from typing import Any
from unittest.mock import patch

from django.db import close_old_connections, connection, transaction
from django.test import TransactionTestCase

from apps.audit.models import AuditEvent
from apps.billing.models import Currency
from apps.customers.models import Customer
from apps.orders.hosting_fulfilment import fulfil_hosting_line
from apps.orders.models import Order, OrderItem
from apps.products.models import Product
from apps.provisioning.models import Service, ServicePlan
from apps.provisioning.provisioning_service import ProvisioningService
from tests.helpers.fsm_helpers import force_status

ORIGINAL_ACTIVATE = ProvisioningService.activate_service


class HostingLineRaceTests(TransactionTestCase):
    def setUp(self) -> None:
        if connection.vendor != "postgresql":
            self.skipTest("row-lock ordering between two fulfilments requires PostgreSQL")
        currency, _ = Currency.objects.get_or_create(code="RON", defaults={"symbol": "lei", "decimals": 2})
        customer = Customer.objects.create(name="Race Buyer", primary_email="race@example.test", status="active")
        plan = ServicePlan.objects.create(name="Race plan", plan_type="shared_hosting", price_monthly=Decimal("9"))
        product = Product.objects.create(
            slug="race", name="Race", product_type="shared_hosting", default_service_plan=plan
        )
        self.order = Order.objects.create(
            customer=customer,
            currency=currency,
            customer_email=customer.primary_email,
            customer_name=customer.name,
            billing_address={},
            total_cents=900,
            subtotal_cents=900,
        )
        force_status(self.order, "provisioning")
        self.service = Service.objects.create(
            customer=customer,
            service_plan=plan,
            currency=currency,
            service_name="race-shop.ro",
            domain="race-shop.ro",
            username="race",
            billing_cycle="monthly",
            price=Decimal("9"),
            status="provisioning",
        )
        self.line = OrderItem.objects.create(
            order=self.order,
            product=product,
            product_name="Race",
            product_type="shared_hosting",
            quantity=1,
            unit_price_cents=900,
            line_total_cents=900,
            service=self.service,
            config={"billing_period": "monthly"},
        )

    def _concurrently(self, *calls: Any) -> list[Any]:
        def run(call: Any) -> Any:
            close_old_connections()
            try:
                return call()
            finally:
                connection.close()

        with ThreadPoolExecutor(max_workers=len(calls)) as pool:
            return list(pool.map(run, calls))

    def _hold_first_activation(self) -> threading.Event:
        """The first activation waits inside its transaction until released, holding its locks."""
        release = threading.Event()
        first = threading.Lock()

        def activate(service: Service, reason: str = "") -> Any:
            if first.acquire(blocking=False):
                release.wait(timeout=3)
            return ORIGINAL_ACTIVATE(service, reason)

        self.enterContext(patch.object(ProvisioningService, "activate_service", side_effect=activate))
        threading.Timer(1.5, release.set).start()
        return release

    def test_two_dispatches_for_one_line_activate_once(self) -> None:
        self._hold_first_activation()
        results = self._concurrently(
            lambda: fulfil_hosting_line(self.line.pk), lambda: fulfil_hosting_line(self.line.pk)
        )
        self.assertTrue(all(result.is_ok() for result in results), results)
        self.service.refresh_from_db()
        self.assertEqual(self.service.status, "active")
        self.assertEqual(
            AuditEvent.objects.filter(action="service_activated", object_id=str(self.service.pk)).count(), 1
        )

    def test_cancel_racing_dispatch_never_activates_a_cancelled_order(self) -> None:
        """A cancellation holding the order's lock commits first: the waiting fulfilment must see it."""
        outcome: list[Any] = []
        with transaction.atomic():
            Order.objects.select_for_update(of=("self",)).get(pk=self.order.pk)
            Order.objects.filter(pk=self.order.pk).update(status="cancelled")
            worker = threading.Thread(
                target=lambda: outcome.extend(self._concurrently(lambda: fulfil_hosting_line(self.line.pk)))
            )
            worker.start()
            worker.join(timeout=1)
            self.assertTrue(worker.is_alive(), "fulfilment did not wait for the order's lock")
        worker.join(timeout=10)
        self.assertEqual(outcome[0].unwrap(), "noop")
        self.service.refresh_from_db()
        self.line.refresh_from_db()
        self.assertEqual((self.service.status, self.line.provisioning_status), ("provisioning", "pending"))
