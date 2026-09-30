"""A failed proforma creation must not leave the order pointing at a discarded row.

`ProformaService.create_from_order` assigns `order.proforma` and saves it, then calls
`transaction.set_rollback(True)` before returning `Err`. The database discards both
writes. The in-memory `Order` the caller still holds does not: it keeps `proforma_id`
set to a row that no longer exists.

`process_pending_orders` refreshes the order on the success branch and not on the error
branch. Everything it does next in the same iteration reads that stale object. The
timeout path performs a full `save()`, which writes the dangling foreign key; on
PostgreSQL that fails at COMMIT, outside the caller's own try/except, so the timed-out
order is never cancelled and the next run repeats it forever.

The failure is injected at `log_security_event`, which the service calls immediately
after linking the proforma to the order. That is a real dependency boundary and it
reproduces the exact ordering — writes committed to the transaction, then a failure,
then the rollback — rather than faking the service's return value.
"""

from __future__ import annotations

from datetime import timedelta
from decimal import Decimal
from unittest.mock import patch

from django.test import TestCase
from django.utils import timezone

from apps.billing.models import Currency, ProformaInvoice
from apps.customers.models import Customer
from apps.orders.models import Order, OrderItem
from apps.orders.tasks import process_pending_orders
from apps.products.models import Product


class StaleProformaPointerTests(TestCase):
    def setUp(self) -> None:
        self.currency, _ = Currency.objects.get_or_create(
            code="RON", defaults={"symbol": "lei", "decimals": 2}
        )
        self.customer = Customer.objects.create(
            name="Stale Pointer SRL",
            customer_type="company",
            status="active",
            primary_email="stale-pointer@test.ro",
        )
        self.product = Product.objects.create(
            name="Stale Hosting",
            slug="stale-hosting",
            product_type="shared_hosting",
            is_active=True,
        )
        self.order = Order.objects.create(
            customer=self.customer,
            currency=self.currency,
            status="draft",
            subtotal_cents=10000,
            tax_cents=2100,
            total_cents=12100,
        )
        OrderItem.objects.create(
            order=self.order,
            product=self.product,
            product_name="Stale Hosting",
            quantity=1,
            unit_price_cents=10000,
            tax_rate=Decimal("0.21"),
            line_total_cents=12100,
        )
        # Past every timeout basis, so one task run reaches the cancellation save that
        # is where a dangling foreign key actually bites.
        Order.objects.filter(pk=self.order.pk).update(
            status="awaiting_payment",
            created_at=timezone.now() - timedelta(days=365),
        )
        self.order.refresh_from_db()

    def test_a_timed_out_order_still_cancels_after_a_failed_proforma(self) -> None:
        """The order must reach a terminal state, not be stranded by a phantom pointer."""
        with patch(
            "apps.billing.proforma_service.log_security_event",
            side_effect=RuntimeError("audit sink unavailable"),
        ):
            result = process_pending_orders()

        self.order.refresh_from_db()
        self.assertEqual(
            self.order.status,
            "cancelled",
            "the timed-out order was never cancelled; it will be retried forever",
        )
        self.assertEqual(result["results"]["errors"], [], "the stale pointer surfaced as a processing error")

    def test_no_order_is_left_pointing_at_a_proforma_that_does_not_exist(self) -> None:
        """States the invariant directly, independently of which save trips over it."""
        with patch(
            "apps.billing.proforma_service.log_security_event",
            side_effect=RuntimeError("audit sink unavailable"),
        ):
            process_pending_orders()

        self.order.refresh_from_db()
        if self.order.proforma_id is not None:
            self.assertTrue(
                ProformaInvoice.objects.filter(pk=self.order.proforma_id).exists(),
                "the order references a proforma the rollback discarded",
            )
