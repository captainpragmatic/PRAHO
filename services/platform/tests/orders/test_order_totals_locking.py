"""Order-total recompute must read discount_cents under the Order-row lock (#329).

`Order.calculate_totals()` recomputed `total_cents = subtotal + tax - discount_cents` from the
in-memory `discount_cents`. An OrderItem create/delete recompute running on a stale Order instance
(one that missed a concurrently committed promotion discount) therefore published a `total_cents`
that disagreed with the stored `discount_cents`. The fix reads discount_cents under
`select_for_update(of=("self",))` before recomputing.
"""

from __future__ import annotations

import threading
import time
from concurrent.futures import ThreadPoolExecutor

from django.db import close_old_connections, connection, transaction
from django.test import TestCase, TransactionTestCase

from apps.billing.models import Currency
from apps.customers.models import Customer
from apps.orders.models import Order, OrderItem
from apps.products.models import Product


class _OrderTotalsFixture:
    """Shared fixture: a 100.00 RON order with one line item (tax_rate 0, so tax_cents == 0)."""

    def _build(self) -> None:
        self.currency, _ = Currency.objects.get_or_create(
            code="RON", defaults={"name": "Romanian Leu", "symbol": "lei"}
        )
        self.customer = Customer.objects.create(
            name="Totals Lock SRL",
            customer_type="company",
            status="active",
        )
        self.product = Product.objects.create(
            slug="totals-hosting",
            name="Totals Hosting",
            product_type="shared_hosting",
        )
        self.order = Order.objects.create(
            customer=self.customer,
            currency=self.currency,
            customer_email="totals@example.com",
            customer_name="Totals Lock SRL",
            subtotal_cents=10000,
            total_cents=10000,
        )
        self._add_item(self.order, unit_price_cents=10000)

    def _add_item(self, order: Order, *, unit_price_cents: int) -> OrderItem:
        # OrderItem.save() recomputes tax_cents from tax_rate (default 0), so tax is 0 here and the
        # totals assertions turn purely on subtotal and the committed discount.
        return OrderItem.objects.create(
            order=order,
            product=self.product,
            product_name=self.product.name,
            product_type=self.product.product_type,
            billing_period="monthly",
            quantity=1,
            unit_price_cents=unit_price_cents,
            setup_cents=0,
            line_total_cents=unit_price_cents,
        )


class OrderTotalsLockTestCase(_OrderTotalsFixture, TestCase):
    """Deterministic single-connection stale-discount regressions (SQLite-friendly)."""

    def setUp(self) -> None:
        self._build()

    def test_calculate_totals_uses_the_committed_discount_not_the_stale_instance(self) -> None:
        """A concurrent promotion commits discount_cents behind our stale Order; the recompute must
        use the committed value, not the instance's pre-promotion 0."""
        stale = Order.objects.get(pk=self.order.pk)  # discount_cents == 0 in memory
        Order.objects.filter(pk=self.order.pk).update(discount_cents=2000)

        stale.calculate_totals()

        # subtotal 10000 - committed discount 2000 = 8000 (tax_rate defaults to 0 in the fixture)
        self.assertEqual(stale.total_cents, 8000)
        self.assertEqual(stale.discount_cents, 2000, "the in-memory instance is refreshed to match")
        stored = Order.objects.get(pk=self.order.pk)
        self.assertEqual(stored.total_cents, 8000)
        self.assertEqual(stored.discount_cents, 2000)

    def test_item_add_recompute_uses_the_committed_discount(self) -> None:
        """Adding an item on a stale Order (signal-driven recompute) reflects the committed discount."""
        stale = Order.objects.get(pk=self.order.pk)
        Order.objects.filter(pk=self.order.pk).update(discount_cents=2000)

        # Creating the item fires handle_order_item_changes -> stale.order.calculate_totals().
        self._add_item(stale, unit_price_cents=5000)

        stored = Order.objects.get(pk=self.order.pk)
        # subtotal 15000 - discount 2000 = 13000
        self.assertEqual(stored.subtotal_cents, 15000)
        self.assertEqual(stored.total_cents, 13000)
        self.assertEqual(stored.discount_cents, 2000)

    def test_item_delete_recompute_uses_the_committed_discount(self) -> None:
        """Deleting an item on a stale Order reflects the committed discount."""
        extra = self._add_item(self.order, unit_price_cents=5000)
        Order.objects.filter(pk=self.order.pk).update(discount_cents=2000)
        stale_extra = OrderItem.objects.get(pk=extra.pk)  # its .order is a fresh-but-soon-stale load

        stale_extra.delete()  # fires handle_order_item_deletion -> calculate_totals()

        stored = Order.objects.get(pk=self.order.pk)
        # back to one item: subtotal 10000 - discount 2000 = 8000
        self.assertEqual(stored.subtotal_cents, 10000)
        self.assertEqual(stored.total_cents, 8000)
        self.assertEqual(stored.discount_cents, 2000)

    def test_committed_discount_is_clamped_to_the_subtotal(self) -> None:
        """#203 interaction: a committed discount larger than the (freshly recomputed) subtotal is
        clamped to the subtotal — total floors at 0 and the clamped discount is persisted."""
        stale = Order.objects.get(pk=self.order.pk)
        # subtotal is 10000 (one item); commit an oversized discount behind the stale instance.
        Order.objects.filter(pk=self.order.pk).update(discount_cents=15000)

        stale.calculate_totals()

        self.assertEqual(stale.subtotal_cents, 10000)
        self.assertEqual(stale.discount_cents, 10000, "discount clamped to subtotal")
        self.assertEqual(stale.total_cents, 0)
        stored = Order.objects.get(pk=self.order.pk)
        self.assertEqual(stored.discount_cents, 10000)
        self.assertEqual(stored.total_cents, 0)

    def test_missing_row_falls_back_to_in_memory_discount(self) -> None:
        """If the Order row vanished (locked read returns no row), recompute from the in-memory
        discount rather than crashing on a None discount."""
        instance = Order.objects.get(pk=self.order.pk)
        instance.discount_cents = 500  # in-memory value the fallback must use
        Order.objects.filter(pk=self.order.pk).delete()

        # Must not raise even though the locked read finds no row.
        instance.calculate_totals()

        self.assertEqual(
            instance.total_cents,
            max(0, instance.subtotal_cents + instance.tax_cents - 500),
        )


class OrderTotalsPostgresConcurrencyTests(_OrderTotalsFixture, TransactionTestCase):
    """Real two-connection interleaving — a held Order lock blocks the item recompute."""

    reset_sequences = True

    def setUp(self) -> None:
        self._build()

    def test_item_recompute_blocks_until_order_lock_is_released(self) -> None:
        if connection.vendor != "postgresql":
            self.skipTest("PostgreSQL row-lock behavior required")

        lock_held = threading.Event()
        release_lock = threading.Event()

        def hold_order_lock() -> None:
            close_old_connections()
            try:
                with transaction.atomic():
                    locked = Order.objects.select_for_update().get(pk=self.order.pk)
                    # Commit a discount into this locked row, then hold the lock.
                    Order.objects.filter(pk=locked.pk).update(discount_cents=2000)
                    lock_held.set()
                    release_lock.wait(timeout=10)
            finally:
                connection.close()

        def add_item() -> None:
            close_old_connections()
            try:
                lock_held.wait(timeout=10)
                self._add_item(Order.objects.get(pk=self.order.pk), unit_price_cents=5000)
            finally:
                connection.close()

        with ThreadPoolExecutor(max_workers=2) as executor:
            holder = executor.submit(hold_order_lock)
            adder = executor.submit(add_item)
            self.assertTrue(lock_held.wait(timeout=10))
            time.sleep(0.5)
            self.assertFalse(adder.done(), "item recompute completed while the Order row lock was held")
            release_lock.set()
            adder.result(timeout=10)
            holder.result(timeout=10)

        self.order.refresh_from_db()
        # The recompute ran after the lock released, so it saw the committed discount.
        self.assertEqual(self.order.discount_cents, 2000)
        self.assertEqual(self.order.total_cents, max(0, self.order.subtotal_cents + self.order.tax_cents - 2000))
