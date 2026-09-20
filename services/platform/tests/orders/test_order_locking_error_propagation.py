"""#104 [W3]: row-lock fallbacks must not swallow genuine database distress.

Both locking helpers on ``Order`` caught ``(NotSupportedError, DatabaseError)``. Because
``NotSupportedError`` *subclasses* ``DatabaseError``, that tuple is equivalent to a bare
``except DatabaseError`` — so a deadlock, lock timeout, or broken connection silently
degraded to an unlocked read instead of surfacing. On SQLite the fallback is legitimate
(no ``SELECT FOR UPDATE`` support); on PostgreSQL it converted distress into a TOCTOU
window on an order number and on money totals.

The enclosing ``transaction.atomic()`` in each helper already rules out the ordinary
autocommit ``TransactionManagementError`` its docstring cites, so ``NotSupportedError`` is
the only arm that should degrade.
"""

from __future__ import annotations

from decimal import Decimal
from unittest.mock import MagicMock, patch

from django.db import DatabaseError, NotSupportedError
from django.test import TestCase

from apps.billing.currency_models import Currency
from apps.customers.models import Customer
from apps.orders.models import Order, OrderItem
from apps.products.models import Product


class LockedLatestOrderNumberErrorHandlingTests(TestCase):
    """``Order._locked_latest_order_number`` — degrade on SQLite, surface on real failures."""

    @staticmethod
    def _queryset(*, side_effect: Exception | None) -> MagicMock:
        qs = MagicMock()
        if side_effect is not None:
            qs.select_for_update.side_effect = side_effect
        qs.values_list.return_value.first.return_value = "ORD-20260101-000007"
        return qs

    def test_unsupported_backend_falls_back_to_an_unlocked_read(self) -> None:
        qs = self._queryset(side_effect=NotSupportedError("sqlite has no SELECT FOR UPDATE"))
        self.assertEqual(Order._locked_latest_order_number(qs), "ORD-20260101-000007")

    def test_genuine_database_error_propagates_instead_of_degrading(self) -> None:
        qs = self._queryset(side_effect=DatabaseError("deadlock detected"))
        with self.assertRaises(DatabaseError):
            Order._locked_latest_order_number(qs)
        # The whole point: it must not have silently retried without the lock.
        qs.values_list.return_value.first.assert_not_called()


class CalculateTotalsDatabaseErrorTests(TestCase):
    """``Order.calculate_totals`` keeps the BROAD catch, and the reason is its caller.

    Narrowing here would surface nothing. This method's item-path caller is the OrderItem
    post_save/post_delete signal, which wraps everything in a blanket ``except Exception``
    (``orders/signals.py:534``, ``:589``). A propagating ``DatabaseError`` would be logged
    and dropped while the OrderItem INSERT still committed — leaving an order whose total
    omits the item entirely. That is money wrong in the direction the narrowing was meant to
    protect, so this site degrades to a consistent recompute instead.

    The test drives the real path (``OrderItem.objects.create`` → signal → calculate_totals),
    because a direct call bypasses the swallowing layer that makes the difference.
    """

    def setUp(self) -> None:
        self.currency, _ = Currency.objects.get_or_create(
            code="RON", defaults={"name": "Romanian Leu", "symbol": "lei", "decimals": 2}
        )
        self.customer = Customer.objects.create(
            name="Totals Probe SRL", customer_type="company", status="active", primary_email="totals@test.ro"
        )
        self.product = Product.objects.create(
            slug="totals-probe", name="Totals Probe", product_type="shared_hosting", is_active=True
        )
        self.order = Order.objects.create(
            customer=self.customer, currency=self.currency, status="draft", total_cents=0
        )

    def _add_item(self, unit_price_cents: int) -> None:
        OrderItem.objects.create(
            order=self.order,
            product=self.product,
            product_name=self.product.name,
            product_type=self.product.product_type,
            quantity=1,
            unit_price_cents=unit_price_cents,
            tax_rate=Decimal("0.0000"),
            tax_cents=0,
            line_total_cents=unit_price_cents,
        )

    def test_totals_still_include_the_item_when_the_row_lock_fails(self) -> None:
        """A DatabaseError must not leave a committed item missing from the order total."""
        self._add_item(10000)
        self.order.refresh_from_db()
        self.assertEqual(self.order.total_cents, 10000)

        with patch.object(Order.objects, "select_for_update", side_effect=DatabaseError("deadlock detected")):
            self._add_item(2500)

        self.order.refresh_from_db()
        self.assertEqual(
            self.order.total_cents,
            12500,
            msg="The second item committed but its value never reached the order total.",
        )

    def test_unsupported_backend_still_degrades(self) -> None:
        with patch.object(Order.objects, "select_for_update", side_effect=NotSupportedError("sqlite")):
            self.order.calculate_totals()  # must not raise
