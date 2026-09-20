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

from unittest.mock import MagicMock, patch

from django.db import DatabaseError, NotSupportedError
from django.test import TestCase

from apps.billing.currency_models import Currency
from apps.customers.models import Customer
from apps.orders.models import Order


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


class CalculateTotalsErrorHandlingTests(TestCase):
    """``Order.calculate_totals`` — the same defect guarding money totals."""

    def setUp(self) -> None:
        self.currency, _ = Currency.objects.get_or_create(
            code="RON", defaults={"name": "Romanian Leu", "symbol": "lei", "decimals": 2}
        )
        self.customer = Customer.objects.create(
            name="Lock Probe SRL", customer_type="company", status="active", primary_email="lock@test.ro"
        )
        self.order = Order.objects.create(
            customer=self.customer,
            currency=self.currency,
            status="draft",
            subtotal_cents=10000,
            tax_cents=1900,
            total_cents=11900,
        )

    def test_genuine_database_error_propagates(self) -> None:
        with (
            patch.object(Order.objects, "select_for_update", side_effect=DatabaseError("lock timeout")),
            self.assertRaises(DatabaseError),
        ):
            self.order.calculate_totals()

    def test_unsupported_backend_still_degrades(self) -> None:
        with patch.object(Order.objects, "select_for_update", side_effect=NotSupportedError("sqlite")):
            self.order.calculate_totals()  # must not raise
