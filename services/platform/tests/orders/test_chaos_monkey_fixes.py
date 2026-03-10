"""
Order save() retry and idempotency constraint regression tests.

Verifies:
  - Order.save() retry wraps each attempt in a savepoint (PostgreSQL compat)
  - Non-order_number IntegrityErrors (e.g. idempotency_key) propagate correctly
  - Order number collision retry succeeds with a regenerated number
  - OrderNumberingService generates sequential numbers
"""

from __future__ import annotations

from unittest.mock import patch

from django.db import IntegrityError
from django.test import TestCase

from apps.billing.models import Currency
from apps.customers.models import Customer
from apps.orders.models import Order
from apps.orders.services import OrderNumberingService
from apps.users.models import User

# ===============================================================================
# HELPERS
# ===============================================================================

def _make_user(email: str = "retry@pragmatichost.com") -> User:
    return User.objects.create_user(email=email, password="testpass123", is_staff=True, staff_role="admin")


def _make_currency() -> Currency:
    c, _ = Currency.objects.get_or_create(code="RON", defaults={"name": "Romanian Leu", "symbol": "lei", "decimals": 2})
    return c


def _make_customer(user: User) -> Customer:
    return Customer.objects.create(
        customer_type="company",
        company_name="Test Corp",
        primary_email=f"test-{user.email}",
        primary_phone="+40700000000",
        data_processing_consent=True,
        created_by=user,
    )


def _make_order(customer: Customer, currency: Currency, **kwargs: object) -> Order:
    return Order.objects.create(
        customer=customer,
        currency=currency,
        customer_email=customer.primary_email,
        customer_name=customer.company_name,
        **kwargs,
    )


# ===============================================================================
# Idempotency key constraint must propagate, not be retried
# ===============================================================================


class OrderIdempotencyConstraintTest(TestCase):
    """Non-order_number IntegrityErrors must propagate without retry."""

    def setUp(self) -> None:
        self.user = _make_user()
        self.currency = _make_currency()
        self.customer = _make_customer(self.user)

    def test_duplicate_idempotency_key_raises(self) -> None:
        """Duplicate idempotency_key for the same customer raises IntegrityError."""
        _make_order(self.customer, self.currency, idempotency_key="test-key-unique-123")

        with self.assertRaises(IntegrityError):
            _make_order(self.customer, self.currency, idempotency_key="test-key-unique-123")

    def test_empty_idempotency_keys_do_not_conflict(self) -> None:
        """Multiple orders with empty idempotency_key (default) must coexist."""
        o1 = _make_order(self.customer, self.currency)
        o2 = _make_order(self.customer, self.currency)
        self.assertNotEqual(o1.order_number, o2.order_number)

    def test_collision_markers_cover_both_db_engines(self) -> None:
        """Collision markers must match both PostgreSQL and SQLite error formats."""
        markers = Order._ORDER_NUMBER_COLLISION_MARKERS
        # PostgreSQL format: constraint name
        self.assertTrue(any("orders_order_number" in m for m in markers))
        # SQLite format: table.column
        self.assertTrue(any("orders.order_number" in m for m in markers))


# ===============================================================================
# Savepoint wrapping allows retry to succeed on order_number collision
# ===============================================================================


class OrderSaveRetrySavepointTest(TestCase):
    """Order.save() retries with savepoint wrapping on order_number collision."""

    def setUp(self) -> None:
        self.user = _make_user("savepoint@test.ro")
        self.currency = _make_currency()
        self.customer = _make_customer(self.user)

    def test_retry_regenerates_on_collision(self) -> None:
        """When order_number collides, save() retries with a new number."""
        first = _make_order(self.customer, self.currency)
        first_number = first.order_number

        second = Order(
            customer=self.customer,
            currency=self.currency,
            customer_email="test@test.ro",
            customer_name="Test",
        )

        call_count = 0
        original_generate = Order.generate_order_number.__wrapped__ if hasattr(Order.generate_order_number, "__wrapped__") else Order.generate_order_number

        def generate_collision_then_unique(self_inner: Order) -> None:
            nonlocal call_count
            call_count += 1
            if call_count <= 1:
                # First call (from initial save): generate the colliding number
                self_inner.order_number = first_number
            else:
                # Retry call: clear and let real generator produce a unique number
                self_inner.order_number = ""
                original_generate(self_inner)

        with patch.object(Order, "generate_order_number", generate_collision_then_unique):
            second.save()

        self.assertNotEqual(second.order_number, first_number)
        self.assertEqual(call_count, 2)


# ===============================================================================
# OrderNumberingService generates sequential numbers
# ===============================================================================


class OrderNumberingServiceTest(TestCase):
    """OrderNumberingService generates sequential, properly formatted order numbers."""

    def test_sequential_for_same_customer(self) -> None:
        """Generated order numbers increment sequentially."""
        user = _make_user("numbering@test.ro")
        currency = _make_currency()
        customer = _make_customer(user)

        num1 = OrderNumberingService.generate_order_number(customer)
        _make_order(customer, currency, order_number=num1)

        num2 = OrderNumberingService.generate_order_number(customer)
        _make_order(customer, currency, order_number=num2)

        seq1 = int(num1.split("-")[-1])
        seq2 = int(num2.split("-")[-1])
        self.assertEqual(seq2, seq1 + 1)
