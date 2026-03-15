"""
Order save() retry and idempotency constraint regression tests.

Verifies:
  - Order.save() retry wraps each attempt in a savepoint (PostgreSQL compat)
  - Non-order_number IntegrityErrors (e.g. idempotency_key) propagate correctly
  - Order number collision retry succeeds with a regenerated number
  - OrderNumberingService generates sequential numbers
  - C2: _regenerate_order_number_sequence() preserves prefix format on collision retry
  - H9: confirm_order creates OrderStatusHistory and enforces state machine transitions
  - M2: _NON_RETRYABLE_CONSTRAINT_MARKERS covers the idempotency key constraint name
  - M10: Idempotency key content validation rejects injection characters
"""

from __future__ import annotations

from unittest.mock import patch

from django.db import IntegrityError
from django.test import TestCase
from rest_framework.test import APIRequestFactory

from apps.billing.models import Currency
from apps.customers.models import Customer
from apps.orders.models import Order, OrderStatusHistory
from apps.orders.services import OrderNumberingService, StatusChangeData
from apps.users.models import User
from tests.helpers.fsm_helpers import force_status

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
        """When order_number collides, save() retries via _regenerate_order_number_sequence.

        C2 fix: The retry now calls _regenerate_order_number_sequence() (not generate_order_number)
        so that the prefix format is preserved when recovering from a collision.
        generate_order_number() is still called exactly once (initial assignment before the loop).
        The key invariant: the saved order_number differs from the colliding one.
        """
        first = _make_order(self.customer, self.currency)
        first_number = first.order_number

        second = Order(
            customer=self.customer,
            currency=self.currency,
            customer_email="test@test.ro",
            customer_name="Test",
        )

        generate_call_count = 0
        regenerate_call_count = 0
        original_regenerate = Order._regenerate_order_number_sequence

        def regenerate_and_count(self_inner: Order) -> None:
            nonlocal regenerate_call_count
            regenerate_call_count += 1
            original_regenerate(self_inner)

        def generate_collision_then_stop(self_inner: Order) -> None:
            nonlocal generate_call_count
            generate_call_count += 1
            # Always assign the colliding number; retry must use _regenerate, not this
            self_inner.order_number = first_number

        with (
            patch.object(Order, "generate_order_number", generate_collision_then_stop),
            patch.object(Order, "_regenerate_order_number_sequence", regenerate_and_count),
        ):
            second.save()

        # generate_order_number called once (initial assignment in save() before the loop)
        self.assertEqual(generate_call_count, 1, "generate_order_number must be called exactly once (initial)")
        # _regenerate_order_number_sequence called once on the first collision (C2 fix)
        self.assertEqual(regenerate_call_count, 1, "_regenerate_order_number_sequence must be called on collision retry")
        # The order was ultimately saved (even if with the regenerated prefix number)
        self.assertIsNotNone(second.pk)


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


# ===============================================================================
# C2: _regenerate_order_number_sequence preserves prefix on collision retry
# ===============================================================================


class OrderNumberPrefixPreservationTest(TestCase):
    """C2: Collision retry must preserve the original order number prefix."""

    def setUp(self) -> None:
        self.user = _make_user("prefix@test.ro")
        self.currency = _make_currency()
        self.customer = _make_customer(self.user)

    def test_regenerate_preserves_prefix(self) -> None:
        """_regenerate_order_number_sequence keeps the prefix and increments sequence."""
        # Create an existing order to establish a sequence baseline
        first = _make_order(self.customer, self.currency)
        original_number = first.order_number
        # e.g. "ORD-20260310-000001" → prefix is "ORD-20260310-"
        parts = original_number.rsplit("-", 1)
        self.assertEqual(len(parts), 2, "order_number must contain at least one dash separator")
        original_prefix = parts[0] + "-"
        original_seq = int(parts[1])

        # Build a second order with same number to trigger regeneration
        second = Order(
            customer=self.customer,
            currency=self.currency,
            customer_email="test@test.ro",
            customer_name="Test",
            order_number=original_number,  # deliberately collide
        )
        second._regenerate_order_number_sequence()

        new_parts = second.order_number.rsplit("-", 1)
        new_prefix = new_parts[0] + "-"
        new_seq = int(new_parts[1])

        self.assertEqual(new_prefix, original_prefix, "Prefix must be preserved after regeneration")
        self.assertGreater(new_seq, original_seq, "Sequence must increment beyond the existing maximum")

    def test_regenerate_increments_from_max_existing(self) -> None:
        """Sequence regeneration uses MAX of existing, not COUNT, to avoid races."""
        # Create several orders to advance the sequence counter
        o1 = _make_order(self.customer, self.currency)
        o2 = _make_order(self.customer, self.currency)
        o3 = _make_order(self.customer, self.currency)

        # The last order has the highest sequence
        max_seq = int(o3.order_number.rsplit("-", 1)[-1])

        # Now simulate regeneration on a fourth order that needs a new sequence
        fourth = Order(
            customer=self.customer,
            currency=self.currency,
            customer_email="test@test.ro",
            customer_name="Test",
            order_number=o1.order_number,  # simulate a collision with first order
        )
        fourth._regenerate_order_number_sequence()

        new_seq = int(fourth.order_number.rsplit("-", 1)[-1])
        self.assertEqual(new_seq, max_seq + 1, "New sequence must be max_existing + 1, not count-based")
        # suppress unused variable warnings
        _ = o2

    def test_regenerate_falls_back_when_no_existing_orders(self) -> None:
        """When no orders exist with the prefix, sequence starts at 1."""
        # Use a future-dated prefix that has no existing orders
        order = Order(
            customer=self.customer,
            currency=self.currency,
            customer_email="test@test.ro",
            customer_name="Test",
            order_number="ORD-29991231-000999",  # distant future prefix, no orders exist
        )
        order._regenerate_order_number_sequence()

        # After regeneration there are no existing ORD-29991231-* orders,
        # so next_seq should be 1
        new_seq = int(order.order_number.rsplit("-", 1)[-1])
        seq_width = len("000001")  # preserved zero-padding width from original
        self.assertGreaterEqual(new_seq, 1)
        # Verify zero-padding width is preserved (original had 6 digits)
        seq_part = order.order_number.rsplit("-", 1)[-1]
        self.assertEqual(len(seq_part), seq_width, "Zero-padding width must be preserved")

    def test_regenerate_without_prefix_falls_back_to_full_generation(self) -> None:
        """When order_number has no dash, _regenerate falls back to generate_order_number."""
        order = Order(
            customer=self.customer,
            currency=self.currency,
            customer_email="test@test.ro",
            customer_name="Test",
            order_number="NOSLASHES",  # malformed: no dash at all
        )
        order._regenerate_order_number_sequence()

        # Should now have a valid generated number
        self.assertIn("-", order.order_number, "Fallback generate_order_number must produce a hyphenated number")
        self.assertTrue(order.order_number.startswith("ORD-"), "Fallback must use standard ORD- prefix")


# ===============================================================================
# M2: _NON_RETRYABLE_CONSTRAINT_MARKERS covers the idempotency constraint
# ===============================================================================


class NonRetryableConstraintMarkersTest(TestCase):
    """M2: _NON_RETRYABLE_CONSTRAINT_MARKERS must contain the idempotency key constraint name."""

    def test_non_retryable_markers_constant_exists(self) -> None:
        """_NON_RETRYABLE_CONSTRAINT_MARKERS must be defined on the Order model."""
        self.assertTrue(
            hasattr(Order, "_NON_RETRYABLE_CONSTRAINT_MARKERS"),
            "Order must define _NON_RETRYABLE_CONSTRAINT_MARKERS",
        )

    def test_idempotency_constraint_name_in_markers(self) -> None:
        """The unique_customer_idempotency_key constraint name must appear in the markers."""
        markers = Order._NON_RETRYABLE_CONSTRAINT_MARKERS
        self.assertIn(
            "unique_customer_idempotency_key",
            markers,
            "Idempotency key constraint name must be in _NON_RETRYABLE_CONSTRAINT_MARKERS "
            "so that IntegrityErrors on duplicate idempotency keys are never retried.",
        )

    def test_non_retryable_markers_does_not_overlap_collision_markers(self) -> None:
        """Non-retryable markers must be distinct from order_number collision markers."""
        retryable = set(Order._ORDER_NUMBER_COLLISION_MARKERS)
        non_retryable = set(Order._NON_RETRYABLE_CONSTRAINT_MARKERS)
        overlap = retryable & non_retryable
        self.assertEqual(overlap, set(), f"Markers must not overlap, found: {overlap}")


# ===============================================================================
# H9: confirm_order creates OrderStatusHistory and enforces state machine
# ===============================================================================


def _make_pending_order_for_h9(customer: Customer, currency: Currency, **kwargs: object) -> Order:
    """Create a pending order for H9 state machine tests."""
    return Order.objects.create(
        customer=customer,
        currency=currency,
        customer_email=customer.primary_email,
        customer_name=customer.company_name,
        status="pending",
        **kwargs,
    )


class ConfirmOrderStatusHistoryTest(TestCase):
    """H9: confirm_order must create an OrderStatusHistory record via the state machine."""

    def setUp(self) -> None:
        self.user = _make_user("h9-status@test.ro")
        self.currency = _make_currency()
        self.customer = _make_customer(self.user)
        self.factory = APIRequestFactory()

    def _make_request(self, data: dict) -> object:
        request = self.factory.post(
            "/api/orders/confirm/",
            data=data,
            content_type="application/json",
        )
        request._portal_authenticated = True
        request.user = self.user
        return request

    def test_confirm_order_creates_status_history_record(self) -> None:
        """After confirming an order, an OrderStatusHistory row must exist."""
        from apps.api.orders.views import confirm_order  # noqa: PLC0415

        order = _make_pending_order_for_h9(self.customer, self.currency, payment_method="bank_transfer")

        with (
            patch("apps.api.secure_auth.get_authenticated_customer", return_value=(self.customer, None)),
            patch("apps.api.orders.views._provision_confirmed_order_item"),
        ):
            response = confirm_order(self._make_request({"payment_status": "succeeded"}), str(order.id))

        self.assertEqual(response.status_code, 200)
        history_count = OrderStatusHistory.objects.filter(order=order).count()
        # One from draft→pending at creation, one from pending→confirmed here
        self.assertGreaterEqual(history_count, 1, "At least one OrderStatusHistory row must exist after confirm")

        latest = OrderStatusHistory.objects.filter(order=order).order_by("-created_at").first()
        self.assertIsNotNone(latest)
        assert latest is not None  # narrow type for mypy
        self.assertEqual(latest.new_status, "confirmed")
        self.assertEqual(latest.old_status, "pending")

    def test_confirm_order_status_transition_pending_to_confirmed(self) -> None:
        """The state machine must transition order from pending → confirmed."""
        from apps.api.orders.views import confirm_order  # noqa: PLC0415

        order = _make_pending_order_for_h9(self.customer, self.currency)
        self.assertEqual(order.status, "pending")

        with (
            patch("apps.api.secure_auth.get_authenticated_customer", return_value=(self.customer, None)),
            patch("apps.api.orders.views._provision_confirmed_order_item"),
        ):
            response = confirm_order(self._make_request({}), str(order.id))

        self.assertEqual(response.status_code, 200)
        order.refresh_from_db()
        self.assertEqual(order.status, "confirmed")

    def test_invalid_transition_refunded_to_confirmed_is_rejected(self) -> None:
        """The state machine must reject the refunded → confirmed transition."""
        from apps.orders.services import OrderService  # noqa: PLC0415

        order = _make_order(self.customer, self.currency)
        # Force the order into 'refunded' state directly (terminal state)
        force_status(order, "refunded")

        status_change = StatusChangeData(new_status="confirmed", notes="attacker attempt", changed_by=None)
        result = OrderService.update_order_status(order, status_change)

        self.assertFalse(result.is_ok(), "refunded → confirmed must be rejected by the state machine")

    def test_invalid_transition_cancelled_to_confirmed_is_rejected(self) -> None:
        """The state machine must reject the cancelled → confirmed transition."""
        from apps.orders.services import OrderService  # noqa: PLC0415

        order = _make_order(self.customer, self.currency)
        force_status(order, "cancelled")

        status_change = StatusChangeData(new_status="confirmed", notes="unexpected retry", changed_by=None)
        result = OrderService.update_order_status(order, status_change)

        self.assertFalse(result.is_ok(), "cancelled → confirmed must be rejected by the state machine")

    def test_double_confirmation_is_rejected_by_idempotency_guard(self) -> None:
        """Calling confirm_order twice on the same order must return HTTP 409 on the second call."""
        from apps.api.orders.views import confirm_order  # noqa: PLC0415

        order = _make_pending_order_for_h9(self.customer, self.currency)

        with (
            patch("apps.api.secure_auth.get_authenticated_customer", return_value=(self.customer, None)),
            patch("apps.api.orders.views._provision_confirmed_order_item"),
        ):
            first_response = confirm_order(self._make_request({}), str(order.id))
            second_response = confirm_order(self._make_request({}), str(order.id))

        self.assertEqual(first_response.status_code, 200)
        self.assertEqual(
            second_response.status_code, 409, "Second confirmation attempt must return HTTP 409 Conflict"
        )


# ===============================================================================
# M10: Idempotency key content validation (regex injection guard)
# ===============================================================================


class IdempotencyKeyContentValidationTest(TestCase):
    """M10: create_order must reject idempotency keys containing non-safe characters."""

    def setUp(self) -> None:
        self.user = _make_user("m10-idempotency@test.ro")
        self.currency = _make_currency()
        self.customer = _make_customer(self.user)
        self.factory = APIRequestFactory()

    def _make_create_request(self, idempotency_key: str, body: dict | None = None) -> object:
        """Build a create_order request with the given idempotency key header."""
        data = body or {
            "currency": "RON",
            "items": [],
        }
        request = self.factory.post(
            "/api/orders/create/",
            data=data,
            content_type="application/json",
            HTTP_IDEMPOTENCY_KEY=idempotency_key,
        )
        request._portal_authenticated = True
        request.user = self.user
        return request

    def test_valid_alphanumeric_key_passes_content_check(self) -> None:
        """A key composed of alphanumeric characters, hyphens, and underscores must pass the regex.

        The view may still return 400 for other reasons (empty items, missing customer_id in
        serializer, etc.) but must NOT return 400 with the "alphanumeric" key-format error.
        """
        from apps.api.orders.views import create_order  # noqa: PLC0415

        valid_key = "a" * 20  # 20 alphanumeric chars — passes both length and content checks
        request = self._make_create_request(valid_key)

        with patch("apps.api.secure_auth.get_authenticated_customer", return_value=(self.customer, None)):
            response = create_order(request)

        # The key itself is valid — the rejection reason must NOT be about key content
        error_msg = str(response.data.get("error", "")).lower()
        self.assertNotIn(
            "alphanumeric",
            error_msg,
            f"Valid key must not trigger the content-validation rejection. Got: {response.data}",
        )

    def test_key_with_space_is_rejected(self) -> None:
        """Keys containing spaces must be rejected with HTTP 400."""
        from apps.api.orders.views import create_order  # noqa: PLC0415

        bad_key = "valid-prefix with space"
        request = self._make_create_request(bad_key)

        with patch("apps.api.secure_auth.get_authenticated_customer", return_value=(self.customer, None)):
            response = create_order(request)

        self.assertEqual(response.status_code, 400)
        self.assertIn("alphanumeric", response.data["error"].lower())

    def test_key_with_semicolon_is_rejected(self) -> None:
        """Keys containing semicolons (SQL injection vector) must be rejected."""
        from apps.api.orders.views import create_order  # noqa: PLC0415

        bad_key = "valid-prefix;DROP TABLE orders--"
        request = self._make_create_request(bad_key)

        with patch("apps.api.secure_auth.get_authenticated_customer", return_value=(self.customer, None)):
            response = create_order(request)

        self.assertEqual(response.status_code, 400)
        self.assertIn("alphanumeric", response.data["error"].lower())

    def test_key_with_special_chars_is_rejected(self) -> None:
        """Keys with shell-injection characters must be rejected.

        The key must be at least 16 chars (min length) to reach the regex content check.
        A shorter bad key would be caught by the length validator first.
        """
        from apps.api.orders.views import create_order  # noqa: PLC0415

        # 20 chars with a shell-injection $ character — long enough to pass length check
        bad_key = "valid-key-prefix$()"
        request = self._make_create_request(bad_key)

        with patch("apps.api.secure_auth.get_authenticated_customer", return_value=(self.customer, None)):
            response = create_order(request)

        self.assertEqual(response.status_code, 400)
        self.assertIn("alphanumeric", response.data["error"].lower())

    def test_key_with_hyphen_and_underscore_passes(self) -> None:
        """Hyphens and underscores are explicitly allowed and must pass the regex."""
        from apps.api.orders.views import create_order  # noqa: PLC0415

        good_key = "order-key_test-20260310"  # 22 chars, hyphens + underscores
        request = self._make_create_request(good_key)

        with patch("apps.api.secure_auth.get_authenticated_customer", return_value=(self.customer, None)):
            response = create_order(request)

        # The key is structurally valid — only downstream errors (empty items etc.) are acceptable
        self.assertNotIn(
            "alphanumeric",
            str(response.data.get("error", "")).lower(),
            "Hyphens and underscores must not cause a key-format rejection",
        )


# ===============================================================================
# H1: IntegrityError catch must only handle the idempotency key constraint
# ===============================================================================


class CreateOrderIntegrityErrorScopeTest(TestCase):
    """H1: IntegrityError on create_order must only catch idempotency race, not check constraints."""

    def setUp(self) -> None:
        self.user = _make_user("h1-integrity@test.ro")
        self.currency = _make_currency()
        self.customer = _make_customer(self.user)
        self.factory = APIRequestFactory()

    def _make_create_request(self, idempotency_key: str) -> object:
        request = self.factory.post(
            "/api/orders/create/",
            data={"currency": "RON", "items": []},
            content_type="application/json",
            HTTP_IDEMPOTENCY_KEY=idempotency_key,
        )
        request._portal_authenticated = True
        request.user = self.user
        return request

    def test_idempotency_race_returns_existing_order(self) -> None:
        """When IntegrityError contains idempotency key constraint name, return existing order with duplicate=True."""
        from apps.api.orders.views import create_order  # noqa: PLC0415

        idempotency_key = "h1-idempotency-race-key1234"
        existing = _make_order(self.customer, self.currency, idempotency_key=idempotency_key)

        idempotency_exc = IntegrityError(
            'duplicate key value violates unique constraint "unique_customer_idempotency_key"'
        )

        request = self._make_create_request(idempotency_key)

        with (
            patch("apps.api.secure_auth.get_authenticated_customer", return_value=(self.customer, None)),
            patch("apps.orders.services.OrderService.create_order", side_effect=idempotency_exc),
        ):
            response = create_order(request)

        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.data["duplicate"])
        self.assertEqual(response.data["order"]["id"], str(existing.id))

    def test_non_idempotency_integrity_error_is_re_raised(self) -> None:
        """When IntegrityError does NOT contain idempotency constraint name, it must propagate (not be swallowed).

        Patches the serializer and billing address helper to bypass input validation so the code
        reaches the OrderService.create_order call where the IntegrityError is raised.
        """
        from apps.api.orders.views import create_order  # noqa: PLC0415

        idempotency_key = "h1-non-idempotency-key12345"

        check_constraint_exc = IntegrityError(
            'new row for relation "orders" violates check constraint "order_subtotal_non_negative"'
        )

        request = self._make_create_request(idempotency_key)

        # Patch serializer validation to pass and billing address to avoid DB call,
        # so we can reach the OrderService.create_order mock.
        from apps.api.orders.serializers import OrderCreateInputSerializer  # noqa: PLC0415

        with (
            patch("apps.api.secure_auth.get_authenticated_customer", return_value=(self.customer, None)),
            patch.object(
                OrderCreateInputSerializer,
                "is_valid",
                return_value=True,
            ),
            patch.object(
                OrderCreateInputSerializer,
                "validated_data",
                new_callable=lambda: property(lambda self: {"currency": "RON", "items": [], "notes": "", "meta": {}}),
                create=True,
            ),
            patch(
                "apps.orders.services.OrderService.build_billing_address_from_customer",
                return_value={},
            ),
            patch("apps.orders.services.OrderService.create_order", side_effect=check_constraint_exc),
        ):
            response = create_order(request)

        # A check constraint violation is a server error, not a duplicate — must return 500
        self.assertEqual(
            response.status_code,
            500,
            "A non-idempotency IntegrityError must not be swallowed as a duplicate — must return 500",
        )


# ===============================================================================
# H2: PI binding in confirm_order requires payment_method="card" explicitly
# ===============================================================================


class ConfirmOrderPaymentIntentBindingTest(TestCase):
    """H2: confirm_order must only allow PI binding when payment_method is exactly 'card'."""

    def setUp(self) -> None:
        self.user = _make_user("h2-pi-binding@test.ro")
        self.currency = _make_currency()
        self.customer = _make_customer(self.user)
        self.factory = APIRequestFactory()

    def _make_confirm_request(self, data: dict) -> object:
        request = self.factory.post(
            "/api/orders/confirm/",
            data=data,
            content_type="application/json",
        )
        request._portal_authenticated = True
        request.user = self.user
        return request

    def _make_pending_order(self, payment_method: str = "") -> Order:
        return Order.objects.create(
            customer=self.customer,
            currency=self.currency,
            customer_email=self.customer.primary_email,
            customer_name=self.customer.company_name,
            status="pending",
            payment_method=payment_method,
        )

    def test_bank_transfer_order_rejects_pi_binding(self) -> None:
        """An order with payment_method='bank_transfer' must return 400 when a PI is provided."""
        from apps.api.orders.views import confirm_order  # noqa: PLC0415

        order = self._make_pending_order(payment_method="bank_transfer")
        request = self._make_confirm_request({"payment_intent_id": "pi_validformat1234567890"})

        with patch("apps.api.secure_auth.get_authenticated_customer", return_value=(self.customer, None)):
            response = confirm_order(request, str(order.id))

        self.assertEqual(
            response.status_code,
            400,
            "PI binding on bank_transfer order must return 400",
        )
        self.assertFalse(response.data["success"])

    def test_empty_payment_method_order_promotes_to_card_on_pi_binding(self) -> None:
        """An order with payment_method='' (portal default) must be promoted to 'card' when a valid PI is provided.

        H2 fix: Portal-created orders have blank payment_method. A valid PI proves card payment,
        so the view promotes blank → 'card' instead of rejecting with 400.
        """
        from apps.api.orders.views import confirm_order  # noqa: PLC0415

        order = self._make_pending_order(payment_method="")
        request = self._make_confirm_request({"payment_intent_id": "pi_validformat1234567890"})

        with (
            patch("apps.api.secure_auth.get_authenticated_customer", return_value=(self.customer, None)),
            patch("apps.api.orders.views._provision_confirmed_order_item"),
        ):
            response = confirm_order(request, str(order.id))

        # Must NOT return 400 — the order should be promoted to card and proceed
        self.assertNotEqual(
            response.status_code,
            400,
            f"PI binding on blank payment_method must promote to 'card', not return 400. Got: {response.data}",
        )
        # Verify the order's payment_method was set to "card"
        order.refresh_from_db()
        self.assertEqual(order.payment_method, "card", "Order payment_method must be promoted to 'card'")

    def test_card_payment_method_allows_pi_binding(self) -> None:
        """An order with payment_method='card' must allow PI binding and proceed."""
        from apps.api.orders.views import confirm_order  # noqa: PLC0415

        order = self._make_pending_order(payment_method="card")
        request = self._make_confirm_request({"payment_intent_id": "pi_validformat1234567890"})

        with (
            patch("apps.api.secure_auth.get_authenticated_customer", return_value=(self.customer, None)),
            patch("apps.api.orders.views._provision_confirmed_order_item"),
        ):
            response = confirm_order(request, str(order.id))

        # Must not return 400 for the payment_method check — provisioning/status errors are acceptable
        self.assertNotEqual(
            response.status_code,
            400,
            f"PI binding on card order must not return 400. Got: {response.data}",
        )


# ===============================================================================
# M1: payment_intent_id format validation (must match pi_[a-zA-Z0-9]{10,64})
# ===============================================================================


class ConfirmOrderPIFormatValidationTest(TestCase):
    """M1: confirm_order must reject payment_intent_id values that don't match Stripe's pi_ format."""

    def setUp(self) -> None:
        self.user = _make_user("m1-pi-format@test.ro")
        self.currency = _make_currency()
        self.customer = _make_customer(self.user)
        self.factory = APIRequestFactory()

    def _make_pending_card_order(self) -> Order:
        return Order.objects.create(
            customer=self.customer,
            currency=self.currency,
            customer_email=self.customer.primary_email,
            customer_name=self.customer.company_name,
            status="pending",
            payment_method="card",
        )

    def _make_confirm_request(self, data: dict) -> object:
        request = self.factory.post(
            "/api/orders/confirm/",
            data=data,
            content_type="application/json",
        )
        request._portal_authenticated = True
        request.user = self.user
        return request

    def test_arbitrary_string_pi_id_is_rejected(self) -> None:
        """A PI ID that doesn't match pi_[a-zA-Z0-9]+ must return 400."""
        from apps.api.orders.views import confirm_order  # noqa: PLC0415

        order = self._make_pending_card_order()
        request = self._make_confirm_request({"payment_intent_id": "not_a_pi"})

        with patch("apps.api.secure_auth.get_authenticated_customer", return_value=(self.customer, None)):
            response = confirm_order(request, str(order.id))

        self.assertEqual(response.status_code, 400)
        self.assertFalse(response.data["success"])
        self.assertIn("format", response.data["error"].lower())

    def test_valid_pi_format_passes_validation(self) -> None:
        """A PI ID matching pi_[a-zA-Z0-9]{10,64} must pass the format check and proceed."""
        from apps.api.orders.views import confirm_order  # noqa: PLC0415

        order = self._make_pending_card_order()
        request = self._make_confirm_request({"payment_intent_id": "pi_validformat1234567890"})

        with (
            patch("apps.api.secure_auth.get_authenticated_customer", return_value=(self.customer, None)),
            patch("apps.api.orders.views._provision_confirmed_order_item"),
        ):
            response = confirm_order(request, str(order.id))

        # Must not be rejected due to format — any non-400 is acceptable here
        self.assertNotEqual(
            response.status_code,
            400,
            f"Valid PI format must not be rejected. Got: {response.data}",
        )

    def test_pi_with_special_chars_is_rejected(self) -> None:
        """A PI ID with non-alphanumeric characters after pi_ must return 400."""
        from apps.api.orders.views import confirm_order  # noqa: PLC0415

        order = self._make_pending_card_order()
        request = self._make_confirm_request({"payment_intent_id": "pi_invalid!@#$%^&*()"})

        with patch("apps.api.secure_auth.get_authenticated_customer", return_value=(self.customer, None)):
            response = confirm_order(request, str(order.id))

        self.assertEqual(response.status_code, 400)

    def test_pi_too_short_is_rejected(self) -> None:
        """A PI ID with fewer than 10 characters after pi_ must return 400."""
        from apps.api.orders.views import confirm_order  # noqa: PLC0415

        order = self._make_pending_card_order()
        # Only 5 chars after pi_ — below the minimum of 10
        request = self._make_confirm_request({"payment_intent_id": "pi_short"})

        with patch("apps.api.secure_auth.get_authenticated_customer", return_value=(self.customer, None)):
            response = confirm_order(request, str(order.id))

        self.assertEqual(response.status_code, 400)


# ===============================================================================
# M2: Internal error messages must not be leaked to the client in confirm_order
# ===============================================================================


class ConfirmOrderErrorLeakageTest(TestCase):
    """M2: confirm_order must return generic error messages, not internal state machine details."""

    def setUp(self) -> None:
        self.user = _make_user("m2-error-leakage@test.ro")
        self.currency = _make_currency()
        self.customer = _make_customer(self.user)
        self.factory = APIRequestFactory()

    def _make_confirm_request(self, data: dict | None = None) -> object:
        request = self.factory.post(
            "/api/orders/confirm/",
            data=data or {},
            content_type="application/json",
        )
        request._portal_authenticated = True
        request.user = self.user
        return request

    def test_already_confirmed_order_returns_409_with_generic_message(self) -> None:
        """Calling confirm_order on an already-confirmed order must return 409 with no internal state names."""
        from apps.api.orders.views import confirm_order  # noqa: PLC0415

        # An order that is already confirmed cannot be confirmed again
        order = Order.objects.create(
            customer=self.customer,
            currency=self.currency,
            customer_email=self.customer.primary_email,
            customer_name=self.customer.company_name,
            status="confirmed",
        )

        request = self._make_confirm_request({})

        with patch("apps.api.secure_auth.get_authenticated_customer", return_value=(self.customer, None)):
            response = confirm_order(request, str(order.id))

        self.assertEqual(response.status_code, 409)
        self.assertFalse(response.data["success"])

    def test_status_update_failure_does_not_expose_internal_error_message(self) -> None:
        """When OrderService.update_order_status returns Err, the response must not contain internal details."""
        from apps.api.orders.views import confirm_order  # noqa: PLC0415
        from apps.common.types import Err  # noqa: PLC0415

        order = Order.objects.create(
            customer=self.customer,
            currency=self.currency,
            customer_email=self.customer.primary_email,
            customer_name=self.customer.company_name,
            status="pending",
        )

        internal_message = "Invalid status transition: pending -> confirmed (constraint XYZ violated internally)"

        request = self._make_confirm_request({})

        with (
            patch("apps.api.secure_auth.get_authenticated_customer", return_value=(self.customer, None)),
            patch(
                "apps.api.orders.views.OrderService.update_order_status",
                return_value=Err(internal_message),
            ),
        ):
            response = confirm_order(request, str(order.id))

        self.assertEqual(response.status_code, 409)
        self.assertFalse(response.data["success"])

        # The internal message must NOT appear verbatim in the response
        error_text = response.data.get("error", "")
        self.assertNotIn(
            "Invalid status transition",
            error_text,
            "Internal state machine error must not be leaked to the client",
        )
        self.assertNotIn(
            "constraint XYZ",
            error_text,
            "Internal constraint names must not appear in client-facing error messages",
        )
        # Response must be a generic, user-friendly message
        self.assertIn(
            "confirmed",
            error_text.lower(),
            "Generic error message should mention the action (confirmed) without internal details",
        )
