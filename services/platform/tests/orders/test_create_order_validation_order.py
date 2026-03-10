"""
Validation ordering test for create_order API endpoint.

Verifies:
  M9: DB fallback idempotency check runs BEFORE input validation,
      so previously-processed requests return cached results regardless
      of current payload validity (correct idempotency semantics).
"""

from unittest.mock import patch

from django.core.cache import cache
from django.test import TestCase
from rest_framework.test import APIRequestFactory

from apps.billing.models import Currency
from apps.customers.models import Customer
from apps.users.models import User


def _make_user(email: str = "m9-test@pragmatichost.com") -> User:
    return User.objects.create_user(email=email, password="testpass123", is_staff=True, staff_role="admin")


def _make_currency() -> Currency:
    c, _ = Currency.objects.get_or_create(code="RON", defaults={"name": "Romanian Leu", "symbol": "lei", "decimals": 2})
    return c


def _make_customer(user: User) -> Customer:
    return Customer.objects.create(
        customer_type="company",
        company_name="M9 Test Corp",
        primary_email=f"m9-{user.email}",
        primary_phone="+40700000000",
        data_processing_consent=True,
        created_by=user,
    )


class CreateOrderValidationBeforeDBTest(TestCase):
    """M9: DB idempotency check runs first, then input validation."""

    def setUp(self) -> None:
        cache.clear()
        self.user = _make_user()
        self.currency = _make_currency()
        self.customer = _make_customer(self.user)
        self.factory = APIRequestFactory()

    def test_invalid_input_still_checks_db_idempotency(self) -> None:
        """DB idempotency check runs before validation — even for malformed requests."""
        from apps.api.orders.views import create_order  # noqa: PLC0415

        request = self.factory.post(
            "/api/orders/create/",
            data={
                "idempotency_key": "a" * 32,
                # Missing required fields (items, currency) — will fail validation
            },
            format="json",
        )
        request._portal_authenticated = True
        request.user = self.user

        with (
            patch("apps.api.secure_auth.get_authenticated_customer", return_value=(self.customer, None)),
            patch("apps.api.orders.views.Order.objects") as mock_manager,
        ):
            # DB fallback runs first — no cached order found
            mock_manager.filter.return_value.first.return_value = None

            response = create_order(request)

        # Still gets 400 (invalid input) — but DB WAS checked first
        self.assertEqual(response.status_code, 400)
        # DB SHOULD have been queried for idempotency (M9: DB check before validation)
        mock_manager.filter.assert_called_once()

    def test_valid_input_reaches_db_fallback(self) -> None:
        """Valid requests with idempotency key DO reach the DB fallback check."""
        from apps.api.orders.views import create_order  # noqa: PLC0415

        request = self.factory.post(
            "/api/orders/create/",
            data={
                "idempotency_key": "b" * 32,
                "items": [{"product_slug": "hosting-plan", "quantity": 1, "billing_period": "monthly"}],
                "currency": "RON",
                "customer_id": self.customer.id,
            },
            format="json",
        )
        request._portal_authenticated = True
        request.user = self.user

        with (
            patch("apps.api.secure_auth.get_authenticated_customer", return_value=(self.customer, None)),
            patch("apps.api.orders.views.Order.objects") as mock_manager,
            patch("apps.api.orders.views.OrderService") as mock_svc,
        ):
            mock_manager.filter.return_value.first.return_value = None
            mock_svc.build_billing_address_from_customer.return_value = {}
            # Let it fail after the DB check — we only care about order of operations
            mock_svc.create_order.side_effect = Exception("Stop here")

            import contextlib  # noqa: PLC0415

            with contextlib.suppress(Exception):
                create_order(request)

        # DB fallback SHOULD have been attempted (after validation passed)
        mock_manager.filter.assert_called_once()
