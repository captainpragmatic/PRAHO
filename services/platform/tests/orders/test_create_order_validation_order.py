"""
Validation ordering test for create_order API endpoint.

Verifies:
  M9: Input validation runs BEFORE DB fallback idempotency check,
      so invalid requests don't incur unnecessary database queries.
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
    """M9: Invalid requests must be rejected before DB idempotency check."""

    def setUp(self) -> None:
        cache.clear()
        self.user = _make_user()
        self.currency = _make_currency()
        self.customer = _make_customer(self.user)
        self.factory = APIRequestFactory()

    def test_invalid_input_rejected_without_db_query(self) -> None:
        """Malformed requests get 400 without hitting Order.objects.filter()."""
        from apps.api.orders.views import create_order  # noqa: PLC0415

        request = self.factory.post(
            "/api/orders/create/",
            data={
                "idempotency_key": "a" * 32,
                # Missing required fields (items, currency) — should fail validation
            },
            format="json",
        )
        request._portal_authenticated = True
        request.user = self.user

        with (
            patch("apps.api.secure_auth.get_authenticated_customer", return_value=(self.customer, None)),
            patch("apps.orders.models.Order.objects") as mock_manager,
        ):
            # If DB fallback runs, this mock would be called
            mock_manager.filter.return_value.first.return_value = None

            response = create_order(request)

        # Should get 400 (invalid input) without querying the DB
        self.assertEqual(response.status_code, 400)
        # DB should NOT have been queried for idempotency
        mock_manager.filter.assert_not_called()

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
