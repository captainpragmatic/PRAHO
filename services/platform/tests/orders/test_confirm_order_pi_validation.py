"""
PaymentIntent validation tests for confirm_order API endpoint.

Verifies:
  H7: confirm_order rejects PI binding for non-stripe orders
  H7: confirm_order rejects mismatched PI when order already has one
  H7: confirm_order allows valid PI for stripe orders
"""

from unittest.mock import MagicMock, patch

from django.test import TestCase
from rest_framework.test import APIRequestFactory

from apps.billing.gateways.base import PaymentConfirmResult
from apps.billing.models import Currency
from apps.customers.models import Customer
from apps.orders.models import Order
from apps.users.models import User


def _make_user(email: str = "pi-test@pragmatichost.com") -> User:
    return User.objects.create_user(email=email, password="testpass123", is_staff=True, staff_role="admin")


def _make_currency() -> Currency:
    c, _ = Currency.objects.get_or_create(code="RON", defaults={"name": "Romanian Leu", "symbol": "lei", "decimals": 2})
    return c


def _make_customer(user: User) -> Customer:
    return Customer.objects.create(
        customer_type="company",
        company_name="PI Test Corp",
        primary_email=f"pi-{user.email}",
        primary_phone="+40700000000",
        data_processing_consent=True,
        created_by=user,
    )


def _make_pending_order(customer: Customer, currency: Currency, **kwargs: object) -> Order:
    return Order.objects.create(
        customer=customer,
        currency=currency,
        customer_email=customer.primary_email,
        customer_name=customer.company_name,
        status="awaiting_payment",
        **kwargs,
    )


class ConfirmOrderPaymentIntentValidationTest(TestCase):
    """H7: confirm_order must validate PaymentIntent against order's payment method."""

    def setUp(self) -> None:
        self.user = _make_user()
        self.currency = _make_currency()
        self.customer = _make_customer(self.user)
        self.factory = APIRequestFactory()

    def _make_request(self, data: dict) -> object:
        """Build a RequestFactory POST request with portal auth attributes."""
        request = self.factory.post(
            "/api/orders/confirm/",
            data=data,
            content_type="application/json",
        )
        request._portal_authenticated = True
        request.user = self.user
        return request

    def test_bank_transfer_order_rejects_payment_intent(self) -> None:
        """Bank transfer orders must not accept Stripe PaymentIntent binding."""
        from apps.api.orders.views import confirm_order  # noqa: PLC0415

        order = _make_pending_order(
            self.customer, self.currency,
            payment_method="bank_transfer",
        )
        # Use a correctly formatted Stripe PI ID (pi_ + alphanumeric, min 10 chars)
        request = self._make_request({"payment_intent_id": "pi_attacker1234567890", "payment_status": "succeeded"})

        # Bypass HMAC decorator: inject pre-authenticated customer directly
        with patch("apps.api.secure_auth.get_authenticated_customer", return_value=(self.customer, None)):
            response = confirm_order(request, str(order.id))

        self.assertEqual(response.status_code, 400)
        self.assertIn("does not accept payment intents", response.data["error"])

    def test_mismatched_pi_rejected(self) -> None:
        """When order already has a PI, a different PI must be rejected."""
        from apps.api.orders.views import confirm_order  # noqa: PLC0415

        order = _make_pending_order(
            self.customer, self.currency,
            payment_method="card",
            payment_intent_id="pi_originalXYZ1234567890",
        )
        request = self._make_request({"payment_intent_id": "pi_attackerXYZ1234567890", "payment_status": "succeeded"})

        with patch("apps.api.secure_auth.get_authenticated_customer", return_value=(self.customer, None)):
            response = confirm_order(request, str(order.id))

        self.assertEqual(response.status_code, 400)
        self.assertIn("does not match", response.data["error"])

    def test_valid_stripe_pi_accepted(self) -> None:
        """Valid card order with matching PI proceeds to confirmation."""
        from apps.api.orders.views import confirm_order  # noqa: PLC0415

        order = _make_pending_order(
            self.customer, self.currency,
            payment_method="card",
            payment_intent_id="pi_validXYZ1234567890",
        )
        request = self._make_request({"payment_intent_id": "pi_validXYZ1234567890", "payment_status": "succeeded"})

        mock_gateway = MagicMock()
        mock_gateway.confirm_payment.return_value = PaymentConfirmResult(success=True, status="succeeded", error=None)

        with patch("apps.api.secure_auth.get_authenticated_customer", return_value=(self.customer, None)), \
             patch("apps.api.orders.views._provision_confirmed_order_item"), \
             patch("apps.billing.gateways.base.PaymentGatewayFactory.create_gateway", return_value=mock_gateway):
            response = confirm_order(request, str(order.id))

        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.data["success"])
        mock_gateway.confirm_payment.assert_called_once_with("pi_validXYZ1234567890")

        order.refresh_from_db()
        # After confirmation, order advances through lifecycle (paid → provisioning or in_review)
        self.assertIn(order.status, ["paid", "in_review", "provisioning"])

    def test_no_pi_order_rejects_non_card_payment(self) -> None:
        """Non-card orders are rejected by the confirm endpoint (security fix).

        Bank-transfer orders must be confirmed via billing/webhook/admin paths,
        not the customer-facing API endpoint.
        """
        from apps.api.orders.views import confirm_order  # noqa: PLC0415

        order = _make_pending_order(
            self.customer, self.currency,
            payment_method="bank_transfer",
        )
        request = self._make_request({"payment_status": "succeeded"})

        with patch("apps.api.secure_auth.get_authenticated_customer", return_value=(self.customer, None)):
            response = confirm_order(request, str(order.id))

        self.assertEqual(response.status_code, 400)
