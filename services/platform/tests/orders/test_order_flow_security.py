"""
Issue #104: Order flow security fixes.

Tests for:
  H11: Server-side Stripe PaymentIntent verification in confirm_order
  C2:  Unified order number generation (model delegates to service)
  M7:  CSP nonce middleware infrastructure
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from django.http import HttpResponse
from django.test import RequestFactory, SimpleTestCase, TestCase
from rest_framework.test import APIRequestFactory

from apps.api.orders.views import confirm_order
from apps.billing.gateways.base import PaymentConfirmResult
from apps.billing.models import Currency
from apps.common.context_processors import csp_nonce
from apps.common.middleware import CSPNonceMiddleware, SecurityHeadersMiddleware
from apps.customers.models import Customer
from apps.orders.models import Order
from apps.users.models import User

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_user(email: str = "flow-sec@pragmatichost.com") -> User:
    return User.objects.create_user(email=email, password="testpass123", is_staff=True, staff_role="admin")


def _make_currency() -> Currency:
    c, _ = Currency.objects.get_or_create(code="RON", defaults={"name": "Romanian Leu", "symbol": "lei", "decimals": 2})
    return c


def _make_customer(user: User) -> Customer:
    return Customer.objects.create(
        customer_type="company",
        company_name="Flow Sec Corp",
        primary_email=f"cust-{user.email}",
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
        status="pending",
        **kwargs,
    )


# ===============================================================================
# H11: STRIPE PAYMENTINTENT SERVER-SIDE VERIFICATION
# ===============================================================================


class StripePaymentVerificationTest(TestCase):
    """H11: confirm_order must verify PaymentIntent status with Stripe."""

    def setUp(self) -> None:
        self.user = _make_user()
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

    def test_confirm_verifies_stripe_pi_succeeded(self) -> None:
        """Stripe PI with status=succeeded allows order confirmation."""
        order = _make_pending_order(
            self.customer,
            self.currency,
            payment_method="card",
            payment_intent_id="pi_testVerifyOK1234567",
        )
        request = self._make_request({
            "payment_intent_id": "pi_testVerifyOK1234567",
            "payment_status": "succeeded",
        })

        mock_gateway = MagicMock()
        mock_gateway.confirm_payment.return_value = PaymentConfirmResult(
            success=True, status="succeeded", error=None,
        )

        with (
            patch("apps.api.secure_auth.get_authenticated_customer", return_value=(self.customer, None)),
            patch("apps.api.orders.views._provision_confirmed_order_item"),
            patch("apps.billing.gateways.base.PaymentGatewayFactory.create_gateway", return_value=mock_gateway),
        ):
            response = confirm_order(request, str(order.id))

        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.data["success"])
        mock_gateway.confirm_payment.assert_called_once_with("pi_testVerifyOK1234567")

    def test_confirm_rejects_non_succeeded_pi(self) -> None:
        """Stripe PI with status != succeeded rejects order confirmation."""
        order = _make_pending_order(
            self.customer,
            self.currency,
            payment_method="card",
            payment_intent_id="pi_testVerifyFail12345",
        )
        request = self._make_request({
            "payment_intent_id": "pi_testVerifyFail12345",
            "payment_status": "succeeded",
        })

        mock_gateway = MagicMock()
        mock_gateway.confirm_payment.return_value = PaymentConfirmResult(
            success=True, status="requires_payment_method", error=None,
        )

        with (
            patch("apps.api.secure_auth.get_authenticated_customer", return_value=(self.customer, None)),
            patch("apps.billing.gateways.base.PaymentGatewayFactory.create_gateway", return_value=mock_gateway),
        ):
            response = confirm_order(request, str(order.id))

        self.assertEqual(response.status_code, 400)
        self.assertIn("Payment verification failed", response.data["error"])

    def test_confirm_rejects_stripe_api_error(self) -> None:
        """Stripe API error (success=False) rejects order confirmation."""
        order = _make_pending_order(
            self.customer,
            self.currency,
            payment_method="card",
            payment_intent_id="pi_testAPIError1234567",
        )
        request = self._make_request({
            "payment_intent_id": "pi_testAPIError1234567",
            "payment_status": "succeeded",
        })

        mock_gateway = MagicMock()
        mock_gateway.confirm_payment.return_value = PaymentConfirmResult(
            success=False, status="error", error="Stripe API unavailable",
        )

        with (
            patch("apps.api.secure_auth.get_authenticated_customer", return_value=(self.customer, None)),
            patch("apps.billing.gateways.base.PaymentGatewayFactory.create_gateway", return_value=mock_gateway),
        ):
            response = confirm_order(request, str(order.id))

        self.assertEqual(response.status_code, 400)
        self.assertIn("Payment verification failed", response.data["error"])

    def test_confirm_rejects_when_stripe_not_configured(self) -> None:
        """When Stripe gateway is not configured, fail-closed with 503."""
        order = _make_pending_order(
            self.customer,
            self.currency,
            payment_method="card",
            payment_intent_id="pi_testNoStripe1234567",
        )
        request = self._make_request({
            "payment_intent_id": "pi_testNoStripe1234567",
            "payment_status": "succeeded",
        })

        with (
            patch("apps.api.secure_auth.get_authenticated_customer", return_value=(self.customer, None)),
            patch(
                "apps.billing.gateways.base.PaymentGatewayFactory.create_gateway",
                side_effect=ValueError("Stripe not configured"),
            ),
        ):
            response = confirm_order(request, str(order.id))

        self.assertEqual(response.status_code, 503)
        self.assertIn("Payment gateway not configured", response.data["error"])

    def test_bank_transfer_skips_stripe_verification(self) -> None:
        """Orders without payment_intent_id skip Stripe verification entirely."""
        order = _make_pending_order(
            self.customer,
            self.currency,
            payment_method="bank_transfer",
        )
        request = self._make_request({"payment_status": "bank_transfer"})

        with (
            patch("apps.api.secure_auth.get_authenticated_customer", return_value=(self.customer, None)),
            patch("apps.api.orders.views._provision_confirmed_order_item"),
            patch("apps.billing.gateways.base.PaymentGatewayFactory.create_gateway") as mock_factory,
        ):
            response = confirm_order(request, str(order.id))

        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.data["success"])
        mock_factory.assert_not_called()

    def test_confirm_verifies_stored_pi_when_request_omits_it(self) -> None:
        """Bug 1 regression: Stripe verification uses order.payment_intent_id, not request payload.

        Attack scenario: order already has a payment_intent_id stored from a previous step,
        attacker omits payment_intent_id from the confirm request hoping to skip Stripe check.
        The view must still verify the stored PI — not skip verification because the field
        is absent from the request body.
        """
        order = _make_pending_order(
            self.customer,
            self.currency,
            payment_method="card",
            payment_intent_id="pi_storedButNotInRequest12",
        )
        # Request deliberately omits payment_intent_id
        request = self._make_request({"payment_status": "succeeded"})

        mock_gateway = MagicMock()
        mock_gateway.confirm_payment.return_value = PaymentConfirmResult(
            success=False, status="requires_payment_method", error="Not paid",
        )

        with (
            patch("apps.api.secure_auth.get_authenticated_customer", return_value=(self.customer, None)),
            patch("apps.billing.gateways.base.PaymentGatewayFactory.create_gateway", return_value=mock_gateway),
        ):
            response = confirm_order(request, str(order.id))

        # Must reject — Stripe said not succeeded, even though request omitted the PI
        self.assertEqual(response.status_code, 400)
        self.assertIn("Payment verification failed", response.data["error"])
        mock_gateway.confirm_payment.assert_called_once_with("pi_storedButNotInRequest12")


# ===============================================================================
# C2: UNIFIED ORDER NUMBER GENERATION
# ===============================================================================


class OrderNumberUnificationTest(TestCase):
    """C2: Order.generate_order_number() delegates to OrderNumberingService."""

    def setUp(self) -> None:
        self.user = _make_user(email="ordnum@pragmatichost.com")
        self.currency = _make_currency()
        self.customer = _make_customer(self.user)

    def test_model_delegates_to_service_format(self) -> None:
        """Model method produces per-customer format (ORD-{YYYY}-{cust}-{seq})."""
        order = Order(customer=self.customer, currency=self.currency)
        order.generate_order_number()

        self.assertIsNotNone(order.order_number)
        # Service format: ORD-{year}-{customer_id[:8]}-{seq:04d}
        self.assertTrue(order.order_number.startswith("ORD-"))
        parts = order.order_number.split("-")
        self.assertEqual(parts[0], "ORD")
        self.assertEqual(len(parts[1]), 4)  # year
        # parts[2] is customer_id[:8] (length varies: integer PK = short, UUID = 8)
        self.assertTrue(len(parts[2]) >= 1)
        # last part is the sequence number
        self.assertTrue(parts[-1].isdigit())

    def test_model_generates_different_from_old_date_format(self) -> None:
        """Model no longer generates old ORD-{YYYYMMDD}-{seq} format when customer exists."""
        order = Order(customer=self.customer, currency=self.currency)
        order.generate_order_number()

        # Old format had 8-digit date (YYYYMMDD), new has 4-digit year
        parts = order.order_number.split("-")
        self.assertEqual(len(parts[1]), 4)  # year, not YYYYMMDD


# ===============================================================================
# M7: CSP NONCE MIDDLEWARE
# ===============================================================================


class CSPNonceMiddlewareTest(SimpleTestCase):
    """M7: CSP nonce generation and injection into headers."""

    def test_nonce_middleware_sets_request_attribute(self) -> None:
        """CSPNonceMiddleware sets request.csp_nonce as a non-empty string."""
        factory = RequestFactory()
        request = factory.get("/")

        def dummy_response(req):
            return HttpResponse("ok")

        middleware = CSPNonceMiddleware(dummy_response)
        middleware(request)

        self.assertTrue(hasattr(request, "csp_nonce"))
        self.assertIsInstance(request.csp_nonce, str)
        self.assertGreater(len(request.csp_nonce), 20)

    def test_security_headers_include_nonce_in_csp(self) -> None:
        """SecurityHeadersMiddleware includes nonce directive in CSP header."""
        factory = RequestFactory()
        request = factory.get("/")
        request.csp_nonce = "test-nonce-value-12345"

        def dummy_response(req):
            return HttpResponse("ok")

        middleware = SecurityHeadersMiddleware(dummy_response)
        response = middleware(request)

        csp = response.get("Content-Security-Policy", "")
        self.assertIn("'nonce-test-nonce-value-12345'", csp)

    def test_security_headers_work_without_nonce(self) -> None:
        """SecurityHeadersMiddleware works if CSPNonceMiddleware is not active."""
        factory = RequestFactory()
        request = factory.get("/")
        # No csp_nonce attribute set

        def dummy_response(req):
            return HttpResponse("ok")

        middleware = SecurityHeadersMiddleware(dummy_response)
        response = middleware(request)

        csp = response.get("Content-Security-Policy", "")
        self.assertIn("default-src 'self'", csp)
        self.assertNotIn("nonce-", csp)


class CSPNonceContextProcessorTest(SimpleTestCase):
    """M7: CSP nonce context processor for templates."""

    def test_returns_nonce_from_request(self) -> None:
        factory = RequestFactory()
        request = factory.get("/")
        request.csp_nonce = "ctx-test-nonce"

        result = csp_nonce(request)
        self.assertEqual(result, {"csp_nonce": "ctx-test-nonce"})

    def test_returns_empty_without_nonce(self) -> None:
        factory = RequestFactory()
        request = factory.get("/")

        result = csp_nonce(request)
        self.assertEqual(result, {"csp_nonce": ""})
